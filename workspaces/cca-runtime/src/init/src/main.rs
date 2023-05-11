mod cca;
mod init;

use anyhow::{anyhow, Error, Result};
use io_utils::fd::{receive_buffer, send_buffer};
use log::{debug, error, info};
use nix::sys::socket::{accept, bind, listen, socket, AddressFamily, SockAddr, SockFlag, SockType};
use runtime_manager_enclave::managers::{self, RuntimeManagerError};
use std::os::unix::prelude::{FromRawFd, RawFd};
use uuid::Uuid;
use veracruz_utils::runtime_manager_message::{
    RuntimeManagerRequest, RuntimeManagerResponse, Status,
};

/// The CID for the VSOCK to listen on
/// Currently set to all 1's so it will listen on all of them
const CID: u32 = 0xFFFFFFFF; // VMADDR_CID_ANY
/// The incoming port to listen on
const PORT: u32 = 5005;
/// max number of outstanding connectiosn in the socket listen queue
const BACKLOG: usize = 1;

// Just request an attestation token and exit
const ATTESTATION_TEST: bool = false;

fn main() -> Result<()> {
    crate::init::init("debug", true)?;

    if ATTESTATION_TEST {
        let challenge = [0u8; 64];
        let _ = attestation(&challenge, Uuid::nil());
        info!("Shutting down");
        return crate::init::reboot().map_err(Error::from);
    }

    let fd: RawFd = if cfg!(not(feature = "simulation")) {
        info!("Using vsock");
        let socket_fd = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )?;

        let sockaddr = SockAddr::new_vsock(CID, PORT);
        bind(socket_fd, &sockaddr)?;
        listen(socket_fd, BACKLOG)?;
        debug!("Waiting for vsock connection on port {}", PORT);
        let f = accept(socket_fd)?;
        debug!("vsock connection accepted");
        f
    } else {
        info!("Using virtio-console");
        let f = nix::fcntl::open("/dev/hvc0", nix::fcntl::OFlag::empty(),
            nix::sys::stat::Mode::empty())?;
        debug!("Opened /dev/hvc0");
        f
    };

    let mut finished = false;

    loop {
        if finished {
            break;
        }
        let received_buffer = receive_buffer(unsafe { std::fs::File::from_raw_fd(fd) })?;
        let received_message: RuntimeManagerRequest = bincode::deserialize(&received_buffer)?;
        let return_message = match received_message {
            RuntimeManagerRequest::Attestation(challenge, challenge_id) => {
                attestation(&challenge, challenge_id)?
            }
            RuntimeManagerRequest::Initialize(policy_json, certificate_chain) => {
                initialize(&policy_json, &certificate_chain)?
            }
            RuntimeManagerRequest::NewTlsSession => {
                debug!("runtime_manager_cca::main NewTlsSession");
                let ns_result = managers::session_manager::new_session();
                let return_message: RuntimeManagerResponse = match ns_result {
                    Ok(session_id) => RuntimeManagerResponse::TlsSession(session_id),
                    Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                };
                return_message
            }
            RuntimeManagerRequest::CloseTlsSession(session_id) => {
                debug!("runtime_manager_cca::main CloseTlsSession");
                let cs_result = managers::session_manager::close_session(session_id);
                let return_message: RuntimeManagerResponse = match cs_result {
                    Ok(_) => RuntimeManagerResponse::Status(Status::Success),
                    Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                };
                finished = true;
                return_message
            }
            RuntimeManagerRequest::SendTlsData(session_id, tls_data) => {
                debug!("runtime_manager_cca::main SendTlsData");
                let return_message =
                    match managers::session_manager::send_data(session_id, &tls_data) {
                        Ok(_) => RuntimeManagerResponse::Status(Status::Success),
                        Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                    };
                return_message
            }
            RuntimeManagerRequest::GetTlsData(session_id) => {
                println!("runtime_manager_cca::main GetTlsData");
                let return_message = match managers::session_manager::get_data(session_id) {
                    Ok((active, output_data)) => {
                        RuntimeManagerResponse::TlsData(output_data, active)
                    }
                    Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                };
                return_message
            } // _ => {
              //     debug!("runtime_manager_cca::main Unknown Opcode");
              //     RuntimeManagerResponse::Status(Status::Unimplemented)
              // }
        };
        let return_buffer = bincode::serialize(&return_message)?;
        debug!(
            "runtime_manager_cca::main calling send buffer with buffer_len:{:?}",
            return_buffer.len()
        );
        send_buffer(unsafe { std::fs::File::from_raw_fd(fd) }, &return_buffer)?;
    }

    info!("Shutting down");
    crate::init::reboot().map_err(Error::from)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let hex_bytes: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    hex_bytes.join("")
}

fn attestation(challenge: &[u8], _challenge_id: Uuid) -> Result<RuntimeManagerResponse> {
    info!("runtime_manager_cca::attestation started");
    managers::session_manager::init_session_manager()?;
    // generate the csr
    let csr: Vec<u8> = managers::session_manager::generate_csr()?;

    if cfg!(feature = "simulation") {
        return fake_attestation(challenge, csr);
    }

    match cca::attestation(challenge) {
        Ok(token) => {
            info!(
                "runtime_manager_cca::attestation token is {} bytes long",
                token.len()
            );
            let hex = bytes_to_hex(&token);
            info!("runtime_manager_cca::attestation token = {:x?}", hex);
            Ok(RuntimeManagerResponse::AttestationData(token, csr))
        }
        Err(e) => {
            error!("runtime_manager_cca::attestation failed! {}", e);
            Err(anyhow!(RuntimeManagerError::AttestationError(e)))
        }
    }
}

/// Handler for the RuntimeManagerRequest::Initialize message
fn initialize(policy_json: &str, cert_chain: &Vec<u8>) -> Result<RuntimeManagerResponse> {
    managers::session_manager::load_policy(policy_json)?;
    info!("runtime_manager_cca::initialize started");
    managers::session_manager::load_cert_chain(cert_chain)?;

    Ok(RuntimeManagerResponse::Status(Status::Success))
}

fn fake_attestation(_challenge: &[u8], csr: Vec<u8>) -> Result<RuntimeManagerResponse> {
    let token_hex = "\
    d28444a1013822a05901c9a60a58400000000000000000000000000000000000
    0000000000000000000000000000000000000000000000000000000000000000
    00000000000000000000000000000019620d5820aea131de37171000aabbccdd
    eeff001122334455667788990123456789abcdef19620ef519621158610476f9
    88091be585ed41801aecfab858548c63057e16b0e676120bbd0d2f9c29e056c5
    d41a0130eb9c21517899dc23146b28e1b062bd3ea4b315fd219f1cbb528cb6e7
    4ca49be16773734f61a1ca61031b2bbf3d918f2f94ffc4228e50919544ae1962
    100119620f875820000000000000000000000000000000000000000000000000
    0000000000000000582000000000000000000000000000000000000000000000
    0000000000000000000058200000000000000000000000000000000000000000
    0000000000000000000000005820000000000000000000000000000000000000
    0000000000000000000000000000582000000000000000000000000000000000
    0000000000000000000000000000000058200000000000000000000000000000
    0000000000000000000000000000000000005820000000000000000000000000
    00000000000000000000000000000000000000005860e8918241325ec38f58cd
    16580233a728271df36ec98d411c859d220cf3ae3e1f386ed7041ecc232082ba
    51c133a09793c2cb44b4b58880e05459e3091687216ba61eab1b4eeccd504718
    af06b4df5a2da171de4a2e27d54a4fe145904857cbe5";
    let token_hex: String = token_hex.chars().filter(|c| !c.is_whitespace()).collect();
    let token = hex::decode(token_hex).ok().unwrap();
    Ok(RuntimeManagerResponse::AttestationData(token, csr))
}
