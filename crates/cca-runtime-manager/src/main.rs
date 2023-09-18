mod cca;
mod init;
mod fake;

use anyhow::{anyhow, Error, Result};
use io_utils::nix::{receive_buffer, send_buffer};
use log::{debug, error, info};
use nix::sys::socket::{
    accept, bind, listen, socket, AddressFamily, SockFlag, SockType, VsockAddr,
};
use nix::unistd::{read, write};
use runtime_manager::managers::{self, RuntimeManagerError};
use std::io::{Read, Write};
use std::os::unix::prelude::FromRawFd;
use std::os::unix::prelude::RawFd;
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
    crate::init::init("trace", true)?;

    std::panic::set_hook(Box::new(|info| {
        error!("{}", info);
        log::logger().flush();
        crate::init::reboot().map_err(Error::from);
    }));

    if ATTESTATION_TEST {
        let challenge = [0u8; 64];
        let _ = attestation(&challenge, Uuid::nil());
        info!("Shutting down");
        return crate::init::reboot().map_err(Error::from);
    }

    let fd: RawFd = if cfg!(not(feature = "fake-host")) {
        info!("Using vsock");
        let socket_fd = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )?;

        let sockaddr = VsockAddr::new(CID, PORT);
        bind(socket_fd, &sockaddr)?;
        listen(socket_fd, BACKLOG)?;
        debug!("Waiting for vsock connection on port {}", PORT);
        let f = accept(socket_fd)?;
        debug!("vsock connection accepted");
        f
    } else {
        info!("Using virtio-serial");
        let f = nix::fcntl::open(
            "/dev/vport1p1",
            nix::fcntl::OFlag::O_RDWR,
            nix::sys::stat::Mode::empty(),
        )?;
        debug!("Opened /dev/vport1p1");
        f
    };

    let mut finished = false;

    loop {
        if finished {
            break;
        }
        let received_buffer = receive_buffer(fd)?;
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
                debug!("runtime_manager_cca::main GetTlsData");
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
        send_buffer(fd, &return_buffer)?;
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

    if cfg!(feature = "fake-host") {
        return fake::fake_attestation(challenge, csr);
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
