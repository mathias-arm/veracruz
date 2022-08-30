#[macro_use]
extern crate log;

use core::{convert::TryFrom, mem::size_of};

use anyhow::{anyhow, Error, Result};
use nix::mount::{mount, MsFlags}; // MntFlags
use nix::sys::stat::Mode;
use nix::unistd::{mkdir, read, close};

use io_utils::raw_fd::{receive_buffer, send_buffer};

use veracruz_utils::runtime_manager_message::{
    RuntimeManagerRequest, RuntimeManagerResponse, Status,
};

use runtime_manager_enclave::managers::{self, RuntimeManagerError};

#[cfg(feature = "vsock")]
use nix::sys::socket::{accept, bind, listen, socket, AddressFamily, SockAddr, SockFlag, SockType};

use nix::fcntl::{open, OFlag};

use bincode;
use serde::{Deserialize, Serialize};
use std::fs;

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
    std::env::set_var("RUST_BACKTRACE", "full");

    // These cannot currently be constants
    let chmod_0555: Mode = Mode::S_IRUSR | Mode::S_IXUSR | Mode::S_IRGRP |
        Mode::S_IXGRP | Mode::S_IROTH | Mode::S_IXOTH;
    let chmod_0755: Mode = Mode::S_IRWXU | Mode::S_IRGRP | Mode::S_IXGRP |
        Mode::S_IROTH | Mode::S_IXOTH;
    let common_mnt_flags: MsFlags = MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID;

    // /dev/urandom is required very early
    mkdir("/dev", chmod_0755).ok();
    let devtmpfs = Some("devtmpfs");
    mount(devtmpfs, "/dev", devtmpfs, MsFlags::MS_NOSUID, Some("mode=0755"))?;

    // Initialize logging
    env_logger::builder().parse_filters("debug").init();

    // Log retroactively :)
    info!("Starting init");
    debug!("Mounting /dev");

    debug!("Mounting /proc");
    mkdir("/proc", chmod_0555).ok();
    mount::<_, _, _, [u8]>(Some("proc"), "/proc", Some("proc"), common_mnt_flags, None)?;

    if ATTESTATION_TEST {
        let challenge = [0u8; 64];
        attestation(&challenge, 0);
        info!("Shutting down");
        return nix::sys::reboot::reboot(nix::sys::reboot::RebootMode::RB_POWER_OFF)
            .map(|_| {})
            .map_err(Error::from);
    }

    #[cfg(feature = "vsock")]
    let fd = {
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
    };

    #[cfg(not(feature = "vsock"))]
    let fd = {
        info!("Using virtio-console");
        let f = open("/dev/hvc0", OFlag::empty(), Mode::empty())?;
        debug!("Opened /dev/hvc0");
        f
    };

    let mut finished = false;

    loop {
        if finished {
            break;
        }
        let received_buffer = match receive_buffer(fd) {
            Ok(r) => r,
            Err(err) => {
                error!("runtime_manager_cca::main receive_buffer: {:?}", err);
                break
            }
        };
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
            RuntimeManagerRequest::GetTlsDataNeeded(session_id) => {
                debug!("runtime_manager_cca::main GetTlsDataNeeded");
                let return_message = match managers::session_manager::get_data_needed(session_id) {
                    Ok(needed) => RuntimeManagerResponse::TlsDataNeeded(needed),
                    Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                };
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
            }
            _ => {
                debug!("runtime_manager_cca::main Unknown Opcode");
                RuntimeManagerResponse::Status(Status::Unimplemented)
            }
        };
        let return_buffer = bincode::serialize(&return_message)?;
        debug!(
            "runtime_manager_cca::main calling send buffer with buffer_len: {:?}",
            return_buffer.len()
        );
        match send_buffer(fd, &return_buffer) {
            Ok(r) => (),
            Err(err) => {
                error!("runtime_manager_cca::main send_buffer: {:?}", err);
                break
            }
        };
    }

    info!("Shutting down");
    nix::sys::reboot::reboot(nix::sys::reboot::RebootMode::RB_POWER_OFF)
        .map(|_| {})
        .map_err(Error::from)
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct cca_ioctl_request {
    challenge: [u8; 64],
    token: [u8; 4096],
    token_length: u64,
}

fn bytes_to_hex(bytes : &[u8]) -> String {
    let hex_bytes : Vec<String> = bytes.iter()
        .map(|b| format!("{:02x}", b)).collect();
    hex_bytes.join("")
}

nix::ioctl_readwrite!(cca_attestation_request, b'A', 1, cca_ioctl_request);

fn attestation(challenge: &[u8], _challenge_id: i32) -> Result<RuntimeManagerResponse> {
    info!("runtime_manager_cca::attestation started");
    managers::session_manager::init_session_manager()?;
    // generate the csr
    let csr: Vec<u8> = managers::session_manager::generate_csr()?;

    #[cfg(not(feature = "qemu"))]
    match open("/dev/cca_attestation", OFlag::empty(), Mode::empty()) {
        Ok(f) => {
            info!("runtime_manager_cca::attestation opening attestation succeeded");
            let mut r = cca_ioctl_request {
                challenge: [0u8; 64],
                token: [0u8; 4096],
                token_length: 0u64
            };

            let mut i : usize = 0;
            let j : usize = std::cmp::min(r.challenge.len(), challenge.len());
            while i < r.challenge.len() && i < challenge.len() {
                r.challenge[i] = challenge[i];
                i += 1;
            }

            match unsafe { cca_attestation_request(f, &mut r) } {
                Ok(c) => {
                    close(f);
                    info!("runtime_manager_cca::attestation ioctl call succeeded ({})", c);
                    info!("runtime_manager_cca::attestation token is {} bytes long", r.token_length);
                    let hex = bytes_to_hex(&r.token[0..(r.token_length as usize)]);
                    info!("runtime_manager_cca::attestation token = {:x?}", hex);
                    let token = r.token[0..(r.token_length as usize)].to_vec();
                    info!("runtime_manager_cca::attestation done");
                    Ok(RuntimeManagerResponse::AttestationData(token, csr))
                }
                Err(e) => {
                    close(f);
                    error!("runtime_manager_cca::attestation ioctl failed! {}", e);
                    Err(anyhow!(RuntimeManagerError::AttestationError(e)))
                }
            }
        }
        Err(err) => {
            error!("runtime_manager_cca::attestation opening attestation failed! {}", err);
            Err(anyhow!(RuntimeManagerError::AttestationError(err)))
        }
    }

    #[cfg(feature = "qemu")]
    {
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
        let token_hex : String = token_hex.chars().filter(|c| !c.is_whitespace()).collect();
        let token = hex::decode(token_hex).ok().unwrap();
        info!("runtime_manager_cca::attestation done");
        Ok(RuntimeManagerResponse::AttestationData(token, csr))
    }
}

/// Handler for the RuntimeManagerRequest::Initialize message
fn initialize(policy_json: &str, cert_chain: &Vec<Vec<u8>>) -> Result<RuntimeManagerResponse> {
    managers::session_manager::load_policy(policy_json)?;
    info!("runtime_manager_cca::initialize started");
    managers::session_manager::load_cert_chain(cert_chain)?;

    return Ok(RuntimeManagerResponse::Status(Status::Success));
}
