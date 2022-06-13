#[macro_use]
extern crate log;

use core::{convert::TryFrom, mem::size_of};

use anyhow::Error;
use nix::mount::{mount, MsFlags}; // MntFlags
use nix::sys::stat::Mode;
use nix::unistd::{mkdir, read};

use io_utils::raw_fd::{receive_buffer, send_buffer};

use veracruz_utils::runtime_manager_message::{
    RuntimeManagerRequest, RuntimeManagerResponse, Status,
};

use runtime_manager_enclave::managers::{self, RuntimeManagerError};

#[cfg(feature = "vsock")]
use nix::sys::socket::{accept, bind, listen, socket, AddressFamily, SockAddr, SockFlag, SockType};

#[cfg(not(feature = "vsock"))]
use nix::fcntl::{open, OFlag};

use bincode;
use serde::{Deserialize, Serialize};

/// The CID for the VSOCK to listen on
/// Currently set to all 1's so it will listen on all of them
const CID: u32 = 0xFFFFFFFF; // VMADDR_CID_ANY
/// The incoming port to listen on
const PORT: u32 = 5005;
/// max number of outstanding connectiosn in the socket listen queue
const BACKLOG: usize = 1;

fn main() -> Result<(), Error> {
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
    env_logger::builder().parse_filters("init=debug").init();

    // Log retroactively :)
    info!("Starting init");
    debug!("Mounting /dev");

    debug!("Mounting /proc");
    mkdir("/proc", chmod_0555).ok();
    mount::<_, _, _, [u8]>(Some("proc"), "/proc", Some("proc"), common_mnt_flags, None)?;

    // let paths = fs::read_dir("/dev").unwrap();
    // for path in paths {
    //     println!("Name: {}", path.unwrap().path().display())
    // }

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
        debug!("Waiting for vsock connection");
        let f = accept(socket_fd)?;
        debug!("vsock connection accepted");
        f
    };

    #[cfg(not(feature = "vsock"))]
    let fd = {
        info!("Using virtio-console");
        open("/dev/hvc0", OFlag::empty(), Mode::empty())?
    };
    debug!("Opened /dev/hvc0");

    // loop {
    //     let mut c = [0u8; 1];
    //     match read(fd, &mut c) {
    //         Ok(_) => {
    //             println!("Read {:?}", c[0]);
    //         },
    //         Err(e) => {
    //             println!("{:?}", e);
    //         }
    //     }
    //     if c[0] == 'q' as u8 {
    //         break;
    //     }
    // }

    loop {
        let mut finished = false;

        let received_buffer =
            receive_buffer(fd).map_err(|err| RuntimeManagerError::VeracruzSocketError(err))?;
        let received_message: RuntimeManagerRequest = bincode::deserialize(&received_buffer)
            .map_err(|err| RuntimeManagerError::BincodeError(err))?;
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
        let return_buffer = bincode::serialize(&return_message)
            .map_err(|err| RuntimeManagerError::BincodeError(err))?;
            debug!(
            "runtime_manager_cca::main calling send buffer with buffer_len:{:?}",
            return_buffer.len()
        );
        send_buffer(fd, &return_buffer)
            .map_err(|err| RuntimeManagerError::VeracruzSocketError(err))?;

        if finished {
            break;
        }
    }


    info!("Shutting down");
    nix::sys::reboot::reboot(nix::sys::reboot::RebootMode::RB_POWER_OFF)
        .map(|_| {})
        .map_err(Error::from)
}


fn attestation(
    challenge: &[u8],
    _challenge_id: i32,
) -> Result<RuntimeManagerResponse, RuntimeManagerError> {
    info!("runtime_manager_cca::attestation started");
    managers::session_manager::init_session_manager()?;
    // generate the csr
    let csr: Vec<u8> = managers::session_manager::generate_csr()?;
    // TODO: generate the attestation document
    return Ok(RuntimeManagerResponse::AttestationData(vec![], csr));
}

/// Handler for the RuntimeManagerRequest::Initialize message
fn initialize(
    policy_json: &str,
    cert_chain: &Vec<Vec<u8>>,
) -> Result<RuntimeManagerResponse, RuntimeManagerError> {
    managers::session_manager::load_policy(policy_json)?;
    info!("runtime_manager_cca::initialize started");
    managers::session_manager::load_cert_chain(cert_chain)?;

    return Ok(RuntimeManagerResponse::Status(Status::Success));
}
