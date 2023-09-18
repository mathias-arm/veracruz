//! Linux-specific material for the Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::anyhow;
use err_derive::Error;
use io_utils::nix::{receive_buffer, send_buffer};
use log::{debug, error, info, warn};
use nix::sys::{signal, socket};
use nix::unistd::read;
use policy_utils::policy::Policy;
use signal_hook::{
    consts::SIGINT,
    iterator::{Handle, Signals},
};

use std::os::unix::io::IntoRawFd;
use std::{
    convert::TryFrom,
    env,
    error::Error,
    fs::{self, File},
    io::{self, Read},
    net::{Shutdown, TcpStream},
    os::unix::fs::PermissionsExt,
    os::unix::net::UnixStream,
    process::{Child, Command, Stdio},
    string::ToString,
    sync::{Arc, Mutex},
    thread::{self, sleep, JoinHandle},
    time::Duration,
};
use tempfile::{self, TempDir};
use veracruz_server::common::{VeracruzServer, VeracruzServerError};
use veracruz_utils::runtime_manager_message::{
    RuntimeManagerRequest, RuntimeManagerResponse, Status,
};

/// Class of CCA-specific errors.
#[derive(Debug, Error)]
pub enum CCAError {
    #[error(display = "CCA: Invalid environment variable value: {}", variable)]
    InvalidEnvironmentVariableValue { variable: String },
    #[error(display = "CCA: Channel error: {}", _0)]
    ChannelError(io::Error),
    #[error(display = "CCA: Qemu spawn error: {}", _0)]
    QemuSpawnError(io::Error),
    #[error(display = "CCA: Serialization error: {}", _0)]
    SerializationError(#[error(source)] bincode::Error),
    #[error(display = "CCA: Unexpected response from runtime manager: {:?}", _0)]
    UnexpectedRuntimeManagerResponse(RuntimeManagerResponse),
}

impl From<CCAError> for VeracruzServerError {
    fn from(error: CCAError) -> Self {
        VeracruzServerError::Anyhow(anyhow!(error))
    }
}

////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////

const VERACRUZ_CCA_QEMU_BIN_DEFAULT: &[&str] = &["qemu-system-aarch64"];
#[cfg(feature = "fake-host")]
const VERACRUZ_CCA_QEMU_FLAGS_DEFAULT: &[&str] = &[
    "-machine",
    "virt",
    "-cpu",
    "max",
    "-smp",
    "1",
    "-m",
    "1024",
    "-M",
    "gic-version=3",
    "-nic",
    "none",
    "-nodefaults",
    "-nographic",
    "-kernel",
    "{kernel_path}",
    "-initrd",
    "{initrd_path}",
    "-global",
    "virtio-mmio.force-legacy=false",
    "-trace",
    "*load*",
    "-serial",
    "chardev:char0",
    "-device",
    "virtio-serial,id=virtio-serial0",
    "-chardev",
    "stdio,id=char0,mux=on",
    "-device",
    "virtconsole,chardev=char0",
];

#[cfg(not(feature = "fake-host"))]
const VERACRUZ_CCA_QEMU_FLAGS_DEFAULT: &[&str] = &[
    "-machine",
    "virt",
    "-cpu",
    "host",
    "-enable-kvm",
    "-smp",
    "1",
    "-m",
    "1024",
    "-M",
    "gic-version=3",
    "-nic",
    "none",
    "-nodefaults",
    "-nographic",
    "-kernel",
    "{kernel_path}",
    "-initrd",
    "{initrd_path}",
    "-M",
    "confidential-guest-support=rme0",
    "-overcommit",
    "mem-lock=on",
    "-object",
    "rme-guest,id=rme0,measurement-algo=sha256",
    "-global",
    "virtio-mmio.force-legacy=false",
    "-trace",
    "*load*",
    "-serial",
    "chardev:char0",
    "-device",
    "virtio-serial,id=virtio-serial0",
    "-chardev",
    "stdio,id=char0,mux=on",
    "-device",
    "virtconsole,chardev=char0",
];

const VERACRUZ_CCA_QEMU_CONSOLE_FLAGS_DEFAULT: &[&str] = &[
    "-chardev",
    "socket,path={console0_path},server=on,wait=off,id=serial1",
    "-device",
    "virtio-serial",
    "-device",
    "virtserialport,chardev=serial1",
];

const VERACRUZ_CCA_QEMU_VSOCK_FLAGS_DEFAULT: &[&str] =
    &["-device", "vhost-vsock-pci,guest-cid={cid}"];

const VERACRUZ_CCA_KERNEL_PATH_DEFAULT: &str = "../cca-runtime/Image.guest";
const VERACRUZ_CCA_INITRD_PATH_DEFAULT: &str = "../cca-runtime/initrd.cpio";

/// The protocol to use with the proxy attestation server.
const PROXY_ATTESTATION_PROTOCOL: &str = "psa";
/// The firmware version to use when communicating with the proxy attestation server.
const FIRMWARE_VERSION: &str = "0.0";

/// The port that is used to communicate with the enclave
const VERACRUZ_PORT: u32 = 5005;

pub struct CCAEnclave {
    // NOTE the order of these fields matter due to drop ordering
    child: Arc<Mutex<Child>>,
    channel: std::os::unix::io::RawFd,
    #[allow(dead_code)]
    stdout_handler: JoinHandle<()>,
    #[allow(dead_code)]
    stderr_handler: JoinHandle<()>,
    signal_handle: Handle,
    #[allow(dead_code)]
    signal_handler: JoinHandle<()>,
    #[allow(dead_code)]
    tempdir: TempDir,
}

impl CCAEnclave {
    fn spawn() -> Result<CCAEnclave, VeracruzServerError> {
        fn env_flags(var: &str, default: &[&str]) -> Result<Vec<String>, VeracruzServerError> {
            match env::var(var) {
                Ok(var) => Ok(var.split_whitespace().map(|s| s.to_owned()).collect()),
                Err(env::VarError::NotPresent) => {
                    Ok(default.iter().map(|s| (*s).to_owned()).collect())
                }
                Err(_) => Err(CCAError::InvalidEnvironmentVariableValue {
                    variable: var.to_owned(),
                }
                .into()),
            }
        }

        // Allow overriding these from environment variables
        let qemu_bin = env_flags("VERACRUZ_CCA_QEMU_BIN", VERACRUZ_CCA_QEMU_BIN_DEFAULT)?;
        let qemu_flags = env_flags("VERACRUZ_CCA_QEMU_FLAGS", VERACRUZ_CCA_QEMU_FLAGS_DEFAULT)?;

        let qemu_vsock_flags = env_flags(
            "VERACRUZ_CCA_QEMU_VSOCK_FLAGS",
            VERACRUZ_CCA_QEMU_VSOCK_FLAGS_DEFAULT,
        )?;

        let qemu_console_flags = env_flags(
            "VERACRUZ_CCA_QEMU_CONSOLE_FLAGS",
            VERACRUZ_CCA_QEMU_CONSOLE_FLAGS_DEFAULT,
        )?;

        // temporary directory for things
        let tempdir = tempfile::tempdir()?;

        // create a temporary socket for communication
        let channel_path = tempdir.path().join("console0");
        // let channel_path = std::path::PathBuf::from("/tmp/console0");
        info!("vc-server: using unix socket: {:?}", channel_path);

        let kernel_path = env::var("VERACRUZ_CCA_KERNEL_PATH")
            .unwrap_or_else(|_| VERACRUZ_CCA_KERNEL_PATH_DEFAULT.to_string());
        let initrd_path = env::var("VERACRUZ_CCA_INITRD_PATH")
            .unwrap_or_else(|_| VERACRUZ_CCA_INITRD_PATH_DEFAULT.to_string());

        let qemu_flags: Vec<String> = qemu_flags
            .iter()
            .map(|s| s.replace("{kernel_path}", &kernel_path))
            .map(|s| s.replace("{initrd_path}", &initrd_path))
            .collect();

        let use_vsock = cfg!(not(feature = "fake-host"));

        let com_flags: Vec<String> = if use_vsock {
            qemu_vsock_flags
                .iter()
                .map(|s| s.replace("{cid}", "3"))
                .collect()
        } else {
            qemu_console_flags
                .iter()
                .map(|s| s.replace("{console0_path}", channel_path.to_str().unwrap()))
                .collect()
        };

        info!("{:?} {:?} {:?}", qemu_bin, qemu_flags, com_flags);

        // startup qemu
        let child = Arc::new(Mutex::new(
            Command::new(&qemu_bin[0])
                .args(&qemu_bin[1..])
                .args(qemu_flags)
                .args(com_flags)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(CCAError::QemuSpawnError)?,
        ));

        // forward stderr/stdin via threads, this is necessary to avoid stdio
        // issues under Cargo test
        let stdout_handler = thread::spawn({
            let mut child_stdout = child.lock().unwrap().stdout.take().unwrap();
            move || {
                let err = io::copy(&mut child_stdout, &mut io::stdout());
                error!("vc-server: qemu: stdout closed: {:?}", err);
            }
        });

        let stderr_handler = thread::spawn({
            let mut child_stderr = child.lock().unwrap().stderr.take().unwrap();
            move || {
                let err = io::copy(&mut child_stderr, &mut io::stderr());
                error!("vc-server: qemu: stderr closed: {:?}", err);
            }
        });

        // hookup signal handler so SIGINT will teardown the child process
        let mut signals = Signals::new(&[SIGINT])?;
        let signal_handle = signals.handle();
        let signal_handler = thread::spawn({
            let child = child.clone();
            move || {
                for sig in signals.forever() {
                    error!("vc-server: qemu: Killed by signal: {:?}", sig);
                    child.lock().unwrap().kill().unwrap();
                    signal_hook::low_level::emulate_default_handler(SIGINT).unwrap();
                }
            }
        });

        if use_vsock {
            thread::sleep(Duration::from_millis(5000));
        }

        let channel = loop {
            if use_vsock {
                info!("Connecting to vsock cid: {} port: {}", 3, VERACRUZ_PORT);
                let addr = socket::VsockAddr::new(3, VERACRUZ_PORT);
                let socket = socket::socket(
                    socket::AddressFamily::Vsock,
                    socket::SockType::Stream,
                    socket::SockFlag::empty(),
                    None,
                )?;
                socket::setsockopt(socket, socket::sockopt::ReuseAddr, &true)?;
                socket::setsockopt(socket, socket::sockopt::ReusePort, &true)?;

                match socket::connect(socket, &addr) {
                    Ok(_) => {
                        info!("Connected");
                        break socket;
                    }
                    Err(nix::errno::Errno::ECONNREFUSED) => {
                        warn!("Connection refused");
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    Err(e) => {
                        error!("Connection failed: {:?}", e);
                        return Err(VeracruzServerError::NixError(e));
                    }
                }
            } else {
                info!(
                    "Connecting to UNIX socket '{}'",
                    channel_path.to_str().unwrap()
                );
                let addr = socket::UnixAddr::new(&channel_path)?;
                let socket = socket::socket(
                    socket::AddressFamily::Unix,
                    socket::SockType::Stream,
                    socket::SockFlag::empty(),
                    None,
                )?;

                match socket::connect(socket, &addr) {
                    Ok(_) => {
                        info!("Connected");
                        break socket;
                    }
                    Err(nix::errno::Errno::ECONNREFUSED) => {
                        warn!("Connection refused");
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    Err(nix::errno::Errno::ENOENT) => {
                        warn!("Connection refused (not found)");
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    Err(e) => {
                        error!("Connection failed: {:?}", e);
                        return Err(VeracruzServerError::NixError(e));
                    }
                }
            }
        };

        Ok(CCAEnclave {
            child,
            channel,
            stdout_handler,
            stderr_handler,
            signal_handle,
            signal_handler,
            tempdir,
        })
    }

    fn communicate(
        &mut self,
        request: &RuntimeManagerRequest,
    ) -> Result<RuntimeManagerResponse, VeracruzServerError> {
        // send request
        let buffer = bincode::serialize(request)?;
        send_buffer(self.channel, &buffer)?;

        // recv response
        let buffer: Vec<u8> = receive_buffer(self.channel)?;
        let response = bincode::deserialize::<RuntimeManagerResponse>(&buffer)?;

        Ok(response)
    }

    /// send a buffer of data to the enclave
    pub fn send_buffer(&self, buffer: &[u8]) -> anyhow::Result<()> {
        send_buffer(self.channel, buffer)
    }

    /// receive a buffer of data from the enclave
    pub fn receive_buffer(&self) -> anyhow::Result<Vec<u8>> {
        receive_buffer(self.channel)
    }

    // NOTE close can report errors, but drop can still happen in weird cases
    fn shutdown(&mut self) -> Result<(), VeracruzServerError> {
        info!("vc-server: shutting down");
        self.signal_handle.close();
        self.child.lock().unwrap().kill()?;
        Ok(())
    }
}

pub struct VeracruzServerCCA {
    enclave: CCAEnclave,
}

impl VeracruzServerCCA {
    /// Kills the Runtime Manager enclave, then closes TCP connection.
    #[inline]
    fn shutdown_isolate(&mut self) -> Result<(), Box<dyn Error>> {
        unsafe {
            self.enclave.shutdown()?;
        };
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////
// Trait implementations.
////////////////////////////////////////////////////////////////////////////

/// An implementation of the `Drop` trait that forcibly kills the runtime
/// manager enclave, and closes the socket used for communicating with it, when
/// a `VeracruzServerCCA` struct is about to go out of scope.
impl Drop for VeracruzServerCCA {
    fn drop(&mut self) {
        info!("Dropping VeracruzServerCCA object, shutting down enclave...");
        if let Err(error) = self.shutdown_isolate() {
            error!(
                "Failed to forcibly shutdown Runtime Manager enclave.  Error produced: {:?}.",
                error
            );
        }
        info!("VeracruzServerCCA object killed.");
    }
}

impl VeracruzServer for VeracruzServerCCA {
    /// Creates a new instance of the `VeracruzServerCCA` type.
    fn new(policy_json: &str) -> Result<Self, VeracruzServerError> {
        // TODO: add in dummy measurement and attestation token issuance here
        // which will use fields from the JSON policy file.
        let policy = Policy::from_json(policy_json)?;

        let (challenge_id, challenge) = proxy_attestation_client::start_proxy_attestation(
            policy.proxy_attestation_server_url(),
        )
        .map_err(|e| {
            error!(
                "Failed to start proxy attestation process.  Error produced: {}.",
                e
            );
            e
        })?;

        let mut meta = Self {
            enclave: CCAEnclave::spawn()?,
        };

        let (token, csr) = {
            let token = RuntimeManagerRequest::Attestation(challenge, challenge_id);
            meta.enclave.send_buffer(&bincode::serialize(&token)?)?;
            // read the response
            let response = meta.enclave.receive_buffer()?;
            match bincode::deserialize(&response[..])? {
                RuntimeManagerResponse::AttestationData(token, csr) => (token, csr),
                response_message => {
                    return Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                        response_message,
                    ))
                }
            }
        };

        let cert_chain = proxy_attestation_client::complete_proxy_attestation_linux(
            policy.proxy_attestation_server_url(),
            &token,
            &csr,
            challenge_id,
        )?;

        meta.enclave
            .communicate(&RuntimeManagerRequest::Initialize(
                policy_json.to_string(),
                cert_chain,
            ))?;

        Ok(meta)
    }

    fn send_buffer(&mut self, buffer: &[u8]) -> Result<(), VeracruzServerError> {
        let ret = self.enclave.send_buffer(buffer)?;
        return Ok(ret);
    }

    fn receive_buffer(&mut self) -> Result<Vec<u8>, VeracruzServerError> {
        let ret = self.enclave.receive_buffer()?;
        return Ok(ret);
    }
}
