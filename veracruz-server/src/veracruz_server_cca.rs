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

#[cfg(feature = "cca")]
pub mod veracruz_server_cca {

    use crate::{veracruz_server::VeracruzServer, VeracruzServerError};
    use err_derive::Error;
    use io_utils::{
        http::{post_buffer, send_proxy_attestation_server_start},
        tcp::{receive_message, send_message},
    };
    use log::{error, info};
    use nix::sys::signal;
    use policy_utils::policy::Policy;
    use rand::Rng;
    use signal_hook::{
        consts::SIGINT,
        iterator::{Handle, Signals},
    };
    use std::{
        convert::TryFrom,
        env,
        error::Error,
        fs::{self, File},
        io::{self, Read},
        net::{Shutdown, TcpStream},
        os::unix::fs::PermissionsExt,
        process::{Child, Command, Stdio},
        string::ToString,
        sync::{Arc, Mutex},
        thread::{self, sleep, JoinHandle},
        time::Duration,
    };
    use tempfile::{self, TempDir};
    use transport_protocol::{
        parse_proxy_attestation_server_response, serialize_native_psa_attestation_token,
    };
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
        SerializationError(bincode::Error),
        #[error(display = "CCA: Unexpected response from runtime manager: {:?}", _0)]
        UnexpectedRuntimeManagerResponse(RuntimeManagerResponse),
    }

    impl From<CCAError> for VeracruzServerError {
        fn from(err: CCAError) -> VeracruzServerError {
            VeracruzServerError::CCAError(err)
        }
    }

    impl From<bincode::Error> for VeracruzServerError {
        fn from(err: bincode::Error) -> VeracruzServerError {
            VeracruzServerError::from(CCAError::SerializationError(err))
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Constants.
    ////////////////////////////////////////////////////////////////////////////

    const VERACRUZ_CCA_QEMU_BIN_DEFAULT: &[&str] = &["qemu-system-aarch64"];
    const VERACRUZ_CCA_QEMU_FLAGS_DEFAULT: &[&str] = &[
        "-machine",
        "virt",
        "-cpu",
        "cortex-a57",
        "-smp",
        "4",
        "-m",
        "3072",
        "-serial",
        "mon:stdio",
        "-nographic",
        "-kernel",
        "{kernel_path}",
        "-initrd",
        "{initrd_path}",
    ];
    const VERACRUZ_CCA_QEMU_CONSOLE_FLAGS_DEFAULT: &[&str] = &[
        "-chardev",
        "socket,path={console0_path},server=on,wait=off,id=charconsole0",
        "-device",
        "virtio-serial-device",
        "-device",
        "virtconsole,chardev=charconsole0,id=console0",
    ];
    const VERACRUZ_CCA_QEMU_VSOCK_FLAGS_DEFAULT: &[&str] = &[
        "-device", "vhost-vsock-pci,guest-cid={cid}",
    ];
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
            let qemu_flags = env_flags(
                "VERACRUZ_CCA_QEMU_FLAGS",
                VERACRUZ_CCA_QEMU_FLAGS_DEFAULT,
            )?;
            let qemu_console_flags = env_flags(
                "VERACRUZ_CCA_QEMU_CONSOLE_FLAGS",
                VERACRUZ_CCA_QEMU_CONSOLE_FLAGS_DEFAULT,
            )?;

            let qemu_vsock_flags = env_flags(
                "VERACRUZ_CCA_QEMU_VSOCK_FLAGS",
                VERACRUZ_CCA_QEMU_VSOCK_FLAGS_DEFAULT,
            )?;

            // temporary directory for things
            let tempdir = tempfile::tempdir()?;

            // create a temporary socket for communication
            let channel_path = tempdir.path().join("console0");
            println!("vc-server: using unix socket: {:?}", channel_path);


            let kernel_path = env::var("VERACRUZ_CCA_KERNEL_PATH")
                .unwrap_or_else(|_| VERACRUZ_CCA_KERNEL_PATH_DEFAULT.to_string());
            let initrd_path =  env::var("VERACRUZ_CCA_INITRD_PATH")
                .unwrap_or_else(|_| VERACRUZ_CCA_INITRD_PATH_DEFAULT.to_string());

            // startup qemu
            let child = Arc::new(Mutex::new(
                Command::new(&qemu_bin[0])
                    .args(&qemu_bin[1..])
                    .args(qemu_flags
                        .iter()
                        .map(|s| s.replace("{kernel_path}", &kernel_path))
                        .map(|s| s.replace("{initrd_path}", &initrd_path))
                    )
                    .args(
                        qemu_console_flags
                            .iter()
                            .map(|s| s.replace("{console0_path}", channel_path.to_str().unwrap())),
                    )
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
                    eprintln!("vc-server: qemu: stdout closed: {:?}", err);
                }
            });

            let stderr_handler = thread::spawn({
                let mut child_stderr = child.lock().unwrap().stderr.take().unwrap();
                move || {
                    let err = io::copy(&mut child_stderr, &mut io::stderr());
                    eprintln!("vc-server: qemu: stderr closed: {:?}", err);
                }
            });

            // hookup signal handler so SIGINT will teardown the child process
            let mut signals = Signals::new(&[SIGINT])?;
            let signal_handle = signals.handle();
            let signal_handler = thread::spawn({
                let child = child.clone();
                move || {
                    for sig in signals.forever() {
                        eprintln!("vc-server: qemu: Killed by signal: {:?}", sig);
                        child.lock().unwrap().kill().unwrap();
                        signal_hook::low_level::emulate_default_handler(SIGINT).unwrap();
                    }
                }
            });

            let channel = loop {
                let addr = nix::sys::socket::SockAddr::new_unix(&channel_path)?;
                let socket = nix::sys::socket::socket(
                    nix::sys::socket::AddressFamily::Unix,
                    nix::sys::socket::SockType::Stream,
                    nix::sys::socket::SockFlag::empty(),
                    None
                )?;
                match nix::sys::socket::connect(socket, &addr) {
                    Ok(_) => break socket,
                    Err(nix::Error::Sys(nix::errno::Errno::ECONNREFUSED)) => {
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    },
                    Err(e) => {
                        return Err(VeracruzServerError::NixError(e))
                    },

                }
            };

            // // connect via socket
            // let channel = loop {
            //     match UnixStream::connect(&channel_path) {
            //         Ok(channel) => {
            //             break channel;
            //         }
            //         Err(err) if err.kind() == io::ErrorKind::NotFound => {
            //             thread::sleep(Duration::from_millis(100));
            //             continue;
            //         }
            //         // NOTE I don't know why this one happens
            //         Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
            //             thread::sleep(Duration::from_millis(100));
            //             continue;
            //         }
            //         Err(err) => {
            //             return Err(CCAError::ChannelError(err).into());
            //         }
            //     };
            // };

            Ok(CCAEnclave {
                child,
                stdout_handler,
                stderr_handler,
                signal_handle,
                signal_handler,
                channel,
                tempdir,
            })
        }

        fn communicate(
            &mut self,
            request: &RuntimeManagerRequest,
        ) -> Result<RuntimeManagerResponse, VeracruzServerError> {
            // send request
            let buffer = bincode::serialize(request)?;
            io_utils::raw_fd::send_buffer(self.channel, &buffer)?;

            // recv response
            let buffer: Vec<u8> = io_utils::raw_fd::receive_buffer(self.channel)?;
            let response = bincode::deserialize::<RuntimeManagerResponse>(&buffer)?;

            Ok(response)
        }

        // NOTE close can report errors, but drop can still happen in weird cases
        fn shutdown(&mut self) -> Result<(), VeracruzServerError> {
            println!("vc-server: shutting down");
            self.signal_handle.close();
            self.child.lock().unwrap().kill()?;
            Ok(())
        }
    }



    pub struct VeracruzServerCCA {
        enclave: CCAEnclave,
    }

    impl VeracruzServerCCA {
        /// Returns `Ok(true)` iff further TLS data can be read from the socket
        /// connecting the Veracruz server and the Linux root enclave.
        /// Returns `Ok(false)` iff no further TLS data can be read.
        ///
        /// Returns an appropriate error if:
        ///
        /// 1. The request could not be serialized, or sent to the enclave.
        /// 2. The response could be not be received, or deserialized.
        /// 3. The response was received and deserialized correctly, but was of
        ///    an unexpected form.
        pub fn tls_data_needed(&mut self, session_id: u32) -> Result<bool, VeracruzServerError> {
            info!("Checking whether TLS data can be read from Runtime Manager enclave (with session: {}).", session_id);

            match self.communicate(&RuntimeManagerRequest::GetTlsDataNeeded(session_id))? {
                RuntimeManagerResponse::TlsDataNeeded(response) => {
                    info!(
                        "Runtime Manager enclave can have further TLS data read: {}.",
                        response
                    );

                    Ok(response)
                }
                otherwise => {
                    error!(
                        "Runtime Manager enclave returned unexpected response.  Received: {:?}.",
                        otherwise
                    );

                    Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                        otherwise,
                    ))
                }
            }
        }

        /// Reads TLS data from the Runtime Manager enclave.  Implicitly assumes
        /// that the Runtime Manager enclave has more data to be read.  Returns
        /// `Ok((alive_status, buffer))` if more TLS data could be read from the
        /// enclave, where `buffer` is a buffer of TLS data and `alive_status`
        /// captures the status of the TLS connection.
        ///
        /// Returns an appropriate error if:
        ///
        /// 1. The TLS data request message cannot be serialized, or transmitted
        ///    to the enclave.
        /// 2. A response is not received back from the Enclave in response to
        ///    the message sent in (1) above, or the message cannot be
        ///    deserialized.
        /// 3. The Runtime Manager enclave sends back a message indicating that
        ///    it was not expecting further TLS data to be requested.
        pub fn read_tls_data(
            &mut self,
            session_id: u32,
        ) -> Result<(bool, Vec<u8>), VeracruzServerError> {
            info!(
                "Reading TLS data from Runtime Manager enclave (with session: {}).",
                session_id
            );

            match self.communicate(&RuntimeManagerRequest::GetTlsData(session_id))? {
                RuntimeManagerResponse::TlsData(buffer, alive) => {
                    info!("{} bytes of TLS data received from Runtime Manager enclave (alive status: {}).", buffer.len(), alive);

                    Ok((alive, buffer))
                }
                otherwise => {
                    error!("Unexpected reply received back from Runtime Manager enclave.  Received: {:?}.", otherwise);

                    Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                        otherwise,
                    ))
                }
            }
        }

        fn communicate(
            &mut self,
            request: &RuntimeManagerRequest,
        ) -> Result<RuntimeManagerResponse, VeracruzServerError> {
            self.enclave.communicate(request)
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
        fn new(policy_json: &str) -> Result<Self, VeracruzServerError>
        where
            Self: Sized,
        {
            // TODO: add in dummy measurement and attestation token issuance here
            // which will use fields from the JSON policy file.
            let policy = Policy::from_json(policy_json).map_err(|e| {
                error!(
                    "Failed to parse Veracruz policy file.  Error produced: {:?}.",
                    e
                );

                VeracruzServerError::VeracruzUtilError(e)
            })?;

            // // Choose a port number at random (to reduce risk of collision
            // // with another test that is still running).
            // let port = rand::thread_rng()
            //     .gen_range(RUNTIME_MANAGER_ENCLAVE_PORT_MIN..RUNTIME_MANAGER_ENCLAVE_PORT_MAX + 1);
            // info!(
            //     "Starting runtime manager enclave (using binary {:?} and port {})",
            //     runtime_enclave_binary_path, port
            // );

            // // Ignore SIGCHLD to avoid zombie processes.
            // unsafe {
            //     signal::sigaction(
            //         signal::Signal::SIGCHLD,
            //         &signal::SigAction::new(
            //             signal::SigHandler::SigIgn,
            //             signal::SaFlags::empty(),
            //             signal::SigSet::empty(),
            //         ),
            //     )
            //     .expect("sigaction failed");
            // }

            let (device_id, challenge) = send_proxy_attestation_server_start(
                policy.proxy_attestation_server_url(),
                "psa",
                FIRMWARE_VERSION,
            )
            .map_err(VeracruzServerError::HttpError)?;

            let mut enclave = Self{enclave: CCAEnclave::spawn()?};

            let (token, csr) =
            match enclave.communicate(&RuntimeManagerRequest::Attestation(challenge, device_id))? {
                RuntimeManagerResponse::AttestationData(token, csr) => (token, csr),
                resp => {
                    return Err(VeracruzServerError::CCAError(
                        CCAError::UnexpectedRuntimeManagerResponse(resp),
                    ))
                }
            };

            let (root_cert, compute_cert) = {
                let req =
                    transport_protocol::serialize_native_psa_attestation_token(&token, &csr, device_id)
                        .map_err(VeracruzServerError::TransportProtocolError)?;
                let req = base64::encode(&req);
                let url = format!(
                    "{:}/PSA/AttestationToken",
                    policy.proxy_attestation_server_url()
                );
                let resp = post_buffer(&url, &req).map_err(VeracruzServerError::HttpError)?;
                let resp = base64::decode(&resp)?;
                let pasr = transport_protocol::parse_proxy_attestation_server_response(None, &resp)
                    .map_err(VeracruzServerError::TransportProtocolError)?;
                let cert_chain = pasr.get_cert_chain();
                let root_cert = cert_chain.get_root_cert();
                let compute_cert = cert_chain.get_enclave_cert();
                (root_cert.to_vec(), compute_cert.to_vec())
            };

            match enclave.communicate(&RuntimeManagerRequest::Initialize(
                policy_json.to_string(),
                vec![compute_cert, root_cert],
            ))? {
                RuntimeManagerResponse::Status(Status::Success) => (),
                resp => {
                    return Err(VeracruzServerError::CCAError(
                        CCAError::UnexpectedRuntimeManagerResponse(resp),
                    ))
                }
            }

            Ok(enclave)
        }

        #[inline]
        fn plaintext_data(
            &mut self,
            _data: Vec<u8>,
        ) -> Result<Option<Vec<u8>>, VeracruzServerError> {
            Err(VeracruzServerError::UnimplementedError)
        }

        fn new_tls_session(&mut self) -> Result<u32, VeracruzServerError> {
            info!("Requesting new TLS session.");

            let message: RuntimeManagerResponse = self.communicate(&RuntimeManagerRequest::NewTlsSession)?;
            match message {
                RuntimeManagerResponse::TlsSession(session_id) => {
                    info!("Enclave started new TLS session with ID: {}.", session_id);
                    Ok(session_id)
                }
                otherwise => {
                    error!(
                        "Unexpected response returned from enclave.  Received: {:?}.",
                        otherwise
                    );
                    Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                        otherwise,
                    ))
                }
            }
        }

        fn close_tls_session(&mut self, session_id: u32) -> Result<(), VeracruzServerError> {
            info!("Requesting close of TLS session with ID: {}.", session_id);

            let message: RuntimeManagerResponse = self.communicate(&RuntimeManagerRequest::CloseTlsSession(session_id))?;
            match message {
                RuntimeManagerResponse::Status(Status::Success) => {
                    info!("TLS session successfully closed.");
                    Ok(())
                }
                RuntimeManagerResponse::Status(status) => {
                    error!("TLS session close request resulted in unexpected status message.  Received: {:?}.", status);
                    Err(VeracruzServerError::Status(status))
                }
                otherwise => {
                    error!(
                        "Unexpected response returned from enclave.  Received: {:?}.",
                        otherwise
                    );
                    Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                        otherwise,
                    ))
                }
            }
        }

        fn tls_data(
            &mut self,
            session_id: u32,
            input: Vec<u8>,
        ) -> Result<(bool, Option<Vec<Vec<u8>>>), VeracruzServerError> {
            info!(
                "Sending TLS data to runtime manager enclave (with session {}).",
                session_id
            );


            let message: RuntimeManagerResponse = self.communicate(&RuntimeManagerRequest::SendTlsData(session_id, input))?;
            match message {
                RuntimeManagerResponse::Status(Status::Success) => {
                    info!("Runtime Manager enclave successfully received TLS data.")
                }
                RuntimeManagerResponse::Status(otherwise) => {
                    error!("Runtime Manager enclave failed to receive TLS data.  Response received: {:?}.", otherwise);
                    return Err(VeracruzServerError::Status(otherwise));
                }
                otherwise => {
                    error!("Runtime Manager enclave produced an unexpected response to TLS data.  Response received: {:?}.", otherwise);
                    return Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                        otherwise,
                    ));
                }
            }

            let mut active = true;
            let mut buffer = Vec::new();

            info!("Reading TLS data...");

            while self.tls_data_needed(session_id)? {
                let (alive_status, received) = self.read_tls_data(session_id)?;

                active = alive_status;
                buffer.push(received);
            }

            info!(
                "Finished reading TLS data (active = {}, received {} bytes).",
                active,
                buffer.len()
            );

            if buffer.is_empty() {
                Ok((active, None))
            } else {
                Ok((active, Some(buffer)))
            }
        }

        /// Kills the Runtime Manager enclave, then closes TCP connection.
        #[inline]
        fn shutdown_isolate(&mut self) -> Result<(), Box<dyn Error>> {
            unsafe { self.enclave.shutdown()?; };
            Ok(())

            // info!("Shutting down Linux runtime manager enclave.");

            // info!("Closing TCP connection...");
            // self.runtime_manager_socket.shutdown(Shutdown::Both)?;

            // info!("Killing and Runtime Manager process...");
            // self.runtime_manager_process.kill()?;

            // info!("TCP connection and process killed.");
            // Ok(())
        }
    }
}
