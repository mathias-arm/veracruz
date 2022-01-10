//! Linux-specific material for the Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "linux")]
pub mod veracruz_server_linux {

    use log::{error, info};

    use io_utils::http::send_proxy_attestation_server_start;
    use std::{
        env,
        net::{Shutdown, TcpStream},
        path::PathBuf,
        process::{Child, Command},
        thread::sleep,
        time::Duration,
    };

    use crate::{veracruz_server::VeracruzServer, VeracruzServerError};
    use io_utils::tcp::{receive_message, send_message};
    use policy_utils::policy::Policy;
    use veracruz_utils::platform::vm::{RuntimeManagerMessage, VMStatus};

    ////////////////////////////////////////////////////////////////////////////
    // Constants.
    ////////////////////////////////////////////////////////////////////////////

    /// IP address to use when communicating with the Runtime Manager enclave.
    const RUNTIME_MANAGER_ENCLAVE_ADDRESS: &'static str = "127.0.0.1";
    /// Port to communicate with the Runtime Manager enclave on.
    const RUNTIME_MANAGER_ENCLAVE_PORT: &'static str = "6000";
    /// The protocol to use with the proxy attestation server.
    const PROXY_ATTESTATION_PROTOCOL: &'static str = "PSA";
    /// The firmware version to use when communicating with the proxy attestation server.
    const FIRMWARE_VERSION: &'static str = "0.0";

    /// A struct capturing all the metadata needed to start and communicate with
    /// the Linux root enclave.
    pub struct VeracruzServerLinux {
        /// The socket used to communicate with the Runtime Manager enclave.
        runtime_manager_socket: TcpStream,
    }

    impl VeracruzServerLinux {
        /// Tears down the Runtime Manager enclave, then closes TCP connections.  Tries
        /// to be as liberal in ignoring erroneous conditions as possible in order to kill as
        /// many things as we can.
        fn teardown(&mut self) -> Result<bool, VeracruzServerError> {
            info!("Tearing down Linux runtime manager enclave.");

            info!("Sending shutdown message.");

            send_message(
                &mut self.runtime_manager_socket,
                &RuntimeManagerMessage::ResetEnclave,
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("Shutdown message successfully sent, awaiting response...");

            let response: RuntimeManagerMessage = receive_message(&mut self.runtime_manager_socket)
                .map_err(VeracruzServerError::SocketError)?;

            info!("Response received.");

            let response = match response {
                RuntimeManagerMessage::Status(VMStatus::Success) => {
                    info!("Enclave successfully shutdown.");

                    Ok(true)
                }
                RuntimeManagerMessage::Status(otherwise) => {
                    info!(
                        "Enclave failed to shutdown (status {:?} received.",
                        otherwise
                    );

                    Ok(false)
                }
                otherwise => {
                    error!(
                        "Unexpected response received from runtime enclave: {:?}.",
                        otherwise
                    );

                    Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise))
                }
            };

            info!("Killing TCP connections.");

            let _result = self.runtime_manager_socket.shutdown(Shutdown::Both);

            info!("TCP connection killed.");

            response
        }

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

            info!("Sending TLS data check message.");

            send_message(
                &mut self.runtime_manager_socket,
                &RuntimeManagerMessage::GetTLSDataNeeded(session_id),
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("TLS data check message successfully sent.");

            info!("Awaiting response...");

            let received: RuntimeManagerMessage = receive_message(&mut self.runtime_manager_socket)
                .map_err(VeracruzServerError::SocketError)?;

            info!("Response received.");

            match received {
                RuntimeManagerMessage::TLSDataNeeded(response) => {
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

                    Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise))
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

            info!("Sending get TLS data message.");

            send_message(
                &mut self.runtime_manager_socket,
                &RuntimeManagerMessage::GetTLSData(session_id),
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("Get TLS data message successfully sent.");

            info!("Awaiting response...");

            let received: RuntimeManagerMessage = receive_message(&mut self.runtime_manager_socket)
                .map_err(VeracruzServerError::SocketError)?;

            info!("Response received.");

            match received {
                RuntimeManagerMessage::TLSData(buffer, alive) => {
                    info!("{} bytes of TLS data received from Runtime Manager enclave (alive status: {}).", buffer.len(), alive);

                    Ok((alive, buffer))
                }
                otherwise => {
                    error!("Unexpected reply received back from Runtime Manager enclave.  Recevied: {:?}.", otherwise);

                    Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise))
                }
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Trait implementations.
    ////////////////////////////////////////////////////////////////////////////

    /// An implementation of the `Drop` trait that forcibly kills the runtime
    /// manager enclave, and closes the socket used for communicating with it, when
    /// a `VeracruzServerLinux` struct is about to go out of scope.
    impl Drop for VeracruzServerLinux {
        fn drop(&mut self) {
            info!("Dropping VeracruzServerLinux object, shutting down enclaves...");
            if let Err(error) = self.teardown() {
                error!(
                    "Failed to forcibly kill Runtime Manager and Linux Root enclave process.  Error produced: {:?}.",
                    error
                );
            }
            info!("VeracruzServerLinux object killed.");
        }
    }

    impl VeracruzServer for VeracruzServerLinux {
        /// Creates a new instance of the `VeracruzServerLinux` type.
        fn new(policy: &str) -> Result<Self, VeracruzServerError>
        where
            Self: Sized,
        {
            // TODO: add in dummy measurement and attestation token issuance here
            // which will use fields from the JSON policy file.
            let policy_json = Policy::from_json(policy).map_err(|e| {
                error!(
                    "Failed to parse Veracruz policy file.  Error produced: {:?}.",
                    e
                );

                VeracruzServerError::VeracruzUtilError(e)
            })?;

            let proxy_attestation_server_url = policy_json.proxy_attestation_server_url();

            let (challenge_id, challenge) = send_proxy_attestation_server_start(
                proxy_attestation_server_url,
                PROXY_ATTESTATION_PROTOCOL,
                FIRMWARE_VERSION,
            )
            .map_err(|e| {
                error!(
                    "Failed to start proxy attestation process.  Error received: {:?}.",
                    e
                );

                VeracruzServerError::HttpError(e)
            })?;

            let runtime_manager_address = format!(
                "{}:{}",
                RUNTIME_MANAGER_ENCLAVE_ADDRESS, RUNTIME_MANAGER_ENCLAVE_PORT
            );

            info!(
                "Establishing connection with new Runtime Manager enclave on address: {}.",
                runtime_manager_address
            );

            let mut runtime_manager_socket = TcpStream::connect(&runtime_manager_address).map_err(|e| {
                error!("Failed to connect to Runtime Manager enclave at address {}.  Error produced: {}.", runtime_manager_address, e);

                VeracruzServerError::IOError(e)
            })?;

            info!(
                "Connected to Runtime Manager enclave at address {}.",
                runtime_manager_address
            );

            info!("Sending Initialize message.");

            send_message(
                &mut runtime_manager_socket,
                &RuntimeManagerMessage::Initialize(policy.to_string(), challenge, challenge_id),
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("Initialize message successfully sent.  Awaiting response...");

            let received: RuntimeManagerMessage = receive_message(&mut runtime_manager_socket).map_err(|e| {
                error!("Failed to receive response to runtime manager enclave initialize message.  Error received: {:?}.", e);

                VeracruzServerError::SocketError(e)
            })?;

            match received {
                RuntimeManagerMessage::AttestationData(attest) => {
                    info!(
                        "Response to attestation message successfully received ({} bytes).",
                        attest.len()
                    );
                }
                RuntimeManagerMessage::Status(VMStatus::Success) => {
                    info!("Runtime manager enclave successfully initialized...");
                    ()
                }
                RuntimeManagerMessage::Status(otherwise) => {
                    error!(
                        "Runtime manager enclave returned non-Success error code: {:?}.",
                        otherwise
                    );

                    return Err(VeracruzServerError::VMStatus(otherwise));
                }
                otherwise => {
                    error!(
                        "Unexpected response from runtime manager enclave: {:?}.",
                        otherwise
                    );

                    return Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise));
                }
            }

            Ok(Self{ runtime_manager_socket })
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

            send_message(
                &mut self.runtime_manager_socket,
                &RuntimeManagerMessage::NewTLSSession,
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("New TLS session message successfully sent.");

            info!("Awaiting response...");

            let message: RuntimeManagerMessage = receive_message(&mut self.runtime_manager_socket)
                .map_err(VeracruzServerError::SocketError)?;

            match message {
                RuntimeManagerMessage::TLSSession(session_id) => {
                    info!("Enclave started new TLS session with ID: {}.", session_id);
                    Ok(session_id)
                }
                otherwise => {
                    error!(
                        "Unexpected response returned from enclave.  Received: {:?}.",
                        otherwise
                    );
                    Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise))
                }
            }
        }

        fn close_tls_session(&mut self, session_id: u32) -> Result<(), VeracruzServerError> {
            info!("Requesting close of TLS session with ID: {}.", session_id);

            send_message(
                &mut self.runtime_manager_socket,
                &RuntimeManagerMessage::CloseTLSSession(session_id),
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("Close TLS session message successfully sent.");

            info!("Awaiting response...");

            let message: RuntimeManagerMessage = receive_message(&mut self.runtime_manager_socket)
                .map_err(VeracruzServerError::SocketError)?;

            info!("Response received.");

            match message {
                RuntimeManagerMessage::Status(VMStatus::Success) => {
                    info!("TLS session successfully closed.");
                    Ok(())
                }
                RuntimeManagerMessage::Status(status) => {
                    error!("TLS session close request resulted in unexpected status message.  Received: {:?}.", status);
                    Err(VeracruzServerError::VMStatus(status))
                }
                otherwise => {
                    error!(
                        "Unexpected response returned from enclave.  Received: {:?}.",
                        otherwise
                    );
                    Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise))
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

            send_message(
                &mut self.runtime_manager_socket,
                &RuntimeManagerMessage::SendTLSData(session_id, input),
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("TLS data successfully sent.");

            info!("Awaiting response...");

            let message: RuntimeManagerMessage = receive_message(&mut self.runtime_manager_socket)
                .map_err(VeracruzServerError::SocketError)?;

            info!("Response received.");

            match message {
                RuntimeManagerMessage::Status(VMStatus::Success) => {
                    info!("Runtime Manager enclave successfully received TLS data.")
                }
                RuntimeManagerMessage::Status(otherwise) => {
                    error!("Runtime Manager enclave failed to receive TLS data.  Response received: {:?}.", otherwise);
                    return Err(VeracruzServerError::VMStatus(otherwise));
                }
                otherwise => {
                    error!("Runtime Manager enclave produced an unexpected response to TLS data.  Response received: {:?}.", otherwise);
                    return Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise));
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

        /// Kills the Linux Root enclave, all spawned Runtime Manager enclaves, and all open
        /// TCP connections and processes that we have a handle to.
        #[inline]
        fn close(&mut self) -> Result<bool, VeracruzServerError> {
            info!("Closing...");
            self.teardown()
        }
    }
}
