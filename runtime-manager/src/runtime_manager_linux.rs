//! Linux-specific material for the Runtime Manager enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::managers::{
    session_manager::{
        close_session, generate_csr, get_data, get_data_needed, init_session_manager,
        load_cert_chain, load_policy, new_session, send_data,
    },
    RuntimeManagerError,
};
use bincode::{deserialize, serialize};
use clap::{App, Arg};
use io_utils::fd::{receive_buffer, send_buffer};
use log::{error, info};
use std::net::TcpListener;
use veracruz_utils::platform::vm::{RuntimeManagerMessage, VMStatus};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// Incoming address to listen on.  Note that `0.0.0.0` implies all addresses.
const INCOMING_ADDRESS: &'static str = "0.0.0.0";
/// The runtime manager enclave's private key.
///
/// *WARNING*: this is complete insecure.
///
/// Note that each instance of the Linux runtime manager has the same private
/// key.  This is because the attestation process on Linux is not fully
/// implemented, and nor can it ever really be without relying on e.g., the
/// presence of a hardware root of trust and a measured boot.  As a result, we
/// have "mocked" the Linux attestation process here, using the same private key
/// for all Linux runtime enclaves as a simple way of implementing the dummy
/// attestation process, rather than autogenerating a new key for each instance.
/// For a real implementation of attestation, see the implementation for AWS
/// Nitro Enclaves.
static ROOT_PRIVATE_KEY: [u8; 32] = [
    0xe6, 0xbf, 0x1e, 0x3d, 0xb4, 0x45, 0x42, 0xbe, 0xf5, 0x35, 0xe7, 0xac, 0xbc, 0x2d, 0x54, 0xd0,
    0xba, 0x94, 0xbf, 0xb5, 0x47, 0x67, 0x2c, 0x31, 0xc1, 0xd4, 0xee, 0x1c, 0x05, 0x76, 0xa1, 0x44,
];

////////////////////////////////////////////////////////////////////////////////
// Initialization.
////////////////////////////////////////////////////////////////////////////////

/// Initializes the runtime manager, bringing up a new session manager instance
/// with the `policy_json` encoding of the policy file.
fn initialize(policy_json: String) -> RuntimeManagerMessage {
    if let Err(e) = init_session_manager() {
        error!(
            "Failed to initialize session manager.  Error produced: {:?}.",
            e
        );

        return RuntimeManagerMessage::Status(VMStatus::Fail);
    }

    if let Err(e) = load_policy(&policy_json) {
        error!("Failed to load policy.  Error produced: {:?}.", e);

        return RuntimeManagerMessage::Status(VMStatus::Fail);
    }

    info!("Session manager initialized with policy.");

    RuntimeManagerMessage::Status(VMStatus::Success)
}

////////////////////////////////////////////////////////////////////////////////
// Native attestation (dummy implementation).
////////////////////////////////////////////////////////////////////////////////

fn native_attestation(csr: Vec<u8>, challenge: Vec<u8>) -> Result<Vec<u8>, RuntimeManagerError> {
    unimplemented!()
}

////////////////////////////////////////////////////////////////////////////////
// Entry point and message dispatcher.
////////////////////////////////////////////////////////////////////////////////

/// Main entry point for Linux: parses command line arguments to find the port
/// number we should be listening on for incoming connections from the Veracruz
/// server.  Parses incoming messages, and acts on them.
pub fn linux_main() -> Result<(), RuntimeManagerError> {
    env_logger::init();

    let matches = App::new("Linux runtime manager enclave")
        .author("The Veracruz Development Team")
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .takes_value(true)
                .required(true)
                .help("Port to listen for new connections on.")
                .value_name("PORT"),
        )
        .get_matches();

    let port = if let Some(port) = matches.value_of("port") {
        info!("Received {} as port to listen on.", port);
        port
    } else {
        error!("Did not receive any port to listen on.  Exiting...");
        return Err(RuntimeManagerError::CommandLineArguments);
    };

    let address = format!("{}:{}", INCOMING_ADDRESS, port);

    info!("Preparing to listen on {}.", address);

    let listener = TcpListener::bind(&address).map_err(|e| {
        error!("Could not bind TCP listener.  Error produced: {}.", e);

        RuntimeManagerError::IOError(e)
    })?;

    info!("TCP listener created on {}.", address);

    let (mut fd, client_addr) = listener.accept().map_err(|ioerr| {
        error!(
            "Failed to accept any incoming TCP connection.  Error produced: {}.",
            ioerr
        );
        RuntimeManagerError::IOError(ioerr)
    })?;

    info!("TCP listener connected on {:?}.", client_addr);

    let mut abort = false;

    while !abort {
        info!("Listening for incoming message...");

        let received_buffer: Vec<u8> = receive_buffer(&mut fd).map_err(|err| {
            error!("Failed to receive message.  Error produced: {}.", err);
            RuntimeManagerError::IOError(err)
        })?;

        let received_message: RuntimeManagerMessage =
            deserialize(&received_buffer).map_err(|derr| {
                error!(
                    "Failed to deserialize received message.  Error produced: {}.",
                    derr
                );
                RuntimeManagerError::BincodeError(derr)
            })?;

        info!("Received message: {:?}.", received_message);

        let return_message = match received_message {
            RuntimeManagerMessage::Initialize(policy_json) => {
                info!("Initializing enclave with policy: {:?}.", policy_json);

                initialize(policy_json)
            }
            RuntimeManagerMessage::Attestation(challenge, _challenge_id) => {
                info!(
                    "Generating attestation data from challenge {:?}.",
                    challenge
                );

                let csr = generate_csr().map_err(|e| {
                    error!(
                        "Failed to generate certificate signing request.  Error produced: {:?}.",
                        e
                    );

                    e
                })?;

                let token = native_attestation(csr, challenge).map_err(|e| {
                    error!(
                        "Failed to generate native attestation token.  Error produced: {:?}.",
                        e
                    );

                    e
                })?;

                RuntimeManagerMessage::AttestationData(token)
            }
            RuntimeManagerMessage::SetCertificateChain(chain) => {
                info!("Setting certificate chain.");

                load_cert_chain(&chain).map_err(|e| {
                    error!("Failed to set certificate chain.  Error produced: {:?}.", e);

                    e
                })?;

                RuntimeManagerMessage::Status(VMStatus::Success)
            }
            RuntimeManagerMessage::NewTLSSession => {
                info!("Initiating new TLS session.");

                new_session()
                    .map(|session_id| RuntimeManagerMessage::TLSSession(session_id))
                    .unwrap_or_else(|e| {
                        error!(
                            "Could not initiate new TLS session.  Error produced: {:?}.",
                            e
                        );
                        RuntimeManagerMessage::Status(VMStatus::Fail)
                    })
            }
            RuntimeManagerMessage::CloseTLSSession(session_id) => {
                info!("Closing TLS session.");

                close_session(session_id)
                    .map(|_e| RuntimeManagerMessage::Status(VMStatus::Success))
                    .unwrap_or_else(|e| {
                        error!("Failed to close TLS session.  Error produced: {:?}.", e);
                        RuntimeManagerMessage::Status(VMStatus::Fail)
                    })
            }
            RuntimeManagerMessage::GetTLSDataNeeded(session_id) => {
                info!("Checking whether TLS data is needed.");

                get_data_needed(session_id)
                    .map(|needed| RuntimeManagerMessage::TLSDataNeeded(needed))
                    .unwrap_or_else(|e|{
                        error!("Failed to check whether further TLS data needed.  Error produced: {:?}.", e);
                        RuntimeManagerMessage::Status(VMStatus::Fail)
                    })
            }
            RuntimeManagerMessage::GetTLSData(session_id) => {
                info!("Retrieving TLS data.");

                get_data(session_id)
                    .map(|(active, data)| RuntimeManagerMessage::TLSData(data, active))
                    .unwrap_or_else(|e| {
                        error!("Failed to retrieve TLS data.  Error produced: {:?}.", e);
                        RuntimeManagerMessage::Status(VMStatus::Fail)
                    })
            }
            RuntimeManagerMessage::SendTLSData(session_id, tls_data) => {
                info!("Sending TLS data.");

                send_data(session_id, &tls_data)
                    .map(|_| RuntimeManagerMessage::Status(VMStatus::Success))
                    .unwrap_or_else(|e| {
                        error!("Failed to send TLS data.  Error produced: {:?}.", e);
                        RuntimeManagerMessage::Status(VMStatus::Fail)
                    })
            }
            RuntimeManagerMessage::ResetEnclave => {
                info!("Shutting down enclave.");

                abort = true;

                RuntimeManagerMessage::Status(VMStatus::Success)
            }
            otherwise => {
                error!("Received unknown or unimplemented opcode: {:?}.", otherwise);
                RuntimeManagerMessage::Status(VMStatus::Unimplemented)
            }
        };

        let return_buffer = serialize(&return_message).map_err(|serr| {
            error!(
                "Failed to serialize returned message.  Error produced: {}.",
                serr
            );
            RuntimeManagerError::BincodeError(serr)
        })?;

        info!("Sending message: {:?}.", return_message);

        send_buffer(&mut fd, &return_buffer).map_err(|e| {
            error!("Failed to send message.  Error produced: {}.", e);
            RuntimeManagerError::IOError(e)
        })?;
    }

    Ok(())
}
