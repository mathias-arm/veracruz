//! Requests and responses to the Runtime Manager
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use serde::{Deserialize, Serialize};

///////////////////////////////////////////////////////////////////////////////
// Status messages.
///////////////////////////////////////////////////////////////////////////////

/// The Status value returned by the enclave/application for operations.
/// This is intended to be received as a bincode serialized
/// `RootEnclaveMessage::Status`
#[derive(Serialize, Deserialize, Debug)]
pub enum Status {
    /// The operation generating the message succeeded
    Success,
    /// The operation generating the message failed
    Fail,
    /// The requested operation is not yet implemented
    Unimplemented,
}

///////////////////////////////////////////////////////////////////////////////
// Command-and-control messages for the runtime manager.
///////////////////////////////////////////////////////////////////////////////

/// An enumerated type describing request messages passed to the Runtime
/// Manager enclave (these originate from the Untrusted Pass-through (Veracruz
/// server).
/// These messages are inteded to be serialized using bincode before transport,
/// and deserialized using bincode after transport.
#[derive(Serialize, Deserialize, Debug)]
pub enum RuntimeManagerRequest {
    /// A request to start the attestation process
    /// parameters:
    /// Vec<u8> - the challenge value
    /// i32     - the challenge ID
    Attestation(Vec<u8>, i32),
    /// A request to close an already established TLS session.  Parameters in
    /// order are:
    /// - The Session ID of the session to be closed.
    CloseTlsSession(u32),
    /// Request TLS data from the enclave.  Parameters in order are:
    /// - The Session ID of the TLS session to request data from.
    GetTlsData(u32),
    /// Request to determine if the TLS Session needs data to be sent to it.
    /// Parameters in order are:
    /// - The Session ID of the TLS session.
    GetTlsDataNeeded(u32),
    /// A request to initialize the Runtime Manager enclave with the provided
    /// policy and certificate (for Nitro).
    /// parameters:
    /// String  - The policy, in JSON format
    /// Vec<Vec<u8>> - The certificate chain for the enclave
    Initialize(String, Vec<Vec<u8>>),
    /// A request to establish a new TLS session with the enclave.
    NewTlsSession,
    /// Request to send TLS data to the enclave.  Parameters in order are:
    /// - The Session ID of the TLS Session associated with the data,
    /// - The TLS data.
    SendTlsData(u32, Vec<u8>),
}

/// An enumerated type describing response messages received from the Runtime
/// Manager enclave (these originate from the Untrusted Pass-through (Veracruz
/// server) in response to the request messages, above.
/// These messages are inteded to be serialized using bincode before transport,
/// and deserialized using bincode after transport.
#[derive(Serialize, Deserialize, Debug)]
pub enum RuntimeManagerResponse {
    #[cfg(feature = "nitro")]
    /// The response to the `Attestation` request.
    /// parameters:
    /// Vec<u8> - The nitro attestation document from the enclave
    AttestationData(Vec<u8>),
    #[cfg(any(feature = "icecap", feature = "linux", feature = "cca"))]
    /// The response to the `Attestation` request.  Parameters (in order) are:
    /// - A byte encoding of the PSA attestation token,
    /// - A byte encoding of the Certificate Signing Request.
    AttestationData(Vec<u8>, Vec<u8>),
    /// A message generated by an operation that did not return data, but did
    /// return a status.  Most operations return data, but if they fail, they
    /// will return a status set to `Status::Fail` (or
    /// `Status::Unimplemented` if it is not implmeneted).  Parameters in
    /// order are:
    /// - The status.
    Status(Status),
    /// Response to `GetTLSData`.  Parameters in order are:
    /// - The TLS data, which may be empty.
    /// - A flag indicating if the TLS session is still alive.
    TlsData(Vec<u8>, bool),
    /// Response to `GetTlsDataNeeded` message.  Parameters in order are:
    /// - Is data needed?
    TlsDataNeeded(bool),
    /// The response to the `NewTLSSession` message.  Parameters in order are:
    /// - The Session ID of the created TLS session.
    TlsSession(u32),
}
