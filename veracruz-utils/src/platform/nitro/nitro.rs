//! Structs needed for AWS Nitro Enclaves, both inside and outside of the
//! enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use serde::{Deserialize, Serialize};

/// The Status value returned by the Nitro enclave for operations
/// This is intended to be received as a bincode serialized
/// `NitroRootEnclaveMessage::Status`
#[derive(Serialize, Deserialize, Debug)]
pub enum NitroStatus {
    /// The operation generating the message succeeded
    Success,
    /// The operation generating the message failed
    Fail,
    /// The requested operation is not yet implemented
    Unimplemented,
}

/// An enumerated type describing messages passed between the Runtime Manager
/// and the Nitro Root Enclave
/// These messages are inteded to be serialized using bincode before transport,
/// and deserialized using bincode after transport
#[derive(Serialize, Deserialize, Debug)]
pub enum NitroRootEnclaveMessage {
    /// A message generated by an operation that did not return data, but did
    /// return a status.
    /// Most operations return data, but if they fail, they will return a
    /// status set to `NitroStatus::Fail` (or `NitroStatus::Unimplemented` if
    /// it is not implemented).
    /// Parameters:
    /// NitroStatus - the Status
    Status(NitroStatus),
    /// A request to fetch the firmware version from the Nitro Root Enclave
    FetchFirmwareVersion,
    /// A response to the `FetchFirmwareVersion` message, it contains the
    /// firmware version of the Nitro Root Enclave, as a string
    FirmwareVersion(String),
    /// A request to set the certificate chain for the Root Enclave
    SetCertChain(Vec<u8>, Vec<u8>),
    /// A request to start the native attestation process.
    /// This is usually initiated from the Proxy Attestation Service
    /// The values:
    /// Vec<u8> - The 128-bit challenge value generated by the caller
    /// i32     - A device ID set by the caller. Will be used by the enclave
    ///           in future operations
    NativeAttestation(Vec<u8>, i32),
    /// A response to the NativeAttestation message. This is generated by the
    /// enclave.
    /// The parameters:
    /// Vec<u8> - The native attestation token generated by the enclave
    /// Vec<u8> - The Certificate Signing Request (CSR), generated by the root
    ///           enclave, to be used by the proxy service to generate the
    ///           Root Enclave Certificate
    TokenData(Vec<u8>, Vec<u8>),
    /// A request to start the proxy attestation process for the caller. This
    /// request will result in a `ChallengeData` response.
    StartProxy,
    /// A response to the `StartProxy` message.
    /// Vec<u8> - The 128-bit challenge value generated by the root enclave
    /// i32     - The challenge ID generated by the root enclave to match the
    ///           challenge to future requests
    ChallengeData(Vec<u8>, i32),
    /// A request (initiated by the Runtime Manager enclave) to start the
    /// proxy attestation process.
    /// The parameters:
    /// Vec<u8> - The native attestation document value, generated by the
    ///           caller.
    /// i32     - The challenge ID value received in the `ChallengeData`
    ///           message letting the root enclave know which challenge value
    ///           to check for in the token
    ProxyAttestation(Vec<u8>, i32),
    /// A response to the ProxyAttestation message. This is the certificate that
    /// the compute enclave will send to it's clients.
    /// The parameters:
    /// Vec<u8> - the compute enclave certificate
    /// Vec<u8> - The root enclave certificate
    /// Vec<u8> - the CA root certificate
    CertChain(Vec<Vec<u8>>),
    /// A successful response to a request that just contains a status
    /// (for example, a response to a SetCertChain request)
    Success,
}

/// An enumerated type describing messages passed between to/from the Runtime
/// Manager enclave (These originate from the Untrusted Pass-through (Veracruz
/// server)
/// These messages are inteded to be serialized using bincode before transport,
/// and deserialized using bincode after transport
#[derive(Serialize, Deserialize, Debug)]
pub enum RuntimeManagerMessage {
    /// A message generated by an operation that did not return data, but did
    /// return a status.
    /// Most operations return data, but if they fail, they will return a
    /// status set to `NitroStatus::Fail` (or `NitroStatus::Unimplemented` if
    /// it is not implmeneted).
    /// Parameters:
    /// NitroStatus - the Status
    Status(NitroStatus),
    /// A request to start the attestation process
    /// parameters:
    /// Vec<u8> - the challenge value
    /// i32     - the challenge ID
    Attestation(Vec<u8>, i32),
    /// The response to the `Attestation` request.
    /// parameters:
    /// Vec<u8> - The nitro attestation document from the enclave
    AttestationData(Vec<u8>),
    /// A request to initialize the Runtime Manager enclave with the provided
    /// policy and certificate
    /// parameters:
    /// String  - The policy, in JSON format
    /// Vec<Vec<u8>> - The certificate chain for the enclave
    Initialize(String, Vec<Vec<u8>>),
    /// A request to establish a new TLS session with the enclave
    NewTLSSession,
    /// The response to the `NewTLSSession` message
    /// Parameters:
    /// u32 - The Session ID of the created TLS Session
    TLSSession(u32),
    /// A request to close an already established TLS session
    /// Parameters:
    /// u32 - The Session ID of the session to be closed
    CloseTLSSession(u32),
    /// Request to determine if the TLS Session needs data to be sent to it
    /// Parameters:
    /// u32 - The Session ID of the TLS session
    GetTLSDataNeeded(u32),
    /// Response to `GetTLSDataNeeded` message
    /// Parameters:
    /// bool - is data needed?
    TLSDataNeeded(bool),
    /// Request to send TLS data to the enclave
    /// Parameters:
    /// u32 - the Session ID of the TLS Session associated with the data
    /// Vec<u8> - The TLS Data
    SendTLSData(u32, Vec<u8>),
    /// Request TLS Data from the enclave
    /// Parameters:
    /// u32 - the Session ID of the TLS Session to request data from
    GetTLSData(u32),
    /// Response to `GetTLSData`
    /// Parameters:
    /// Vec<u8> - The TLS Data. May be empty
    /// bool    - a flag indicating if the TLS session is still alive
    TLSData(Vec<u8>, bool), // TLS Data, alive_flag
    /// A request to reset the enclave
    ResetEnclave,
}
