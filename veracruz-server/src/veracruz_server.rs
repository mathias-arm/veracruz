//! Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "icecap")]
use crate::veracruz_server_icecap::IceCapError;
#[cfg(feature = "cca")]
use crate::veracruz_server_cca::veracruz_server_cca::CCAError;
use actix_web::{error, http::StatusCode, HttpResponse, HttpResponseBuilder};
#[cfg(feature = "nitro")]
use base64;
use err_derive::Error;
#[cfg(feature = "nitro")]
use io_utils::nitro::NitroError;
use io_utils::{error::SocketError, http::HttpError};
use rustls::Error as TLSError;
use std::error::Error;

pub type VeracruzServerResponder = Result<String, VeracruzServerError>;

#[derive(Debug, Error)]
pub enum VeracruzServerError {
    #[error(display = "VeracruzServer: TLSError: {:?}.", _0)]
    TLSError(#[error(source)] TLSError),
    #[error(display = "VeracruzServer: HexError: {:?}.", _0)]
    HexError(#[error(source)] hex::FromHexError),
    #[error(display = "VeracruzServer: Utf8Error: {:?}.", _0)]
    Utf8Error(#[error(source)] std::str::Utf8Error),
    #[error(display = "VeracruzServer: FromUtf8Error: {:?}.", _0)]
    FromUtf8Error(#[error(source)] std::string::FromUtf8Error),
    #[error(display = "VeracruzServer: SerdeJsonError: {:?}.", _0)]
    SerdeJsonError(#[error(source)] serde_json::Error),
    #[error(
        display = "VeracruzServer: Function {} received non-success status: {:?}",
        _0,
        _1
    )]
    ResponseError(&'static str, transport_protocol::ResponseStatus),
    #[error(display = "VeracruzServer: IOError: {:?}.", _0)]
    IOError(#[error(source)] std::io::Error),
    #[error(display = "VeracruzServer: Base64Error: {:?}.", _0)]
    Base64Error(#[error(source)] base64::DecodeError),
    #[error(display = "VeracruzServer: TLSError: unspecified.")]
    TLSUnspecifiedError,
    #[error(display = "VeracruzServer: Invalid cipher suite: {:?}", _0)]
    InvalidCiphersuiteError(String),
    #[error(display = "VeracruzServer: webpki: {:?}.", _0)]
    WebpkiError(#[error(source)] webpki::Error),
    #[error(display = "VeracruzServer: webpki: {:?}.", _0)]
    WebpkiDNSNameError(#[error(source)] rustls::client::InvalidDnsNameError),
    #[error(display = "VeracruzServer: Failed to obtain lock {:?}.", _0)]
    LockError(String),
    #[error(display = "VeracruzServer: TryIntoError: {}.", _0)]
    TryIntoError(#[error(source)] std::num::TryFromIntError),
    #[error(display = "VeracruzServer: ParseIntError: {}.", _0)]
    ParseIntError(#[error(source)] std::num::ParseIntError),
    #[error(display = "VeracruzServer: MpscSendError (of type ()) Error: {}.", _0)]
    MpscSendEmptyError(#[error(source)] std::sync::mpsc::SendError<()>),
    #[error(
        display = "VeracruzServer: MpscSendError (of type std::sync::mpsc::SendError<(u32, std::vec::Vec<u8>)>) Error: {}.",
        _0
    )]
    MpscSendU32VecU8Error(#[error(source)] std::sync::mpsc::SendError<(u32, std::vec::Vec<u8>)>),
    #[error(
        display = "VeracruzServer: MpscSendError (of type std::vec::Vec<u8>) Error: {}.",
        _0
    )]
    MpscSendVecU8Error(#[error(source)] std::sync::mpsc::SendError<std::vec::Vec<u8>>),
    #[error(display = "VeracruzServer: Mpsc TryRecvError: {}.", _0)]
    MpscTryRecvError(#[error(source)] std::sync::mpsc::TryRecvError),
    /// A HTTP error was produced.
    #[error(display = "Http error: {}.", _0)]
    HttpError(HttpError),
    #[cfg(any(feature = "cca", feature = "linux", feature = "nitro"))]
    #[error(display = "VeracruzServer: BincodeError: {:?}", _0)]
    BincodeError(bincode::ErrorKind),
    #[cfg(any(feature = "cca", feature = "nitro", feature = "linux"))]
    #[error(display = "VeracruzServer: Status: {:?}", _0)]
    Status(veracruz_utils::runtime_manager_message::Status),
    #[cfg(any(feature = "cca", feature = "linux", feature = "nitro"))]
    #[error(
        display = "VeracruzServer: Received Invalid Runtime Manager response: {:?}",
        _0
    )]
    InvalidRuntimeManagerResponse(veracruz_utils::runtime_manager_message::RuntimeManagerResponse),
    #[cfg(feature = "nitro")]
    #[error(
        display = "VeracruzServer: Received Invalid Nitro Root Enclave Message: {:?}",
        _0
    )]
    #[cfg(feature = "nitro")]
    InvalidNitroRootEnclaveMessage(veracruz_utils::platform::nitro::nitro::NitroRootEnclaveMessage),
    #[cfg(any(feature = "cca", feature = "linux", feature = "nitro"))]
    #[error(display = "VeracruzServer: Received Invalid Protocol Buffer Message")]
    InvalidProtoBufMessage,
    #[cfg(any(feature = "cca", feature = "nitro"))]
    #[error(display = "VeracruzServer: Nix Error: {:?}", _0)]
    NixError(#[error(source)] nix::Error),
    #[cfg(feature = "nitro")]
    #[error(display = "VeracruzServer: Serde Error")]
    SerdeError,
    #[cfg(any(feature = "nitro", feature = "cca"))]
    #[error(display = "VeracruzServer: Veracruz Socket Error:{:?}", _0)]
    VeracruzSocketError(#[error(source)] io_utils::error::SocketError),
    #[cfg(feature = "nitro")]
    #[error(display = "VeracruzServer: Nitro Error:{:?}", _0)]
    NitroError(#[error(source)] NitroError),
    #[cfg(feature = "icecap")]
    #[error(display = "VeracruzServer: IceCap error: {:?}", _0)]
    IceCapError(IceCapError),
    #[cfg(feature = "cca")]
    #[error(display = "VeracruzServer: CCA error: {:?}", _0)]
    CCAError(CCAError),
    #[error(display = "VeracruzServer: Enclave function {} failed.", _0)]
    EnclaveCallError(&'static str),
    #[error(
        display = "VeracruzServer: Missing {}, which is caused by non-existence, empty field, null, zero, etc.",
        _0
    )]
    MissingFieldError(&'static str),
    #[error(
        display = "VeracruzServer: MismatchError: variable `{}` mismatch, expected {:?} but received {:?}.",
        variable,
        expected,
        received
    )]
    MismatchError {
        variable: &'static str,
        expected: std::vec::Vec<u8>,
        received: std::vec::Vec<u8>,
    },
    #[error(display = "VeracruzServer: TransportProtocolError: {:?}.", _0)]
    TransportProtocolError(#[error(source)] transport_protocol::TransportProtocolError),
    #[error(display = "VeracruzServer: PolicyError: {:?}.", _0)]
    VeracruzUtilError(#[error(source)] policy_utils::error::PolicyError),
    #[error(display = "VeracruzServer: Postcard Error: {:?}.", _0)]
    PostcardError(#[error(source)] postcard::Error),
    #[error(display = "VeracruzServer: Join Error: {:?}.", _0)]
    JoinError(std::boxed::Box<dyn std::any::Any + Send + 'static>),
    #[error(
        display = "VeracruzServer: Invalid length of variable `{}`, expected {}",
        _0,
        _1
    )]
    InvalidLengthError(&'static str, usize),
    #[error(display = "VeracruzServer: Uninitialized enclave.")]
    UninitializedEnclaveError,
    #[error(display = "VeracruzServer: Unknown attestation protocol.")]
    UnknownAttestationTokenError,
    #[error(display = "VeracruzServer: Unsupported request (not implemented in this platform).")]
    UnimplementedRequestError,
    #[error(display = "VeracruzServer: Unsupported request (not found).")]
    UnsupportedRequestError,
    #[error(display = "VeracruzServer: Invalid request format")]
    InvalidRequestFormatError,
    #[error(display = "VeracruzServer: Received non-success post status.")]
    ReceivedNonSuccessPostStatusError,
    #[error(display = "VeracruzServer: Debug is disable.")]
    DebugIsDisableError,
    #[error(display = "VeracruzServer: Direct response message {}.", _0)]
    DirectMessageError(String, StatusCode),
    #[error(display = "VeracruzServer: Error message {}.", _0)]
    DirectStrError(&'static str),
    #[error(display = "VeracruzServer: Unimplemented")]
    UnimplementedError,
    #[error(display = "VeracruzServer: Invalid runtime manager hash")]
    InvalidRuntimeManagerHash,
    /// Transport protocol buffer handling returned an error
    #[cfg(feature = "nitro")]
    #[error(display = "VeracruzServer: TransportProtocol error:{}", _0)]
    TransportProtocol(transport_protocol::custom::TransportProtocolError),
    /// A base64 decode error occurred
    // #[cfg(feature = "nitro")]
    #[error(display = "VeracruzServer: Base64 Decode error:{:?}", _0)]
    Base64Decode(base64::DecodeError),
    /// Some socket-related functionality failed.
    #[error(display = "VeracruzServer: socket error:{:?}", _0)]
    SocketError(SocketError),
    /// A remote http server returned a non-success (200) status
    #[cfg(feature = "nitro")]
    #[error(display = "NitroServer: Non-Success HTTP Response received")]
    NonSuccessHttp,
}

impl<T> From<std::sync::PoisonError<T>> for VeracruzServerError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        VeracruzServerError::LockError(format!("{:?}", error))
    }
}

impl error::ResponseError for VeracruzServerError {
    fn error_response(&self) -> HttpResponse {
        HttpResponseBuilder::new(self.status_code()).body(format!("{:?}", self))
    }
    fn status_code(&self) -> StatusCode {
        match self {
            VeracruzServerError::DirectMessageError(_, e) => *e,
            VeracruzServerError::UnimplementedRequestError
            | VeracruzServerError::UnknownAttestationTokenError => StatusCode::NOT_IMPLEMENTED,
            VeracruzServerError::UnsupportedRequestError => StatusCode::NOT_FOUND,
            _otherwise => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[cfg(feature = "nitro")]
impl From<std::boxed::Box<bincode::ErrorKind>> for VeracruzServerError {
    fn from(error: std::boxed::Box<bincode::ErrorKind>) -> Self {
        VeracruzServerError::BincodeError(*error)
    }
}

pub trait VeracruzServer {
    fn new(policy: &str) -> Result<Self, VeracruzServerError>
    where
        Self: Sized;

    fn plaintext_data(&mut self, _data: Vec<u8>) -> Result<Option<Vec<u8>>, VeracruzServerError> {
        // this function is not strictly needed, should we remove at some point?
        unimplemented!();
    }

    fn new_tls_session(&mut self) -> Result<u32, VeracruzServerError>;

    fn close_tls_session(&mut self, session_id: u32) -> Result<(), VeracruzServerError>;

    // The first bool indicates if the enclave is active, and the second vec contains the response
    fn tls_data(
        &mut self,
        session_id: u32,
        input: Vec<u8>,
    ) -> Result<(bool, Option<Vec<Vec<u8>>>), VeracruzServerError>;

    fn shutdown_isolate(&mut self) -> Result<(), Box<dyn Error>>;
}
