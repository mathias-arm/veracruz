//! Platform-specific material.
//!
//! Material specific to a particular platform that Veracruz supports, and which
//! does not fit elsewhere.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

pub mod error;
#[cfg(feature = "linux")]
pub mod linux;
#[cfg(feature = "nitro")]
pub mod nitro;
#[cfg(feature = "tz")]
pub mod tz;
#[cfg(any(feature = "linux", feature = "nitro"))]
pub mod vm;

#[cfg(feature = "std")]
use error::PlatformError;
#[cfg(feature = "std")]
use std::{
    fmt,
    str::FromStr,
};

/// A type capturing the platform the enclave is running on.
#[derive(Debug)]
pub enum Platform {
    /// The enclave is running as a Linux process, either unprotected or as part of a
    /// protected Virtual Machine-like enclaving mechanism.
    Linux,
    /// The enclave is running under Intel SGX.
    SGX,
    /// The enclave is running under Arm TrustZone.
    TrustZone,
    /// The enclave is running under AWS Nitro enclaves.
    Nitro,
    /// The mock platform for unit testing (client unit tests, at the moment).
    Mock,
}

#[cfg(feature = "std")]
impl FromStr for Platform {
    type Err = PlatformError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sgx"       => Ok(Platform::SGX),
            "trustzone" => Ok(Platform::TrustZone),
            "nitro"     => Ok(Platform::Nitro),
            "linux"     => Ok(Platform::Linux),
            _           => Err(PlatformError::InvalidPlatform(format!("{}", s))),
        }
    }
}

#[cfg(feature = "std")]
impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Platform::Linux      => write!(f, "linux"),
            Platform::SGX        => write!(f, "sgx"),
            Platform::TrustZone  => write!(f, "trustzone"),
            Platform::Nitro      => write!(f, "nitro"),
            Platform::Mock       => write!(f, "mock"),
        }
    }
}
