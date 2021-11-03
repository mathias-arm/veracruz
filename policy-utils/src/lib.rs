//! Types and definitions relating to the Veracruz global policy.
//!
//! The global policy captures important information about a Veracruz
//! computation that principals need to audit before they enroll themselves in a
//! computation.  This includes:
//!
//! - The identities and roles of every principals in the computation,
//! - Important URLs, both for the Veracruz bridge server on the untrusted
//!   host's machine and the Veracruz proxy attestation service,
//! - Permissible ciphersuites for TLS connections between clients and the
//!   trusted Veracruz runtime, as well as the hashes of the expected program
//!   and of the trusted Veracruz runtime itself,
//! - The expiry date (moment in time) of the self-signed certificate issued by
//!   the enclave during a pre-computation bootstrapping process,
//! - The execution strategy that will be used by the trusted Veracruz runtime
//!   to execute the WASM binary, as well as a debug configuration flag which
//!   allows the WASM binary to write data to `stdout` on the untrusted host's
//!   machine,
//! - The order in which data inputs provisioned into the enclave will be placed
//!   which is important for the program provider to understand in order to
//!   write software for Veracruz.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![cfg_attr(feature = "sgx", no_std)]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(feature = "std")]
use error::PlatformError;
#[cfg(feature = "std")]
use std::{fmt, str::FromStr};

/// Error types related to the handling of policies.
pub mod error;
/// Expiry timepoints for policies and their subcomponents.
pub mod expiry;
/// Parsers for turning strings into useful policy-related types.
pub mod parsers;
/// Types for working with policies themselves.
pub mod policy;
/// Principals, and their roles.
pub mod principal;

////////////////////////////////////////////////////////////////////////////
// Platforms supported by Veracruz.
////////////////////////////////////////////////////////////////////////////

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
    /// The enclave is running under IceCap.
    IceCap,
    /// The mock platform for unit testing (client unit tests, at the moment).
    Mock,
}

#[cfg(feature = "std")]
impl FromStr for Platform {
    type Err = PlatformError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sgx" => Ok(Platform::SGX),
            "trustzone" => Ok(Platform::TrustZone),
            "nitro" => Ok(Platform::Nitro),
            "icecap" => Ok(Platform::IceCap),
            "linux" => Ok(Platform::Linux),
            _ => Err(PlatformError::InvalidPlatform(format!("{}", s))),
        }
    }
}

#[cfg(feature = "std")]
impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Platform::Linux => write!(f, "linux"),
            Platform::SGX => write!(f, "sgx"),
            Platform::TrustZone => write!(f, "trustzone"),
            Platform::Nitro => write!(f, "nitro"),
            Platform::IceCap => write!(f, "icecap"),
            Platform::Mock => write!(f, "mock"),
        }
    }
}
