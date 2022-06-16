//! IO-related functionality
//!
//! This is input/output-related functionality that is useful in many places
//! across the Veracruz codebase.  The material consists of socket- and RawFD
//! utility functions.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[macro_use]
extern crate log;

/// IO-related error type.
pub mod error;
#[cfg(any(feature = "nitro", feature = "linux", feature = "cca"))]
/// FD-related material.
pub mod fd;
#[cfg(feature = "linux")]
/// TCP-socket related material.
pub mod tcp;
