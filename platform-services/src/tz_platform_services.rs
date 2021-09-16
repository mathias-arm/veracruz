//! Arm TrustZone/OP-TEE-specific platform services
//!
//! Implements the `getrandom` platform service using a trusted entropy source
//! provided by OP-TEE.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use super::result;

use optee_utee::Random;

/// Fills a buffer, `buffer`, with random bytes sampled from the thread-local
/// random number source.  Uses the Optee trusted RTS library from the Rust TZ
/// SDK to implement this.
pub fn platform_getrandom(buffer: &mut [u8]) -> result::Result<()> {
    Random::generate(buffer);
    result::Result::Success(())
}

/// Returns the clock resolution in nanoseconds.
/// TODO: implement it
pub fn platform_getclockres(clock_id: u8) -> result::Result<u64> {
    result::Result::Unavailable
}

/// Returns the clock time in nanoseconds.
/// TODO: implement it
pub fn platform_getclocktime(clock_id: u8) -> result::Result<u64> {
    result::Result::Unavailable
}
