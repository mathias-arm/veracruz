//! Lib target for Icecap Veracruz Server.
//! It's used for unit testing
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

<<<<<<< HEAD:icecap-veracruz-server/src/lib.rs
pub mod server;
=======
#[cfg(feature = "cca")]
pub mod cca;
#[cfg(feature = "icecap")]
pub mod icecap;
#[cfg(feature = "linux")]
pub mod linux;
#[cfg(feature = "nitro")]
pub mod nitro;
>>>>>>> f15aa1b2 (Start support for Linux CCA Realm):veracruz-server/src/platforms/mod.rs
