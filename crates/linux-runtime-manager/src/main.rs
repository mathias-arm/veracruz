//! Linux-specific material for the Runtime Manager enclave
//!
//! NB: note that the attestation flow presented in this
//! module is *completely* insecure and just presented here as a
//! mockup of what a real attestation flow should look like.  See
//! the AWS Nitro Enclave attestation flow for a real example.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::{anyhow, Result};
use clap::Arg;
use hex::decode_to_slice;
use lazy_static::lazy_static;
use log::debug;
use log::{error, info};
use raw_fd::{receive_buffer, send_buffer};
use runtime_manager::managers::RuntimeManagerError;
use runtime_manager::{
    common_runtime::CommonRuntime, managers::session_manager::init_session_manager,
};
use std::{net::TcpStream, os::unix::io::AsRawFd, os::unix::prelude::RawFd, sync::Mutex};

mod linux_runtime;

lazy_static! {
    static ref RUNTIME_MANAGER_MEASUREMENT: Mutex<Vec<u8>> = Mutex::new(vec![0u8; 32]);
}
////////////////////////////////////////////////////////////////////////////////
// Entry point and message dispatcher.
////////////////////////////////////////////////////////////////////////////////

fn main() -> Result<(), String> {
    linux_main().map_err(|err| {
        format!(
            "Linux Enclave Runtime Manager::main encap returned error:{:?}",
            err
        )
    })
}

/// Main entry point for Linux: parses command line arguments to find the port
/// number we should be listening on for incoming connections from the Veracruz
/// server.  Parses incoming messages, and acts on them.
pub fn linux_main() -> Result<()> {
    env_logger::init();

    init_session_manager()?;

    let matches = clap::Command::new("Linux runtime manager enclave")
        .author("The Veracruz Development Team")
        .arg(
            Arg::new("address")
                .short('a')
                .long("address")
                .num_args(1)
                .required(true)
                .help("Address for connecting to Veracruz Server.")
                .value_name("ADDRESS"),
        )
        .arg(
            Arg::new("runtime_manager_measurement")
                .short('m')
                .long("measurement")
                .num_args(1)
                .required(true)
                .help("SHA256 measurement of the Runtime Manager enclave binary.")
                .value_name("MEASUREMENT"),
        )
        .get_matches();

    let address = if let Some(address) = matches.get_one::<String>("address") {
        address
    } else {
        error!("No address given. Exiting...");
        return Err(anyhow!(RuntimeManagerError::CommandLineArguments));
    };

    let measurement =
        if let Some(measurement) = matches.get_one::<String>("runtime_manager_measurement") {
            measurement
        } else {
            error!("No measurement given. Exiting...");
            return Err(anyhow!(RuntimeManagerError::CommandLineArguments));
        };

    let mut measurement_bytes = vec![0u8; 32];

    if let Err(err) = decode_to_slice(measurement, &mut measurement_bytes) {
        error!(
            "Failed to decode Runtime Manager measurement ({}).  Error produced: {:?}.",
            measurement, err
        );
        return Err(anyhow!(RuntimeManagerError::CommandLineArguments));
    }

    {
        let mut rmm = RUNTIME_MANAGER_MEASUREMENT.lock().unwrap();
        *rmm = measurement_bytes;
    }

    let linux_runtime = linux_runtime::LinuxRuntime {};

    debug!("linux_runtime_manager::linux_main accept succeeded. looping");
    let runtime = CommonRuntime::new(&linux_runtime);
    loop {
        let stream = TcpStream::connect(&address).map_err(|e| {
            error!("Could not connect to Veracruz Server on {}: {}", address, e);
            anyhow!(e)
        })?;
        info!("Connected to Veracruz Server on {}.", address);

        // Configure TCP to flush outgoing buffers immediately. This reduces latency
        // when dealing with small packets
        let _ = stream.set_nodelay(true);

        let fd: RawFd = stream.as_raw_fd();

        debug!("Linux Runtime Manager::main accept succeeded. Looping");
        loop {
            let received_buffer = receive_buffer(fd)?;
            let response_buffer = runtime.decode_dispatch(&received_buffer)?;
            debug!(
                "Linux Runtime Manager::main_loop received:{:02x?}",
                response_buffer
            );
            send_buffer(fd, &response_buffer)?;
        }
    }
}
