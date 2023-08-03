//! Common file descriptor-related material
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright and licensing
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for copyright
//! and licensing information.

use anyhow::Result;
use bincode::{deserialize, serialize};
use byteorder::{ByteOrder, LittleEndian};
use log::error;
use nix::unistd::{read, write};
use serde::{de::DeserializeOwned, Serialize};
use std::os::unix::prelude::RawFd;

/// Sends a `buffer` of data (by first transmitting an encoded length followed by
/// the data proper) to the file descriptor `fd`.
pub fn send_buffer(fd: RawFd, buffer: &[u8]) -> Result<()> {
    let len = buffer.len();

    // 1: Encode the data length and send it.
    {
        let mut buff = [0u8; 9];
        LittleEndian::write_u64(&mut buff, len as u64);
        write(fd, &buff)?;
    }

    // 2. Send the data proper.
    write(fd, &buffer)?;

    Ok(())
}

pub fn read_exact(fd: RawFd, mut buf: &mut [u8]) -> nix::Result<()> {
    while !buf.is_empty() {
        match read(fd, buf) {
            Ok(0) => break,
            Ok(n) => {
                let tmp = buf;
                buf = &mut tmp[n..];
            }
            Err(nix::errno::Errno::EINTR) => {}
            Err(e) => return Err(e),
        }
    }
    if !buf.is_empty() {
        Err(nix::errno::Errno::ENODATA)
    } else {
        Ok(())
    }
}

/// Reads a buffer of data from a file descriptor `fd` by first reading a length
/// of data, followed by the data proper.
pub fn receive_buffer(fd: RawFd) -> Result<Vec<u8>> {
    // 1. First read and decode the length of the data proper.
    let length = {
        let mut buff = [0u8; 9];
        crate::nix::read_exact(fd, &mut buff)?;
        LittleEndian::read_u64(&buff) as usize
    };

    // 2. Next, read the data proper.
    let mut buffer = vec![0u8; length];
    crate::nix::read_exact(fd, &mut buffer)?;

    Ok(buffer)
}

/// Transmits a serialized message, `data`, via a socket.
///
/// Fails if the message cannot be serialized, or if the serialized message
/// cannot be transmitted.
pub fn send_message<T>(socket: RawFd, data: T) -> Result<()>
where
    T: Serialize,
{
    let message = serialize(&data).map_err(|e| {
        error!("Failed to serialize message.  Error produced: {}.", e);

        e
    })?;

    send_buffer(socket, &message).map_err(|e| {
        error!("Failed to transmit message.  Error produced: {}.", e);

        e
    })?;

    Ok(())
}

/// Receives and deserializes a message via a socket.
///
/// Fails if no message can be received, or if the received message cannot be
/// deserialized.
pub fn receive_message<T>(socket: RawFd) -> Result<T>
where
    T: DeserializeOwned,
{
    let response = receive_buffer(socket).map_err(|e| {
        error!("Failed to receive response.  Error produced: {}.", e);

        e
    })?;

    let message: T = deserialize(&response).map_err(|e| {
        error!("Failed to deserialize response.  Error produced: {}.", e);

        e
    })?;

    Ok(message)
}
