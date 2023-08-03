use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::close;
use nix::Result;

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct cca_ioctl_request {
    challenge: [u8; 64],
    token: [u8; 4096],
    token_length: u64,
}

nix::ioctl_readwrite!(cca_attestation_request, b'A', 1, cca_ioctl_request);

pub fn attestation(challenge: &[u8]) -> Result<Vec<u8>> {
    match open("/dev/cca_attestation", OFlag::empty(), Mode::empty()) {
        Ok(f) => {
            let mut r = cca_ioctl_request {
                challenge: [0u8; 64],
                token: [0u8; 4096],
                token_length: 0u64,
            };

            let m = std::cmp::min(r.challenge.len(), challenge.len());
            let (src, _) = challenge.split_at(m);
            let (dst, _) = r.challenge.split_at_mut(m);
            dst.copy_from_slice(src);

            match unsafe { cca_attestation_request(f, &mut r) } {
                Ok(c) => {
                    let _ = close(f);
                    if c == 0 {
                        Ok(r.token[0..(r.token_length as usize)].to_vec())
                    } else {
                        Err(nix::errno::Errno::from_i32(c))
                    }
                }
                Err(e) => {
                    let _ = close(f);
                    Err(e)
                }
            }
        }
        Err(e) => Err(e),
    }
}
