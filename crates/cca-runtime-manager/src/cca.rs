use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::{close, mkdir, read, write};
use nix::Result;

pub fn attestation(challenge: &[u8]) -> Result<Vec<u8>> {
    let chmod_0755: Mode = Mode::S_IRWXU | Mode::S_IRGRP | Mode::S_IXGRP |
        Mode::S_IROTH | Mode::S_IXOTH;
    let report = "/sys/kernel/config/tsm/report/report0";
    let inblob = format!("{report}/inblob");
    let outblob = format!("{report}/outblob");

    mkdir(report, chmod_0755).ok();

    let s = nix::sys::stat::stat(inblob.as_str());

    let mut c = challenge.clone();
    match open(inblob.as_str(), OFlag::O_WRONLY, Mode::empty()) {
            Ok(f) => {
            while c.len() > 0 {
                match write(f, challenge) {
                    Ok(l) => {
                        (_, c) = c.split_at(l);
                    },
                    Err(err) => {
                        return Err(err);
                    },
                }
            }
            close(f)?;
        },
        Err(err) => {
            return Err(err);
        }
    }

    match open(outblob.as_str(), OFlag::empty(), Mode::empty()) {
        Ok(f) => {
            let mut blob = vec![];
            loop {
                let mut buf = [0u8; 256];
                match read(f, &mut buf) {
                    Ok(l) => {
                        if l == 0 {
                            break;
                        } else {
                            blob.extend(buf.split_at(l).0);
                        }
                    },
                    Err(err) => {
                        return Err(err);
                    },
                }
            }
            return Ok(blob);
        },
        Err(err) => {
            return Err(err);
        }
    }
}
