use log::{debug, info};
use nix::mount::{mount, MsFlags};
use nix::sys::stat::Mode;
use nix::unistd::mkdir;
use nix::Result;

pub fn init(filters: &str, backtrace: bool) -> nix::Result<()> {
    if backtrace {
        std::env::set_var("RUST_BACKTRACE", "full");
    }

    // These cannot currently be constants
    let chmod_0555: Mode = Mode::S_IRUSR
        | Mode::S_IXUSR
        | Mode::S_IRGRP
        | Mode::S_IXGRP
        | Mode::S_IROTH
        | Mode::S_IXOTH;
    let chmod_0755: Mode =
        Mode::S_IRWXU | Mode::S_IRGRP | Mode::S_IXGRP | Mode::S_IROTH | Mode::S_IXOTH;
    let common_mnt_flags: MsFlags = MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID;

    // /dev/urandom is required very early
    mkdir("/dev", chmod_0755).ok();
    let devtmpfs = Some("devtmpfs");
    mount(
        devtmpfs,
        "/dev",
        devtmpfs,
        MsFlags::MS_NOSUID,
        Some("mode=0755"),
    )?;

    // Initialize logging
    env_logger::builder().parse_filters(filters).init();

    // Log retroactively :)
    info!("Starting init");
    debug!("Mounting /dev");

    debug!("Mounting /proc");
    mkdir("/proc", chmod_0555).ok();
    mount::<_, _, _, [u8]>(Some("proc"), "/proc", Some("proc"), common_mnt_flags, None)?;

    Ok(())
}

pub fn reboot() -> Result<()> {
    debug!("Rebooting");
    nix::sys::reboot::reboot(nix::sys::reboot::RebootMode::RB_POWER_OFF).map(|_| {})
}
