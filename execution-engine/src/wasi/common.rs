//! Common code for any implementation of WASI:
//! - An interface for handling memory access.
//! - An interface for executing a program.
//! - A WASI Wrapper. It wraps the strictly type WASI-like API
//! in the virtual file system, and converts wasm number- and address-based
//! parameters to properly typed parameters and rust-style error handling to
//! c-style returning code.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![allow(non_camel_case_types)]

use crate::fs::{FileSystem, FileSystemError};
use byteorder::{LittleEndian, ReadBytesExt};
use err_derive::Error;
use log::info;
use serde::{Deserialize, Serialize};
#[cfg(any(feature = "std", feature = "tz", feature = "nitro"))]
use std::sync::{Arc, Mutex};
#[cfg(feature = "sgx")]
use std::sync::{Arc, SgxMutex as Mutex};
use std::{
    convert::TryFrom, io::Cursor, mem::size_of, slice::from_raw_parts, string::String, vec::Vec,
};
use veracruz_utils::policy::principal::Principal;
use wasi_types::{
    Advice, ClockId, DirEnt, ErrNo, Event, EventFdState, EventRwFlags, EventType, Fd, FdFlags,
    IoVec, LookupFlags, OpenFlags, RiFlags, Rights, RoFlags, SdFlags, SetTimeFlags, SiFlags,
    Signal, Subscription, SubscriptionClock, SubscriptionFdReadwrite, Whence,
};

////////////////////////////////////////////////////////////////////////////////
// Common constants.
////////////////////////////////////////////////////////////////////////////////

/// List of WASI API.
#[derive(Debug, PartialEq, Clone, FromPrimitive, ToPrimitive, Serialize, Deserialize, Copy)]
pub enum WASIAPIName {
    ARGS_GET = 1,
    ARGS_SIZES_GET,
    ENVIRON_GET,
    ENVIRON_SIZES_GET,
    CLOCK_RES_GET,
    CLOCK_TIME_GET,
    FD_ADVISE,
    FD_ALLOCATE,
    FD_CLOSE,
    FD_DATASYNC,
    FD_FDSTAT_GET,
    FD_FDSTAT_SET_FLAGS,
    FD_FDSTAT_SET_RIGHTS,
    FD_FILESTAT_GET,
    FD_FILESTAT_SET_SIZE,
    FD_FILESTAT_SET_TIMES,
    FD_PREAD,
    FD_PRESTAT_GET,
    FD_PRESTAT_DIR_NAME,
    FD_PWRITE,
    FD_READ,
    FD_READDIR,
    FD_RENUMBER,
    FD_SEEK,
    FD_SYNC,
    FD_TELL,
    FD_WRITE,
    PATH_CREATE_DIRECTORY,
    PATH_FILESTAT_GET,
    PATH_FILESTAT_SET_TIMES,
    PATH_LINK,
    PATH_OPEN,
    PATH_READLINK,
    PATH_REMOVE_DIRECTORY,
    PATH_RENAME,
    PATH_SYMLINK,
    PATH_UNLINK_FILE,
    POLL_ONEOFF,
    PROC_EXIT,
    PROC_RAISE,
    SCHED_YIELD,
    RANDOM_GET,
    SOCK_RECV,
    SOCK_SEND,
    SOCK_SHUTDOWN,
}

impl TryFrom<&str> for WASIAPIName {
    type Error = ();
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let rst = match s {
            "args_get" => WASIAPIName::ARGS_GET,
            "args_sizes_get" => WASIAPIName::ARGS_SIZES_GET,
            "environ_get" => WASIAPIName::ENVIRON_GET,
            "environ_sizes_get" => WASIAPIName::ENVIRON_SIZES_GET,
            "clock_res_get" => WASIAPIName::CLOCK_RES_GET,
            "clock_time_get" => WASIAPIName::CLOCK_TIME_GET,
            "fd_advise" => WASIAPIName::FD_ADVISE,
            "fd_allocate" => WASIAPIName::FD_ALLOCATE,
            "fd_close" => WASIAPIName::FD_CLOSE,
            "fd_datasync" => WASIAPIName::FD_DATASYNC,
            "fd_fdstat_get" => WASIAPIName::FD_FDSTAT_GET,
            "fd_fdstat_set_flags" => WASIAPIName::FD_FDSTAT_SET_FLAGS,
            "fd_fdstat_set_rights" => WASIAPIName::FD_FDSTAT_SET_RIGHTS,
            "fd_filestat_get" => WASIAPIName::FD_FILESTAT_GET,
            "fd_filestat_set_size" => WASIAPIName::FD_FILESTAT_SET_SIZE,
            "fd_filestat_set_times" => WASIAPIName::FD_FILESTAT_SET_TIMES,
            "fd_pread" => WASIAPIName::FD_PREAD,
            "fd_prestat_get" => WASIAPIName::FD_PRESTAT_GET,
            "fd_prestat_dir_name" => WASIAPIName::FD_PRESTAT_DIR_NAME,
            "fd_pwrite" => WASIAPIName::FD_PWRITE,
            "fd_read" => WASIAPIName::FD_READ,
            "fd_readdir" => WASIAPIName::FD_READDIR,
            "fd_renumber" => WASIAPIName::FD_RENUMBER,
            "fd_seek" => WASIAPIName::FD_SEEK,
            "fd_sync" => WASIAPIName::FD_SYNC,
            "fd_tell" => WASIAPIName::FD_TELL,
            "fd_write" => WASIAPIName::FD_WRITE,
            "path_create_directory" => WASIAPIName::PATH_CREATE_DIRECTORY,
            "path_filestat_get" => WASIAPIName::PATH_FILESTAT_GET,
            "path_filestat_set_times" => WASIAPIName::PATH_FILESTAT_SET_TIMES,
            "path_link" => WASIAPIName::PATH_LINK,
            "path_open" => WASIAPIName::PATH_OPEN,
            "path_readlink" => WASIAPIName::PATH_READLINK,
            "path_remove_directory" => WASIAPIName::PATH_REMOVE_DIRECTORY,
            "path_rename" => WASIAPIName::PATH_RENAME,
            "path_symlink" => WASIAPIName::PATH_SYMLINK,
            "path_unlink_file" => WASIAPIName::PATH_UNLINK_FILE,
            "poll_oneoff" => WASIAPIName::POLL_ONEOFF,
            "proc_exit" => WASIAPIName::PROC_EXIT,
            "proc_raise" => WASIAPIName::PROC_RAISE,
            "sched_yield" => WASIAPIName::SCHED_YIELD,
            "random_get" => WASIAPIName::RANDOM_GET,
            "sock_recv" => WASIAPIName::SOCK_RECV,
            "sock_send" => WASIAPIName::SOCK_SEND,
            "sock_shutdown" => WASIAPIName::SOCK_SHUTDOWN,
            _otherwise => return Err(()),
        };
        Ok(rst)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Miscellanea that doesn't fit elsewhere.
////////////////////////////////////////////////////////////////////////////////

/// Unpack a sequence of `bytes` and return a `T`.
pub trait Unpack<T> {
    fn unpack(bytes: &[u8]) -> FileSystemError<T>;
}

impl Unpack<IoVec> for IoVec {
    fn unpack(bytes: &[u8]) -> FileSystemError<IoVec> {
        if bytes.len() != size_of::<IoVec>() {
            return Err(ErrNo::Inval);
        }
        let mut rdr = Cursor::new(bytes);
        let buf = rdr.read_u32::<LittleEndian>()?;
        let len = rdr.read_u32::<LittleEndian>()?;
        Ok(IoVec { buf, len })
    }
}

impl Unpack<Subscription> for Subscription {
    fn unpack(bytes: &[u8]) -> FileSystemError<Subscription> {
        if bytes.len() != size_of::<Subscription>() {
            return Err(ErrNo::Inval);
        }
        let mut rdr = Cursor::new(bytes);
        let userdata = rdr.read_u64::<LittleEndian>()?;
        // build SubscriptionClock
        // NOTE: not sure if clock_id is read correctly as it is u8
        let clock_id = rdr.read_u64::<LittleEndian>()?;
        let clock_id = u8::try_from(clock_id).map_err(|_| ErrNo::Inval)?;
        let clock_id = ClockId::try_from(clock_id).map_err(|_| ErrNo::Inval)?;
        let timeout = rdr.read_u64::<LittleEndian>()?.into();
        let precision = rdr.read_u64::<LittleEndian>()?.into();
        // NOTE: not sure if clock_id is read correctly as it is u16
        let flags = rdr.read_u64::<LittleEndian>()?;
        let flags = u16::try_from(flags).map_err(|_| ErrNo::Inval)?;
        let clock = SubscriptionClock {
            clock_id,
            timeout,
            precision,
            flags,
        };
        // build SubscriptionFdReadwrite
        // NOTE: not sure if fd is read correctly as FD itself is u32,
        //       but SubscriptionFdReadwrites occupies a u64 slot
        let fd = rdr.read_u64::<LittleEndian>()?;
        let fd = u32::try_from(fd).map_err(|_| ErrNo::Inval)?.into();
        let fd_readwrite = SubscriptionFdReadwrite { fd };
        Ok(Subscription {
            userdata,
            clock,
            fd_readwrite,
        })
    }
}

impl Unpack<Event> for Event {
    fn unpack(bytes: &[u8]) -> FileSystemError<Event> {
        if bytes.len() != size_of::<Event>() {
            return Err(ErrNo::Inval);
        }
        let mut rdr = Cursor::new(bytes);
        let user_data = rdr.read_u64::<LittleEndian>()?;
        let error = rdr.read_u16::<LittleEndian>()?;
        let error = ErrNo::try_from(error).map_err(|_| ErrNo::Inval)?;
        // NOTE: not sure if ty (type) is read correctly as it is u16
        let ty = rdr.read_u48::<LittleEndian>()?;
        let ty = u8::try_from(ty).map_err(|_| ErrNo::Inval)?;
        let ty = EventType::try_from(ty).map_err(|_| ErrNo::Inval)?;
        let fd_state = if ty == EventType::FdRead || ty == EventType::FdWrite {
            let file_size = rdr.read_u64::<LittleEndian>()?;
            // NOTE: not sure if flag is read correctly as it is u64
            let flags = rdr.read_u64::<LittleEndian>()?;
            let flags = u16::try_from(flags).map_err(|_| ErrNo::Inval)?;
            let flags = EventRwFlags::try_from(flags).map_err(|_| ErrNo::Inval)?;
            Some(EventFdState { file_size, flags })
        } else {
            None
        };
        Ok(Event {
            user_data,
            error,
            ty,
            fd_state,
        })
    }
}

/// The memory handler for interacting with the wasm memory space.
/// An execution engine must implement `write_buffer` and `read_buffer`
/// before using the WASIWrapper, because the WASI implementation requires
/// an extra memory handler as the first parameter.
///
/// NOTE: we purposely choose u32 here as the execution engine is likely received u32 as
/// parameters
pub trait MemoryHandler {
    /// Write the `buffer` to `address`.
    fn write_buffer(&mut self, address: u32, buffer: &[u8]) -> FileSystemError<()>;
    /// Read `length` bytes from `address`.
    fn read_buffer(&self, address: u32, length: u32) -> FileSystemError<Vec<u8>>;

    /// Reads a string at `address` of `length` from the runtime state's memory,
    /// starting at base address `address`.  If it fails, return ErrNo.
    fn read_cstring(&self, address: u32, length: u32) -> FileSystemError<String> {
        let bytes = self.read_buffer(address, length)?;
        let rst = String::from_utf8(bytes).map_err(|_e| ErrNo::IlSeq)?;
        Ok(rst)
    }

    /// Performs a scattered read from several locations, as specified by a list
    /// of `IoVec` structures, `scatters`, from the runtime state's memory.
    fn read_iovec_scattered(&self, scatters: &[IoVec]) -> FileSystemError<Vec<Vec<u8>>> {
        let mut rst = Vec::new();
        for IoVec { buf, len } in scatters.iter() {
            rst.push(self.read_buffer(*buf, *len)?)
        }
        Ok(rst)
    }

    /// Reads a list of `IoVec` structures from a byte buffer.  Fails if reading of
    /// any `IoVec` fails, for any reason.
    fn unpack_array<T>(&self, ptr: u32, count: u32) -> FileSystemError<Vec<T>>
    where
        T: Unpack<T>,
    {
        let size = size_of::<T>();
        let all_bytes = self.read_buffer(ptr, count * (size as u32))?;
        let mut rst = Vec::new();

        for bytes in all_bytes.chunks(size) {
            rst.push(T::unpack(bytes)?)
        }
        Ok(rst)
    }

    /// The default implementation for writing a u32 to `address`.
    fn write_u32(&mut self, address: u32, number: u32) -> FileSystemError<()>
    {
        self.write_buffer(address, &u32::to_le_bytes(number))
    }

    /// The default implementation for writing a u64 to `address`.
    fn write_u64(&mut self, address: u32, number: u64) -> FileSystemError<()>
    {
        self.write_buffer(address, &u64::to_le_bytes(number))
    }

    /// The default implementation for writing a struct to `address`.
    fn write_struct<T>(&mut self, address: u32, element: &T) -> FileSystemError<()>
    where
        T: Sized,
    {
        let byte: &[u8] =
            unsafe { from_raw_parts((element as *const T) as *const u8, size_of::<T>()) };
        self.write_buffer(address, &byte)
    }

    /// Write the content to the buf_address and the starting address to buf_pointers.
    /// For example:
    /// buf_address:
    /// --------------------------------------------------------------------
    ///  conten[0] content[1] ......
    /// --------------------------------------------------------------------
    ///    ^           ^
    ///   0x10        0x64
    /// buf_pointers: [0x10, 0x64, ...]
    ///
    fn write_string_list(
        &mut self,
        content: &Vec<Vec<u8>>,
        mut buf_address: u32,
        mut buf_pointers: u32,
    ) -> FileSystemError<()> {
        for to_write in content {
            // Write to the buf
            self.write_buffer(buf_address, &to_write)?;
            // Write to the pointer array
            self.write_u32(buf_pointers, buf_address)?;
            // Modify the offset
            buf_address += to_write.len() as u32;
            buf_pointers += size_of::<u32>() as u32;
        }
        Ok(())
    }
}
////////////////////////////////////////////////////////////////////////////////
// The host runtime state.
////////////////////////////////////////////////////////////////////////////////

/// A wrapper on VFS for WASI, which provides common API used by wasm execution engine.
#[derive(Clone)]
pub struct WASIWrapper {
    /// The synthetic filesystem associated with this machine.
    filesystem: Arc<Mutex<FileSystem>>,
    /// The environment variables that have been passed to this program from the
    /// global policy file.  These are stored as a key-value mapping from
    /// variable name to value.
    environment_variables: Vec<(String, String)>,
    /// The array of program arguments that have been passed to this program,
    /// again from the global policy file.
    program_arguments: Vec<String>,
    /// The principal that accesses the filesystem. This information is used in path_open.
    principal: Principal,
    /// The exit code, if program calls proc_exit.
    exit_code: Option<u32>,
}

impl WASIWrapper {
    /// The name of the WASM program's entry point.
    pub(crate) const ENTRY_POINT_NAME: &'static str = "_start";
    /// The name of the WASM program's linear memory.
    pub(crate) const LINEAR_MEMORY_NAME: &'static str = "memory";
    /// The name of the containing module for all WASI imports.
    pub(crate) const WASI_SNAPSHOT_MODULE_NAME: &'static str = "wasi_snapshot_preview1";

    ////////////////////////////////////////////////////////////////////////////
    // Creating and modifying runtime states.
    ////////////////////////////////////////////////////////////////////////////

    /// Creates a new initial `WASIWrapper`.
    pub fn new(filesystem: Arc<Mutex<FileSystem>>, principal: Principal) -> Self {
        Self {
            filesystem,
            environment_variables: Vec::new(),
            program_arguments: Vec::new(),
            principal,
            exit_code: None,
        }
    }

    ///////////////////////////////////////////////////////
    //// Functions for the execution engine internal
    ///////////////////////////////////////////////////////

    /// An internal function for the execution engine to directly read the file.
    #[inline]
    pub(crate) fn read_file_by_filename(&mut self, file_name: &str) -> FileSystemError<Vec<u8>> {
        let mut fs = self.filesystem.lock().map_err(|_| ErrNo::Busy)?;
        fs.read_file_by_filename(&Principal::InternalSuperUser, file_name)
    }

    pub(crate) fn exit_code(&self) -> Option<u32> {
        self.exit_code
    }

    ////////////////////////////////////////////////////////////////////////////
    // WASI implementation
    ////////////////////////////////////////////////////////////////////////////

    /// The implementation of the WASI `args_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn args_get(
        &self,
        memory_ref: &mut impl MemoryHandler,
        address_for_string_ptrs: u32,
        buf_address: u32,
    ) -> FileSystemError<()> {
        info!("args_get is called");
        let buffer = self
            .program_arguments
            .iter()
            .map(|arg| format!("{}\0", arg).into_bytes())
            .collect();
        memory_ref.write_string_list(&buffer, buf_address, address_for_string_ptrs)
    }

    /// The implementation of the WASI `args_sizes_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn args_sizes_get(
        &self,
        memory_ref: &mut impl MemoryHandler,
        address_for_counts: u32,
        address_for_buffer_size: u32,
    ) -> FileSystemError<()> {
        info!("args_sizes_get is called");
        let environc = self.program_arguments.len() as u32;
        let environ_buf_size = self
            .program_arguments
            .iter()
            .fold(0, |acc, arg| acc + format!("{}\0", arg).as_bytes().len());

        memory_ref.write_u32(address_for_counts, environc)?;
        memory_ref.write_u32(
            address_for_buffer_size,
            environ_buf_size as u32,
        )
    }

    /// The implementation of the WASI `environ_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn environ_get(
        &self,
        memory_ref: &mut impl MemoryHandler,
        address_for_string_ptrs: u32,
        buf_address: u32,
    ) -> FileSystemError<()> {
        info!("environ_get is called");
        let buffer = self
            .environment_variables
            .iter()
            .map(|(key, value)| {
                let environ = format!("{}={}\0", key, value);
                environ.into_bytes()
            })
            .collect::<Vec<_>>();
        memory_ref.write_string_list(&buffer, buf_address, address_for_string_ptrs)
    }

    /// THe implementation of the WASI `environ_sizes_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn environ_sizes_get(
        &self,
        memory_ref: &mut impl MemoryHandler,
        address_for_counts: u32,
        address_for_buffer_size: u32,
    ) -> FileSystemError<()> {
        info!("environ_sizes_get is called");
        let environc = self.environment_variables.len() as u32;
        let environ_buf_size = self
            .environment_variables
            .iter()
            .fold(0, |acc, (key, value)| {
                acc + format!("{}={}\0", key, value).as_bytes().len()
            });

        memory_ref.write_u32(address_for_counts, environc)?;
        memory_ref.write_u32(
            address_for_buffer_size,
            environ_buf_size as u32,
        )
    }

    /// The implementation of the WASI `clock_res_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn clock_res_get(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        clock_id: u32,
        address: u32,
    ) -> FileSystemError<()> {
        let clock_id: u8 = Self::decode_wasi_arg(clock_id)?;
        let clock_id: ClockId = Self::decode_wasi_arg(clock_id)?;
        let fs = self.lock_vfs()?;
        let time = fs.clock_res_get(clock_id)?;
        memory_ref.write_u64(address, time.as_nanos())
    }

    /// The implementation of the WASI `clock_time_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn clock_time_get(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        clock_id: u32,
        precision: u64,
        address: u32,
    ) -> FileSystemError<()> {
        let clock_id: u8 = Self::decode_wasi_arg(clock_id)?;
        let clock_id: ClockId = Self::decode_wasi_arg(clock_id)?;
        let fs = self.lock_vfs()?;
        let time = fs.clock_time_get(clock_id, precision.into())?;
        memory_ref.write_u64(address, time.as_nanos())
    }

    /// The implementation of the WASI `fd_advise` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_advise(
        &mut self,
        _: &mut impl MemoryHandler,
        fd: u32,
        offset: u64,
        len: u64,
        advice: u8,
    ) -> FileSystemError<()> {
        let advice: Advice = Self::decode_wasi_arg(advice)?;
        let mut fs = self.lock_vfs()?;
        fs.fd_advise(fd.into(), offset, len, advice)
    }

    /// The implementation of the WASI `fd_allocate` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_allocate(
        &mut self,
        _: &mut impl MemoryHandler,
        fd: u32,
        offset: u64,
        len: u64,
    ) -> FileSystemError<()> {
        let mut fs = self.lock_vfs()?;
        fs.fd_allocate(fd.into(), offset, len)
    }

    /// The implementation of the WASI `fd_close` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_close(&mut self, fd: u32) -> FileSystemError<()> {
        let mut fs = self.lock_vfs()?;
        fs.fd_close(fd.into())
    }

    /// The implementation of the WASI `fd_datasync` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_datasync(&mut self, _: &mut impl MemoryHandler, fd: u32) -> FileSystemError<()> {
        let mut fs = self.lock_vfs()?;
        fs.fd_datasync(fd.into())
    }

    /// The implementation of the WASI `fd_fdstat_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_fdstat_get(
        &self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        address: u32,
    ) -> FileSystemError<()> {
        let fs = self.lock_vfs()?;
        let stat = fs.fd_fdstat_get(fd.into())?;
        memory_ref.write_struct(address, &stat)
    }

    /// The implementation of the WASI `fd_fdstat_set_flags` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_fdstat_set_flags(
        &mut self,
        _: &mut impl MemoryHandler,
        fd: u32,
        flags: u16,
    ) -> FileSystemError<()> {
        let flags: FdFlags = Self::decode_wasi_arg(flags)?;
        let mut fs = self.lock_vfs()?;
        fs.fd_fdstat_set_flags(fd.into(), flags)
    }

    /// The implementation of the WASI `fd_fdstat_set_rights` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_fdstat_set_rights(
        &mut self,
        _: &mut impl MemoryHandler,
        fd: u32,
        rights_base: u64,
        rights_inheriting: u64,
    ) -> FileSystemError<()> {
        let rights_base: Rights = Self::decode_wasi_arg(rights_base)?;
        let rights_inheriting: Rights = Self::decode_wasi_arg(rights_inheriting)?;
        let mut fs = self.lock_vfs()?;
        fs.fd_fdstat_set_rights(fd.into(), rights_base, rights_inheriting)
    }

    /// The implementation of the WASI `fd_filestat_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_filestat_get(
        &self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        address: u32,
    ) -> FileSystemError<()> {
        let fs = self.lock_vfs()?;
        let stat = fs.fd_filestat_get(fd.into());
        memory_ref.write_struct(address, &stat)
    }

    /// The implementation of the WASI `fd_filestat_set_size` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_filestat_set_size(
        &mut self,
        _: &mut impl MemoryHandler,
        fd: u32,
        size: u64,
    ) -> FileSystemError<()> {
        let mut fs = self.lock_vfs()?;
        fs.fd_filestat_set_size(fd.into(), size)
    }

    /// The implementation of the WASI `fd_filestat_set_times` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_filestat_set_times(
        &mut self,
        _: &mut impl MemoryHandler,
        fd: u32,
        atime: u64,
        mtime: u64,
        fst_flag: u16,
    ) -> FileSystemError<()> {
        let fst_flag: SetTimeFlags = Self::decode_wasi_arg(fst_flag)?;
        let mut fs = self.lock_vfs()?;
        fs.fd_filestat_set_times(fd.into(), atime.into(), mtime.into(), fst_flag)
    }

    /// The implementation of the WASI `fd_pread` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_pread(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        iovec_base: u32,
        iovec_count: u32,
        mut offset: u64,
        address: u32,
    ) -> FileSystemError<()> {
        let iovecs = memory_ref.unpack_array::<IoVec>(iovec_base, iovec_count)?;

        let mut size_read = 0;
        for iovec in iovecs.iter() {
            let mut fs = self.lock_vfs()?;
            let to_write = fs.fd_pread(fd.into(), iovec.len as usize, offset)?;
            offset = offset + (to_write.len() as u64);
            memory_ref.write_buffer(iovec.buf, &to_write)?;
            size_read += to_write.len() as u32;
        }
        memory_ref.write_u32(address, size_read)
    }

    /// The implementation of the WASI `fd_prestat_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_prestat_get(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        address: u32,
    ) -> FileSystemError<()> {
        let fd = Fd(fd);
        let mut fs = self.lock_vfs()?;
        let pre = fs.fd_prestat_get(fd.into())?;
        memory_ref.write_struct(address, &pre)
    }

    /// The implementation of the WASI `fd_prestat_dir_name` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_prestat_dir_name(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        address: u32,
        size: u32,
    ) -> FileSystemError<()> {
        let size = size as usize;
        let mut fs = self.lock_vfs()?;
        let result = fs.fd_prestat_dir_name(fd.into())?;
        if result.len() > size as usize {
            return Err(ErrNo::NameTooLong);
        }
        memory_ref.write_buffer(address, &result.into_bytes())
    }

    /// The implementation of the WASI `fd_pwrite` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_pwrite(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        iovec_base: u32,
        iovec_count: u32,
        offset: u64,
        address: u32,
    ) -> FileSystemError<()> {
        let iovecs = memory_ref.unpack_array::<IoVec>(iovec_base, iovec_count)?;
        let bufs = memory_ref.read_iovec_scattered(&iovecs)?;

        let mut size_written = 0;
        for buf in bufs.iter() {
            let mut fs = self.lock_vfs()?;
            size_written +=
                fs.fd_pwrite(fd.into(), buf.to_vec(), offset + (size_written as u64))?;
        }
        memory_ref.write_u32(address, size_written)
    }

    /// The implementation of the WASI `fd_read` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_read(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        iovec_base: u32,
        iovec_count: u32,
        address: u32,
    ) -> FileSystemError<()> {
        let iovecs = memory_ref.unpack_array::<IoVec>(iovec_base, iovec_count)?;

        let mut size_read = 0;
        for iovec in iovecs.iter() {
            let mut fs = self.lock_vfs()?;
            let to_write = fs.fd_read(fd.into(), iovec.len as usize)?;
            memory_ref.write_buffer(iovec.buf, &to_write)?;
            size_read += to_write.len() as u32;
        }
        memory_ref.write_u32(address, size_read)
    }

    /// The implementation of the WASI `fd_readdir` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_readdir(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        mut buf_ptr: u32,
        buf_len: u32,
        cookie: u64,
        result_ptr: u32,
    ) -> FileSystemError<()> {
        let mut fs = self.lock_vfs()?;
        let dir_entries = fs.fd_readdir(fd.into(), cookie.into())?;

        let mut written = 0;
        for dir in dir_entries {
            //NOTE: `buf_len` is the count of how many dir entries can store.
            if buf_len == written {
                break;
            }
            memory_ref.write_struct(buf_ptr, &dir)?;
            buf_ptr += size_of::<DirEnt>() as u32;
            written += 1;
        }
        memory_ref.write_u32(result_ptr, written as u32)
    }

    /// The implementation of the WASI `fd_renumber` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_renumber(
        &mut self,
        _: &mut impl MemoryHandler,
        old_fd: u32,
        new_fd: u32,
    ) -> FileSystemError<()> {
        let mut fs = self.lock_vfs()?;
        fs.fd_renumber(old_fd.into(), new_fd.into())
    }

    /// The implementation of the WASI `fd_seek` function.
    #[inline]
    pub(crate) fn fd_seek(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        offset: i64,
        whence: u8,
        address: u32,
    ) -> FileSystemError<()> {
        let whence: Whence = Self::decode_wasi_arg(whence)?;
        let mut fs = self.lock_vfs()?;
        let new_offset = fs.fd_seek(fd.into(), offset, whence)?;
        memory_ref.write_u64(address, new_offset)
    }

    /// The implementation of the WASI `fd_sync` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_sync(&mut self, _: &mut impl MemoryHandler, fd: u32) -> FileSystemError<()> {
        let mut fs = self.lock_vfs()?;
        fs.fd_sync(fd.into())
    }

    /// The implementation of the WASI `fd_tell` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_tell(
        &self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        address: u32,
    ) -> FileSystemError<()> {
        let fs = self.lock_vfs()?;
        let offset = fs.fd_tell(fd.into())?;
        memory_ref.write_u64(address, offset)
    }

    /// The implementation of the WASI `fd_write` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn fd_write(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        iovec_base: u32,
        iovec_count: u32,
        address: u32,
    ) -> FileSystemError<()> {
        let iovecs = memory_ref.unpack_array::<IoVec>(iovec_base, iovec_count)?;
        let bufs = memory_ref.read_iovec_scattered(&iovecs)?;

        let mut size_written = 0;
        for buf in bufs.iter() {
            let mut fs = self.lock_vfs()?;
            size_written += fs.fd_write(fd.into(), buf.clone())?;
        }
        memory_ref.write_u32(address, size_written)
    }

    /// The implementation of the WASI `path_create_directory` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn path_create_directory(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        path_address: u32,
        path_length: u32,
    ) -> FileSystemError<()> {
        let path = memory_ref.read_cstring(path_address, path_length)?;
        let mut fs = self.lock_vfs()?;
        fs.path_create_directory(fd.into(), path)
    }

    /// The implementation of the WASI `path_filestat_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn path_filestat_get(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        flags: u32,
        path_address: u32,
        path_length: u32,
        address: u32,
    ) -> FileSystemError<()> {
        let path = memory_ref.read_cstring(path_address, path_length)?;
        let flags: LookupFlags = Self::decode_wasi_arg(flags)?;
        let mut fs = self.lock_vfs()?;
        let stat = fs.path_filestat_get(fd.into(), flags, path)?;
        memory_ref.write_struct(address, &stat)
    }

    /// The implementation of the WASI `path_filestat_set_times` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn path_filestat_set_times(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        flags: u32,
        path_address: u32,
        path_length: u32,
        atime: u64,
        mtime: u64,
        fst_flag: u16,
    ) -> FileSystemError<()> {
        let path = memory_ref.read_cstring(path_address, path_length)?;
        let flags: LookupFlags = Self::decode_wasi_arg(flags)?;
        let fst_flag: SetTimeFlags = Self::decode_wasi_arg(fst_flag)?;
        let mut fs = self.lock_vfs()?;
        fs.path_filestat_set_times(
            fd.into(),
            flags,
            path,
            atime.into(),
            mtime.into(),
            fst_flag,
        )
    }

    /// The implementation of the WASI `path_link` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn path_link(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        old_fd: u32,
        old_flags: u32,
        old_address: u32,
        old_path_len: u32,
        new_fd: u32,
        new_address: u32,
        new_path_len: u32,
    ) -> FileSystemError<()> {
        let old_flags: LookupFlags = Self::decode_wasi_arg(old_flags)?;
        let old_path = memory_ref.read_cstring(old_address, old_path_len)?;
        let new_path = memory_ref.read_cstring(new_address, new_path_len)?;
        let mut fs = self.lock_vfs()?;
        fs.path_link(old_fd.into(), old_flags, old_path, new_fd.into(), new_path)
    }

    /// The implementation of the WASI `path_open` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn path_open(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        dir_flags: u32,
        path_address: u32,
        path_length: u32,
        oflags: u16,
        fs_rights_base: u64,
        fs_rights_inheriting: u64,
        fd_flags: u16,
        address: u32,
    ) -> FileSystemError<()> {
        let fd = Fd(fd);
        let path = memory_ref.read_cstring(path_address, path_length)?;
        let dir_flags: LookupFlags = Self::decode_wasi_arg(dir_flags)?;
        let oflags: OpenFlags = Self::decode_wasi_arg(oflags)?;
        let fs_rights_base: Rights = Self::decode_wasi_arg(fs_rights_base)?;
        let fs_rights_inheriting: Rights = Self::decode_wasi_arg(fs_rights_inheriting)?;
        let fd_flags: FdFlags = Self::decode_wasi_arg(fd_flags)?;
        let mut fs = self.lock_vfs()?;
        let new_fd = fs.path_open(
            &self.principal,
            fd,
            dir_flags,
            &path,
            oflags,
            fs_rights_base,
            fs_rights_inheriting,
            fd_flags,
        )?;
        memory_ref.write_u32(address, new_fd.into())
    }

    /// The implementation of the WASI `path_readlink` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn path_readlink(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        path_address: u32,
        path_length: u32,
        buf: u32,
        buf_len: u32,
        address: u32,
    ) -> FileSystemError<()> {
        let path = memory_ref.read_cstring(path_address, path_length)?;
        let mut fs = self.lock_vfs()?;
        let mut rst = fs.path_readlink(fd.into(), path)?;
        let buf_len = buf_len as usize;
        let to_write = if buf_len < rst.len() {
            buf_len
        } else {
            rst.len()
        };
        //NOTE: it should at most shrink the size of rst.
        rst.resize(to_write, 0);
        memory_ref.write_buffer(buf, &rst)?;
        memory_ref.write_u32(address, to_write as u32)
    }

    /// The implementation of the WASI `path_remove_directory` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn path_remove_directory(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        path_address: u32,
        path_length: u32,
    ) -> FileSystemError<()> {
        let path = memory_ref.read_cstring(path_address, path_length)?;
        let mut fs = self.lock_vfs()?;
        fs.path_remove_directory(fd.into(), path)
    }

    /// The implementation of the WASI `path_rename` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn path_rename(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        old_fd: u32,
        old_address: u32,
        old_path_len: u32,
        new_fd: u32,
        new_address: u32,
        new_path_len: u32,
    ) -> FileSystemError<()> {
        let old_path = memory_ref.read_cstring(old_address, old_path_len)?;
        let new_path = memory_ref.read_cstring(new_address, new_path_len)?;
        let mut fs = self.lock_vfs()?;
        fs.path_rename(old_fd.into(), old_path, new_fd.into(), new_path)
    }

    /// The implementation of the WASI `path_symlink` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn path_symlink(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        old_address: u32,
        old_path_len: u32,
        fd: u32,
        new_address: u32,
        new_path_len: u32,
    ) -> FileSystemError<()> {
        let old_path = memory_ref.read_cstring(old_address, old_path_len)?;
        let new_path = memory_ref.read_cstring(new_address, new_path_len)?;
        let mut fs = self.lock_vfs()?;
        fs.path_symlink(old_path, fd.into(), new_path)
    }

    /// The implementation of the WASI `path_unlink_file` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn path_unlink_file(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        path_address: u32,
        path_len: u32,
    ) -> FileSystemError<()> {
        let path = memory_ref.read_cstring(path_address, path_len)?;
        let mut fs = self.lock_vfs()?;
        fs.path_unlink_file(fd.into(), path)
    }

    /// The implementation of the WASI `poll_oneoff` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn poll_oneoff(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        subscriptions: u32,
        events: u32,
        size: u32,
        address: u32,
    ) -> FileSystemError<()> {
        let subscriptions = memory_ref.unpack_array::<Subscription>(subscriptions, size)?;
        let events = memory_ref.unpack_array::<Event>(events, size)?;
        let mut fs = self.lock_vfs()?;
        let rst = fs.poll_oneoff(subscriptions, events)?;
        memory_ref.write_u32(address, rst.into())
    }

    /// The implementation of the WASI `proc_exit` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn proc_exit(&mut self, _: &mut impl MemoryHandler, exit_code: u32) {
        self.exit_code = Some(exit_code);
    }

    /// The implementation of the WASI `proc_raise` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn proc_raise(&mut self, _: &mut impl MemoryHandler, signal: u8) -> FileSystemError<()> {
        let _signal: Signal = Self::decode_wasi_arg(signal)?;
        Err(ErrNo::NoSys)
    }

    /// The implementation of the WASI `sched_yield` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn sched_yield(&mut self, _: &mut impl MemoryHandler) -> FileSystemError<()> {
        Err(ErrNo::NoSys)
    }

    #[inline]
    pub(crate) fn random_get(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        buf_ptr: u32,
        length: u32,
    ) -> FileSystemError<()> {
        let fs = self.lock_vfs()?;
        let bytes = fs.random_get(length)?;
        memory_ref.write_buffer(buf_ptr, &bytes)
    }

    /// The implementation of the WASI `sock_recv` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn sock_recv(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        socket: u32,
        ri_address: u32,
        ri_len: u32,
        ri_flag: u16,
        ro_data_len: u32,
        ro_flag: u32,
    ) -> FileSystemError<()> {
        let iovecs = memory_ref.unpack_array::<IoVec>(ri_address, ri_len)?;
        let ri_flag: RiFlags = Self::decode_wasi_arg(ri_flag)?;

        let mut size_read = 0;
        let mut ro_rst = RoFlags::empty();
        for iovec in iovecs.iter() {
            let mut fs = self.lock_vfs()?;
            let (to_write, next_ro_rst) =
                fs.sock_recv(socket.into(), iovec.len as usize, ri_flag)?;
            memory_ref.write_buffer(iovec.buf, &to_write)?;
            size_read += to_write.len() as u32;
            ro_rst = ro_rst | next_ro_rst;
        }
        memory_ref.write_u32(ro_data_len, size_read)?;
        memory_ref.write_buffer(ro_flag, &u16::to_le_bytes(ro_rst.bits()))
    }

    /// The implementation of the WASI `sock_send` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn sock_send(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        socket: u32,
        si_address: u32,
        si_len: u32,
        si_flag: u16,
        address: u32,
    ) -> FileSystemError<()> {
        let iovecs = memory_ref.unpack_array::<IoVec>(si_address, si_len)?;
        let bufs = memory_ref.read_iovec_scattered(&iovecs)?;
        let si_flag: SiFlags = Self::decode_wasi_arg(si_flag)?;

        let mut size_written = 0;
        for buf in bufs.iter() {
            let mut fs = self.lock_vfs()?;
            size_written += fs.sock_send(socket.into(), buf.to_vec(), si_flag)?;
        }
        memory_ref.write_u32(address, size_written)
    }

    /// The implementation of the WASI `sock_recv` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    #[inline]
    pub(crate) fn sock_shutdown(
        &mut self,
        _: &mut impl MemoryHandler,
        socket: u32,
        sd_flag: u8,
    ) -> FileSystemError<()> {
        let sd_flag: SdFlags = Self::decode_wasi_arg(sd_flag)?;
        let mut fs = self.lock_vfs()?;
        fs.sock_shutdown(socket.into(), sd_flag)
    }

    ///////////////////////////////////////
    // Internal methods
    ///////////////////////////////////////
    /// Lock the VFS in WASIWrapper.
    /// If the locks fails, it returns Busy error code.
    fn lock_vfs(&self) -> FileSystemError<std::sync::MutexGuard<'_, FileSystem>> {
        self.filesystem.lock().map_err(|_|ErrNo::Busy)
    }
    /// Converts `arg` of type `R` to type `T`,
    /// or returns from the function with the `Inval` error code.
    fn decode_wasi_arg<T, R>(arg: R) -> FileSystemError<T> where T: TryFrom<R> {
        T::try_from(arg).map_err(|_| ErrNo::Inval)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Fatal execution errors/runtime panics.
////////////////////////////////////////////////////////////////////////////////

/// A fatal, runtime error that terminates the Veracruz execution immediately.  This
/// is akin to a "kernel panic" for Veracruz: these errors are not passed to the
/// WASM program running on the platform, but are instead fundamental issues
/// that require immediate shutdown as they cannot be fixed.
///
/// *NOTE*: care should be taken when presenting these errors to users when in
/// release (e.g. not in debug) mode: they can give away a lot of information
/// about what is going on inside the enclave.
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum FatalEngineError {
    /// The WASM module supplied by the program supplier was invalid and could
    /// not be parsed.
    #[error(display = "FatalEngineError: Invalid WASM program (e.g. failed to parse it).")]
    InvalidWASMModule,
    /// The Veracruz engine was passed bad arguments by the WASM program running
    /// on the platform.  This should never happen if the WASM program uses
    /// `libveracruz` as the platform should ensure H-Calls are always
    /// well-formed.  Seeing this either indicates a bug in `libveracruz` or a
    /// programming error in the source that originated the WASM programming if
    /// `libveracruz` was not used.
    #[error(
        display = "FatalEngineError: Bad arguments passed to host function '{:?}'.",
        function_name
    )]
    BadArgumentsToHostFunction {
        /// The name of the host function that was being invoked.
        function_name: WASIAPIName,
    },
    /// The WASM program tried to invoke an unknown H-call on the Veracruz engine.
    #[error(display = "FatalEngineError: Unknown Host call invoked: '{:?}'.", _0)]
    UnknownHostFunction(HostFunctionIndexOrName),
    /// No linear memory was registered: this is a programming error (a bug)
    /// that should be fixed.
    #[error(display = "FatalEngineError: No WASM memory registered.")]
    NoMemoryRegistered,
    /// No program module was registered: this is a programming error (a bug)
    /// that should be fixed.
    #[error(display = "FatalEngineError: No WASM program module registered.")]
    NoProgramModuleRegistered,
    /// The WASM program's entry point was missing or malformed.
    #[error(display = "FatalEngineError: Failed to find the entry point in the WASM program.")]
    NoProgramEntryPoint,
    /// The WASM program's entry point was missing or malformed.
    #[error(display = "FatalEngineError: Execution engine is not ready.")]
    EngineIsNotReady,
    /// Wrapper for direct error message.
    #[error(display = "FatalEngineError: WASM program returns code other than wasi ErrNo.")]
    ReturnedCodeError,
    /// A lock could not be obtained for some reason, wrappiing the failure information as String.
    #[error(display = "ProvisioningError: Failed to obtain lock {:?}.", _0)]
    FailedToObtainLock(String),
    /// Wrapper for WASI Trap.
    #[error(display = "FatalEngineError: WASMIError: Trap: {:?}.", _0)]
    WASMITrapError(#[source(error)] wasmi::Trap),
    /// Wrapper for WASI Error other than Trap.
    #[error(display = "FatalEngineError: WASMIError {:?}.", _0)]
    WASMIError(#[source(error)] wasmi::Error),
    #[error(display = "FatalEngineError: Wasi-ErrNo {:?}.", _0)]
    WASIError(#[source(error)] wasi_types::ErrNo),
    /// anyhow Error Wrapper.
    #[error(display = "FatalEngineError: anyhow Error {:?}.", _0)]
    AnyhowError(String),
    /// Wasmtime trap.
    #[error(display = "FatalEngineError: Wasmtime Trap Error {:?}.", _0)]
    WasmtimeTrapError(String),
}

/// Either the index or the name of a host call
#[derive(Debug, Serialize, Deserialize)]
pub enum HostFunctionIndexOrName {
    Index(usize),
    Name(String),
}

// Convertion from any error raised by any mutex of type <T> to FatalEngineError.
impl<T> From<std::sync::PoisonError<T>> for FatalEngineError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        FatalEngineError::FailedToObtainLock(format!("{:?}", error))
    }
}

impl From<anyhow::Error> for FatalEngineError {
    fn from(error: anyhow::Error) -> Self {
        FatalEngineError::AnyhowError(format!("{:?}", error))
    }
}

#[cfg(any(feature = "std", feature = "nitro"))]
impl From<wasmtime::Trap> for FatalEngineError {
    fn from(error: wasmtime::Trap) -> Self {
        FatalEngineError::WasmtimeTrapError(format!("{:?}", error))
    }
}

impl From<WASIAPIName> for FatalEngineError {
    fn from(error: WASIAPIName) -> Self {
        FatalEngineError::BadArgumentsToHostFunction {
            function_name: error,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Implementation of the H-calls.
////////////////////////////////////////////////////////////////////////////////

/// Details the arguments expected by the module's entry point, if any is found.
pub(crate) enum EntrySignature {
    /// The expected entry point (e.g. "main") is not found in the WASM module
    /// or it was found and it did not have a recognisable type signature.
    NoEntryFound,
    /// The entry point does not expect any parameters.
    NoParameters,
    /// The entry point expects a dummy `argv` and an `argc` to be supplied.
    ArgvAndArgc,
}

////////////////////////////////////////////////////////////////////////////////
// The strategy trait.
////////////////////////////////////////////////////////////////////////////////

/// This is what an execution strategy exposes to clients outside of this
/// library.  This functionality is sufficient to implement both
/// `freestanding-execution-engine` and `runtime-manager` and if any functionality is
/// missing that these components require then it should be added to this trait
/// and implemented for all supported implementation strategies.
///
/// Note that the top-level function `execute` in this crate relies on this trait.
pub trait ExecutionEngine: Send {
    /// Invokes the entry point of the WASM program `file_name`.  Will fail if
    /// the WASM program fails at runtime.  On success, returns the succ/error code
    /// returned by the WASM program entry point as an `i32` value.
    fn invoke_entry_point(&mut self, file_name: &str) -> Result<ErrNo, FatalEngineError>;
}