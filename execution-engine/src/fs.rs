//! A synthetic filesystem.
//!
//! This virtual file system(VFS) for Veracruz runtime and axecution engine.
//! The VFS adopts most WASI API with *strict typing* and *Rust-style error handling*.
//! The Veracruz runtime will use this VFS directly, while any execution engine
//! can wrap all methods here to match the WASI API.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use policy_utils::principal::{FileRights, Principal, RightsTable, StandardStream};
use std::{
    collections::HashMap,
    convert::AsRef,
    ffi::OsString,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Component, Path, PathBuf},
    vec::Vec,
    sync::{Arc, Mutex, MutexGuard},
};
use wasi_types::{
    Advice, DirCookie, DirEnt, ErrNo, Event, Fd, FdFlags, FdStat, FileDelta, FileSize, FileStat,
    FileType, Inode, LookupFlags, OpenFlags, PreopenType, Prestat, RiFlags, Rights, RoFlags,
    SdFlags, SetTimeFlags, SiFlags, Size, Subscription, Timestamp, Whence,
};
use log::info;

////////////////////////////////////////////////////////////////////////////////
// Filesystem errors.
////////////////////////////////////////////////////////////////////////////////

/// Filesystem errors either return a result of type `T` or a defined error
/// code.  The return code `ErrNo::Success` is implicit if `Ok(result)` is ever
/// returned from a filesystem function.  The result `Err(ErrNo::Success)`
/// should never be returned.
pub type FileSystemResult<T> = Result<T, ErrNo>;

/// Internal shared inode table.
type SharedInodeTable = Arc<Mutex<InodeTable>>;

////////////////////////////////////////////////////////////////////////////////
// Global functions.
////////////////////////////////////////////////////////////////////////////////

/// Get random bytes
fn getrandom_to_buffer(buf_len: Size) -> FileSystemResult<Vec<u8>> {
    let mut buf = vec![0; buf_len as usize];
    if let result::Result::Success = getrandom(&mut buf) {
        Ok(buf)
    } else {
        Err(ErrNo::NoSys)
    }
}

/// Return a random u32
fn random_u32() -> FileSystemResult<u32> {
    let result: [u8; 4] = getrandom_to_buffer(4)?
        .as_slice()
        .try_into()
        .map_err(|_| ErrNo::Inval)?;
    Ok(u32::from_le_bytes(result))
}

/// Return a random u64
fn random_u64() -> FileSystemResult<u64> {
    let result: [u8; 8] = getrandom_to_buffer(8)? 
        .as_slice()
        .try_into()
        .map_err(|_| ErrNo::Inval)?;
    Ok(u64::from_le_bytes(result))
}

////////////////////////////////////////////////////////////////////////////////
// INodes.
////////////////////////////////////////////////////////////////////////////////

/// INodes wrap the actual raw file data, and associate meta-data with that raw
/// data buffer.
#[derive(Clone, Debug)]
struct InodeEntry {
    /// The current inode.
    current: Inode,
    /// The parent inode.
    parent: Inode,
    /// The path of this inode relative to the parent.
    path: PathBuf,
    /// The status of this file.
    file_stat: FileStat,
    /// The content of the inode.
    data: InodeImpl,
}

impl InodeEntry {
    /// Resize a file to `size`, fill with `fill_byte` if it grows,
    /// and update the file status.
    /// Return ErrNo::IsDir, if it is not a file
    pub(self) fn resize_file(&mut self, size: FileSize, fill_byte: u8) -> FileSystemResult<()> {
        self.data.resize_file(size, fill_byte)?;
        self.file_stat.file_size = size;
        Ok(())
    }

    /// Read maximum `max` bytes from the offset `offset`.
    /// Return ErrNo::IsDir if it is not a file.
    pub(self) fn read_file(&self, max: usize, offset: FileSize) -> FileSystemResult<Vec<u8>> {
        self.data.read_file(max, offset)
    }

    /// Write `buf` to the file from the offset `offset`,
    /// update the file status and return the number of written bytes.
    /// Otherwise, return ErrNo::IsDir if it is not a file.
    pub(self) fn write_file(&mut self, buf: Vec<u8>, offset: FileSize) -> FileSystemResult<Size> {
        let rst = self.data.write_file(buf, offset)?;
        self.file_stat.file_size = self.data.len()?;
        Ok(rst)
    }

    /// Truncate the file.
    /// Return ErrNo::IsDir if it is not a file.
    pub(self) fn truncate_file(&mut self) -> FileSystemResult<()> {
        self.data.truncate_file()?;
        self.file_stat.file_size = 0u64;
        Ok(())
    }

    /// Insert a file to the directory at `self`.
    /// Return ErrNo:: NotDir if `self` is not a directory.
    pub(self) fn insert<T: AsRef<Path>>(&mut self, path: T, inode: Inode) -> FileSystemResult<()> {
        self.data.insert(path, inode)
    }

    /// Return the inode of `path`.
    /// Return ErrNo:: NotDir if `self` is not a directory.
    pub(self) fn get_inode_by_path<T: AsRef<Path>>(&self, path: T) -> FileSystemResult<Inode> {
        self.data.get_inode_by_path(path)
    }

    /// Return the absolute path of this inode.
    pub(self) fn absolute_path(&self, inode_table: &InodeTable) -> FileSystemResult<PathBuf> {
        if self.current == self.parent {
            Ok(self.path.clone())
        } else {
            let mut parent_path = inode_table.get(&self.parent)?.absolute_path(inode_table)?;
            parent_path.push(self.path.as_path());
            Ok(parent_path)
        }
    }

    /// Check if the inode is a directory
    pub(crate) fn is_dir(&self) -> bool {
        self.data.is_dir()
    }

    /// Read metadata of all files and sub-dirs in the dir and return a vec of DirEnt,
    /// or return NotDir if `self` is not a dir
    pub(self) fn read_dir(&self, inode_table: &InodeTable) -> FileSystemResult<Vec<(DirEnt, Vec<u8>)>> {
        self.data.read_dir(inode_table)
    }
}

/// The actual data of an inode, either a file or a directory.
#[derive(Clone, Debug)]
enum InodeImpl {
    /// A file
    File(Vec<u8>),
    /// A directory. The `PathBuf` key is the relative path and must match to the name inside the `Inode`.
    Directory(HashMap<PathBuf, Inode>),
}

impl InodeImpl {
    /// Return a new Directory InodeImpl containing only current and parent paths
    pub(crate) fn new_directory(current: Inode, parent: Inode) -> Self {
        let mut dir = HashMap::new();
        dir.insert(PathBuf::from("."), current);
        dir.insert(PathBuf::from(".."), parent);
        Self::Directory(dir)
    }

    /// Resize a file to `size`, and fill with `fill_byte` if it grows.
    /// Otherwise, return ErrNo::IsDir if it is not a file.
    pub(self) fn resize_file(&mut self, size: FileSize, fill_byte: u8) -> FileSystemResult<()> {
        match self {
            Self::File(file) => {
                file.resize(size as usize, fill_byte);
                Ok(())
            }
            Self::Directory(_) => Err(ErrNo::IsDir),
        }
    }

    /// Read maximum `max` bytes from the offset `offset`.
    /// Otherwise, return ErrNo::IsDir if it is not a file.
    pub(self) fn read_file(&self, max: usize, offset: FileSize) -> FileSystemResult<Vec<u8>> {
        let bytes = match self {
            Self::File(b) => b,
            Self::Directory(_) => return Err(ErrNo::IsDir),
        };
        // NOTE: It should be safe to convert a u64 to usize.
        let offset = offset as usize;
        //          offset
        //             v
        // ---------------------------------------------
        // |  ....     | to_read              |        |
        // ---------------------------------------------
        //             v ...  read_length ... v
        //             ------------------------
        //             | rst                  |
        //             ------------------------
        let (_, to_read) = bytes.split_at(offset);
        let read_length = if max < to_read.len() {
            max
        } else {
            to_read.len()
        };
        let (rst, _) = to_read.split_at(read_length);
        info!("call read_file read {:?} bytes", rst.len());
        Ok(rst.to_vec())
    }

    /// Write `buf` to the file from the offset `offset` and return the number of written bytes.
    /// Otherwise, return ErrNo::IsDir if it is not a file.
    pub(self) fn write_file(&mut self, buf: Vec<u8>, offset: FileSize) -> FileSystemResult<Size> {
        let bytes = match self {
            Self::File(b) => b,
            Self::Directory(_) => return Err(ErrNo::IsDir),
        };
        info!("call write_file before: {:?}", bytes.len());
        // NOTE: It should be safe to convert a u64 to usize.
        let offset = offset as usize;
        //          offset
        //             v  .. remain_length .. v
        // ----------------------------------------------
        // |  ....     | to_write             0 0 ...   |
        // ----------------------------------------------
        //             v     ...    buf.len()    ...    v
        //             ----------------------------------
        //             | buf                            |
        //             ----------------------------------
        let remain_length = bytes.len() - offset;
        if remain_length <= buf.len() {
            info!("call fd_pwrite grows length");
            let mut grow_vec = vec![0; buf.len() - remain_length];
            bytes.append(&mut grow_vec);
        }
        let rst = buf.len();
        bytes[offset..(offset + rst)].copy_from_slice(&buf);
        info!("call write_file result: {:?}", bytes.len());
        Ok(rst as Size)
    }

    /// Truncate the file.
    /// Return ErrNo::IsDir if it is not a file.
    pub(self) fn truncate_file(&mut self) -> FileSystemResult<()> {
        match self {
            Self::File(b) => {
                b.clear();
                Ok(())
            }
            Self::Directory(_) => Err(ErrNo::IsDir),
        }
    }

    /// Insert a file to the directory at `self`.
    /// Return ErrNo:: NotDir if `self` is not a directory.
    pub(self) fn insert<T: AsRef<Path>>(&mut self, path: T, inode: Inode) -> FileSystemResult<()> {
        match self {
            InodeImpl::Directory(path_table) => {
                path_table.insert(path.as_ref().to_path_buf(), inode.clone())
            }
            _otherwise => return Err(ErrNo::NotDir),
        };
        Ok(())
    }

    /// Insert a file to the directory at `self`.
    /// Return ErrNo:: NotDir if `self` is not a directory.
    pub(self) fn get_inode_by_path<T: AsRef<Path>>(&self, path: T) -> FileSystemResult<Inode> {
        match self {
            InodeImpl::Directory(path_table) => {
                Ok(path_table.get(path.as_ref()).ok_or(ErrNo::NoEnt)?.clone())
            }
            _otherwise => return Err(ErrNo::NotDir),
        }
    }

    /// Return the number of the bytes, if it is a file,
    /// or the number of inodes, if it it is a directory.
    pub(self) fn len(&self) -> FileSystemResult<FileSize> {
        let rst = match self {
            Self::File(f) => f.len(),
            Self::Directory(f) => f.len(),
        };
        Ok(rst as FileSize)
    }

    /// Check if it is a directory
    pub(crate) fn is_dir(&self) -> bool {
        match self {
            Self::Directory(_) => true,
            _ => false,
        }
    }

    /// Read metadata of files in the dir and return a vec of DirEnt,
    /// or return NotDir if `self` is not a dir
    pub(self) fn read_dir(&self, inode_table: &InodeTable) -> FileSystemResult<Vec<(DirEnt, Vec<u8>)>> {
        let dir = match self {
            InodeImpl::Directory(d) => d,
            _otherwise => return Err(ErrNo::NotDir),
        };
        let mut rst = Vec::new();
        for (index, (path, inode)) in dir.iter().enumerate() {
            let path = path.as_os_str().as_bytes().to_vec();
            let dir_ent = DirEnt {
                next: (index as u64 + 1u64).into(),
                inode: inode.clone(),
                name_len: path.len() as u32,
                file_type: inode_table.get(&inode)?.file_stat.file_type,
            };
            rst.push((dir_ent, path))
        }
        Ok(rst)
    }
}

struct InodeTable {
    /// All inodes
    table: HashMap<Inode, InodeEntry>,
    /// The Right table for Principal, including participants and programs.
    /// It will be used to create a new FileSystem (handler).
    rights_table: RightsTable,
    /// The inodes for stdin, stdout and stderr, respectively.
    stdin: Inode,
    stdout: Inode,
    stderr: Inode,
}

impl InodeTable {
    /// The root directory name. It will be pre-opened for any wasm program.
    pub(self) const ROOT_DIRECTORY: &'static str = "/";
    /// The root directory inode. It will be pre-opened for any wasm program.
    /// File descriptors 0 to 2 are reserved for the standard streams.
    /// TODO change to 2
    pub(self) const ROOT_DIRECTORY_INODE: Inode = Inode(2);
    fn new(rights_table: RightsTable) -> FileSystemResult<Self> {
        let mut rst = Self {
            table: HashMap::new(),
            // Must update those fields with random number
            // See below the function call install_standard_streams
            stdin: Inode(0),
            stdout: Inode(1),
            stderr: Inode(2),
            rights_table,
        };
        // Add the root directory
        rst
        .add_dir(
            Self::ROOT_DIRECTORY_INODE,
            Path::new(Self::ROOT_DIRECTORY),
            Self::ROOT_DIRECTORY_INODE,
        )?;
        // Add the standard in out and err.
        rst.install_standard_streams_inode()?;
        Ok(rst)
    }

    fn install_new_rights_table(&mut self, rights_table: RightsTable)  -> FileSystemResult<()> {
        self.rights_table = rights_table;
        Ok(())
    }

    /// Install standard streams (`stdin`, `stdout`, `stderr`).
    fn install_standard_streams_inode(
        &mut self,
    ) -> FileSystemResult<()> {
        self.stdin = self.new_inode()?;
        self.add_file(
            self.stdin,
            "stdin",
            self.stdin,
            "".as_bytes(),
        )?;

        self.stdout = self.new_inode()?;
        self.add_file(
            self.stdout,
            "stdout",
            self.stdout,
            "".as_bytes(),
        )?;

        self.stderr = self.new_inode()?;
        self.add_file(
            self.stderr,
            "stderr",
            self.stderr,
            "".as_bytes(),
        )?;
        Ok(())
    }

    fn stdin(&self) -> Inode {
        self.stdin
    }

    fn stdout(&self) -> Inode {
        self.stdout
    }

    fn stderr(&self) -> Inode {
        self.stderr
    }

    /// Insert a new inode 
    fn insert(&mut self, inode: Inode, entry : InodeEntry) -> FileSystemResult<()> {
        self.table.insert(inode, entry);
        Ok(())
    }

    /// Return the inode entry associated to `inode`
    fn get(&self, inode: &Inode) -> FileSystemResult<&InodeEntry> {
        self.table.get(&inode).ok_or(ErrNo::NoEnt)
    }

    /// Return the inode entry associated to `inode`
    fn get_mut(&mut self, inode: &Inode) -> FileSystemResult<&mut InodeEntry> {
        self.table.get_mut(&inode).ok_or(ErrNo::NoEnt)
    }

    fn is_dir(&self, inode: &Inode) -> bool {
        self.get(inode).map(|i| i.is_dir()).unwrap_or(false)
    }

    fn get_rights(&self, principal: &Principal) -> FileSystemResult<&HashMap<PathBuf, Rights>> {
        self.rights_table.get(principal).ok_or(ErrNo::Access)
    }

    /// Return the inode and the associated inode entry at the relative `path` in the parent
    /// inode `parent_inode`. Return Error if `fd` is not a directory.
    fn get_inode_by_inode_path<T: AsRef<Path>>(
        &self,
        parent_inode: &Inode,
        path: T,
    ) -> FileSystemResult<(Inode, &InodeEntry)> {
        let parent_inode = parent_inode.clone();
        info!("get_inode_by_inode_path parent {:?} the content {:?}",parent_inode, self.get(&parent_inode));
        let inode = path
            .as_ref()
            .components()
            .fold(Ok(parent_inode), |last, component| {
                // If there is an error
                let last = last?;
                // Find the next inode
                self.get(&last)?.get_inode_by_path(component)
            })?;
        //let inode = parent_inode_entry.get_inode_by_path(path.as_ref())?;
        Ok((inode, self.get(&inode)?))
    }

    /// Pick a fresh inode randomly.
    fn new_inode(&self) -> FileSystemResult<Inode> {
        loop {
            let new_inode = Inode(random_u64()?);
            if !self.table.contains_key(&new_inode) {
                return Ok(new_inode);
            }
        }
    }


    /// Install a directory with inode `new_inode` and attatch it under the parent inode `parent`.
    /// The `new_inode` MUST be fresh.
    fn add_dir<T: AsRef<Path>>(
        &mut self,
        parent: Inode,
        path: T,
        new_inode: Inode,
    ) -> FileSystemResult<()> {
        let file_stat = FileStat {
            device: (0u64).into(),
            inode: new_inode.clone(),
            file_type: FileType::Directory,
            num_links: 0,
            file_size: 0u64,
            atime: Timestamp::from_nanos(0),
            mtime: Timestamp::from_nanos(0),
            ctime: Timestamp::from_nanos(0),
        };
        let path = path.as_ref().to_path_buf();
        let node = InodeEntry {
            current: new_inode.clone(),
            parent,
            file_stat,
            path: path.clone(),
            data: InodeImpl::new_directory(new_inode.clone(), parent.clone()),
        };
        // NOTE: first add the inode to its parent inode, in the case of parent is not a directory,
        // it causes error and no side effect will be made to the file system, i.e no island inode.
        // If parent is not equal to new_inode, it means `new_inode` is not a ROOT,
        // Hence, add the new inode into the parent inode dir.
        if parent != new_inode {
            self.table
                .get_mut(&parent)
                .ok_or(ErrNo::NoEnt)?
                .insert(path.clone(), new_inode.clone())?;
        }
        // Add the map from the new inode to inode implementation.
        self.insert(new_inode.clone(), node)?;
        Ok(())
    }

    /// Create all directories in the `path`, if necessary, e.g. `/path/to/a/new/dir`.
    /// The last component in `path` will be treated a directory rather a file.
    fn add_all_dir<T: AsRef<Path>>(&mut self, mut parent: Inode, path: T) -> FileSystemResult<Inode> {
        // iterate over the path and create the directory if necessary.
        for component in path.as_ref().components() {
            if let Component::Normal(c) = component {
                let new_parent = match self.get_inode_by_inode_path(&parent, c) {
                    Ok((o, _)) => o,
                    // Directory is not exist, hence create it.
                    Err(ErrNo::NoEnt) => {
                        let new_inode = self.new_inode()?;
                        self.add_dir(parent.clone(), c, new_inode.clone())?;
                        new_inode
                    }
                    Err(e) => return Err(e),
                };
                parent = new_parent;
            } else {
                return Err(ErrNo::Inval);
            }
        }
        Ok(parent)
    }

    /// Install a file with content `raw_file_data` and attatch it to `inode`.
    /// Create any missing directory in the path.
    fn add_file<T: AsRef<Path>>(
        &mut self,
        parent: Inode,
        path: T,
        new_inode: Inode,
        raw_file_data: &[u8],
    ) -> FileSystemResult<()> {
        let path = path.as_ref();
        info!("call add_file with parent {:?} and path {:?}", parent, path);
        // Create missing directories in the `parent` inode if the path contains directory,
        // and shift the `parent` to the direct parent of the new file.
        // Note that if the parent() return None, it means an empty `path` is passed in, hence it
        // is an error.
        let (parent, path) = {
            let parent_path = path.parent().ok_or(ErrNo::Inval)?;
            // No parent, directly add it
            if parent_path == Path::new("") {
                info!("add_file without parent");
                (parent, path)
            } else {
                let file_path = path.file_name().map(|s| s.as_ref()).ok_or(ErrNo::Inval)?;
                self.add_all_dir(parent, parent_path)?;
                (
                    self.get_inode_by_inode_path(&parent, parent_path)?.0,
                    file_path,
                )
            }
        };
        //let (parent, path) = if let Some(parent_path) = path.parent() {
            //info!("parent_path: {:?}",parent_path)
            //let file_path = path.file_name().map(|s| s.as_ref()).ok_or(ErrNo::Inval)?;
            //self.add_all_dir(parent, parent_path)?;
            //(
                //self.get_inode_by_inode_path(&parent, parent_path)?.0,
                //file_path,
            //)
        //} else {
            //(parent, path)
        //};
        info!(
            "call add_file with new parent {:?} and path {:?}",
            parent, path
        );
        let file_size = raw_file_data.len();
        let file_stat = FileStat {
            device: 0u64.into(),
            inode: new_inode.clone(),
            file_type: FileType::RegularFile,
            num_links: 0,
            file_size: file_size as u64,
            atime: Timestamp::from_nanos(0),
            mtime: Timestamp::from_nanos(0),
            ctime: Timestamp::from_nanos(0),
        };
        let node = InodeEntry {
            current: new_inode.clone(),
            parent,
            file_stat,
            path: path.to_path_buf(),
            data: InodeImpl::File(raw_file_data.to_vec()),
        };
        // Add the map from the new inode to inode implementation.
        self.insert(new_inode.clone(), node)?;
        // Add the new inode into the parent inode dir. If the parent == new_inode, it may be
        // special inode, e.g. stdin stdout stderr
        if parent != new_inode {
            self.table
                .get_mut(&parent)
                .ok_or(ErrNo::NoEnt)?
                .insert(path, new_inode.clone())?;
        }
        Ok(())
    }

    fn print(&self) {
        info!("inode table");
        for (k,v) in self.table.iter() {
        info!("{:?} ->{}",k,if v.is_dir() { format!("{:?}",v.data) } else { format!("file") });
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// File-table entries.
////////////////////////////////////////////////////////////////////////////////

/// Each file table entry contains an index into the inode table, pointing to an
/// `InodeEntry`, where the static file data is stored.
#[derive(Clone, Debug)]
struct FdEntry {
    /// The index to `inode_table` in FileSystem.
    inode: Inode,
    /// Metadata for the file descriptor.
    fd_stat: FdStat,
    /// The current offset of the file descriptor.
    offset: FileSize,
    /// Advice on how regions of the file are to be used.
    advice: Vec<(FileSize, FileSize, Advice)>,
}

////////////////////////////////////////////////////////////////////////////////
// Filesystems.
////////////////////////////////////////////////////////////////////////////////

/// The filesystem proper, which collects together various tables and bits of
/// meta-data.
#[derive(Clone)]
pub struct FileSystem {
    /// A table of file descriptor table entries.  This is indexed by file
    /// descriptors.  
    fd_table: HashMap<Fd, FdEntry>,
    /// In order to quickly allocate file descriptors, we keep track of a monotonically increasing
    /// candidate, starting just above the reserved values. With this approach, file descriptors
    /// can not be re-allocated after being freed, imposing an artificial limit of 2^31 file
    /// descriptor allocations over the course of a program's execution.
    next_fd_candidate: Fd,
    /// The inode table, which points to the actual data associated with a file
    /// and other metadata.  This table is indexed by the Inode.
    inode_table: SharedInodeTable,
    /// We allocate inodes in the same way as we allocate file descriptors. Inode's are 64 bits
    /// rather than 31 bits, so the artificial limit on inode allocations is 2^64.
    next_inode_candidate: Inode,
    /// Preopen FD table. Mapping the FD to dir name.
    prestat_table: HashMap<Fd, PathBuf>,
}

impl FileSystem {
    ////////////////////////////////////////////////////////////////////////////
    // Creating filesystems.
    ////////////////////////////////////////////////////////////////////////////
    //// TODO FIRST_FD???
    /// The root directory file descriptor. It will be pre-opened for any wasm program.
    pub const ROOT_DIRECTORY_FD: Fd = Fd(3);
    /// The default initial rights on a newly created file.
    pub const DEFAULT_RIGHTS: Rights = Rights::all();

    /// Creates a new, empty filesystem and return the superuser handler, which has all the
    /// capabilities on the entire filesystem.
    ///
    /// NOTE: the file descriptors 0, 1, and 2 are pre-allocated for stdin and
    /// similar with respect to the parameter `std_streams_table`.  
    /// Rust programs are going to expect that this is true, so we
    /// need to preallocate some files corresponding to those, here.
    #[inline]
    pub fn new(
        //TODO REMOVE
        rights_table: RightsTable,
    ) -> FileSystemResult<Self> {
        let mut rst = Self {
            fd_table: HashMap::new(),
            next_fd_candidate: Fd(u32::from(Self::ROOT_DIRECTORY_FD) + 1),
            inode_table: Arc::new(Mutex::new(InodeTable::new(rights_table)?)),
            next_inode_candidate: Inode(u64::from(Self::ROOT_DIRECTORY_INODE) + 1),
            prestat_table: HashMap::new(),
        };
        let mut all_rights = HashMap::new();
        all_rights.insert(PathBuf::from("/"), Rights::all());
        all_rights.insert(PathBuf::from("stdin"), Rights::all());
        all_rights.insert(PathBuf::from("stdout"), Rights::all());
        all_rights.insert(PathBuf::from("stderr"), Rights::all());

        //// Set up standard streams table
        //let std_streams_table = vec![
            //StandardStream::Stdin(FileRights::new(
                //String::from("stdin"),
                //Rights::all(),
            //)),
            //StandardStream::Stdout(FileRights::new(
                //String::from("stdout"),
                //Rights::all(),
            //)),
            //StandardStream::Stderr(FileRights::new(
                //String::from("stderr"),
                //Rights::all(),
            //)),
        //];

        rst.install_prestat::<PathBuf>(&all_rights)?;
        rst.lock_inode_table()?.print();
        Ok(rst)
    }

    pub fn spawn(
        &self,
        principal: &Principal,
    ) -> FileSystemResult<Self> {
        info!("filesystem spawn is called");
        let mut rst = Self {
            fd_table: HashMap::new(),
            inode_table: self.inode_table.clone(),
            prestat_table: HashMap::new(),
        };
        // Must clone as install_prestat need to lock the inode_table too
        let rights_table = self.lock_inode_table()?.get_rights(principal)?.clone();
        info!("filesystem spawn rights_table: {:?}", rights_table);
        rst.install_prestat::<PathBuf>(&rights_table)?;
        info!("filesystem spawn fd_table: {:?}", rights_table);
        rst.lock_inode_table()?.print();
        Ok(rst)
    }

    /// Create a dummy filesystem
    pub(crate) fn new_dummy() -> Self {
        let mut rights_table = HashMap::new();
        rights_table.insert(Principal::NoCap, HashMap::new());
        Self {
            fd_table: HashMap::new(),
            inode_table: Arc::new(Mutex::new(InodeTable::new(rights_table).unwrap())),
            prestat_table: HashMap::new(),
        }
    }

    /// install a new rights table for the file system. This function should only be called INSIDE
    /// this crate.
    pub(crate) fn install_new_rights_table(&mut self, rights_table: RightsTable) -> FileSystemResult<()> {
        self.lock_inode_table()?.install_new_rights_table(rights_table)
    }

    ////////////////////////////////////////////////////////////////////////
    // Internal auxiliary methods
    ////////////////////////////////////////////////////////////////////////
    
    /// Lock the inode table
    fn lock_inode_table(&self) -> FileSystemResult<MutexGuard<InodeTable>> {
        self.inode_table.lock().map_err(|_| ErrNo::Busy)
    }

    /// Install standard streams (`stdin`, `stdout`, `stderr`).
    fn install_standard_streams_fd(
        &mut self,
        std_streams_table: &Vec<StandardStream>,
    ) -> FileSystemResult<()> {
        info!("call install_standard_streams_fd");
        for std_stream in std_streams_table {
            // Map each standard stream to an fd and inode.
            // Rights are assumed to be already configured by the execution engine in the rights table
            // at that point.
            // Base rights are ignored and replaced with the default rights

            let (rights, fd_number, inode_number) = match std_stream {
                // TODO USE RANDOM INODE
                StandardStream::Stdin(file_rights) => (file_rights.rights(), 0, self.lock_inode_table()?.stdin()),
                StandardStream::Stdout(file_rights) => (file_rights.rights(), 1, self.lock_inode_table()?.stdout()),
                StandardStream::Stderr(file_rights) => (file_rights.rights(), 2, self.lock_inode_table()?.stderr()),
            };
            //self.lock_inode_table()?
                //.add_file(
                //Self::ROOT_DIRECTORY_INODE,
                //&path,
                //Inode(inode_number),
                //"".as_bytes(),
            //)?;
            self.install_fd(
                Fd(fd_number),
                FileType::RegularFile,
                inode_number,
                //TODO use the actual rights
                &Self::DEFAULT_RIGHTS,
                &Self::DEFAULT_RIGHTS,
            );
        }
        Ok(())
    }

    /// Install `stdin`, `stdout`, `stderr`, `$ROOT`, and all dir in `dir_paths`,
    /// and then pre-open them.
    fn install_prestat<T: AsRef<Path> + std::cmp::Eq + std::hash::Hash + Sized>(
        &mut self,
        rights_table: &HashMap<T, Rights>,
    ) -> FileSystemResult<()> {
        // Install ROOT_DIRECTORY_FD is the first FD prestat will open.
        // TODO move to inode_table ??
        //self.lock_inode_table()?
        //.add_dir(
            //Self::ROOT_DIRECTORY_INODE,
            //Path::new(Self::ROOT_DIRECTORY),
            //Self::ROOT_DIRECTORY_INODE,
        //)?;
        // TODO we no longer need this ?
        self.install_fd(
            Self::ROOT_DIRECTORY_FD,
            FileType::Directory,
            InodeTable::ROOT_DIRECTORY_INODE,
            &Self::DEFAULT_RIGHTS,
            &Self::DEFAULT_RIGHTS,
        );
        // TODO we no longer need this ?
        self.prestat_table
            .insert(Self::ROOT_DIRECTORY_FD, PathBuf::from(InodeTable::ROOT_DIRECTORY));
        
        // contrusct the rights for stdin stdout and stderr.
        let std_streams_table = rights_table.iter().filter_map(|(k,v)|{
            let file : &Path = k.as_ref();
            let rights = *v;
            if file == Path::new("stdin") {
                Some(StandardStream::Stdin(FileRights::new(
                    String::from("stdin"),
                    u64::from(rights) as u32,
                )))
            } else if file == Path::new("stdout") {
                Some(StandardStream::Stdout(FileRights::new(
                    String::from("stdout"),
                    u64::from(rights) as u32,
                )))
            } else if file == Path::new("stderr") {
                Some(StandardStream::Stderr(FileRights::new(
                    String::from("stderr"),
                    u64::from(rights) as u32,
                )))
            } else {
                None
            }
        }).collect::<Vec<_>>();
        // Pre open the standard streams.
        self.install_standard_streams_fd(&std_streams_table)?;

        // TODO: REMOVE ??? Assume the ROOT_DIRECTORY_FD is the first FD prestat will open.
        let root_fd_number = Self::ROOT_DIRECTORY_FD.0;
        //let root_inode_number = InodeTable::ROOT_DIRECTORY_INODE.0;

        // Load all pre-opened directories. Create directories if necessary.
        for (index, (path, rights)) in rights_table.iter().filter(|(k,_)|{
            let k = k.as_ref();
            k != Path::new("stdin") 
            && k != Path::new("stdout")
            && k != Path::new("stderr")
        }).enumerate() {
            //Inode(index as u64 + root_inode_number + 1);
            // TODO CHANGE TO NOT +1
            let new_fd = Fd(index as u32 + root_fd_number + 1);
            let path = path.as_ref();
            // strip off the root
            let relative_path = path.strip_prefix("/").unwrap_or(path).clone();
            let new_inode = {
                if relative_path == Path::new("") {
                    InodeTable::ROOT_DIRECTORY_INODE
                } else {
                    self.lock_inode_table()?.add_all_dir(InodeTable::ROOT_DIRECTORY_INODE, relative_path)?
                }
            };
            info!("install path: {:?} with inode {:?}", path, new_inode);
            self.install_fd(
                new_fd,
                // We use unknown here as we allow pre install either file or dir
                FileType::Unknown,
                new_inode,
                &rights,
                &rights,
            );
            self.prestat_table.insert(new_fd, path.to_path_buf());
        }

        Ok(())
    }

    /// Install a `fd` to the file system. The fd will be of type RegularFile.
    fn install_fd(
        &mut self,
        fd: Fd,
        file_type: FileType,
        inode: Inode,
        rights_base: &Rights,
        rights_inheriting: &Rights,
    ) {
        let fd_stat = FdStat {
            file_type,
            flags: FdFlags::empty(),
            rights_base: rights_base.clone(),
            rights_inheriting: rights_inheriting.clone(),
        };

        let fd_entry = FdEntry {
            inode: inode.clone(),
            fd_stat,
            offset: 0,
            /// Advice on how regions of the file are to be used.
            advice: Vec::new(),
        };
        self.fd_table.insert(fd.clone(), fd_entry);
    }

    /// Pick a new fd randomly.
    fn new_fd(&mut self) -> FileSystemResult<Fd> {
        let mut cur = self.next_fd_candidate;
        loop {
            if u32::from(cur) & 1 << 31 != 0 {
                return Err(ErrNo::NFile); // Not quite accurate, but this may be the best fit
            }
            let next = Fd(u32::from(cur) + 1);
            if !self.fd_table.contains_key(&cur) {
                self.next_fd_candidate = next;
                return Ok(cur);
            }
            cur = next;
        }
    }

    /// Pick a new inode randomly.
    fn new_inode(&mut self) -> FileSystemResult<Inode> {
        let mut cur = self.next_inode_candidate;
        loop {
            let next = match u64::from(cur).checked_add(1) {
                Some(next) => Inode(next),
                None => return Err(ErrNo::NFile), // Not quite accurate, but this may be the best fit
            };
            if !self.inode_table.contains_key(&cur) {
                self.next_inode_candidate = next;
                return Ok(cur);
            }
            cur = next;
        }
    }

    /// Check if `rights` is allowed in `fd`
    fn check_right(&self, fd: &Fd, rights: Rights) -> FileSystemResult<()> {
        if self
            .fd_table
            .get(fd)
            .ok_or(ErrNo::BadF)?
            .fd_stat
            .rights_base
            .contains(rights)
        {
            Ok(())
        } else {
            Err(ErrNo::Access)
        }
    }

    /// Return the inode and the associated inode entry, contained in file descriptor `fd`
    fn get_inode_by_fd(&self, fd: &Fd) -> FileSystemResult<Inode> {
        Ok(self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.inode)
    }

    /// Return the inode and the associated inode entry at the relative `path` in the file
    /// descriptor `fd`. Return Error if `fd` is not a directory.
    fn get_inode_by_fd_path<T: AsRef<Path>>(
        &self,
        fd: &Fd,
        path: T,
    ) -> FileSystemResult<Inode> {
        let parent_inode = self.get_inode_by_fd(&fd)?;
        info!("get_inode_by_fd_path fd {:?}",fd);
        Ok(self.lock_inode_table()?.get_inode_by_inode_path(&parent_inode, path)?.0)
    }

    ////////////////////////////////////////////////////////////////////////////
    // Operations on the filesystem. Rust style implementation of WASI API
    ////////////////////////////////////////////////////////////////////////////

    /// Allows the programmer to declare how they intend to use various parts of
    /// a file to the runtime.
    #[inline]
    pub(crate) fn fd_advise(
        &mut self,
        fd: Fd,
        offset: FileSize,
        len: FileSize,
        adv: Advice,
    ) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::FD_ADVISE)?;
        let entry = self.fd_table.get_mut(&fd).ok_or(ErrNo::BadF)?;
        entry.advice.push((offset, len, adv));
        Ok(())
    }

    /// The stub implementation of `fd_allocate`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn fd_allocate(
        &mut self,
        _fd: Fd,
        _offset: FileSize,
        _len: FileSize,
    ) -> FileSystemResult<()> {
        Err(ErrNo::NoSys)
    }

    /// Implements the `fd_close` operation on the filesystem, which closes a
    /// file descriptor.  Returns `ErrNo::BadF`, if `fd` is not a current file-descriptor.
    #[inline]
    pub(crate) fn fd_close(&mut self, fd: Fd) -> FileSystemResult<()> {
        self.fd_table.remove(&fd).ok_or(ErrNo::BadF)?;
        Ok(())
    }

    /// The stub implementation of `fd_datasync`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn fd_datasync(&mut self, fd: Fd) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::FD_DATASYNC)?;
        Err(ErrNo::NoSys)
    }

    /// Return a copy of the status of the file descriptor, `fd`.
    #[inline]
    pub(crate) fn fd_fdstat_get(&self, fd: Fd) -> FileSystemResult<FdStat> {
        Ok(self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.fd_stat.clone())
    }

    /// Change the flag associated with the file descriptor, `fd`.
    #[inline]
    pub(crate) fn fd_fdstat_set_flags(&mut self, fd: Fd, flags: FdFlags) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::FD_FDSTAT_SET_FLAGS)?;
        self.fd_table.get_mut(&fd).ok_or(ErrNo::BadF)?.fd_stat.flags = flags;
        Ok(())
    }

    /// Change the right associated with the file descriptor, `fd`.
    #[inline]
    pub(crate) fn fd_fdstat_set_rights(
        &mut self,
        fd: Fd,
        rights_base: Rights,
        rights_inheriting: Rights,
    ) -> FileSystemResult<()> {
        let mut fd_stat = self.fd_table.get_mut(&fd).ok_or(ErrNo::BadF)?.fd_stat;
        fd_stat.rights_base = rights_base;
        fd_stat.rights_inheriting = rights_inheriting;
        Ok(())
    }

    /// Return a copy of the status of the open file pointed by the file descriptor, `fd`.
    pub(crate) fn fd_filestat_get(&self, fd: Fd) -> FileSystemResult<FileStat> {
        let inode = self
            .fd_table
            .get(&fd)
            .map(|fte| fte.inode)
            .ok_or(ErrNo::BadF)?;

        Ok(self
            .lock_inode_table()?
            .get(&inode)?
            .file_stat
            .clone())
    }

    /// Change the size of the open file pointed by the file descriptor, `fd`. The extra bytes are
    /// filled with ZERO.
    pub(crate) fn fd_filestat_set_size(&mut self, fd: Fd, size: FileSize) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::FD_FILESTAT_SET_SIZE)?;
        let inode = self
            .fd_table
            .get(&fd)
            .map(|FdEntry { inode, .. }| inode.clone())
            .ok_or(ErrNo::BadF)?;

        self.lock_inode_table()?
            .get_mut(&inode)?
            .resize_file(size, 0)
    }

    /// Change the time of the open file pointed by the file descriptor, `fd`. If `fst_flags`
    /// contains `ATIME_NOW` or `MTIME_NOW`, the method immediately returns unsupported error
    /// `NoSys`.
    pub(crate) fn fd_filestat_set_times(
        &mut self,
        fd: Fd,
        atime: Timestamp,
        mtime: Timestamp,
        fst_flags: SetTimeFlags,
        current_time: Timestamp,
    ) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::FD_FILESTAT_SET_TIMES)?;
        let inode = self
            .fd_table
            .get(&fd)
            .map(|FdEntry { inode, .. }| inode.clone())
            .ok_or(ErrNo::BadF)?;
        let current_time = self.clock_time_get(ClockId::RealTime, Timestamp::from_nanos(0))?;

        let mut inode_table = self.lock_inode_table()?;
        let mut inode_impl = inode_table.get_mut(&inode)?;
        if fst_flags.contains(SetTimeFlags::ATIME_NOW) {
            inode_impl.file_stat.atime = current_time;
        } else if fst_flags.contains(SetTimeFlags::MTIME_NOW) {
            inode_impl.file_stat.mtime = current_time;
        } else if fst_flags.contains(SetTimeFlags::ATIME) {
            inode_impl.file_stat.atime = atime;
        } else if fst_flags.contains(SetTimeFlags::MTIME) {
            inode_impl.file_stat.mtime = mtime;
        }
        Ok(())
    }

    /// A rust-style implementation for `fd_pread`.
    /// The actual WASI spec, requires, after `fd`, an extra parameter of type IoVec,
    /// to which the content should be written.
    /// Also the WASI requires the function returns the number of byte read.
    /// However, the implementation of WASI spec of fd_pread depends on
    /// how a particular execution engine handles the memory.
    /// That is, different engines provide different API to interact the linear memory
    /// space of WASM. Hence, the method here return the read bytes as `Vec<u8>`.
    pub(crate) fn fd_pread(
        &self,
        fd: Fd,
        buffer_len: usize,
        offset: FileSize,
    ) -> FileSystemResult<Vec<u8>> {
        info!(
            "call fd_pread: fd {:?}, buffer_len {}, offset {}",
            fd, buffer_len, offset
        );
        self.check_right(&fd, Rights::FD_READ)?;
        let inode = self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.inode;

        self.lock_inode_table()?
            .get(&inode)?
            .read_file(buffer_len, offset)
    }

    /// Return the status of a pre-opened Fd `fd`.
    #[inline]
    pub(crate) fn fd_prestat_get(&mut self, fd: Fd) -> FileSystemResult<Prestat> {
        info!("fd_prestat_get Fd {:?} with {:?}",fd,self.prestat_table);
        let path = self.prestat_table.get(&fd).ok_or(ErrNo::BadF)?;
        let resource_type = PreopenType::Dir {
            name_len: path.as_os_str().len() as u32,
        };
        Ok(Prestat { resource_type })
    }

    /// Return the path of a pre-opened Fd `fd`. The path must be consistent with the status returned by `fd_prestat_get`
    #[inline]
    pub(crate) fn fd_prestat_dir_name(&mut self, fd: Fd) -> FileSystemResult<PathBuf> {
        info!("fd_prestat_dir_name Fd {:?}",fd);
        let path = self.prestat_table.get(&fd).ok_or(ErrNo::BadF)?;
        info!("fd_prestat_dir_name path {:?}",path);
        Ok(path.to_path_buf())
    }

    /// A rust-style implementation for `fd_pwrite`.
    /// The actual WASI spec, requires that `ciovec` is of type Vec<IoVec>.
    /// However, the implementation of WASI spec of fd_pread depends on
    /// how a particular execution engine handles the memory.
    /// That is, different engines provide different API to interact the linear memory
    /// space of WASM.
    pub(crate) fn fd_pwrite(
        &mut self,
        fd: Fd,
        buf: &[u8],
        offset: FileSize,
    ) -> FileSystemResult<Size> {
        info!(
            "call fd_pread: fd {:?}, buffer_len {}, offset {}",
            fd,
            buf.len(),
            offset
        );
        self.check_right(&fd, Rights::FD_WRITE)?;
        let inode = self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.inode;

        self.lock_inode_table()?
            .get_mut(&inode)?
            .write_file(buf.to_vec(), offset)
    }

    /// A rust-style base implementation for `fd_read`. It directly calls `fd_pread` with the
    /// current `offset` of Fd `fd` and then calls `fd_seek`.
    pub(crate) fn fd_read(&mut self, fd: Fd, len: usize) -> FileSystemResult<Vec<u8>> {
        self.check_right(&fd, Rights::FD_READ)?;
        let offset = self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.offset;

        let rst = self.fd_pread(fd, len, offset)?;
        self.fd_seek(fd, rst.len() as i64, Whence::Current)?;
        Ok(rst)
    }

    /// The implementation of `fd_readdir`.
    #[inline]
    pub(crate) fn fd_readdir(
        &mut self,
        fd: Fd,
        cookie: DirCookie,
    ) -> FileSystemResult<Vec<(DirEnt, Vec<u8>)>> {
        info!("call fd_readdir on {:?} and cookie {:?}", fd, cookie);
        self.check_right(&fd, Rights::FD_READDIR)?;
        //TODO REMOVE DEBUG CODE
        let dir_inode = self.get_inode_by_fd(&fd)?;
        // limit lock scope
        let mut dirs = {
            let inode_table = self.lock_inode_table()?;
            inode_table.get(&dir_inode)?.read_dir(&inode_table)?
        };
        let cookie = cookie.0 as usize;
        if dirs.len() < cookie {
            return Err(ErrNo::Inval);
        }
        let rst = dirs.split_off(cookie);
        info!("call fd_readdir dir {:?}", rst);
        Ok(rst)
    }

    /// Atomically renumbers the `old_fd` to the `new_fd`.  Note that as
    /// execution engine is single-threaded this is atomic from the WASM program's
    /// point of view.
    pub(crate) fn fd_renumber(&mut self, old_fd: Fd, new_fd: Fd) -> FileSystemResult<()> {
        let entry = self.fd_table.get(&old_fd).ok_or(ErrNo::BadF)?.clone();
        if self.fd_table.get(&new_fd).is_none() {
            self.fd_table.insert(new_fd, entry);
            self.fd_table.remove(&old_fd);
            Ok(())
        } else {
            Err(ErrNo::BadF)
        }
    }

    /// Change the offset of Fd `fd`.
    pub(crate) fn fd_seek(
        &mut self,
        fd: Fd,
        delta: FileDelta,
        whence: Whence,
    ) -> FileSystemResult<FileSize> {
        self.check_right(&fd, Rights::FD_SEEK)?;
        let FdEntry { inode, offset, .. } = self.fd_table.get(&fd).ok_or(ErrNo::BadF)?;
        let file_size = self
            .lock_inode_table()?
            .get(inode)?
            .file_stat
            .file_size;

        let new_base_offset = match whence {
            Whence::Current => *offset,
            Whence::End => file_size,
            Whence::Start => 0,
        };

        // NOTE: Ensure the computation does not overflow.
        let new_offset: FileSize = if delta >= 0 {
            // It is safe to convert a positive i64 to u64.
            let t_offset = new_base_offset + (delta.abs() as u64);
            // If offset is greater the file size, then expand the file.
            if t_offset > file_size {
                self.fd_filestat_set_size(fd.clone(), t_offset)?;
            }
            t_offset
        } else {
            // It is safe to convert a positive i64 to u64.
            if (delta.abs() as u64) > new_base_offset {
                return Err(ErrNo::SPipe);
            }
            new_base_offset - (delta.abs() as u64)
        };

        // Update the offset
        self.fd_table.get_mut(&fd).ok_or(ErrNo::BadF)?.offset = new_offset;
        Ok(new_offset)
    }

    /// The stub implementation of `fd_sync`. It is a no-op now.
    #[inline]
    pub(crate) fn fd_sync(&mut self, fd: Fd) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::FD_SYNC)?;
        Ok(())
    }

    /// Returns the current offset associated with the file descriptor.
    #[inline]
    pub(crate) fn fd_tell(&self, fd: Fd) -> FileSystemResult<FileSize> {
        self.check_right(&fd, Rights::FD_TELL)?;
        Ok(self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.offset.clone())
    }

    /// A rust-style base implementation for `fd_write`. It directly calls `fd_pwrite` with the
    /// current `offset` of Fd `fd` and then calls `fd_seek`.
    pub(crate) fn fd_write(&mut self, fd: Fd, buf: &[u8]) -> FileSystemResult<Size> {
        self.check_right(&fd, Rights::FD_WRITE)?;
        let offset = self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.offset;

        let rst = self.fd_pwrite(fd, buf, offset)?;
        self.fd_seek(fd, rst as i64, Whence::Current)?;
        Ok(rst)
    }

    /// The implementation of `path_create_directory`.
    #[inline]
    pub(crate) fn path_create_directory<T: AsRef<Path>>(
        &mut self,
        fd: Fd,
        path: T,
    ) -> FileSystemResult<()> {
        info!(
            "call path_create_directory with fd {:?} and path {:?}",
            fd,
            path.as_ref()
        );
        self.check_right(&fd, Rights::PATH_CREATE_DIRECTORY)?;
        info!("call path_create_directory capability check passes");
        let parent_inode = self.get_inode_by_fd(&fd)?;
        if !self.lock_inode_table()?.is_dir(&parent_inode) {
            return Err(ErrNo::NotDir);
        }
        // The path exists
        if self.get_inode_by_fd_path(&fd, path.as_ref()).is_ok() {
            return Err(ErrNo::Exist);
        }
        info!("call path_create_directory starts creating dir");
        // Create ALL missing dir in the path
        // In each round, the `last` carries the current parent inode or an error
        // and component is the next component in the path.
        path.as_ref().components().fold(
            Ok(parent_inode),
            |last: FileSystemResult<Inode>, component| {
                // If there is an error
                let last = last?;
                info!(
                    "call path_create_directory last {:?} and components {:?}",
                    last, component
                );
                let component_path = match component {
                    Component::Normal(p) => Ok(p),
                    _otherwise => Err(ErrNo::Inval),
                }?;
                let new_inode = self.lock_inode_table()?.new_inode()?;
                self.lock_inode_table()?.add_dir(last, component_path, new_inode)?;
                // return the next inode, preparing for the next round.
                Ok(new_inode)
            },
        )?;
        info!("call path_create_directory done");
        Ok(())
    }

    /// Return a copy of the status of the file at path `path`. We only support the searching from the root Fd. We ignore searching flag `flags`.
    pub(crate) fn path_filestat_get<T: AsRef<Path>>(
        &mut self,
        fd: Fd,
        _flags: LookupFlags,
        path: T,
    ) -> FileSystemResult<FileStat> {
        let path = path.as_ref();
        self.check_right(&fd, Rights::PATH_FILESTAT_GET)?;
        // ONLY allow search on the root for now.
        if fd != Self::ROOT_DIRECTORY_FD {
            return Err(ErrNo::NotDir);
        }
        let inode = self.get_inode_by_fd_path(&fd, path)?;
        Ok(self
            .lock_inode_table()?
            .get(&inode)?
            .file_stat
            .clone())
    }

    /// Change the time of the open file at `path` If `fst_flags`
    /// contains `ATIME_NOW` or `MTIME_NOW`, the method immediately returns unsupported error
    /// `NoSys`. We only support searching from the root Fd. We ignore searching flag `flags`.
    pub(crate) fn path_filestat_set_times<T: AsRef<Path>>(
        &mut self,
        fd: Fd,
        _flags: LookupFlags,
        path: T,
        atime: Timestamp,
        mtime: Timestamp,
        fst_flags: SetTimeFlags,
        current_time: Timestamp,
    ) -> FileSystemResult<()> {
        let path = path.as_ref();
        self.check_right(&fd, Rights::PATH_FILESTAT_SET_TIMES)?;
        // ONLY allow search on the root for now.
        if fd != Self::ROOT_DIRECTORY_FD {
            return Err(ErrNo::NotDir);
        }

        let inode = self.get_inode_by_fd_path(&fd, path)?;
        let mut inode_table = self.lock_inode_table()?;
        let mut inode_impl = inode_table.get_mut(&inode)?;
        if fst_flags.contains(SetTimeFlags::ATIME_NOW) {
            inode_impl.file_stat.atime = current_time;
        } else if fst_flags.contains(SetTimeFlags::MTIME_NOW) {
            inode_impl.file_stat.mtime = current_time;
        } else if fst_flags.contains(SetTimeFlags::ATIME) {
            inode_impl.file_stat.atime = atime;
        } else if fst_flags.contains(SetTimeFlags::MTIME) {
            inode_impl.file_stat.mtime = mtime;
        }
        Ok(())
    }

    /// A minimum functionality of opening a file or directory on behalf of the principal `principal`.
    /// We only support search from the root Fd. We ignore the dir look up flag.
    ///
    /// The behaviour of `path_open` varies based on the open flags `oflags`:
    /// * if no flag is set, open a file at the path, if exists, starting from the directory opened by the file descriptor `fd`;
    /// * if `EXCL` is set, `path_open` fails if the path exists;
    /// * if `CREATE` is set, create a new file at the path if the path does not exist;
    /// * if `TRUNC` is set, the file at the path is truncated, that is, clean the content and set the file size to ZERO; and
    /// * if `DIRECTORY` is set, `path_open` fails if the path is not a directory.
    pub(crate) fn path_open<T: AsRef<Path>>(
        &mut self,
        principal: &Principal,
        // The parent fd for searching
        fd: Fd,
        dirflags: LookupFlags,
        path: T,
        oflags: OpenFlags,
        rights_base: Rights,
        rights_inheriting: Rights,
        flags: FdFlags,
    ) -> FileSystemResult<Fd> {
        let path = path.as_ref();
        info!("call path_open, on behalf of fd {:?} and principal {:?}, dirflag {:?}, path {:?} with open_flag {:?}, right_base {:?}, rights_inheriting {:?} and fd_flag {:?}",
            fd, principal, dirflags.bits(), path, oflags, rights_base, rights_inheriting, flags);
        // Read the parent inode.
        let parent_inode = self.get_inode_by_fd(&fd)?;
        // NOTE: limit the lock space
        let mut absolute_path = {
            let inode_table = self.lock_inode_table()?;
            inode_table.get(&parent_inode)?.absolute_path(&inode_table)?
        };
        absolute_path.push(path.clone());
        // Manually convert to the canonicalize form.
        // NOTE that the canonicalize function call in pathbuf seems require some sys info.
        let absolute_path: PathBuf = absolute_path.iter().map(|c| c.clone()).collect();
        info!(
            "call path_open on abs path {:?}",
            absolute_path
        );
        if !self.lock_inode_table()?.is_dir(&parent_inode) {
            return Err(ErrNo::NotDir);
        }
        // Read the right related to the principal.
        // NOTE: A correct and better way to control capability is to
        // separate the Fd space of of different participants.
        let principal_right = if *principal != Principal::InternalSuperUser {
            self.get_right(&principal, absolute_path.as_path())?
        } else {
            Rights::all()
        };
        // Intersect with the inheriting right from `fd`
        let fd_inheriting = self
            .fd_table
            .get(&fd)
            .ok_or(ErrNo::BadF)?
            .fd_stat
            .rights_inheriting;
        let principal_right = principal_right & fd_inheriting;
        // Check the right of the program on path_open
        if !principal_right.contains(Rights::PATH_OPEN) {
            return Err(ErrNo::Access);
        }
        let rights_base = rights_base & principal_right;
        let rights_inheriting = rights_inheriting & principal_right;
        info!(
            "call path_open, the actually right {:?} and inheriting right {:?}",
            rights_base, rights_inheriting
        );
        // Several oflags logic, inc. `create`, `excl` and `directory`.
        let inode = match self.get_inode_by_fd_path(&fd, path) {
            Ok(inode) => {
                // If file exists and `excl` is set, return `Exist` error.
                if oflags.contains(OpenFlags::EXCL) {
                    return Err(ErrNo::Exist);
                }
                if oflags.contains(OpenFlags::DIRECTORY) && !self.lock_inode_table()?.is_dir(&inode) {
                    return Err(ErrNo::NotDir);
                }
                inode
            }
            Err(e) => {
                info!("AA: {:?}",e);
                // If file does NOT exists and `create` is NOT set, return `NoEnt` error.
                if !oflags.contains(OpenFlags::CREATE) {
                    return Err(e);
                }
                // Check the right of the program on create file
                if !principal_right.contains(Rights::PATH_CREATE_FILE) {
                    return Err(ErrNo::Access);
                }
                let new_inode = self.lock_inode_table()?.new_inode()?;
                self.lock_inode_table()?.add_file(parent_inode, path, new_inode, &vec![])?;
                new_inode
            }
        };
        // Truncate the file if `trunc` flag is set.
        if oflags.contains(OpenFlags::TRUNC) {
            // Check the right of the program on truacate
            if !principal_right.contains(Rights::PATH_FILESTAT_SET_SIZE) {
                return Err(ErrNo::Access);
            }
            self.lock_inode_table()?
                .get_mut(&inode)?
                .truncate_file()?;
        }
        let new_fd = self.new_fd()?;
        let FileStat {
            file_type,
            file_size,
            ..
        } = self.lock_inode_table()?.get(&inode)?.file_stat;
        let fd_stat = FdStat {
            file_type,
            flags,
            rights_base,
            rights_inheriting,
        };
        self.fd_table.insert(
            new_fd,
            FdEntry {
                inode,
                fd_stat,
                offset: 0,
                advice: vec![(0, file_size, Advice::Normal)],
            },
        );
        info!("new fd {:?} created for {:?}.", new_fd, absolute_path);
        Ok(new_fd)
    }

    /// The stub implementation of `path_readlink`. Return unsupported error `NoSys`.
    /// We only support the searching from the root Fd.
    #[inline]
    pub(crate) fn path_readlink<T: AsRef<Path>>(
        &mut self,
        fd: Fd,
        _path: T,
    ) -> FileSystemResult<Vec<u8>> {
        self.check_right(&fd, Rights::PATH_READLINK)?;
        // ONLY allow search on the root for now.
        if fd != Self::ROOT_DIRECTORY_FD {
            return Err(ErrNo::NotDir);
        }
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `path_remove_directory`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn path_remove_directory<T: AsRef<Path>>(
        &mut self,
        fd: Fd,
        _path: T,
    ) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::PATH_REMOVE_DIRECTORY)?;
        // ONLY allow search on the root for now.
        if fd != Self::ROOT_DIRECTORY_FD {
            return Err(ErrNo::NotDir);
        }
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `path_rename`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn path_rename<T: AsRef<Path>, R: AsRef<Path>>(
        &mut self,
        old_fd: Fd,
        _old_path: T,
        new_fd: Fd,
        _new_path: R,
    ) -> FileSystemResult<()> {
        self.check_right(&old_fd, Rights::PATH_RENAME_SOURCE)?;
        self.check_right(&new_fd, Rights::PATH_RENAME_TARGET)?;
        Err(ErrNo::NoSys)
    }

    /// Get random bytes.
    #[inline]
    pub(crate) fn random_get(&self, buf_len: Size) -> FileSystemResult<Vec<u8>> {
        getrandom_to_buffer(buf_len)
    }

    /// The stub implementation of `path_rename`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn path_link<T: AsRef<Path>, R: AsRef<Path>>(
        &mut self,
        old_fd: Fd,
        _old_flag: LookupFlags,
        _old_path: T,
        new_fd: Fd,
        _new_path: R,
    ) -> FileSystemResult<()> {
        self.check_right(&old_fd, Rights::PATH_LINK_SOURCE)?;
        self.check_right(&new_fd, Rights::PATH_LINK_TARGET)?;
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `path_symlink`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn path_symlink<T: AsRef<Path>, R: AsRef<Path>>(
        &mut self,
        _old_path: T,
        fd: Fd,
        _new_path: R,
    ) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::PATH_SYMLINK)?;
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `path_unlink_file`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn path_unlink_file<T: AsRef<Path>>(
        &mut self,
        fd: Fd,
        _path: T,
    ) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::PATH_UNLINK_FILE)?;
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `poll_oneoff`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn poll_oneoff(
        &mut self,
        _subscriptions: Vec<Subscription>,
        _events: Vec<Event>,
    ) -> FileSystemResult<Size> {
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `sock_recv`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn sock_recv(
        &mut self,
        socket: Fd,
        _buffer_len: usize,
        _ri_flags: RiFlags,
    ) -> FileSystemResult<(Vec<u8>, RoFlags)> {
        self.check_right(&socket, Rights::FD_READ)?;
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `sock_send`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn sock_send(
        &mut self,
        socket: Fd,
        _buf: &[u8],
        _si_flags: SiFlags,
    ) -> FileSystemResult<Size> {
        self.check_right(&socket, Rights::FD_WRITE)?;
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `sock_shutdown`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn sock_shutdown(&mut self, socket: Fd, _flags: SdFlags) -> FileSystemResult<()> {
        self.check_right(&socket, Rights::SOCK_SHUTDOWN)?;
        Err(ErrNo::NoSys)
    }

    ////////////////////////////////////////////////////////////////////////
    // Public interface for the filesystem.
    // It will be used by the veracruz runtime.
    ////////////////////////////////////////////////////////////////////////

    /// Write to a file on path `file_name`. If `is_append` is set, `data` will be append to `file_name`.
    /// Otherwise this file will be truncated. The `principal` must have the right on `path_open`,
    /// `fd_write` and `fd_seek`.
    pub fn write_file_by_absolute_path<T: AsRef<Path>>(
        &mut self,
        principal: &Principal,
        file_name: T,
        data: &[u8],
        is_append: bool,
    ) -> Result<(), ErrNo> {
        let file_name = file_name.as_ref();
        let file_name = file_name
            .strip_prefix("/")
            .unwrap_or(file_name)
            .clone();
        info!("write_file_by_filename: {:?}", file_name);
        let oflag = OpenFlags::CREATE
            | if !is_append {
                OpenFlags::TRUNC
            } else {
                OpenFlags::empty()
            };
        // create the dir if necessary
        if let Some(parent_path) = file_name.parent() {
            self.lock_inode_table()?.add_all_dir(InodeTable::ROOT_DIRECTORY_INODE, parent_path)?;
        }
        let fd = self.path_open(
            principal,
            FileSystem::ROOT_DIRECTORY_FD,
            LookupFlags::empty(),
            file_name,
            oflag,
            FileSystem::DEFAULT_RIGHTS,
            FileSystem::DEFAULT_RIGHTS,
            FdFlags::empty(),
        )?;
        if !self
            .fd_table
            .get(&fd)
            .ok_or(ErrNo::BadF)?
            .fd_stat
            .rights_base
            .contains(Rights::FD_WRITE | Rights::FD_SEEK)
        {
            return Err(ErrNo::Access);
        }
        if is_append {
            self.fd_seek(fd, 0, Whence::End)?;
        }
        self.fd_write(fd, data)?;
        self.fd_close(fd)?;
        Ok(())
    }

    /// Read a file on path `file_name`.
    /// The `principal` must have the right on `path_open`,
    /// `fd_read` and `fd_seek`.
    pub fn read_file_by_absolute_path<T: AsRef<Path>>(
        &mut self,
        principal: &Principal,
        file_name: T,
    ) -> Result<Vec<u8>, ErrNo> {
        let file_name = file_name.as_ref();
        let file_name = file_name
            .strip_prefix("/")
            .unwrap_or(file_name)
            .clone();
        info!("read_file_by_absolute_path: {:?}", file_name);
        let fd = self.path_open(
            principal,
            FileSystem::ROOT_DIRECTORY_FD,
            LookupFlags::empty(),
            file_name,
            OpenFlags::empty(),
            FileSystem::DEFAULT_RIGHTS,
            FileSystem::DEFAULT_RIGHTS,
            FdFlags::empty(),
        )?;
        if !self
            .fd_table
            .get(&fd)
            .ok_or(ErrNo::BadF)?
            .fd_stat
            .rights_base
            .contains(Rights::FD_READ | Rights::FD_SEEK)
        {
            return Err(ErrNo::Access);
        }
        let file_stat = self.fd_filestat_get(fd)?;
        let rst = self.fd_read(fd, file_stat.file_size as usize)?;
        self.fd_close(fd)?;
        Ok(rst)
    }

    /// Read all files recursively on path `path`.
    /// The `principal` must have the right on `path_open`,
    /// `fd_read` and `fd_seek`.
    pub fn read_all_files_by_absolute_path<T: AsRef<Path>>(
        &mut self,
        principal: &Principal,
        path: T,
    ) -> Result<Vec<(PathBuf, Vec<u8>)>, ErrNo> {
        let path = path.as_ref();
        info!("read_all_files_by_filename: {:?}", path);
        // Convert the absolute path to relative path and then find the inode
        let inode = self.lock_inode_table()?.get_inode_by_inode_path(
            &InodeTable::ROOT_DIRECTORY_INODE,
            path.strip_prefix("/").unwrap_or(path).clone(),
        )?.0;
        let mut rst = Vec::new();
        if self.lock_inode_table()?.is_dir(&inode) {
            // Limit the lock scope
            let all_dir = {
                let inode_table = self.lock_inode_table()?;
                inode_table.get(&inode)?.read_dir(&inode_table)?
            };
            for (_, sub_relative_path) in all_dir.iter() {
                let sub_relative_path =
                    PathBuf::from(OsString::from_vec(sub_relative_path.to_vec()));
                // Ignore the path for current and parent directories.
                if sub_relative_path != PathBuf::from(".")
                    && sub_relative_path != PathBuf::from("..")
                {
                    let mut sub_absolute_path = path.to_path_buf();
                    sub_absolute_path.push(sub_relative_path);
                    rst.append(
                        &mut self.read_all_files_by_absolute_path(principal, sub_absolute_path)?,
                    );
                }
            }
        } else {
            let buf = self.read_file_by_absolute_path(principal, path)?;
            rst.push((path.to_path_buf(), buf));
        }

        Ok(rst)
    }

    //TODO REMOVE
    /// Get the maximum right associated to the principal on the file
    fn get_right<T: AsRef<Path>>(
        &self,
        principal: &Principal,
        file_name: T,
    ) -> FileSystemResult<Rights> {
        let file_name = file_name.as_ref();
        let rights_table = self.lock_inode_table()?;
        let principal_rights_table = rights_table.get_rights(principal)?;
        for ancestor in file_name.ancestors() {
            if let Some(o) = principal_rights_table.get(ancestor) {
                return Ok(o.clone());
            }
        }
        Err(ErrNo::Access)
    }


    /// Return the type of the inode pointed by `fd`
    fn get_inode_type(&self, fd: &Fd) -> FileSystemResult<FileType>{
        let inode = self.get_inode_by_fd(fd)?;
        Ok(self.lock_inode_table()?.get(&inode)?.file_stat.file_type)
    }
}
