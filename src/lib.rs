//! Detect which Windows processes hold a file or directory open.
//!
//! Two complementary mechanisms are provided:
//!
//! * [`restart_manager::detect_file_lock`] asks the Windows Restart Manager
//!   which processes have a file open. This is the same information the
//!   "file is in use" dialog of Windows Installer is based on.
//! * [`handles::scan_handles`] walks the system-wide handle table (similar to
//!   Sysinternals `handle.exe`) and matches NT object names. It works for
//!   directories, which the Restart Manager cannot register, and for files
//!   whose lock the Restart Manager misses.
//!
//! Both APIs take a Win32 path (drive letters, `subst` drives and UNC paths
//! are supported). Complete results for handles owned by other users or
//! protected processes require running elevated; [`handles::scan_handles`]
//! reports the processes it could not inspect instead of silently omitting
//! them.

mod sys;

pub mod handles;
pub mod restart_manager;

use std::fmt;
use std::path::{Path, PathBuf};

pub use handles::{ObjectKind, OpenHandle, ScanReport, scan_handles};
pub use restart_manager::detect_file_lock;
pub use sys::PathRelation;

/// The kind of application the Restart Manager reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProcessKind {
    MainWindow,
    OtherWindow,
    Service,
    Explorer,
    Console,
    Critical,
    Unknown,
}

impl ProcessKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProcessKind::MainWindow => "main-window",
            ProcessKind::OtherWindow => "other-window",
            ProcessKind::Service => "service",
            ProcessKind::Explorer => "explorer",
            ProcessKind::Console => "console",
            ProcessKind::Critical => "critical",
            ProcessKind::Unknown => "unknown",
        }
    }
}

/// A process holding a file open, as reported by the Restart Manager.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    /// Full image path, when it could be queried.
    pub image_path: Option<String>,
    /// Friendly application name supplied by the Restart Manager.
    pub app_name: Option<String>,
    /// Short service name when the holder is a service.
    pub service_name: Option<String>,
    pub kind: ProcessKind,
}

/// Result of inspecting one file with the Restart Manager.
#[derive(Debug, Clone)]
pub struct FileLock {
    pub path: PathBuf,
    pub processes: Vec<ProcessInfo>,
}

impl FileLock {
    pub fn is_locked(&self) -> bool {
        !self.processes.is_empty()
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    PathNotFound(PathBuf),
    Win32 {
        operation: &'static str,
        code: u32,
    },
    Nt {
        operation: &'static str,
        status: i32,
    },
    Other(&'static str),
}

impl Error {
    pub(crate) fn win32(operation: &'static str, code: u32) -> Self {
        Error::Win32 { operation, code }
    }

    pub(crate) fn nt(operation: &'static str, status: i32) -> Self {
        Error::Nt { operation, status }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(error) => write!(f, "{error}"),
            Error::PathNotFound(path) => {
                write!(f, "path does not exist: {}", path.display())
            }
            Error::Win32 { operation, code } => write!(
                f,
                "{operation} failed with Win32 error {code}: {}",
                std::io::Error::from_raw_os_error(*code as i32)
            ),
            Error::Nt { operation, status } => {
                write!(f, "{operation} failed with NTSTATUS 0x{status:08X}")
            }
            Error::Other(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Resolve a path to an absolute, extended-prefix-free path.
///
/// `canonicalize` resolves symlinks/junctions and 8.3 names, which makes the
/// result comparable with NT object names. Non-existent paths fall back to a
/// lexical absolute path so callers can still report a useful error.
pub(crate) fn absolute_path(path: &Path) -> Result<PathBuf> {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        let canonical = canonical.to_string_lossy();
        return Ok(PathBuf::from(sys::strip_verbatim(&canonical)));
    }

    let absolute = std::path::absolute(path)?;
    Ok(PathBuf::from(sys::strip_verbatim(
        &absolute.to_string_lossy(),
    )))
}
