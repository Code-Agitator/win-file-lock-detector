//! Directory (and file) occupancy detection by scanning the system-wide
//! handle table, in the spirit of Sysinternals `handle.exe`.
//!
//! The Restart Manager can only be asked about files, so directories are
//! inspected directly:
//!
//! 1. Take a snapshot of every handle (`NtQuerySystemInformation`).
//! 2. Keep the ones whose object type is `File` (discovered empirically from
//!    a handle this process owns).
//! 3. Duplicate each candidate into this process, resolve its name with
//!    `GetFinalPathNameByHandleW` (falling back to `NtQueryObject`), and
//!    compare it with the target.
//!
//! Only disk objects are named; pipes and character devices are skipped,
//! which also avoids the known hangs of querying pipe object names.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use windows_sys::Win32::Foundation::HANDLE;

use crate::sys::{self, CandidatePath, DeviceMap};
use crate::{Error, PathRelation, Result, absolute_path};

/// Name resolution can block inside the kernel (for example on a handle to a
/// stalled device). Queries therefore run on a scratch thread and are
/// abandoned after this timeout.
const HANDLE_QUERY_TIMEOUT: Duration = Duration::from_millis(250);

enum QueryOutcome {
    Named {
        name: Option<String>,
        is_directory: Option<bool>,
    },
    TimedOut,
}

/// Resolve the name of a handle we already duplicated into this process.
///
/// The operation is enclosed in a timeout because `GetFinalPathNameByHandleW`
/// and `NtQueryObject` can block indefinitely on some devices. On timeout the
/// scratch thread and the duplicated handle are abandoned until process exit.
fn resolve_duplicate(handle_value: usize) -> QueryOutcome {
    let (sender, receiver) = mpsc::channel();

    let spawned = std::thread::Builder::new().spawn(move || {
        // SAFETY: handles are valid process-wide, and the value came from
        // `DuplicateHandle` in this process.
        let handle = handle_value as HANDLE;
        let name = sys::object_path(handle);
        let is_directory = if name.is_some() {
            sys::object_is_directory(handle)
        } else {
            None
        };
        sys::close_handle(handle);
        let _ = sender.send(QueryOutcome::Named { name, is_directory });
    });

    if spawned.is_err() {
        // Out of threads: report nothing rather than querying inline (which
        // could block the whole scan).
        sys::close_handle(handle_value as HANDLE);
        return QueryOutcome::Named {
            name: None,
            is_directory: None,
        };
    }

    match receiver.recv_timeout(HANDLE_QUERY_TIMEOUT) {
        Ok(outcome) => outcome,
        Err(RecvTimeoutError::Timeout) => QueryOutcome::TimedOut,
        Err(RecvTimeoutError::Disconnected) => QueryOutcome::Named {
            name: None,
            is_directory: None,
        },
    }
}

/// What kind of object a handle refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    Directory,
    File,
    Unknown,
}

impl ObjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ObjectKind::Directory => "directory",
            ObjectKind::File => "file",
            ObjectKind::Unknown => "unknown",
        }
    }
}

/// One open handle that points at the target or at something inside it.
#[derive(Debug, Clone)]
pub struct OpenHandle {
    pub pid: u32,
    pub image_path: Option<String>,
    /// The path the handle was opened on, in Win32 form when possible.
    pub matched_path: PathBuf,
    pub relation: PathRelation,
    pub object_kind: ObjectKind,
    /// Granted access mask of the original handle.
    pub access: u32,
}

/// Result of a handle-table scan.
#[derive(Debug, Clone)]
pub struct ScanReport {
    pub target: PathBuf,
    pub target_is_directory: bool,
    pub include_descendants: bool,
    pub handles: Vec<OpenHandle>,
    /// Processes whose handles could not be inspected (usually access denied).
    pub skipped_processes: Vec<u32>,
    /// Processes with at least one handle whose name query timed out.
    pub timed_out_processes: Vec<u32>,
    /// Number of `File` handles considered before filtering by name.
    pub examined_handles: usize,
}

impl ScanReport {
    pub fn is_in_use(&self) -> bool {
        !self.handles.is_empty()
    }

    pub fn process_count(&self) -> usize {
        self.handles
            .iter()
            .map(|handle| handle.pid)
            .collect::<BTreeSet<_>>()
            .len()
    }

    pub fn exact_handles(&self) -> impl Iterator<Item = &OpenHandle> {
        self.handles
            .iter()
            .filter(|handle| handle.relation == PathRelation::Exact)
    }

    pub fn descendant_handles(&self) -> impl Iterator<Item = &OpenHandle> {
        self.handles
            .iter()
            .filter(|handle| handle.relation == PathRelation::Descendant)
    }
}

/// Scan the system handle table for open handles on `target`.
///
/// When `target` is a directory and `include_descendants` is true, handles on
/// files and subdirectories inside it are reported as well; those are what
/// usually prevent deleting or renaming a directory. Set it to false to only
/// report handles that were opened on the directory itself.
pub fn scan_handles(target: &Path, include_descendants: bool) -> Result<ScanReport> {
    let metadata = match std::fs::metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::PathNotFound(target.to_path_buf()));
        }
        Err(error) => return Err(error.into()),
    };
    let target_is_directory = metadata.is_dir();

    let target_path = absolute_path(target)?;
    let target_display = target_path.to_string_lossy().into_owned();
    let target_display_folded = sys::normalize_for_compare(&target_display);

    let device_map = DeviceMap::new();
    let target_nt = device_map
        .to_nt(&target_display)
        .map(|nt| device_map.canonical_nt(&nt));
    let target_nt_folded = target_nt.as_deref().map(sys::normalize_for_compare);

    // Best effort: without this, handles of other users are invisible.
    let _ = sys::enable_debug_privilege();

    // A handle we own gives us the object type index of "File" objects.
    let sentinel =
        sys::open_sentinel().ok_or_else(|| Error::win32("CreateFileW", sys::last_error()))?;
    let snapshot = match sys::snapshot_handles() {
        Ok(snapshot) => {
            sys::close_handle(sentinel);
            snapshot
        }
        Err(error) => {
            sys::close_handle(sentinel);
            return Err(error);
        }
    };

    let self_pid = sys::current_pid();
    let sentinel_handle = sentinel as usize;
    let file_type_index = (0..snapshot.len())
        .map(|index| snapshot.entry(index))
        .find(|entry| entry.pid == self_pid && entry.handle == sentinel_handle)
        .map(|entry| entry.type_index)
        .ok_or(Error::Other(
            "could not locate the sentinel file handle in the system handle table",
        ))?;

    let mut process_handles: HashMap<u32, Option<HANDLE>> = HashMap::new();
    let mut image_paths: HashMap<u32, Option<String>> = HashMap::new();
    let mut inaccessible_processes = HashSet::new();
    let mut skipped_processes = BTreeSet::new();
    let mut timed_out_processes = BTreeSet::new();
    let mut seen = HashSet::new();
    let mut handles = Vec::new();
    let mut examined_handles = 0usize;

    for index in 0..snapshot.len() {
        let entry = snapshot.entry(index);
        if entry.type_index != file_type_index {
            continue;
        }
        // Idle/System never reference user paths in a useful way.
        if entry.pid <= 4 {
            continue;
        }
        if entry.pid == self_pid && entry.handle == sentinel_handle {
            continue;
        }
        examined_handles += 1;

        if inaccessible_processes.contains(&entry.pid) {
            continue;
        }

        let process = *process_handles
            .entry(entry.pid)
            .or_insert_with(|| sys::open_process_for_handles(entry.pid));
        let Some(process) = process else {
            skipped_processes.insert(entry.pid);
            inaccessible_processes.insert(entry.pid);
            continue;
        };

        let Some(duplicate) = sys::duplicate_handle(process, entry.handle) else {
            continue;
        };

        // Pipes, sockets and character devices share the `File` object type;
        // they cannot name a disk path, and querying them can block.
        if !sys::is_disk_object(duplicate) {
            sys::close_handle(duplicate);
            continue;
        }

        let (name, is_directory) = match resolve_duplicate(duplicate as usize) {
            QueryOutcome::Named { name, is_directory } => (name, is_directory),
            QueryOutcome::TimedOut => {
                timed_out_processes.insert(entry.pid);
                continue;
            }
        };

        let Some(name) = name else {
            continue;
        };

        let candidate = if name.starts_with(r"\Device\") || name.starts_with(r"\??\") {
            CandidatePath::from_object_name(name, &device_map)
        } else {
            CandidatePath::from_win32_path(name, &device_map)
        };

        let Some(relation) = sys::compare_paths(
            &target_display_folded,
            target_nt_folded.as_deref(),
            &candidate,
        ) else {
            continue;
        };
        if relation == PathRelation::Descendant && !include_descendants {
            continue;
        }

        let object_kind = match is_directory {
            Some(true) => ObjectKind::Directory,
            Some(false) => ObjectKind::File,
            None if relation == PathRelation::Exact => {
                if target_is_directory {
                    ObjectKind::Directory
                } else {
                    ObjectKind::File
                }
            }
            None => ObjectKind::Unknown,
        };

        if !seen.insert((entry.pid, candidate.display.to_lowercase())) {
            continue;
        }

        let image_path = image_paths
            .entry(entry.pid)
            .or_insert_with(|| sys::process_image_path(entry.pid))
            .clone();

        handles.push(OpenHandle {
            pid: entry.pid,
            image_path,
            matched_path: PathBuf::from(&candidate.display),
            relation,
            object_kind,
            access: entry.access,
        });
    }

    for handle in process_handles.values().flatten() {
        sys::close_handle(*handle);
    }

    handles.sort_by(|a, b| {
        a.relation
            .cmp(&b.relation)
            .then_with(|| a.matched_path.cmp(&b.matched_path))
            .then_with(|| a.pid.cmp(&b.pid))
    });

    Ok(ScanReport {
        target: target_path,
        target_is_directory,
        include_descendants,
        handles,
        skipped_processes: skipped_processes.into_iter().collect(),
        timed_out_processes: timed_out_processes.into_iter().collect(),
        examined_handles,
    })
}
