//! File lock detection backed by the Windows Restart Manager.
//!
//! The Restart Manager can only be asked about *files*, not directories, and it
//! answers per registered resource. To keep a one-to-one mapping between
//! queried paths and holders this module starts one session per file.

use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::RestartManager::{
    CCH_RM_SESSION_KEY, RM_APP_TYPE, RM_PROCESS_INFO, RmConsole, RmCritical, RmEndSession,
    RmExplorer, RmGetList, RmMainWindow, RmOtherWindow, RmRegisterResources, RmService,
    RmStartSession,
};

use crate::sys;
use crate::{Error, FileLock, ProcessInfo, ProcessKind, Result, absolute_path};

/// An open Restart Manager session; ended on drop.
struct Session {
    handle: u32,
}

impl Session {
    fn start() -> Result<Self> {
        let mut handle = 0u32;
        // RmStartSession writes CCH_RM_SESSION_KEY characters plus a NUL.
        let mut key = [0u16; CCH_RM_SESSION_KEY as usize + 1];

        // SAFETY: both out parameters are valid for the duration of the call.
        let result = unsafe { RmStartSession(&mut handle, 0, key.as_mut_ptr()) };
        if result != ERROR_SUCCESS {
            return Err(Error::win32("RmStartSession", result));
        }

        Ok(Self { handle })
    }

    fn register_file(&self, path: &Path) -> Result<()> {
        let path = sys::wide(&path.to_string_lossy());
        let files = [path.as_ptr()];

        // SAFETY: the path array and its strings outlive the call; no
        // applications or services are registered.
        let result = unsafe {
            RmRegisterResources(
                self.handle,
                files.len() as u32,
                files.as_ptr(),
                0,
                ptr::null(),
                0,
                ptr::null(),
            )
        };
        if result != ERROR_SUCCESS {
            return Err(Error::win32("RmRegisterResources", result));
        }

        Ok(())
    }

    fn processes(&self) -> Result<Vec<RM_PROCESS_INFO>> {
        let mut needed = 0u32;
        let mut count = 0u32;
        let mut reboot_reason = 0u32;

        // First call discovers the required buffer size.
        // SAFETY: null buffer with a zero count is the documented sizing query.
        let mut result = unsafe {
            RmGetList(
                self.handle,
                &mut needed,
                &mut count,
                ptr::null_mut(),
                &mut reboot_reason,
            )
        };

        if result == ERROR_SUCCESS {
            return Ok(Vec::new());
        }
        if result != ERROR_MORE_DATA {
            return Err(Error::win32("RmGetList", result));
        }

        // The process list can grow between the sizing call and the real one;
        // retry with the newly reported size.
        for _ in 0..8 {
            let capacity = needed.max(count).max(1) as usize;
            let mut buffer = vec![RM_PROCESS_INFO::default(); capacity];
            let mut slots = capacity as u32;
            let mut needed_now = 0u32;

            // SAFETY: `buffer` has `slots` initialized entries.
            result = unsafe {
                RmGetList(
                    self.handle,
                    &mut needed_now,
                    &mut slots,
                    buffer.as_mut_ptr(),
                    &mut reboot_reason,
                )
            };

            if result == ERROR_SUCCESS {
                buffer.truncate(slots as usize);
                return Ok(buffer);
            }
            if result != ERROR_MORE_DATA {
                return Err(Error::win32("RmGetList", result));
            }

            needed = needed_now.max(slots).max(1);
        }

        Err(Error::win32("RmGetList", ERROR_MORE_DATA))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: the handle came from RmStartSession and is ended once.
        unsafe {
            RmEndSession(self.handle);
        }
    }
}

#[allow(non_upper_case_globals)]
fn process_kind(kind: RM_APP_TYPE) -> ProcessKind {
    match kind {
        RmMainWindow => ProcessKind::MainWindow,
        RmOtherWindow => ProcessKind::OtherWindow,
        RmService => ProcessKind::Service,
        RmExplorer => ProcessKind::Explorer,
        RmConsole => ProcessKind::Console,
        RmCritical => ProcessKind::Critical,
        _ => ProcessKind::Unknown,
    }
}

/// Ask the Restart Manager which processes have `path` open.
///
/// The path should point at an existing file. An empty process list means no
/// process currently holds the file.
pub fn detect_file_lock(path: &Path) -> Result<FileLock> {
    let absolute = absolute_path(path)?;

    let session = Session::start()?;
    session.register_file(&absolute)?;

    let mut processes: Vec<ProcessInfo> = session
        .processes()?
        .into_iter()
        .map(|info| {
            let pid = info.Process.dwProcessId;
            ProcessInfo {
                pid,
                image_path: sys::process_image_path(pid),
                app_name: sys::utf16z(&info.strAppName),
                service_name: sys::utf16z(&info.strServiceShortName),
                kind: process_kind(info.ApplicationType),
            }
        })
        .collect();

    processes.sort_by(|a, b| {
        a.pid
            .cmp(&b.pid)
            .then_with(|| a.service_name.cmp(&b.service_name))
            .then_with(|| a.app_name.cmp(&b.app_name))
    });
    processes.dedup_by(|a, b| {
        a.pid == b.pid && a.service_name == b.service_name && a.app_name == b.app_name
    });

    Ok(FileLock {
        path: absolute,
        processes,
    })
}

/// Detect locks for several files, one Restart Manager session per path.
pub fn detect_file_locks(paths: &[PathBuf]) -> Result<Vec<FileLock>> {
    paths.iter().map(|path| detect_file_lock(path)).collect()
}
