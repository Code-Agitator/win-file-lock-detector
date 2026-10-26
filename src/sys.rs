//! Low-level Win32/NT helpers shared by the Restart Manager and handle-scanning
//! detectors.

use std::ffi::c_void;
use std::mem::{self, MaybeUninit};
use std::ptr;

use windows_sys::Wdk::Foundation::NtQueryObject;
use windows_sys::Wdk::Storage::FileSystem::{
    FileStandardInformation as FileStandardInformationClass, NtQueryInformationFile,
};
use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_NOT_ALL_ASSIGNED, GetLastError,
    HANDLE, INVALID_HANDLE_VALUE, LUID,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, GetFileType, GetFinalPathNameByHandleW,
    OPEN_EXISTING, QueryDosDeviceW,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use crate::{Error, Result};

const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005u32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023u32 as i32;

/// `SystemExtendedHandleInformation`, valid on Windows 7 and later.
const SYSTEM_EXTENDED_HANDLE_INFORMATION: i32 = 64;

/// `ObjectNameInformation`; windows-sys only exposes a subset of this enum.
const OBJECT_NAME_INFORMATION_CLASS: i32 = 1;

const MAX_HANDLE_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;
const MAX_OBJECT_NAME_BYTES: usize = 256 * 1024;

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Decode a fixed-size, NUL terminated UTF-16 field.
pub fn utf16z(buf: &[u16]) -> Option<String> {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    if end == 0 {
        None
    } else {
        Some(String::from_utf16_lossy(&buf[..end]))
    }
}

pub fn last_error() -> u32 {
    unsafe { GetLastError() }
}

/// Best-effort `SeDebugPrivilege` escalation. Without it (i.e. not running
/// elevated) handles owned by other users or protected processes are invisible.
pub fn enable_debug_privilege() -> bool {
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return false;
        }

        let privilege_name = wide("SeDebugPrivilege");
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        let mut ok = false;
        if LookupPrivilegeValueW(ptr::null(), privilege_name.as_ptr(), &mut luid) != 0 {
            let state = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            let adjusted =
                AdjustTokenPrivileges(token, 0, &state, 0, ptr::null_mut(), ptr::null_mut()) != 0;
            // AdjustTokenPrivileges reports success even when the privilege was
            // not assigned; GetLastError() is the real answer.
            ok = adjusted && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
        }

        CloseHandle(token);
        ok
    }
}

/// Full Win32 image path of a process, when it can be queried.
pub fn process_image_path(pid: u32) -> Option<String> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 32768];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(process, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(process);
        if ok == 0 {
            None
        } else {
            Some(String::from_utf16_lossy(&buf[..len as usize]))
        }
    }
}

// ---------------------------------------------------------------------------
// System handle table
// ---------------------------------------------------------------------------

/// `SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX`.
#[repr(C)]
#[derive(Clone, Copy)]
struct SystemHandleTableEntryInfoEx {
    object: *mut c_void,
    unique_process_id: usize,
    handle_value: usize,
    granted_access: u32,
    creator_back_trace_index: u16,
    object_type_index: u16,
    handle_attributes: u32,
    reserved: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct SystemHandleEntry {
    pub pid: u32,
    pub handle: usize,
    pub access: u32,
    pub type_index: u16,
}

/// One snapshot of the system-wide handle table.
///
/// The kernel writes a variable-length array after a two-word header, so the
/// buffer is kept alive and entries are decoded with unaligned reads.
pub struct HandleSnapshot {
    buffer: Vec<usize>,
    count: usize,
}

impl HandleSnapshot {
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn entry(&self, index: usize) -> SystemHandleEntry {
        debug_assert!(index < self.count);

        let header = 2 * mem::size_of::<usize>();
        let offset = header + index * mem::size_of::<SystemHandleTableEntryInfoEx>();
        // SAFETY: `index` is bounded by `count`, which was capped to the number
        // of entries that actually fit in `buffer` when the snapshot was taken.
        let raw = unsafe {
            ptr::read_unaligned((self.buffer.as_ptr() as *const u8).add(offset)
                as *const SystemHandleTableEntryInfoEx)
        };

        SystemHandleEntry {
            pid: raw.unique_process_id as u32,
            handle: raw.handle_value,
            access: raw.granted_access,
            type_index: raw.object_type_index,
        }
    }
}

pub fn snapshot_handles() -> Result<HandleSnapshot> {
    let mut size = 1usize << 20;

    for _ in 0..16 {
        let words = size.div_ceil(mem::size_of::<usize>());
        let mut buffer = vec![0usize; words];
        let mut returned = 0u32;

        // SAFETY: the buffer is at least `size` bytes and `size` fits in u32.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
                buffer.as_mut_ptr().cast(),
                size as u32,
                &mut returned,
            )
        };

        if status == STATUS_INFO_LENGTH_MISMATCH
            || status == STATUS_BUFFER_OVERFLOW
            || status == STATUS_BUFFER_TOO_SMALL
        {
            size = size.max(1).saturating_mul(2);
            if returned as usize > size {
                size = (returned as usize).saturating_add(64 * 1024);
            }
            if size > MAX_HANDLE_SNAPSHOT_BYTES {
                return Err(Error::nt(
                    "NtQuerySystemInformation",
                    STATUS_INFO_LENGTH_MISMATCH,
                ));
            }
            continue;
        }

        if status != 0 {
            return Err(Error::nt("NtQuerySystemInformation", status));
        }

        // SAFETY: on success the kernel has written the header.
        let count = unsafe { ptr::read_unaligned(buffer.as_ptr()) };
        let max_entries = size.saturating_sub(2 * mem::size_of::<usize>())
            / mem::size_of::<SystemHandleTableEntryInfoEx>();
        let count = count.min(max_entries);

        return Ok(HandleSnapshot { buffer, count });
    }

    Err(Error::nt(
        "NtQuerySystemInformation",
        STATUS_INFO_LENGTH_MISMATCH,
    ))
}

// ---------------------------------------------------------------------------
// Duplicating handles out of other processes
// ---------------------------------------------------------------------------

/// Duplicate a handle owned by another process into the current process.
pub fn duplicate_handle(source_process: HANDLE, source_handle: usize) -> Option<HANDLE> {
    let mut duplicate: HANDLE = ptr::null_mut();
    // SAFETY: both handles were obtained from the OS; the out parameter is valid.
    let ok = unsafe {
        DuplicateHandle(
            source_process,
            source_handle as HANDLE,
            GetCurrentProcess(),
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 { None } else { Some(duplicate) }
}

pub fn open_process_for_handles(pid: u32) -> Option<HANDLE> {
    // SAFETY: plain API call with an out-of-band PID.
    let handle = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid) };
    if handle.is_null() { None } else { Some(handle) }
}

pub fn close_handle(handle: HANDLE) {
    // SAFETY: callers only pass handles they own; closing twice is not done.
    unsafe {
        CloseHandle(handle);
    }
}

pub fn current_pid() -> u32 {
    unsafe { GetCurrentProcessId() }
}

// ---------------------------------------------------------------------------
// Object names and types
// ---------------------------------------------------------------------------

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectNameInformation {
    name: UnicodeString,
}

/// File handles (of type `File`) also cover pipes and character devices.
/// Only real disk objects can be usefully named, and skipping devices avoids
/// the well-known hangs when querying some pipe object names.
pub fn is_disk_object(handle: HANDLE) -> bool {
    // SAFETY: `handle` is a valid handle owned by this process.
    unsafe { GetFileType(handle) == FILE_TYPE_DISK }
}

/// Name of a disk file/directory object.
///
/// `GetFinalPathNameByHandleW` is tried first because it returns a Win32 path
/// directly, but it requires `FILE_READ_ATTRIBUTES`. For handles opened with
/// narrower access we fall back to `NtQueryObject`, which yields an
/// `\Device\...` NT path.
pub fn object_path(handle: HANDLE) -> Option<String> {
    if !is_disk_object(handle) {
        return None;
    }

    if let Some(path) = final_path(handle) {
        return Some(path);
    }

    nt_object_name(handle)
}

fn final_path(handle: HANDLE) -> Option<String> {
    let mut buf = vec![0u16; 512];
    loop {
        // SAFETY: buffer and its length are consistent.
        let written =
            unsafe { GetFinalPathNameByHandleW(handle, buf.as_mut_ptr(), buf.len() as u32, 0) };
        if written == 0 {
            return None;
        }
        let written = written as usize;
        if written < buf.len() {
            return Some(String::from_utf16_lossy(&buf[..written]));
        }
        if written > 32768 {
            return None;
        }
        buf.resize(written + 1, 0);
    }
}

fn nt_object_name(handle: HANDLE) -> Option<String> {
    let mut buf = vec![0u8; 2048];

    for _ in 0..8 {
        let mut returned = 0u32;
        // SAFETY: the buffer and length are consistent; the handle is valid.
        let status = unsafe {
            NtQueryObject(
                handle,
                OBJECT_NAME_INFORMATION_CLASS,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut returned,
            )
        };

        if status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_OVERFLOW {
            let needed = (returned as usize).max(buf.len()).saturating_add(16);
            if needed > MAX_OBJECT_NAME_BYTES {
                return None;
            }
            buf.resize(needed, 0);
            continue;
        }
        if status != 0 {
            return None;
        }

        // SAFETY: the kernel wrote an OBJECT_NAME_INFORMATION into `buf`.
        let info = unsafe { ptr::read_unaligned(buf.as_ptr() as *const ObjectNameInformation) };
        let name = info.name;
        if name.buffer.is_null() || name.length == 0 {
            return None;
        }
        let units = (name.length as usize) / 2;
        // SAFETY: `length` covers `units` UTF-16 code units inside `buf`.
        let slice = unsafe { std::slice::from_raw_parts(name.buffer, units) };
        return Some(String::from_utf16_lossy(slice));
    }

    None
}

/// `FILE_STANDARD_INFORMATION`, used only for the `Directory` flag.
#[repr(C)]
struct FileStandardInfo {
    allocation_size: i64,
    end_of_file: i64,
    number_of_links: u32,
    delete_pending: u8,
    directory: u8,
}

pub fn object_is_directory(handle: HANDLE) -> Option<bool> {
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut info = MaybeUninit::<FileStandardInfo>::zeroed();

    // SAFETY: the output buffer matches the requested information class/size.
    let status = unsafe {
        NtQueryInformationFile(
            handle,
            &mut io_status,
            info.as_mut_ptr().cast(),
            mem::size_of::<FileStandardInfo>() as u32,
            FileStandardInformationClass,
        )
    };

    if status >= 0 {
        // SAFETY: on success the kernel initialized the buffer.
        Some(unsafe { info.assume_init() }.directory != 0)
    } else {
        None
    }
}

/// Open a local file or directory just to obtain a known `File` object type
/// handle, which is then located in a handle snapshot.
pub fn open_sentinel() -> Option<HANDLE> {
    let exe = std::env::current_exe().ok()?;
    let exe = exe.to_string_lossy();
    let path = wide(&exe);

    // SAFETY: `path` is NUL terminated and lives for the call.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        None
    } else {
        Some(handle)
    }
}

// ---------------------------------------------------------------------------
// DOS <-> NT path mapping
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DeviceMap {
    /// `(drive, device)`, e.g. `("C:", "\\Device\\HarddiskVolume3")`.
    entries: Vec<(String, String)>,
}

impl DeviceMap {
    pub fn new() -> Self {
        let mut entries = Vec::new();

        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", letter as char);
            let drive_wide = wide(&drive);
            let mut buf = vec![0u16; 1024];

            // SAFETY: both buffers are valid for the duration of the call.
            let len =
                unsafe { QueryDosDeviceW(drive_wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
            if len == 0 {
                continue;
            }

            let end = buf.iter().position(|&c| c == 0).unwrap_or(len as usize);
            if end == 0 {
                continue;
            }
            let device = String::from_utf16_lossy(&buf[..end]);
            entries.push((drive, device));
        }

        Self { entries }
    }

    #[cfg(test)]
    fn from_entries(entries: Vec<(&str, &str)>) -> Self {
        Self {
            entries: entries
                .into_iter()
                .map(|(drive, device)| (drive.to_string(), device.to_string()))
                .collect(),
        }
    }

    /// Convert a DOS path (`C:\...`, `\\server\share\...`) into the NT device
    /// namespace (`\Device\HarddiskVolume3\...`). Resolves `subst` drives.
    pub fn to_nt(&self, path: &str) -> Option<String> {
        self.to_nt_inner(path, 0)
    }

    fn to_nt_inner(&self, path: &str, depth: usize) -> Option<String> {
        if depth > 8 {
            return None;
        }

        let path = path.replace('/', "\\");

        if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
            return Some(format!(r"\Device\Remote\{rest}"));
        }
        if let Some(rest) = path.strip_prefix(r"\\?\") {
            return self.to_nt_inner(rest, depth + 1);
        }
        if let Some(rest) = path.strip_prefix(r"\??\") {
            // Some APIs report UNC paths as `\??\UNC\server\share`.
            if let Some(unc) = rest.strip_prefix(r"UNC\") {
                return Some(format!(r"\Device\Remote\{unc}"));
            }
            return self.to_nt_inner(rest, depth + 1);
        }
        if let Some(rest) = path.strip_prefix(r"\\.\") {
            return self.to_nt_inner(rest, depth + 1);
        }
        if let Some(rest) = path.strip_prefix(r"\\") {
            return Some(format!(r"\Device\Remote\{rest}"));
        }

        let bytes = path.as_bytes();
        if bytes.len() < 2 || bytes[1] != b':' {
            return None;
        }

        let drive = &path[..2];
        let rest = path[2..].trim_start_matches('\\');
        let device = self
            .entries
            .iter()
            .find(|(d, _)| d.eq_ignore_ascii_case(drive))
            .map(|(_, device)| device.as_str())?;

        let device = if let Some(subst) = device.strip_prefix(r"\??\") {
            self.to_nt_inner(subst, depth + 1)?
        } else {
            device.to_string()
        };
        let device = device.trim_end_matches('\\');

        if rest.is_empty() {
            Some(device.to_string())
        } else {
            Some(format!(r"{device}\{rest}"))
        }
    }

    /// Convert an NT path back into a DOS path for display, when possible.
    pub fn to_dos(&self, nt_path: &str) -> Option<String> {
        if let Some(rest) = nt_path
            .strip_prefix(r"\Device\Remote\")
            .or_else(|| nt_path.strip_prefix(r"\Device\Mup\"))
            .or_else(|| nt_path.strip_prefix(r"\Device\LanmanRedirector\"))
            .or_else(|| nt_path.strip_prefix(r"\Device\WebDavRedirector\"))
        {
            return Some(format!(r"\\{rest}"));
        }
        if let Some(rest) = nt_path.strip_prefix(r"\??\") {
            return Some(rest.to_string());
        }

        for (drive, device) in &self.entries {
            let resolved = self
                .resolve_device(device, 0)
                .unwrap_or_else(|| device.clone());

            let prefix_matches = nt_path
                .get(..resolved.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&resolved));
            if !prefix_matches {
                continue;
            }
            if nt_path.len() == resolved.len() {
                return Some(drive.clone());
            }
            if nt_path.as_bytes()[resolved.len()] == b'\\' {
                return Some(format!(r"{drive}\{}", &nt_path[resolved.len() + 1..]));
            }
        }

        None
    }

    fn resolve_device(&self, device: &str, depth: usize) -> Option<String> {
        if depth > 8 {
            return None;
        }
        if let Some(rest) = device.strip_prefix(r"\??\") {
            return self.to_nt_inner(rest, depth + 1);
        }
        Some(device.to_string())
    }

    /// Normalize the various redirector device names to a single prefix so that
    /// UNC targets and their handles compare equal.
    pub fn canonical_nt(&self, nt_path: &str) -> String {
        if let Some(rest) = nt_path
            .strip_prefix(r"\Device\Mup\")
            .or_else(|| nt_path.strip_prefix(r"\Device\LanmanRedirector\"))
            .or_else(|| nt_path.strip_prefix(r"\Device\WebDavRedirector\"))
        {
            return format!(r"\Device\Remote\{rest}");
        }
        nt_path.to_string()
    }
}

/// Strip `\\?\` / `\\?\UNC\` prefixes so the path is human readable.
pub fn strip_verbatim(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = path.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        path.to_string()
    }
}

/// A path as returned by one of the two naming APIs.
#[derive(Debug, Clone)]
pub struct CandidatePath {
    /// Human-readable form (DOS path when we could translate it).
    pub display: String,
    /// Whether `display` is a DOS path that can be compared directly.
    pub display_is_dos: bool,
    /// NT device path, when the name came from `NtQueryObject` or the DOS path
    /// could be mapped to a device.
    pub nt: Option<String>,
}

impl CandidatePath {
    pub fn from_object_name(name: String, map: &DeviceMap) -> Self {
        let nt = map.canonical_nt(&name);
        match map.to_dos(&nt) {
            Some(dos) => Self {
                display: dos,
                display_is_dos: true,
                nt: Some(nt),
            },
            None => Self {
                display: name,
                display_is_dos: false,
                nt: Some(nt),
            },
        }
    }

    pub fn from_win32_path(path: String, map: &DeviceMap) -> Self {
        let display = strip_verbatim(&path);
        let nt = map.to_nt(&display).map(|nt| map.canonical_nt(&nt));
        Self {
            display,
            display_is_dos: true,
            nt,
        }
    }
}

/// Case-insensitive relationship between a target path and a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathRelation {
    /// The candidate is the target itself.
    Exact,
    /// The candidate is inside the target.
    Descendant,
}

pub fn normalize_for_compare(path: &str) -> String {
    let path = path.replace('/', "\\");
    let path = path
        .strip_prefix(r"\\?\UNC\")
        .map_or(path.clone(), |rest| format!(r"\\{rest}"));
    let path = path.strip_prefix(r"\\?\").unwrap_or(&path).to_string();
    path.trim_end_matches('\\').to_lowercase()
}

/**
 * Compare a target with a candidate in one path namespace.
 */
pub fn relation_in_namespace(target_folded: &str, candidate_folded: &str) -> Option<PathRelation> {
    let target = target_folded.trim_end_matches('\\');
    let candidate = candidate_folded.trim_end_matches('\\');

    if candidate == target {
        return Some(PathRelation::Exact);
    }

    if candidate.len() > target.len()
        && candidate.starts_with(target)
        && candidate.as_bytes().get(target.len()) == Some(&b'\\')
    {
        return Some(PathRelation::Descendant);
    }

    None
}

/// Compare two candidate paths, preferring the DOS namespace when both sides
/// have one (this also covers volumes mounted under a folder).
pub fn compare_paths(
    target_display_folded: &str,
    target_nt_folded: Option<&str>,
    candidate: &CandidatePath,
) -> Option<PathRelation> {
    if candidate.display_is_dos {
        let display_folded = normalize_for_compare(&candidate.display);
        if let Some(relation) = relation_in_namespace(target_display_folded, &display_folded) {
            return Some(relation);
        }
    }

    if let (Some(target_nt), Some(candidate_nt)) = (target_nt_folded, candidate.nt.as_deref()) {
        let candidate_nt_folded = normalize_for_compare(candidate_nt);
        if let Some(relation) = relation_in_namespace(target_nt, &candidate_nt_folded) {
            return Some(relation);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device_map() -> DeviceMap {
        DeviceMap::from_entries(vec![
            ("C:", r"\Device\HarddiskVolume3"),
            ("D:", r"\Device\HarddiskVolume4"),
            // A `subst` drive, whose target must be resolved recursively.
            ("X:", r"\??\C:\subst-target"),
        ])
    }

    #[test]
    fn dos_paths_convert_to_nt_paths() {
        let map = device_map();
        assert_eq!(
            map.to_nt(r"C:\foo\bar").as_deref(),
            Some(r"\Device\HarddiskVolume3\foo\bar")
        );
        assert_eq!(
            map.to_nt(r"d:\other").as_deref(),
            Some(r"\Device\HarddiskVolume4\other")
        );
        assert_eq!(
            map.to_nt(r"C:\").as_deref(),
            Some(r"\Device\HarddiskVolume3")
        );
    }

    #[test]
    fn subst_drives_resolve_recursively() {
        let map = device_map();
        assert_eq!(
            map.to_nt(r"X:\nested\file.txt").as_deref(),
            Some(r"\Device\HarddiskVolume3\subst-target\nested\file.txt")
        );
    }

    #[test]
    fn unc_paths_use_the_remote_namespace() {
        let map = device_map();
        assert_eq!(
            map.to_nt(r"\\server\share\dir").as_deref(),
            Some(r"\Device\Remote\server\share\dir")
        );
        assert_eq!(
            map.to_nt(r"\??\UNC\server\share\dir").as_deref(),
            Some(r"\Device\Remote\server\share\dir")
        );
        assert_eq!(
            map.canonical_nt(r"\Device\Mup\server\share\dir"),
            r"\Device\Remote\server\share\dir"
        );
    }

    #[test]
    fn nt_paths_convert_back_to_dos_paths() {
        let map = device_map();
        assert_eq!(
            map.to_dos(r"\Device\HarddiskVolume4\dir\file").as_deref(),
            Some(r"D:\dir\file")
        );
        assert_eq!(
            map.to_dos(r"\Device\HarddiskVolume4").as_deref(),
            Some("D:")
        );
        assert_eq!(
            map.to_dos(r"\Device\Mup\server\share").as_deref(),
            Some(r"\\server\share")
        );
        assert_eq!(
            map.to_dos(r"\Device\HarddiskVolume3\subst-target\x")
                .as_deref(),
            Some(r"C:\subst-target\x")
        );
    }

    #[test]
    fn verbatim_prefixes_are_stripped() {
        assert_eq!(strip_verbatim(r"\\?\C:\dir"), r"C:\dir");
        assert_eq!(strip_verbatim(r"\\?\UNC\server\share"), r"\\server\share");
        assert_eq!(strip_verbatim(r"C:\dir"), r"C:\dir");
    }

    #[test]
    fn path_relations_respect_component_boundaries() {
        assert_eq!(
            relation_in_namespace(r"c:\foo", r"c:\foo"),
            Some(PathRelation::Exact)
        );
        assert_eq!(
            relation_in_namespace(r"c:\foo", r"c:\foo\bar.txt"),
            Some(PathRelation::Descendant)
        );
        assert_eq!(relation_in_namespace(r"c:\foo", r"c:\foobar"), None);
        assert_eq!(
            relation_in_namespace(r"c:", r"c:\bar"),
            Some(PathRelation::Descendant)
        );
    }

    #[test]
    fn path_comparison_uses_both_namespaces() {
        let map = device_map();
        let target_display = normalize_for_compare(r"D:\Projects\Demo");
        let target_nt = map
            .to_nt(r"D:\Projects\Demo")
            .map(|nt| map.canonical_nt(&nt));
        let target_nt = target_nt.as_deref().map(normalize_for_compare);

        let dos = CandidatePath::from_win32_path(r"D:\Projects\Demo\file.txt".into(), &map);
        assert_eq!(
            compare_paths(&target_display, target_nt.as_deref(), &dos),
            Some(PathRelation::Descendant)
        );

        let nt = CandidatePath::from_object_name(
            r"\Device\HarddiskVolume4\Projects\Demo\file.txt".into(),
            &map,
        );
        assert_eq!(
            compare_paths(&target_display, target_nt.as_deref(), &nt),
            Some(PathRelation::Descendant)
        );

        let sibling = CandidatePath::from_win32_path(r"D:\Projects\Demo2".into(), &map);
        assert_eq!(
            compare_paths(&target_display, target_nt.as_deref(), &sibling),
            None
        );
    }
}
