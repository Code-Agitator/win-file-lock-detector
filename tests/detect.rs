//! Live detection tests.
//!
//! These tests open real handles in the test process and then inspect the
//! system. Running them inside CI containers without the required privileges is
//! still expected to work for handles owned by the same user.

use std::fs::{self, File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use win_file_lock_detector::{
    ObjectKind, PathRelation, ScanReport, detect_file_lock, scan_handles,
};

const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;

fn unique_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("wflt-{tag}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp directory");
    dir
}

#[test]
fn restart_manager_reports_our_open_file() {
    let dir = unique_dir("rm");
    let path = dir.join("locked.txt");
    fs::write(&path, b"data").expect("write test file");

    // No sharing: the file is genuinely in use.
    let locked = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .open(&path)
        .expect("open test file exclusively");

    let lock = detect_file_lock(&path).expect("detect file lock");

    assert!(
        lock.is_locked(),
        "Restart Manager reported no holders for an exclusively opened file"
    );
    assert!(
        lock.processes
            .iter()
            .any(|process| process.pid == std::process::id()),
        "Restart Manager did not report the test process: {:?}",
        lock.processes
    );

    drop(locked);
    fs::remove_dir_all(dir).expect("remove temp directory");
}

#[test]
fn handle_scan_reports_directory_and_contained_handles() {
    let dir = unique_dir("handles");

    let directory = OpenOptions::new()
        .read(true)
        .share_mode(SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(&dir)
        .expect("open directory handle");

    let child = dir.join("child.txt");
    fs::write(&child, b"data").expect("write child file");
    let child_handle = File::open(&child).expect("open child file");

    let report = scan_handles(&dir, true).expect("scan directory");
    let own_pid = std::process::id();

    assert!(
        report.handles.iter().any(|handle| {
            handle.pid == own_pid
                && handle.relation == PathRelation::Exact
                && handle.object_kind == ObjectKind::Directory
        }),
        "directory handle was not found: {}",
        describe(&report)
    );

    assert!(
        report.handles.iter().any(|handle| {
            handle.pid == own_pid
                && handle.relation == PathRelation::Descendant
                && handle.matched_path == plain_path(&child)
        }),
        "child file handle was not found: {}",
        describe(&report)
    );

    let exact_only = scan_handles(&dir, false).expect("scan directory without descendants");
    assert!(
        !exact_only
            .handles
            .iter()
            .any(|handle| { handle.pid == own_pid && handle.relation == PathRelation::Descendant }),
        "exact mode reported a descendant: {}",
        describe(&exact_only)
    );

    drop(child_handle);
    drop(directory);
    fs::remove_dir_all(dir).expect("remove temp directory");
}

fn plain_path(path: &std::path::Path) -> PathBuf {
    let canonical = fs::canonicalize(path).expect("canonicalize path");
    let text = canonical.to_string_lossy();
    PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(text.as_ref()))
}

fn describe(report: &ScanReport) -> String {
    report
        .handles
        .iter()
        .map(|handle| {
            format!(
                "pid={} {:?} {} {:?}",
                handle.pid,
                handle.relation,
                handle.matched_path.display(),
                handle.object_kind
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}
