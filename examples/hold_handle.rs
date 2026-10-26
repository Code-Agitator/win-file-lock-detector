//! Test helper: keep a file or directory handle open for a number of seconds.
//!
//! ```text
//! cargo run --example hold_handle -- <path> [seconds]
//! ```
//!
//! It opens the path with `FILE_FLAG_BACKUP_SEMANTICS` (required for
//! directories) and holds the handle open for the given time.

use std::ffi::c_void;
use std::time::Duration;

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

fn main() {
    let mut args = std::env::args().skip(1);
    let path = match args.next() {
        Some(path) => path,
        None => {
            eprintln!("usage: hold_handle <path> [seconds]");
            std::process::exit(2);
        }
    };
    let seconds = args
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(60);

    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: `wide` is NUL terminated and outlives the call.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut::<c_void>(),
        )
    };

    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        eprintln!("CreateFileW failed: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }

    println!(
        "pid {} holding {} for {}s",
        std::process::id(),
        path,
        seconds
    );
    std::thread::sleep(Duration::from_secs(seconds));

    // SAFETY: the handle came from CreateFileW and is closed once.
    unsafe {
        CloseHandle(handle);
    }
}
