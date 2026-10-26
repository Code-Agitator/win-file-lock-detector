use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use win_file_lock_detector::{
    Error, FileLock, OpenHandle, PathRelation, ScanReport, detect_file_lock, scan_handles,
};

const USAGE: &str = "\
win-file-lock-detector - find processes that hold a file or directory open

USAGE:
    win-file-lock-detector <PATH> [OPTIONS]

OPTIONS:
    --json        Print machine-readable JSON
    --handles     Use system handle scanning instead of the Restart Manager
                  (directories always use handle scanning)
    --exact       For directories, only report handles to the directory itself,
                  not to files or subdirectories inside it
    -h, --help    Print this help
    -V, --version Print the version

EXIT STATUS:
    0  no process holds the path
    1  at least one process holds the path
    2  error

NOTES:
    Run elevated for complete results. Without SeDebugPrivilege, handles held
    by other users or by protected processes cannot be inspected.
";

struct Options {
    path: PathBuf,
    json: bool,
    exact: bool,
    handles: bool,
}

enum Parsed {
    Run(Options),
    Help,
    Version,
}

fn main() -> ExitCode {
    let args: Vec<OsString> = env::args_os().skip(1).collect();

    let options = match parse_args(&args) {
        Ok(Parsed::Run(options)) => options,
        Ok(Parsed::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Parsed::Version) => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("error: {message}\n");
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    match run(&options) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}

fn parse_args(args: &[OsString]) -> Result<Parsed, String> {
    let mut path = None;
    let mut json = false;
    let mut exact = false;
    let mut handles = false;
    let mut positional_only = false;

    for argument in args {
        if positional_only {
            set_path(&mut path, PathBuf::from(argument.as_os_str()))?;
            continue;
        }

        let Some(text) = argument.to_str() else {
            // Not valid Unicode, so it cannot be one of our options.
            set_path(&mut path, PathBuf::from(argument.as_os_str()))?;
            continue;
        };

        match text {
            "--" => positional_only = true,
            "-h" | "--help" | "/?" => return Ok(Parsed::Help),
            "-V" | "--version" => return Ok(Parsed::Version),
            "--json" => json = true,
            "--exact" => exact = true,
            "--handles" => handles = true,
            other if other.starts_with('-') => {
                return Err(format!("unknown option: {other}"));
            }
            other => set_path(&mut path, PathBuf::from(other))?,
        }
    }

    let path = path.ok_or_else(|| "missing <PATH>".to_string())?;
    Ok(Parsed::Run(Options {
        path,
        json,
        exact,
        handles,
    }))
}

fn set_path(path: &mut Option<PathBuf>, value: PathBuf) -> Result<(), String> {
    if path.is_some() {
        return Err("expected exactly one path".to_string());
    }
    *path = Some(value);
    Ok(())
}

fn run(options: &Options) -> Result<ExitCode, Error> {
    let metadata = match std::fs::metadata(&options.path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::PathNotFound(options.path.clone()));
        }
        Err(error) => return Err(error.into()),
    };
    let is_directory = metadata.is_dir();

    if options.handles || is_directory {
        let include_descendants = is_directory && !options.exact;
        let report = scan_handles(&options.path, include_descendants)?;

        if options.json {
            print!("{}", scan_json(&report));
        } else {
            print_scan_text(&report);
        }
        warn_skipped(&report);

        Ok(if report.is_in_use() {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        })
    } else {
        let lock = detect_file_lock(&options.path)?;

        if options.json {
            print!("{}", file_json(&lock));
        } else {
            print_file_text(&lock);
        }

        Ok(if lock.is_locked() {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        })
    }
}

fn warn_skipped(report: &ScanReport) {
    if !report.skipped_processes.is_empty() {
        let pids = report
            .skipped_processes
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!(
            "warning: could not inspect {} process(es); handles held by them are not reported \
             (run elevated for complete results): {pids}",
            report.skipped_processes.len()
        );
    }

    if !report.timed_out_processes.is_empty() {
        let pids = report
            .timed_out_processes
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!(
            "warning: timed out while resolving handles of {} process(es); some of their \
             handles are not reported: {pids}",
            report.timed_out_processes.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Human-readable output
// ---------------------------------------------------------------------------

fn print_file_text(lock: &FileLock) {
    println!("Path: {}", lock.path.display());
    println!("Type: file");
    println!("Method: Restart Manager");

    if lock.processes.is_empty() {
        println!("Result: not in use (no process has the file open)");
        return;
    }

    println!("Result: in use ({} process(es))", lock.processes.len());
    println!();
    println!("Processes holding the file:");

    for process in &lock.processes {
        println!("  PID {:<6}  {}", process.pid, rm_process_label(process));
        if let Some(image) = &process.image_path {
            println!("    image: {image}");
        }
        if let Some(app) = &process.app_name {
            println!("    app: {app}");
        }
        if let Some(service) = &process.service_name {
            println!("    service: {service}");
        }
        println!("    type: {}", process.kind.as_str());
    }
}

fn print_scan_text(report: &ScanReport) {
    println!("Path: {}", report.target.display());
    println!(
        "Type: {}",
        if report.target_is_directory {
            "directory"
        } else {
            "file"
        }
    );
    println!("Method: handle scan");

    if !report.is_in_use() {
        println!(
            "Result: not in use (examined {} file handle(s))",
            report.examined_handles
        );
        return;
    }

    println!(
        "Result: in use ({} handle(s) from {} process(es))",
        report.handles.len(),
        report.process_count()
    );

    let exact: Vec<&OpenHandle> = report.exact_handles().collect();
    if !exact.is_empty() {
        println!();
        println!(
            "Handle(s) to the {} itself:",
            if report.target_is_directory {
                "directory"
            } else {
                "file"
            }
        );
        for handle in exact {
            print_handle(handle);
        }
    }

    let descendants: Vec<&OpenHandle> = report.descendant_handles().collect();
    if !descendants.is_empty() {
        println!();
        println!("Open items inside the directory:");
        for handle in descendants {
            print_handle(handle);
        }
    }

    println!();
    println!("Examined {} file handle(s).", report.examined_handles);
}

fn print_handle(handle: &OpenHandle) {
    println!(
        "  PID {:<6}  {}",
        handle.pid,
        image_name(handle.image_path.as_deref()).unwrap_or_else(|| "<unknown>".to_string())
    );
    println!("    path: {}", handle.matched_path.display());
    println!("    object: {}", handle.object_kind.as_str());
    println!("    access: 0x{:08X}", handle.access);
    if let Some(image) = &handle.image_path {
        println!("    image: {image}");
    }
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

fn file_json(lock: &FileLock) -> String {
    let processes = lock
        .processes
        .iter()
        .map(|process| {
            format!(
                "    {{\"pid\": {}, \"name\": {}, \"image\": {}, \"app_name\": {}, \
                 \"service\": {}, \"type\": {}}}",
                process.pid,
                json_string(&rm_process_label(process)),
                json_option(process.image_path.as_deref()),
                json_option(process.app_name.as_deref()),
                json_option(process.service_name.as_deref()),
                json_string(process.kind.as_str()),
            )
        })
        .collect::<Vec<_>>();

    let mut out = String::new();
    out.push_str("{\n");
    let _ = writeln!(
        out,
        "  \"path\": {},",
        json_string(&lock.path.display().to_string())
    );
    out.push_str("  \"type\": \"file\",\n");
    out.push_str("  \"method\": \"restart-manager\",\n");
    let _ = writeln!(out, "  \"in_use\": {},", lock.is_locked());
    let _ = writeln!(out, "  \"processes\": [{}]", json_lines(&processes));
    out.push_str("}\n");
    out
}

fn scan_json(report: &ScanReport) -> String {
    let handles = report
        .handles
        .iter()
        .map(|handle| {
            format!(
                "    {{\"pid\": {}, \"name\": {}, \"image\": {}, \"path\": {}, \
                 \"relation\": {}, \"object\": {}, \"access\": {}}}",
                handle.pid,
                json_string(
                    &image_name(handle.image_path.as_deref())
                        .unwrap_or_else(|| "<unknown>".to_string())
                ),
                json_option(handle.image_path.as_deref()),
                json_string(&handle.matched_path.display().to_string()),
                json_string(match handle.relation {
                    PathRelation::Exact => "exact",
                    PathRelation::Descendant => "descendant",
                }),
                json_string(handle.object_kind.as_str()),
                handle.access,
            )
        })
        .collect::<Vec<_>>();

    let skipped = report
        .skipped_processes
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>();
    let timed_out = report
        .timed_out_processes
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>();

    let mut out = String::new();
    out.push_str("{\n");
    let _ = writeln!(
        out,
        "  \"path\": {},",
        json_string(&report.target.display().to_string())
    );
    let _ = writeln!(
        out,
        "  \"type\": {},",
        json_string(if report.target_is_directory {
            "directory"
        } else {
            "file"
        })
    );
    out.push_str("  \"method\": \"handle-scan\",\n");
    let _ = writeln!(out, "  \"in_use\": {},", report.is_in_use());
    let _ = writeln!(
        out,
        "  \"include_descendants\": {},",
        report.include_descendants
    );
    let _ = writeln!(out, "  \"handles\": [{}],", json_lines(&handles));
    let _ = writeln!(out, "  \"skipped_processes\": [{}],", skipped.join(", "));
    let _ = writeln!(
        out,
        "  \"timed_out_processes\": [{}],",
        timed_out.join(", ")
    );
    let _ = writeln!(out, "  \"examined_handles\": {}", report.examined_handles);
    out.push_str("}\n");
    out
}

fn json_lines(items: &[String]) -> String {
    if items.is_empty() {
        String::new()
    } else {
        format!("\n{}\n  ", items.join(",\n"))
    }
}

fn json_option(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_string(), json_string)
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", character as u32);
            }
            character => out.push(character),
        }
    }
    out.push('"');
    out
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn rm_process_label(process: &win_file_lock_detector::ProcessInfo) -> String {
    image_name(process.image_path.as_deref())
        .or_else(|| process.app_name.clone())
        .unwrap_or_else(|| "<unknown>".to_string())
}

fn image_name(path: Option<&str>) -> Option<String> {
    path.and_then(|path| {
        Path::new(path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
    })
}
