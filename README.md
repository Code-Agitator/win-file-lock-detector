# win-file-lock-detector

在 Windows 上检测「哪个进程占用了某个文件或目录」，核心实现基于 `windows-sys`（无其他依赖）。

- **文件**：封装 Windows Restart Manager（`RmStartSession` / `RmRegisterResources` /
  `RmGetList` / `RmEndSession`），与安装程序弹出「文件正在使用」时依据的是同一套机制。
- **目录**：Restart Manager 不接受目录，因此改用系统句柄表扫描
  （`NtQuerySystemInformation(SystemExtendedHandleInformation)` + `DuplicateHandle` +
  `GetFinalPathNameByHandleW` / `NtQueryObject`），行为类似 Sysinternals `handle.exe`。
  目录内部的文件 / 子目录句柄也会一并报告，因为它们同样会阻止删除或重命名目录。

要求 64 位 Windows 10 或更高版本（当前 Rust MSVC 工具链的最低支持版本）。

## 构建与使用

```bash
cargo build --release
```

```text
win-file-lock-detector <PATH> [OPTIONS]

OPTIONS:
    --json        输出 JSON
    --handles     强制使用句柄扫描（目录始终使用句柄扫描）
    --exact       目录模式下只报告「目录本身」的句柄，不报告目录内的文件
    -h, --help    帮助
    -V, --version 版本
```

退出码：

| 退出码 | 含义 |
| --- | --- |
| 0 | 没有被占用 |
| 1 | 至少有一个进程持有句柄 |
| 2 | 参数错误或检测失败 |

### 示例

````text
> win-file-lock-detector.exe D:\work\demo\report.docx
Path: D:\work\demo\report.docx
Type: file
Method: Restart Manager
Result: in use (1 process(es))

Processes holding the file:
  PID 23104   WINWORD.EXE
    image: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
    app: Microsoft Word
    type: main-window
````

````text
> win-file-lock-detector.exe D:\work\demo
Path: D:\work\demo
Type: directory
Method: handle scan
Result: in use (2 handle(s) from 2 process(es))

Handle(s) to the directory itself:
  PID 14820   explorer.exe
    path: D:\work\demo
    object: directory
    access: 0x00100080
    image: C:\Windows\explorer.exe

Open items inside the directory:
  PID 23104   Code.exe
    path: D:\work\demo\main.rs
    object: file
    access: 0x0012019F
    image: C:\Users\demo\AppData\Local\Programs\Microsoft VS Code\Code.exe
````

`--json` 会把同样的信息输出为机器可读格式，适合在脚本里使用。

## 两种检测方式的区别

| | Restart Manager | 句柄扫描 |
| --- | --- | --- |
| 支持文件 | 是 | 是 |
| 支持目录 | 否 | 是 |
| 能拿到进程名 / 应用名 | 是（含服务名） | 进程映像路径 |
| 需要管理员权限 | 通常需要 | 完整结果需要 |

Restart Manager 报告的是**会妨碍文件替换 / 删除**的占用。仅以
`FILE_READ_ATTRIBUTES` 且允许全部共享方式打开的句柄可能不会被它视为占用；
想列出所有已打开的句柄（无论共享模式）请加 `--handles`。

## 权限与不完整结果

句柄扫描会尽力启用 `SeDebugPrivilege`（需要管理员）。无法打开的进程（其他用户、
受保护进程等）会列在 `skipped_processes` 中；句柄名称解析超过 250ms 的进程会列在
`timed_out_processes` 中——少数设备句柄会让 `GetFinalPathNameByHandleW` /
`NtQueryObject` 在内核里阻塞，这些查询在独立线程中执行，超时后放弃，不会拖死整个扫描。
两种情况都会在 stderr 给出警告，JSON 中也会包含对应字段。

## 作为库使用

```rust
use std::path::Path;
use win_file_lock_detector::{detect_file_lock, scan_handles};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 文件：Restart Manager
    let lock = detect_file_lock(Path::new(r"D:\work\demo\report.docx"))?;
    for process in &lock.processes {
        println!(
            "{} {} {:?}",
            process.pid,
            process.image_path.as_deref().unwrap_or("<unknown>"),
            process.kind
        );
    }

    // 目录：句柄扫描（第二个参数为是否包含目录内的条目）
    let report = scan_handles(Path::new(r"D:\work\demo"), true)?;
    for handle in &report.handles {
        println!(
            "{} {:?} {} {:?}",
            handle.pid, handle.relation, handle.matched_path.display(), handle.object_kind
        );
    }

    Ok(())
}
```

`restart_manager::detect_file_locks` 可以一次检测多个文件（每个文件一个 Restart
Manager 会话，以保证结果和路径一一对应）。

## 实现要点

1. 先打开一个自己进程的句柄，在句柄表快照里反查出 `File` 对象类型的索引，
   从而避免解析 `ObjectTypesInformation`。
2. 枚举 `SystemExtendedHandleInformation`，对 `File` 类型的句柄逐个
   `OpenProcess(PROCESS_DUP_HANDLE)` + `DuplicateHandle` 复制到本进程。
3. `GetFileType` 过滤掉管道 / 套接字 / 字符设备（它们同样是 `File` 对象，
   但无法给出磁盘路径，且查询名称可能挂起）。
4. 优先 `GetFinalPathNameByHandleW` 取 Win32 路径；它要求
   `FILE_READ_ATTRIBUTES`，失败时回退到 `NtQueryObject` 的 NT 设备路径。
5. 通过 `QueryDosDevice` 建立盘符 ↔ NT 设备映射（支持 `subst`、UNC、
   `\??\` 前缀），同时比较 Win32 路径和 NT 路径，并用路径分隔符做边界检查，
   避免 `C:\foo` 误匹配 `C:\foobar`。

## 测试

```bash
cargo test
```

集成测试会在测试进程内真实打开文件 / 目录句柄，再验证两种检测方式都能找到它。

也可以手动复现：

```bash
cargo run --example hold_handle -- "D:\work\demo" 60
```

另开一个终端运行检测器即可看到 `hold_handle.exe`。

## 已知限制

- 卷挂载到文件夹、`\\?\Volume{...}` 等特殊路径可能无法与 NT 设备路径对应；
  常见盘符、`subst` 盘和 UNC 路径已处理。
- 扫描基于某一时刻的句柄表快照，期间新打开或关闭的句柄可能不在结果中。
- 同一进程指向同一路径的多个句柄按 `(PID, 路径)` 去重。
- 只支持本机路径；网络路径的结果取决于凭据和访问权限。
