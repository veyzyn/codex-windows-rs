# codex-windows-rs

`codex-windows-rs` is a Rust launcher for running Codex on Windows with a smoother setup flow and environment repairs.

It replaces the old PowerShell-heavy flow with a native binary that:

- extracts the DMG/app payload on Windows
- patches Codex startup env handling for full PATH hydration
- patches preload exposure behavior
- prepares native Electron modules
- resolves a native `codex.exe` path reliably
- launches Codex with clean TUI progress output

## Requirements

- Windows
- Node.js + npm
- `7z.exe` available (or downloadable by launcher)

## Usage

```powershell
codex-launcher
```

Optional flags:

```powershell
codex-launcher --reuse
codex-launcher --no-launch
codex-launcher --show-codex-output
codex-launcher --work-dir work
codex-launcher --codex-cli-path "C:\path\to\codex.exe"
```

## Build

```powershell
cargo build --release
```

Binary output:

`target\release\codex-launcher.exe`

