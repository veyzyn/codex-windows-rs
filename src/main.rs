use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use reqwest::blocking::Client;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::HashSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc;
use std::time::Duration;
use url::Url;
use walkdir::WalkDir;
use which::which;

#[cfg(windows)]
use winreg::RegKey;
#[cfg(windows)]
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

const NPM_CONFIG_KEYS: [&str; 5] = [
    "npm_config_runtime",
    "npm_config_target",
    "npm_config_disturl",
    "npm_config_arch",
    "npm_config_build_from_source",
];

const DEFAULT_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC";
const SPINNER_TICKS: [&str; 8] = [
    "\u{280B}", "\u{2819}", "\u{2839}", "\u{2838}", "\u{283C}", "\u{2834}", "\u{2826}", "\u{2827}",
];
const STATUS_OK: &str = "\u{2713}";
const STATUS_FAIL: &str = "\u{2717}";
const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_DIM: &str = "\x1b[2m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_CYAN: &str = "\x1b[36m";
const PRELOAD_PROCESS_EXPOSE: &str = "const P={env:process.env,platform:process.platform,versions:process.versions,arch:process.arch,cwd:()=>process.env.PWD,argv:process.argv,pid:process.pid};n.contextBridge.exposeInMainWorld(\"process\",P);";
const MAIN_ENV_PATCH_MARKER: &str = "/* CODEX_WINDOWS_ENV_FIX_V1 */";
const MAIN_MPE_PATH_FIX_MARKER: &str = "/* CODEX_WINDOWS_MPE_PATH_FIX_V1 */";
const MAIN_MPE_PATH_FIX_TARGET: &str = "e.binDirectory&&(n.PATH=_pe(n.PATH,e.binDirectory))";
const MAIN_MPE_PATH_FIX_REPLACEMENT: &str = "e.binDirectory&&(n.PATH=_pe(n.PATH??n.Path,e.binDirectory),n.Path=n.PATH/* CODEX_WINDOWS_MPE_PATH_FIX_V1 */)";
const MAIN_ENV_PATCH_JS: &str = r#"(function(){if(process.platform!=="win32")return;try{const cp=require("child_process");const split=function(v){return String(v||"").split(";").map(function(s){return s.trim();}).filter(Boolean);};const expand=function(v){return String(v||"").replace(/%([^%]+)%/g,function(_,k){return process.env[k]||("%"+k+"%");}).replace(/[\\\/]+$/,"");};const add=function(arr,seen,v){const p=expand(v);if(!p)return;const key=p.toLowerCase();if(!seen.has(key)){seen.add(key);arr.push(p);}};const readReg=function(key){try{const out=cp.spawnSync("reg.exe",["query",key,"/v","Path"],{encoding:"utf8",windowsHide:true});if(out.status!==0)return[];const lines=String(out.stdout||"").split(/\r?\n/);for(const line of lines){if(!/REG_(SZ|EXPAND_SZ)/i.test(line))continue;const m=line.match(/Path\s+REG_\w+\s+(.*)$/i);if(m&&m[1])return split(m[1]);}return [];}catch{return[];}};const seen=new Set();const out=[];for(const p of split(process.env.PATH||process.env.Path||""))add(out,seen,p);for(const p of readReg("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"))add(out,seen,p);for(const p of readReg("HKCU\\Environment"))add(out,seen,p);const sr=process.env.SystemRoot||process.env.windir||"C:\\Windows";const extras=[sr+"\\System32",sr+"\\System32\\Wbem",sr+"\\System32\\WindowsPowerShell\\v1.0",sr+"\\System32\\OpenSSH",(process.env.LOCALAPPDATA||"")+"\\Microsoft\\WinGet\\Links",(process.env.USERPROFILE||"")+"\\.cargo\\bin",(process.env.USERPROFILE||"")+"\\scoop\\shims",(process.env.ProgramFiles||"")+"\\Git\\cmd",(process.env.ProgramFiles||"")+"\\Git\\usr\\bin",(process.env["ProgramFiles(x86)"]||"")+"\\Git\\cmd",(process.env["ProgramFiles(x86)"]||"")+"\\Git\\usr\\bin"];for(const p of extras)add(out,seen,p);if(!process.env.SystemRoot)process.env.SystemRoot=sr;if(!process.env.windir)process.env.windir=sr;if(!process.env.ComSpec)process.env.ComSpec=sr+"\\System32\\cmd.exe";if(!process.env.PATHEXT)process.env.PATHEXT=".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC";const fixed=out.join(";");process.env.PATH=fixed;process.env.Path=fixed;}catch{}})();"#;

#[derive(Debug, Parser)]
#[command(
    name = "codex-launcher",
    version,
    about = "Extract and run Codex DMG on Windows with repaired environment handling"
)]
struct Cli {
    #[arg(long = "dmg-path")]
    dmg_path: Option<PathBuf>,

    #[arg(long = "work-dir", default_value = "work")]
    work_dir: PathBuf,

    #[arg(long = "codex-cli-path")]
    codex_cli_path: Option<PathBuf>,

    #[arg(long = "extra-path")]
    extra_path: Vec<String>,

    #[arg(long = "reuse", default_value_t = false)]
    reuse: bool,

    #[arg(long = "no-launch", default_value_t = false)]
    no_launch: bool,

    #[arg(long = "show-codex-output", default_value_t = false)]
    show_codex_output: bool,

    // Compatibility flag from the PowerShell runner. Intentionally no-op because
    // this launcher does not generate shims.
    #[arg(long = "no-command-shims", default_value_t = false, hide = true)]
    no_command_shims: bool,
}

#[derive(Debug, Clone)]
struct NodeTools {
    node: PathBuf,
    npm: PathBuf,
    npx: Option<PathBuf>,
}

fn main() {
    if let Err(err) = run() {
        log_error(&format!("error: {err:#}"));
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse_from(preprocess_args());
    let _ = cli.no_command_shims;

    repair_process_environment(&cli.extra_path);
    ensure_git_on_path();
    ensure_rg_on_path();

    let node_tools = resolve_node_tools()?;

    for key in NPM_CONFIG_KEYS {
        remove_env_var(key);
    }

    let dmg_path = resolve_dmg_path(cli.dmg_path.as_deref())?;
    let work_dir = ensure_dir(&cli.work_dir)?;

    let seven_zip = resolve_7z(Some(&work_dir))?.ok_or_else(|| anyhow!("7z not found."))?;

    let extracted_dir = work_dir.join("extracted");
    let electron_dir = work_dir.join("electron");
    let app_dir = work_dir.join("app");
    let native_dir = work_dir.join("native-builds");
    let user_data_dir = work_dir.join("userdata");
    let cache_dir = work_dir.join("cache");

    if !cli.reuse {
        extract_dmg_to_app(
            &seven_zip,
            &dmg_path,
            &extracted_dir,
            &electron_dir,
            &app_dir,
            &node_tools,
        )?;
    }

    run_step("Patching main startup env", || {
        patch_main_bundle_env(&app_dir)
    })?;
    run_step("Self-testing env patch", || {
        run_env_fix_self_test(&node_tools.node)
    })?;
    run_step("Patching preload", || patch_preload(&app_dir))?;

    let pkg: Value = run_step("Reading app metadata", || {
        let pkg_path = app_dir.join("package.json");
        if !pkg_path.exists() {
            bail!("package.json not found at {}", pkg_path.display());
        }
        let pkg_raw = fs::read_to_string(&pkg_path)
            .with_context(|| format!("failed to read {}", pkg_path.display()))?;
        let pkg: Value = serde_json::from_str(&pkg_raw).context("failed to parse package.json")?;
        Ok(pkg)
    })?;

    let electron_version = json_path_string(&pkg, &["devDependencies", "electron"])
        .ok_or_else(|| anyhow!("Electron version not found."))?;
    let better_version = json_path_string(&pkg, &["dependencies", "better-sqlite3"])
        .ok_or_else(|| anyhow!("better-sqlite3 version not found."))?;
    let pty_version = json_path_string(&pkg, &["dependencies", "node-pty"])
        .ok_or_else(|| anyhow!("node-pty version not found."))?;

    let pty_arch = detect_pty_arch();
    let bs_dst = app_dir.join("node_modules/better-sqlite3/build/Release/better_sqlite3.node");
    let pty_dst_pre = app_dir.join(format!("node_modules/node-pty/prebuilds/{pty_arch}"));
    let skip_native =
        cli.no_launch && cli.reuse && bs_dst.exists() && pty_dst_pre.join("pty.node").exists();

    let electron_exe = native_dir.join("node_modules/electron/dist/electron.exe");
    if skip_native {
        log_info("Native modules already present in app. Skipping rebuild.");
    } else {
        run_step("Preparing native modules", || {
            prepare_native_modules(
                &app_dir,
                &native_dir,
                &electron_version,
                &better_version,
                &pty_version,
                &pty_arch,
                &bs_dst,
                &pty_dst_pre,
                &node_tools,
            )
        })?;
    }

    if !cli.no_launch {
        let codex_cli: PathBuf = run_step("Resolving Codex CLI", || {
            resolve_codex_cli_path(cli.codex_cli_path.as_deref(), &node_tools.npm)?
                .ok_or_else(|| anyhow!("codex.exe not found."))
        })?;

        let mut codex_child = run_step("Launching Codex", || {
            launch_codex(
                &app_dir,
                &native_dir,
                &electron_exe,
                &user_data_dir,
                &cache_dir,
                &pkg,
                &codex_cli,
                cli.show_codex_output,
            )
        })?;
        log_info("Codex launched, press Ctrl+C to exit or close Codex.");
        let status = codex_child
            .wait()
            .context("failed waiting for Codex process")?;
        check_status(status, "codex process")?;
    }

    Ok(())
}

fn log_step_success(label: &str) {
    println!("  {ANSI_GREEN}{STATUS_OK}{ANSI_RESET} {ANSI_BOLD}{label}{ANSI_RESET}");
}

fn log_step_failure(label: &str) {
    eprintln!("  {ANSI_RED}{STATUS_FAIL}{ANSI_RESET} {ANSI_BOLD}{label}{ANSI_RESET}");
}

fn log_progress_done(label: &str) {
    println!(
        "  {ANSI_GREEN}{STATUS_OK}{ANSI_RESET} {ANSI_BOLD}{label}{ANSI_RESET} {ANSI_CYAN}[========================================]{ANSI_RESET} {ANSI_DIM}100%{ANSI_RESET}"
    );
}

fn log_info(message: &str) {
    println!("  {ANSI_CYAN}i{ANSI_RESET} {ANSI_DIM}{message}{ANSI_RESET}");
}

fn log_warn(message: &str) {
    eprintln!("  {ANSI_YELLOW}!{ANSI_RESET} {message}");
}

fn log_error(message: &str) {
    eprintln!("  {ANSI_RED}{message}{ANSI_RESET}");
}

fn preprocess_args() -> Vec<OsString> {
    let mut out = Vec::new();
    let mut args = env::args_os();
    if let Some(first) = args.next() {
        out.push(first);
    }
    for arg in args {
        if let Some(s) = arg.to_str() {
            let mapped = match s {
                "-DmgPath" | "--DmgPath" => Some("--dmg-path"),
                "-WorkDir" | "--WorkDir" => Some("--work-dir"),
                "-CodexCliPath" | "--CodexCliPath" => Some("--codex-cli-path"),
                "-ExtraPath" | "--ExtraPath" => Some("--extra-path"),
                "-NoCommandShims" | "--NoCommandShims" => Some("--no-command-shims"),
                "-Reuse" | "--Reuse" => Some("--reuse"),
                "-NoLaunch" | "--NoLaunch" => Some("--no-launch"),
                "-ShowCodexOutput" | "--ShowCodexOutput" => Some("--show-codex-output"),
                _ => None,
            };
            if let Some(m) = mapped {
                out.push(OsString::from(m));
                continue;
            }
        }
        out.push(arg);
    }
    out
}

fn run_step<T, F>(label: &str, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .expect("valid spinner template")
            .tick_strings(&SPINNER_TICKS),
    );
    pb.set_message(label.to_owned());
    pb.enable_steady_tick(Duration::from_millis(110));

    match f() {
        Ok(value) => {
            pb.finish_and_clear();
            log_step_success(label);
            Ok(value)
        }
        Err(err) => {
            pb.finish_and_clear();
            log_step_failure(label);
            Err(err)
        }
    }
}

fn resolve_node_tools() -> Result<NodeTools> {
    let node = resolve_command_path(&["node.exe", "node"], &[])?;
    let mut local_hints = Vec::new();
    if let Some(node_dir) = node.parent() {
        local_hints.push(node_dir.join("npm.cmd"));
        local_hints.push(node_dir.join("npm"));
        local_hints.push(node_dir.join("npx.cmd"));
        local_hints.push(node_dir.join("npx"));
    }

    let npm = resolve_command_path(&["npm.cmd", "npm.exe", "npm"], &local_hints)?;
    let npx = resolve_command_path_optional(&["npx.cmd", "npx.exe", "npx"], &local_hints);

    Ok(NodeTools { node, npm, npx })
}

fn resolve_command_path(names: &[&str], hints: &[PathBuf]) -> Result<PathBuf> {
    for name in names {
        if let Ok(path) = which(name) {
            return Ok(canonicalize_best(&path));
        }
    }
    for hint in hints {
        if hint.exists() {
            return Ok(canonicalize_best(hint));
        }
    }
    bail!("command not found: {}", names.join(" or "))
}

fn resolve_command_path_optional(names: &[&str], hints: &[PathBuf]) -> Option<PathBuf> {
    for name in names {
        if let Ok(path) = which(name) {
            return Some(canonicalize_best(&path));
        }
    }
    for hint in hints {
        if hint.exists() {
            return Some(canonicalize_best(hint));
        }
    }
    None
}

fn resolve_dmg_path(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        if !path.exists() {
            bail!("DMG not found: {}", path.display());
        }
        return Ok(canonicalize_best(path));
    }

    let cwd = env::current_dir().context("failed to read current directory")?;
    let mut roots = vec![cwd.clone()];
    if let Some(name) = cwd.file_name().and_then(OsStr::to_str) {
        if name.eq_ignore_ascii_case("codex-launcher") {
            if let Some(parent) = cwd.parent() {
                roots.push(parent.to_path_buf());
            }
        }
    }

    for root in &roots {
        let default = root.join("Codex.dmg");
        if default.exists() {
            return Ok(canonicalize_best(&default));
        }
    }

    for root in &roots {
        if let Some(found) = first_dmg_in_dir(root)? {
            return Ok(found);
        }
    }

    bail!("No DMG found.")
}

fn first_dmg_in_dir(dir: &Path) -> Result<Option<PathBuf>> {
    let mut entries = fs::read_dir(dir)
        .with_context(|| format!("failed to read directory {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(OsStr::to_str)
                .map(|ext| ext.eq_ignore_ascii_case("dmg"))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    entries.sort();
    Ok(entries.first().map(|p| canonicalize_best(p)))
}

fn ensure_dir(path: &Path) -> Result<PathBuf> {
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))?;
    Ok(canonicalize_best(path))
}

fn resolve_7z(base_dir: Option<&Path>) -> Result<Option<PathBuf>> {
    if let Ok(path) = which("7z") {
        return Ok(Some(path));
    }

    let p1 = join_env_path("ProgramFiles", "7-Zip\\7z.exe");
    let p2 = join_env_path("ProgramFiles(x86)", "7-Zip\\7z.exe");
    for cand in [p1, p2].into_iter().flatten() {
        if cand.exists() {
            return Ok(Some(canonicalize_best(&cand)));
        }
    }

    if which("winget").is_ok() {
        let mut cmd = Command::new("winget");
        cmd.args([
            "install",
            "--id",
            "7zip.7zip",
            "-e",
            "--source",
            "winget",
            "--accept-package-agreements",
            "--accept-source-agreements",
            "--silent",
        ]);
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        let _ = cmd.status();

        let p1 = join_env_path("ProgramFiles", "7-Zip\\7z.exe");
        let p2 = join_env_path("ProgramFiles(x86)", "7-Zip\\7z.exe");
        for cand in [p1, p2].into_iter().flatten() {
            if cand.exists() {
                return Ok(Some(canonicalize_best(&cand)));
            }
        }
    }

    let Some(base_dir) = base_dir else {
        return Ok(None);
    };

    let tools = base_dir.join("tools");
    let seven_zip_dir = tools.join("7zip");
    fs::create_dir_all(&seven_zip_dir)
        .with_context(|| format!("failed to create {}", seven_zip_dir.display()))?;

    let client = Client::builder()
        .build()
        .context("failed to build HTTP client")?;
    let html = match client.get("https://www.7-zip.org/").send() {
        Ok(resp) => resp
            .error_for_status()
            .context("failed to fetch 7-zip homepage")?
            .text()
            .context("failed to read 7-zip homepage")?,
        Err(_) => return Ok(None),
    };

    let re = Regex::new(r#"href="a/(7z[0-9]+-extra\.7z)""#).expect("regex is valid");
    let Some(extra_name) = re
        .captures(&html)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_owned())
    else {
        return Ok(None);
    };

    let seven_r = tools.join("7zr.exe");
    let extra_path = tools.join(&extra_name);
    if !seven_r.exists() {
        download_file(&client, "https://www.7-zip.org/a/7zr.exe", &seven_r)?;
    }
    if !extra_path.exists() {
        let extra_url = format!("https://www.7-zip.org/a/{extra_name}");
        download_file(&client, &extra_url, &extra_path)?;
    }

    let status = Command::new(&seven_r)
        .arg("x")
        .arg("-y")
        .arg(&extra_path)
        .arg(format!("-o{}", seven_zip_dir.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to run 7zr")?;
    if !status.success() {
        return Ok(None);
    }

    let candidate = seven_zip_dir.join("7z.exe");
    if candidate.exists() {
        return Ok(Some(canonicalize_best(&candidate)));
    }
    Ok(None)
}

fn download_file(client: &Client, url: &str, out_path: &Path) -> Result<()> {
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let bytes = client
        .get(url)
        .send()
        .with_context(|| format!("failed to GET {url}"))?
        .error_for_status()
        .with_context(|| format!("failed response for {url}"))?
        .bytes()
        .with_context(|| format!("failed reading body from {url}"))?;
    fs::write(out_path, &bytes).with_context(|| format!("failed to write {}", out_path.display()))
}

fn extract_dmg_to_app(
    seven_zip: &Path,
    dmg_path: &Path,
    extracted_dir: &Path,
    electron_dir: &Path,
    app_dir: &Path,
    node_tools: &NodeTools,
) -> Result<()> {
    fs::create_dir_all(extracted_dir)
        .with_context(|| format!("failed to create {}", extracted_dir.display()))?;
    run_7z_with_progress(
        Command::new(seven_zip)
            .arg("x")
            .arg("-y")
            .arg(dmg_path)
            .arg(format!("-o{}", extracted_dir.display()))
            .arg("-bso0")
            .arg("-bsp1"),
        "Extracting DMG archive",
        true,
    )?;

    fs::create_dir_all(electron_dir)
        .with_context(|| format!("failed to create {}", electron_dir.display()))?;
    let hfs = extracted_dir.join("4.hfs");
    if hfs.exists() {
        run_7z_with_progress(
            Command::new(seven_zip)
                .arg("x")
                .arg("-y")
                .arg(&hfs)
                .arg("Codex Installer/Codex.app/Contents/Resources/app.asar")
                .arg("Codex Installer/Codex.app/Contents/Resources/app.asar.unpacked")
                .arg(format!("-o{}", electron_dir.display()))
                .arg("-bso0")
                .arg("-bsp1"),
            "Extracting app payload",
            true,
        )?;
    } else {
        let direct_app =
            extracted_dir.join("Codex Installer/Codex.app/Contents/Resources/app.asar");
        if !direct_app.exists() {
            bail!("app.asar not found.");
        }
        let direct_unpacked =
            extracted_dir.join("Codex Installer/Codex.app/Contents/Resources/app.asar.unpacked");
        let dest_base = electron_dir.join("Codex Installer/Codex.app/Contents/Resources");
        fs::create_dir_all(&dest_base)
            .with_context(|| format!("failed to create {}", dest_base.display()))?;
        copy_file(&direct_app, &dest_base.join("app.asar"))?;
        if direct_unpacked.exists() {
            copy_dir_recursive(&direct_unpacked, &dest_base.join("app.asar.unpacked"))?;
        }
    }

    fs::create_dir_all(app_dir)
        .with_context(|| format!("failed to create {}", app_dir.display()))?;
    let asar = electron_dir.join("Codex Installer/Codex.app/Contents/Resources/app.asar");
    if !asar.exists() {
        bail!("app.asar not found.");
    }
    run_asar_extract(&asar, app_dir, node_tools)?;

    let unpacked =
        electron_dir.join("Codex Installer/Codex.app/Contents/Resources/app.asar.unpacked");
    if unpacked.exists() {
        copy_dir_recursive(&unpacked, app_dir)?;
    }

    Ok(())
}

fn run_asar_extract(asar: &Path, app_dir: &Path, node_tools: &NodeTools) -> Result<()> {
    let npm_status = run_checked_quiet_spinner(
        Command::new(&node_tools.npm)
            .arg("exec")
            .arg("--yes")
            .arg("@electron/asar")
            .arg("--")
            .arg("extract")
            .arg(asar)
            .arg(app_dir),
        "Unpacking app.asar",
    );
    if npm_status.is_ok() {
        return Ok(());
    }

    let Some(npx_path) = &node_tools.npx else {
        bail!("asar extract failed: npm exec failed and npx is unavailable");
    };

    run_checked_quiet_spinner(
        Command::new(npx_path)
            .arg("--yes")
            .arg("@electron/asar")
            .arg("extract")
            .arg(asar)
            .arg(app_dir),
        "Unpacking app.asar",
    )
}

fn patch_preload(app_dir: &Path) -> Result<()> {
    let preload = app_dir.join(".vite/build/preload.js");
    if !preload.exists() {
        return Ok(());
    }

    let raw = fs::read_to_string(&preload)
        .with_context(|| format!("failed to read {}", preload.display()))?;
    if raw.contains(PRELOAD_PROCESS_EXPOSE) {
        return Ok(());
    }

    let re = Regex::new(r#"n\.contextBridge\.exposeInMainWorld\("codexWindowType",[A-Za-z0-9_$]+\);n\.contextBridge\.exposeInMainWorld\("electronBridge",[A-Za-z0-9_$]+\);"#)
        .expect("regex is valid");
    let mat = re
        .find(&raw)
        .ok_or_else(|| anyhow!("preload patch point not found."))?;
    let mut replacement = String::with_capacity(PRELOAD_PROCESS_EXPOSE.len() + mat.as_str().len());
    replacement.push_str(PRELOAD_PROCESS_EXPOSE);
    replacement.push_str(mat.as_str());
    let patched = raw.replacen(mat.as_str(), &replacement, 1);

    fs::write(&preload, patched).with_context(|| format!("failed to write {}", preload.display()))
}

fn prepare_native_modules(
    app_dir: &Path,
    native_dir: &Path,
    electron_version: &str,
    better_version: &str,
    pty_version: &str,
    arch: &str,
    bs_dst: &Path,
    pty_dst_pre: &Path,
    node_tools: &NodeTools,
) -> Result<()> {
    fs::create_dir_all(native_dir)
        .with_context(|| format!("failed to create {}", native_dir.display()))?;

    let package_json = native_dir.join("package.json");
    if !package_json.exists() {
        run_checked_quiet_spinner(
            Command::new(&node_tools.npm)
                .arg("init")
                .arg("-y")
                .current_dir(native_dir),
            "Initializing native build workspace",
        )?;
    }

    let bs_src_probe =
        native_dir.join("node_modules/better-sqlite3/build/Release/better_sqlite3.node");
    let pty_src_probe = native_dir.join(format!("node_modules/node-pty/prebuilds/{arch}/pty.node"));
    let electron_exe = native_dir.join("node_modules/electron/dist/electron.exe");
    let have_native = bs_src_probe.exists() && pty_src_probe.exists() && electron_exe.exists();

    if !have_native {
        let deps = [
            format!("better-sqlite3@{better_version}"),
            format!("node-pty@{pty_version}"),
            "@electron/rebuild".to_owned(),
            "prebuild-install".to_owned(),
            format!("electron@{electron_version}"),
        ];
        let mut cmd = Command::new(&node_tools.npm);
        cmd.arg("install").arg("--no-save");
        for dep in deps {
            cmd.arg(dep);
        }
        cmd.current_dir(native_dir);
        run_checked_quiet(&mut cmd, "install native dependencies")?;
    }

    // No mid-step logging here: this function runs under a parent spinner.
    let mut rebuild_ok = true;
    if !have_native {
        let rebuild_cli = native_dir.join("node_modules/@electron/rebuild/lib/cli.js");
        if !rebuild_cli.exists() {
            rebuild_ok = false;
            log_warn("electron-rebuild failed: electron-rebuild not found.");
        } else {
            let status = Command::new(&node_tools.node)
                .arg(&rebuild_cli)
                .arg("-v")
                .arg(electron_version)
                .arg("-w")
                .arg("better-sqlite3,node-pty")
                .current_dir(native_dir)
                .stdout(Stdio::null())
                .status();
            match status {
                Ok(s) if s.success() => {}
                Ok(s) => {
                    rebuild_ok = false;
                    log_warn(&format!(
                        "electron-rebuild failed with status {}",
                        format_exit_status(s)
                    ));
                }
                Err(err) => {
                    rebuild_ok = false;
                    log_warn(&format!("electron-rebuild failed: {err}"));
                }
            }
        }
    }

    if !rebuild_ok && !have_native {
        log_warn("Trying prebuilt Electron binaries for better-sqlite3...");
        let bs_dir = native_dir.join("node_modules/better-sqlite3");
        if bs_dir.exists() {
            let prebuild_cli = native_dir.join("node_modules/prebuild-install/bin.js");
            if !prebuild_cli.exists() {
                bail!("prebuild-install not found.");
            }
            let status = Command::new(&node_tools.node)
                .arg(prebuild_cli)
                .arg("-r")
                .arg("electron")
                .arg("-t")
                .arg(electron_version)
                .arg("--tag-prefix=electron-v")
                .current_dir(&bs_dir)
                .stdout(Stdio::null())
                .status()
                .context("failed to run prebuild-install")?;
            if !status.success() {
                log_warn(&format!(
                    "prebuild-install failed with status {}",
                    format_exit_status(status)
                ));
            }
        }
    }

    set_env_var("ELECTRON_RUN_AS_NODE", "1");
    let probe_result = (|| -> Result<()> {
        if !electron_exe.exists() {
            bail!("electron.exe not found.");
        }
        if !native_dir.join("node_modules/better-sqlite3").exists() {
            bail!("better-sqlite3 not installed.");
        }
        run_checked_quiet(
            Command::new(&electron_exe)
                .arg("-e")
                .arg("try{require('./node_modules/better-sqlite3');process.exit(0)}catch(e){console.error(e);p
          rocess.exit(1)}")
                .current_dir(native_dir),
            "better-sqlite3 load check",
        )
    })();
    remove_env_var("ELECTRON_RUN_AS_NODE");
    probe_result?;

    let bs_src = native_dir.join("node_modules/better-sqlite3/build/Release/better_sqlite3.node");
    if !bs_src.exists() {
        bail!("better_sqlite3.node not found.");
    }
    copy_file(&bs_src, bs_dst)?;

    let pty_src_dir = native_dir.join(format!("node_modules/node-pty/prebuilds/{arch}"));
    let pty_dst_rel = app_dir.join("node_modules/node-pty/build/Release");
    fs::create_dir_all(pty_dst_pre)
        .with_context(|| format!("failed to create {}", pty_dst_pre.display()))?;
    fs::create_dir_all(&pty_dst_rel)
        .with_context(|| format!("failed to create {}", pty_dst_rel.display()))?;

    for file in ["pty.node", "conpty.node", "conpty_console_list.node"] {
        let src = pty_src_dir.join(file);
        if src.exists() {
            copy_file(&src, &pty_dst_pre.join(file))?;
            copy_file(&src, &pty_dst_rel.join(file))?;
        }
    }

    Ok(())
}

fn launch_codex(
    app_dir: &Path,
    native_dir: &Path,
    electron_exe: &Path,
    user_data_dir: &Path,
    cache_dir: &Path,
    pkg: &Value,
    codex_cli: &Path,
    show_codex_output: bool,
) -> Result<Child> {
    let renderer_url = Url::from_file_path(app_dir.join("webview/index.html"))
        .map_err(|_| anyhow!("failed to build file URL for renderer"))?
        .to_string();

    remove_env_var("ELECTRON_RUN_AS_NODE");
    set_env_var("ELECTRON_RENDERER_URL", renderer_url);
    set_env_var("ELECTRON_FORCE_IS_PACKAGED", "1");
    let build_number =
        json_path_string(pkg, &["codexBuildNumber"]).unwrap_or_else(|| "510".to_owned());
    let build_flavor =
        json_path_string(pkg, &["codexBuildFlavor"]).unwrap_or_else(|| "prod".to_owned());
    set_env_var("CODEX_BUILD_NUMBER", build_number);
    set_env_var("CODEX_BUILD_FLAVOR", &build_flavor);
    set_env_var("BUILD_FLAVOR", &build_flavor);
    set_env_var("NODE_ENV", "production");
    set_env_var("CODEX_CLI_PATH", codex_cli);
    set_env_var("PWD", app_dir);

    ensure_git_on_path();

    fs::create_dir_all(user_data_dir)
        .with_context(|| format!("failed to create {}", user_data_dir.display()))?;
    fs::create_dir_all(cache_dir)
        .with_context(|| format!("failed to create {}", cache_dir.display()))?;

    let mut command = Command::new(electron_exe);
    command
        .arg(app_dir)
        .arg(format!("--user-data-dir={}", user_data_dir.display()))
        .arg(format!("--disk-cache-dir={}", cache_dir.display()))
        .current_dir(native_dir);

    if show_codex_output {
        command.arg("--enable-logging");
        command
            .spawn()
            .context("failed to spawn launch codex process")
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
        command
            .spawn()
            .context("failed to spawn launch codex process")
    }
}

fn resolve_codex_cli_path(explicit: Option<&Path>, npm_cmd: &Path) -> Result<Option<PathBuf>> {
    if let Some(path) = explicit {
        if !path.exists() {
            bail!("Codex CLI not found: {}", path.display());
        }
        if is_exe_path(path) {
            return Ok(Some(canonicalize_best(path)));
        }
        if let Some(found) = resolve_codex_from_wrapper(path) {
            return Ok(Some(found));
        }
        bail!(
            "Codex CLI path is not a native executable: {} (expected codex.exe)",
            path.display()
        );
    }

    if let Some(env_override) = env::var_os("CODEX_CLI_PATH") {
        let path = PathBuf::from(env_override);
        if path.exists() {
            if is_exe_path(&path) {
                return Ok(Some(canonicalize_best(&path)));
            }
            if let Some(found) = resolve_codex_from_wrapper(&path) {
                return Ok(Some(found));
            }
        }
    }

    let mut candidates = Vec::<PathBuf>::new();

    for query in ["codex.exe", "codex"] {
        let output = Command::new("where.exe")
            .arg(query)
            .output()
            .with_context(|| format!("failed to run where.exe {query}"));
        if let Ok(output) = output {
            if output.status.success() {
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    let clean = trim_wrapping_quotes(line.trim());
                    if !clean.is_empty() {
                        candidates.push(PathBuf::from(clean));
                    }
                }
            }
        }
    }

    if let Ok(Some(npm_root)) =
        run_capture(Command::new(npm_cmd).arg("root").arg("-g"), "npm root -g")
    {
        let npm_root = PathBuf::from(npm_root.trim());
        if !npm_root.as_os_str().is_empty() {
            let vendor_arch = detect_vendor_arch();
            candidates.push(npm_root.join(format!(
                "@openai/codex/vendor/{vendor_arch}/codex/codex.exe"
            )));
            candidates
                .push(npm_root.join("@openai/codex/vendor/x86_64-pc-windows-msvc/codex/codex.exe"));
            candidates.push(
                npm_root.join("@openai/codex/vendor/aarch64-pc-windows-msvc/codex/codex.exe"),
            );
            candidates.push(npm_root.join(format!(
                "@openai/codex/node_modules/@openai/codex-win32-x64/vendor/{vendor_arch}/cod
          ex/codex.exe"
            )));
            candidates.push(npm_root.join(format!(
                "@openai/codex/node_modules/@openai/codex-win32-arm64/vendor/{vendor_arch}/c
          odex/codex.exe"
            )));
            candidates.push(
                npm_root.join(
                    "@openai/codex/node_modules/@openai/codex-win32-x64/vendor/x86_64-pc-windows-msvc/codex/co
          dex.exe",
                ),
            );
            candidates.push(
                npm_root.join(
                    "@openai/codex/node_modules/@openai/codex-win32-arm64/vendor/aarch64-pc-windows-msvc/codex
          /codex.exe",
                ),
            );

            let modern_node_modules = npm_root.join("@openai/codex/node_modules");
            if modern_node_modules.exists() {
                if let Some(found) = find_modern_codex_exe(&modern_node_modules) {
                    candidates.push(found);
                }
            }
        }
    }

    for candidate in candidates {
        if !candidate.exists() {
            continue;
        }
        if is_exe_path(&candidate) {
            return Ok(Some(canonicalize_best(&candidate)));
        }
        if let Some(found) = resolve_codex_from_wrapper(&candidate) {
            return Ok(Some(found));
        }
    }

    Ok(None)
}

fn is_exe_path(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .map(|ext| ext.eq_ignore_ascii_case("exe"))
        .unwrap_or(false)
}

fn resolve_codex_from_wrapper(path: &Path) -> Option<PathBuf> {
    let parent = path.parent()?;
    let direct_vendor = parent.join("node_modules/@openai/codex/vendor");
    if let Some(found) = find_first_file_named(&direct_vendor, "codex.exe") {
        return Some(canonicalize_best(&found));
    }

    let modern_node_modules = parent.join("node_modules/@openai/codex/node_modules");
    if let Some(found) = find_modern_codex_exe(&modern_node_modules) {
        return Some(canonicalize_best(&found));
    }

    None
}

fn find_modern_codex_exe(root: &Path) -> Option<PathBuf> {
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        if !entry
            .file_name()
            .to_string_lossy()
            .eq_ignore_ascii_case("codex.exe")
        {
            continue;
        }
        let normalized = entry
            .path()
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        if normalized.contains("/@openai/codex-win32-x64/vendor/")
            || normalized.contains("/@openai/codex-win32-arm64/vendor/")
        {
            return Some(entry.path().to_path_buf());
        }
    }
    None
}

fn patch_main_bundle_env(app_dir: &Path) -> Result<()> {
    let main_bundle = find_main_bundle_path(app_dir)?;
    let original = fs::read(&main_bundle)
        .with_context(|| format!("failed to read {}", main_bundle.display()))?;
    let raw = String::from_utf8(original.clone())
        .with_context(|| format!("main bundle is not valid UTF-8: {}", main_bundle.display()))?;

    let already_env_patched = raw.contains(MAIN_ENV_PATCH_MARKER);
    let already_mpe_patched = raw.contains(MAIN_MPE_PATH_FIX_MARKER);
    if already_env_patched && already_mpe_patched {
        return Ok(());
    }

    let hash = sha256_hex(&original);
    let backup = PathBuf::from(format!("{}.bak.{}", main_bundle.display(), &hash[..12]));
    if !backup.exists() {
        fs::write(&backup, &original)
            .with_context(|| format!("failed to write backup {}", backup.display()))?;
    }

    let signature_ok = raw.contains("function zK(")
        && raw.contains("Object.assign(process.env")
        && raw.contains("_n.env");
    if !signature_ok {
        bail!(
            "main bundle signature mismatch for env patch (sha256: {}) in {}",
            hash,
            main_bundle.display()
        );
    }

    let mut patched = raw.clone();

    if !already_env_patched {
        let inject = format!("{}{}\n", MAIN_ENV_PATCH_MARKER, MAIN_ENV_PATCH_JS);
        patched = if let Some(idx) = patched.find("\"use strict\";") {
            let insert_at = idx + "\"use strict\";".len();
            format!(
                "{}{}{}",
                &patched[..insert_at],
                inject,
                &patched[insert_at..]
            )
        } else {
            format!("{inject}{patched}")
        };
    }

    if !already_mpe_patched {
        if patched.contains(MAIN_MPE_PATH_FIX_TARGET) {
            patched = patched.replacen(MAIN_MPE_PATH_FIX_TARGET, MAIN_MPE_PATH_FIX_REPLACEMENT, 1);
        } else {
            bail!(
                "main bundle signature mismatch for mpe PATH fix (sha256: {}) in {}",
                hash,
                main_bundle.display()
            );
        }
    }

    fs::write(&main_bundle, patched)
        .with_context(|| format!("failed to write {}", main_bundle.display()))?;
    Ok(())
}

fn find_main_bundle_path(app_dir: &Path) -> Result<PathBuf> {
    let build_dir = app_dir.join(".vite/build");
    if !build_dir.exists() {
        bail!("main bundle directory not found: {}", build_dir.display());
    }
    let mut mains = fs::read_dir(&build_dir)
        .with_context(|| format!("failed to read {}", build_dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(OsStr::to_str)
                    .map(|x| x.eq_ignore_ascii_case("js"))
                    .unwrap_or(false)
                && p.file_name()
                    .and_then(OsStr::to_str)
                    .map(|name| name.starts_with("main-"))
                    .unwrap_or(false)
        })
        .collect::<Vec<_>>();

    if mains.is_empty() {
        mains = fs::read_dir(&build_dir)
            .with_context(|| format!("failed to read {}", build_dir.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.extension()
                        .and_then(OsStr::to_str)
                        .map(|x| x.eq_ignore_ascii_case("js"))
                        .unwrap_or(false)
                    && p.file_name()
                        .and_then(OsStr::to_str)
                        .map(|name| name.starts_with("main"))
                        .unwrap_or(false)
            })
            .collect::<Vec<_>>();
    }

    mains.sort();
    mains
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("main bundle not found in {}", build_dir.display()))
}

fn run_env_fix_self_test(node_exe: &Path) -> Result<()> {
    if !node_exe.exists() {
        bail!(
            "node executable not found for env self-test: {}",
            node_exe.display()
        );
    }

    let user_root = env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir);
    let constrained_arg0 = user_root.join(".codex/tmp/arg0/codex-launcher-selftest");
    let constrained = format!(r"{};C:\codex\vendor", constrained_arg0.display());
    let script = format!(
        "process.env.PATH=process.env.TEST_PATH||'';process.env.Path=process.env.PATH;{};process.stdout.write(process.env.PATH||'');",
        MAIN_ENV_PATCH_JS
    );

    let output = Command::new(node_exe)
        .arg("-e")
        .arg(script)
        .env("TEST_PATH", &constrained)
        .output()
        .with_context(|| format!("failed to run env self-test via {}", node_exe.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "env self-test command failed (status {}): {} {}",
            format_exit_status(output.status),
            stdout.trim(),
            stderr.trim()
        );
    }

    let path_line = String::from_utf8_lossy(&output.stdout);
    let path_line = path_line.trim();
    let lower = path_line.to_ascii_lowercase();

    if !lower.contains(r"\windows\system32") {
        bail!("env self-test failed: repaired PATH is missing C:\\Windows\\System32");
    }

    let tooling_markers = [
        r"\microsoft\winget\links",
        r"\.cargo\bin",
        r"\scoop\shims",
        r"\git\cmd",
        r"\git\usr\bin",
    ];
    if !tooling_markers.iter().any(|m| lower.contains(m)) {
        bail!("env self-test failed: repaired PATH is missing expected user/tooling directories");
    }

    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn find_first_file_named(root: &Path, file_name: &str) -> Option<PathBuf> {
    if !root.exists() {
        return None;
    }
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file()
            && entry
                .file_name()
                .to_string_lossy()
                .eq_ignore_ascii_case(file_name)
        {
            return Some(entry.path().to_path_buf());
        }
    }
    None
}

fn detect_vendor_arch() -> &'static str {
    if env::var("PROCESSOR_ARCHITECTURE")
        .map(|v| v.eq_ignore_ascii_case("ARM64"))
        .unwrap_or(false)
    {
        "aarch64-pc-windows-msvc"
    } else {
        "x86_64-pc-windows-msvc"
    }
}

fn detect_pty_arch() -> &'static str {
    if env::var("PROCESSOR_ARCHITECTURE")
        .map(|v| v.eq_ignore_ascii_case("ARM64"))
        .unwrap_or(false)
    {
        "win32-arm64"
    } else {
        "win32-x64"
    }
}

fn json_path_string(root: &Value, path: &[&str]) -> Option<String> {
    let mut current = root;
    for segment in path {
        current = current.get(*segment)?;
    }

    match current {
        Value::String(s) => {
            if s.is_empty() {
                None
            } else {
                Some(s.clone())
            }
        }
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn repair_process_environment(extra_path_entries: &[String]) {
    let system_root = env::var("SystemRoot")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| env::var("windir").ok().filter(|v| !v.trim().is_empty()))
        .unwrap_or_else(|| "C:\\Windows".to_owned());
    set_env_var("SystemRoot", &system_root);
    if env::var("windir")
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        set_env_var("windir", &system_root);
    }
    if env::var("ComSpec")
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        let cmd = PathBuf::from(&system_root).join("System32/cmd.exe");
        set_env_var("ComSpec", cmd);
    }
    if env::var("PATHEXT")
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        set_env_var("PATHEXT", DEFAULT_PATHEXT);
    }

    let mut path_candidates = Vec::<String>::new();
    let current_path = current_path_value();
    if !current_path.is_empty() {
        path_candidates.extend(split_path_entries(&current_path));
    }

    if let Some(machine_path) = machine_path_from_registry() {
        path_candidates.extend(split_path_entries(&machine_path));
    }
    if let Some(user_path) = user_path_from_registry() {
        path_candidates.extend(split_path_entries(&user_path));
    }

    path_candidates.extend([
        PathBuf::from(&system_root)
            .join("System32")
            .to_string_lossy()
            .to_string(),
        PathBuf::from(&system_root)
            .join("System32/Wbem")
            .to_string_lossy()
            .to_string(),
        PathBuf::from(&system_root)
            .join("System32/WindowsPowerShell/v1.0")
            .to_string_lossy()
            .to_string(),
        PathBuf::from(&system_root)
            .join("System32/OpenSSH")
            .to_string_lossy()
            .to_string(),
    ]);

    if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
        path_candidates.push(
            PathBuf::from(local_app_data)
                .join("Microsoft/WinGet/Links")
                .to_string_lossy()
                .to_string(),
        );
    }
    if let Some(user_profile) = env::var_os("USERPROFILE") {
        let user_profile = PathBuf::from(user_profile);
        path_candidates.push(
            user_profile
                .join(".cargo/bin")
                .to_string_lossy()
                .to_string(),
        );
        path_candidates.push(
            user_profile
                .join("scoop/shims")
                .to_string_lossy()
                .to_string(),
        );
    }
    if let Some(program_files) = env::var_os("ProgramFiles") {
        let pf = PathBuf::from(program_files);
        path_candidates.push(pf.join("Git/cmd").to_string_lossy().to_string());
        path_candidates.push(pf.join("Git/usr/bin").to_string_lossy().to_string());
    }
    if let Some(program_files_x86) = env::var_os("ProgramFiles(x86)") {
        let pf = PathBuf::from(program_files_x86);
        path_candidates.push(pf.join("Git/cmd").to_string_lossy().to_string());
        path_candidates.push(pf.join("Git/usr/bin").to_string_lossy().to_string());
    }

    for extra in extra_path_entries {
        path_candidates.extend(split_path_entries(extra));
    }

    let joined = join_unique_path(path_candidates);
    set_path_value(&joined);
}

fn ensure_git_on_path() {
    let candidates = [
        join_env_path("ProgramFiles", "Git\\cmd\\git.exe"),
        join_env_path("ProgramFiles", "Git\\bin\\git.exe"),
        join_env_path("ProgramFiles(x86)", "Git\\cmd\\git.exe"),
        join_env_path("ProgramFiles(x86)", "Git\\bin\\git.exe"),
    ];

    let git_dir = candidates
        .into_iter()
        .flatten()
        .find(|p| p.exists())
        .and_then(|p| p.parent().map(Path::to_path_buf));

    if let Some(git_dir) = git_dir {
        prepend_path_entry(&git_dir);
    }
}

fn ensure_rg_on_path() {
    if which("rg").is_ok() {
        return;
    }

    let candidate_exe = [
        join_env_path("LOCALAPPDATA", "Microsoft\\WinGet\\Links\\rg.exe"),
        join_env_path("USERPROFILE", ".cargo\\bin\\rg.exe"),
        join_env_path("ProgramFiles", "Git\\usr\\bin\\rg.exe"),
        join_env_path("ProgramFiles(x86)", "Git\\usr\\bin\\rg.exe"),
    ]
    .into_iter()
    .flatten()
    .find(|p| p.exists());

    if let Some(exe) = candidate_exe {
        if let Some(dir) = exe.parent() {
            prepend_path_entry(dir);
        }
    }
}

fn prepend_path_entry(dir: &Path) {
    let current = current_path_value();
    if path_contains_entry(&current, dir) {
        return;
    }
    let dir_str = dir.to_string_lossy();
    let next = if current.trim().is_empty() {
        dir_str.to_string()
    } else {
        format!("{dir_str};{current}")
    };
    set_path_value(&next);
}

fn path_contains_entry(path_value: &str, entry: &Path) -> bool {
    let needle = normalize_path_entry(&entry.to_string_lossy());
    if needle.is_empty() {
        return true;
    }
    split_path_entries(path_value)
        .into_iter()
        .map(|part| normalize_path_entry(&part))
        .any(|part| !part.is_empty() && part == needle)
}

fn split_path_entries(value: &str) -> Vec<String> {
    value.split(';').map(|s| s.to_owned()).collect()
}

fn join_unique_path(entries: Vec<String>) -> String {
    let mut seen = HashSet::<String>::new();
    let mut out = Vec::<String>::new();
    for entry in entries {
        let normalized = normalize_path_entry(&entry);
        if normalized.is_empty() {
            continue;
        }
        let key = normalized.to_ascii_lowercase();
        if seen.insert(key) {
            out.push(normalized);
        }
    }
    out.join(";")
}

fn normalize_path_entry(entry: &str) -> String {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let expanded = expand_env_variables(trimmed);
    expanded
        .trim()
        .trim_end_matches('\\')
        .trim_end_matches('/')
        .to_owned()
}

fn expand_env_variables(input: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"%([^%]+)%").expect("valid regex"));
    re.replace_all(input, |caps: &regex::Captures<'_>| {
        let key = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        match env::var(key) {
            Ok(v) => Cow::Owned(v),
            Err(_) => Cow::Owned(
                caps.get(0)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_owned(),
            ),
        }
    })
    .to_string()
}

fn current_path_value() -> String {
    env::var("PATH")
        .or_else(|_| env::var("Path"))
        .unwrap_or_default()
}

fn set_path_value(path: &str) {
    set_env_var("PATH", path);
    set_env_var("Path", path);
}

#[cfg(windows)]
fn machine_path_from_registry() -> Option<String> {
    let hk = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hk
        .open_subkey("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment")
        .ok()?;
    key.get_value::<String, _>("Path").ok()
}

#[cfg(not(windows))]
fn machine_path_from_registry() -> Option<String> {
    None
}

#[cfg(windows)]
fn user_path_from_registry() -> Option<String> {
    let hk = RegKey::predef(HKEY_CURRENT_USER);
    let key = hk.open_subkey("Environment").ok()?;
    key.get_value::<String, _>("Path").ok()
}

#[cfg(not(windows))]
fn user_path_from_registry() -> Option<String> {
    None
}

fn join_env_path(var_name: &str, suffix: &str) -> Option<PathBuf> {
    let base = env::var_os(var_name)?;
    let base = PathBuf::from(base);
    if base.as_os_str().is_empty() {
        return None;
    }
    Some(base.join(suffix))
}

fn copy_file(src: &Path, dst: &Path) -> Result<()> {
    let parent = dst
        .parent()
        .ok_or_else(|| anyhow!("destination has no parent: {}", dst.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    fs::copy(src, dst)
        .with_context(|| format!("failed to copy {} -> {}", src.display(), dst.display()))?;
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    if !src.exists() {
        return Ok(());
    }
    for entry in WalkDir::new(src) {
        let entry = entry.with_context(|| format!("failed to walk {}", src.display()))?;
        let rel = entry
            .path()
            .strip_prefix(src)
            .with_context(|| format!("failed to strip prefix {}", src.display()))?;
        let target = dst.join(rel);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)
                .with_context(|| format!("failed to create {}", target.display()))?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            fs::copy(entry.path(), &target).with_context(|| {
                format!(
                    "failed to copy {} -> {}",
                    entry.path().display(),
                    target.display()
                )
            })?;
        }
    }
    Ok(())
}

fn run_capture(command: &mut Command, label: &str) -> Result<Option<String>> {
    let output = command
        .output()
        .with_context(|| format!("failed to run {label}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if text.is_empty() {
        Ok(None)
    } else {
        Ok(Some(text))
    }
}

fn run_checked_quiet(command: &mut Command, label: &str) -> Result<()> {
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let status = command
        .status()
        .with_context(|| format!("failed to run {label}"))?;
    check_status(status, label)
}

fn run_checked_quiet_spinner(command: &mut Command, label: &str) -> Result<()> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .expect("valid spinner template")
            .tick_strings(&SPINNER_TICKS),
    );
    pb.set_message(label.to_owned());
    pb.enable_steady_tick(Duration::from_millis(110));

    command.stdout(Stdio::null()).stderr(Stdio::null());
    let status = command
        .status()
        .with_context(|| format!("failed to run {label}"));
    match status {
        Ok(status) if status.success() => {
            pb.finish_and_clear();
            log_step_success(label);
            Ok(())
        }
        Ok(status) => {
            pb.finish_and_clear();
            log_step_failure(label);
            bail!("{label} failed with status {}", format_exit_status(status))
        }
        Err(err) => {
            pb.finish_and_clear();
            log_step_failure(label);
            Err(err)
        }
    }
}

fn run_7z_with_progress(command: &mut Command, label: &str, tolerate_non_zero: bool) -> Result<()> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to run {label}"))?;

    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg:<28} [{bar:40.cyan/blue}] {pos:>3}%")
            .expect("valid progress template")
            .progress_chars("=>-"),
    );
    pb.set_message(label.to_owned());
    pb.enable_steady_tick(Duration::from_millis(120));

    let (tx, rx) = mpsc::channel::<String>();

    if let Some(stdout) = child.stdout.take() {
        let tx_out = tx.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                let _ = tx_out.send(line);
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let tx_err = tx.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                let _ = tx_err.send(line);
            }
        });
    }
    drop(tx);

    let mut last_percent = 0u64;
    loop {
        while let Ok(line) = rx.try_recv() {
            if let Some(percent) = parse_percent(&line) {
                let percent = percent.min(100);
                if percent > last_percent {
                    last_percent = percent;
                    pb.set_position(percent);
                }
            }
        }

        if let Some(status) = child.try_wait().context("failed waiting for 7z process")? {
            while let Ok(line) = rx.try_recv() {
                if let Some(percent) = parse_percent(&line) {
                    let percent = percent.min(100);
                    if percent > last_percent {
                        last_percent = percent;
                        pb.set_position(percent);
                    }
                }
            }

            pb.set_position(100);
            if status.success() {
                pb.finish_and_clear();
                log_progress_done(label);
                return Ok(());
            }

            if tolerate_non_zero {
                pb.finish_and_clear();
                log_progress_done(label);
                return Ok(());
            }

            pb.finish_and_clear();
            log_step_failure(label);
            bail!("{label} failed with status {}", format_exit_status(status));
        }

        std::thread::sleep(Duration::from_millis(80));
    }
}

fn parse_percent(line: &str) -> Option<u64> {
    static PERCENT_RE: OnceLock<Regex> = OnceLock::new();
    let re = PERCENT_RE
        .get_or_init(|| Regex::new(r"(^|[^0-9])(100|[1-9]?[0-9])%").expect("valid regex"));
    re.captures(line)
        .and_then(|caps| caps.get(2))
        .and_then(|m| m.as_str().parse::<u64>().ok())
}

fn check_status(status: ExitStatus, label: &str) -> Result<()> {
    if status.success() {
        Ok(())
    } else {
        bail!("{label} failed with status {}", format_exit_status(status))
    }
}

fn format_exit_status(status: ExitStatus) -> String {
    match status.code() {
        Some(code) => code.to_string(),
        None => "unknown".to_owned(),
    }
}

fn trim_wrapping_quotes(s: &str) -> &str {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn canonicalize_best(path: &Path) -> PathBuf {
    if let Ok(canon) = fs::canonicalize(path) {
        return normalize_windows_path(canon);
    }
    if path.is_absolute() {
        return normalize_windows_path(path.to_path_buf());
    }
    match env::current_dir() {
        Ok(cwd) => normalize_windows_path(cwd.join(path)),
        Err(_) => normalize_windows_path(path.to_path_buf()),
    }
}

fn normalize_windows_path(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let s = path.to_string_lossy();
        if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{}", rest));
        }
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            return PathBuf::from(rest.to_string());
        }
    }
    path
}
#[allow(unused_unsafe)]
fn set_env_var<K: AsRef<OsStr>, V: AsRef<OsStr>>(key: K, value: V) {
    unsafe { env::set_var(key, value) }
}

#[allow(unused_unsafe)]
fn remove_env_var<K: AsRef<OsStr>>(key: K) {
    unsafe { env::remove_var(key) }
}
