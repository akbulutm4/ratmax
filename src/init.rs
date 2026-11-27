//! One-step read-only workspace initialization (`ratmax init` and embedded TUI wizard).
//!
//! Reads the user's connected W95 Max (original `0028` or prepared `0034` Core 1–4)
//! twice across distinct request seeds with zero flash writes, zero marker changes,
//! and zero resets, then creates verified `baseline/`, `backup/`, `sessions/`, and
//! `workspace.json`.
#[cfg(any(test, all(target_os = "linux", feature = "linux-query")))]
use crate::{
    access_job::{AccessBaseline, key_frame, read_frame},
    boot_bank,
    firmware::sha256,
    model::Model,
    queries::{NormalQuery, NormalReply, OfflineQueryFrame},
    readback::RuntimeDescriptorReply,
    sensitivity_body::conservative_echo,
    transport::LocalFeatureTransport,
};
#[cfg(all(target_os = "linux", feature = "linux-query"))]
use crate::backup_restore;
use crate::{
    assets::{self, Manifest},
    boot_roundtrip::{self, Mode},
    discovery,
    model::Core,
    query_session::Binding,
    workflow::Workspace,
};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
};
#[cfg(all(target_os = "linux", feature = "linux-query"))]
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub struct DetectedMouse {
    pub mode: Mode,
    pub binding: Binding,
}

impl DetectedMouse {
    pub fn mode_label(&self) -> String {
        match self.mode {
            Mode::Normal => "Original Core 1 (0028)".into(),
            Mode::Target(c) => format!("Core {} (0034)", c.number()),
            Mode::Boot => "Bootloader mode".into(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct InitOptions {
    pub assets: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    pub workspace: Option<PathBuf>,
    pub progress_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
pub struct InitReport {
    pub complete: bool,
    pub mode: Mode,
    pub node: String,
    pub usb_parent: String,
    pub workspace: PathBuf,
    pub baseline: PathBuf,
    pub backup: PathBuf,
    pub assets: PathBuf,
    pub sessions: PathBuf,
    pub backup_sha256: String,
    pub active_bank_sha256: String,
    pub device_writes: usize,
    pub resets: usize,
}

/// Passive sysfs-only detection of a connected W95 Max mouse. Never opens `/dev/hidraw*`.
pub fn detect_mouse() -> Result<Option<DetectedMouse>, String> {
    let report = discovery::collect(Path::new("/sys"))?;
    Ok(boot_roundtrip::detect_connected_mouse(&report)?
        .map(|(mode, binding)| DetectedMouse { mode, binding }))
}

/// Resolve and validate the extracted `BloodyWorkShop8` firmware asset directory.
pub fn resolve_assets(
    explicit: Option<&Path>,
    workspace_path: Option<&Path>,
) -> Result<PathBuf, String> {
    let candidate = if let Some(path) = explicit {
        path.to_path_buf()
    } else if let Some(hint) = workspace_path.and_then(Workspace::read_assets_hint) {
        hint
    } else if let Some(default) = assets::default_asset_root() {
        default
    } else {
        return Err(
            "stock BloodyWorkShop8 firmware assets not found; extract them with `7z` (see `ratmax --help`) or pass --assets PATH"
                .into(),
        );
    };
    let canonical = fs::canonicalize(&candidate)
        .map_err(|e| format!("assets path {}: {e}", candidate.display()))?;
    let manifest = Manifest::embedded().map_err(|e| e.to_string())?;
    for core in Core::ALL {
        manifest
            .inspect_file(&canonical, core)
            .map_err(|e| format!("assets validation failed in {}: {e}", canonical.display()))?;
    }
    Ok(canonical)
}

#[cfg(any(test, all(target_os = "linux", feature = "linux-query")))]
fn write_progress(path: Option<&Path>, text: &str) {
    if let Some(path) = path {
        let _ = fs::write(path, text);
    }
}

#[cfg(any(test, all(target_os = "linux", feature = "linux-query")))]
fn pair(transport: &mut dyn LocalFeatureTransport, frame: &[u8]) -> Result<Vec<u8>, String> {
    transport.set_local(frame).map_err(|e| e.to_string())?;
    let reply = transport.get_local(7, 64).map_err(|e| e.to_string())?;
    if reply.len() != 64 {
        return Err(format!("expected 64-byte reply, got {}", reply.len()));
    }
    Ok(reply)
}

#[cfg(any(test, all(target_os = "linux", feature = "linux-query")))]
fn ensure_gate_closed(transport: &mut dyn LocalFeatureTransport) -> Result<(), String> {
    let probe = read_frame(2, 0xfec0, 8);
    if pair(transport, &probe)? == probe {
        return Ok(());
    }
    transport
        .set_local(&key_frame(0))
        .map_err(|e| e.to_string())?;
    if pair(transport, &probe)? != probe {
        return Err("could not confirm RAM read gate is closed".into());
    }
    Ok(())
}

#[cfg(any(test, all(target_os = "linux", feature = "linux-query")))]
fn read_block(
    transport: &mut dyn LocalFeatureTransport,
    address: u32,
    seed: u8,
) -> Result<[u8; 32], String> {
    let mut frame = read_frame(2, address, 8);
    frame[32..].fill(seed);
    let reply = pair(transport, &frame)?;
    if reply[..32] != frame[..32] {
        return Err(format!(
            "addressed read at 0x{address:08x} altered selector bytes"
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&reply[32..64]);
    Ok(out)
}

#[cfg(any(test, all(target_os = "linux", feature = "linux-query")))]
struct RawPasses {
    banks: [Vec<u8>; 2],
    images: [Vec<u8>; 2],
}

#[cfg(any(test, all(target_os = "linux", feature = "linux-query")))]
#[cfg_attr(not(all(target_os = "linux", feature = "linux-query")), allow(dead_code))]
struct CapturedData {
    baseline: AccessBaseline,
    packed: [Vec<u8>; 2],
    images: [Vec<u8>; 2],
    comparison: boot_bank::Comparison,
    backup_sha256: String,
    active_bank_sha256: String,
}

#[cfg(any(test, all(target_os = "linux", feature = "linux-query")))]
fn capture_readonly(
    detected: &DetectedMouse,
    transport: &mut dyn LocalFeatureTransport,
    progress_file: Option<&Path>,
) -> Result<CapturedData, String> {
    write_progress(progress_file, "Verifying mouse identity & layout…");

    let id_codec = OfflineQueryFrame::new(NormalQuery::Identity, 64).map_err(|e| e.to_string())?;
    let identity = pair(transport, &id_codec.request())?;
    let (version, live_core) = match id_codec.decode(&identity).map_err(|e| e.to_string())? {
        NormalReply::Identity {
            model: Model::W95Max,
            core,
            version_compare_word,
            ..
        } => (version_compare_word, core),
        _ => return Err("unexpected reply to identity query".into()),
    };
    match detected.mode {
        Mode::Normal => {
            if version != 0x28 || live_core != Core::One {
                return Err(format!(
                    "expected 0028 Core 1, device reported version 0x{version:04x} Core {}",
                    live_core.number()
                ));
            }
        }
        Mode::Target(expected_core) => {
            if version != 0x34 || live_core != expected_core {
                return Err(format!(
                    "expected 0034 Core {}, device reported version 0x{version:04x} Core {}",
                    expected_core.number(),
                    live_core.number()
                ));
            }
        }
        Mode::Boot => {
            return Err("mouse is in bootloader mode; reconnect in normal mode first".into());
        }
    }

    let st_codec = OfflineQueryFrame::new(NormalQuery::Status, 64).map_err(|e| e.to_string())?;
    let status = pair(transport, &st_codec.request())?;
    match st_codec.decode(&status).map_err(|e| e.to_string())? {
        NormalReply::Status {
            display_version_word,
            ..
        } if display_version_word == version => {}
        _ => return Err("device status version disagrees with identity version".into()),
    }

    let layout = pair(transport, &crate::readback::descriptor_request())?;
    let bases = RuntimeDescriptorReply::decode(&layout)
        .map_err(|e| e.to_string())?
        .descriptor()
        .bases();
    if (
        bases.sensitivity,
        bases.main_profile,
        bases.additional_profile,
    ) != (0xe000, 0xe200, 0xfe9c)
    {
        return Err("mouse runtime layout bases differ from supported E000/E200/FE9C".into());
    }

    let header_req = read_frame(0x2F, 0xE000, 2);
    let header = pair(transport, &header_req)?;
    conservative_echo(&header_req, &header).map_err(|e| e.to_string())?;
    if header[32..36] != [0xA4; 4] && !(version == 0x34 && header[32..36] == [0xFF; 4]) {
        return Err("unexpected sensitivity header marker at 0xE000".into());
    }

    let sources = vec![
        sha256(&identity),
        sha256(&status),
        sha256(&layout),
        sha256(&header),
    ];
    let baseline = AccessBaseline::new(
        detected.binding.clone(),
        [identity, status, layout, header],
        sources,
    )?;

    ensure_gate_closed(transport)?;
    transport
        .set_local(&key_frame(0x2218_4952))
        .map_err(|e| e.to_string())?;

    let read_result = (|| -> Result<RawPasses, String> {
        let w0 = read_block(transport, 0xfec0, 0xa5)?;
        let w1 = read_block(transport, 0xfec0, 0x5a)?;
        if w0 != w1 {
            return Err("RAM read gate witness echoed or changed between seeds".into());
        }

        let mut banks = [
            Vec::with_capacity(boot_bank::BANK_BYTES),
            Vec::with_capacity(boot_bank::BANK_BYTES),
        ];
        let mut images = [Vec::with_capacity(65536), Vec::with_capacity(65536)];

        for (pass, seed) in [0xa5_u8, 0x5a_u8].into_iter().enumerate() {
            write_progress(
                progress_file,
                &format!("Reading boot bank (pass {}/2)…", pass + 1),
            );
            for block in 0..boot_bank::BANK_BLOCKS {
                let addr = boot_bank::BANK_BASE + (block * 32) as u32;
                banks[pass].extend_from_slice(&read_block(transport, addr, seed)?);
            }
            for block in 0..2048_usize {
                if block % 64 == 0 {
                    let pct = (block * 100) / 2048;
                    write_progress(
                        progress_file,
                        &format!("Reading flash (pass {}/2 · {pct}%)…", pass + 1),
                    );
                }
                let addr = (block * 32) as u32;
                images[pass].extend_from_slice(&read_block(transport, addr, seed)?);
            }
        }
        Ok(RawPasses { banks, images })
    })();

    let close_result = ensure_gate_closed(transport);
    let RawPasses { banks, images } = match (read_result, close_result) {
        (Ok(data), Ok(())) => data,
        (Err(e), Ok(())) => return Err(e),
        (Ok(_), Err(ce)) => {
            return Err(format!("read succeeded but failed to close RAM gate: {ce}"));
        }
        (Err(e), Err(ce)) => return Err(format!("{e} (and failed to close RAM gate: {ce})")),
    };

    write_progress(progress_file, "Verifying two-pass capture…");
    if banks[0] != banks[1] {
        return Err("active boot bank passes disagreed".into());
    }
    if !boot_bank::matches_known_bank(&banks[0]) {
        return Err(format!(
            "active boot bank SHA-256 {} is not a recognized W95 Max bootloader",
            sha256(&banks[0])
        ));
    }
    if images[0] != images[1] || images[0].len() != 65536 {
        return Err("64 KiB internal flash passes disagreed".into());
    }
    if !boot_bank::valid_w95max_identity(&images[0][0xfec0..0xff20]) {
        return Err("captured flash identity block at 0xFEC0..0xFF20 is not a valid W95 Max".into());
    }
    let (embedded_base, embedded_bank) = boot_bank::embedded_bank(&images[0])
        .ok_or_else(|| "captured flash contains no recognized embedded boot bank copy".to_string())?;
    if embedded_bank != banks[0].as_slice() {
        return Err("active boot bank differs from the embedded boot bank copy in flash".into());
    }

    let mut packed = [
        Vec::with_capacity(boot_bank::PASS_BYTES),
        Vec::with_capacity(boot_bank::PASS_BYTES),
    ];
    for pass in 0..2 {
        packed[pass].extend_from_slice(&banks[pass]);
        for &offset in &boot_bank::GAPS {
            let at = embedded_base + offset as usize;
            packed[pass].extend_from_slice(&images[pass][at..at + 32]);
        }
        packed[pass].extend_from_slice(&images[pass][0xfec0..0xff20]);
        packed[pass].extend_from_slice(&images[pass][0xe000..0xe100]);
        packed[pass].extend_from_slice(&images[pass][0xff40..0xff80]);
    }
    if packed[0] != packed[1] {
        return Err("assembled boot-preflight passes disagreed".into());
    }
    let comparison = boot_bank::compare(&packed[0])
        .ok_or_else(|| "boot-preflight comparison failed".to_string())?;
    if !comparison.matches_embedded_copy_and_identity {
        return Err("captured boot bank / identity failed structural verification".into());
    }

    let backup_sha256 = sha256(&images[0]);
    let active_bank_sha256 = sha256(&banks[0]);
    Ok(CapturedData {
        baseline,
        packed,
        images,
        comparison,
        backup_sha256,
        active_bank_sha256,
    })
}

#[cfg(all(target_os = "linux", feature = "linux-query"))]
fn fresh_subdir(root: &Path, base_name: &str) -> Result<PathBuf, String> {
    let plain = root.join(base_name);
    if !plain.exists() {
        fs::create_dir_all(&plain).map_err(|e| format!("create {}: {e}", plain.display()))?;
        return Ok(plain);
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    for suffix in 0..1000_u32 {
        let name = if suffix == 0 {
            format!("{base_name}-{stamp}")
        } else {
            format!("{base_name}-{stamp}-{suffix}")
        };
        let candidate = root.join(name);
        if !candidate.exists() {
            fs::create_dir_all(&candidate)
                .map_err(|e| format!("create {}: {e}", candidate.display()))?;
            return Ok(candidate);
        }
    }
    Err(format!("could not allocate fresh directory under {}", root.display()))
}

#[cfg(all(target_os = "linux", feature = "linux-query"))]
fn chown_to_sudo_user(path: &Path) {
    let (Ok(uid_s), Ok(gid_s)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) else {
        return;
    };
    let (Ok(uid), Ok(gid)) = (uid_s.parse::<u32>(), gid_s.parse::<u32>()) else {
        return;
    };
    let uid = Some(rustix::fs::Uid::from_raw(uid));
    let gid = Some(rustix::fs::Gid::from_raw(gid));
    let _ = rustix::fs::chown(path, uid, gid);
}

#[cfg(all(target_os = "linux", feature = "linux-query"))]
fn save_with_owner(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
    chown_to_sudo_user(path);
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "linux-query"))]
fn persist_workspace(
    detected: &DetectedMouse,
    captured: CapturedData,
    assets_dir: PathBuf,
    data_dir: &Path,
    workspace_path: &Path,
    progress_file: Option<&Path>,
) -> Result<InitReport, String> {
    write_progress(progress_file, "Saving verified baseline & backup…");
    fs::create_dir_all(data_dir).map_err(|e| format!("create {}: {e}", data_dir.display()))?;
    chown_to_sudo_user(data_dir);

    let baseline_dir = fresh_subdir(data_dir, "baseline")?;
    chown_to_sudo_user(&baseline_dir);
    let backup_dir = fresh_subdir(data_dir, "backup")?;
    chown_to_sudo_user(&backup_dir);
    let sessions_dir = data_dir.join("sessions");
    fs::create_dir_all(&sessions_dir)
        .map_err(|e| format!("create {}: {e}", sessions_dir.display()))?;
    chown_to_sudo_user(&sessions_dir);

    save_with_owner(
        &baseline_dir.join("boot-preflight.pass0.candidate.bin"),
        &captured.packed[0],
    )?;
    save_with_owner(
        &baseline_dir.join("boot-preflight.pass1.candidate.bin"),
        &captured.packed[1],
    )?;
    let baseline_session = serde_json::json!({
        "schema": 1,
        "mode": "native_init_boot_bank",
        "scope": "boot_bank",
        "baseline": captured.baseline,
        "boot_preflight": {
            "comparison": captured.comparison,
        },
        "result": {
            "complete": true,
            "release_lock_allowed": true,
            "two_seed_boot_preflight_match": true,
        },
        "worker_stop": {
            "reaped": true,
            "exit_success": true,
        },
    });
    save_with_owner(
        &baseline_dir.join("session.json"),
        &serde_json::to_vec_pretty(&baseline_session).map_err(|e| e.to_string())?,
    )?;

    save_with_owner(
        &backup_dir.join("normal-image.pass0.bin"),
        &captured.images[0],
    )?;
    save_with_owner(
        &backup_dir.join("normal-image.pass1.bin"),
        &captured.images[1],
    )?;
    let backup_session = serde_json::json!({
        "schema": 1,
        "mode": "native_normal_firmware_backup",
        "worker_reaped": true,
        "worker_state_agreed": true,
        "result": {
            "complete": true,
            "release_lock_allowed": true,
            "gate_dirty": false,
            "uncertain": false,
            "marker_program_intents": 0,
            "reset_intents": 0,
            "backup": {
                "bytes": 65536,
                "sha256": captured.backup_sha256,
                "passes_equal": true,
                "matches_fresh_identity_settings_and_embedded_bank": true,
            },
        },
    });
    save_with_owner(
        &backup_dir.join("session.json"),
        &serde_json::to_vec_pretty(&backup_session).map_err(|e| e.to_string())?,
    )?;

    // Self-verify both persisted sessions using the real loaders before updating workspace.json.
    boot_roundtrip::load(&baseline_dir)?;
    backup_restore::Plan::load(&backup_dir)?;

    if let Some(parent) = workspace_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        chown_to_sudo_user(parent);
    }
    let workspace = Workspace {
        schema: 1,
        baseline: fs::canonicalize(&baseline_dir).unwrap_or(baseline_dir.clone()),
        backup: fs::canonicalize(&backup_dir).unwrap_or(backup_dir.clone()),
        assets: assets_dir.clone(),
        sessions: fs::canonicalize(&sessions_dir).unwrap_or(sessions_dir.clone()),
    };
    let ws_bytes = serde_json::to_vec_pretty(&workspace).map_err(|e| e.to_string())?;
    let tmp = workspace_path.with_extension("json.tmp");
    save_with_owner(&tmp, &ws_bytes)?;
    fs::rename(&tmp, workspace_path)
        .map_err(|e| format!("rename {}: {e}", workspace_path.display()))?;
    chown_to_sudo_user(workspace_path);

    // Final end-to-end validation through Workspace::load.
    let loaded = Workspace::load(workspace_path)?;
    write_progress(progress_file, "Done.");

    Ok(InitReport {
        complete: true,
        mode: detected.mode,
        node: detected.binding.device_path(),
        usb_parent: detected.binding.usb_parent.clone(),
        workspace: workspace_path.to_path_buf(),
        baseline: loaded.baseline,
        backup: loaded.backup,
        assets: loaded.assets,
        sessions: loaded.sessions,
        backup_sha256: captured.backup_sha256,
        active_bank_sha256: captured.active_bank_sha256,
        device_writes: 0,
        resets: 0,
    })
}

/// Run the live read-only initialization against the connected W95 Max mouse.
pub fn run(options: &InitOptions) -> Result<InitReport, String> {
    #[cfg(all(target_os = "linux", feature = "linux-query"))]
    {
        write_progress(options.progress_file.as_deref(), "Detecting mouse…");
        let workspace_path = options
            .workspace
            .clone()
            .unwrap_or_else(Workspace::preferred_config_path);
        let data_dir = options
            .data_dir
            .clone()
            .unwrap_or_else(Workspace::preferred_data_dir);
        let assets_dir = resolve_assets(options.assets.as_deref(), Some(&workspace_path))?;
        let detected = detect_mouse()?
            .ok_or_else(|| "no supported Bloody W95 Max mouse detected on USB".to_string())?;
        write_progress(
            options.progress_file.as_deref(),
            &format!("Opening {}…", detected.binding.device_path()),
        );
        let mut device = crate::query_session::open_init_device(&detected.binding)?;
        let captured = capture_readonly(
            &detected,
            device.as_mut(),
            options.progress_file.as_deref(),
        )?;
        persist_workspace(
            &detected,
            captured,
            assets_dir,
            &data_dir,
            &workspace_path,
            options.progress_file.as_deref(),
        )
    }
    #[cfg(not(all(target_os = "linux", feature = "linux-query")))]
    {
        let _ = options;
        Err("live mouse initialization requires Linux with the linux-query feature".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TransportError;

    struct MockMouse {
        image: Vec<u8>,
        bank: Vec<u8>,
        core: Core,
        version: u16,
        gate_open: bool,
        last_reply: Vec<u8>,
        closed_after: bool,
    }

    impl MockMouse {
        fn new(core: Core, version: u16, bank: Vec<u8>, copy_base: usize) -> Self {
            let mut image = vec![0xff_u8; 65536];
            image[copy_base..copy_base + boot_bank::BANK_BYTES].copy_from_slice(&bank);
            // Valid W95 Max identity block at 0xFEC0..0xFF20
            image[0xfec4..0xfec6].copy_from_slice(&version.to_le_bytes());
            let packed = 0x0578_u16 | u16::from(core.firmware_index().get());
            image[0xfec6..0xfec8].copy_from_slice(&packed.to_le_bytes());
            image[0xfee0..0xfee4].copy_from_slice(&0x09da_712f_u32.to_le_bytes());
            image[0xfee8..0xfeea].copy_from_slice(&packed.to_le_bytes());
            image[0xfefc..0xff00].copy_from_slice(&[0xa4; 4]);
            image[0xff06..0xff08].copy_from_slice(&packed.to_le_bytes());
            // Valid sensitivity block header
            image[0xe000..0xe004].copy_from_slice(&[0xa4; 4]);
            Self {
                image,
                bank,
                core,
                version,
                gate_open: false,
                last_reply: vec![0; 64],
                closed_after: false,
            }
        }
    }

    impl LocalFeatureTransport for MockMouse {
        fn set_local(&mut self, frame: &[u8]) -> Result<(), TransportError> {
            let mut reply = frame.to_vec();
            match frame[1] {
                0x1f => {
                    let packed = 0x0578_u16 | u16::from(self.core.firmware_index().get());
                    reply[10..12].copy_from_slice(&packed.to_le_bytes());
                    reply[12..14].copy_from_slice(&self.version.to_le_bytes());
                }
                0x2d => {
                    reply[8..12].copy_from_slice(&0x0000_0001_u32.to_le_bytes());
                    reply[12..14].copy_from_slice(&self.version.to_le_bytes());
                }
                0x05 => {
                    reply[12..14].copy_from_slice(&0xE000_u16.to_le_bytes());
                    reply[14..16].copy_from_slice(&0xE200_u16.to_le_bytes());
                    reply[16..18].copy_from_slice(&0xFE9C_u16.to_le_bytes());
                    reply[18] = 0;
                    reply[19] = 0;
                }
                0x2f => {
                    let addr = u32::from_le_bytes(frame[28..32].try_into().unwrap()) as usize;
                    let words = usize::from(frame[24]);
                    reply[32..32 + words * 4].copy_from_slice(&self.image[addr..addr + words * 4]);
                }
                0x25 => {
                    let key = u32::from_le_bytes(frame[8..12].try_into().unwrap());
                    self.gate_open = key == 0x2218_4952;
                    if !self.gate_open {
                        self.closed_after = true;
                    }
                }
                0x02 if self.gate_open => {
                    let addr = u32::from_le_bytes(frame[28..32].try_into().unwrap());
                    if addr >= boot_bank::BANK_BASE {
                        let off = (addr - boot_bank::BANK_BASE) as usize;
                        reply[32..64].copy_from_slice(&self.bank[off..off + 32]);
                    } else {
                        let off = addr as usize;
                        reply[32..64].copy_from_slice(&self.image[off..off + 32]);
                    }
                }
                _ => {}
            }
            self.last_reply = reply;
            Ok(())
        }

        fn get_local(&mut self, _report_id: u8, _length: usize) -> Result<Vec<u8>, TransportError> {
            Ok(self.last_reply.clone())
        }
    }

    #[test]
    fn mock_capture_closes_gate_and_rejects_unrecognized_bank() {
        let mut mouse = MockMouse::new(Core::Three, 0x34, vec![0x55; boot_bank::BANK_BYTES], 0x46cc);
        let binding = Binding {
            node: "hidraw3".into(),
            hid_sysfs_path: "/sys/devices/pci0000:00/usb1/1-5/1-5:1.2/0003:09DA:712F.0004".into(),
            usb_parent: "/sys/devices/pci0000:00/usb1/1-5".into(),
            usb_interface_path: "/sys/devices/pci0000:00/usb1/1-5/1-5:1.2".into(),
            usb_bus_number: 1,
            usb_device_number: 3,
            usb_interface_number: 2,
            usb_release_bcd: 0x34,
            vendor_id: 0x09da,
            product_id: 0x712f,
            manufacturer: "A4TECH".into(),
            product: "Bloody W95 Max".into(),
            serial: None,
            hid_phys: Some("usb-1-5/input2".into()),
            hid_unique: Some(String::new()),
            major_minor: "243:3".into(),
            feature_07_total_bytes: 64,
            descriptor_bytes: 180,
            descriptor_sha256:
                "a4fc70e1648716690a8989efb837f907447bc0ced5e68e906a53615fb7890d24".into(),
        };
        let detected = DetectedMouse {
            mode: Mode::Target(Core::Three),
            binding,
        };
        let err = match capture_readonly(&detected, &mut mouse, None) {
            Ok(_) => panic!("synthetic bank should fail known-bank digest check"),
            Err(e) => e,
        };
        // Even on failure, the RAM read gate MUST be closed before returning!
        assert!(mouse.closed_after);
        assert!(!mouse.gate_open);
        assert!(
            err.contains("not a recognized W95 Max bootloader"),
            "unexpected error: {err}"
        );
    }
}
