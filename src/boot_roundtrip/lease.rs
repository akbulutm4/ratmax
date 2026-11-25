//! Exclusive ownership across complete restore attempts and stopped-job handoff.
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Serialize, Deserialize)]
struct Owner {
    coordinator_pid: u32,
    reference_sha256: String,
    output: std::path::PathBuf,
}
#[derive(Serialize, Deserialize)]
struct Worker {
    pid: u32,
    session: std::path::PathBuf,
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    serde_json::from_slice(&crate::preview::read_file(path, 1_048_576)?).map_err(|e| e.to_string())
}
fn atomic(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let temporary = path.with_extension(format!("{}.new", std::process::id()));
    super::executor::save_json(&temporary, value)?;
    fs::rename(temporary, path).map_err(|e| e.to_string())?;
    fs::File::open(path.parent().ok_or("missing lease directory")?)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}

struct DirectoryGuard(fs::File);
impl Drop for DirectoryGuard {
    fn drop(&mut self) {
        // Explicit unlock also releases transient copies inherited by a process
        // spawned in another thread before its close-on-exec descriptors close.
        let _ = self.0.unlock();
    }
}
fn locked_directory(path: &Path) -> Result<DirectoryGuard, String> {
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    file.try_lock()
        .map_err(|e| format!("lease ownership is busy: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata().map_err(|e| e.to_string())?;
        let named = fs::metadata(path).map_err(|e| e.to_string())?;
        if (opened.dev(), opened.ino()) != (named.dev(), named.ino()) {
            return Err("lease directory changed while acquiring ownership".into());
        }
    }
    Ok(DirectoryGuard(file))
}
pub(crate) fn acquire(
    lock: &Path,
    output: &Path,
    reference: &str,
    recovery: bool,
) -> Result<(), String> {
    let owner = Owner {
        coordinator_pid: std::process::id(),
        reference_sha256: reference.into(),
        output: fs::canonicalize(output).map_err(|e| e.to_string())?,
    };
    match crate::query_session::acquire_lock(lock) {
        Ok(()) => super::executor::save_json(&lock.join("owner.json"), &owner),
        Err(error) if recovery => {
            let _guard = locked_directory(lock)?;
            let current: Owner = read(&lock.join("owner.json"))?;
            if Path::new("/proc")
                .join(current.coordinator_pid.to_string())
                .exists()
            {
                return Err("recovery cannot adopt a live coordinator's lock".into());
            }
            // The directory lock serializes handoff without leaving a claim
            // that could prevent the next stopped-job handoff.
            let result = handoff(lock, output, &owner, |pid| {
                Path::new("/proc").join(pid.to_string()).exists()
            });
            if result.is_ok() && lock.join("recovery-claim").exists() {
                fs::remove_dir(lock.join("recovery-claim")).map_err(|e| e.to_string())?;
            }
            let _ = error;
            result
        }
        Err(error) => Err(error),
    }
}
fn handoff(
    lock: &Path,
    output: &Path,
    new: &Owner,
    alive: impl Fn(u32) -> bool,
) -> Result<(), String> {
    let old: Owner = read(&lock.join("owner.json"))?;
    let worker: Worker = read(&lock.join("worker.json"))?;
    if old.coordinator_pid == 0
        || worker.pid == 0
        || alive(old.coordinator_pid)
        || alive(worker.pid)
        || old.reference_sha256 != new.reference_sha256
        || !worker.session.starts_with(&old.output)
    {
        return Err("recovery lock has a live, unknown or differently bound predecessor".into());
    }
    let path = worker.session.join("session.json");
    let report: serde_json::Value = read(&path)?;
    if report["worker_pid"] != worker.pid
        || report["worker_reaped"] != true
        || (matches!(
            report["mode"].as_str(),
            Some("native_button_cycle" | "native_button_recovery" | "native_preset_cycle")
        ) && report["native"] != true)
        || !matches!(
            report["mode"].as_str(),
            Some(
                "native_prepared_firmware_job"
                    | "native_backup_restore_attempt"
                    | "native_boot_readback_attempt"
                    | "native_pre_record_entry_return"
                    | "native_target_boot_entry"
                    | "native_target_pre_record_return"
                    | "native_button_cycle"
                    | "native_button_recovery"
                    | "native_preset_cycle"
            )
        )
    {
        return Err("recovery requires a recorded reaped firmware/restore worker".into());
    }
    super::executor::save_json(
        &output.join("previous-lock.json"),
        &serde_json::json!({
            "owner":old,"worker":worker,"session_sha256":crate::firmware::sha256(&crate::preview::read_file(&path,1_048_576)?),
            "coordinator_and_worker_absent":true,"progress_reused":false,
        }),
    )?;
    atomic(&lock.join("owner.json"), new)?;
    fs::remove_file(lock.join("worker.json")).map_err(|e| e.to_string())?;
    Ok(())
}
pub(crate) fn worker(lock: &Path, session: &Path, pid: u32) -> Result<(), String> {
    let owner: Owner = read(&lock.join("owner.json"))?;
    if owner.coordinator_pid != std::process::id() {
        return Err("worker lease is owned by another coordinator".into());
    }
    atomic(
        &lock.join("worker.json"),
        &Worker {
            pid,
            session: fs::canonicalize(session).map_err(|e| e.to_string())?,
        },
    )
}

pub(crate) fn stopped_worker(lock: &Path, session: &Path, reference: &str) -> Result<u32, String> {
    let owner: Owner = read(&lock.join("owner.json"))?;
    let worker: Worker = read(&lock.join("worker.json"))?;
    if owner.coordinator_pid == 0
        || worker.pid == 0
        || owner.reference_sha256 != reference
        || worker.session != fs::canonicalize(session).map_err(|e| e.to_string())?
        || !worker.session.starts_with(&owner.output)
        || [owner.coordinator_pid, worker.pid]
            .iter()
            .any(|pid| Path::new("/proc").join(pid.to_string()).exists())
    {
        return Err("restoration requires the recorded coordinator and worker to be absent".into());
    }
    Ok(worker.pid)
}
pub(crate) fn release(lock: &Path) -> Result<(), String> {
    let _guard = locked_directory(lock)?;
    let owner: Owner = read(&lock.join("owner.json"))?;
    if owner.coordinator_pid != std::process::id() {
        return Err("cannot release another coordinator's lease".into());
    }
    if lock.join("worker.json").exists() {
        fs::remove_file(lock.join("worker.json")).map_err(|e| e.to_string())?;
    }
    fs::remove_file(lock.join("owner.json")).map_err(|e| e.to_string())?;
    if lock.join("recovery-claim").exists() {
        fs::remove_dir(lock.join("recovery-claim")).map_err(|e| e.to_string())?;
    }
    fs::remove_dir(lock).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directory_lock_serializes_adoption_and_a_legacy_claim_does_not_block_repeated_handoff() {
        let root = std::env::temp_dir().join(format!("ratmax-lease-repeat-{}", std::process::id()));
        let lock = root.join("lock");
        let previous = root.join("previous");
        let next = root.join("next");
        for path in [&lock, &previous, &next] {
            fs::create_dir_all(path).unwrap();
        }
        for (round, mode) in [
            "native_backup_restore_attempt",
            "native_pre_record_entry_return",
            "native_target_boot_entry",
            "native_target_pre_record_return",
            "native_button_cycle",
            "native_button_recovery",
        ]
        .into_iter()
        .enumerate()
        {
            let destination = next.join(format!("round-{round}"));
            fs::create_dir(&destination).unwrap();
            fs::write(
                lock.join("owner.json"),
                serde_json::to_vec(&Owner {
                    coordinator_pid: u32::MAX - 1,
                    reference_sha256: "reference".into(),
                    output: previous.clone(),
                })
                .unwrap(),
            )
            .unwrap();
            super::super::executor::save_json(
                &lock.join("worker.json"),
                &Worker {
                    pid: u32::MAX - 2,
                    session: previous.clone(),
                },
            )
            .unwrap();
            fs::write(
                previous.join("session.json"),
                serde_json::to_vec(
                    &serde_json::json!({"mode":mode,"native":true,"worker_pid":u32::MAX-2,"worker_reaped":true}),
                )
                .unwrap(),
            )
            .unwrap();
            fs::create_dir(lock.join("recovery-claim")).unwrap();
            if mode.starts_with("native_button_") {
                let path = previous.join("session.json");
                let bytes = fs::read(&path).unwrap();
                let mut fixture: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                fixture["native"] = false.into();
                fs::write(&path, serde_json::to_vec(&fixture).unwrap()).unwrap();
                assert!(acquire(&lock, &destination, "reference", true).is_err());
                fs::write(&path, bytes).unwrap();
            }
            let guard = locked_directory(&lock).unwrap();
            assert!(locked_directory(&lock).is_err());
            assert!(acquire(&lock, &destination, "reference", true).is_err());
            drop(guard);
            acquire(&lock, &destination, "reference", true).unwrap();
            assert!(!lock.join("recovery-claim").exists());
            assert!(!lock.join("worker.json").exists());
        }
        release(&lock).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_never_adopts_a_legacy_lock_or_live_owner() {
        let root = std::env::temp_dir().join(format!("ratmax-lease-live-{}", std::process::id()));
        let lock = root.join("lock");
        let first = root.join("first");
        let next = root.join("next");
        for path in [&lock, &first, &next] {
            fs::create_dir_all(path).unwrap();
        }
        assert!(acquire(&lock, &next, "reference", true).is_err());
        assert!(lock.is_dir());
        assert!(!lock.join("recovery-claim").exists());
        fs::remove_dir(&lock).unwrap();
        acquire(&lock, &first, "reference", false).unwrap();
        assert!(acquire(&lock, &next, "reference", true).is_err());
        assert!(!lock.join("recovery-claim").exists());
        release(&lock).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn handoff_requires_matching_dead_coordinator_and_reaped_worker_and_reuses_no_progress() {
        let root = std::env::temp_dir().join(format!("ratmax-lease-{}", std::process::id()));
        let lock = root.join("lock");
        let previous = root.join("previous");
        let output = root.join("next");
        for path in [&lock, &previous, &output] {
            fs::create_dir_all(path).unwrap();
        }
        let old = Owner {
            coordinator_pid: 111,
            reference_sha256: "reference".into(),
            output: previous.clone(),
        };
        let new = Owner {
            coordinator_pid: std::process::id(),
            reference_sha256: "reference".into(),
            output: output.clone(),
        };
        super::super::executor::save_json(&lock.join("owner.json"), &old).unwrap();
        super::super::executor::save_json(
            &lock.join("worker.json"),
            &Worker {
                pid: 222,
                session: previous.clone(),
            },
        )
        .unwrap();
        super::super::executor::save_json(&previous.join("session.json"),&serde_json::json!({"mode":"native_prepared_firmware_job","worker_pid":222,"worker_reaped":true})).unwrap();
        assert!(handoff(&lock, &output, &new, |_| true).is_err());
        let wrong = Owner {
            coordinator_pid: 333,
            reference_sha256: "other".into(),
            output: output.clone(),
        };
        assert!(handoff(&lock, &output, &wrong, |_| false).is_err());
        let mut report: serde_json::Value = read(&previous.join("session.json")).unwrap();
        report["worker_reaped"] = false.into();
        fs::write(
            previous.join("session.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        assert!(handoff(&lock, &output, &new, |_| false).is_err());
        report["worker_reaped"] = true.into();
        fs::write(
            previous.join("session.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        handoff(&lock, &output, &new, |_| false).unwrap();
        assert!(output.join("previous-lock.json").is_file());
        assert!(!lock.join("worker.json").exists());
        let owner: Owner = read(&lock.join("owner.json")).unwrap();
        assert_eq!(owner.coordinator_pid, std::process::id());
        release(&lock).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
