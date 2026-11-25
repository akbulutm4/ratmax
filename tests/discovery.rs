#![cfg(unix)]

use ratmax::discovery;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

const VENDOR_DESCRIPTOR: &[u8] = &[
    0x06, 0x00, 0xFF, 0x09, 0x01, 0xA1, 0x01, 0x85, 0x07, 0x75, 0x08, 0x95, 0x3F, 0xB1, 0x02, 0xC0,
];

struct Fixture {
    base: PathBuf,
    root: PathBuf,
    usb: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "ratmax-p1-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&base).unwrap();
        let root = base.join("sys");
        let usb = root.join("devices/pci0000/usb1/1-2");
        fs::create_dir_all(&usb).unwrap();
        fs::create_dir_all(root.join("class/hidraw")).unwrap();
        for (name, value) in [
            ("idVendor", "09da\n"),
            ("idProduct", "1234\n"),
            ("manufacturer", "COMPANY \n"),
            ("product", "W95Max      \n"),
            ("serial", "\n"),
            ("bcdDevice", "0100\n"),
            ("busnum", "1\n"),
            ("devnum", "3\n"),
        ] {
            fs::write(usb.join(name), value).unwrap();
        }
        Self { base, root, usb }
    }

    fn add(&self, index: u8, descriptor: &[u8]) -> PathBuf {
        let interface = self.usb.join(format!("1-2:1.{index}"));
        let hid = interface.join(format!("0003:09DA:1234.{index:04}"));
        let node = hid.join(format!("hidraw/hidraw{index}"));
        fs::create_dir_all(&node).unwrap();
        fs::write(interface.join("bInterfaceNumber"), format!("{index:02x}\n")).unwrap();
        fs::write(hid.join("uevent"), "HID_ID=0003:000009DA:00001234\nHID_NAME=fixture mouse\nHID_PHYS=fixture/input0\nHID_UNIQ=\n").unwrap();
        fs::write(hid.join("report_descriptor"), descriptor).unwrap();
        fs::write(node.join("dev"), format!("240:{index}\n")).unwrap();
        std::os::unix::fs::symlink(&hid, node.join("device")).unwrap();
        std::os::unix::fs::symlink(&node, self.root.join(format!("class/hidraw/hidraw{index}")))
            .unwrap();
        hid
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[test]
fn cached_candidate_has_advertised_geometry_and_preserves_strings_without_device_access() {
    let fixture = Fixture::new();
    fixture.add(0, VENDOR_DESCRIPTOR);
    let report = discovery::collect(&fixture.root).unwrap();
    assert!(report.complete());
    assert_eq!(report.matching_interfaces.len(), 1);
    let interface = &report.matching_interfaces[0];
    assert_eq!(interface.feature_07_total_bytes, Some(64));
    assert_eq!(interface.manufacturer.as_deref(), Some("COMPANY "));
    assert_eq!(interface.product.as_deref(), Some("W95Max      "));
    assert_eq!(interface.serial.as_deref(), Some(""));
    assert_eq!(interface.usb_interface_number, Some(0));
    assert_eq!(interface.usb_release_bcd, Some(0x100));
    assert_eq!(
        interface.usb_parent.as_deref(),
        Some(fixture.usb.to_str().unwrap())
    );
    assert!(interface.candidate_for_later_query);
    assert!(!interface.model_confirmed);
    assert_eq!(report.unique_query_candidate.as_deref(), Some("hidraw0"));
    assert_eq!(report.hidraw_handles_opened, 0);
    assert_eq!(report.device_reports_sent, 0);
    assert!(!report.live_queries_enabled);
    assert!(
        report
            .cached_file_open_attempts
            .iter()
            .all(|path| PathBuf::from(path).starts_with(fixture.root.join("devices")))
    );
}

#[test]
fn unrelated_vid_is_filtered_before_descriptor_or_usb_parent_reads() {
    let fixture = Fixture::new();
    let hid = fixture.add(0, VENDOR_DESCRIPTOR);
    fs::write(hid.join("uevent"), "HID_ID=0003:0000046D:00001234\n").unwrap();
    fs::remove_file(hid.join("report_descriptor")).unwrap();
    let report = discovery::collect(&fixture.root).unwrap();
    assert!(report.complete());
    assert_eq!(report.filtered_out_entries, 1);
    assert!(report.matching_interfaces.is_empty());
    assert_eq!(report.cached_file_open_attempts.len(), 1);
    assert!(report.cached_file_open_attempts[0].ends_with("uevent"));
}

#[test]
fn multiple_candidates_are_retained_without_choosing_the_first() {
    let fixture = Fixture::new();
    fixture.add(0, VENDOR_DESCRIPTOR);
    fixture.add(1, VENDOR_DESCRIPTOR);
    let report = discovery::collect(&fixture.root).unwrap();
    assert!(report.complete());
    assert!(report.unique_query_candidate.is_none());
    assert_eq!(report.ambiguous_query_candidates, ["hidraw0", "hidraw1"]);
    assert_eq!(
        report.matching_interfaces[0].usb_parent,
        report.matching_interfaces[1].usb_parent
    );
}

#[test]
fn boot_strings_standard_usages_and_wrong_geometry_block_query_eligibility() {
    let fixture = Fixture::new();
    fixture.add(0, VENDOR_DESCRIPTOR);
    fs::write(fixture.usb.join("manufacturer"), "A4 BOOT \n").unwrap();
    assert!(
        !discovery::collect(&fixture.root)
            .unwrap()
            .matching_interfaces[0]
            .candidate_for_later_query
    );
    fs::write(fixture.usb.join("manufacturer"), "COMPANY \n").unwrap();
    let standard = [
        0x05, 1, 0x09, 2, 0xA1, 1, 0x85, 7, 0x75, 8, 0x95, 63, 0xB1, 2, 0xC0,
    ];
    fixture.add(1, &standard);
    let short = [
        0x06, 0, 0xFF, 0x09, 1, 0xA1, 1, 0x85, 7, 0x75, 8, 0x95, 1, 0xB1, 2, 0xC0,
    ];
    fixture.add(2, &short);
    let report = discovery::collect(&fixture.root).unwrap();
    assert!(report.matching_interfaces[0].candidate_for_later_query);
    assert!(!report.matching_interfaces[1].candidate_for_later_query);
    assert!(!report.matching_interfaces[2].candidate_for_later_query);
    assert_eq!(report.unique_query_candidate.as_deref(), Some("hidraw0"));
}

#[test]
fn descriptor_parse_errors_keep_raw_bytes_and_never_report_query_readiness() {
    let fixture = Fixture::new();
    fixture.add(0, &[0xFE, 0, 0]);
    let report = discovery::collect(&fixture.root).unwrap();
    assert!(report.collection_complete);
    assert!(!report.descriptor_analysis_complete);
    assert!(!report.complete());
    let interface = &report.matching_interfaces[0];
    assert!(!interface.candidate_for_later_query);
    let descriptor = interface.descriptor.as_ref().unwrap();
    assert_eq!(descriptor.hex, "fe0000");
    assert!(descriptor.parse_error.is_some());
}

#[test]
fn missing_duplicate_oversized_or_mismatched_metadata_is_not_silently_empty_success() {
    let fixture = Fixture::new();
    let hid = fixture.add(0, VENDOR_DESCRIPTOR);
    fs::write(
        hid.join("uevent"),
        "HID_ID=0003:09DA:1234\nHID_ID=0003:09DA:1234\n",
    )
    .unwrap();
    let duplicate = discovery::collect(&fixture.root).unwrap();
    assert!(!duplicate.complete());
    assert!(!duplicate.errors.is_empty());
    fs::remove_file(hid.join("uevent")).unwrap();
    assert!(
        !discovery::collect(&fixture.root)
            .unwrap()
            .collection_complete
    );
    fs::write(hid.join("uevent"), vec![b'x'; 8193]).unwrap();
    assert!(
        !discovery::collect(&fixture.root)
            .unwrap()
            .collection_complete
    );
    fs::write(hid.join("uevent"), "HID_ID=0003:09DA:1234\n").unwrap();
    fs::write(fixture.usb.join("idProduct"), "5678\n").unwrap();
    let mismatch = discovery::collect(&fixture.root).unwrap();
    assert!(!mismatch.collection_complete);
    assert!(!mismatch.matching_interfaces[0].candidate_for_later_query);
    assert!(mismatch.unique_query_candidate.is_none());
}

#[test]
fn escaped_attribute_and_nonregular_descriptor_are_never_opened() {
    let fixture = Fixture::new();
    let hid = fixture.add(0, VENDOR_DESCRIPTOR);
    fs::remove_file(hid.join("report_descriptor")).unwrap();
    let outside = fixture.base.join("outside");
    fs::write(&outside, VENDOR_DESCRIPTOR).unwrap();
    std::os::unix::fs::symlink(&outside, hid.join("report_descriptor")).unwrap();
    let report = discovery::collect(&fixture.root).unwrap();
    assert!(!report.collection_complete);
    assert!(
        !report
            .cached_file_open_attempts
            .iter()
            .any(|path| path == outside.to_str().unwrap())
    );
    fs::remove_file(hid.join("report_descriptor")).unwrap();
    fs::create_dir(hid.join("report_descriptor")).unwrap();
    let report = discovery::collect(&fixture.root).unwrap();
    assert!(!report.collection_complete);
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.detail.contains("not a regular"))
    );
}

#[test]
fn snapshot_export_is_new_host_directory_with_exact_raw_descriptor_and_refuses_sysfs() {
    let fixture = Fixture::new();
    fixture.add(0, VENDOR_DESCRIPTOR);
    let report = discovery::collect(&fixture.root).unwrap();
    let output = fixture.base.join("snapshot");
    report.save(&output).unwrap();
    assert_eq!(
        fs::read(output.join("hidraw0.report_descriptor.bin")).unwrap(),
        VENDOR_DESCRIPTOR
    );
    assert!(output.join("discovery.json").is_file());
    assert!(report.save(&output).is_err());
    let forbidden = fixture.root.join("snapshot");
    assert!(report.save(&forbidden).is_err());
    assert!(!forbidden.exists());
}

#[test]
fn cli_passive_discovery_uses_fixture_root_and_returns_nonzero_for_incomplete_analysis() {
    let fixture = Fixture::new();
    let hid = fixture.add(0, VENDOR_DESCRIPTOR);
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_ratmax"))
            .arg("discover-passive")
            .arg("--sysfs-root")
            .arg(&fixture.root)
            .arg("--json")
            .output()
            .unwrap()
    };
    let good = run();
    assert!(good.status.success());
    let json: serde_json::Value = serde_json::from_slice(&good.stdout).unwrap();
    assert_eq!(json["mode"], "passive_cached_metadata");
    assert_eq!(json["matching_interfaces"][0]["feature_07_total_bytes"], 64);
    assert_eq!(json["hidraw_handles_opened"], 0);
    fs::write(hid.join("report_descriptor"), [0xFE, 0, 0]).unwrap();
    let partial = run();
    assert_eq!(partial.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&partial.stdout).unwrap();
    assert_eq!(json["descriptor_analysis_complete"], false);
}
