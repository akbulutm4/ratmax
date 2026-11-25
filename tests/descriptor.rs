use ratmax::descriptor::{self, ReportKind};

fn bytes(hex: &str) -> Vec<u8> {
    hex.split_whitespace()
        .map(|value| u8::from_str_radix(value, 16).unwrap())
        .collect()
}

#[test]
fn kernel_documentation_mouse_example_has_four_unnumbered_input_bytes() {
    // Linux HID introduction's independent 52-byte descriptor example.
    let descriptor = bytes(
        "05 01 09 02 a1 01 09 01 a1 00 05 09 19 01 29 03 15 00 25 01 75 01 95 03 81 02 75 05 95 01 81 01 05 01 09 30 09 31 09 38 15 81 25 7f 75 08 95 03 81 06 c0 c0",
    );
    let result = descriptor::inspect(&descriptor).unwrap();
    assert_eq!(result.application_collections[0].usage.page, 1);
    assert_eq!(result.application_collections[0].usage.id, 2);
    assert_eq!(result.reports.len(), 1);
    assert_eq!(result.reports[0].kind, ReportKind::Input);
    assert_eq!(result.reports[0].bits, 32);
    assert_eq!(result.reports[0].report_id, 0);
    assert_eq!(result.reports[0].total_report_bytes, 4);
    assert!(result.feature_report(7).is_none());
}

#[test]
fn standard_boot_keyboard_geometry_separates_input_and_led_output_padding() {
    let descriptor = bytes(
        "05 01 09 06 a1 01 05 07 19 e0 29 e7 15 00 25 01 75 01 95 08 81 02 95 01 75 08 81 01 95 05 75 01 05 08 19 01 29 05 91 02 95 01 75 03 91 01 95 06 75 08 15 00 25 65 05 07 19 00 29 65 81 00 c0",
    );
    let result = descriptor::inspect(&descriptor).unwrap();
    assert_eq!(result.reports.len(), 2);
    let input = result
        .reports
        .iter()
        .find(|report| report.kind == ReportKind::Input)
        .unwrap();
    let output = result
        .reports
        .iter()
        .find(|report| report.kind == ReportKind::Output)
        .unwrap();
    assert_eq!((input.bits, input.total_report_bytes), (64, 8));
    assert_eq!((output.bits, output.total_report_bytes), (8, 1));
}

#[test]
fn numbered_feature_counts_payload_and_id_once_and_keeps_other_report_types_separate() {
    let result = descriptor::inspect(&bytes(
        "06 00 ff 09 01 a1 01 85 07 75 08 95 3f b1 02 95 02 81 02 95 03 91 02 c0",
    ))
    .unwrap();
    let feature = result.feature_report(7).unwrap();
    assert_eq!(
        (feature.bits, feature.data_bytes, feature.total_report_bytes),
        (504, 63, 64)
    );
    assert_eq!(feature.application_collections, [0]);
    assert_eq!(
        result
            .reports
            .iter()
            .find(|report| report.kind == ReportKind::Input)
            .unwrap()
            .total_report_bytes,
        3
    );
    assert_eq!(
        result
            .reports
            .iter()
            .find(|report| report.kind == ReportKind::Output)
            .unwrap()
            .total_report_bytes,
        4
    );
}

#[test]
fn global_push_pop_restores_geometry_id_and_usage_page_and_counts_constants() {
    let result = descriptor::inspect(&bytes(
        "06 00 ff 09 01 a1 01 85 07 75 03 95 01 b1 01 a4 85 08 75 08 95 02 b1 02 b4 b1 01 c0",
    ))
    .unwrap();
    assert_eq!(result.feature_report(7).unwrap().bits, 6);
    assert_eq!(result.feature_report(7).unwrap().total_report_bytes, 2);
    assert_eq!(result.feature_report(8).unwrap().bits, 16);
    assert_eq!(result.feature_report(8).unwrap().total_report_bytes, 3);
    let page = descriptor::inspect(&bytes(
        "06 00 ff a4 05 01 b4 09 01 a1 01 85 07 75 08 95 01 b1 02 c0",
    ))
    .unwrap();
    assert_eq!(page.application_collections[0].usage.page, 0xFF00);
}

#[test]
fn shared_id_across_applications_is_aggregated_and_association_remains_explicit() {
    let result = descriptor::inspect(&bytes(
        "06 00 ff 09 01 a1 01 85 07 75 08 95 01 b1 02 c0 06 01 ff 09 02 a1 01 75 04 b1 01 c0",
    ))
    .unwrap();
    let feature = result.feature_report(7).unwrap();
    assert_eq!(feature.bits, 12);
    assert_eq!(feature.total_report_bytes, 3);
    assert_eq!(feature.application_collections, [0, 1]);
}

#[test]
fn extended_usage_and_ranges_are_parsed_without_expanding_unbounded_lists() {
    let result =
        descriptor::inspect(&bytes("0b 01 00 00 ff a1 01 85 07 75 08 95 01 b1 02 c0")).unwrap();
    assert_eq!(result.application_collections[0].usage.page, 0xFF00);
    assert_eq!(result.application_collections[0].usage.id, 1);
    assert!(descriptor::inspect(&bytes("05 01 19 02 29 01 a1 01")).is_err());
    assert!(descriptor::inspect(&bytes("05 01 19 01 a1 01")).is_err());
}

#[test]
fn malformed_unsupported_and_excessive_descriptors_fail_closed() {
    for hex in [
        "",
        "06 00",
        "fe 00 00",
        "0c",
        "c0",
        "b4",
        "a4",
        "05 01 09 02 a1 01",                            // unclosed collection
        "05 01 09 02 a1 01 85 00 75 08 95 01 b1 02 c0", // reserved ID
        "05 01 09 02 a1 01 75 08 b1 02 c0",             // no count
        "05 01 09 02 a1 01 77 ff ff ff ff 97 ff ff ff ff b1 02 c0", // overflow
        "05 01 09 02 a1 01 75 08 95 01 b1 02 85 07 b1 02 c0", // mixed IDs
        "05 01 09 02 a1 01 a9 01 75 08 95 01 b1 02 c0", // delimiter
        "75 08 95 01 b1 02",                            // no Application collection
        "05 01 09 02 a1 01 75 08 95 01 b1 02 c0 a1 01", // stale usage must not leak
    ] {
        assert!(descriptor::inspect(&bytes(hex)).is_err(), "{hex}");
    }
    assert!(descriptor::inspect(&vec![0; descriptor::MAX_DESCRIPTOR_BYTES + 1]).is_err());
    let mut excessive = bytes("05 01 09 02 a1 01");
    for _ in 0..40 {
        excessive.extend_from_slice(&[0x09, 1, 0xA1, 0]);
    }
    assert!(descriptor::inspect(&excessive).is_err());
}
