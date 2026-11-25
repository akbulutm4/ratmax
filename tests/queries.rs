use ratmax::{
    model::{Core, Model},
    protocol::ProtocolError,
    queries::{self, NormalQuery, NormalReply, OfflineQueryFrame, QueryError},
};

#[test]
fn only_two_exact_query_headers_are_allowed_and_no_write_flag_is_exposed() {
    for opcode in 0..=255_u8 {
        let header = [7, opcode, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            NormalQuery::from_header(&header).is_ok(),
            matches!(opcode, 0x1F | 0x2D)
        );
    }
    for query in NormalQuery::ALL {
        for offset in 0..8 {
            let mut changed = query.header();
            changed[offset] ^= 1;
            assert!(
                NormalQuery::from_header(&changed).is_err(),
                "header byte {offset}"
            );
        }
        for length in [32, 64, 72] {
            let frame = OfflineQueryFrame::new(query, length).unwrap();
            let request = frame.request();
            assert_eq!(request.len(), length);
            assert_eq!(&request[..8], &query.header());
            assert!(request[2..].iter().all(|byte| *byte == 0));
        }
    }
}

#[test]
fn framing_checks_are_explicit_hypothetical_geometry_not_a_device_length_guess() {
    for (query, minimum) in [(NormalQuery::Identity, 18), (NormalQuery::Status, 32)] {
        assert!(OfflineQueryFrame::new(query, minimum).is_ok());
        assert!(OfflineQueryFrame::new(query, 72).is_ok());
        for length in [0, 7, minimum - 1, 73, usize::MAX] {
            assert!(matches!(
                OfflineQueryFrame::new(query, length),
                Err(QueryError::FrameLength { .. })
            ));
        }
        let frame = OfflineQueryFrame::new(query, 64).unwrap();
        for length in [0, 7, minimum, 63, 65, 72] {
            let mut reply = frame.request();
            reply.resize(length, 0);
            assert!(matches!(
                frame.decode(&reply),
                Err(QueryError::Protocol {
                    error: ProtocolError::Length { .. }
                })
            ));
        }
    }
}

#[test]
fn echoed_header_is_validated_before_any_reply_fields_are_used() {
    for query in NormalQuery::ALL {
        let frame = OfflineQueryFrame::new(query, 64).unwrap();
        for offset in 0..8 {
            let mut reply = frame.request();
            reply[offset] ^= 1;
            assert!(
                matches!(frame.decode(&reply), Err(QueryError::Protocol { error: ProtocolError::Header { offset: actual, .. } }) if actual == offset)
            );
        }
    }
}

#[test]
fn identity_decodes_little_endian_model_core_and_raw_version_and_preserves_payload() {
    let frame = OfflineQueryFrame::new(NormalQuery::Identity, 64).unwrap();
    for (index, core) in [
        (0_u16, Core::Four),
        (1, Core::One),
        (2, Core::Two),
        (3, Core::Three),
    ] {
        let mut reply = frame.request();
        reply[8..18].copy_from_slice(&[0x11, 0x22, 0, 0, 0x34, 0x12, 0xA5, 0xB6, 0xC7, 0xD8]);
        reply[10..12].copy_from_slice(&(0x578 | index).to_le_bytes());
        match frame.decode(&reply).unwrap() {
            NormalReply::Identity {
                model,
                core: found,
                packed_model_core,
                version_compare_word,
                raw_payload,
            } => {
                assert_eq!(model, Model::W95Max);
                assert_eq!(found, core);
                assert_eq!(packed_model_core, 0x578 | index);
                assert_eq!(version_compare_word, 0x1234);
                assert_eq!(&raw_payload, &reply[8..18]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    let mut reply = frame.request();
    reply[10..12].copy_from_slice(&0x57C_u16.to_le_bytes());
    assert!(matches!(
        frame.decode(&reply),
        Err(QueryError::UnsupportedModel { model_id: 0x57C })
    ));
}

#[test]
fn status_checks_state_high_byte_and_keeps_display_word_separate_from_identity_version() {
    let frame = OfflineQueryFrame::new(NormalQuery::Status, 72).unwrap();
    for state in [0_u32, 0x00FF_FFFF, 0x0102_0304, 0x01FF_FFFF] {
        let mut reply = frame.request();
        reply[8..12].copy_from_slice(&state.to_le_bytes());
        reply[12..14].copy_from_slice(&[0x78, 0x56]);
        reply[14..32].fill(0xA5);
        match frame.decode(&reply).unwrap() {
            NormalReply::Status {
                state_dword,
                state_high_byte,
                display_version_word,
                raw_payload,
            } => {
                assert_eq!(state_dword, state);
                assert_eq!(state_high_byte, (state >> 24) as u8);
                assert_eq!(display_version_word, 0x5678);
                assert_eq!(&raw_payload, &reply[8..32]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    for high_byte in [2_u8, 127, 255] {
        let mut reply = frame.request();
        reply[11] = high_byte;
        assert!(
            matches!(frame.decode(&reply), Err(QueryError::RejectedState { high_byte: actual }) if actual == high_byte)
        );
    }
}

#[test]
fn query_audit_is_explicitly_offline_and_advertises_only_identity_and_status() {
    let policy = serde_json::to_value(queries::audit()).unwrap();
    assert_eq!(policy["mode"], "offline_query_audit");
    assert_eq!(policy["live_queries_enabled"], false);
    assert_eq!(policy["device_enumerated"], false);
    assert!(policy["actual_feature_report_length"].is_null());
    let list = policy["normal_query_allowlist"].as_array().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0]["opcode"], 0x1F);
    assert_eq!(list[1]["opcode"], 0x2D);
}
