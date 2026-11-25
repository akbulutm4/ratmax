use ratmax::protocol::{
    DeviceValue, FinalBlock, GENERIC_LOCAL_LEN, ProtocolError, Query, check_local_record_ack,
    reset_local_request,
};

#[test]
fn query_and_reset_layouts_match_zero_argument_generic_helper_calls() {
    for (query, opcode, count) in [(Query::DeviceValue, 0x29, 8), (Query::FinalBlock, 0x2B, 28)] {
        let buffer = query.local_request();
        assert_eq!(buffer.len(), 72);
        assert_eq!(&buffer[..8], &[7, opcode, 0, 0, 0, 0, 0, 0]);
        assert!(buffer[8..].iter().all(|byte| *byte == 0));
        assert_eq!(query.payload_len(), count);
    }
    let reset = reset_local_request();
    assert_eq!(reset[0], 7);
    assert!(reset[1..].iter().all(|byte| *byte == 0));
}

#[test]
fn generic_replies_require_all_eight_header_bytes_and_exact_mock_size() {
    for query in [Query::DeviceValue, Query::FinalBlock] {
        let valid = query.local_request();
        for offset in 0..8 {
            let mut reply = valid;
            reply[offset] ^= 1;
            assert!(
                matches!(query.decode_local_reply(&reply), Err(ProtocolError::Header { offset: actual, .. }) if actual == offset)
            );
        }
        for size in [0, 7, 16, 64, 71, 73] {
            let mut reply = valid.to_vec();
            reply.resize(size, 0);
            assert!(matches!(
                query.decode_local_reply(&reply),
                Err(ProtocolError::Length {
                    expected: GENERIC_LOCAL_LEN,
                    ..
                })
            ));
        }
    }
}

#[test]
fn device_value_preserves_u_v_order_and_detects_erased_u_only() {
    let mut reply = [0; 72];
    reply[..2].copy_from_slice(&[7, 0x29]);
    reply[8..16].copy_from_slice(&[0x78, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB, 0x90]);
    let value = DeviceValue::decode_local_reply(&reply).unwrap();
    assert_eq!(
        value,
        DeviceValue {
            u: 0x1234_5678,
            v: 0x90AB_CDEF
        }
    );
    assert!(!value.needs_initialization());
    reply[12..16].fill(0xFF);
    assert!(
        !DeviceValue::decode_local_reply(&reply)
            .unwrap()
            .needs_initialization()
    );
    reply[8..12].fill(0xFF);
    assert!(
        DeviceValue::decode_local_reply(&reply)
            .unwrap()
            .needs_initialization()
    );
}

#[test]
fn final_block_write_changes_only_first_dword_and_preserves_opaque_tail() {
    let mut reply = [0; 72];
    reply[..2].copy_from_slice(&[7, 0x2B]);
    for (index, byte) in reply[8..36].iter_mut().enumerate() {
        *byte = (index * 7 + 3) as u8;
    }
    let original = reply[8..36].to_vec();
    let block = FinalBlock::decode_local_reply(&reply).unwrap();
    for replacement in [0_u32, u32::MAX, 0x1234_ABCD] {
        let buffer = block.local_write_with_first_dword(replacement);
        assert_eq!(&buffer[..8], &[7, 0x2B, 1, 0, 0, 0, 0, 0]);
        assert_eq!(&buffer[8..12], &replacement.to_le_bytes());
        assert_eq!(&buffer[12..36], &original[4..]);
        assert!(buffer[36..].iter().all(|byte| *byte == 0));
        assert_eq!(
            block.as_bytes(),
            original.as_slice(),
            "source block must remain unchanged"
        );
    }
}

#[test]
fn record_ack_checks_report_id_length_and_ack_without_inventing_echo_or_crc() {
    let mut reply = [0xA5; 64];
    reply[..2].copy_from_slice(&[7, 1]);
    assert!(
        check_local_record_ack(&reply).is_ok(),
        "remaining bytes have no established echo semantics"
    );
    reply[1] = 0;
    assert!(matches!(
        check_local_record_ack(&reply),
        Err(ProtocolError::RecordRejected { ack: 0 })
    ));
    reply[1] = 1;
    reply[0] = 0;
    assert!(matches!(
        check_local_record_ack(&reply),
        Err(ProtocolError::Header { offset: 0, .. })
    ));
    for size in [0, 1, 2, 63, 65] {
        assert!(matches!(
            check_local_record_ack(&vec![0; size]),
            Err(ProtocolError::Length { .. })
        ));
    }
}
