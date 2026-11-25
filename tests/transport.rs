use ratmax::transport::{
    ExpectedCall, LocalFeatureTransport, MockTransport, TransportError, TransportFailure,
};

#[test]
fn script_enforces_exact_request_then_response_and_never_supplies_implicit_success() {
    let mut mock = MockTransport::new(vec![
        ExpectedCall::Set {
            bytes: vec![7, 0x29],
            outcome: Ok(()),
        },
        ExpectedCall::Get {
            report_id: 7,
            length: 72,
            outcome: Ok(vec![7; 72]),
        },
    ]);
    mock.set_local(&[7, 0x29]).unwrap();
    assert_eq!(mock.get_local(7, 72).unwrap(), vec![7; 72]);
    assert_eq!(mock.remaining(), 0);
    assert_eq!(
        mock.get_local(7, 72).unwrap_err().kind,
        TransportFailure::ScriptMismatch
    );
    assert_eq!(mock.trace().len(), 3);
}

#[test]
fn wrong_order_bytes_report_id_or_requested_length_fail_the_script() {
    let expected = || ExpectedCall::Get {
        report_id: 7,
        length: 72,
        outcome: Ok(vec![0; 72]),
    };
    for (id, size) in [(0, 72), (7, 64)] {
        let mut mock = MockTransport::new(vec![expected()]);
        assert_eq!(
            mock.get_local(id, size).unwrap_err().kind,
            TransportFailure::ScriptMismatch
        );
    }
    let mut mock = MockTransport::new(vec![expected()]);
    assert_eq!(
        mock.set_local(&[7, 0]).unwrap_err().kind,
        TransportFailure::ScriptMismatch
    );
    let mut mock = MockTransport::new(vec![ExpectedCall::Set {
        bytes: vec![7, 0],
        outcome: Ok(()),
    }]);
    assert_eq!(
        mock.set_local(&[7, 1]).unwrap_err().kind,
        TransportFailure::ScriptMismatch
    );
}

#[test]
fn transport_errors_and_short_replies_are_retained_for_the_protocol_layer() {
    let error = TransportError::new(TransportFailure::Disconnected, "scripted disconnect");
    let mut mock = MockTransport::new(vec![
        ExpectedCall::Set {
            bytes: vec![7],
            outcome: Err(error.clone()),
        },
        ExpectedCall::Get {
            report_id: 7,
            length: 72,
            outcome: Ok(vec![7]),
        },
    ]);
    assert_eq!(mock.set_local(&[7]).unwrap_err(), error);
    assert_eq!(
        mock.get_local(7, 72).unwrap(),
        vec![7],
        "mock must not silently pad a truncated reply"
    );
}
