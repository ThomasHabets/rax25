use super::*;

fn connection(extended: bool, mode: RejectMode) -> Data {
    let mut data = Data::new(Callsign::new("LOCAL").unwrap());
    data.peer = Some(Callsign::new("REMOTE").unwrap());
    if extended {
        data.set_version_2_2();
    } else {
        data.set_version_2();
    }
    let config = XidConfig::default();
    let mut parameters = config
        .negotiate(&config.offer(extended), extended, 256)
        .unwrap();
    parameters.reject_mode = mode;
    data.apply_negotiated(parameters);
    data
}

fn iframe(ns: u8, nr: u8) -> Iframe {
    Iframe {
        ns,
        nr,
        poll: PollFinal::Clear,
        pid: 0xf0,
        payload: vec![ns],
    }
}

fn delivered(actions: &[Action]) -> Vec<u8> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Deliver(bytes) => Some(bytes[0]),
            _ => None,
        })
        .collect()
}

#[test]
fn recovery_selection_and_opt_out() {
    for extended in [false, true] {
        let config = XidConfig::default();
        for (bits, expected) in [
            (negotiation::REJ, RejectMode::Rej),
            (negotiation::SREJ, RejectMode::Srej),
            (negotiation::MULTI_SREJ, RejectMode::MultiSrej),
        ] {
            let mut peer = config.offer(extended);
            peer.optional_functions = Some(
                bits | if extended {
                    negotiation::MOD128
                } else {
                    negotiation::MOD8
                },
            );
            assert_eq!(
                config.negotiate(&peer, extended, 256).unwrap().reject_mode,
                expected
            );
            let disabled = XidConfig {
                srej: false,
                ..config.clone()
            };
            assert_eq!(
                disabled.negotiate(&peer, extended, 256).is_some(),
                expected == RejectMode::Rej
            );
        }
        let config = XidConfig {
            receive_window: 7,
            receive_window_extended: 127,
            ..config
        };
        let p = config
            .negotiate(&config.offer(extended), extended, 256)
            .unwrap();
        assert_eq!(p.receive_window, if extended { 64 } else { 4 });
        let mut data = connection(extended, RejectMode::Rej);
        data.set_srej(false);
        assert!(!data.xid_policy().srej);
        assert!(
            !data
                .accepted_data(&Callsign::new("REMOTE").unwrap())
                .xid_policy()
                .srej
        );
    }
}

#[test]
fn selective_receive_buffers_deduplicates_and_wraps() {
    let state = Connected::new(ConnectedState::Connected);
    for extended in [false, true] {
        for mode in [RejectMode::Srej, RejectMode::MultiSrej] {
            let mut data = connection(extended, mode);
            let modulus = data.modulus.as_u8();
            data.vr = modulus - 2;
            let actions = state.iframe(&mut data, &iframe(1, 0), CommandResponse::Command);
            let requests: Vec<_> = actions
                .iter()
                .filter_map(|a| match a {
                    Action::SendSrej(s) => Some(s),
                    _ => None,
                })
                .collect();
            assert_eq!(
                requests.len(),
                if mode == RejectMode::MultiSrej { 1 } else { 3 }
            );
            if mode == RejectMode::MultiSrej {
                assert_eq!(requests[0].additional, [modulus - 1, 0]);
            }
            assert_eq!(data.selective_buffer.len(), 1);
            assert!(
                state
                    .iframe(&mut data, &iframe(1, 0), CommandResponse::Command)
                    .is_empty()
            );
            assert_eq!(data.selective_buffer.len(), 1);
            let actions =
                state.iframe(&mut data, &iframe(modulus - 1, 0), CommandResponse::Command);
            assert_eq!(delivered(&actions), []);
            let actions =
                state.iframe(&mut data, &iframe(modulus - 2, 0), CommandResponse::Command);
            assert_eq!(delivered(&actions), [modulus - 2, modulus - 1]);
            let actions = state.iframe(&mut data, &iframe(0, 0), CommandResponse::Command);
            assert_eq!(delivered(&actions), [0, 1]);
            assert_eq!(data.vr, 2);
            assert!(data.sreject_exception.is_empty());
            assert_eq!(data.selective_buffer, []);
            assert_eq!(
                delivered(&state.iframe(&mut data, &iframe(1, 0), CommandResponse::Command)),
                []
            );
        }
    }
}

#[test]
fn selective_retransmission_ack_and_checkpoint_semantics() {
    for extended in [false, true] {
        let mut data = connection(extended, RejectMode::MultiSrej);
        for ns in 0..4 {
            data.iframe_resend_queue.push_back(iframe(ns, 0));
        }
        data.vs = 4;
        let state = Connected::new(ConnectedState::TimerRecovery);
        let request = Srej {
            nr: 1,
            poll: PollFinal::Clear,
            additional: vec![2, 1],
        };
        let actions = state.srej(&mut data, &request, CommandResponse::Response);
        let resent: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                Action::SendIframe(p) => Some(p.ns),
                _ => None,
            })
            .collect();
        assert_eq!(resent, [1, 2]);
        assert_eq!(data.va, 0); // F=0 must not acknowledge frame zero.
        assert_eq!(data.iframe_resend_queue.len(), 4);
        let actions = state.srej(
            &mut data,
            &Srej {
                poll: PollFinal::Set,
                ..request
            },
            CommandResponse::Response,
        );
        assert!(!actions.iter().any(|a| matches!(a, Action::SendIframe(_))));
        assert_eq!(data.va, 1);
        assert_eq!(data.iframe_resend_queue.len(), 3);
        assert!(data.t1.running);
        assert!(!data.t3.running);
    }
}

#[test]
fn missing_requests_are_repeated_on_poll_and_busy_takes_priority() {
    let state = Connected::new(ConnectedState::Connected);
    let mut data = connection(true, RejectMode::MultiSrej);
    let _ = state.iframe(&mut data, &iframe(3, 0), CommandResponse::Command);
    for _ in 0..2 {
        assert!(matches!(
            data.enquiry_response(PollFinal::Set),
            Action::SendSrej(Srej {
                nr: 0,
                poll: PollFinal::Set,
                ..
            })
        ));
    }
    data.own_receiver_busy = true;
    assert!(matches!(
        data.enquiry_response(PollFinal::Set),
        Action::SendRnr { .. }
    ));
    data.clear_exception_conditions();
    assert_eq!(data.selective_buffer, []);
    assert!(data.sreject_exception.is_empty());
    assert!(matches!(
        data.enquiry_response(PollFinal::Set),
        Action::SendRr { .. }
    ));
}

#[test]
fn rej_and_unnegotiated_links_do_not_buffer() {
    let state = Connected::new(ConnectedState::Connected);
    let mut data = connection(false, RejectMode::Rej);
    let actions = state.iframe(&mut data, &iframe(3, 0), CommandResponse::Command);
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::SendRej { nr: 0, .. }))
    );
    assert_eq!(data.selective_buffer, []);
    assert_eq!(
        Data::new(Callsign::new("LOCAL").unwrap()).reject_mode,
        RejectMode::Rej
    );
}

#[test]
fn supervisory_codec_handles_nonzero_nr_lists_and_spans() {
    for extended in [false, true] {
        for nr in 0..if extended { 128 } else { 8 } {
            for poll in [PollFinal::Clear, PollFinal::Set] {
                for packet_type in [
                    PacketType::Rej(Rej { poll, nr }),
                    PacketType::Srej(Srej {
                        nr,
                        poll,
                        additional: vec![1, 3],
                    }),
                ] {
                    let p = Packet {
                        src: Callsign::new("LOCAL").unwrap().into(),
                        dst: Callsign::new("REMOTE").unwrap().into(),
                        digipeater: vec![],
                        modulus: if extended {
                            Modulus::Extended
                        } else {
                            Modulus::Standard
                        },
                        packet_type,
                    };
                    let parsed = Packet::parse(&p.serialize(), Some(extended)).unwrap();
                    assert_eq!(parsed.packet_type, p.packet_type);
                }
            }
        }
    }
    assert_eq!(
        Srej::parse_additional(&[253, 3], true).unwrap(),
        [126, 127, 0, 1]
    );
    for (bytes, extended) in [(&[1][..], false), (&[3][..], true), (&[3, 4][..], true)] {
        assert!(matches!(
            Srej::parse_additional(bytes, extended),
            Err(crate::Error::InvalidSrej(_))
        ));
    }
}

#[test]
fn selective_window_rejects_old_and_outside_frames_without_delivery() {
    let state = Connected::new(ConnectedState::Connected);
    for extended in [false, true] {
        let mut data = connection(extended, RejectMode::MultiSrej);
        data.vr = 2;
        let window = data.negotiated.as_ref().unwrap().receive_window;
        let ns = (data.vr + window) % data.modulus.as_u8();
        for ns in [1, ns] {
            let mut frame = iframe(ns, 0);
            frame.poll = PollFinal::Set;
            let actions = state.iframe(&mut data, &frame, CommandResponse::Command);
            assert_eq!(delivered(&actions), []);
            assert_eq!(data.selective_buffer, []);
            assert!(
                actions
                    .iter()
                    .any(|a| matches!(a, Action::SendRr { nr: 2, .. }))
            );
        }
    }
}

#[test]
fn invalid_srej_and_disabled_policy_do_not_silently_enable_recovery() {
    let state = Connected::new(ConnectedState::Connected);
    for mode in [RejectMode::Rej, RejectMode::Srej, RejectMode::MultiSrej] {
        let mut data = connection(true, mode);
        data.vs = 1;
        data.iframe_resend_queue.push_back(iframe(0, 0));
        let request = Srej {
            poll: PollFinal::Clear,
            nr: 5,
            additional: vec![],
        };
        let actions = state.srej(&mut data, &request, CommandResponse::Response);
        assert!(!actions.iter().any(|a| matches!(a, Action::SendIframe(_))));
        assert!(actions.iter().any(|a| matches!(a, Action::DlError(_))));
    }
}

#[test]
fn failed_connected_negotiation_resets_to_legacy_rej() {
    let mut data = connection(true, RejectMode::MultiSrej);
    data.set_xid_config(XidConfig {
        management_retries: 0,
        ..Default::default()
    });
    data.confirm_xid();
    assert!(data.confirming_xid());
    assert_eq!(data.reject_mode, RejectMode::Rej);
    data.obuf.extend(b"pending");
    assert!(data.flush().is_empty());
    let state = Connected::new(ConnectedState::Connected);
    let (next, _) = handle(&state, &mut data, &Event::ManagementTimeout);
    assert_eq!(next.unwrap().name(), "AwaitingConnection");
    assert!(!data.ext());
    assert!(!data.confirming_xid());
    assert_eq!(data.reject_mode, RejectMode::Rej);
    assert!(data.negotiated.is_none());
    assert!(!data.management.running);
}

#[test]
fn go_back_n_retransmissions_refresh_piggyback_ack() {
    let mut data = connection(true, RejectMode::Rej);
    data.iframe_resend_queue.push_back(iframe(0, 0));
    data.vr = 3;
    let actions = data.invoke_retransmission(0);
    assert!(matches!(
        &actions[0],
        Action::SendIframe(Iframe { nr: 3, .. })
    ));
    assert_eq!(data.iframe_resend_queue[0].nr, 0);
}

#[test]
fn resets_clear_selective_state_and_local_resets_reconfirm() {
    let state = Connected::new(ConnectedState::Connected);
    let mut data = connection(true, RejectMode::MultiSrej);
    let _ = state.iframe(&mut data, &iframe(3, 0), CommandResponse::Command);
    let _ = data.establish_data_link();
    assert_eq!(data.reject_mode, RejectMode::Rej);
    assert_eq!(data.xid_phase, XidPhase::BeforeLink);
    assert_eq!(data.selective_buffer, []);
    assert!(data.sreject_exception.is_empty());
    let _ = state.sabme(
        &mut data,
        &Callsign::new("REMOTE").unwrap(),
        &Sabme {
            poll: PollFinal::Set,
        },
    );
    assert!(data.negotiated.is_none());
    assert_eq!(data.reject_mode, RejectMode::Rej);
    assert_eq!(data.xid_phase, XidPhase::Complete);
    assert!(!data.management.running);
}
