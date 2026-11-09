# Differences From the AX.25 Specifications

This document describes how rax25's current implementation differs from the
AX.25 documents in [spec/](spec/), and why. It is an implementation companion,
not a replacement specification or a claim of full AX.25 conformance.

The main baseline is [AX.25 v2.2 (1998)](spec/1998%20-%20AX25.2.2.pdf).
The [2006 update](spec/2006%20-%20AX25.2.2-Jul%2098-2.pdf) and
[2017 update](spec/2017%20-%20AX25.2.2-Sep%2017-1-10Sep17.pdf) revise its
state diagrams. [AX.25 v2.0 (1984)](spec/1984%20-%20AX25V20.pdf) provides
historical context; supporting modulo-8 connections does not mean rax25
implements every aspect of that edition separately.

Page references below use the documents' printed page numbers. Where the code
identifies a diagram as erroneous, the explanation records the implementation's
interpretation, rather than an independently adopted official erratum.

## Changes Between Specification Editions

These are selected protocol changes, corrections, and regressions relevant to
this implementation, not an exhaustive editorial diff. The years identify the
files in `spec/`; the 2006 document still labels itself "Revision: July 1998".
Figure and page references identify the newer edition unless stated otherwise.
Bug assessments here are implementation notes, not official errata.

### 1984->1998

- Adds modulo-128 sequencing and SABME alongside modulo-8/SABM
  (sections 4.2 and 4.3.3.1).
- Adds selective-reject recovery and XID parameter negotiation
  (sections 4.3.2.4 and 4.3.3.7).
- Defines segmentation/reassembly and a layered service model, with SDL state
  diagrams taking precedence over prose (Preface, sections 2 and 6.6, Appendix C).
- Limits digipeating to two hops, reflecting the move toward network nodes
  (Preface and section 3.12.5).

### 1998->2006

- Redraws the figures in Visio and repaginates the SDL (Foreword, Appendix C).
- Renumbers XID bits from one-based to zero-based without changing wire masks;
  this also fixes the REJ/SREJ prose's inconsistent bit references
  (section 4.3.3.7, Figure 4.5).
- Fixes the TimerRecovery SABM(E) reset: the duplicated `V(S) <- 0` becomes
  `V(R) <- 0` (Figure C4.5, page 101; 1998 page 99).
- Fixes Connected T3 expiry to initialize `RC` to 1 rather than 0
  (Figure C4.4, page 96; 1998 page 93).
- Changes TimerRecovery I-frame acknowledgement handling from assigning
  `V(A) <- N(R)` to calling "Check I frames ack'd"
  (Figure C4.5, page 103; 1998 page 102).
- Introduces a typo: Disconnected's leftmost `DL-CONNECT Request` should be
  `DL-DISCONNECT Request` (Figure C4.1, page 88).
- Introduces an I-frame error-code bug: an I response reports O instead of S;
  O means an oversized information field (Figures C4.4/C4.5, pages 98/103).
  The 2017 diagrams retain O, and Connected additionally reverses the
  command-test branches (Figures C4.4c/C4.5c, pages 93/96).

### 2006->2017

- Fixes the Disconnected `DL-CONNECT`/`DL-DISCONNECT` typo
  (Figure C4.1, page 88).
- Fixes successful connection establishment to start T3 instead of stopping it
  (Figure C4.2, page 89; 2006 page 91).
- Fixes enquiry replies to use RR/RNR responses rather than commands, and adds
  SREJ-aware enquiry handling (Figure C4.7a, page 101; 2006 page 109).
- Fixes the peer-busy acknowledgement path to stop T3 instead of starting it,
  and initializes link-establishment `RC` to 1 instead of 0
  (Figure C4.7a, page 101; 2006 pages 109-110).
- Adds TimerRecovery final-response handling to restart T1 after retransmission
  and clear `RC` when everything is acknowledged (Figure C4.5b, page 95).
- Changes the T1-expiry backoff from `2 ** (RC + 1) * SRT` to
  `(RC * 0.25) + SRT * 2` (Figure C4.7b, page 102; 2006 page 111).
- Changes XID defaults from combined SREJ/REJ and modulo-8 to SREJ and
  modulo-128 (section 4.3.3.7).
- Permits multiframe SREJ and assigns optional-functions bit 22 to segmentation,
  but introduces a contradiction: the prose still requires bit 22 to be zero
  (Figure 4.5 and section 4.3.3.7, pages 32-33).
- Introduces an invalid modulo-8 default window: `k <- 8` replaces 4, although
  section 6.7.2 still limits it to 7 (Figure C4.7b, page 102).
- Introduces a wrong error code: unexpected UA while Connected shares FRMR's
  error K instead of reporting C (Figure C4.4b, page 92; 2006 page 97).
- Introduces a timer regression: SABM(E) in TimerRecovery stops T3 instead of
  starting it before returning to Connected (Figure C4.5b, page 95;
  2006 page 101).

## Deliberate Choices

### Shared AGW Packet Engine

The async packet engine shares one KISS channel across independently timed
AX.25 links. AGW application registration and ownership are local routing
policy, not over-the-air protocol extensions. Outgoing digipeater paths are
attached to all link packets; responses reverse the incoming path and clear
its repeated bits. Serialization preserves digipeater H bits, including
marked routes supplied through the Dire Wolf-compatible AGW CALL* extension.
Incoming frames are accepted only after all digipeaters have repeated them.
AGW connected streams use PID 0xf0. Queue reports count buffered and
unacknowledged AX.25 frames, since KISS does not expose the hardware TX queue.
The AGW example's `--xid` enables the library's existing XID negotiation and
legacy fallback policy; `--extended` selects the requested outgoing mode.

### Linux Extended-Sequence Indicator

Rax25 follows Linux's nonstandard use of a reserved source-address bit to
indicate extended sequence numbers. This helps tools such as `axlisten` decode
packets without observing connection establishment. The negotiated connection
mode remains authoritative when it is available: `Packet::parse` accepts an
explicit mode, and only infers the mode from this bit when passed `None`.
Outgoing packets carry their effective sequencing mode; serialization derives
both the control-field format and the Linux address hint from that same mode.
The hint is enabled by default for compatibility, but applications can disable
it with the async builder's `linux_extended_hint(false)`, the sync client's
`set_linux_extended_hint(false)`, or `Packet::serialize_with_linux_extended_hint(false)`.
Disabling it leaves the source reserved bit set to one and does not change
control-field encoding, destination bits, or receive parsing. Such peers must
use the known connection mode rather than infer it from this hint.
Connection endpoints use flag-free `Callsign` identities; packet headers use
`Addr` values that retain wire flags. This API distinction does not change
the address encoding, and an explicit zero SSID identifies the same station
as an omitted SSID.

See [packet parsing and serialization](src/lib.rs) and [connection handling](src/async.rs).

### Receive Size and Transmit Window

Outgoing payloads default to 256 bytes, consistent with the specification's
2048-bit information-field size. Incoming payloads may instead be up to 65535
bytes by default. This deliberately permits larger frames from peers without
requiring rax25 to transmit frames that may overwhelm radio hardware.

The transmit window is 4 for modulo-8 and 32 for modulo-128 connections,
following the 1998 initialization diagram (page 109). The 2017 initialization
diagram (page 102) gives 8 for modulo-8. Rax25 retains 4: a window of 8 would
exhaust the entire sequence space and make acknowledgement wraparound
ambiguous; the maximum safe modulo-8 window is 7.

See `DEFAULT_MTU_OUT`, `DEFAULT_MTU_IN`, `set_version_2`, and
`set_version_2_2` in [the state machine](src/state.rs).

### Application Data Is a Byte Stream

Application writes do not preserve message boundaries. Rax25 buffers bytes and
splits them into I frames according to the transmit size and available window.
It does not implement the specification's segmentation and reassembly service
for preserving larger application data units. This is an intentional API choice
for stream-oriented applications; segmentation remains an unimplemented feature.

See `Connected::data` and `Data::flush` in [the state machine](src/state.rs).

## State-Machine Corrections and Interpretations

The following choices are implemented in [src/state.rs](src/state.rs).
Changes that follow the 2017 revision differ from the 1998 baseline, but are
not extensions beyond all the supplied specifications.

| Situation | Rax25 behavior and rationale |
| --- | --- |
| Answering an enquiry, 1998 page 106 | Sends RR/RNR as a response, not an RR command. This follows the 2017 correction and allows a polling Linux peer to receive an answer instead of another question. The implementation retains the simpler receiver-busy choice between RNR and RR rather than the full 2017 enquiry-response logic. |
| Checking acknowledgements while the peer is busy, 1998 page 107 | Stops T3 and runs T1, following 2017. Running the idle timer alongside the outstanding-response timer would create competing enquiries. |
| Establishing a link, 1998 page 106 | Starts the retry counter at 1, following 2017, so the initial attempt counts toward the retry limit. |
| Receiving UA while awaiting connection, 1998 page 88 / 2017 page 89 | Stops T1, starts T3, and resets the retry counter to 0. Starting T3 follows 2017; resetting the counter is an additional choice noted in the code as matching Direwolf, so a successful connection does not retain retries from establishment. |
| Receiving SABM(E) while connected or recovering | Resets V(R), correcting the duplicated V(S) assignment in 1998. Starts T3 even when leaving TimerRecovery; the code rejects the 2017 instruction to stop both timers because the resulting connected link needs idle supervision. |
| RR processing in TimerRecovery, 2017 page 95 | Continues processing when the poll-command condition is false, supplying the diagram's missing branch. In the final-response retransmission path it also follows the 2017 additions that restart T1 or clear the retry counter when fully acknowledged. |
| Receiving I frames, 2017 pages 93 and 96 | Rejects an I response with error S. Oversized payloads produce error O. The implementation treats the diagram's command/response and error-O routing as erroneous: error O describes excessive information-field length, not command status. |
| I-frame acknowledgement handling in TimerRecovery | Uses `check_iframe_acked`, following 2017, rather than only updating V(A) as in 1998. This also maintains acknowledgement-related timers. |
| T3 expiry while connected | Sets the retry counter to 1 before sending an enquiry, following 2017 instead of the 1998 value of 0. |
| Unexpected UA while connected | Reports error C and re-establishes the link. The code treats the 2017 diagram's error K as undocumented. |
| Disconnect completion and retry exhaustion | Stops T3 on release retry exhaustion. Where the earlier diagrams omit a DM poll/final value, uses false; for TimerRecovery exhaustion this follows the explicit 2017 value. These choices prevent supervision after disconnection and avoid inventing a final response without a poll. |

The implementation also interprets the initialization diagrams' `kr` as the
transmit window `k`. The XID prose's use of `N1` for retry count is treated as
a naming error: retry count is `N2`, while `N1` describes information-field size.

## XID Negotiation

The codec retains the 1998 defaults (combined SREJ/REJ and modulo-8), rather
than the 2017 prose's selective reject and modulo-128. Capability bit numbering
changes from one-based in 1998 to zero-based in 2017 without shifting the wire
masks. The 2017 table additionally permits multiframe SREJ and assigns a
segmentation bit, although its prose still requires the segmentation bit to be
zero. See the comments in [src/xid.rs](src/xid.rs) for these discrepancies.

Active XID negotiation is opt-in; responding to pre-connection commands does
not require enabling active negotiation. Negotiation occurs before SABM(E),
following sections 4.3.3.7 and 6.3.2. Appendix C5 instead describes sending
XID after UA. Rax25 deliberately follows the main text so the chosen modulus
and limits are known before connection establishment and application data.

An unspecified mode prefers modulo-128; an explicitly selected mode constrains
negotiation. Rejection or management retry exhaustion falls back to modulo-8
and v2.0 defaults, including when extended mode was requested. Only half
duplex and REJ are advertised: receiving XID does not enable unimplemented
SREJ or segmentation. Receive size and window are directional notifications;
timeout and retry count are negotiated using the greater offered values.

Management retransmissions have a separate timer and counter from data-link
supervision. Established connections are not renegotiated in this implementation.

A SABM does not indicate whether an earlier XID response reached the initiator.
If every response was lost, a standard-mode initiator may have fallen back to
v2.0 defaults while the responder still has a pending proposal. The responder
therefore accepts at least the legacy 256-byte payload size even when it
advertised a smaller receive limit. Compliant negotiated peers still transmit
within the advertised limit; this receive tolerance prevents failed negotiation
from making legacy fallback unusable.

## Optional Experiments

Both experiments below are disabled by default. They are selected through
`Experiment` in the library and `--experiments` in the async examples.
They should not be mistaken for baseline AX.25 behavior.

| Experiment | Difference and motivation |
| --- | --- |
| `ResetRetryOnAckUpdate` (`reset-retry-on-ack-update`) | Resets the retry counter when V(A) advances. A fresh acknowledgement proves progress even if an RR final response was lost; without this, a connection carrying useful data can still reach its retry limit. |
| `ResendOnRrCommand` (`resend-on-rr-command`) | In TimerRecovery, permits the acknowledgement/retransmission path whenever T1 is running, rather than requiring an RR response with F=1. This can recover when enquiries cross or responses are lost. Despite its name, the condition is broader than just receiving an RR command; the code notes that it still needs a guard against retransmission before a probe has had time to receive an answer. |

See `Experiment`, `Data::update_ack`, and `Connected::rr_timer_recovery` in
[src/state.rs](src/state.rs). These are attempts to address retry/recovery
problems, not guarantees of correct behavior under every loss pattern.

## Incomplete Behavior and Transport Assumptions

These are limitations or implementation details, not intentional amendments
to the wire protocol.

- **Timer selection:** `select_t1_value` is incomplete. It resets SRT to the
  configured default when the retry counter is zero, and on expiry uses an
  interpretation of the 2017 expression as `SRT = 2 * SRT + RC * 250ms`.
  It does not implement full RTT measurement or consistently update T1V.
  The 3-second initial SRT and 10-second T3 are implementation defaults;
  they are not claimed to be mandated by the specifications. The async
  examples expose `--srt` and `--t3v` for other environments.
- **Delayed acknowledgements:** There is no complete T2 response-delay timer.
  Section 6.7.1.2 describes T2 as optional, so its absence alone is not a
  protocol extension, but acknowledgement timing is not a complete rendering
  of all the diagrams.
- **Recovery:** SREJ is disabled, out-of-order frame storage
  is incomplete, and some state/event handlers are placeholders. Basic REJ
  recovery is supported. The full enquiry-response
  procedure and simultaneous extended connection establishment are also
  incomplete. These gaps should not be treated as deliberate interoperability
  policies.
- **KISS framing and FCS:** The library exchanges AX.25 packets through a
  KISS TNC over serial or TCP. It does not generate or verify an AX.25 FCS
  in those packet buffers (`USE_FCS` is false); over-the-air framing and FCS
  handling are delegated to the TNC. This does not remove the FCS requirement
  from over-the-air AX.25 frames.
- **Protocol identifiers:** The connected stream emits PID `0xf0` (no layer 3),
  and I-frame parsing currently assumes that PID. This is not a general
  implementation of every layer-3 protocol or segmentation PID in AX.25.

Lossy integration tests exercise some recovery paths, but do not establish
full conformance. Required tests use bounded, explicit losses; unrestricted
random-loss tests are opt-in stress tests because loss can exceed the finite
retry budget. The data-only random-loss test is also ignored, and a seed
associated with a lost UA is excluded from the random test cases.
The source also contains disabled proposals for automatically leaving
TimerRecovery when all data is acknowledged; those proposals are not current
behavior.
