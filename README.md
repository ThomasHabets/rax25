# rax25

Rust library for AX.25 connected mode.

https://github.com/ThomasHabets/rax25
https://blog.habets.se/2024/09/An-AX.25-implementation-in-Rust.html

## Status

* Seem to be working well.
* Both 8 and 128 modulus supported.
* Basic REJ retransmission is supported.
* Negotiated single- and multi-frame SREJ, with per-connection opt-out.
* Segmentation: not implemented.
* The sync API is not great.

Interoperability with linux kernel stack is lightly tested on every
push to github.

## Technical details

Library operations return `rax25::Result<T>` with a typed `rax25::Error`.
Callers can match error variants and inspect wrapped causes through
`std::error::Error::source`. The examples use `anyhow` for application-level
error reporting; it is not a library dependency.

Connection APIs use `Callsign` for station identity (callsign plus SSID).
`Callsign::new("m0qqq-0")` canonicalizes to `M0QQQ`; equality and hashing
ignore textual case and an explicit zero SSID. Wire addresses use `Addr`,
which combines a `Callsign` with frame-specific `AddrFlags`.
Use `callsign.with_flags(flags)` or `Addr::from(callsign)` to build one,
and `addr.callsign()` to access its identity without flags.

`Packet::serialize()` uses the packet's stored sequencing mode. Connection
state sets it for outgoing frames; use `packet.with_extended(true)` when
constructing extended-mode packets directly.

Frame roles use `CommandResponse::{Command, Response}` and poll/final bits
use `PollFinal::{Clear, Set}`. For example, an XID query is constructed with
`Packet::xid(local, peer, CommandResponse::Command, PollFinal::Set, None)`.
The same types are used by frame fields and state-machine events/actions;
raw address C-bit accessors remain available for legacy encodings.

The Linux source-address extended-mode hint is optional as an experiment.  For
raw packets, use `packet.serialize_with_linux_extended_hint(true/false)`. This
only disables the wire hint; modulo-128 framing and negotiated receive mode are
unchanged.

The extended hint bit is ignored on reception.

Address construction and serialization use named `AddrFlags` instead of
positional boolean arguments. For example,
`Addr::new_bits("M0QQQ-1", AddrFlags::LAST | AddrFlags::HIGH)` sets the final
address and high-bit indicators explicitly.

## Testing

Required lossy TCP tests use explicit, bounded packet-drop scenarios so timer
scheduling cannot change the fault being tested. They check retransmission,
echo delivery, and shutdown in standard and extended modes. Unrestricted
seeded random loss remains an opt-in stress test: random outages can exceed
the protocol's finite retry budget, so successful delivery is not guaranteed.

```shell
cargo test --features async --test async_tcp_examples random_loss_stress -- --ignored --nocapture
```

The easiest test setup is to simply use a "bent pipe" TCP socket that both ends
connect to. That way it's fast, doesn't lose any packets, and doesn't require
any hardware.

This will do it:

```shell
while true; do socat TCP-LISTEN:10000,reuseaddr TCP-LISTEN:10001,reuseaddr;sleep 1;done
```

After that you can run a server and client like:

```shell
cargo run --example async_server -- -v debug -p tcp://127.0.0.1:10000 -s M0QQQ-1 --capture server.pcap
cargo run --example async_client -- -v info -p tcp://127.0.0.1:10001 -s M0QQQ-2 --capture client.pcap -e M0QQQ-1
```

## XID Negotiation

Active XID negotiation is opt-in. Add `--xid` to `async_client` to negotiate
before establishing the connection. Without `-e`, XID prefers modulo-128 and
can select modulo-8; `-e` requests extended mode. A peer that rejects XID or
does not answer within the management retry limit is contacted using SABM
and AX.25 v2.0 defaults instead.

```shell
cargo run --features async --example async_client -- --xid -p tcp://localhost:10001 -s M0QQQ-2 M0QQQ-1
```

Both APIs answer pre-connection and connected XID commands. They advertise
half duplex, REJ, and single-/multi-frame SREJ, but not segmentation.
SREJ activates only after successful negotiation; unnegotiated links use REJ.
Receive sizes and windows constrain the other
station's transmissions; acknowledgement timeout and retry count use the
greater offered values. See [SPEC_DIFFERENCES.md](SPEC_DIFFERENCES.md) for
the specification interpretation and remaining limitations.

In the async API, enable negotiation with
`ConnectionBuilder::xid(XidConfig::default())`. In the sync API, use
`Client::connect_with_xid(&peer, None)`; `set_xid_config` customizes local
limits and management retries. Both clients expose `negotiated_parameters()`.
The examples provide `--no-extended` to constrain XID to modulo-8 and
`--xid-receive-size` to set the advertised receive payload limit. `--srt`
also sets the XID management retry interval.

Disable SREJ per connection with `ConnectionBuilder::srej(false)`,
`Client::set_srej(false)`, or `XidConfig { srej: false, ..Default::default() }`.
The builder/client switch also restricts explicit XID configuration and is
inherited by accepted connections. These are setup policies, not live mode
switches. All connection examples, including AGW, accept `--no-srej`;
AGW applies this policy to links created by its shared packet engine.
Capability alone does not initiate XID. Both sync examples now accept `--xid`.
The `reject_mode` field of `negotiated_parameters()` reports REJ, single SREJ,
or multi-SREJ when a negotiation exists.

Dire Wolf 1.7 ignores XID before link establishment. Use
`ConnectionBuilder::xid_after_connect(config)` or
`Client::connect_then_xid(&peer, mode)`, or add `--xid --xid-after-connect`
to the client example. This establishes SABM(E) first, negotiates without
changing its modulus, and falls back to a standard REJ link on failure.
XID-first setup also reconfirms after UA because Dire Wolf resets negotiated
parameters on SABM(E). Established async links continue negotiation in their
background task without requiring a pending application read.

## KISS Channel Busy

Rax25 automatically handles port-zero MeshCore-compatible ChannelBusy
notifications (`C0 06 8E state C0`, 0 quiet, 1 busy). Busy suspends T1, T3,
and XID management timers; quiet resumes their remaining time, per C3.2.
This works with native async clients, the AGW engine, and synchronous
KISS/bus clients. Custom synchronous hubs can implement `recv_event_timeout`
to supply `HubEvent::ChannelBusy` alongside data frames.

If using rustradio's `bell202`, enable its notifications with
`--busy-threshold-db=-30`, adjusting the threshold for your receiver. Its
receive-power detector approximates channel activity; noise can hold timers
paused. Recent audio builds also report local TX busy by default (unless
`--full-duplex` is set), but do not implement CSMA. Timer suspension
neither sends RNR nor inhibits transmission. See `SPEC_DIFFERENCES.md` for the
C2a detection limitations.

## KISS Loss Proxy

Run a frame-aware loss proxy between a KISS application and its modem:

```shell
cargo run --features async --example kiss_loss_proxy -- \
  --listen 127.0.0.1:8000 --modem tcp://localhost:8001 \
  --tx-drop 50 --rx-drop 50 --seed 123 --capture loss.pcapng
```

Connect the application to port 8000. TX means application to modem; RX is
the reverse. Drop percentages are independent, default to zero, and apply
only to KISS data frames on any port. Modem control commands pass through.
The modem may also use a `serial:///dev/ttyUSB0` endpoint. One application
connection is accepted per run; EOF half-closes the opposite writer.

The optional capture must be a new file. It records forwarded and dropped
AX.25 packets on named TX/RX interfaces, with comment `dropped` on discarded
packets. Omit `--seed` for a random seed, which is printed for replay.
Separate directional RNGs reproduce decisions for each direction's frame
sequence; retransmission timing can still change that sequence.

## AGW Server

The `agw-kiss` binary is the default target for `cargo run`. It serves one AGW
port over one KISS modem. Library users can omit the `agw` feature by
disabling default features.
The existing client examples still use rax25 directly, not AGW.

```shell
cargo run -- --tcp localhost:8001 --listen 127.0.0.1:8000 --capture agw.pcap
cargo run -- --dev /dev/rfcomm0 --baud 9600 --listen 127.0.0.1:8000
```

It supports multiple application sockets and AX.25 links, exclusive incoming
callsign registration/unregistration, direct and connect-via establishment,
connected binary streams, disconnects, UI transmission, discovery, capability
and queue queries. Add `-e` for outgoing modulo-128 links; incoming links follow
the peer's SABM/SABME. Add `--xid` to negotiate parameters before outgoing
connections, using modulo-8 by default or modulo-128 with `-e`. Use
`--xid --xid-after-connect` to negotiate only after SABM(E)/UA, as needed
by Dire Wolf 1.7. Peers without
XID support use the library's standard-mode fallback. API `Port(1)` maps to
wire port zero and KISS channel zero.
Connected streams use PID 0xf0; monitoring, raw mode, heard lists, authentication
and nonstandard connected PIDs are not implemented. Bind only to trusted hosts.

Queue counts include buffered and unacknowledged AX.25 data frames, not the
unknown hardware queue inside a KISS TNC. Capability radio timing/rate values
are conventional defaults, not measurements: KISS cannot query these settings.
Slow application sockets are closed when their bounded output queue fills;
link transmit queues are bounded and overflowing links are disconnected.
Modem failure stops the server rather than silently reconnecting.

## Dire Wolf Audio Interoperability

Case names appear in every START/PASS/FAIL message and artifact directory:

| Test | Mode | Recovery and loss | Transfer |
| --- | --- | --- | --- |
| `direwolf_standard_srej_audio` | modulo-8 | XID-negotiated multi-SREJ; drop I frames 1 and 2 each direction | 256-byte pattern plus small echoes |
| `direwolf_extended_srej_audio` | modulo-128 | XID-negotiated multi-SREJ; same scripted drops | Same small echoes |
| `direwolf_standard_rej_audio`, `direwolf_extended_rej_audio` | respective mode | XID-negotiated REJ; same scripted drops | Same small echoes |
| `direwolf_standard_audio`, `direwolf_extended_audio` | respective mode | No XID; random loss at 0%, 5%, 10% | Small echoes |
| `direwolf_lossy_file_transfer` | modulo-8 | No XID; REJ; random 10% loss | 4 KiB upload and echo download |
| `direwolf_lossy_file_transfer_extended_srej` | modulo-128 | Post-connect XID multi-SREJ; random 10% loss | 4 KiB upload and echo download |

To run the modulo-128 file transfer and produce an annotated `loss.pcapng`:

```shell
tests/run_direwolf_interop.sh direwolf_lossy_file_transfer_extended_srej
```

The printed artifact directory contains `rax25.pcap`, `direwolf.stdout.log`,
and `agw.log`. Scripted-loss cases also contain `to-direwolf.pcap`,
`from-direwolf.pcap`, and corresponding loss logs. Random-loss cases instead
include `loss.pcapng` with dropped-frame comments.

XID diagnostics print single-SREJ and multi-SREJ separately. Dire Wolf 1.7
can clear single-SREJ while selecting multi-SREJ (`0x200000`); a false
single-SREJ bit therefore does not mean all selective recovery was rejected.
In modulo-8 tests it advertises and uses multi-SREJ despite logging internal
warnings that SREJ should not be used in basic mode. These are observations
of that binary's behavior, not a claim of consistent official support.
The warning sites in the 1.7 source are
[out-of-order receive](https://github.com/wb2osz/direwolf/blob/1.7/src/ax25_link.c#L2911)
and [enquiry response](https://github.com/wb2osz/direwolf/blob/1.7/src/ax25_link.c#L5837).

The `direwolf_lossy_file_transfer` case additionally uploads a 4 KiB binary
file and downloads its echo, checking both copies byte-for-byte in standard
mode with 10% TX/RX loss. It prints recovery counts and requires
retransmitted I frames and REJ frames in the capture. The upload is queued as
one burst, exercising the full transmit window.
The generated `transfer.bin` is retained with the interop artifacts.
This slow test is excluded from pre-commit. Run it manually with
`tests/run_direwolf_interop.sh direwolf_lossy_file_transfer`.
GitHub Actions runs it separately after the pre-commit suite.
The harness detects modem support for RX and local-TX busy reporting. With
both available it enables `--busy-threshold-db=-30`, uses 3-second timers,
and increases the modulo-128 bulk window from 4 to 16 (scripted tests: 8).
Modulo-8 SREJ retains its four-frame ambiguity limit; standard bulk REJ uses
a seven-frame Dire Wolf window. To exercise this profile with a newer modem:

```shell
BELL202_BIN="$HOME/bin/bell202" tests/run_direwolf_interop.sh direwolf_lossy_file_transfer
```

Older modems keep the conservative timers and windows, including the pinned
release used by default in CI. No unpublished dependency is required.
The extended file variant requires XID-negotiated multi-SREJ, retransmissions,
and SREJ frames, and rejects unexpected REJ recovery. Both bulk cases are
excluded from local pre-commit and selected by the CI file-transfer step.

Latency investigation (local PipeWire/ALSA setup): a no-loss standard-mode
run measured echo round trips of 1.16 s, 1.66 s, and 4.52 s for 7-, 40-, and
256-byte payloads. Subtracting AX.25 bytes at 1200 bit/s in both directions
leaves about 0.9 s of fixed overhead, including HDLC flags, transmit delays,
DSP and audio buffering; this does not isolate audio-server latency.
With older modems, the long bulk-test runtime also includes 45-second retry
waits (including setup retransmissions), not simply audio-path latency.
Requesting 20 ms via `PULSE_LATENCY_MSEC` failed to decode packets in a control run; it is not
enabled by the harness.

The audio interop tests run both standard and extended AX.25 through the KISS
loss proxy at some loss percentages, using seed 123.  Each run retains
`loss.pcapng` with dropped-frame comments alongside the client capture and
child-process logs. Nonzero-loss cases allow longer deadlines for over-the-air
retries.

An integration test runs the `bell202` modem from the published rustradio
release pinned in `tests/run_direwolf_interop.sh` against an installed Dire Wolf
binary, through two virtual audio cables. A registered AGW application echoes
data using Dire Wolf's AX.25 stack; the test checks standard and extended
connections, bidirectional binary data, and disconnect. No Dire Wolf source is
required.

On Linux, install Dire Wolf, PipeWire, `pipewire-pulse`, WirePlumber,
`dbus-run-session`, `pactl`, and the ALSA PulseAudio plugin
(`libasound2-plugins` on Debian). Then run:

```shell
bash tests/run_direwolf_interop.sh
```

The pre-commit Tickbox runs this test after the parallel checks. The Rust
test cases are marked ignored so ordinary `cargo test` does not require the
external audio tools. The launcher installs the pinned release's `bell202`
example from crates.io with `--features audio --locked` and starts an isolated
audio session, leaving desktop audio unchanged. Building the modem requires
Rust 1.98 or newer and ALSA/JACK development libraries (`libasound2-dev`,
`libjack-jackd2-dev`, and `pkg-config` on Debian).
Set `BELL202_BIN` to use an already-built modem. `DIREWOLF_BIN` selects a
different Dire Wolf executable. No sibling checkout is needed.
Directly running the ignored Rust tests requires both `BELL202_BIN` and a
live Pulse server; the tests never install dependencies themselves.
Logs and captures remain under `target/direwolf_interop/` for inspection,
or under `$CARGO_TARGET_DIR/direwolf_interop/` when set. Tickbox uses
`target/<branch>.test.direwolf/`, retaining the modem between runs and keeping
artifacts outside its temporary checkout. GitHub Actions uploads logs and
captures on failure.

## Probe XID Capabilities

The `xid_probe` example sends an XID capability query without establishing an
AX.25 data connection. It prints the peer's advertised parameters and exits.
Both serial and TCP KISS endpoints are supported:

```shell
cargo run --features async --example xid_probe -- -p tcp://localhost:8000 -s M0QQQ-1 M0QQQ-2
cargo run --features async --example xid_probe -- -p serial:///dev/rfcomm0 -s M0QQQ-1 --timeout 3s --retries 3 M0QQQ-2
```

`--retries` counts retransmissions after the initial query. A timeout, rejected
query, or closed KISS connection produces an error exit; the probe never falls
back to SABM or SABME.

## Reference documentation

See the [spec/](spec/) folder.

* 1998 spec: Unless specified otherwise, spec page numbers refer to this
  version.
* 2006 spec update: despite its name and title page, is actually from 2006.
* 2017 spec update has [some findings by
  isomer](https://github.com/isomer/ax25embed/blob/main/ax25/ax25_dl.c)
* There is [work in progress](https://github.com/packethacking/ax25spec) to fix
  bugs and clarify.

Also see:
* [Examining Ambiguities in the Automatic Packet Reporting
  System](https://digitalcommons.calpoly.edu/cgi/viewcontent.cgi?article=2449&context=theses)
* Check [Direwolf
  implementation](https://github.com/wb2osz/direwolf/blob/master/src/ax25_link.c)
  "Erratum" comments.

## Misc

* [PR for wireshark to decode extended
  mode](https://gitlab.com/wireshark/wireshark/-/merge_requests/17121)
