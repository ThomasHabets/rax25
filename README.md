# rax25

Rust library for AX.25 connected mode.

https://github.com/ThomasHabets/rax25
https://blog.habets.se/2024/09/An-AX.25-implementation-in-Rust.html

## Status

* Seem to be working well.
* Both 8 and 128 modulus supported.
* Basic REJ retransmission is supported.
* SREJ untested / probably broken.
* Segmentation: not implemented.
* The sync API is not great. Async API may also need some work

Interoperability with linux kernel stack is lightly tested on every
push to github.

## Technical details

Library operations return `rax25::Result<T>` with a typed `rax25::Error`.
Callers can match error variants and inspect wrapped causes through
`std::error::Error::source`. The examples use `anyhow` for application-level
error reporting; it is not a library dependency.

Address construction and serialization use named `AddrFlags` instead of
positional boolean arguments. For example,
`Addr::new_bits("M0QQQ-1", AddrFlags::LAST | AddrFlags::HIGH)` sets the final
address and high-bit indicators explicitly.

* The reserved bit used by the Linux kernel (and other Linux tools,
  like `axlisten`) to indicate extended sequence numbers is set. This
  crate sets it too, but since we know the connection state, it's
  ignored on reception.

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

Both APIs answer pre-connection XID commands. They advertise half duplex and
REJ, not SREJ or segmentation. Receive sizes and windows constrain the other
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

## Dire Wolf Audio Interoperability

An opt-in integration test runs the `bell202` modem from the published
rustradio 0.20.2 release against an installed Dire Wolf binary, through two
virtual audio cables. A registered AGW application echoes data using Dire
Wolf's AX.25 stack; the test checks standard and extended connections,
bidirectional binary data, and disconnect. No Dire Wolf source is required.

On Linux, install Dire Wolf, PipeWire, `pipewire-pulse`, WirePlumber,
`dbus-run-session`, `pactl`, and the ALSA PulseAudio plugin
(`libasound2-plugins` on Debian). Then run:

```shell
bash tests/run_direwolf_interop.sh
```

The launcher installs the pinned release's `bell202` example from crates.io
with `--features audio --locked` into `target/direwolf_interop/rustradio-0.20.2/`
and starts an isolated audio session, leaving desktop audio unchanged.
Set `BELL202_BIN` to use an already-built modem. `DIREWOLF_BIN` selects a
different Dire Wolf executable. No sibling checkout is needed.
Logs and captures remain under `target/direwolf_interop/` for inspection.

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

Also see:
* [Examining Ambiguities in the Automatic Packet Reporting
  System](https://digitalcommons.calpoly.edu/cgi/viewcontent.cgi?article=2449&context=theses)
* Check [Direwolf
  implementation](https://github.com/wb2osz/direwolf/blob/master/src/ax25_link.c)
  "Erratum" comments.

## Misc

* [PR for wireshark to decode extended
  mode](https://gitlab.com/wireshark/wireshark/-/merge_requests/17121)
