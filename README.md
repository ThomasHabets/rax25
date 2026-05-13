# rax25

Rust library for AX.25 connected mode.

https://github.com/ThomasHabets/rax25
https://blog.habets.se/2024/09/An-AX.25-implementation-in-Rust.html

## Status

* Seem to be working well.
* Both 8 and 128 modulus supported.
* REJ untested / probably broken.
* SREJ untested / probably broken.
* Segmentation: not implemented.
* The sync API is not great. Async API may also need some work

Interoperability with linux kernel stack is lightly tested on every
push to github.

## Technical details

* The reserved bit used by the Linux kernel (and other Linux tools,
  like `axlisten`) to indicate extended sequence numbers is set. This
  crate sets it too, but since we know the connection state, it's
  ignored on reception.

## Testing

The easiest test setup is to simply use a "bent pipe" TCP socket that both ends
connect to. That way it's fast, doesn't lose any packets, and doesn't require
any hardware.

This will do it:

```shell
while true; do socat TCP-LISTEN:10000,reuseaddr TCP-LISTEN:10001,reuseaddr;sleep 1;done
```

After that you can run a server and client like:

```shell
cargo run --example async_server -- -v 10 -p tcp://127.0.0.1:10000 -s M0QQQ-1 --capture server.pcap
cargo run --example async_client -- -v 10 -p tcp://127.0.0.1:10001 -s M0QQQ-2 --capture client.pcap -e M0QQQ-1
```

## Reference documentation

* [1998 spec](https://www.tapr.org/pdf/AX25.2.2.pdf). Page annotations
  in code are in reference to this doc.
* [2006 spec update](http://www.ax25.net/AX25.2.2-Jul%2098-2.pdf), which
  despite its name and title page, is actually from 2006.
* [2017 spec update](https://wiki.oarc.uk/_media/packet:ax25.2.2.10.pdf)
* [isomer's spec
  findings](https://github.com/isomer/ax25embed/blob/main/ax25/ax25_dl.c)
* [Examining Ambiguities in the Automatic Packet Reporting
  System](https://digitalcommons.calpoly.edu/cgi/viewcontent.cgi?article=2449&context=theses)
* Check [Direwolf
  implementation](https://github.com/wb2osz/direwolf/blob/master/src/ax25_link.c)
  "Erratum" comments.

## Misc

* [PR for wireshark to decode extended
  mode](https://gitlab.com/wireshark/wireshark/-/merge_requests/17121)
