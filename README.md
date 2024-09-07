# rax25

Rust library for AX.25 connected mode.

https://github.com/ThomasHabets/rax25
https://blog.habets.se/2024/09/An-AX.25-implementation-in-Rust.html

## Status

* AX.25 2.0 parts implemented, and seem to be working well.
* Both 8 and 128 modulus supported.
* REJ untested / probably broken.
* SREJ untested / probably broken.
* The API is not great.
* No support yet for server side.

Interoperability with linux kernel stack is lightly tested on every push to
github.

## Technical details

* The reserved bit used by the Linux kernel (and other Linux tools, like
  `axlisten`) to indicate extended sequence numbers is both set and assumed
  set, here. The other reserved bit that Linux sets for mod-8 is not set or
  interpreted here.

## Reference documentation

* [1998 spec](https://www.tapr.org/pdf/AX25.2.2.pdf). Page annotations in code
  are in reference to this doc.
* [2017 update of spec](https://wiki.oarc.uk/_media/packet:ax25.2.2.10.pdf)
* [isomer's spec findings](https://github.com/isomer/ax25embed/blob/main/ax25/ax25_dl.c)
* [Examining Ambiguities in the Automatic Packet Reporting System](https://digitalcommons.calpoly.edu/cgi/viewcontent.cgi?article=2449&context=theses)

## Misc

* [PR for wireshark to decode extended mode](https://gitlab.com/wireshark/wireshark/-/merge_requests/17121)
