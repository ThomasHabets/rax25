# rax25

Rust library for AX.25 connected mode.

https://github.com/ThomasHabets/rax25

## Status

* AX.25 2.0 parts implemented, and seem to be working well.
* Both 8 and 128 modulus supported.
* REJ untested / probably broken.
* SREJ untested / probably broken.
* The API is not great.
* No support yet for server side.

## Technical details

* The reserved bit used by the Linux kernel (and other Linux tools, like
  `axlisten`) to indicate extended sequence numbers is both set and assumed
  set, here. The other reserved bit that Linux sets for mod-8 is not set or
  interpreted here.

## Reference documentation

* https://www.tapr.org/pdf/AX25.2.2.pdf
* Examining Ambiguities in the Automatic Packet Reporting System.pdf
