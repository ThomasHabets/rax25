#!/usr/bin/env bash
#
# Hacky script that sets up a kernel AX.25 environment behind a KISS
# serial port. That serial port is then meant to be used by rax25 for
# interoperation testing.

set -ueo pipefail

sudo pkill kissattach || true
pkill socat || true
pkill axshd ||true
sleep 0.1

SOCATOUT="$(mktemp)"
socat -d -d pty,rawer,echo=0 pty,rawer,echo=0 2> "${SOCATOUT}" &
SOCAT=$!

sleep 0.2
PTY1="$(grep 'PTY is ' "$SOCATOUT" | head -1 | sed 's/.* //g')"
PTY2="$(grep 'PTY is ' "$SOCATOUT" | tail -1 | sed 's/.* //g')"
sudo kissattach "$PTY1" radio1
sudo kissparms -p radio1 -c 1
ln -fs "$PTY2" $HOME/tmp/rax25.serial

sleep 0.1
LD_LIBRARY_PATH=$HOME/opt/gcc/lib64/ $HOME/scm/axsh/ax25/axsh/axshd  -r radio1 -s M0THC-2 > /dev/null 2>/dev/null &
AXSHD=$!

sudo axlisten -cart
kill $SOCAT || true
kill $AXSHD || true
sudo pkill kissattach || true
wait $SOCAT || true
wait $AXSHD || true
