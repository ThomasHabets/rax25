#!/usr/bin/env bash
#
# Hacky script to set up a test environment using Direwolf.
# Unfortunately direwolf doesn't bridge between AGW and KISS,
# so we have to set up a virtual audio cable between them.
# Set up virtual audio cable by running:
#   sudo modprobe snd-aloop
# And then in pavucontrol, in the Configuration tab, turn
# "Built-in audio" or whatever it's called "off".

set -ueo pipefail

DW_AGW=8010
DW_KISS=8011

pkill direwolf || true

sleep 0.1

direwolf -t 0 -c <(cat <<EOF
ADEVICE hw:1,1,1 hw:1,1,0
#CHANNEL 0
MYCALL M0THC-4
AGWPORT $DW_AGW
MODEM 9600
#V20 M0THC-2
NOXID M0THC-2
EOF
) &
DW1=$!

direwolf -p -t 0 -c <(cat <<EOF
ADEVICE hw:1,0,0 hw:1,0,1
#CHANNEL 0
MYCALL M0THC-5
#KISSPORT $DW_KISS
MODEM 9600
#V20 M0THC-2
EOF
) &
DW2=$!

# Waiting for child processes.
sigint() {
        true
}
trap sigint SIGINT
wait $DW1 || true
wait $DW2 || true
echo "Test fully shut down"
# TODO: start something listening.
