#!/bin/bash
# usage: run.sh <host ns> <client ns>
BIN=$(cd "$(dirname "$0")/../.." && pwd)/target/release/examples/natlab
CODE=$(shuf -i 100000000-999999999 -n1)
ARGS="mqtt://203.0.113.254:1883 203.0.113.100:3478 203.0.113.101:3478"
ip netns exec $1 $BIN host $CODE $ARGS > /tmp/natlab_host.txt 2>&1 &
HP=$!
sleep 1.5
ip netns exec $2 $BIN client $CODE $ARGS > /tmp/natlab_client.txt 2>&1
C=$?
wait $HP; H=$?
echo "== host($1) exit $H"; grep -E "punch|received|rtt|FAILED|candidates" /tmp/natlab_host.txt | cut -c1-260
echo "== client($2) exit $C"; grep -E "punch|received|rtt|FAILED|candidates" /tmp/natlab_client.txt | cut -c1-260
