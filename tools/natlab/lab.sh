#!/bin/bash
# usage: lab.sh <natA easy|hard> <natB easy|hard>   (A = host, B = client)
D=$(dirname $(readlink -f $0))
for f in $D/stun.pid $D/mosq.pid; do [ -f $f ] && kill $(cat $f) 2>/dev/null; done
sleep 0.3
$D/setup.sh $1 $2 $3 >/dev/null
ip netns exec inet python3 $D/stun_server.py 203.0.113.100 203.0.113.101 >/dev/null 2>&1 &
echo $! > $D/stun.pid
ip netns exec inet mosquitto -c $D/mosq.conf >/dev/null 2>&1 &
echo $! > $D/mosq.pid
sleep 0.8
echo "######## host NAT=$1  client NAT=$2  firewall=${3:-fw}"
$D/run.sh hA hB
