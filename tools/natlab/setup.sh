#!/bin/bash
# usage: setup.sh <natA: easy|hard> <natB: easy|hard> [fw|nofw]
# fw (default): routers drop unsolicited WAN input like real home routers.
set -e
cleanup() { for n in inet rA hA rB hB; do ip netns del $n 2>/dev/null || true; done; }
cleanup
for n in inet rA hA rB hB; do ip netns add $n; ip netns exec $n ip link set lo up; done
ip netns exec inet ip link add br0 type bridge
ip netns exec inet ip addr add 203.0.113.254/24 dev br0
ip netns exec inet ip addr add 203.0.113.100/24 dev br0
ip netns exec inet ip addr add 203.0.113.101/24 dev br0
ip netns exec inet ip link set br0 up
mk() { # router side, wan ip, lan net, host ns, nat kind
  R=$1; WAN=$2; LAN=$3; H=$4; KIND=$5; PEER=$6
  ip link add ${R}w type veth peer name ${R}wi
  ip link set ${R}w netns $R; ip link set ${R}wi netns inet
  ip netns exec inet ip link set ${R}wi master br0; ip netns exec inet ip link set ${R}wi up
  ip netns exec $R ip addr add $WAN/24 dev ${R}w; ip netns exec $R ip link set ${R}w up
  ip link add ${R}l type veth peer name ${H}e
  ip link set ${R}l netns $R; ip link set ${H}e netns $H
  ip netns exec $R ip addr add $LAN.1/24 dev ${R}l; ip netns exec $R ip link set ${R}l up
  ip netns exec $H ip addr add $LAN.2/24 dev ${H}e; ip netns exec $H ip link set ${H}e up
  ip netns exec $H ip route add default via $LAN.1
  ip netns exec $R sysctl -qw net.ipv4.ip_forward=1
  if [ "$FW" != nofw ]; then
    ip netns exec $R iptables -A INPUT -i ${R}w -m conntrack --ctstate NEW,INVALID -j DROP
    ip netns exec $R iptables -A FORWARD -i ${R}w -m conntrack --ctstate NEW,INVALID -j DROP
  fi
  if [ "$KIND" = hard ]; then
    ip netns exec $R iptables -t nat -A POSTROUTING -o ${R}w -j MASQUERADE --random-fully
  elif [ "$KIND" = oneway ]; then
    # Looks "easy" to STUN (full-cone port for the STUN mapping) but maps traffic towards the
    # peer to a random port: the peer hears us, we never hear the peer back (seen in the field).
    ip netns exec $R iptables -t nat -A PREROUTING -i ${R}w -p udp --dport 47810 -j DNAT --to-destination $LAN.2:47810
    ip netns exec $R iptables -t nat -A POSTROUTING -o ${R}w -d $PEER -j MASQUERADE --random-fully
    ip netns exec $R iptables -t nat -A POSTROUTING -o ${R}w -j MASQUERADE
    ip netns exec $R iptables -I FORWARD -i ${R}w -m conntrack --ctstate DNAT -j ACCEPT
  else
    ip netns exec $R iptables -t nat -A POSTROUTING -o ${R}w -j MASQUERADE
  fi
}
FW=${3:-fw}
mk rA 203.0.113.1 10.1.0 hA $1 203.0.113.2
mk rB 203.0.113.2 10.2.0 hB $2 203.0.113.1
echo "lab ready: A=$1 B=$2"
