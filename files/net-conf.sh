#!/usr/bin/env bash
set -xue

if ip link show dummy0 &> /dev/null; then
    echo 'Network already provisioned'
    exit 0
fi

nft -f nft.conf

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv4.conf.all.route_localnet=1

ip rule add fwmark 1088 table 100
ip route add local default dev lo table 100

# Dummy device to set default gateway
ip link add dummy0 type dummy
ip link set dummy0 up
ip addr add 10.0.0.1/24 dev dummy0
ip route add default via 10.0.0.2 dev dummy0
/tproxy/tproxy -listen 0.0.0.0:1088 -socket /net/tproxy.sock &>/dev/null & disown
