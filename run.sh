#!/usr/bin/env bash
set -ue

./tproxy/tproxy -mode server --socket ./net/tproxy.sock &>/dev/null &

# Cleanup on exit
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT
sudo runc --root runc-state run dev-container
