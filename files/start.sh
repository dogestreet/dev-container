#!/usr/bin/env bash

set -xue

./net-conf.sh
cd /home/user && sudo -u user -- env XDG_RUNTIME_DIR=/tmp XDG_BACKEND=wayland XDG_SESSION_TYPE=wayland XDG_SESSION_ID=1 WAYLAND_DISPLAY=wayland-1 PULSE_SERVER=unix:/tmp/pulseaudio.sock /usr/bin/dbus-launch bash
