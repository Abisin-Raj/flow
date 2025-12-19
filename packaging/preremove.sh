#!/bin/bash
set -e

# stop service
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop flow.service || true
    systemctl disable flow.service || true
    rm -f /etc/systemd/system/flow.service || true
    systemctl daemon-reload || true
fi

# remove launcher
rm -f /usr/local/bin/flow || true

# leave /opt/flow to allow manual backup
