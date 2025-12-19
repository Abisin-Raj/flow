#!/bin/bash
set -e

# create runtime dirs
mkdir -p /opt/flow
mkdir -p /var/log/flow
chown -R root:root /opt/flow
chown -R root:root /opt/flow
chmod 0755 /opt/flow

# set up virtualenv
if [ ! -d /opt/flow/venv ]; then
    echo "Creating virtual environment in /opt/flow/venv..."
    python3 -m venv /opt/flow/venv
fi

# install dependencies
if [ -f /opt/flow/requirements.txt ]; then
    echo "Installing dependencies..."
    /opt/flow/venv/bin/pip install --upgrade pip
    /opt/flow/venv/bin/pip install -r /opt/flow/requirements.txt
fi

# install launcher (force update)
cat > /usr/local/bin/flow <<'EOS'
#!/bin/bash
APP_PY="/opt/flow/desktop_front/start_flow.py"
PY_BIN="/opt/flow/venv/bin/python3"
USER_UID=$(id -u)
DBUS_ADDR="unix:path=/run/user/${USER_UID}/bus"
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-$DBUS_ADDR}"
if [ "$EUID" -ne 0 ]; then
    exec sudo DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" "$PY_BIN" "$APP_PY"
else
    exec "$PY_BIN" "$APP_PY"
fi
EOS
chmod 0755 /usr/local/bin/flow

# enable systemd service
if command -v systemctl >/dev/null 2>&1; then
    cp /opt/flow/packaging/flow.service /etc/systemd/system/flow.service || true
    systemctl daemon-reload || true
    systemctl enable flow.service || true
fi
