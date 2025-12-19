#!/usr/bin/env bash
set -e

# 1. Must run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script with sudo"
  exit 1
fi

RESET_DB=false
for arg in "$@"; do
  case $arg in
    --reset-db)
      RESET_DB=true
      shift
      ;;
  esac
done

# 2. Install System Dependencies
echo "Installing system dependencies..."

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
fi

if [[ "$OS" == "fedora" || "$OS" == "rhel" || "$OS" == "centos" ]]; then
    echo "Detected Fedora/RHEL (dnf)"
    dnf install -y nftables python3-pip libcap polkit rsync gcc gcc-c++ python3-devel cmake libpq-devel net-tools
elif [[ "$OS" == "debian" || "$OS" == "ubuntu" || "$OS" == "linuxmint" || "$OS" == "pop" ]]; then
    echo "Detected Debian/Ubuntu (apt)"
    apt-get update
    apt-get install -y nftables python3-venv python3-pip libcap2-bin policykit-1 rsync build-essential python3-dev cmake libpq-dev net-tools
elif [[ "$OS" == "arch" || "$OS" == "manjaro" ]]; then
    echo "Detected Arch Linux (pacman)"
    pacman -Sy --noconfirm nftables python-pip libcap polkit rsync base-devel cmake postgresql-libs net-tools
elif command -v dnf >/dev/null; then
    echo "Fallback: Detected dnf"
    dnf install -y nftables python3-pip libcap polkit rsync gcc gcc-c++ python3-devel cmake libpq-devel net-tools
elif command -v apt-get >/dev/null; then
    echo "Fallback: Detected apt-get"
    apt-get update
    apt-get install -y nftables python3-venv python3-pip libcap2-bin policykit-1 rsync build-essential python3-dev cmake libpq-dev net-tools
elif command -v pacman >/dev/null; then
    echo "Fallback: Detected pacman"
    pacman -Sy --noconfirm nftables python-pip libcap polkit rsync base-devel cmake postgresql-libs net-tools
else
    echo "Unsupported package manager. Please install 'nftables', 'python3-venv', and 'pip' manually."
fi

# 3. Paths
SRC_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
INSTALL_DIR="/opt/flow"

echo "Installing Flow from $SRC_DIR to $INSTALL_DIR"

# 4. Copy code to /opt/flow (exclude old venv if any)
mkdir -p "$INSTALL_DIR"
rsync -a --delete \
  --exclude 'venv' \
  --exclude '.git' \
  --exclude '__pycache__' \
  --exclude '*.sqlite3*' \
  "$SRC_DIR"/ "$INSTALL_DIR"/

# 5. Create venv in /opt/flow
cd "$INSTALL_DIR"
if [ ! -d "venv" ]; then
  echo "Creating virtualenv in $INSTALL_DIR/venv"
  python3 -m venv venv
fi

# 6. Install dependencies
echo "Installing Python dependencies into venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r requirements.txt

# 7. Initialize Database
echo "Initializing database..."
# Note: You must ensure PostgreSQL is running and the database 'flowdb' exists.
# The user configures connection details in core/settings.py or ENV vars.

# We don't delete sqlite files anymore as we use Postgres.
if [ "$RESET_DB" = true ]; then
  echo "Warning: --reset-db flag was passed but auto-reset for Postgres is not safe."
  echo "Please DROP and CREATE the database manually if you wish to wipe it."
fi
"$INSTALL_DIR/venv/bin/python" manage.py makemigrations core
"$INSTALL_DIR/venv/bin/python" manage.py migrate

# 8. Install launcher
echo "Installing launcher to /usr/local/bin/flow"
cp "$INSTALL_DIR/packaging/flow" /usr/local/bin/flow
chmod +x /usr/local/bin/flow

# 9. Install desktop file (optional, system-wide)
echo "Installing desktop file to /usr/share/applications/flow.desktop"
cp "$INSTALL_DIR/packaging/flow.desktop" /usr/share/applications/flow.desktop

# 9b. Install application icon
echo "Installing application icon to /usr/share/pixmaps/flow.png"
cp "$INSTALL_DIR/resources/icon.png" /usr/share/pixmaps/flow.png
chmod 644 /usr/share/pixmaps/flow.png

# 10. Create flow group for firewall helper access
echo "Creating 'flow' group for firewall helper access"
if ! getent group flow > /dev/null 2>&1; then
    groupadd -r flow
    echo "Created 'flow' group"
else
    echo "'flow' group already exists"
fi

# 11. Install firewall helper
echo "Installing firewall helper service"
mkdir -p /opt/flow-helper
cp "$INSTALL_DIR/core/firewall_helper.py" /opt/flow-helper/firewall_helper.py
chmod 644 /opt/flow-helper/firewall_helper.py

# Install helper wrapper script
cp "$INSTALL_DIR/packaging/flow-firewall-helper" /usr/bin/flow-firewall-helper
chmod 755 /usr/bin/flow-firewall-helper

# Install systemd service
cp "$INSTALL_DIR/packaging/flow-firewall.service" /etc/systemd/system/flow-firewall.service
chmod 644 /etc/systemd/system/flow-firewall.service

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable flow-firewall.service
systemctl restart flow-firewall.service


echo ""
echo "=========================================="
echo "Flow installed successfully to $INSTALL_DIR"
echo "=========================================="
echo ""
echo "✓ Flow UI launcher: /usr/local/bin/flow"
echo "✓ Desktop entry: /usr/share/applications/flow.desktop"
echo "✓ Application icon: /usr/share/pixmaps/flow.png"
echo "✓ Firewall helper service: flow-firewall.service"
echo ""
echo "IMPORTANT: Add users to the 'flow' group:"
echo "  sudo usermod -aG flow <username>"
echo "  (Users must log out and back in for group changes)"
echo ""
echo "Troubleshooting:"
echo "  - Check firewall: systemctl status flow-firewall.service"
echo ""
echo "Launch Flow via the application menu or run: flow"
echo ""


