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
    dnf install -y nftables python3-pip libcap polkit rsync gcc gcc-c++ python3-devel cmake libpq-devel net-tools postgresql-server postgresql-contrib
elif [[ "$OS" == "debian" || "$OS" == "ubuntu" || "$OS" == "linuxmint" || "$OS" == "pop" ]]; then
    echo "Detected Debian/Ubuntu (apt)"
    apt-get update
    apt-get install -y nftables python3-venv python3-pip libcap2-bin policykit-1 rsync build-essential python3-dev cmake libpq-dev net-tools postgresql postgresql-contrib
elif [[ "$OS" == "arch" || "$OS" == "manjaro" ]]; then
    echo "Detected Arch Linux (pacman)"
    pacman -Sy --noconfirm nftables python-pip libcap polkit rsync base-devel cmake postgresql-libs net-tools postgresql
elif command -v dnf >/dev/null; then
    echo "Fallback: Detected dnf"
    dnf install -y nftables python3-pip libcap polkit rsync gcc gcc-c++ python3-devel cmake libpq-devel net-tools postgresql-server postgresql-contrib
elif command -v apt-get >/dev/null; then
    echo "Fallback: Detected apt-get"
    apt-get update
    apt-get install -y nftables python3-venv python3-pip libcap2-bin policykit-1 rsync build-essential python3-dev cmake libpq-dev net-tools postgresql postgresql-contrib
elif command -v pacman >/dev/null; then
    echo "Fallback: Detected pacman"
    pacman -Sy --noconfirm nftables python-pip libcap polkit rsync base-devel cmake postgresql-libs net-tools postgresql
else
    echo "Unsupported package manager. Please install dependencies manually."
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
# 7. Initialize Database
echo "Configuring PostgreSQL..."

# Identify the service name (usually 'postgresql')
PG_SERVICE="postgresql"

# Initialize DB if necessary (Fedora/RHEL/CentOS specific)
if command -v postgresql-setup >/dev/null; then
    if [ ! -d "/var/lib/pgsql/data/base" ]; then
        echo "Initializing PostgreSQL database..."
        postgresql-setup --initdb || echo "Initdb failed or already initialized."
    fi
fi

# Configure pg_hba.conf to allow password auth for flowuser
# This fixes "Ident authentication failed" errors on Fedora/RHEL
echo "Checking PostgreSQL authentication configuration..."
PG_HBA=""
if [ -f "/var/lib/pgsql/data/pg_hba.conf" ]; then
    PG_HBA="/var/lib/pgsql/data/pg_hba.conf"
elif [ -d "/etc/postgresql" ]; then
    # Best effort find for Debian/Ubuntu
    PG_HBA=$(find /etc/postgresql -name pg_hba.conf 2>/dev/null | head -n 1)
fi

if [ -n "$PG_HBA" ]; then
    echo "Found pg_hba.conf at $PG_HBA"
    if ! grep -q "flowuser" "$PG_HBA"; then
        echo "Adding password auth rule for flowuser..."
        # Keep a backup
        cp "$PG_HBA" "$PG_HBA.bak"
        # Insert at the top to ensure precedence over generic rules
        sed -i '1i # Flow Application Rules' "$PG_HBA"
        sed -i '2i host    flowdb          flowuser                127.0.0.1/32            scram-sha-256' "$PG_HBA"
        sed -i '3i host    flowdb          flowuser                ::1/128                 scram-sha-256' "$PG_HBA"
        
        NEED_RELOAD=true
    else
        echo "Rule for flowuser already exists in pg_hba.conf"
    fi
else
    echo "Warning: Could not find pg_hba.conf. You may need to manually configure password authentication for user 'flowuser'."
fi

# Enable and start service
echo "Starting PostgreSQL service..."
systemctl enable "$PG_SERVICE"
systemctl start "$PG_SERVICE"

if [ "$NEED_RELOAD" = true ]; then
    echo "Reloading PostgreSQL to apply auth changes..."
    systemctl reload "$PG_SERVICE"
fi

# Create User and Database
# We switch to postgres user to run psql commands
echo "Creating database user 'flowuser' and database 'flowdb'..."

# Create user if not exists
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname = 'flowuser'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER flowuser WITH PASSWORD 'flowpass';"

# Create db if not exists
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = 'flowdb'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE flowdb OWNER flowuser;"

# Grant privileges (just to be safe)
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE flowdb TO flowuser;"
# Grant CREATEDB to allow running tests (which create a test database)
sudo -u postgres psql -c "ALTER USER flowuser CREATEDB;"
# For Postgres 15+ we might need to grant schema usage
sudo -u postgres psql -d flowdb -c "GRANT ALL ON SCHEMA public TO flowuser;" || true

if [ "$RESET_DB" = true ]; then
  echo "Resetting database..."
  sudo -u postgres psql -c "DROP DATABASE IF EXISTS flowdb;"
  sudo -u postgres psql -c "CREATE DATABASE flowdb OWNER flowuser;"
  sudo -u postgres psql -d flowdb -c "GRANT ALL ON SCHEMA public TO flowuser;" || true
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


