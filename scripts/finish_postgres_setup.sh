#!/bin/bash
set -e

echo "Starting PostgreSQL Service..."
# Attempt to start, if it fails we will see why.
sudo systemctl enable postgresql
sudo systemctl start postgresql
sudo systemctl status postgresql --no-pager

echo "Configuring User and Database..."
# Build the commands
# We use || true to not fail if they already exist

sudo -u postgres psql -c "CREATE USER flowuser WITH PASSWORD 'flowpass';" || echo "User creation warning (might exist)"
sudo -u postgres psql -c "CREATE DATABASE flowdb OWNER flowuser;" || echo "DB creation warning (might exist)"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE flowdb TO flowuser;"
echo "PostgreSQL setup steps completed."
