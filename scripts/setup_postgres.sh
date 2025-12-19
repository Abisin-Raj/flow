#!/bin/bash
set -e

# Step 1. Install PostgreSQL
echo "Installing PostgreSQL..."
sudo dnf install -y postgresql-server postgresql-contrib

echo "Initializing Database..."
# Only init if not already existing
if [ ! -d "/var/lib/pgsql/data/base" ]; then
    sudo postgresql-setup --initdb
else
    echo "Data directory appears populated. Skipping initdb."
fi

echo "Starting PostgreSQL..."
sudo systemctl enable postgresql
sudo systemctl start postgresql

# Step 2. Configure User and DB
echo "Configuring User and Database..."
# Run psql commands as postgres user
sudo -u postgres psql -c "CREATE USER flowuser WITH PASSWORD 'flowpass';" || echo "User flowuser might already exist."
sudo -u postgres psql -c "CREATE DATABASE flowdb OWNER flowuser;" || echo "Database flowdb might already exist."
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE flowdb TO flowuser;"

echo "PostgreSQL setup complete."
