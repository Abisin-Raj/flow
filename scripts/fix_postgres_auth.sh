#!/bin/bash
set -e

PG_DATA="/var/lib/pgsql/data"
HBA_FILE="$PG_DATA/pg_hba.conf"

# Use sudo to check for file existence because permissions on /var/lib/pgsql/data are restricted
echo "Checking for $HBA_FILE..."
if ! sudo test -f "$HBA_FILE"; then
    echo "Error: Could not find $HBA_FILE even with sudo privileges."
    echo "Double check that PostgreSQL is initialized and installed."
    # Try to find it via find command if typical location fails, just in case? 
    # No, keep it simple for now. 
    exit 1
fi

echo "Backing up $HBA_FILE..."
sudo cp "$HBA_FILE" "$HBA_FILE.bak.$(date +%s)"

echo "Modifying pg_hba.conf to allow password authentication..."
# We use sudo tee to write safely if needed, but sed -i works with sudo usually.
# Update IPv4 local connections from ident to scram-sha-256
sudo sed -i -E 's/(host\s+all\s+all\s+127\.0\.0\.1\/32\s+)ident/\1scram-sha-256/' "$HBA_FILE"
# Update IPv6 local connections from ident to scram-sha-256
sudo sed -i -E 's/(host\s+all\s+all\s+::1\/128\s+)ident/\1scram-sha-256/' "$HBA_FILE"

echo "Restarting PostgreSQL service..."
sudo systemctl restart postgresql

echo "Authentication configuration updated. You should now be able to connect with a password."
