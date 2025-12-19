#!/bin/bash
set -e
echo "Updating password for flowuser..."
sudo -u postgres psql -c "ALTER USER flowuser WITH PASSWORD 'flowpass';"
echo "Password updated."
