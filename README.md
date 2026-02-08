# FLOW NETWORK MONITOR

Flow is a desktop focused network and endpoint monitor. It combines a Django backend with a PyQt6 desktop UI. It collects connection metadata, detects suspicious patterns, and scans files for known malware.

The app is designed for a single Linux machine. It is not a central SIEM. Think of it as a local SOC sidekick.

## FEATURES

Flow tracks network activity through netstat based polling and optional raw packet sniffing. It records connections in SQLite and shows them in the desktop UI.

An alert engine raises alerts for patterns such as high connection rate, port scans, reverse shell behavior, rare outbound ports, ARP anomalies and gateway poisoning.

A file scanner computes SHA256 and TLSH hashes, compares them against a local signature database, and can quarantine malicious files.

A folder watcher polls configured folders and scans new or modified files.

A dashboard and widgets show alerts, timelines, top attackers, connections, metrics and quarantine status.

You can export data to CSV via the Export tab and control background services via the Service Control tab (for testing).

Desktop notifications inform you when new high severity alerts appear.


## ARCHITECTURE

Backend is Django and PostgreSQL. Models live in `core.models`. The backend runs inside the desktop process and in management commands. There is no standalone web server for normal use.

Frontend is PyQt6 in `desktop_front`. `start_flow.py` sets up Django, launches collectors, and starts the Qt main window.

Collectors in `core.collectors` run background threads for connection collection and detectors. They store data in the database.

Detectors include light_sniffer, packet_sniffer, rare_port_detector, rev_shell_detector, rev_shell_blocker, ARP MITM and scan_detector.

File scanning code sits in `core.file_scanner` and `core.file_scan_service`. It records to `QuarantinedFile` and `MalwareSignature`.

## SETUP REQUIREMENTS

*   Linux system with `/proc` and `/proc/net` available.
*   Python 3.10 or newer.
*   PostgreSQL database server.
*   System packages that help: `python3`, `python3-venv`, build tools, `libffi` and `openssl` headers.
*   Python packages are listed in `requirements.txt`. Main ones are Django, PyQt6, geoip2, maxminddb, scapy, matplotlib, requests, pytest, ruff, mypy and bandit.
*   The MaxMind GeoLite2 database file should be present at `data/GeoLite2-City.mmdb`. You must agree to the MaxMind license to use that database.

## INSTALLATION

### Quick Install (Recommended)

Run the automated installer to set up Flow in `/opt/flow`:

```bash
sudo ./install.sh
```

This will:
1.  Install the application to `/opt/flow`.
2.  Set up a virtual environment with all dependencies.
3.  Create a desktop entry and launcher.
4.  Initialize a fresh database.

### Running the App

Once installed, you can launch Flow from your application menu ("Flow Network Monitor") or via terminal:

```bash
sudo flow
```



### Manual Development Setup

If you want to run the code directly from the source folder for development:

1.  Create and activate a virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3.  Run migrations:
    ```bash
    python manage.py migrate
    ```
4.  Start the app:
    ```bash
    python desktop_front/start_flow.py
    ```

## PERMISSIONS AND LINUX CAPABILITIES

Flow requires elevated privileges for certain features:
- **Packet sniffing**: Reading raw network packets requires `CAP_NET_RAW`
- **Firewall operations**: Managing nftables rules requires `CAP_NET_ADMIN`
- **Socket inspection**: Viewing all network connections requires privileges

### How Flow Handles Privileges

When installed via RPM, Flow uses **Linux capabilities** instead of requiring full root access. This is the professional, secure approach used by tools like Wireshark and tcpdump.

**After RPM installation**, capabilities are automatically applied:
```bash
getcap /usr/bin/flow
# Output: /usr/bin/flow = cap_net_raw,cap_net_admin+ep
```

With capabilities set, Flow runs without sudo and without password prompts. Simply launch it from your application menu or run:
```bash
flow
```

### Development Mode (Without RPM)

To run the application from source with full privileges (needed for packet sniffing):

```bash
sudo python desktop_front/start_flow.py
```


### Important Notes

- **Standard user mode**: Flow can run without privileges, but packet sniffing will be disabled. Connection monitoring via `/proc/net` still works.
- **Capabilities are lost on binary updates**: If you rebuild or update the Flow binary, you must reapply capabilities using `setcap`.
- **Security**: Capabilities provide only the specific permissions needed, not full root access. This is much safer than running with sudo.
- **Group membership**: After installation, users must be added to the `flow` group to use firewall features:
  ```bash
  sudo usermod -aG flow <username>
  ```
  Users must log out and back in for group changes to take effect.

## DETECTORS OVERVIEW

Connection based rules run in `core.collectors` and `core.alert_engine`. They look for high connection rate, port scans, SYN floods and suspicious ports.

Rare port detector tracks repeated outbound connections from a local host to uncommon ports on the Internet. It raises “Suspicious Outbound Port” alerts.

Reverse shell detector inspects the connection table for long lived connections to suspicious ports such as 4444 or 5555. Reverse shell blocker is an optional module that tries to kill processes behind such connections. It is aggressive and expects root access.

ARP detectors monitor `/proc/net/arp` and the routing table. They track the gateway MAC and warn if it changes. They also flag MAC addresses that claim many IPs on the same subnet.

The `light_sniffer` reads `/proc/net/tcp` and tracks `SYN_SENT` states. It now attributes outbound scans to the local host instead of the remote IP.

The raw packet sniffer reads Ethernet and IP headers using raw sockets. It is more precise but needs extra privileges. It is optional and fails safe if permissions are missing.

## FILE SCANNER AND QUARANTINE

File scanning entry point is `core.file_scan_service.scan_and_record`. It does the following:
*   Computes SHA256 and TLSH for the file.
*   Looks up in `MalwareSignature` for exact or fuzzy match.
*   If malicious it moves the file into `~/.flow_quarantine` and creates a `QuarantinedFile` record with hash, match type, distance and family.

The File Scanner tab in the UI lets you:
*   Run a one off scan on a chosen file.
*   View the quarantine list.
*   Restore a file from quarantine if you trust it.
*   Delete a file permanently from quarantine.

Watched folders are configured through the File Scanner widget. The folder watcher polls those paths and scans new or modified files.

By default Flow writes quarantine paths under your home directory. Paths are stored in the database so you can restore later.

## SETTINGS AND DATA STORAGE

Settings are stored in two places.
*   Static defaults live in `flow/settings.py` and `core/app_settings.py`.
*   Dynamic settings live in the `AppSetting` model and are accessed via `core.settings_api`. The Settings tab in the UI writes and reads those values.

Important directories:
*   Database file: `db.sqlite3` in the project directory.
*   Logs: `~/.flow_logs/app.log` and related files.
*   CSV exports: `~/.flow_exports`.
*   High severity CSV log: `~/.flow_csv`.
*   Quarantine: `~/.flow_quarantine`.

You should treat `db.sqlite3` and `~/.flow_quarantine` as sensitive. They show historical connections, alerts and paths to malware.

## TESTING AND VERIFICATION

Run Django checks.

```bash
python manage.py check
```

Run unit tests.

```bash
pytest -q
```


## KNOWN LIMITATIONS

*   Flow assumes a Linux machine with `/proc` and `netstat`. It is not tested on Windows or macOS.
*   Raw packet sniffing needs extra privileges and is disabled by default for normal users.
*   Fuzzy file matching does a linear scan over `MalwareSignature` entries. This is fine for a modest number of signatures. It will slow down if the database grows huge.
*   Folder watcher is polling based. Watching huge trees with a short interval can cause extra disk activity.
*   The old web based port scanner view is gated behind DEBUG. It is not intended for production use.

## SHIPMENT NOTES

For shipping the app you should:
*   Provide a short quick start in the README with the exact commands for your target distro.
*   Ship with DEBUG set to False and a sane `DJANGO_ALLOWED_HOSTS` default.
*   Mention clearly that root is not required, and that packet level features are optional and disabled without privileges.
*   Clarify license and attribution for GeoLite2 in the README or a separate LICENSES file.

## TROUBLESHOOTING

### Database Reset
If you encounter database errors or need a fresh start:

1.  Stop the application.
2.  Remove the database file:
    ```bash
    sudo rm /opt/flow/db.sqlite3
    ```
3.  Recreate the database structure:
    ```bash
    cd /opt/flow
    sudo venv/bin/python3 manage.py migrate
    ```
4.  Restart the application:
    ```bash
    sudo flow
    ```

### Capabilities Not Working

If Flow still asks for a password or packet sniffing doesn't work:

1. **Check if capabilities are set**:
   ```bash
   getcap /usr/bin/flow
   ```
   Expected output: `/usr/bin/flow = cap_net_raw,cap_net_admin+ep`

2. **If capabilities are missing**, reapply them:
   ```bash
   sudo setcap cap_net_raw,cap_net_admin+ep /usr/bin/flow
   ```

3. **Verify setcap is installed**:
   ```bash
   which setcap
   ```
   If not found, install libcap:
   ```bash
   sudo dnf install -y libcap  # Fedora/RHEL
   sudo apt install -y libcap2-bin  # Debian/Ubuntu
   ```

4. **After binary updates**: Capabilities are file-specific and lost when the binary is replaced. Rerun `setcap` after any Flow updates.




