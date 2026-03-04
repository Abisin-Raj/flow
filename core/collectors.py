"""
Collectors Module.

This module is the data ingestion engine for network traffic.
It periodically polls system network state (via `ss`, `/proc/net`, or `netstat`),
parses the active connections, enriches them with process information (PID, name),
saves them to the `Connection` database, and evaluates them against alert rules.
"""

import subprocess
import time
import threading
import logging
import ipaddress
from datetime import timedelta

from django.utils import timezone
from django.db import close_old_connections, transaction

from core.models import Connection
from core.alert_engine import create_alert_for_connection
from core.process_tree import get_process_info
# Import /proc filesystem parser for broader network visibility
from core.proc_net_parser import parse_proc_net
# from core import app_settings as cfg  # Removed: app_settings.py deleted
from core import settings_api as cfg  # Use settings_api instead
log = logging.getLogger("core.collectors")

try:
    from core.rare_port_detector import handle_connection as rare_port_handle
except Exception as e:
    log.warning("Failed to import rare_port_detector: %s", e)
    rare_port_handle = None

# Optional detector imports (guarded, so missing modules do not break the app)
try:
    from core.light_sniffer import start_light_sniffer
except Exception as e:
    log.warning("Failed to import light_sniffer: %s", e)
    start_light_sniffer = None

# rare_port_detector is event-driven via handle_connection, no background thread needed

# ARP collector is deprecated in favor of detector
start_arp_mitm_collector = None

try:
    from core.arp_mitm_detector import start_arp_mitm_detector
except Exception as e:
    log.warning("Failed to import start_arp_mitm_detector: %s", e)
    start_arp_mitm_detector = None


try:
    from core.rev_shell_detector import start_rev_shell_detector
except Exception as e:
    log.warning("Failed to import rev_shell_detector: %s", e)
    start_rev_shell_detector = None

try:
    from core.dns_monitor import start_dns_monitor
except Exception as e:
    log.warning("Failed to import dns_monitor: %s", e)
    start_dns_monitor = None

try:
    from core.persistence_watcher import start_persistence_watcher
except Exception as e:
    log.warning("Failed to import persistence_watcher: %s", e)
    start_persistence_watcher = None

try:
    from core.tx_spike_detector import start_tx_spike_detector
except Exception as e:
    log.warning("Failed to import tx_spike_detector: %s", e)
    start_tx_spike_detector = None


def find_pid_for_connection(src_ip, src_port, dst_ip, dst_port):
    """
    Try to map a 4-tuple to a PID using ss first, then /proc/net/tcp fallback.
    Returns PID or None.
    """
    import re
    import os
    
    # Try ss first (faster)
    try:
        cmd = ["ss", "-tnp", "state", "established"]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        for line in out.splitlines():
            if f"{src_ip}:{src_port}" in line and f"{dst_ip}:{dst_port}" in line:
                m = re.search(r"pid=(\d+)", line)
                if m:
                    return int(m.group(1))
    except Exception:
        pass

    # Fallback: scan /proc/net/tcp for local/remote hex tuples then map inode -> pid
    try:
        def ipport_to_hex(ip, port):
            import socket
            packed = socket.inet_aton(ip)
            hexip = "".join("{:02X}".format(b) for b in packed[::-1])  # little endian
            hexport = "{:04X}".format(int(port))
            return hexip, hexport

        lhex, lport = ipport_to_hex(src_ip, src_port)
        rhex, rport = ipport_to_hex(dst_ip, dst_port)

        with open("/proc/net/tcp", "r") as f:
            lines = f.readlines()[1:]
        for ln in lines:
            parts = ln.split()
            local, remote = parts[1], parts[2]
            local_ip, local_p = local.split(":")
            remote_ip, remote_p = remote.split(":")
            if local_ip == lhex and local_p == lport and remote_ip == rhex and remote_p == rport:
                inode = parts[9]
                # Find pid by inode
                for pid in os.listdir("/proc"):
                    if not pid.isdigit():
                        continue
                    fd_dir = f"/proc/{pid}/fd"
                    try:
                        for fd in os.listdir(fd_dir):
                            try:
                                target = os.readlink(f"{fd_dir}/{fd}")
                                if "socket:[" in target and inode in target:
                                    return int(pid)
                            except Exception:
                                continue
                    except Exception:
                        continue
    except Exception:
        pass

    return None


