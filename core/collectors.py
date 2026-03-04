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


def get_proc_name_from_pid(pid):
    """
    Get process name from PID using /proc/{pid}/exe or /proc/{pid}/comm.
    """
    import os
    if not pid:
        return None
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
        return os.path.basename(exe)
    except Exception:
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                return f.read().strip()
        except Exception:
            return None


def create_attributed_alert(src_ip, src_port, dst_ip, dst_port, message, severity="medium", **kwargs):
    """
    Find process that owns the connection and either skip alert or attach proc name.
    
    This helps in reducing false positives by checking if the process is ignored
    before raising an alert.

    Args:
        src_ip (str): Source IP.
        src_port (int): Source Port.
        dst_ip (str): Destination IP.
        dst_port (int): Destination Port.
        message (str): Alert message.
        severity (str): Alert severity.
        **kwargs: Extra arguments for `create_alert_for_connection`.

    Returns:
        Alert or None: Created alert or None if skipped/failed.
    """
    try:
        pid = find_pid_for_connection(src_ip, src_port, dst_ip, dst_port)
        proc_name = get_proc_name_from_pid(pid) if pid else None
    except Exception:
        proc_name = None

    if proc_name and cfg.is_process_ignored_name(proc_name):
        log.info("Skipping alert for ignored process %s pid=%s", proc_name, pid)
        return None

    # Import here to avoid circular imports at module import time
    from core.alert_engine import create_alert_for_connection

    try:
        return create_alert_for_connection(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            message=message,
            severity=severity,
            proc_name=proc_name,
            **kwargs,
        )
    except Exception:
        log.exception("Failed to create attributed alert for %s:%s -> %s:%s", src_ip, src_port, dst_ip, dst_port)
        return None




def start_connection_collector():
    t = threading.Thread(target=connection_collector_loop, daemon=True)
    t.start()


def start_maintenance_thread():
    """Starts a background thread for periodic maintenance tasks."""
    t = threading.Thread(target=maintenance_loop, daemon=True)
    t.start()


def maintenance_loop(interval=60):
    """
    Loop that runs maintenance tasks every `interval` seconds.
    """
    from core.maintenance import run_all_maintenance
    from django.db import close_old_connections

    while True:
        try:
            run_all_maintenance()
        except Exception as e:
            log.warning("Maintenance task failed: %s", e)
        finally:
            close_old_connections()
        time.sleep(interval)

def parse_ss_output():
    """
    Run: ss -tnp state established
    Parse output into list of dicts.
    Superior to netstat as it is modern and standard on Linux.
    """
    import re
    try:
        # -t: tcp, -u: udp, -w: raw (icmp), -x: unix, -S: sctp, -n: numeric, -p: processes, -a: all
        cmd = ["ss", "-tunpwS", "-a"]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except Exception as e:
        log.warning("parse_ss_output failed: %s", e)
        return []

    lines = output.strip().splitlines()
    results = []

    # Skip header if present
    start_idx = 0
    if lines and "Recv-Q" in lines[0]:
        start_idx = 1

    for line in lines[start_idx:]:
        parts = line.split()
        if len(parts) < 4:
            continue

        # Default fallback values
        protocol = "tcp"
        state = "ESTABLISHED"
        
        # Check for Netid column (tcp, udp, raw, p_dgr, etc.)
        # With -tunp -a, output is: Netid State Recv-Q Send-Q Local Peer Process
        if parts[0] in ("tcp", "udp", "raw", "p_raw", "p_dgr", "icmp", "icmp6"):
            protocol = parts[0]
            if len(parts) > 1:
                state = parts[1]
                
            # Indices for Netid presence
            # [Netid, State, RecvQ, SendQ, Local, Peer, Process...]
            local_idx = 4
            remote_idx = 5
        else:
            # Fallback for older ss versions or different column layouts without Netid explicitly first
            # Check if first column is a state string or a number
            first_col_is_state = False

            if parts[0].isdigit():
                 first_col_is_state = False
            elif parts[0] in ("ESTAB", "LISTEN", "UNCONN", "TIME-WAIT", "CLOSE-WAIT", "SYN-SENT", "SYN-RECV", "FIN-WAIT-1", "FIN-WAIT-2", "CLOSE", "CLOSING", "LAST-ACK"):
                 first_col_is_state = True
                 state = parts[0]
            else:
                 # Heuristic: if it looks like an IP, definitely not state
                 if "." in parts[0] or ":" in parts[0]:
                      first_col_is_state = False
                 else:
                      # Assume state if it's a word
                      first_col_is_state = not parts[0].isdigit()
                      if first_col_is_state:
                          state = parts[0]

            # Indices based on column presence
            if first_col_is_state:
                 # [State, RecvQ, SendQ, Local, Peer, Process...]
                 local_idx = 3
                 remote_idx = 4
            else:
                 # [RecvQ, SendQ, Local, Peer, Process...]
                 local_idx = 2
                 remote_idx = 3
             
        if len(parts) <= remote_idx:
             continue

        try:
            local = parts[local_idx]
            remote = parts[remote_idx]
            
            # Use regex to find PID info which might be anywhere in the line
            # Format: users:(("name",pid=123,fd=4))
            pid = None
            proc_name = ""
            
            if "users:" in line:
                m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
                if m:
                    proc_name = m.group(1)
                    pid = int(m.group(2))
            
            results.append({
                "protocol": protocol,
                "local_address": local,
                "remote_address": remote,
                "state": state,
                "pid": pid,
                "process_name": proc_name,
            })
        except Exception:
            continue
            
    return results


def parse_netstat_output():
    """
    Run: netstat -tunp
    Parse output into a list of dicts.
    
    Note: netstat -tunp shows process info only with root or CAP_NET_ADMIN.
    Without that, process column stays empty, but parsing still works.
    """
    try:
        output = subprocess.check_output(
            ["netstat", "-tunp"], stderr=subprocess.DEVNULL
        ).decode()
    except Exception as e:
        log.warning("parse_netstat_output failed: %s", e)
        return []

    lines = output.strip().splitlines()
    results = []

    for line in lines:
        if not (line.startswith("tcp") or line.startswith("udp")):
            continue

        parts = line.split()
        if len(parts) < 6:
            continue

        proto = parts[0]
        local = parts[3]
        remote = parts[4]

        if proto.startswith("tcp"):
            state = parts[5]
        else:
            state = "LISTEN"

        # PID/Program name is usually the last column, e.g. "1234/python"
        # It might be missing if not root
        pid_prog = parts[6] if len(parts) > 6 else "-"
        pid = None
        proc_name = ""

        if pid_prog not in ("-", "0"):
            pid_str, _, name = pid_prog.partition("/")
            try:
                pid = int(pid_str)
            except ValueError:
                pid = None
            proc_name = name or ""

        results.append(
            {
                "protocol": proto,
                "local_address": local,
                "remote_address": remote,
                "state": state,
                "pid": pid,
                "process_name": proc_name,
            }
        )

