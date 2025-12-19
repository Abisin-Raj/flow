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
    Use this wrapper from collectors where alerts are created for network connections.
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

def parse_ss_output():
    """
    Run: ss -tnp state established
    Parse output into list of dicts.
    Superior to netstat as it is modern and standard on Linux.
    """
    import re
    try:
        # -t: tcp, -n: numeric, -p: processes
        cmd = ["ss", "-tnp", "state", "established"]
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

        # Check if first column is a state string or a number
        # Known states: ESTAB, LISTEN, SYN-SENT, etc.
        # If it's a number, it's Recv-Q, meaning State column is hidden.
        first_col_is_state = False
        if parts[0].isdigit():
             first_col_is_state = False
        elif parts[0] in ("ESTAB", "LISTEN", "UNCONN", "TIME-WAIT", "CLOSE-WAIT", "SYN-SENT", "SYN-RECV", "FIN-WAIT-1", "FIN-WAIT-2", "CLOSE", "CLOSING", "LAST-ACK"):
             first_col_is_state = True
        else:
             # Heuristic: if it looks like an IP, definitely not state
             if "." in parts[0] or ":" in parts[0]:
                  first_col_is_state = False
             else:
                  # Assume state if it's a word
                  first_col_is_state = not parts[0].isdigit()

        # Indexes based on column presence
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
                "protocol": "tcp",
                "local_address": local,
                "remote_address": remote,
                "state": "ESTABLISHED",
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

    return results


def split_address(addr: str):
    """
    Split 'ip:port' into (ip, port_int).
    Handles '*:*' and '0.0.0.0:*'.
    """
    if addr in ("*:*", "0.0.0.0:*", ":::*"):
        return addr, 0

    ip, sep, port = addr.rpartition(":")
    if sep == "":
        return addr, 0

    try:
        port_int = int(port)
    except ValueError:
        port_int = 0

    return ip, port_int


@transaction.atomic
def save_connections(data_list):
    """
    Store parsed netstat entries into Connection.
    Also evaluate alert rules.
    """
    now = timezone.now()

    for entry in data_list:
        src_ip, src_port = split_address(entry["local_address"])
        dst_ip, dst_port = split_address(entry["remote_address"])

        try:
            ipaddress.ip_address(src_ip)
            ipaddress.ip_address(dst_ip)
        except ValueError:
            # log.debug("Skipping invalid IP pair: %s -> %s", src_ip, dst_ip)
            continue

        pid = entry.get("pid")
        process_name = entry.get("process_name") or ""
        ppid = None
        if pid:
            info = get_process_info(pid)
            if info:
                ppid = info.get("ppid") or None
                if not process_name:
                    process_name = info.get("name") or ""

        conn = Connection.objects.create(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=entry["protocol"],
            status=entry["state"],
            pid=pid,
            ppid=ppid,
            process_name=process_name,
        )

        # Check for rare outbound ports
        if rare_port_handle:
            try:
                rare_port_handle(
                    src_ip=conn.src_ip,
                    dst_ip=conn.dst_ip,
                    dst_port=conn.dst_port,
                    protocol=conn.protocol,
                )
            except Exception:
                log.exception(
                    "rare-port detector failed for connection id=%s",
                    getattr(conn, "id", None),
                )

        try:
            evaluate_alert_rules(conn, now)
        except Exception:
            continue


def evaluate_alert_rules(conn: Connection, now):
    """
    Alert logic using thresholds from app_settings.
    Demo mode gently lowers thresholds.
    """
    if not conn.src_ip:
        return

    # Check if this connection is from an ignored process
    try:
        pid = find_pid_for_connection(
            conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port
        )
        proc_name = get_proc_name_from_pid(pid) if pid else None
        if proc_name and cfg.is_process_ignored_name(proc_name):
            log.info(
                "Skipping alert for connection owned by ignored process %s (pid=%s)",
                proc_name, pid
            )
            return
    except Exception as e:
        log.debug("Process attribution check failed: %s", e)

    settings = cfg.get_detector_settings()
    if cfg.DEMO_MODE:
        high_rate_limit = max(5, settings["high_rate_limit"] // 4)
        high_rate_window = cfg.HIGH_RATE_WINDOW_SECONDS
        portscan_ports = max(10, cfg.PORTSCAN_DISTINCT_PORTS // 5)
        portscan_window = cfg.PORTSCAN_WINDOW_SECONDS
        syn_threshold = max(5, cfg.SYN_THRESHOLD // 5)
    else:
        high_rate_limit = settings["high_rate_limit"]
        high_rate_window = cfg.HIGH_RATE_WINDOW_SECONDS
        portscan_ports = cfg.PORTSCAN_DISTINCT_PORTS
        portscan_window = cfg.PORTSCAN_WINDOW_SECONDS
        syn_threshold = cfg.SYN_THRESHOLD

    window_short = now - timedelta(seconds=high_rate_window)
    window_long = now - timedelta(seconds=portscan_window)

    recent_same_src = Connection.objects.filter(
        src_ip=conn.src_ip,
        timestamp__gte=window_short,
    )

    count_short = recent_same_src.count()

    if count_short > high_rate_limit:
        create_alert_for_connection(
            src_ip=conn.src_ip,
            message=f"High connection rate from {conn.src_ip} ({count_short} connections in {high_rate_window}s)",
            alert_type="High Connection Rate",
            severity="high",
            connection=conn,
            pid=conn.pid,
            process_name=conn.process_name,
        )
        return

    recent_ports = (
        Connection.objects.filter(
            src_ip=conn.src_ip,
            timestamp__gte=window_long,
        )
        .values_list("dst_port", flat=True)
        .distinct()
    )

    distinct_count = recent_ports.count()

    if distinct_count > portscan_ports:
        create_alert_for_connection(
            src_ip=conn.src_ip,
            message=f"Possible port scan from {conn.src_ip} ({distinct_count} unique destination ports in {portscan_window}s)",
            alert_type="Port Scan",
            severity="high",
            connection=conn,
            pid=conn.pid,
            process_name=conn.process_name,
        )
        return

    status_lower = (conn.status or "").lower()

    if "syn_sent" in status_lower or "syn" in status_lower:
        recent_syn = recent_same_src.filter(status__icontains="SYN").count()
        if recent_syn > syn_threshold:
            create_alert_for_connection(
                src_ip=conn.src_ip,
                message=f"Repeated SYN connections from {conn.src_ip} ({recent_syn} recent SYN states)",
                alert_type="SYN Flood",
                severity="medium",
                connection=conn,
                pid=conn.pid,
                process_name=conn.process_name,
            )
            return

    src_ip = conn.src_ip or ""
    is_localhost = src_ip in ("127.0.0.1", "localhost", "::1") or src_ip.startswith("127.0.")

    if conn.dst_port in cfg.SUSPICIOUS_PORTS and not is_localhost:
        create_alert_for_connection(
            src_ip=conn.src_ip,
            message=f"Connection to sensitive port {conn.dst_port} from {conn.src_ip}",
            alert_type="Sensitive Port",
            severity="low",
            connection=conn,
            pid=conn.pid,
            process_name=conn.process_name,
        )

    # 5. Reverse shell suspicious outbound connection
    try:
        reverse_ports = cfg.get_port_list("reverse_shell_ports", "4444,5555,1337")
    except Exception:
        reverse_ports = [4444, 5555, 1337]

    if (
        conn.dst_port in reverse_ports
        and not conn.src_ip.startswith("127.")
        and not cfg.is_ip_ignored(conn.src_ip)
    ):
        msg = (
            f"Possible reverse shell connection from {conn.src_ip} "
            f"to {conn.dst_ip}:{conn.dst_port}"
        )
        create_alert_for_connection(
            src_ip=conn.src_ip,
            dst_ip=conn.dst_ip,
            dst_port=conn.dst_port,
            message=msg,
            alert_type="Reverse Shell",
            severity="high",
            pid=conn.pid,
            process_name=conn.process_name,
        )


def connection_collector_loop(interval=3):
    """
    Background loop: collect netstat data every `interval` seconds.
    Handles database errors by retrying with backoff.
    """
    from django.db import connection
    from django.db.utils import DatabaseError

    backoff = 1
    max_backoff = 60
    consecutive_db_errors = 0
    DB_ERROR_THRESHOLD = 5

    while True:
        try:
            connection.close()  # Ensure clean state start
            
            # Try ss first (best for PIDs and modern Linux)
            items = parse_ss_output()
            
            # Fallback to /proc if ss failed or returned nothing
            if not items:
                # Try /proc filesystem (sees all connections including sandboxed apps but lacking PIDs usually)
                items = parse_proc_net()
            
            # If /proc also returns no or very few connections, fall back to netstat
            if (not items or len(items) < 3) and not items:
                # log.info("Few/no connections, trying netstat fallback")
                items = parse_netstat_output()
            
            if items:
                save_connections(items)
            
            # success reset
            consecutive_db_errors = 0
            backoff = 1
            time.sleep(interval)

        except DatabaseError as e:
            log.warning("DB error in collectors: %s", e)
            consecutive_db_errors += 1
            if consecutive_db_errors >= DB_ERROR_THRESHOLD:
                log.error("Too many DB errors, pausing collectors for %s seconds", max_backoff)
                time.sleep(max_backoff)
                consecutive_db_errors = 0
                backoff = 1
            else:
                time.sleep(backoff)
                backoff = min(backoff * 2, max_backoff)

        except Exception as e:
            log.warning("Unexpected error in connection_collector_loop: %s", e)
            time.sleep(interval)
        finally:
            close_old_connections()


def start_collectors():
    log.info("Starting collectors")

    try:
        start_connection_collector()
    except Exception:
        log.exception("Failed to start connection collector")

    # start light sniffer (reads /proc/net/tcp) for extra port scan hints
    if start_light_sniffer:
        try:
            start_light_sniffer()
            log.info("Light sniffer started")
        except Exception:
            log.exception("Failed to start light sniffer")

    # start rare port monitor
    # rare_port_detector is integrated into save_connections loop

    # start ARP MITM detector (unified)
    # start_arp_mitm_collector is deprecated

    if start_arp_mitm_detector:
        try:
            start_arp_mitm_detector()
            log.info("ARP MITM detector started")
        except Exception:
            log.exception("Failed to start ARP MITM detector")

    # start reverse shell detector
    if start_rev_shell_detector:
        try:
            start_rev_shell_detector()
            log.info("Reverse shell detector started")
        except Exception:
            log.exception("Failed to start reverse shell detector")
