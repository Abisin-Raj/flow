"""
Light Sniffer Module.

This module implements a lightweight mechanism to detect network activity by polling
system files like `/proc/net/tcp` and `/proc/net/udp`. This avoids the overhead
and permission requirements of raw sockets.
"""
import threading
import time
import logging
import socket

from core.scan_detector import detector
from core.alert_engine import create_alert_with_geo

LOG = logging.getLogger("light_sniffer")

# Paths to Linux procfs network tables
TCP_PATH = "/proc/net/tcp"
TCP6_PATH = "/proc/net/tcp6"
UDP_PATH = "/proc/net/udp"

_running = False

# track seen tuple to avoid duplicate processing
_seen_entries = set()


def _parse_ip(hex_ip):
    """
    Parse IP address from procfs hex representation.
    
    Args:
        hex_ip (str): Hex string (8-char for IPv4, 32-char for IPv6).
        
    Returns:
        str: IP address string or None.
    """
    try:
        if len(hex_ip) == 8:
            # IPv4: hex like "0100007F" -> reverse -> 127.0.0.1
            ip_bytes = bytes.fromhex(hex_ip)
            # procfs stores IP addresses in little-endian
            ip_bytes = ip_bytes[::-1]
            return socket.inet_ntoa(ip_bytes)
        elif len(hex_ip) == 32:
            # IPv6: 32-char hex, stored as 4 groups of 8 hex chars (little-endian per group)
            # Each 8-char group needs to be byte-reversed
            groups = [hex_ip[i:i+8] for i in range(0, 32, 8)]
            ip_bytes = b''
            for g in groups:
                group_bytes = bytes.fromhex(g)
                ip_bytes += group_bytes[::-1]
            return socket.inet_ntop(socket.AF_INET6, ip_bytes)
        else:
            return None
    except Exception:
        return None


def _parse_port(hex_port):
    """
    Parse port number from procfs hex representation.
    """
    try:
        return int(hex_port, 16)
    except Exception:
        return 0


def _read_table(path):
    """
    Read and parse a network table (tcp/udp) from procfs.

    Args:
        path (str): Path to the proc file (e.g., /proc/net/tcp).

    Returns:
        list: A list of tuples (local_ip, local_port, remote_ip, remote_port, state).
    """
    results = []
    try:
        with open(path) as f:
            next(f)  # skip header
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local_ip_hex, local_port_hex = parts[1].split(":")
                rem_ip_hex, rem_port_hex = parts[2].split(":")

                local_ip = _parse_ip(local_ip_hex)
                local_port = _parse_port(local_port_hex)
                remote_ip = _parse_ip(rem_ip_hex)
                remote_port = _parse_port(rem_port_hex)
                state = parts[3]

                results.append((local_ip, local_port, remote_ip, remote_port, state))
        return results
    except Exception as e:
        LOG.warning("Failed reading %s: %s", path, e)
        return []


def _record_syn_from_entry(src_ip: str, dst_port: int, now_ts: float):
    """
    Note a SYN packet via detector and create alert if threshold reached.
    """
    try:
        if not src_ip or dst_port <= 0:
            return

        # record packet event in detector
        try:
            detector.note_packet(src_ip=str(src_ip), dst_port=int(dst_port), ts=now_ts)
        except Exception:
            pass

        # Ask detector if an alert should be produced (includes cooldown)
        try:
            category = detector.evaluate(src_ip, now_ts)
        except Exception:
            category = None

        if not category:
            return

        # fetch recent events for context
        try:
            events = detector.recent(src_ip, now_ts)
        except Exception:
            events = [(now_ts, dst_port)]

        # build message and severity
        note = f"Port scan detected (light sniffer), category: {category}, recent {len(events)} ports"
        severity = "high" if category in ("fast", "brute") else "medium"

        # create alert
        try:
            create_alert_with_geo(
                src_ip=src_ip,
                alert_type="Port Scan",
                message=note,
                severity=severity,
                category=category,
            )
            LOG.info(
                "Created light-sniffer alert for %s, category: %s", src_ip, category
            )
        except Exception:
            LOG.exception("Failed to create port scan alert for %s", src_ip)

    except Exception:
        LOG.exception("_record_syn_from_entry error")


def _worker(poll_interval=1):
    """
    Worker loop that parses /proc/net/{tcp,udp} and looks for SYN_SENT entries,
    then applies burst detection (many distinct dst ports from same remote).
    """
    global _running
    LOG.info("Light packet metadata sniffer started")
    seen = _seen_entries

    while _running:
        tcp_entries = _read_table(TCP_PATH)
        tcp6_entries = _read_table(TCP6_PATH)
        # udp_entries = _read_table(UDP_PATH)  # keep for future use

        now_ts = time.time()

        for lip, lp, rip, rp, state in tcp_entries + tcp6_entries:
            # ignore invalid parses
            if not rip or not lip:
                continue

            # build a stable key to avoid repeated processing in short loops
            key = (lip, lp, rip, rp, state)
            if key in seen:
                continue
            seen.add(key)

            # state "02" == SYN_SENT in TCP table hex state code
            # detect outgoing SYN attempts toward many ports from same remote
            try:
                if state == "02":
                    # Outbound SYN from this machine to remote host
                    _record_syn_from_entry(src_ip=lip, dst_port=rp, now_ts=now_ts)
            except Exception:
                LOG.exception("Error processing tcp entry %s", key)

        # prune the seen set occasionally to keep memory bounded
        if len(seen) > 20000:
            # keep only recent items (inefficient but simple)
            seen.clear()

        time.sleep(poll_interval)

    LOG.info("Light packet metadata sniffer stopped")


def start_light_sniffer():
    """
    Start the light sniffer in a background thread.
    """
    global _running
    if _running:
        return
    _running = True
    t = threading.Thread(target=_worker, daemon=True)
    t.start()


def stop_light_sniffer():
    global _running
    _running = False
