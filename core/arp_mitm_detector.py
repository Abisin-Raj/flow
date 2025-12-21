"""
ARP MITM (Man-in-the-Middle) Detector.

This module is responsible for detecting ARP spoofing attacks, also known as ARP cache poisoning.
It works by:
1.  Monitoring the default gateway's MAC address for changes.
2.  Checking for multiple IP addresses associated with a single MAC address.
3.  Analyzing ARP tables from `/proc/net/arp`.
"""

import time
import threading
import logging
import socket

from core.alert_engine import create_alert_with_geo
from django.db import close_old_connections

# Initialize logger for this module
LOG = logging.getLogger("core.arp_mitm")

# Constants for detection tuning
CHECK_INTERVAL = 5  # Seconds between checks
MAC_MULTI_IP_THRESHOLD = 5  # Max IPs allowed per MAC before alerting
ALERT_COOLDOWN = 60  # Minimum seconds between similar alerts


def _hex_to_ip(hex_str):
    """
    Convert a hex string representation of an IP address to dotted-decimal format.

    Args:
        hex_str (str): The hex string (e.g., "0100000A" for 10.0.0.1 in little-endian).

    Returns:
        str: The IP address string (e.g., "10.0.0.1"), or None if conversion fails.
    """
    try:
        # Convert hex string to bytes
        # hex like "0100000A" (10.0.0.1 little-endian)
        b = bytes.fromhex(hex_str)
        # Reverse bytes to handle little-endian format
        b = b[::-1]
        # Convert bytes to standard IP string
        return socket.inet_ntoa(b)
    except Exception:
        return None


def _get_default_gateway_ip():
    """
    Retrieve the IP address of the default gateway from system routing tables.

    Reads `/proc/net/route` to find the default route (destination 00000000).

    Returns:
        str: The IP address of the default gateway, or None if not found.
    """
    try:
        with open("/proc/net/route") as f:
            # Skip header line
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                dest_hex, gw_hex = parts[1], parts[2]
                
                # Check for default route (Destination 00000000)
                if dest_hex != "00000000":
                    continue
                
                # Convert hex gateway address to IP string
                gw_ip = _hex_to_ip(gw_hex)
                return gw_ip
    except Exception:
        return None
    return None


def _read_arp():
    """
    Read the system ARP table from `/proc/net/arp`.

    Returns:
        tuple: A tuple containing:
            - ip_to_mac (dict): Mapping of IP addresses to MAC addresses.
            - mac_to_ips (dict): Mapping of MAC addresses to sets of IP addresses.
    """
    ip_to_mac = {}
    mac_to_ips = {}
    try:
        with open("/proc/net/arp") as f:
            # Skip header
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) < 6:
                    continue
                ip = parts[0]
                mac = parts[3]
                
                # Ignore incomplete entries
                if mac == "00:00:00:00:00:00":
                    continue
                
                # Populate mappings
                ip_to_mac[ip] = mac
                mac_to_ips.setdefault(mac, set()).add(ip)
    except Exception as e:
        LOG.warning("Failed reading /proc/net/arp: %s", e)
    return ip_to_mac, mac_to_ips


def _same_subnet(ip1, ip2):
    """
    Check if two IP addresses are likely in the same subnet (assuming /24 for simplicity).

    Args:
        ip1 (str): First IP address.
        ip2 (str): Second IP address.

    Returns:
        bool: True if the first 3 octets match, False otherwise.
    """
    try:
        a1 = ip1.split(".")
        a2 = ip2.split(".")
        if len(a1) < 3 or len(a2) < 3:
            return False
        # Compare first three octets
        return a1[0] == a2[0] and a1[1] == a2[1] and a1[2] == a2[2]
    except Exception:
        return False


def _worker():
    """
    Background worker thread function for continuous ARP monitoring.
    
    This function runs indefinitely, performing checks at `CHECK_INTERVAL`.
    It detects:
    1. Gateway MAC address changes.
    2. MAC addresses claiming multiple IP addresses (potential spoofing).
    """
    LOG.info("ARP MITM detector started")
    baseline_gw_mac = None
    last_gw_alert = 0.0
    last_multi_alert = 0.0

    while True:
        now_ts = time.time()
        gw_ip = _get_default_gateway_ip()
        ip_to_mac, mac_to_ips = _read_arp()

        # Check for Gateway MAC spoofing
        if gw_ip:
            gw_mac = ip_to_mac.get(gw_ip)
            if gw_mac:
                if baseline_gw_mac is None:
                    # Initialize baseline on first run
                    baseline_gw_mac = gw_mac
                    LOG.info("Baseline gateway %s MAC set to %s", gw_ip, gw_mac)
                elif gw_mac != baseline_gw_mac:
                    # Detected change in Gateway MAC
                    if now_ts - last_gw_alert > ALERT_COOLDOWN:
                        msg = f"Gateway MAC changed for {gw_ip}: {baseline_gw_mac} -> {gw_mac}. Possible ARP spoofing."
                        try:
                            create_alert_with_geo(
                                src_ip=gw_ip,
                                alert_type="MITM Gateway Poison",
                                message=msg,
                                severity="high",
                                category="mitm:arp",
                            )
                            LOG.info("Created gateway poison alert for %s", gw_ip)
                        except Exception:
                            LOG.exception("Failed to create gateway poison alert")
                        # Trust the new MAC? Or keep alert? Currently updates baseline.
                        baseline_gw_mac = gw_mac
                        last_gw_alert = now_ts

        # Check for multi-IP per MAC detection (possible MITM host impersonating many)
        for mac, ips in mac_to_ips.items():
            if len(ips) >= MAC_MULTI_IP_THRESHOLD:
                # Check they are in same subnet as gateway to reduce noise (e.g., virtual interfaces)
                ip_list = list(ips)
                suspicious_ip = ip_list[0]
                if gw_ip and not _same_subnet(suspicious_ip, gw_ip):
                    continue
                
                # Rate limit alerts
                if now_ts - last_multi_alert > ALERT_COOLDOWN:
                    msg = f"MAC {mac} is associated with {len(ips)} IPs ({', '.join(ip_list[:5])}...). Possible ARP spoofing / MITM."
                    try:
                        create_alert_with_geo(
                            src_ip=suspicious_ip,
                            alert_type="ARP Spoofing",
                            message=msg,
                            severity="medium",
                            category="mitm:arp",
                        )
                        LOG.info("Created ARP spoof alert for MAC %s", mac)
                    except Exception:
                        LOG.exception("Failed to create ARP spoof alert")
                    last_multi_alert = now_ts
                    break # Break to avoid multiple alerts in one cycle

        # Clean up database connections to prevent leak in long-running thread
        close_old_connections()
        time.sleep(CHECK_INTERVAL)


def analyze(entries):
    """
    Analyze list of (ip, mac) tuples to find suspicious mapping.
    
    Args:
        entries (list): List of tuples (ip, mac).

    Returns:
        list: List of dicts {'mac': mac, 'ips': [ip, ...]} for entries with MACs mapping to multiple IPs.
    """
    mac_to_ips = {}
    for ip, mac in entries:
        mac_to_ips.setdefault(mac, set()).add(ip)

    suspicious = []
    for mac, ips in mac_to_ips.items():
        if len(ips) >= MAC_MULTI_IP_THRESHOLD:
            suspicious.append({"mac": mac, "ips": list(ips)})
    return suspicious


def start_arp_mitm_detector():
    """
    Start the ARP MITM detector in a background thread.
    """
    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    LOG.info("ARP MITM detector thread launched")
