import time
import threading
import logging
import socket

from core.alert_engine import create_alert_with_geo
from django.db import close_old_connections

LOG = logging.getLogger("core.arp_mitm")

CHECK_INTERVAL = 5
MAC_MULTI_IP_THRESHOLD = 5
ALERT_COOLDOWN = 60


def _hex_to_ip(hex_str):
    try:
        # hex like "0100000A" (10.0.0.1 little-endian)
        b = bytes.fromhex(hex_str)
        b = b[::-1]
        return socket.inet_ntoa(b)
    except Exception:
        return None


def _get_default_gateway_ip():
    try:
        with open("/proc/net/route") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                dest_hex, gw_hex = parts[1], parts[2]
                # iface = parts[0]  # Unused, removed
                if dest_hex != "00000000":
                    continue
                gw_ip = _hex_to_ip(gw_hex)
                return gw_ip
    except Exception:
        return None
    return None


def _read_arp():
    """
    Return (ip_to_mac, mac_to_ips) from /proc/net/arp
    """
    ip_to_mac = {}
    mac_to_ips = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) < 6:
                    continue
                ip = parts[0]
                mac = parts[3]
                if mac == "00:00:00:00:00:00":
                    continue
                ip_to_mac[ip] = mac
                mac_to_ips.setdefault(mac, set()).add(ip)
    except Exception as e:
        LOG.warning("Failed reading /proc/net/arp: %s", e)
    return ip_to_mac, mac_to_ips


def _same_subnet(ip1, ip2):
    try:
        a1 = ip1.split(".")
        a2 = ip2.split(".")
        if len(a1) < 3 or len(a2) < 3:
            return False
        return a1[0] == a2[0] and a1[1] == a2[1] and a1[2] == a2[2]
    except Exception:
        return False


def _worker():
    LOG.info("ARP MITM detector started")
    baseline_gw_mac = None
    last_gw_alert = 0.0
    last_multi_alert = 0.0

    while True:
        now_ts = time.time()
        gw_ip = _get_default_gateway_ip()
        ip_to_mac, mac_to_ips = _read_arp()

        if gw_ip:
            gw_mac = ip_to_mac.get(gw_ip)
            if gw_mac:
                if baseline_gw_mac is None:
                    baseline_gw_mac = gw_mac
                    LOG.info("Baseline gateway %s MAC set to %s", gw_ip, gw_mac)
                elif gw_mac != baseline_gw_mac:
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
                        baseline_gw_mac = gw_mac
                        last_gw_alert = now_ts

        # multi-IP per MAC detection (possible MITM host impersonating many)
        for mac, ips in mac_to_ips.items():
            if len(ips) >= MAC_MULTI_IP_THRESHOLD:
                # check they are in same subnet as gateway if possible, to reduce noise
                ip_list = list(ips)
                suspicious_ip = ip_list[0]
                if gw_ip and not _same_subnet(suspicious_ip, gw_ip):
                    continue
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
                    break

                    last_multi_alert = now_ts
                    break

        close_old_connections()
        time.sleep(CHECK_INTERVAL)


def analyze(entries):
    """
    Analyze list of (ip, mac) tuples.
    Returns list of dicts: {'mac': mac, 'ips': [ip, ...]} for suspicious entries.
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
    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    LOG.info("ARP MITM detector thread launched")
