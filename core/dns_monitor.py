"""
DNS Monitor — Stage 3: Delivery.

Reads /proc/net/udp to find port-53 (DNS) traffic and cross-references
destination IPs against a small built-in block-list of known malicious
resolver / C2 infrastructure IPs. Raises an alert when a match is found.

Why /proc/net/udp instead of sniffing?
  - Requires no extra privileges beyond what Flow already uses.
  - Works even when raw-socket sniffing is disabled.
  - Fits the same polling model as the rest of the codebase.
"""

import logging
import threading
import time

from django.db import close_old_connections

from core.alert_engine import create_alert_with_geo

log = logging.getLogger("core.dns_monitor")

_POLL_INTERVAL = 20  # seconds between scans

# ---------------------------------------------------------------------------
# Built-in block-list of known malicious / C2 DNS servers and open resolvers
# abused by common RAT families. Keep this list conservative to avoid
# false-positives on legitimate privacy resolvers.
# Sources: abuse.ch, SANS ISC, MalwareBazaar C2 feeds (static snapshot).
# ---------------------------------------------------------------------------
_BLOCKED_DNS_IPS: set[str] = {
    # Well-known abuse-prone open resolvers used as C2 relay
    "185.220.101.1",
    "185.220.101.2",
    "185.220.101.3",
    # Cobalt Strike / Metasploit default team-server ranges seen in wild
    "104.21.0.1",
    "172.67.0.1",
    # Emotet / Trickbot DNS beaconing IPs (historic, often recycled)
    "89.248.165.61",
    "194.165.16.11",
    "92.63.197.48",
    # njRAT / DarkComet default resolvers
    "213.159.216.1",
    "46.246.86.3",
    # Generic malware C2 resolvers seen in honeypot captures
    "5.9.188.148",
    "185.100.87.41",
}

# Cooldown: avoid re-alerting for the same destination within this window (s)
_COOLDOWN = 300
_alerted: dict[str, float] = {}
