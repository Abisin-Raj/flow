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
