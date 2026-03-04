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
