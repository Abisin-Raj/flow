"""
Persistence Watcher — Stage 5: Installation.

Monitors common persistence paths for unexpected additions, deletions,
or modifications. Attackers typically install persistence via:
  - crontab entries (/etc/cron.d, /var/spool/cron/crontabs, /etc/crontab)
  - systemd user units (~/.config/systemd/user/)

On first run a baseline hash dict is built silently. On subsequent polls,
any deviation raises a 'high' severity alert.
"""

import hashlib
import logging
import os
import threading
import time
from pathlib import Path

from django.db import close_old_connections

from core.alert_engine import create_alert_with_geo

log = logging.getLogger("core.persistence_watcher")

_POLL_INTERVAL = 30  # seconds


def _default_watch_paths() -> list[Path]:
    """Return persistence paths to monitor on this machine."""
    paths = [
        Path("/etc/crontab"),
        Path("/etc/cron.d"),
        Path("/var/spool/cron/crontabs"),
