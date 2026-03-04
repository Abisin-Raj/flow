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
    ]
    # User systemd units (expand ~)
    user_systemd = Path.home() / ".config" / "systemd" / "user"
    if user_systemd.exists():
        paths.append(user_systemd)
    return paths


def _hash_file(path: Path) -> str:
    """Return SHA-256 hex digest of a file, or empty string on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _snapshot(paths: list[Path]) -> dict[str, str]:
    """
    Walk each path (file or directory) and return a mapping of
    absolute-path-string → sha256 for every file found.
    """
    state: dict[str, str] = {}
    for root in paths:
        if root.is_file():
            digest = _hash_file(root)
            if digest:
                state[str(root)] = digest
        elif root.is_dir():
            try:
                for entry in os.scandir(root):
