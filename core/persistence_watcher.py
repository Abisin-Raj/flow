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

