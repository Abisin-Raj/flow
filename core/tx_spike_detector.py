"""
TX Spike Detector — Stage 7: Actions on Objectives (Data Exfiltration).

Periodically reads /sys/class/net/<iface>/statistics/tx_bytes for all
active non-loopback interfaces and computes the upload rate. If the
upload volume exceeds a configurable threshold within the measurement
window, a 'high' severity alert is raised.

Default threshold: 50 MB uploaded within a single 60-second window.
This is deliberately conservative to avoid false-positives from large
but legitimate transfers (e.g., backups, software updates).

The threshold can be overridden via the AppSetting key:
  tx_spike_threshold_mb  (integer, megabytes per window)
"""

import logging
