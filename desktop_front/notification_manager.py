"""
Notification Manager (Qt-native).

Pure Qt implementation using QSystemTrayIcon.showMessage().
No DBus, no notify-send, no subprocess calls.

This is the correct way to show desktop notifications from a Qt app.
"""

import time
import logging
from PyQt6.QtWidgets import QSystemTrayIcon
from PyQt6.QtCore import QObject

log = logging.getLogger("desktop_front.notification_manager")


class NotificationManager(QObject):
    """
    Qt-native notification manager using QSystemTrayIcon.
    
    Features:
    - Rate limiting to prevent spam
    - Severity-aware icons
    - No external dependencies
    """
    
    def __init__(self, tray_icon: QSystemTrayIcon):
        super().__init__()
        self.tray_icon = tray_icon
        self.last_sent = {}  # alert_key -> timestamp
        self.cooldown_seconds = 10  # prevent spam
        log.info("NotificationManager initialized (Qt-native)")

    def notify_alert(self, title: str, message: str, severity: str = "medium"):
        """
        Show a notification via system tray.
        
        Args:
            title: Notification title
            message: Notification body text
            severity: low, medium, high, or critical
        """
        if not self.tray_icon or not self.tray_icon.isVisible():
            log.debug("Tray icon not available, skipping notification")
            return

        # Rate limiting - prevent duplicate notifications
        key = f"{title}:{message[:50]}"
        now = time.time()

        if key in self.last_sent:
            if now - self.last_sent[key] < self.cooldown_seconds:
                log.debug(f"Rate limited notification: {title}")
                return

        self.last_sent[key] = now

        # Map severity to Qt icon
        severity_lower = (severity or "medium").lower()
        icon = QSystemTrayIcon.MessageIcon.Information
        
        if severity_lower == "high":
            icon = QSystemTrayIcon.MessageIcon.Warning
        elif severity_lower == "critical":
            icon = QSystemTrayIcon.MessageIcon.Critical

        # Truncate long messages
        if len(message) > 200:
            message = message[:197] + "..."

        try:
            self.tray_icon.showMessage(title, message, icon, 8000)
            log.info(f"Notification sent: {title} [{severity_lower}]")
        except Exception as e:
            log.error(f"Failed to show notification: {e}")

    def show_alert(self, alert_obj):
        """
        Convenience method to show notification from an Alert model instance.
        """
        if not alert_obj:
            return

        title = f"Flow Alert: {alert_obj.alert_type or 'Security Event'}"
        message = alert_obj.message or "No details available"
        severity = alert_obj.severity or "medium"
        
        self.notify_alert(title, message, severity)

    def notify_block(self, ip: str, duration: int):
        """Notify user that an IP was blocked."""
        self.notify_alert(
            "IP Blocked",
            f"Blocked {ip} for {duration} seconds",
            "high"
        )

    def notify_unblock(self, ip: str):
        """Notify user that an IP was unblocked."""
        self.notify_alert(
            "IP Unblocked",
            f"Unblocked {ip}",
            "low"
        )
