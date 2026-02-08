"""
Notification Manager (Qt-native).

Pure Qt implementation using QSystemTrayIcon.showMessage().
No DBus, no notify-send, no subprocess calls.

This is the correct way to show desktop notifications from a Qt app.
"""

import time
import logging
from PyQt6.QtWidgets import QSystemTrayIcon
from PyQt6.QtCore import QObject, Qt

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

        # Rate limiting - prevent duplicate notifications within 5 seconds
        key = f"{title}:{message[:50]}"
        now = time.time()
        if key in self.last_sent:
            if now - self.last_sent[key] < 5: # 5 second cooldown
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

        # Try QSystemTrayIcon first
        try:
            if self.tray_icon and self.tray_icon.isVisible():
                self.tray_icon.showMessage(title, message, icon, 8000)
                log.info(f"Notification sent via Tray: {title}")
                return
        except Exception as e:
            log.warning(f"Tray notification failed: {e}")

        # Fallback to Toast Notification and notify-send
        self._notify_via_toast(title, message, severity_lower)
        self._notify_send_subprocess(title, message, severity_lower)

    def _notify_via_toast(self, title, message, severity):
        """Show a highly visible message box as fallback."""
        try:
            from PyQt6.QtWidgets import QMessageBox, QApplication
            
            # Find the active window to use as parent, or global app
            app = QApplication.instance()
            parent = app.activeWindow()
            
            # Use critical icon for high severity
            icon = QMessageBox.Icon.Information
            if severity in ("high", "critical"):
                icon = QMessageBox.Icon.Critical
            elif severity == "medium":
                icon = QMessageBox.Icon.Warning
                
            # Create a message box that stays on top
            msg_box = QMessageBox(parent)
            msg_box.setIcon(icon)
            msg_box.setWindowTitle(title)
            msg_box.setText(message)
            msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
            msg_box.setWindowFlags(msg_box.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)
            
            # Use show() instead of exec() to avoid blocking the whole app 
            # (Signal Dispatcher now makes .show() safe and visible)
            msg_box.show()
            
            # Keep a reference to prevent garbage collection
            if not hasattr(self, "_active_dialogs"):
                self._active_dialogs = []
            self._active_dialogs.append(msg_box)
            
            # Auto-close after 10 seconds to keep screen clean
            QTimer.singleShot(10000, msg_box.close)
            msg_box.finished.connect(lambda: self._active_dialogs.remove(msg_box) if msg_box in self._active_dialogs else None)
            
            log.info(f"Notification sent via MessageBox: {title}")
            
        except Exception as e:
            log.error(f"MessageBox notification failed: {e}")

    def _notify_send_subprocess(self, title, message, severity):
        """Fallback using the notify-send command line tool."""
        # Previous notify-send implementation kept as backup...
        import subprocess
        import shutil

        if not shutil.which("notify-send"):
            log.debug("notify-send not found, skipping fallback notification")
            return

        urgency = "normal"
        if severity == "high":
            urgency = "critical"
        elif severity == "low":
            urgency = "low"

        try:
            subprocess.Popen(
                ["notify-send", "-u", urgency, "-a", "Flow", title, message],
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL
            )
            log.info(f"Notification sent via notify-send: {title}")
        except Exception as e:
            log.error(f"notify-send failed: {e}")

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
