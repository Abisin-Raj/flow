# desktop_front/notification_manager.py
import os
import pwd
import logging
import subprocess
from PyQt6.QtWidgets import QSystemTrayIcon

log = logging.getLogger("desktop_front.notification_manager")


def send_notification(title, message):
    try:
        dbus_addr = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
        if not dbus_addr:
            raise RuntimeError("No DBUS_SESSION_BUS_ADDRESS in environment")

        cmd = [
            "notify-send",
            "--icon=dialog-warning",
            title,
            message
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env={"DBUS_SESSION_BUS_ADDRESS": dbus_addr}
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"notify-send failed code={result.returncode} stderr={result.stderr.strip()}"
            )

        logging.info(f"Notification sent successfully: {title}")

    except Exception as e:
        logging.error(f"Notification error: {e}", exc_info=True)


class NotificationManager:
    def __init__(self, tray_icon: QSystemTrayIcon):
        self.tray = tray_icon
        log.info("NotificationManager initialized, tray_icon=%s", tray_icon)

    def show_alert(self, alert_obj):
        title = "Flow Alert"
        log.info("show_alert called with alert_obj=%s", alert_obj)

        if not alert_obj:
            log.warning("show_alert: no alert_obj, returning")
            return

        sev = getattr(alert_obj, "severity", "unknown")
        msg_text = getattr(alert_obj, "message", "") or "No details"

        body = f"{sev.upper()}: {msg_text}"
        if len(body) > 200:
            body = body[:197] + "..."

        # Try system tray first (works when app runs in user session)
        try:
            if self.tray:
                self.tray.showMessage(title, body, QSystemTrayIcon.MessageIcon.Critical, 8000)
                log.info("Tray notification sent")
        except Exception:
            log.exception("Tray notification failed")

        # Always attempt notify-send as fallback (works when app runs as root)
        send_notification(title, body)
