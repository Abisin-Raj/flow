import sys
import os
import signal
import logging
from pathlib import Path

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import QTimer

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "flow.settings")


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0

def setup_django():
    import django

    django.setup()


def setup_logging():
    # Using .flow_logs to be consistent with the project rename and previous fixes
    log_dir = Path.home() / ".flow_logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "app.log"

    logging.basicConfig(
        filename=str(log_file),
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    logging.getLogger("core.collectors").info("Logging initialized")


def run_initial_cleanup(days: int = 7):
    from django.core.management import call_command
    from core import settings_api

    # Override days if setting exists
    try:
        days_str = settings_api.get("retention.days", str(days))
        days = int(days_str)
    except Exception:
        pass

    logger = logging.getLogger("maintenance")
    try:
        logger.info(f"Running automatic cleanup_old_data for last {days} days")
        call_command("cleanup_old_data", days=days)
    except Exception as e:
        logger.warning(f"Automatic cleanup_old_data failed: {e}")


def apply_dark_theme(app: QApplication):
    app.setStyleSheet(
        """
        QMainWindow {
            background-color: #121212;
            color: #f0f0f0;
        }
        QWidget {
            background-color: #121212;
            color: #f0f0f0;
        }
        QTableWidget {
            background-color: #1e1e1e;
            color: #f0f0f0;
            gridline-color: #333333;
        }
        QHeaderView::section {
            background-color: #232323;
            color: #f0f0f0;
            padding: 4px;
        }
        QPushButton {
            background-color: #333333;
            color: #f0f0f0;
            border-radius: 4px;
            padding: 4px 8px;
        }
        QPushButton:hover {
            background-color: #444444;
        }
        QLineEdit {
            background-color: #1e1e1e;
            color: #f0f0f0;
            border: 1px solid #444444;
            padding: 2px;
        }
        QLabel {
            color: #f0f0f0;
        }
        """
    )


def show_startup_notice(parent) -> bool:
    msg = QMessageBox(parent)
    msg.setWindowTitle("Flow Network Monitor - Startup Notice")
    msg.setText("Intended use and restrictions")
    msg.setInformativeText(
        "This tool monitors network activity on this device only. "
        "Do not monitor or scan networks you do not own or have written permission to test. "
        "Use responsibly. The project authors are not liable for misuse."
    )
    msg.setStandardButtons(
        QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel
    )
    ret = msg.exec()
    return ret == QMessageBox.StandardButton.Ok


def start_background_services():
    from core.collectors import start_collectors
    from core.folder_watcher import start_folder_watcher
    from core.packet_sniffer import start_packet_sniffer
    from core import settings_api

    try:
        start_collectors()
    except Exception:
        logging.exception("Failed to start collectors")

    try:
        start_folder_watcher()
    except Exception:
        logging.exception("Failed to start folder watcher")

    try:
        if settings_api.get_bool("enable_raw_sniffer"):
            logging.info("Starting raw packet sniffer (requires root or CAP_NET_RAW)")
            start_packet_sniffer()
        else:
            logging.info("Raw packet sniffer disabled by settings (enable_raw_sniffer is False)")
    except Exception:
        logging.exception("Failed to start packet sniffer")


def start_notifications(main_window):
    try:
        from desktop_front.notification_manager import NotificationManager
        from desktop_front.alert_watcher import AlertWatcher
        from core import auto_mitigator

        notif_mgr = NotificationManager(main_window.tray_icon)

        def notify_from_thread(alert_obj):
            # 1. Trigger desktop notification
            QTimer.singleShot(0, lambda: notif_mgr.show_alert(alert_obj))
            
            # 2. Run auto-mitigation checks
            try:
                auto_mitigator.process_alert(alert_obj)
            except Exception as e:
                logging.error("Auto-mitigation failed for alert %s: %s", alert_obj.id, e)

        watcher = AlertWatcher(
            notify_func=notify_from_thread,
            poll_interval=3,
            start_from_latest=False,
        )
        watcher.start()
    except Exception:
        logging.exception("Failed to start notification manager or watcher")


def main():
    setup_logging()
    setup_django()
    run_initial_cleanup(days=7)

    signal.signal(signal.SIGINT, signal.SIG_DFL)

    app = QApplication(sys.argv)
    apply_dark_theme(app)

    try:
        from desktop_front.main import FlowWindow
    except Exception:
        logging.exception("Failed importing GUI main window")
        raise

    window = FlowWindow()

    # show window before notice so it appears in the taskbar
    window.show()
    window.raise_()
    window.activateWindow()

    if not show_startup_notice(parent=window):
        sys.exit(0)

    start_background_services()

    try:
        window.statusBar().showMessage(
            "Collectors running, sniffer active, old data cleaned"
        )
    except Exception as e:
        logging.warning("Failed to update status bar: %s", e)

    start_notifications(window)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
