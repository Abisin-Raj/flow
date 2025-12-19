import sys
import logging
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QTabWidget,
    QSystemTrayIcon,
    QMenu,
)
from PyQt6.QtGui import QIcon, QAction

from desktop_front.dashboard_widget import DashboardWidget
from desktop_front.connections_widget import ConnectionsWidget
from desktop_front.alerts_widget import AlertsWidget
from desktop_front.file_scan_widget import FileScanWidget
from desktop_front.threat_timeline_widget import ThreatTimelineWidget
from desktop_front.top_attackers_widget import TopAttackersWidget
from desktop_front.settings_widget import SettingsWidget
from desktop_front.service_control_widget import ServiceControlWidget
from desktop_front.export_widget import ExportWidget
from desktop_front.response_widget import ResponseWidget

log = logging.getLogger(__name__)


class FlowWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Flow")
        self.resize(1000, 700)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.tabs.currentChanged.connect(self._on_tab_changed)

        # main tabs
        self.dashboard_tab = DashboardWidget(self)
        self.tabs.addTab(self.dashboard_tab, "Dashboard")

        self.connections_tab = ConnectionsWidget(self)
        self.tabs.addTab(self.connections_tab, "Connections")

        self.alerts_tab = AlertsWidget(self)
        self.tabs.addTab(self.alerts_tab, "Alerts")

        self.response_tab = ResponseWidget(self)
        self.tabs.addTab(self.response_tab, "Security Operations")

        # Connect alerts selection to response widget
        self.alerts_tab.alert_selected.connect(self.response_tab.set_alert)

        self.timeline_tab = ThreatTimelineWidget(self)
        self.tabs.addTab(self.timeline_tab, "Threat Timeline")

        self.top_attackers_tab = TopAttackersWidget(self)
        self.tabs.addTab(self.top_attackers_tab, "Top Attackers")

        self.file_scan_tab = FileScanWidget(self)
        self.tabs.addTab(self.file_scan_tab, "File Scanner")

        self.settings_tab = SettingsWidget(self)
        self.tabs.addTab(self.settings_tab, "Settings")

        self.export_tab = ExportWidget(self)
        self.tabs.addTab(self.export_tab, "Export")

        # new testing-only tab
        self.service_control_tab = ServiceControlWidget(self)
        self.tabs.addTab(self.service_control_tab, "Service Control (Test)")

        # system tray
        self.tray_icon = None
        self._create_system_tray()

    def _on_tab_changed(self, index):
        tab_name = self.tabs.tabText(index)
        log.info(f"Tab changed to index {index}: {tab_name}")

    def _create_system_tray(self):
        # Try system-wide icon first (when installed)
        icon_path = Path("/usr/share/pixmaps/flow.png")
        if not icon_path.exists():
            # Try resources folder (development/packaging location)
            icon_path = Path(__file__).resolve().parent / "resources" / "icon.png"
        if not icon_path.exists():
            # Fallback to old icons folder
            icon_path = Path(__file__).resolve().parent / "icons" / "tray_icon.png"

        if icon_path.exists():
            icon = QIcon(str(icon_path))
            self.setWindowIcon(icon)  # Set taskbar icon too
        else:
            icon = self.style().standardIcon(
                self.style().StandardPixmap.SP_ComputerIcon
            )

        tray = QSystemTrayIcon(icon, self)
        tray.setToolTip("Flow")
        menu = QMenu()

        restore_action = QAction("Show", self)
        restore_action.triggered.connect(self.show_from_tray)
        menu.addAction(restore_action)

        hide_action = QAction("Hide to tray", self)
        hide_action.triggered.connect(self.hide_to_tray)
        menu.addAction(hide_action)

        menu.addSeparator()

        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self._quit_app)
        menu.addAction(quit_action)

        tray.setContextMenu(menu)
        tray.activated.connect(self._on_tray_activated)
        tray.show()

        self.tray_icon = tray

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self.show_from_tray()
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_from_tray()

    def show_from_tray(self):
        self.show()
        self.raise_()
        self.activateWindow()

    def hide_to_tray(self):
        self.hide()

    def _quit_app(self):
        if self.tray_icon:
            self.tray_icon.hide()
        QApplication.instance().quit()

    def closeEvent(self, event):
        event.ignore()
        self.hide_to_tray()


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    app = QApplication(sys.argv)

    win = FlowWindow()
    win.show()

    try:
        from desktop_front.notification_manager import NotificationManager

        NotificationManager(win.tray_icon)
    except Exception:
        pass

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
