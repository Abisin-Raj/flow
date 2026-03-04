"""
Main GUI Entry Point (PyQt6).

This module defines the main application window (`FlowWindow`) and the `main()` execution loop.
It assembles all the widgets (tabs) into a single cohesive interface and manages the system tray integration.
"""

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
    """
    The main application window containing the tabbed interface.
    
    Responsibilities:
    1. Initialize all feature widgets (Dashboard, Connections, Alerts, etc.).
    2. Manage the tab layout.
    3. Initialize and manage the System Tray icon and menu.
    4. Handle window lifecycle events (close to tray, etc.).
    """
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

        self.service_control_tab = ServiceControlWidget(self)
        self.tabs.addTab(self.service_control_tab, "Service Control")

        # system tray
        self.tray_icon = None
        self._create_system_tray()

    def _on_tab_changed(self, index):
        """Log tab changes for debugging usage patterns."""
        tab_name = self.tabs.tabText(index)
        log.info(f"Tab changed to index {index}: {tab_name}")

    def _create_system_tray(self):
        """
        Setup the system tray icon with a context menu (Open, Hide, Quit).
        Attempts to locate the icon in various standard locations.
        """
        # Try system-wide icon first (when installed)
        icon_path = Path("/usr/share/pixmaps/flow.png")
        if not icon_path.exists():
