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
