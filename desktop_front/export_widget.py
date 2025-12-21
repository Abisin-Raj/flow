import sys
import os
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
)

from desktop_front.ui_helpers import make_small_button

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "flow.settings")

import django  # noqa: E402

django.setup()

from django.db import DatabaseError  # noqa: E402

from core.export_service import export_alerts_to_csv, export_connections_to_csv  # noqa: E402


"""
Export Widget.

This module implements the Export tab, allowing users to dump Alerts and Connections data to CSV files.
It calls into the `core.export_service` to perform the actual write operations.
"""

class ExportWidget(QWidget):
    """
    Simple UI with buttons to trigger CSV exports.
    """
    def __init__(self, parent=None):
        super().__init__(parent)

        main = QVBoxLayout(self)

        info = QLabel(
            "Export recent Alerts and Connections to CSV files.\n"
            "Files are written under your home folder in .flow_exports."
        )
        info.setWordWrap(True)

        main.addWidget(info)

        btn_layout = QHBoxLayout()
        self.alerts_btn = make_small_button("Export alerts to CSV")
        self.conns_btn = make_small_button("Export connections to CSV")

        self.alerts_btn.clicked.connect(self.export_alerts)
        self.conns_btn.clicked.connect(self.export_connections)

        btn_layout.addWidget(self.alerts_btn)
        btn_layout.addWidget(self.conns_btn)
        btn_layout.addStretch()

        self.status_label = QLabel("Ready.")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignLeft)

        main.addLayout(btn_layout)
        main.addWidget(self.status_label)
        main.addStretch()

    def export_alerts(self):
        """
        Trigger export of alerts.
        Handles database locking errors gracefully.
        """
        try:
            path = export_alerts_to_csv()
        except DatabaseError:
            QMessageBox.warning(
                self,
                "Database busy",
                "Could not export alerts because the database is locked.",
            )
            return
        except Exception as e:
            QMessageBox.critical(
                self,
                "Export failed",
                f"Failed to export alerts:\n{e}",
            )
            return

        self.status_label.setText(f"Alerts exported to: {path}")
        QMessageBox.information(
            self,
            "Export complete",
            f"Alerts exported to:\n{path}",
        )

    def export_connections(self):
        """
        Trigger export of connections.
        Handles database locking errors gracefully.
        """
        try:
            path = export_connections_to_csv()
        except DatabaseError:
            QMessageBox.warning(
                self,
                "Database busy",
                "Could not export connections because the database is locked.",
            )
            return
        except Exception as e:
            QMessageBox.critical(
                self,
                "Export failed",
                f"Failed to export connections:\n{e}",
            )
            return

        self.status_label.setText(f"Connections exported to: {path}")
        QMessageBox.information(
            self,
            "Export complete",
            f"Connections exported to:\n{path}",
        )
