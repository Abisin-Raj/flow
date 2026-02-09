"""
Alerts Widget.

This module implements the Alerts tab, displaying a table of security alerts.
It allows filtering, clearing alerts, and taking actions like blocking IPs.
"""

import sys
import os
from pathlib import Path

from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QColor, QBrush
from PyQt6.QtWidgets import (
    QWidget,
    QLineEdit,
    QLabel,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QMessageBox,
    QApplication,
    QSplitter,
    QTextEdit,
    QPushButton,
)
from PyQt6.QtCore import pyqtSignal, Qt

from desktop_front.ui_helpers import make_small_button, tune_table

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "flow.settings")

import django  # noqa: E402

django.setup()

import logging  # noqa: E402
from django.db import DatabaseError  # noqa: E402
from django.utils import timezone  # noqa: E402
from core.models import Alert  # noqa: E402
from core.alert_engine import _get_field_map  # noqa: E402
from core import settings_api  # noqa: E402
from core.firewall import block_ip  # noqa: E402
from desktop_front.ui_utils import TableColumnManager  # noqa: E402

log = logging.getLogger("desktop_front.alerts_widget")


class AlertsWidget(QWidget):
    """
    The Alerts tab widget.
    
    Displays security alerts in a color-coded table (High=Red, Medium=Yellow, Low=Blue).
    Provides controls to filter results and block source IPs.
    """
    SRC_IP_COL = 3  # "Source IP" column (was 4 when icon column existed)
    alert_selected = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)

        self.field_map = _get_field_map()
        self.seen_alert_ids = set()  # Track seen alerts for notifications

        self.logical_columns = []
        if self.field_map.get("time"):
            self.logical_columns.append("time")
        if self.field_map.get("src"):
            self.logical_columns.append("src")
        if self.field_map.get("dst"):
            self.logical_columns.append("dst")
        if self.field_map.get("proto"):
            self.logical_columns.append("proto")
        if self.field_map.get("severity"):
            self.logical_columns.append("severity")
        if self.field_map.get("status"):
            self.logical_columns.append("status")
        if self.field_map.get("message"):
            self.logical_columns.append("message")

        model_fields = {f.name for f in Alert._meta.get_fields() if hasattr(f, "name")}
        if "src_country" in model_fields:
            self.logical_columns.append("src_country")
        if "src_city" in model_fields:
            self.logical_columns.append("src_city")
        if "latitude" in model_fields:
            self.logical_columns.append("latitude")
        if "longitude" in model_fields:
            self.logical_columns.append("longitude")
        if self.field_map.get("category") or "category" in model_fields:
            self.logical_columns.append("category")

        if "category" in self.logical_columns:
            try:
                self.logical_columns.remove("category")
                if "severity" in self.logical_columns:
                    idx = self.logical_columns.index("severity")
                    self.logical_columns.insert(idx + 1, "category")
                else:
                    self.logical_columns.insert(1, "category")
            except Exception:
                if "category" not in self.logical_columns:
                    self.logical_columns.append("category")

        # headers = []
        # for key in self.logical_columns:
        #     if key == "time":
        #         headers.append("Time")
        #     elif key == "src":
        #         headers.append("Source IP")
        #     elif key == "dst":
        #         headers.append("Destination IP")
        #     elif key == "proto":
        #         headers.append("Protocol")
        #     elif key == "severity":
        #         headers.append("Severity")
        #     elif key == "status":
        #         headers.append("Status")
        #     elif key == "message":
        #         headers.append("Message")
        #     elif key == "src_country":
        #         headers.append("Country")
        #     elif key == "src_city":
        #         headers.append("City")
        #     elif key == "latitude":
        #         headers.append("Lat")
        #     elif key == "longitude":
        #         headers.append("Lon")
        #     elif key == "category":
        #         headers.append("Category")
        #     else:
        #         headers.append(key)

        main_layout = QVBoxLayout(self)

        top_layout = QHBoxLayout()
        self.ip_search = QLineEdit()
        self.ip_search.setPlaceholderText("Filter source IP")
        self.ip_search.returnPressed.connect(self.refresh_alerts)

        self.port_search = QLineEdit()
        self.port_search.setPlaceholderText("Filter port")
        self.port_search.returnPressed.connect(self.refresh_alerts)

        top_layout.addWidget(QLabel("IP:"))
        top_layout.addWidget(self.ip_search)
        top_layout.addWidget(QLabel("Port:"))
        top_layout.addWidget(self.port_search)

        top_layout.addStretch()

        self.clear_button = make_small_button("Clear alerts")
        self.clear_button.clicked.connect(self.clear_alerts)
        top_layout.addWidget(self.clear_button)

        self.block_ip_btn = make_small_button("Block source IP")
        self.block_ip_btn.clicked.connect(self.on_block_source_ip)
        top_layout.addWidget(self.block_ip_btn)

        # Demo Button
        self.test_notif_btn = make_small_button("Trigger Test Alert")
        self.test_notif_btn.clicked.connect(self.trigger_demo_notif)
        top_layout.addWidget(self.test_notif_btn)



        self.table = QTableWidget()
        self.table.setColumnCount(11)
        self.table.setHorizontalHeaderLabels(
            [
                "Time",
                "Severity",
                "Type",
                "Source IP",
                "Destination IP",
                "Port",
                "PID",
                "Process",
                "Lat",
                "Lon",
                "Message",
            ]
        )
        self.table.setSortingEnabled(False)
        
        # tune_table(self.table)
        
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        # header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive) # TableColumnManager handles this

        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        
        self.col_manager = TableColumnManager(self.table, "alerts_table_state")
        self.col_manager.setup()

        # Add "Explain Alert" toggle button
        self.explain_btn = QPushButton("Explain Alert")
        self.explain_btn.setCheckable(True)
        self.explain_btn.setChecked(False)
        self.explain_btn.toggled.connect(self._toggle_explain_panel)
        top_layout.addWidget(self.explain_btn)
        
        main_layout.addLayout(top_layout)
        
        # Create splitter with table and explanation panel
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.addWidget(self.table)
        
        # Explanation panel (hidden by default)
        self.explain_panel = QTextEdit()
        self.explain_panel.setReadOnly(True)
        self.explain_panel.setVisible(False)
        self.explain_panel.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #e5e7eb;
                font-size: 13px;
                padding: 8px;
                border: 1px solid #334155;
                border-radius: 4px;
            }
        """)
        self.splitter.addWidget(self.explain_panel)
        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 2)
        
        main_layout.addWidget(self.splitter)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_alerts)
        self.timer.start(5000)

        self.refresh_alerts()

        app = QApplication.instance()
        if app:
            app.aboutToQuit.connect(self.cleanup)

    def cleanup(self):
        if hasattr(self, "timer") and self.timer.isActive():
            self.timer.stop()
        if hasattr(self, "col_manager"):
            self.col_manager.save_state()

    def trigger_demo_notif(self):
        """Manually trigger a notification for demonstration."""
        try:
            main_window = self.window()
            if main_window and hasattr(main_window, 'notification_manager'):
                nm = main_window.notification_manager
                if nm:
                    nm.notify_alert(
                        "DEMO ALERT", 
                        "This alert was triggered manually for the presentation.", 
                        "high"
                    )
        except Exception:
            pass

    def refresh_alerts(self):
        time_field = self.field_map.get("time")
        try:
            if time_field:
                base_qs = Alert.objects.order_by(f"-{time_field}")
            else:
                base_qs = Alert.objects.order_by("-id")

            ip_term = (
                self.ip_search.text().strip() if hasattr(self, "ip_search") else ""
            )
            if ip_term:
                try:
                    base_qs = base_qs.filter(src_ip__startswith=ip_term)
                except Exception as e:
                    log.debug("Failed to filter alerts by src_ip: %s", e)

            port_term = (
                self.port_search.text().strip() if hasattr(self, "port_search") else ""
            )
            if port_term.isdigit():
                pval = int(port_term)
                try:
                    base_qs = base_qs.filter(dst_port=pval)
                except Exception:
                    try:
                        base_qs = base_qs.filter(dstport=pval)
                    except Exception:
                        try:
                            base_qs = base_qs.filter(port=pval)
                        except Exception as e:
                            log.debug("Failed to filter alerts by port field: %s", e)

            alerts = list(base_qs[:200])
        except DatabaseError:
            return

        # Notify for new alerts (only unresolved, high/critical severity)
        self._notify_new_alerts(alerts)

        self.table.setRowCount(len(alerts))

        for row, a in enumerate(alerts):
            # Time column
            local_time = timezone.localtime(a.timestamp)
            t_item = QTableWidgetItem(local_time.strftime("%Y-%m-%d %H:%M:%S"))
            t_item.setData(Qt.ItemDataRole.UserRole, a.id)
            self.table.setItem(row, 0, t_item)
            self.table.setItem(row, 1, QTableWidgetItem(a.severity or ""))
            self.table.setItem(row, 2, QTableWidgetItem(a.alert_type or ""))
            self.table.setItem(row, 3, QTableWidgetItem(a.src_ip or ""))
            self.table.setItem(row, 4, QTableWidgetItem(a.dst_ip or ""))

            port_text = str(a.dst_port) if a.dst_port is not None else ""
            self.table.setItem(row, 5, QTableWidgetItem(port_text))

            pid_text = str(a.pid) if getattr(a, "pid", None) is not None else ""
            self.table.setItem(row, 6, QTableWidgetItem(pid_text))

            proc_name = getattr(a, "process_name", None) or getattr(a, "proc_name", None) or ""
            self.table.setItem(row, 7, QTableWidgetItem(proc_name))

            lat_text = f"{a.latitude:.4f}" if a.latitude is not None else ""
            lon_text = f"{a.longitude:.4f}" if a.longitude is not None else ""
            self.table.setItem(row, 8, QTableWidgetItem(lat_text))
            self.table.setItem(row, 9, QTableWidgetItem(lon_text))

            self.table.setItem(row, 10, QTableWidgetItem(a.message or ""))

            self._color_row_by_severity(row, a)

        if "category" in self.logical_columns:
            try:
                cat_col = self.logical_columns.index("category")
                for r in range(self.table.rowCount()):
                    cell = self.table.item(r, cat_col)
                    if cell and cell.text().strip():
                        self.table.scrollToItem(cell)
                        break
            except Exception as e:
                log.debug("Failed to scroll to category cell: %s", e)

        # self.table.resizeColumnsToContents() # Disabled to allow user resizing

    def _color_row_by_severity(self, row, alert_obj):
        """
        Apply background color to the row based on alert severity.
        """
        field_name = self.field_map.get("severity")
        if not field_name:
            return

        sev = getattr(alert_obj, field_name, "") or ""
        sev = str(sev).lower()

        if "critical" in sev or "high" in sev:
            color = "#7a1f1f"
        elif "medium" in sev:
            color = "#7a6a1f"
        elif "low" in sev or "info" in sev:
            color = "#1f4d7a"
        else:
            return

        brush = QBrush(QColor(color))
        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            if item:
                item.setBackground(brush)

    def clear_alerts(self):
        reply = QMessageBox.question(
            self,
            "Clear alerts",
            "Delete all alerts from the database?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        Alert.objects.all().delete()
        self.refresh_alerts()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.col_manager.handle_resize()





    def _get_selected_src_ip(self) -> str | None:
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, self.SRC_IP_COL)
        if item is None:
            return None
        ip = item.text().strip()
        return ip or None

    def on_block_source_ip(self):
        """
        Handler for the 'Block source IP' button.
        Triggers a firewall block via the privileged helper.
        """
        if not settings_api.firewall_allowed():
            QMessageBox.warning(
                self,
                "Firewall disabled",
                "Firewall control is disabled in Settings.\n\n"
                "Enable 'Allow Flow to manage firewall rules' in the Settings tab.",
            )
            return

        # Get IP first
        ip = self._get_selected_src_ip()
        if not ip:
            QMessageBox.information(
                self,
                "No alert selected",
                "Select an alert row with a valid source IP first.",
            )
            return

        # Attempt to get severity from the alert object associated with the row
        severity = "medium"
        row = self.table.currentRow()
        if row >= 0:
            item = self.table.item(row, 0)
            if item:
                alert_id = item.data(Qt.ItemDataRole.UserRole)
                if alert_id:
                    try:
                        alert = Alert.objects.get(id=alert_id)
                        severity = getattr(alert, "severity", "medium").lower()
                    except Exception:
                        pass

        confirm = QMessageBox.question(
            self,
            "Block IP",
            f"Add a firewall rule to block traffic from {ip}?\n"
            f"Severity: {severity}\n\n"
            "This uses nftables via pkexec. You might be asked for your password.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if confirm != QMessageBox.StandardButton.Yes:
            return

        ok, msg = block_ip(ip, severity=severity)

        if ok:
            QMessageBox.information(
                self,
                "Firewall rule added",
                f"IP {ip} was sent to nftables.\n\nResult: {msg}",
            )
        else:
            QMessageBox.warning(
                self,
                "Firewall rule failed",
                f"Could not add rule for {ip}.\n\nError: {msg}",
            )
        log.info("Firewall result for %s: ok=%s msg=%s", ip, ok, msg)

    def _on_selection_changed(self):
        row = self.table.currentRow()
        if row < 0:
            self.alert_selected.emit(None)
            return

        item = self.table.item(row, 0)
        if not item:
            return

        alert_id = item.data(Qt.ItemDataRole.UserRole)
        if not alert_id:
            return

        try:
            alert = Alert.objects.get(id=alert_id)
            self.alert_selected.emit(alert)
            # Update explanation panel if visible
            self._update_explanation(alert)
        except Alert.DoesNotExist:
            self.alert_selected.emit(None)
        except Exception as e:
            log.error("Error fetching selected alert: %s", e)

    def _toggle_explain_panel(self, checked):
        """Toggle visibility of the explanation panel."""
        self.explain_panel.setVisible(checked)
        if checked:
            # Update explanation for current selection
            row = self.table.currentRow()
            if row >= 0:
                item = self.table.item(row, 0)
                if item:
                    alert_id = item.data(Qt.ItemDataRole.UserRole)
                    try:
                        alert = Alert.objects.get(id=alert_id)
                        self._update_explanation(alert)
                    except Exception:
                        pass

    def _update_explanation(self, alert):
        """Update the explanation panel with alert details."""
        if not self.explain_panel.isVisible():
            return
        
        if alert is None:
            self.explain_panel.setText("Select an alert to see details.")
            return
        
        self.explain_panel.setText(self._build_explanation(alert))

    def _build_explanation(self, alert) -> str:
        """Build human-readable explanation for an alert."""
        lines = []
        
        lines.append("=" * 40)
        lines.append("ALERT DETAILS")
        lines.append("=" * 40)
        lines.append("")
        
        lines.append(f"Alert Type: {alert.alert_type or 'Unknown'}")
        lines.append(f"Severity: {(alert.severity or 'medium').upper()}")
        lines.append(f"Detected At: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        lines.append("-" * 40)
        lines.append("NETWORK DETAILS")
        lines.append("-" * 40)
        
        if alert.src_ip:
            lines.append(f"Source IP: {alert.src_ip}")
            if alert.latitude is not None and alert.longitude is not None:
                lines.append(f"Location: {alert.latitude:.4f}, {alert.longitude:.4f}")
        if alert.dst_ip:
            lines.append(f"Destination IP: {alert.dst_ip}")
        if alert.dst_port:
            lines.append(f"Destination Port: {alert.dst_port}")
        lines.append("")
        
        if alert.process_name or alert.pid:
            lines.append("-" * 40)
            lines.append("PROCESS DETAILS")
            lines.append("-" * 40)
            if alert.process_name:
                lines.append(f"Process: {alert.process_name}")
            if alert.pid:
                lines.append(f"PID: {alert.pid}")
            lines.append("")
        
        if alert.category:
            lines.append(f"Category: {alert.category}")
            lines.append("")
        
        lines.append("-" * 40)
        lines.append("DESCRIPTION")
        lines.append("-" * 40)
        lines.append(alert.message or "No additional details.")
        lines.append("")
        
        lines.append("-" * 40)
        lines.append("STATUS")
        lines.append("-" * 40)
        if alert.resolved:
            lines.append("✓ RESOLVED")
        else:
            lines.append("⚠ ACTIVE THREAT")
        
        return "\n".join(lines)

    def _notify_new_alerts(self, alerts):
        """
        Send notifications for new, unresolved, high-severity alerts.
        Only notifies once per alert (tracked by seen_alert_ids).
        """
        # Get notification manager from parent window
        try:
            main_window = self.window()
            if not main_window or not hasattr(main_window, 'notification_manager'):
                return
            nm = main_window.notification_manager
            if not nm:
                return
        except Exception:
            return
        
        for alert in alerts:
            # Skip if already seen
            if alert.id in self.seen_alert_ids:
                continue
            
            # Skip resolved alerts
            if alert.resolved:
                self.seen_alert_ids.add(alert.id)
                continue
            
            # Only notify for medium/high/critical severity
            severity = (alert.severity or "").lower()
            if severity not in ("medium", "high", "critical"):
                self.seen_alert_ids.add(alert.id)
                continue
            
            # Send notification
            nm.notify_alert(
                title=f"Flow Alert: {alert.alert_type or 'Security Event'}",
                message=alert.message or f"Alert from {alert.src_ip}",
                severity=severity
            )
            
            self.seen_alert_ids.add(alert.id)
            log.info(f"Sent notification for alert {alert.id}")

