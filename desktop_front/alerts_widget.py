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
    SRC_IP_COL = 3  # "Source IP" column (was 4 when icon column existed)
    alert_selected = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)

        self.field_map = _get_field_map()

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



        self.table = QTableWidget()
        self.table.setColumnCount(9)
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
                "Message",
            ]
        )
        self.table.setSortingEnabled(False)
        
        tune_table(self.table)

        self.table.itemSelectionChanged.connect(self._on_selection_changed)


        
        self.col_manager = TableColumnManager(self.table, "alerts_table_state")
        self.col_manager.setup()

        main_layout.addLayout(top_layout)
        main_layout.addWidget(self.table)

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

            self.table.setItem(row, 8, QTableWidgetItem(a.message or ""))

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
        if not settings_api.firewall_allowed():
            QMessageBox.warning(
                self,
                "Firewall disabled",
                "Firewall control is disabled in Settings.\n\n"
                "Enable 'Allow Flow to manage firewall rules' in the Settings tab.",
            )
            return

        ip = self._get_selected_src_ip()
        if not ip:
            QMessageBox.information(
                self,
                "No alert selected",
                "Select an alert row with a valid source IP first.",
            )
            return

        confirm = QMessageBox.question(
            self,
            "Block IP",
            f"Add a firewall rule to block traffic from {ip}?\n\n"
            "This uses nftables via pkexec. You might be asked for your password.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if confirm != QMessageBox.StandardButton.Yes:
            return

        ok, msg = block_ip(ip)

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
        except Alert.DoesNotExist:
            self.alert_selected.emit(None)
        except Exception as e:
            log.error("Error fetching selected alert: %s", e)
