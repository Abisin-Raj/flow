"""
Threat Timeline Widget.

This module provides a unified chronological view of security events.
It combines network alerts, file quarantine events, and connection details.
It also integrates process ancestry (process tree) to show the origin of threats.
"""

from datetime import timedelta

from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QApplication,
)

from desktop_front.ui_helpers import tune_table

from django.utils import timezone

from core.models import Alert, QuarantinedFile
from core.process_tree import build_process_chain


class ThreatTimelineWidget(QWidget):
    """
    Unified attack timeline:
    - Alerts
    - Connection info
    - Process chain (parent tree)
    - File quarantine events (if present)
    
    Auto-refreshes every 5 seconds.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)
        
        self.table = QTableWidget(self)
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(
            [
                "Time",
                "Type",
                "Severity",
                "Source",
                "Destination",
                "Details",
                "Process Chain",
            ]
        )
        
        # Dark theme styling
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #121212;
                color: #e0e0e0;
                gridline-color: #333333;
                border: none;
            }
            QHeaderView::section {
                background-color: #1e1e1e;
                color: #e0e0e0;
                border: 1px solid #333333;
                padding: 4px;
            }
            QTableWidget::item {
                border-bottom: 1px solid #333333;
            }
            QTableWidget::item:selected {
                background-color: #333333;
            }
        """)
        
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        # Equal width for all columns initially, but allow checking
        width = self.table.viewport().width()
        if width > 0:
            count = self.table.columnCount()
            col_width = width // count
            for i in range(count):
                self.table.setColumnWidth(i, col_width)
        
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(False)
        
        tune_table(self.table)
        
        # Add persistence
        from desktop_front.ui_utils import TableColumnManager
        self.col_manager = TableColumnManager(self.table, "timeline_table_state")
        self.col_manager.setup()

        layout.addWidget(self.table)
        self.setLayout(layout)

        self.timer = QTimer(self)
        self.timer.setInterval(5000)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()
        
        # Connect cleanup
        app = QApplication.instance()
        if app:
            app.aboutToQuit.connect(self.cleanup)

        self.refresh()

    def cleanup(self):
        if hasattr(self, "col_manager"):
            self.col_manager.save_state()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "col_manager"):
            self.col_manager.handle_resize()

    def refresh(self):
        """Refresh the threat timeline with recent alerts and quarantine events."""
        import logging
        log = logging.getLogger("desktop_front.threat_timeline")
        
        try:
            from django.db import connection as db_connection
            db_connection.close()  # Force fresh connection for thread safety
            
            # Simple query - no select_related to avoid issues
            alerts = list(Alert.objects.all().order_by("-timestamp")[:100])
            
            log.info(f"Threat timeline: found {len(alerts)} alerts")

            rows = []

            for alert in alerts:
                conn = alert.connection
                
                # Get source IP (from alert or connection)
                src = alert.src_ip or ""
                if not src and conn:
                    src = conn.src_ip or ""
                
                # Get destination
                dst = ""
                if conn and conn.dst_ip:
                    dst = f"{conn.dst_ip}:{conn.dst_port}"
                elif alert.dst_ip:
                    dst_port = f":{alert.dst_port}" if alert.dst_port else ""
                    dst = f"{alert.dst_ip}{dst_port}"

                # Build process chain from connection PID
                chain = ""
                if conn and conn.pid:
                    try:
                        chain = build_process_chain(conn.pid)
                    except Exception:
                        # If process chain building fails, just use PID
                        chain = f"PID {conn.pid}"

                rows.append(
                    {
                        "time": alert.timestamp,
                        "type": alert.alert_type or "Alert",
                        "severity": alert.severity or "",
                        "src": src,
                        "dst": dst,
                        "details": alert.message or "",
                        "process_chain": chain,
                    }
                )

            # Add quarantine events
            # Define window for quarantine lookback (e.g. last 24 hours)
            window = timezone.now() - timedelta(hours=24)
            try:
                q_events = list(
                    QuarantinedFile.objects.filter(detected_at__gte=window)
                    .order_by("-detected_at")
                    [:50]  # Limit quarantine events
                )

                for q in q_events:
                    rows.append(
                        {
                            "time": q.detected_at,
                            "type": "Quarantine",
                            "severity": "high",
                            "src": "",
                            "dst": "",
                            "details": f"File quarantined: {q.filename}",
                            "process_chain": "",
                        }
                    )
            except Exception as e:
                # Quarantine events are optional, so just log and continue
                log.debug(f"Could not fetch quarantine events: {e}")

            # Sort by time descending
            rows.sort(key=lambda r: r["time"], reverse=True)

            # Update table
            self.table.setRowCount(0) # Clear first
            
            if not rows:
                # Show "no data" message
                self.table.setRowCount(1)
                self.table.setItem(0, 0, QTableWidgetItem("No security events found."))
                self.table.setSpan(0, 0, 1, 7) # Span across all columns
            else:
                self.table.setRowCount(len(rows))
                for row_idx, row in enumerate(rows):
                    local_time = timezone.localtime(row["time"])
                    self._set_item(row_idx, 0, local_time.strftime("%Y-%m-%d %H:%M:%S"))
                    self._set_item(row_idx, 1, row["type"])
                    self._set_item(row_idx, 2, row["severity"])
                    self._set_item(row_idx, 3, row["src"])
                    self._set_item(row_idx, 4, row["dst"])
                    self._set_item(row_idx, 5, row["details"])
                    self._set_item(row_idx, 6, row["process_chain"])
                
        except Exception as e:
            # Log error but don't crash the widget
            log.error(f"Error refreshing threat timeline: {e}")

    def _set_item(self, row, col, text):
        item = QTableWidgetItem(str(text))
        item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.table.setItem(row, col, item)
