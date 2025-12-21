"""
Dashboard Widget.

This module implements the main dashboard tab, which provides a high-level overview of the system status.
It includes key metrics (connections today, alerts, quarantines), real-time graphs, and "Top N" lists.
"""

from datetime import datetime, timezone

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QSizePolicy,
)

import logging
from django.db import DatabaseError
from django.db.models import Q

from core.models import Connection, Alert
try:
    from core.models import QuarantinedFile
except Exception:
    QuarantinedFile = None

from desktop_front.dashboard_graphs_widget import DashboardGraphsWidget


log = logging.getLogger(__name__)


class DashboardWorker(QThread):
    """
    Background thread to fetch dashboard statistics from the database.
    This prevents the UI from freezing while performing potentially slow count queries.
    """
    data_ready = pyqtSignal(dict)

    def run(self):
        # Ensure we start with a clean connection state
        from django.db import connection
        connection.close()
        data = {}
        try:
            now = datetime.now(timezone.utc)
            start = datetime(
                now.year,
                now.month,
                now.day,
                tzinfo=timezone.utc,
            )

            # Core counts
            conn_qs = Connection.objects.filter(timestamp__gte=start)
            connections_today = conn_qs.count()

            unique_src_today = (
                conn_qs.exclude(src_ip="")
                .values("src_ip")
                .distinct()
                .count()
            )

            unique_dst_today = (
                conn_qs.exclude(dst_ip="")
                .values("dst_ip")
                .distinct()
                .count()
            )

            # Alerts
            alert_qs = Alert.objects.filter(timestamp__gte=start)
            high_alerts_today = alert_qs.filter(
                Q(severity__icontains="high") | Q(severity__icontains="critical")
            ).count()

            high_alert_ips_today = (
                alert_qs.filter(
                    Q(severity__icontains="high") | Q(severity__icontains="critical")
                )
                .exclude(src_ip="")
                .values("src_ip")
                .distinct()
                .count()
            )

            # Quarantines
            quarantines_total = 0
            if QuarantinedFile is not None:
                quarantines_total = QuarantinedFile.objects.count()

            # Top Ports
            from django.db.models import Count
            top_ports = (
                conn_qs.values("dst_port")
                .annotate(c=Count("id"))
                .order_by("-c")[:5]
            )
            ports_text = ", ".join(
                f"{p['dst_port']} ({p['c']})" for p in top_ports if p["dst_port"]
            ) or "None"

            # Top IPs
            external_qs = (
                conn_qs.exclude(dst_ip__startswith="10.")
                .exclude(dst_ip__startswith="192.168.")
                .exclude(dst_ip__startswith="172.")
                .exclude(dst_ip__startswith="127.")

            )
            top_ips = (
                external_qs.values("dst_ip")
                .annotate(c=Count("id"))
                .order_by("-c")[:5]
            )
            ips_text = ", ".join(
                f"{p['dst_ip']} ({p['c']})" for p in top_ips if p["dst_ip"]
            ) or "None"

            # Traffic Level
            traffic_level = "Quiet"
            if connections_today > 1000:
                traffic_level = "Busy"
            elif connections_today > 100:
                traffic_level = "Normal"

            data = {
                "connections_today": connections_today,
                "unique_src_today": unique_src_today,
                "unique_dst_today": unique_dst_today,
                "high_alerts_today": high_alerts_today,
                "high_alert_ips_today": high_alert_ips_today,
                "quarantines_total": quarantines_total,
                "ports_text": ports_text,
                "ips_text": ips_text,
                "traffic_level": traffic_level,
            }
        except DatabaseError as e:
            log.warning("Dashboard DB busy: %s", e)
            data = {"error": f"Database busy {e}"}
        except Exception as e:
            log.exception("Dashboard query error: %s", e)
            data = {"error": f"Dashboard query error {e}"}
        finally:
            # Explicitly close the connection for this thread to prevent leaks
            connection.close()

        self.data_ready.emit(data)


class DashboardWidget(QWidget):
    """
    The main Dashboard tab UI.
    
    Layout:
    1.  Top Stats Row: Key metrics cards (Connections, Alerts, Quarantines).
    2.  Graphs Section: Real-time traffic plots (via DashboardGraphsWidget).
    3.  Overview Grid: Additional stats and Top-5 lists.
    4.  Footer: Refresh status and controls.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None

        # Labels
        self.connections_label = None
        self.high_alerts_label = None
        self.quarantine_label = None
        self.unique_src_label = None
        self.unique_dst_label = None
        self.high_alert_ips_label = None
        self.traffic_level_label = None
        self.top_ports_label = None
        self.top_ips_label = None
        self.status_label = None

        self._build_ui()
        self._setup_timer()
        self.refresh_dashboard()

    def _build_ui(self):
        """Construct the widget layout."""
        main = QVBoxLayout()
        main.setContentsMargins(12, 12, 12, 12)
        main.setSpacing(12)
        self.setLayout(main)

        # --- Top Stats Row ---
        # Use a fixed width layout or stretch factors to keep these compact
        top_row = QHBoxLayout()
        top_row.setSpacing(12)
        # Add stretch at the end to keep them left-aligned and compact if window is wide
        # Or just let them expand but maybe set max width on cards?
        # Let's try adding them to a container widget with fixed height/width policy if needed.
        # For now, just adding them and a stretch at the end might achieve "smaller columns" feel
        # if they don't take up full width.
        
        main.addLayout(top_row)

        self.connections_label = self._make_stat_card("Connections today", "0", top_row)
        self.high_alerts_label = self._make_stat_card("High alerts today", "0", top_row)
        self.quarantine_label = self._make_stat_card("Quarantines", "0", top_row)
        
        # Add stretch to push them to the left, making them "smaller" in appearance 
        # (not stretching to fill full width)
        top_row.addStretch() 

        # Removed Export button as requested


        # --- Graphs Section ---
        graphs_title = QLabel("Real-time graphs")
        graphs_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        graphs_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #f0f0f0; margin-top: 8px;")
        main.addWidget(graphs_title)

        graphs_frame = QFrame()
        graphs_frame.setFrameShape(QFrame.Shape.StyledPanel)
        graphs_frame.setStyleSheet("background-color: #121212; border-radius: 6px;")
        graphs_layout = QVBoxLayout()
        graphs_layout.setContentsMargins(0, 0, 0, 0)
        graphs_frame.setLayout(graphs_layout)

        self.graphs = DashboardGraphsWidget(self)
        self.graphs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        graphs_layout.addWidget(self.graphs)
        
        range_label = QLabel("Range: last 10 minutes")
        range_label.setStyleSheet("color: #888888; padding: 4px;")
        graphs_layout.addWidget(range_label)

        main.addWidget(graphs_frame)


        # --- Flow Overview Section ---
        overview_title = QLabel("Flow Overview")
        overview_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #f0f0f0; margin-top: 12px;")
        main.addWidget(overview_title)

        # Grid for overview cards
        from PyQt6.QtWidgets import QGridLayout
        grid = QGridLayout()
        grid.setSpacing(12)
        main.addLayout(grid)

        # Row 1 of grid
        self.unique_src_label = self._make_grid_card(grid, 0, 0, "Unique source IPs today", "0", "#3b82f6") # Blue accent
        self.high_alert_ips_label = self._make_grid_card(grid, 0, 1, "High alert IPs today", "0", "#ef4444") # Red accent
        self.traffic_level_label = self._make_grid_card(grid, 0, 2, "Traffic level", "-", "#f59e0b") # Amber accent
        self.unique_dst_label = self._make_grid_card(grid, 0, 3, "Unique destination IPs today", "0", "#10b981") # Green accent

        # Row 2 of grid (Wider cards for lists)
        self.top_ports_label = self._make_list_card(grid, 1, 0, 2, "Top destination ports today", "-")
        self.top_ips_label = self._make_list_card(grid, 1, 2, 2, "Top external IPs today", "-")


        # --- Footer ---
        bottom_row = QHBoxLayout()
        self.status_label = QLabel("Status: idle")
        self.status_label.setStyleSheet("color: #888888;")
        bottom_row.addWidget(self.status_label)
        bottom_row.addStretch()
        
        refresh_btn = QPushButton("Refresh dashboard")
        refresh_btn.clicked.connect(self.refresh_dashboard)
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #333333;
                color: #f0f0f0;
                border: 1px solid #555555;
                padding: 4px 10px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #444444;
            }
        """)
        bottom_row.addWidget(refresh_btn)
        main.addLayout(bottom_row)

    def _make_stat_card(self, title, value, layout):
        frame = QFrame()
        frame.setFixedWidth(200) # Force smaller fixed width
        frame.setStyleSheet("""
            QFrame {
                background-color: #1e1e1e;
                border: 1px solid #333333;
                border-radius: 6px;
            }
        """)
        v = QVBoxLayout()
        v.setContentsMargins(12, 10, 12, 10)
        frame.setLayout(v)
        
        t = QLabel(title)
        t.setStyleSheet("color: #aaaaaa; font-size: 12px; border: none; background: transparent;")
        val = QLabel(value)
        val.setStyleSheet("color: #ffffff; font-size: 18px; font-weight: bold; border: none; background: transparent;")
        
        v.addWidget(t)
        v.addWidget(val)
        layout.addWidget(frame)
        return val

    def _make_grid_card(self, grid, row, col, title, value, accent_color):
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: #1e1e1e;
                border: 1px solid #333333;
                border-radius: 6px;
                border-left: 4px solid {accent_color};
            }}
        """)
        v = QVBoxLayout()
        v.setContentsMargins(12, 12, 12, 12)
        frame.setLayout(v)
        
        t = QLabel(title)
        t.setStyleSheet("color: #cccccc; font-size: 13px; border: none;")
        val = QLabel(value)
        val.setStyleSheet(f"color: {accent_color}; font-size: 24px; font-weight: bold; border: none;")
        
        v.addWidget(t)
        v.addWidget(val)
        grid.addWidget(frame, row, col)
        return val

    def _make_list_card(self, grid, row, col, colspan, title, value):
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background-color: #1e1e1e;
                border: 1px solid #333333;
                border-radius: 6px;
            }
        """)
        v = QVBoxLayout()
        v.setContentsMargins(12, 12, 12, 12)
        frame.setLayout(v)
        
        t = QLabel(title)
        t.setStyleSheet("color: #ffffff; font-weight: bold; font-size: 13px; margin-bottom: 4px;")
        val = QLabel(value)
        val.setStyleSheet("color: #aaaaaa; font-size: 12px; font-family: monospace;")
        val.setWordWrap(True)
        
        v.addWidget(t)
        v.addWidget(val)
        grid.addWidget(frame, row, col, 1, colspan)
        return val

    def _setup_timer(self):
        self.timer = QTimer(self)
        self.timer.setInterval(10000)
        self.timer.timeout.connect(self.refresh_dashboard)
        self.timer.start()

    def refresh_dashboard(self):
        if self.worker is not None and self.worker.isRunning():
            return
        self.status_label.setText("Status: refreshing...")
        self.worker = DashboardWorker()
        self.worker.data_ready.connect(self._update_from_worker)
        self.worker.start()

    def _update_from_worker(self, data):
        if "error" in data:
            self.status_label.setText(data["error"])
            return

        self.connections_label.setText(str(data.get("connections_today", 0)))
        self.high_alerts_label.setText(str(data.get("high_alerts_today", 0)))
        self.quarantine_label.setText(str(data.get("quarantines_total", 0)))

        self.unique_src_label.setText(str(data.get("unique_src_today", 0)))
        self.unique_dst_label.setText(str(data.get("unique_dst_today", 0)))
        self.high_alert_ips_label.setText(str(data.get("high_alert_ips_today", 0)))
        self.traffic_level_label.setText(str(data.get("traffic_level", "-")))
        
        self.top_ports_label.setText(str(data.get("ports_text", "-")))
        self.top_ips_label.setText(str(data.get("ips_text", "-")))

        self.status_label.setText("Status: updated")
