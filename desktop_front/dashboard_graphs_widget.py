"""
Dashboard Graphs Widget.

This module provides the real-time matplotlib graphs for the dashboard.
It plots connection rates and alert rates over the last N minutes.
"""

import sys
from pathlib import Path
from datetime import timedelta
from collections import deque
import warnings
import logging
from django.utils import timezone
from django.db import DatabaseError
from django.db.models import Count
from django.db.models.functions import TruncMinute
from core.models import Connection, Alert

log = logging.getLogger(__name__)

from PyQt6.QtCore import QTimer, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
)

from matplotlib.figure import Figure  # noqa: E402
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas  # noqa: E402

class GraphWorker(QThread):
    """
    Background thread to compute time-series data for graphs.
    """
    data_ready = pyqtSignal(list, list, list)

    def __init__(self, minutes):
        super().__init__()
        self.minutes = minutes

    def run(self):
        from django.db import connection
        try:
            labels, conn_series, alert_series = self._gather_timeseries()
            self.data_ready.emit(labels, conn_series, alert_series)
        except Exception as e:
            log.exception("Graph worker failed: %s", e)
        finally:
            connection.close()

    def _query_counts_last_minute(self, start_dt, end_dt):
        try:
            conn_count = Connection.objects.filter(
                timestamp__gte=start_dt, timestamp__lt=end_dt
            ).count()
        except DatabaseError:
            conn_count = 0
        except Exception:
            conn_count = 0

        fields = {f.name for f in Alert._meta.fields}
        if "timestamp" in fields:
            try:
                alert_count = Alert.objects.filter(
                    timestamp__gte=start_dt, timestamp__lt=end_dt
                ).count()
            except DatabaseError:
                alert_count = 0
            except Exception:
                alert_count = 0
        else:
            alert_count = 0

        return conn_count, alert_count

    def _gather_timeseries(self):
        now = timezone.now()
        # Round down 'now' to nearest minute to align buckets
        now = now.replace(second=0, microsecond=0)
        start_range = now - timedelta(minutes=self.minutes)

        # Initialize dense timeline with zeros
        # We want descending order logic often, but let's build a dict first
        # key = datetime
        timeline = {}
        # Pre-fill last N minutes
        for i in range(self.minutes):
            dt = start_range + timedelta(minutes=i + 1)
            # Ensure timezone awareness consistency if needed, 
            # generally TruncMinute returns timezone-aware if USE_TZ=True
            timeline[dt] = {"conn": 0, "alert": 0}

        try:
            # Aggregate Connections
            conn_qs = (
                Connection.objects.filter(timestamp__gte=start_range)
                .annotate(minute=TruncMinute("timestamp"))
                .values("minute")
                .annotate(count=Count("id"))
                .order_by("minute")
            )
            for entry in conn_qs:
                m = entry["minute"]
                # m is aware datetime. We need to match with timeline keys.
                # timeline keys were constructed from 'now', safe to assume they match 
                # if truncate logic is same.
                # But TruncMinute returns start of minute.
                if m in timeline:
                    timeline[m]["conn"] = entry["count"]
                else:
                    # In case of drift or 'now' differences, try generic replacement
                    m_safe = m.replace(second=0, microsecond=0)
                    if m_safe in timeline:
                        timeline[m_safe]["conn"] = entry["count"]

            # Aggregate Alerts
            alert_qs = (
                Alert.objects.filter(timestamp__gte=start_range)
                .annotate(minute=TruncMinute("timestamp"))
                .values("minute")
                .annotate(count=Count("id"))
                .order_by("minute")
            )
            for entry in alert_qs:
                m = entry["minute"]
                if m in timeline:
                    timeline[m]["alert"] = entry["count"]
                else:
                    m_safe = m.replace(second=0, microsecond=0)
                    if m_safe in timeline:
                        timeline[m_safe]["alert"] = entry["count"]

        except Exception as e:
            log.warning("Aggregation query failed: %s", e)

        # Convert back to sorted lists
        labels = []
        conn_series = []
        alert_series = []

        # sorted by time ascending
        sorted_keys = sorted(timeline.keys())
        for dt in sorted_keys:
            labels.append(timezone.localtime(dt).strftime("%H:%M"))
            conn_series.append(timeline[dt]["conn"])
            alert_series.append(timeline[dt]["alert"])

        return labels, conn_series, alert_series


class DashboardGraphsWidget(QWidget):
    """
    Widget containing the Matplotlib canvas for traffic graphs.
    """
    def __init__(self, parent=None, minutes=30, refresh_interval_ms=5000):
        super().__init__(parent)

        self.minutes = int(minutes)
        self.refresh_interval_ms = int(refresh_interval_ms)
        self.worker = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0) # No margins to fit seamlessly

        # Dark theme setup for Matplotlib
        import matplotlib.pyplot as plt
        plt.style.use('dark_background')

        self.fig_conn = Figure(figsize=(6, 3.0), tight_layout=True)
        self.fig_conn.patch.set_facecolor('#121212') # Match app background
        self.canvas_conn = FigureCanvas(self.fig_conn)
        self.ax_conn = self.fig_conn.subplots()
        self.ax_conn.set_facecolor('#121212')

        self.fig_alert = Figure(figsize=(6, 3.0), tight_layout=True)
        self.fig_alert.patch.set_facecolor('#121212')
        self.canvas_alert = FigureCanvas(self.fig_alert)
        self.ax_alert = self.fig_alert.subplots()
        self.ax_alert.set_facecolor('#121212')

        layout.addWidget(self.canvas_conn)
        layout.addWidget(self.canvas_alert)

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.canvas_conn.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.canvas_alert.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )

        controls = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh now")
        self.refresh_btn.clicked.connect(self._update)
        # Style the refresh button to look clickable
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #333333;
                color: #f0f0f0;
                border: 1px solid #555555;
                padding: 4px 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #444444;
            }
        """)
        
        self.range_label = QLabel(f"Range: last {self.minutes} minutes")
        self.range_label.setStyleSheet("color: #888888;")
        controls.addWidget(self.range_label)
        controls.addStretch()
        controls.addWidget(self.refresh_btn)
        layout.addLayout(controls)

        self._time_labels = deque(maxlen=self.minutes)
        self._conn_counts = deque(maxlen=self.minutes)
        self._alert_counts = deque(maxlen=self.minutes)

        self._init_buffers()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._update)
        self.timer.start(self.refresh_interval_ms)

        # Initial update
        QTimer.singleShot(100, self._update)

    def _init_buffers(self):
        now = timezone.now()
        for i in range(self.minutes):
            t = now - timedelta(minutes=self.minutes - i - 1)
            label = timezone.localtime(t).strftime("%H:%M")
            self._time_labels.append(label)
            self._conn_counts.append(0)
            self._alert_counts.append(0)

    def _update(self):
        # Skip drawing if widget is not visible or too small (prevents layout warnings)
        if not self.isVisible() or self.width() < 10 or self.height() < 10:
            return
        
        if self.worker is not None and self.worker.isRunning():
            return

        self.worker = GraphWorker(self.minutes)
        self.worker.data_ready.connect(self._on_data_ready)
        self.worker.start()

    def _on_data_ready(self, labels, conn_series, alert_series):
        self._time_labels.clear()
        self._conn_counts.clear()
        self._alert_counts.clear()

        for lbl, c, a in zip(labels, conn_series, alert_series):
            self._time_labels.append(lbl)
            self._conn_counts.append(c)
            self._alert_counts.append(a)

        try:
            self.ax_conn.clear()
            # Blue fill for connections
            self.ax_conn.fill_between(
                list(self._time_labels),
                list(self._conn_counts),
                color="#3b82f6",
                alpha=0.3
            )
            self.ax_conn.plot(
                list(self._time_labels),
                list(self._conn_counts),
                color="#60a5fa", # Lighter blue line
                marker="o",
                linewidth=1.5,
                markersize=4,
            )
            self.ax_conn.set_title("Connections per minute", color="#e5e7eb")
            self.ax_conn.set_ylabel("Connections", color="#9ca3af")
            self.ax_conn.tick_params(axis="x", rotation=45, colors="#9ca3af")
            self.ax_conn.tick_params(axis="y", colors="#9ca3af")
            self.ax_conn.grid(True, linewidth=0.3, color="#374151")
            
            # Remove spines
            self.ax_conn.spines['top'].set_visible(False)
            self.ax_conn.spines['right'].set_visible(False)
            self.ax_conn.spines['bottom'].set_color('#374151')
            self.ax_conn.spines['left'].set_color('#374151')
            
            self.canvas_conn.draw()
        except Exception as e:
            log.warning("Failed to draw connections graph: %s", e)

        try:
            self.ax_alert.clear()
            # Green line for alerts
            self.ax_alert.plot(
                list(self._time_labels),
                list(self._alert_counts),
                color="#4ade80", # Green line
                marker="o",
                linewidth=1.5,
                markersize=4,
            )
            self.ax_alert.set_title("Alerts per minute", color="#e5e7eb")
            self.ax_alert.set_ylabel("Alerts", color="#9ca3af")
            self.ax_alert.tick_params(axis="x", rotation=45, colors="#9ca3af")
            self.ax_alert.tick_params(axis="y", colors="#9ca3af")
            self.ax_alert.grid(True, linewidth=0.3, color="#374151")

            # Remove spines
            self.ax_alert.spines['top'].set_visible(False)
            self.ax_alert.spines['right'].set_visible(False)
            self.ax_alert.spines['bottom'].set_color('#374151')
            self.ax_alert.spines['left'].set_color('#374151')

            self.canvas_alert.draw()
        except Exception as e:
            log.warning("Failed to draw alerts graph: %s", e)


if __name__ == "__main__":
    from PyQt6.QtWidgets import QApplication

    app = QApplication(sys.argv)
    w = DashboardGraphsWidget(minutes=20, refresh_interval_ms=5000)
    w.show()
    sys.exit(app.exec())
