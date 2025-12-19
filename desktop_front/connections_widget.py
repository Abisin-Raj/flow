from datetime import datetime
from django.utils.timezone import localtime
from PyQt6.QtCore import Qt, QTimer, QThread, QObject, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QColor, QBrush
from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QStyledItemDelegate,
    QStyle,
    QComboBox,  # Added for status filter
)

from desktop_front.ui_helpers import make_small_button

from django.db import DatabaseError, connections

from core.models import Connection
from desktop_front.ui_utils import TableColumnManager


class StatusDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        painter.save()
        
        # Handle selection background
        if option.state & QStyle.StateFlag.State_Selected:
            painter.fillRect(option.rect, QColor("#333333"))
            
        # Get text and color
        text = index.data(Qt.ItemDataRole.DisplayRole)
        fg_brush = index.data(Qt.ItemDataRole.ForegroundRole)
        
        if text:
            # Determine text color
            if fg_brush and isinstance(fg_brush, QBrush):
                color = fg_brush.color()
            elif isinstance(fg_brush, QColor):
                color = fg_brush
            else:
                color = QColor("#e0e0e0")
            
            painter.setPen(color)
            
            # Set Bold Font
            font = painter.font()
            font.setBold(True)
            painter.setFont(font)
            
            painter.drawText(option.rect, Qt.AlignmentFlag.AlignCenter, str(text))
            
        painter.restore()


class ConnectionsWorker(QObject):
    data_ready = pyqtSignal(list)
    error = pyqtSignal(str)

    @pyqtSlot(int, str, str, str)
    def refresh(self, limit, ip_filter, port_filter, status_filter=""):
        from django.db import connection
        try:
            # Force close potentially old/stale connection for this thread
            connection.close()
            
            qs = Connection.objects.all().order_by("-timestamp")

            if ip_filter:
                qs = qs.filter(
                    src_ip__icontains=ip_filter
                ) | qs.filter(dst_ip__icontains=ip_filter)

            if port_filter:
                try:
                    port_int = int(port_filter)
                    qs = qs.filter(src_port=port_int) | qs.filter(dst_port=port_int)
                except ValueError:
                    pass
            
            # Apply status filter if specified
            if status_filter:
                qs = qs.filter(status__icontains=status_filter)

            # Use values() to get dicts
            data = list(qs.values(
                "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "status", "pid", "process_name"
            )[: limit])

            self.data_ready.emit(data)
        except DatabaseError as e:
            self.error.emit(f"Database busy: {e}")
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.error.emit(f"Error loading connections: {e}")
        finally:
            # Close DB connection to prevent leaks/locking in this thread
            connections.close_all()


class ConnectionsWidget(QWidget):
    request_refresh = pyqtSignal(int, str, str, str)

    def __init__(self, parent=None):
        super().__init__(parent)

        self.limit = 200
        self.refresh_interval_ms = 3000
        self._is_loading = False

        self._build_ui()
        
        # Initialize Thread and Worker
        self.thread = QThread()
        self.worker = ConnectionsWorker()
        self.worker.moveToThread(self.thread)
        
        # Connect signals
        self.request_refresh.connect(self.worker.refresh)
        self.worker.data_ready.connect(self._on_data_loaded)
        self.worker.error.connect(self._on_error)
        
        # Cleanup on app exit
        app = QApplication.instance()
        if app:
            app.aboutToQuit.connect(self._cleanup_thread)
        
        # Start thread
        self.thread.start()

        self._setup_timer()
        
        # Initial refresh
        QTimer.singleShot(100, self.refresh_table)
        
        # Force column resizing to be enabled after layout is done
        QTimer.singleShot(500, self._enforce_resize_mode)

    def _enforce_resize_mode(self):
        """
        Nuclear option: Force Interactive mode after everything is loaded.
        """
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        for i in range(self.table.columnCount()):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.Interactive)

    def _build_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)
        self.setLayout(layout)

        filter_row = QHBoxLayout()
        filter_row.setSpacing(4)

        self.ip_filter_edit = QLineEdit()
        self.ip_filter_edit.setPlaceholderText("Filter by IP (source or destination)")
        filter_row.addWidget(self.ip_filter_edit, 3)

        self.port_filter_edit = QLineEdit()
        self.port_filter_edit.setPlaceholderText("Filter by port")
        filter_row.addWidget(self.port_filter_edit, 1)
        
        # Status filter dropdown
        self.status_filter = QComboBox()
        self.status_filter.addItems(["ESTABLISHED", "All Statuses", "LISTEN", "TIME_WAIT", "CLOSE_WAIT"])
        self.status_filter.setCurrentText("ESTABLISHED")
        self.status_filter.setToolTip("Filter by connection status")
        filter_row.addWidget(self.status_filter, 1)

        apply_btn = make_small_button("Apply filter")
        apply_btn.clicked.connect(self.refresh_table)
        filter_row.addWidget(apply_btn)

        clear_btn = make_small_button("Clear filter")
        clear_btn.clicked.connect(self._clear_filters)
        filter_row.addWidget(clear_btn)

        refresh_btn = make_small_button("Refresh now")
        refresh_btn.clicked.connect(self.refresh_table)
        filter_row.addWidget(refresh_btn)

        layout.addLayout(filter_row)

        self.table = QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels(
            [
                "Time",
                "Src IP",
                "Src Port",
                "Dst IP",
                "Dst Port",
                "Protocol",
                "Status",
                "PID",
                "Process",
            ]
        )
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(False)
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
        self.table.setSortingEnabled(False)
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        
        self.col_manager = TableColumnManager(self.table, "connections_table_state")
        self.col_manager.setup()

        # Use the delegate for the Status column (index 6)
        self.table.setItemDelegateForColumn(6, StatusDelegate(self.table))

        # tune_table(self.table)  # Removed to allow interactive resizing via TableColumnManager

        layout.addWidget(self.table)

        self.status_label = QLabel("Last refresh: never")
        self.status_label.setStyleSheet("color: #aaaaaa; padding-top: 2px;")
        layout.addWidget(self.status_label)

    def _setup_timer(self):
        self.timer = QTimer(self)
        self.timer.setInterval(self.refresh_interval_ms)
        self.timer.timeout.connect(self.refresh_table)
        self.timer.start()

    def _clear_filters(self):
        self.ip_filter_edit.clear()
        self.port_filter_edit.clear()
        self.status_filter.setCurrentText("ESTABLISHED")
        self.refresh_table()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.col_manager.handle_resize()

    def refresh_table(self):
        # We can allow multiple requests or debounce. 
        # Since we have a worker, we can just emit the signal.
        # But to avoid flooding, we can check a flag or just let the queue handle it.
        # Let's keep it simple.
        
        ip_filter = self.ip_filter_edit.text().strip()
        port_filter = self.port_filter_edit.text().strip()
        status_filter = self.status_filter.currentText()
        
        # Convert "All Statuses" to empty string for no filtering
        if status_filter == "All Statuses":
            status_filter = ""
        
        self.request_refresh.emit(self.limit, ip_filter, port_filter, status_filter)

    def _on_data_loaded(self, rows):
        self.table.setRowCount(len(rows))

        for row_idx, conn_dict in enumerate(rows):
            try:
                self._set_row(row_idx, conn_dict)
            except Exception:
                import traceback
                traceback.print_exc()

        now_txt = datetime.now().strftime("%H:%M:%S")
        self.status_label.setText(f"Last refresh: {now_txt}")

    def _on_error(self, err_msg):
        self.status_label.setText(err_msg)

    def _set_row(self, row, conn_dict):
        # Time and connection data
        ts = conn_dict.get("timestamp")
        if ts:
            ts = localtime(ts)
        time_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else ""

        cols = [
            time_str,
            conn_dict.get("src_ip") or "",
            str(conn_dict.get("src_port") or ""),
            conn_dict.get("dst_ip") or "",
            str(conn_dict.get("dst_port") or ""),
            (conn_dict.get("protocol") or "").lower(),
        ]

        for col, value in enumerate(cols):  # Start from column 0
            item = QTableWidgetItem(value)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            self.table.setItem(row, col, item)

        status_text = conn_dict.get("status") or ""
        status_item = QTableWidgetItem(status_text.upper())
        status_item.setFlags(status_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        # Set text color (foreground) instead of background
        color = self._status_color(status_text)
        status_item.setForeground(QBrush(color))
        
        self.table.setItem(row, 6, status_item)  # Column 6 (Protocol is 5)

        # PID
        pid_val = conn_dict.get("pid")
        pid_text = str(pid_val) if pid_val is not None else ""
        pid_item = QTableWidgetItem(pid_text)
        pid_item.setFlags(pid_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.table.setItem(row, 7, pid_item)  # Column 7

        # Process
        proc_name = conn_dict.get("process_name") or ""
        proc_item = QTableWidgetItem(proc_name)
        proc_item.setFlags(proc_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.table.setItem(row, 8, proc_item)  # Column 8

    def _status_color(self, status):
        s = (status or "").upper()

        # Brighter colors for text on dark background
        if "ESTABLISHED" in s:
            return QColor("#4caf50") # Green
        if "LISTEN" in s:
            return QColor("#64b5f6") # Blue
        if "SYN" in s:
            return QColor("#ff9800") # Orange
        if "TIME_WAIT" in s or "CLOSE_WAIT" in s or "FIN" in s:
            return QColor("#ffd54f") # Amber
        
        return QColor("#bdbdbd") # Grey
        
    def _cleanup_thread(self):
        if hasattr(self, "col_manager"):
            self.col_manager.save_state()
        if hasattr(self, "thread") and self.thread.isRunning():
            self.thread.quit()
            self.thread.wait()




