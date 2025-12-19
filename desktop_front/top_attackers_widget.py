from datetime import timedelta

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QMessageBox,
    QApplication,
)
from desktop_front.ui_helpers import make_small_button, tune_table
from desktop_front.ui_utils import TableColumnManager
from core import settings_api
from core.firewall import block_ip

from django.utils import timezone
from django.db.models import Count, Min, Max, Q as DjQ

from core.models import Alert
from core.alert_engine import _get_field_map


class TopAttackersWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.field_map = _get_field_map()
        self.current_entries = []

        main_layout = QVBoxLayout(self)

        header_layout = QHBoxLayout()
        title = QLabel("Top attackers")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        header_layout.addWidget(title)
        header_layout.addStretch()

        header_layout.addWidget(QLabel("Filter IP"))
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("192.168 or 10.")
        header_layout.addWidget(self.ip_input)

        self.apply_button = make_small_button("Apply")
        self.apply_button.clicked.connect(self.refresh)
        header_layout.addWidget(self.apply_button)

        self.clear_button = make_small_button("Clear")
        self.clear_button.clicked.connect(self.clear_filter)
        header_layout.addWidget(self.clear_button)

        self.refresh_button = make_small_button("Refresh now")
        self.refresh_button.clicked.connect(self.refresh)
        header_layout.addWidget(self.refresh_button)

        self.block_ip_btn = make_small_button("Block source IP")
        self.block_ip_btn.clicked.connect(self.on_block_ip)
        header_layout.addWidget(self.block_ip_btn)

        main_layout.addLayout(header_layout)

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(
            [
                "Source IP",
                "Total alerts",
                "High alerts",
                "Medium alerts",
                "Categories",
                "First seen",
                "Last seen",
            ]
        )
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
        tune_table(self.table)
        self.col_manager = TableColumnManager(self.table, "top_attackers_table_state")
        self.col_manager.setup()

        main_layout.addWidget(self.table)

        self.status_label = QLabel("Ready")
        main_layout.addWidget(self.status_label)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(20000)

        self.refresh()

        app = QApplication.instance()
        if app:
            app.aboutToQuit.connect(self.cleanup)

    def _configure_header(self, table):
        pass

    def clear_filter(self):
        self.ip_input.clear()
        self.refresh()

    def refresh(self):
        try:
            self._refresh_data()
            count = len(self.current_entries)
            self.status_label.setText(f"Top attackers updated ({count} rows)")
        except Exception as e:
            import traceback

            traceback.print_exc()
            self.status_label.setText(f"Error updating top attackers: {e}")

    def _refresh_data(self):
        now = timezone.now()
        start = now - timedelta(days=7)

        time_field = self.field_map.get("time") or "timestamp"
        severity_field = self.field_map.get("severity") or "severity"
        src_field = self.field_map.get("src") or "src_ip"
        category_field = self.field_map.get("category") or "category"

        base = Alert.objects.filter(**{f"{time_field}__gte": start})

        ip_filter = self.ip_input.text().strip()
        if ip_filter:
            base = base.filter(**{f"{src_field}__icontains": ip_filter})

        # 1. Get top attackers in one query
        qs = (
            base.values(src_field)
            .exclude(**{f"{src_field}__isnull": True})
            .exclude(**{src_field: ""})
            .annotate(
                total=Count("id"),
                high=Count("id", filter=DjQ(**{f"{severity_field}__iexact": "high"})),
                medium=Count(
                    "id", filter=DjQ(**{f"{severity_field}__iexact": "medium"})
                ),
                first_seen=Min(time_field),
                last_seen=Max(time_field),
            )
            .order_by("-total")
        )

        rows = list(qs[:200])
        self.current_entries = rows
        
        # Ensure columns have visible width
        for i in range(self.table.columnCount()):
            if self.table.columnWidth(i) < 10:
                self.table.setColumnWidth(i, 150)

        if not rows:
            self.table.setRowCount(0)
            return

        # 2. Fetch categories for all those IPs in one query
        src_ips = [r[src_field] for r in rows if r.get(src_field)]

        categories_qs = (
            base.filter(**{f"{src_field}__in": src_ips})
            .values(src_field, category_field)
            .exclude(**{f"{category_field}__isnull": True})
            .exclude(**{category_field: ""})
            .annotate(count=Count("id"))
        )

        # Build a mapping: ip -> list of (category, count) sorted by count
        cat_map = {}
        for row in categories_qs:
            ip = row[src_field]
            cat = row[category_field]
            count = row["count"]
            if ip not in cat_map:
                cat_map[ip] = []
            cat_map[ip].append((cat, count))

        for ip, items in cat_map.items():
            items.sort(key=lambda x: x[1], reverse=True)

        # 3. Populate table
        self.table.setRowCount(len(rows))

        for row_idx, r in enumerate(rows):
            src_ip = r.get(src_field) or "unknown"
            total = r.get("total", 0)
            high = r.get("high", 0)
            medium = r.get("medium", 0)

            first = r.get("first_seen")
            last = r.get("last_seen")
            if first:
                first = timezone.localtime(first)
                first_str = first.strftime("%Y-%m-%d %H:%M:%S")
            else:
                first_str = ""
            if last:
                last = timezone.localtime(last)
                last_str = last.strftime("%Y-%m-%d %H:%M:%S")
            else:
                last_str = ""

            # resolve category summary from cat_map
            cat_info = cat_map.get(src_ip, [])
            cat_parts = []
            for cat, count in cat_info[:5]:
                cat_parts.append(f"{cat} ({count})")
            cats_str = ", ".join(cat_parts) if cat_parts else "none"

            self.table.setItem(row_idx, 0, QTableWidgetItem(str(src_ip)))
            self.table.setItem(row_idx, 1, QTableWidgetItem(str(total)))
            self.table.setItem(row_idx, 2, QTableWidgetItem(str(high)))
            self.table.setItem(row_idx, 3, QTableWidgetItem(str(medium)))
            self.table.setItem(row_idx, 4, QTableWidgetItem(cats_str))
            self.table.setItem(row_idx, 5, QTableWidgetItem(first_str))
            self.table.setItem(row_idx, 6, QTableWidgetItem(last_str))

        # self.table.resizeColumnsToContents()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.col_manager.handle_resize()

    def cleanup(self):
        if hasattr(self, "col_manager"):
            self.col_manager.save_state()

    def on_block_ip(self):
        if not settings_api.firewall_allowed():
            QMessageBox.warning(
                self,
                "Firewall disabled",
                "Firewall control is disabled in Settings.\n\n"
                "Enable 'Allow Flow to manage firewall rules' in the Settings tab.",
            )
            return

        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(
                self,
                "No IP selected",
                "Select a row with a valid source IP first.",
            )
            return
        
        item = self.table.item(row, 0) # Source IP is column 0
        if not item:
            return
            
        ip = item.text().strip()
        if not ip or ip == "unknown":
            QMessageBox.information(
                self,
                "Invalid IP",
                "Selected row does not have a valid IP.",
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
