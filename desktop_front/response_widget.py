import logging
import sys
import subprocess
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QHBoxLayout,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QDialog,
    QFormLayout,
    QLineEdit,
    QComboBox,
    QDialogButtonBox
)
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QColor

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "flow.settings")
import django
django.setup()

from core.models import Alert
from core import mitigation_engine
from core import firewall

log = logging.getLogger("desktop_front.response_widget")


class BlockIPDialog(QDialog):
    """Dialog for blocking an IP address"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Block IP Address")
        self.resize(400, 200)
        
        layout = QFormLayout(self)
        
        # IP Address input
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("e.g., 192.168.1.100")
        layout.addRow("IP Address:", self.ip_input)
        
        # Reason input
        self.reason_input = QLineEdit()
        self.reason_input.setText("manually_blocked")
        self.reason_input.setPlaceholderText("Alphanumeric, dashes, underscores only")
        layout.addRow("Reason:", self.reason_input)
        
        # Timeout dropdown
        self.timeout_combo = QComboBox()
        self.timeout_combo.addItem("Permanent", None)
        self.timeout_combo.addItem("1 minute", 60)
        self.timeout_combo.addItem("5 minutes", 300)
        self.timeout_combo.addItem("15 minutes", 900)
        self.timeout_combo.addItem("30 minutes", 1800)
        self.timeout_combo.addItem("1 hour", 3600)
        self.timeout_combo.addItem("6 hours", 21600)
        self.timeout_combo.addItem("24 hours", 86400)
        layout.addRow("Timeout:", self.timeout_combo)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
    
    def get_values(self):
        """Return (ip, reason, timeout_seconds)"""
        ip = self.ip_input.text().strip()
        reason = self.reason_input.text().strip()
        timeout = self.timeout_combo.currentData()
        return ip, reason, timeout


class ResponseWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.current_alert: Alert | None = None
        self.current_actions: list[mitigation_engine.MitigationAction] = []

        self.layout = QVBoxLayout(self)

        # --- Section 1: Incident Response (Top) ---
        self.title_label = QLabel("Incident Response")
        self.title_label.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 5px;")
        self.layout.addWidget(self.title_label)

        self.info_label = QLabel("Select an alert in the Alerts tab to see response guidance.")
        self.info_label.setWordWrap(True)
        self.layout.addWidget(self.info_label)

        # Action buttons row
        self.button_row = QHBoxLayout()
        self.block_ip_btn = QPushButton("Block Source IP (Alert)")
        self.resolve_btn = QPushButton("Mark Resolved")
        
        self.start_helper_btn = QPushButton("Start Firewall Helper")
        self.start_helper_btn.setVisible(False)
        self.start_helper_btn.setStyleSheet("background-color: #2c5e2e; color: white;")

        self.block_ip_btn.clicked.connect(self.on_block_ip_clicked)
        self.resolve_btn.clicked.connect(self.on_mark_resolved_clicked)
        self.start_helper_btn.clicked.connect(self.start_helper)

        self.button_row.addWidget(self.block_ip_btn)
        self.button_row.addWidget(self.resolve_btn)
        self.button_row.addWidget(self.start_helper_btn)
        self.button_row.addStretch()

        self.layout.addLayout(self.button_row)

        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.text.setMaximumHeight(150) # Limit height to save space for table
        self.layout.addWidget(self.text)
        
        # Separator
        separator = QLabel("")
        separator.setStyleSheet("border-bottom: 1px solid #555; margin: 10px 0;")
        self.layout.addWidget(separator)

        # --- Section 2: Global Firewall Rules (Bottom) ---
        
        fw_header = QHBoxLayout()
        self.fw_label = QLabel("Active Firewall Rules")
        self.fw_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        fw_header.addWidget(self.fw_label)
        
        self.fw_status_indicator = QLabel("●")
        self.fw_status_indicator.setStyleSheet("color: gray; font-size: 16px;")
        fw_header.addWidget(self.fw_status_indicator)
        
        fw_header.addStretch()
        
        self.manual_block_btn = QPushButton("Manually Block IP")
        self.manual_block_btn.clicked.connect(self.manual_block_dialog)
        fw_header.addWidget(self.manual_block_btn)
        
        self.unblock_btn = QPushButton("Unblock Selected")
        self.unblock_btn.clicked.connect(self.unblock_selected)
        self.unblock_btn.setEnabled(False)
        fw_header.addWidget(self.unblock_btn)
        
        self.refresh_btn = QPushButton("Refresh List")
        self.refresh_btn.clicked.connect(self.refresh_firewall_data)
        fw_header.addWidget(self.refresh_btn)
        
        self.layout.addLayout(fw_header)

        # Blocked IPs table
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["IP Address", "Reason", "Type"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        
        self.layout.addWidget(self.table)
        
        self.fw_info_label = QLabel("Checking firewall status...")
        self.fw_info_label.setStyleSheet("color: gray;")
        self.layout.addWidget(self.fw_info_label)

        # Start refresh timer for firewall data
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_firewall_data)
        self.refresh_timer.start(10000)  # Refresh every 10 seconds

        # Initial checks
        self._update_buttons_enabled()
        self.refresh_firewall_data()

    def _update_buttons_enabled(self):
        has_alert = self.current_alert is not None
        has_block_action = any(a.code == "block_ip" for a in self.current_actions)
        
        # Check firewall status
        is_fw_up = firewall.is_firewall_available()
        
        self.start_helper_btn.setVisible(not is_fw_up)
        
        # Alert blocking
        self.block_ip_btn.setEnabled(has_alert and has_block_action and is_fw_up)
        self.resolve_btn.setEnabled(has_alert)
        
        # Manual blocking
        self.manual_block_btn.setEnabled(is_fw_up)
        self.refresh_btn.setEnabled(is_fw_up) # Can try refresh even if down to check status
        
        if not is_fw_up:
             msg = "Firewall helper is offline (Start it to block)"
             self.block_ip_btn.setToolTip(msg)
             self.manual_block_btn.setToolTip(msg)
        else:
             self.block_ip_btn.setToolTip("")
             self.manual_block_btn.setToolTip("")

    def set_alert(self, alert: Alert | None):
        """
        Called by AlertsWidget when user selects an alert row.
        """
        self.current_alert = alert
        self.text.clear()
        self.current_actions = []

        if not alert:
            self.info_label.setText("No alert selected.")
            self._update_buttons_enabled()
            return

        src = getattr(alert, 'src_ip', 'unknown')
        self.info_label.setText(f"Alert #{alert.id} from {src}")

        actions = mitigation_engine.suggest_actions_for_alert(alert)
        self.current_actions = actions

        # build guidance text
        lines = []
        lines.append(f"Type: {getattr(alert, 'alert_type', '')}")
        lines.append(f"Severity: {getattr(alert, 'severity', '')}")
        lines.append(f"Message: {getattr(alert, 'message', '')}")
        lines.append("")
        lines.append("Recommended actions:")

        for idx, act in enumerate(actions, start=1):
            lines.append(f"{idx}. {act.label} – {act.description}")

        self.text.setPlainText("\n".join(lines))

        self._update_buttons_enabled()

    def _pick_action(self, code: str) -> mitigation_engine.MitigationAction | None:
        for act in self.current_actions:
            if act.code == code:
                return act
        return None

    def on_block_ip_clicked(self):
        """Handle blocking from Alert context"""
        if not self.current_alert:
            return

        act = self._pick_action("block_ip")
        if not act or not act.ip_to_block:
            QMessageBox.warning(self, "No IP", "No target IP available for this alert.")
            return

        ip = act.ip_to_block

        confirm = QMessageBox.question(
            self,
            "Block IP",
            f"Add {ip} to the firewall block set using nftables?\n"
            "This requires root privileges and nft to be available.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        ok, err = firewall.block_ip(ip)
        if not ok:
            QMessageBox.critical(
                self,
                "Firewall Error",
                f"Failed to block {ip}.\n\nDetails: {err or 'Unknown error'}",
            )
            return

        QMessageBox.information(
            self,
            "IP Blocked",
            f"{ip} was added to the nftables block set.\n"
            "Traffic from/to this address should now be dropped.",
        )
        self.refresh_firewall_data() # Update the table immediately

    def on_mark_resolved_clicked(self):
        if not self.current_alert:
            return

        alert = self.current_alert
        try:
            if hasattr(alert, "resolved"):
                alert.resolved = True
            if hasattr(alert, "resolution_note"):
                note = getattr(alert, "resolution_note") or ""
                if note:
                    alert.resolution_note = note + " | Marked resolved from UI"
                else:
                    alert.resolution_note = "Marked resolved from UI"
            alert.save()
            QMessageBox.information(self, "Resolved", "Alert marked as resolved.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update alert: {e}")

    def start_helper(self):
        """Attempt to start the firewall helper service via pkexec"""
        if firewall.is_firewall_available():
            self._update_buttons_enabled()
            self.refresh_firewall_data()
            return

        import subprocess
        
        try:
            cmd = ["pkexec", "systemctl", "start", "flow-firewall.service"]
            res = subprocess.run(cmd, capture_output=True, text=True)
            
            if res.returncode == 0:
                QMessageBox.information(
                    self, "Started", "Service start command sent. Initializing..."
                )
                # Check back in 2s
                QTimer.singleShot(2000, self.refresh_firewall_data)
            elif res.returncode in (126, 127):
                pass
            else:
                 QMessageBox.warning(self, "Failed", f"Error provided: {res.stderr}")
        except Exception as e:
             QMessageBox.critical(self, "Error", f"Execution failed: {e}")

    # --- Firewall Management Methods ---

    def refresh_firewall_data(self):
        """Refresh firewall status and blocked IPs list"""
        # Check helper status
        is_available = firewall.is_firewall_available()
        self._update_buttons_enabled() # Update button states based on availablity
        
        if is_available:
            self.fw_status_indicator.setStyleSheet("color: green; font-size: 16px;")
            
            # Get blocked IPs
            blocked_ips = firewall.get_blocked_ips()
            self.update_table(blocked_ips)
            self.fw_info_label.setText(f"{len(blocked_ips)} IP(s) currently blocked")
        else:
            self.fw_status_indicator.setStyleSheet("color: red; font-size: 16px;")
            self.table.setRowCount(0)
            self.fw_info_label.setText("Firewall helper unavailable - cannot list blocked IPs")

    def update_table(self, blocked_ips):
        """Update the blocked IPs table"""
        self.table.setRowCount(len(blocked_ips))
        
        for row, ip in enumerate(blocked_ips):
            # IP address
            ip_item = QTableWidgetItem(ip)
            ip_item.setFlags(ip_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, 0, ip_item)
            
            # Reason (generic)
            reason_item = QTableWidgetItem("blocked_by_flow")
            reason_item.setFlags(reason_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, 1, reason_item)
            
            # Type (Persistent)
            type_item = QTableWidgetItem("Persistent")
            type_item.setFlags(type_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, 2, type_item)
            
    def on_selection_changed(self):
        """Enable/disable unblock button based on selection"""
        self.unblock_btn.setEnabled(len(self.table.selectedItems()) > 0)

    def manual_block_dialog(self):
        """Show dialog to block an IP manually"""
        dialog = BlockIPDialog(self)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            ip, reason, timeout = dialog.get_values()
            
            if not ip:
                QMessageBox.warning(self, "Invalid Input", "Please enter an IP address")
                return
            
            if not reason:
                reason = "manually_blocked"
            
            # Block the IP
            success, error = firewall.block_ip(ip, timeout)
            
            if success:
                timeout_str = f" ({timeout}s)" if timeout else " (permanent)"
                QMessageBox.information(
                    self, 
                    "Success", 
                    f"Blocked {ip}{timeout_str}"
                )
                self.refresh_firewall_data()
            else:
                QMessageBox.critical(
                    self,
                    "Firewall Error",
                    f"Failed to block {ip}:\n{error}"
                )

    def unblock_selected(self):
        """Unblock the selected IP"""
        selected_items = self.table.selectedItems()
        if not selected_items:
            return
        
        row = selected_items[0].row()
        ip = self.table.item(row, 0).text()
        
        # Confirm
        reply = QMessageBox.question(
            self,
            "Confirm Unblock",
            f"Are you sure you want to unblock {ip}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            success, error = firewall.unblock_ip(ip)
            
            if success:
                QMessageBox.information(self, "Success", f"Unblocked {ip}")
                self.refresh_firewall_data()
            else:
                QMessageBox.critical(
                    self,
                    "Firewall Error",
                    f"Failed to unblock {ip}:\n{error}"
                )
