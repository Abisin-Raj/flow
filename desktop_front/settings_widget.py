import sys
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QLabel,
    QLineEdit,
    QCheckBox,
    QPushButton,
    QMessageBox,
    QListWidget,
    QSizePolicy,
)

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

import os  # noqa: E402

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "flow.settings")

import django  # noqa: E402

django.setup()

from core import settings_api  # noqa: E402
from core.firewall import unblock_ip, get_blocked_ips  # noqa: E402


def _get_bool(key: str, default: bool) -> bool:
    raw = settings_api.get(key, "1" if default else "0")
    if isinstance(raw, bool):
        return raw
    text = str(raw).strip().lower()
    return text in ("1", "true", "yes", "on")


class SettingsWidget(QWidget):
    """
    Settings panel for detector thresholds and alert behavior.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _make_small_button(self, text):
        btn = QPushButton(text)
        btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        btn.setMaximumWidth(180)
        return btn

    def _build_ui(self):
        main_layout = QVBoxLayout(self)

        title = QLabel("Flow settings")
        title.setAlignment(Qt.AlignmentFlag.AlignLeft)
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 8px;")
        main_layout.addWidget(title)

        subtitle = QLabel(
            "Tune detector sensitivity and alert behavior. Changes apply within a few seconds."
        )
        subtitle.setWordWrap(True)
        main_layout.addWidget(subtitle)

        # Firewall checkbox (moved to top for visibility)
        self.allow_fw_cb = QCheckBox("Allow Flow to manage firewall rules")
        self.allow_fw_cb.setToolTip(
            "When enabled, Flow can run nftables commands through pkexec to block IPs. "
            "You will still be asked for confirmation and system password."
        )

        self.allow_fw_cb.setChecked(settings_api.get_bool("allow_firewall_actions"))
        main_layout.addWidget(self.allow_fw_cb)

        self.auto_block_cb = QCheckBox("Auto-block high severity threats (requires firewall enabled)")
        self.auto_block_cb.setToolTip(
            "If enabled, high severity alerts (like flood or brute force) will automatically trigger a temporary IP block."
        )
        self.auto_block_cb.setChecked(settings_api.get_bool("auto_block_high_severity"))
        main_layout.addWidget(self.auto_block_cb)

        # Unblock IP controls
        unblock_layout = QVBoxLayout()
        unblock_layout.addWidget(QLabel("Blocked IPs:"))
        
        self.blocked_ip_list = QListWidget()
        self.blocked_ip_list.setToolTip("Select an IP to unblock")
        unblock_layout.addWidget(self.blocked_ip_list)

        self.unblock_btn = self._make_small_button("Unblock Selected IP")
        self.unblock_btn.clicked.connect(self.on_unblock_ip)
        
        # Right align the unblock button
        unblock_btn_layout = QHBoxLayout()
        unblock_btn_layout.addStretch()
        unblock_btn_layout.addWidget(self.unblock_btn)
        unblock_layout.addLayout(unblock_btn_layout)
        
        main_layout.addLayout(unblock_layout)

        self.refresh_blocked_ips()

        form = QFormLayout()
        form.setLabelAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        form.setFormAlignment(Qt.AlignmentFlag.AlignTop)

        # Detector thresholds
        self.window_input = QLineEdit(settings_api.get("detector.window_seconds", "10"))
        self.window_input.setMaxLength(6)
        self.window_input.setFixedWidth(70)
        self.window_input.setToolTip(
            "Time window in seconds used for counting unique destination ports of a source IP."
        )
        form.addRow("Scan window (seconds):", self.window_input)

        self.fast_ports_input = QLineEdit(settings_api.get("detector.fast_ports", "50"))
        self.fast_ports_input.setMaxLength(6)
        self.fast_ports_input.setFixedWidth(70)
        self.fast_ports_input.setToolTip(
            "Minimum number of unique ports in the scan window that counts as a fast scan."
        )
        form.addRow("Fast scan ports (count in window):", self.fast_ports_input)

        self.brute_ports_input = QLineEdit(
            settings_api.get("detector.brute_ports", "200")
        )
        self.brute_ports_input.setMaxLength(6)
        self.brute_ports_input.setFixedWidth(70)
        self.brute_ports_input.setToolTip(
            "Minimum unique ports in a short brute window that counts as a brute scan."
        )
        form.addRow("Brute scan ports (count):", self.brute_ports_input)

        self.brute_window_input = QLineEdit(
            settings_api.get("detector.brute_window", "5")
        )
        self.brute_window_input.setMaxLength(6)
        self.brute_window_input.setFixedWidth(70)
        self.brute_window_input.setToolTip(
            "Short time window in seconds used for brute scan detection."
        )
        form.addRow("Brute scan window (seconds):", self.brute_window_input)

        self.slow_ports_input = QLineEdit(settings_api.get("detector.slow_ports", "15"))
        self.slow_ports_input.setMaxLength(6)
        self.slow_ports_input.setFixedWidth(70)
        self.slow_ports_input.setToolTip(
            "Minimum unique ports in the scan window that counts as a slow scan."
        )
        form.addRow("Slow scan ports (count in window):", self.slow_ports_input)

        self.cooldown_input = QLineEdit(
            settings_api.get("detector.cooldown_seconds", "30")
        )
        self.cooldown_input.setMaxLength(6)
        self.cooldown_input.setFixedWidth(70)
        self.cooldown_input.setToolTip(
            "Cooldown in seconds before the same source IP can trigger another scan alert."
        )
        form.addRow("Alert cooldown (seconds):", self.cooldown_input)

        self.high_rate_input = QLineEdit(
            settings_api.get("detector.high_rate_limit", "100")
        )
        self.high_rate_input.setMaxLength(6)
        self.high_rate_input.setFixedWidth(70)
        self.high_rate_input.setToolTip(
            "Max connections allowed from a single IP in 10 seconds before triggering an alert."
        )
        form.addRow("High rate limit (count):", self.high_rate_input)


        self.max_store_input = QLineEdit(settings_api.get("detector.max_store", "1000"))
        self.max_store_input.setMaxLength(6)
        self.max_store_input.setFixedWidth(70)
        self.max_store_input.setToolTip(
            "Maximum events stored per source IP for scan detection history."
        )
        form.addRow("Max events per source IP:", self.max_store_input)

        self.retention_input = QLineEdit(settings_api.get("retention.days", "7"))
        self.retention_input.setMaxLength(6)
        self.retention_input.setFixedWidth(70)
        self.retention_input.setToolTip(
            "Number of days to keep connection and alert logs. Older data is deleted on startup."
        )
        form.addRow("Data retention (days):", self.retention_input)




        main_layout.addLayout(form)

        # Alert behavior
        alerts_title = QLabel("Alert behavior")
        alerts_title.setStyleSheet(
            "font-size: 14px; font-weight: bold; margin-top: 12px;"
        )
        main_layout.addWidget(alerts_title)

        alerts_layout = QVBoxLayout()

        self.ignore_internal_checkbox = QCheckBox(
            "Ignore internal local network connections in alerts"
        )
        self.ignore_internal_checkbox.setToolTip(
            "When enabled, alerts will ignore traffic where both source and destination are private or local IPs."
        )
        self.ignore_internal_checkbox.setChecked(
            _get_bool("detector.ignore_private_ranges", True)
        )
        alerts_layout.addWidget(self.ignore_internal_checkbox)

        self.ignore_self_checkbox = QCheckBox(
            "Ignore alerts triggered by this device IP"
        )
        self.ignore_self_checkbox.setToolTip(
            "When enabled, Flow will detect your own IP automatically and skip alerts created by it."
        )
        self.ignore_self_checkbox.setChecked(_get_bool("detector.ignore_my_ip", True))

        alerts_layout.addWidget(self.ignore_self_checkbox)

        # Manual ignored IPs controls
        ignore_ip_row = QHBoxLayout()

        ignore_ip_label = QLabel("Ignored IPs (manual):")
        ignore_ip_row.addWidget(ignore_ip_label)

        self.ignore_ip_input = QLineEdit()
        self.ignore_ip_input.setPlaceholderText("Enter IP to ignore, for example 192.168.1.50")
        ignore_ip_row.addWidget(self.ignore_ip_input)

        self.ignore_ip_add_btn = QPushButton("Add")
        self.ignore_ip_add_btn.clicked.connect(self._on_add_ignored_ip)
        ignore_ip_row.addWidget(self.ignore_ip_add_btn)

        alerts_layout.addLayout(ignore_ip_row)

        self.ignored_ip_list = QListWidget()
        self.ignored_ip_list.setToolTip("Double click an IP to remove it from the ignore list")
        self.ignored_ip_list.itemDoubleClicked.connect(self._on_remove_ignored_ip)
        alerts_layout.addWidget(self.ignored_ip_list)

        self._reload_ignored_ip_list()

        # Ignored processes section
        ignore_proc_layout = QHBoxLayout()
        ignore_proc_label = QLabel("Ignored processes:")
        ignore_proc_label.setToolTip("Process names that will not trigger alerts (comma separated)")
        ignore_proc_layout.addWidget(ignore_proc_label)

        self.ignore_proc_input = QLineEdit()
        self.ignore_proc_input.setPlaceholderText("antigravity, chrome, code")
        ignore_proc_layout.addWidget(self.ignore_proc_input)

        from PyQt6.QtCore import QTimer
        self.ignore_proc_save_btn = QPushButton("Save")
        
        def _on_save_ignored_processes():
            text = self.ignore_proc_input.text()
            lst = [p.strip() for p in text.split(",") if p.strip()]
            settings_api.set_ignored_processes(lst)
            self.ignore_proc_save_btn.setText("Saved")
            QTimer.singleShot(900, lambda: self.ignore_proc_save_btn.setText("Save"))

        self.ignore_proc_save_btn.clicked.connect(_on_save_ignored_processes)
        ignore_proc_layout.addWidget(self.ignore_proc_save_btn)

        alerts_layout.addLayout(ignore_proc_layout)

        # Load current ignored processes
        try:
            current = settings_api.get_ignored_processes()
            self.ignore_proc_input.setText(", ".join(current))
        except Exception:
            self.ignore_proc_input.setText("")

        main_layout.addLayout(alerts_layout)

        # Buttons
        btn_row = QHBoxLayout()
        btn_row.addStretch(1)

        self.reset_btn = self._make_small_button("Reset to defaults")
        self.reset_btn.clicked.connect(self.reset_to_defaults)
        btn_row.addWidget(self.reset_btn)

        self.clear_ignored_btn = self._make_small_button("Clear ignored IPs")
        self.clear_ignored_btn.clicked.connect(self.clear_ignored_ips)
        btn_row.addWidget(self.clear_ignored_btn)

        self.save_button = self._make_small_button("Save settings")
        self.save_button.clicked.connect(self.save_settings)
        btn_row.addWidget(self.save_button)

        main_layout.addLayout(btn_row)
        main_layout.addStretch()

    def reset_to_defaults(self):
        confirm = QMessageBox.question(
            self, 
            "Reset Defaults", 
            "Are you sure you want to reset all settings to defaults?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            settings_api.set_bulk(settings_api.DEFAULTS)
            QMessageBox.information(self, "Reset", "Settings reset. Please restart the application to apply changes.")

    def clear_ignored_ips(self):
        confirm = QMessageBox.question(
            self, 
            "Clear Ignored IPs", 
            "Are you sure you want to clear all ignored IPs?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            settings_api.set_ignored_ips([])
            self._reload_ignored_ip_list()
            QMessageBox.information(self, "Cleared", "Ignored IPs list cleared.")

    def save_settings(self):
        try:
            updates = {
                "detector.window_seconds": self.window_input.text().strip(),
                "detector.fast_ports": self.fast_ports_input.text().strip(),
                "detector.brute_ports": self.brute_ports_input.text().strip(),
                "detector.brute_window": self.brute_window_input.text().strip(),
                "detector.slow_ports": self.slow_ports_input.text().strip(),
                "detector.cooldown_seconds": self.cooldown_input.text().strip(),
                "detector.high_rate_limit": self.high_rate_input.text().strip(),
                "detector.max_store": self.max_store_input.text().strip(),
                "retention.days": self.retention_input.text().strip(),
                "detector.ignore_private_ranges": "1" if self.ignore_internal_checkbox.isChecked() else "0",
                "detector.ignore_my_ip": "1" if self.ignore_self_checkbox.isChecked() else "0",
                "allow_firewall_actions": "1" if self.allow_fw_cb.isChecked() else "0",
                "auto_block_high_severity": "1" if self.auto_block_cb.isChecked() else "0",
            }
            settings_api.set_bulk(updates)

        except Exception as e:
            QMessageBox.critical(self, "Save failed", f"Could not save settings:\n{e}")
            return

        QMessageBox.information(self, "Saved", "Settings saved successfully.")


    def _reload_ignored_ip_list(self) -> None:
        self.ignored_ip_list.clear()
        try:
            ips = settings_api.get_ignored_ips()
        except Exception:
            ips = []
        for ip in ips:
            self.ignored_ip_list.addItem(ip)

    def _on_add_ignored_ip(self) -> None:
        ip = self.ignore_ip_input.text().strip()
        if not ip:
            return
        try:
            settings_api.add_ignored_ip(ip)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to add ignored IP: {e}")
            return
        self.ignore_ip_input.clear()
        self._reload_ignored_ip_list()

    def _on_remove_ignored_ip(self, item) -> None:
        ip = item.text().strip()
        if not ip:
            return
        result = QMessageBox.question(
            self,
            "Remove ignored IP",
            f"Stop ignoring {ip}?",
        )
        if result != QMessageBox.StandardButton.Yes:
            return
        try:
            settings_api.remove_ignored_ip(ip)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to remove ignored IP: {e}")
            return
        self._reload_ignored_ip_list()

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh_blocked_ips()

    def refresh_blocked_ips(self):
        self.blocked_ip_list.clear()
        for ip in get_blocked_ips():
            self.blocked_ip_list.addItem(ip)

    def on_unblock_ip(self):
        if not self.allow_fw_cb.isChecked():
            QMessageBox.warning(self, "Firewall disabled", "Enable firewall management first.")
            return

        item = self.blocked_ip_list.currentItem()
        if not item:
            QMessageBox.information(self, "Selection required", "Select an IP address to unblock.")
            return
        
        ip = item.text()

        confirm = QMessageBox.question(
            self,
            "Unblock IP",
            f"Remove firewall rule for {ip}?\n\n"
            "This uses nftables via pkexec. You might be asked for your password.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if confirm != QMessageBox.StandardButton.Yes:
            return

        ok, msg = unblock_ip(ip)

        if ok:
            QMessageBox.information(
                self,
                "Firewall rule removed",
                f"IP {ip} was unblocked.\n\nResult: {msg}",
            )
            self.refresh_blocked_ips()
        else:
            QMessageBox.warning(
                self,
                "Unblock failed",
                f"Could not remove rule for {ip}.\n\nError: {msg}",
            )
