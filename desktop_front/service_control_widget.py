import sys
import os
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QCheckBox,
    QMessageBox,
)

from desktop_front.ui_helpers import make_small_button

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "flow.settings")

import django  # noqa: E402

django.setup()

from core import settings_api  # noqa: E402


class ServiceControlWidget(QWidget):
    """
    Testing-only panel to enable or disable background services.
    Changes are stored in AppSetting and take effect next time the app starts.
    
    This is primarily used for debugging or running the UI without the heavy backend analysis.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        main = QVBoxLayout(self)

        title = QLabel("Flow Service Control (Testing Only)")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 18px; font-weight: bold; padding: 8px;")

        info = QLabel(
            "Use this panel for demonstrations and testing.\n"
            "These toggles control whether services start on the next launch.\n"
            "They do not hard-stop already running threads."
        )
        info.setWordWrap(True)

        main.addWidget(title)
        main.addWidget(info)

        flags = settings_api.get_service_flags()

        self.chk_collectors = QCheckBox("Enable collectors (connection analyzers)")
        self.chk_collectors.setChecked(flags.get("collectors", True))

        self.chk_folder = QCheckBox("Enable folder watcher (file quarantine)")
        self.chk_folder.setChecked(flags.get("folder_watcher", True))

        self.chk_sniffer = QCheckBox("Enable packet sniffer (raw sockets)")
        self.chk_sniffer.setChecked(flags.get("sniffer", True))

        self.chk_light = QCheckBox("Enable light sniffer (/proc/net/tcp)")
        self.chk_light.setChecked(flags.get("light_sniffer", True))

        self.chk_alert_watch = QCheckBox("Enable alert watcher (tray notifications)")
        self.chk_alert_watch.setChecked(flags.get("alert_watcher", True))

        for w in [
            self.chk_collectors,
            self.chk_folder,
            self.chk_sniffer,
            self.chk_light,
            self.chk_alert_watch,
        ]:
            main.addWidget(w)

        button_row = QHBoxLayout()
        button_row.addStretch()
        btn_save = make_small_button("Save testing config")
        btn_save.clicked.connect(self.save_flags)
        button_row.addWidget(btn_save)
        button_row.addStretch()

        main.addLayout(button_row)

        note = QLabel(
            "Note: For now these switches are test-only.\n"
            "If you disable a service here, restart the app to see effect."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color: #bbbbbb; font-size: 11px;")
        main.addWidget(note)

    def save_flags(self):
        settings_api.set_service_flag("collectors", self.chk_collectors.isChecked())
        settings_api.set_service_flag("folder_watcher", self.chk_folder.isChecked())
        settings_api.set_service_flag("sniffer", self.chk_sniffer.isChecked())
        settings_api.set_service_flag("light_sniffer", self.chk_light.isChecked())
        settings_api.set_service_flag("alert_watcher", self.chk_alert_watch.isChecked())

        QMessageBox.information(
            self,
            "Saved",
            "Testing configuration saved.\n"
            "Restart the application to apply service changes.",
        )
