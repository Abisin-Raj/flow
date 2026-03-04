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
    Panel to enable or disable background services.
    Changes are stored in AppSetting and take effect next time the app starts.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        main = QVBoxLayout(self)

        title = QLabel("Flow Service Control")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 18px; font-weight: bold; padding: 8px;")

        info = QLabel(
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
