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
