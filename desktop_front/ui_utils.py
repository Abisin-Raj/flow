from PyQt6.QtCore import QSettings
from PyQt6.QtWidgets import QHeaderView, QTableWidget

class TableColumnManager:
    """
    Manages column resizing configuration and persistence for QTableWidget.
    Ensures:
    1. Interactive resizing.
    2. Persistence via QSettings.
    3. Initial equal column distribution.
    """
    def __init__(self, table: QTableWidget, settings_key: str):
        self.table = table
        self.settings_key = settings_key
        self.default_set = False

    def setup(self):
        """Configures header and restores state."""
        header = self.table.horizontalHeader()
        header.setSectionsMovable(True)
        header.setStretchLastSection(True)
        # Force Interactive on all sections to be sure
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for i in range(self.table.columnCount()):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.Interactive)
        self.restore_state()

    def restore_state(self):
        """Restores column widths from QSettings."""
        settings = QSettings("Flow", "FlowApp")
        state = settings.value(self.settings_key)
        if state:
            self.table.horizontalHeader().restoreState(state)
            self.default_set = True
        else:
            self.default_set = False
        
        # KEY FIX: Override any saved "Stretch" or "Fixed" modes from the past.
        # Always force Interactive so user can resize.
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for i in range(self.table.columnCount()):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.Interactive)

    def save_state(self):
        """Saves current column widths to QSettings."""
        settings = QSettings("Flow", "FlowApp")
        state = self.table.horizontalHeader().saveState()
        settings.setValue(self.settings_key, state)

    def handle_resize(self):
        """
        Call this from the widget's resizeEvent.
        Distributes columns equally on first valid resize if no state was restored.
        """
        if not self.default_set:
            width = self.table.viewport().width()
            count = self.table.columnCount()
            if width > 0 and count > 0:
                col_width = width // count
                # If stretching last section, don't set fixed width for it
                stretch_last = self.table.horizontalHeader().stretchLastSection()
                limit = count - 1 if stretch_last else count
                
                for i in range(limit):
                    self.table.setColumnWidth(i, col_width)
                
                self.default_set = True
