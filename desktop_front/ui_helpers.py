from PyQt6.QtWidgets import (
    QPushButton,
    QSizePolicy,
    QHeaderView,
    QAbstractScrollArea,
)

def make_small_button(text: str) -> QPushButton:
    btn = QPushButton(text)
    btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
    btn.setMaximumWidth(170)
    return btn

def tune_table(table):
    """
    Make QTableWidget or QTableView resize nicely with the window.
    """
    header = table.horizontalHeader()
    header.setStretchLastSection(True)
    header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
