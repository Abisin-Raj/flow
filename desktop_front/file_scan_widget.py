import os
import time

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QFileDialog,
    QMessageBox,
    QApplication,
    QCheckBox,
    QHeaderView,
    QAbstractScrollArea,
)

from desktop_front.ui_helpers import make_small_button, tune_table

from PyQt6.QtCore import QObject, QThread, pyqtSignal
from django.utils import timezone

from core.file_scan_service import scan_and_record
from core.models import QuarantinedFile, WatchedFolder


from desktop_front.ui_utils import TableColumnManager

class FileScanWorker(QObject):
    progress = pyqtSignal(int)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, path: str, auto_quarantine: bool):
        super().__init__()
        self.path = path
        self.auto_quarantine = auto_quarantine

    def run(self):
        from core.file_scan_service import scan_and_record

        try:
            def cb(pct: int):
                try:
                    self.progress.emit(int(max(0, min(100, pct))))
                except Exception:
                    pass

            result = scan_and_record(
                self.path,
                auto_quarantine=self.auto_quarantine,
                progress_cb=cb,
            )
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class FileScanWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.quarantine_entries = []
        self.watched_entries = []

        main_layout = QVBoxLayout(self)

        # Scan controls
        scan_layout = QHBoxLayout()
        self.scan_button = make_small_button("Scan file")
        self.scan_button.clicked.connect(self.on_scan_clicked)

        self.scan_existing_button = make_small_button("Scan Existing Files")
        self.scan_existing_button.clicked.connect(self.scan_existing_files)

        self.status_label = QLabel("Ready to scan.")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignLeft)

        self.scan_progress_label = QLabel("Scan progress: idle")
        # self.scan_progress_label.setVisible(False) # Keep it visible or handle visibility in logic

        self.auto_quarantine_checkbox = QCheckBox("Auto quarantine")
        self.auto_quarantine_checkbox.setChecked(False)

        scan_layout.addWidget(self.scan_button)
        scan_layout.addWidget(self.auto_quarantine_checkbox)
        scan_layout.addWidget(self.scan_existing_button)
        scan_layout.addWidget(self.status_label)
        scan_layout.addWidget(self.scan_progress_label)
        scan_layout.addStretch()

        # Quarantine table + actions
        q_actions_layout = QHBoxLayout()
        q_label = QLabel("Quarantined files:")
        self.restore_button = make_small_button("Restore file")
        self.delete_button = make_small_button("Delete permanently")

        self.restore_button.clicked.connect(self.on_restore_clicked)
        self.delete_button.clicked.connect(self.on_delete_clicked)

        q_actions_layout.addWidget(q_label)
        q_actions_layout.addStretch()
        q_actions_layout.addWidget(self.restore_button)
        q_actions_layout.addWidget(self.delete_button)

        self.q_table = QTableWidget()
        # Columns:
        # 0  Filename
        # 1  Original path
        # 2  Quarantine path
        # 3  Reason
        # 4  SHA-256
        # 5  Fuzzy hash
        # 6  Match type
        # 7  Match distance
        # 8  Signature family
        # 9  Signature severity
        # 10 Detected at
        self.q_table.setColumnCount(11)
        self.q_table.setHorizontalHeaderLabels(
            [
                "Filename",
                "Original path",
                "Quarantine path",
                "Reason",
                "SHA-256",
                "Fuzzy hash",
                "Match type",
                "Distance",
                "Family",
                "Severity",
                "Detected at",
            ]
        )
        self.q_table.setSortingEnabled(False)
        tune_table(self.q_table)

        self.q_col_manager = TableColumnManager(self.q_table, "quarantine_table_state")
        self.q_col_manager.setup()

        # Watched folders controls
        watched_controls = QHBoxLayout()
        watched_label = QLabel("Watched folders:")
        self.add_folder_btn = make_small_button("Add folder")
        self.remove_folder_btn = make_small_button("Remove")
        self.toggle_auto_btn = make_small_button("Toggle auto quarantine")
        self.toggle_enabled_btn = make_small_button("Toggle enabled")

        self.add_folder_btn.clicked.connect(self.on_add_folder)
        self.remove_folder_btn.clicked.connect(self.on_remove_folder)
        self.toggle_auto_btn.clicked.connect(self.on_toggle_auto_quarantine)
        self.toggle_enabled_btn.clicked.connect(self.on_toggle_enabled)

        watched_controls.addWidget(watched_label)
        watched_controls.addStretch()
        watched_controls.addWidget(self.add_folder_btn)
        watched_controls.addWidget(self.remove_folder_btn)
        watched_controls.addWidget(self.toggle_auto_btn)
        watched_controls.addWidget(self.toggle_enabled_btn)

        # Watched folders table
        self.w_table = QTableWidget()
        self.w_table.setColumnCount(5)
        self.w_table.setHorizontalHeaderLabels(
            ["Folder path", "Recursive", "Auto quarantine", "Enabled", "Created at"]
        )
        self.w_table.setSortingEnabled(False)
        tune_table(self.w_table)

        self.w_col_manager = TableColumnManager(self.w_table, "watched_table_state")
        self.w_col_manager.setup()

        main_layout.addLayout(scan_layout)
        main_layout.addLayout(q_actions_layout)
        main_layout.addWidget(self.q_table)
        main_layout.addLayout(watched_controls)
        main_layout.addWidget(self.w_table)



        self.load_quarantine_table()
        self.load_quarantine_table()
        self.load_watched_table()

        self._scan_thread = None
        self._scan_worker = None

        app = QApplication.instance()
        if app:
            app.aboutToQuit.connect(self.cleanup)

    def cleanup(self):
        if hasattr(self, "q_col_manager"):
            self.q_col_manager.save_state()
        if hasattr(self, "w_col_manager"):
            self.w_col_manager.save_state()

    def load_quarantine_table(self):
        entries = QuarantinedFile.objects.order_by("-detected_at")[:200]
        self.quarantine_entries = list(entries)

        self.q_table.setRowCount(len(entries))

        for row, q in enumerate(entries):
            # core fields
            self.q_table.setItem(row, 0, QTableWidgetItem(q.filename))
            self.q_table.setItem(row, 1, QTableWidgetItem(q.original_path))
            self.q_table.setItem(row, 2, QTableWidgetItem(q.quarantine_path))
            self.q_table.setItem(row, 3, QTableWidgetItem(q.reason))

            # new hash related fields, all with safe getattr
            sha256 = getattr(q, "sha256", "") or ""
            fuzzy_hash = getattr(q, "fuzzy_hash", "") or ""
            match_type = getattr(q, "match_type", "") or ""
            match_distance = getattr(q, "match_distance", "") or ""
            sig_family = getattr(q, "signature_family", "") or ""
            sig_severity = getattr(q, "signature_severity", "") or ""

            self.q_table.setItem(row, 4, QTableWidgetItem(sha256))
            self.q_table.setItem(row, 5, QTableWidgetItem(fuzzy_hash))
            self.q_table.setItem(row, 6, QTableWidgetItem(match_type))
            self.q_table.setItem(row, 7, QTableWidgetItem(str(match_distance)))
            self.q_table.setItem(row, 8, QTableWidgetItem(sig_family))
            self.q_table.setItem(row, 9, QTableWidgetItem(sig_severity))

            detected_str = ""
            if q.detected_at:
                try:
                    local_dt = timezone.localtime(q.detected_at)
                    detected_str = local_dt.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    detected_str = q.detected_at.strftime("%Y-%m-%d %H:%M:%S")
            self.q_table.setItem(row, 10, QTableWidgetItem(detected_str))

        # self.q_table.resizeColumnsToContents()

    def load_watched_table(self):
        entries = WatchedFolder.objects.order_by("created_at")
        self.watched_entries = list(entries)

        self.w_table.setRowCount(len(entries))

        for row, wf in enumerate(entries):
            self.w_table.setItem(row, 0, QTableWidgetItem(wf.path))
            self.w_table.setItem(
                row, 1, QTableWidgetItem("yes" if wf.recursive else "no")
            )
            self.w_table.setItem(
                row, 2, QTableWidgetItem("yes" if wf.auto_quarantine else "no")
            )
            self.w_table.setItem(
                row, 3, QTableWidgetItem("yes" if wf.enabled else "no")
            )

            created_str = ""
            if wf.created_at:
                try:
                    local_dt = timezone.localtime(wf.created_at)
                    created_str = local_dt.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    created_str = wf.created_at.strftime("%Y-%m-%d %H:%M:%S")
            self.w_table.setItem(row, 4, QTableWidgetItem(created_str))

        # self.w_table.resizeColumnsToContents()

    def _scan_files_with_progress(self, files_to_scan):
        total = len(files_to_scan)
        if total == 0:
            self.scan_progress_label.setText("Scan progress 0%")
            self.scan_progress_label.setVisible(False)
            return

        self.scan_progress_label.setVisible(True)
        self.scan_progress_label.setText("Scan progress 0%")
        QApplication.processEvents()

        for idx, path in enumerate(files_to_scan, start=1):
            percent = int(idx * 100 / total)
            self.scan_progress_label.setText(f"Scan progress {percent}%")
            QApplication.processEvents()

        
            try:
                scan_and_record(path, do_quarantine=True)
            except Exception:
                pass

        self.scan_progress_label.setText("Scan complete 100%")
        QApplication.processEvents()
        time.sleep(0.2)
        self.scan_progress_label.setVisible(False)
        self.load_quarantine_table()

    def scan_existing_files(self):
        if not self.scan_existing_button.isEnabled():
            return

        self.scan_existing_button.setEnabled(False)
        self.scan_existing_button.setText("Scanning...")
        QApplication.processEvents()

        try:
            # Collect all files first
            files_to_scan = []
            try:
                watched = WatchedFolder.objects.filter(enabled=True)
                for wf in watched:
                    root = wf.path
                    recursive = wf.recursive
                    if not os.path.isdir(root):
                        continue
                    
                    if recursive:
                        for dirpath, _, filenames in os.walk(root):
                            for f in filenames:
                                files_to_scan.append(os.path.join(dirpath, f))
                    else:
                        for f in os.listdir(root):
                            full = os.path.join(root, f)
                            if os.path.isfile(full):
                                files_to_scan.append(full)
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to collect files: {e}")
                return

            self._scan_files_with_progress(files_to_scan)

        finally:
            self.scan_existing_button.setEnabled(True)
            self.scan_existing_button.setText("Scan Existing Files")

    def on_scan_clicked(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select file to scan")
        if not file_path:
            return
        self.start_manual_scan(file_path)

    def start_manual_scan(self, path: str):
        if not path:
            QMessageBox.warning(self, "File Scanner", "Please choose a file to scan.")
            return

        auto_quarantine = self.auto_quarantine_checkbox.isChecked() if hasattr(self, "auto_quarantine_checkbox") else False

        if self._scan_thread is not None:
            QMessageBox.information(self, "File Scanner", "A scan is already running.")
            return

        self.scan_progress_label.setText("Scan progress: 0%")

        self._scan_thread = QThread(self)
        self._scan_worker = FileScanWorker(path, auto_quarantine)
        self._scan_worker.moveToThread(self._scan_thread)

        self._scan_thread.started.connect(self._scan_worker.run)
        self._scan_worker.progress.connect(self._on_scan_progress)
        self._scan_worker.finished.connect(self._on_scan_finished)
        self._scan_worker.error.connect(self._on_scan_error)

        self._scan_worker.finished.connect(self._cleanup_scan_thread)
        self._scan_worker.error.connect(self._cleanup_scan_thread)
        self._scan_thread.finished.connect(self._cleanup_scan_thread)

        if self.scan_button:
            self.scan_button.setEnabled(False)

        self._scan_thread.start()

    def _on_scan_progress(self, pct: int):
        self.scan_progress_label.setText(f"Scan progress: {pct}%")

    def _on_scan_finished(self, result: dict):
        self.scan_progress_label.setText("Scan progress: 100%")
        
        msg = result.get("reason", "Scan complete.")
        # Construct a more detailed message if possible, similar to old logic
        is_malicious = result.get("is_malicious")
        sha256 = result.get("sha256", "")
        match_type = result.get("match_type", "")
        # match_distance = result.get("match_distance")
        # family = result.get("name") or result.get("matched_signature", {}).get("family") # matched_signature might be object or dict
        # result['matched_signature'] is a model instance or None.
        # If it's a model instance, we can access attributes.
        # But passing model instance across threads might be risky if not careful, but here it's just read.
        # However, the worker emits 'result' which contains the model instance.
        
        # Let's format the message
        lines = [f"Reason: {msg}"]
        if sha256:
            lines.append(f"SHA-256: {sha256}")
        if match_type:
            lines.append(f"Match Type: {match_type}")
        
        full_msg = "\n".join(lines)

        if is_malicious:
            QMessageBox.warning(self, "Scan Result", f"Malicious file detected:\n{full_msg}")
        else:
            QMessageBox.information(self, "Scan Result", f"File is clean:\n{full_msg}")
        
        self._enable_scan_button()
        self.load_quarantine_table()

    def _on_scan_error(self, err: str):
        self.scan_progress_label.setText("Scan progress: error")
        QMessageBox.critical(self, "Scan Error", err)
        self._enable_scan_button()

    def _cleanup_scan_thread(self, *args):
        if self._scan_thread:
            self._scan_thread.quit()
            self._scan_thread.wait()
            self._scan_thread = None
            self._scan_worker = None

    def _enable_scan_button(self):
        if hasattr(self, "scan_button") and self.scan_button:
            self.scan_button.setEnabled(True)

    def _get_selected_quarantine(self):
        row = self.q_table.currentRow()
        if row < 0 or row >= len(self.quarantine_entries):
            return None
        return self.quarantine_entries[row]

    def on_restore_clicked(self):
        q = self._get_selected_quarantine()
        if not q:
            QMessageBox.information(
                self, "No selection", "Select a quarantined file row first."
            )
            return

        if not q.quarantine_path:
            QMessageBox.information(
                self,
                "Cannot restore",
                "This entry has no quarantine path.",
            )
            return

        if not os.path.exists(q.quarantine_path):
            QMessageBox.warning(
                self,
                "File missing",
                "Quarantined file no longer exists on disk.",
            )
            return

        reply = QMessageBox.question(
            self,
            "Restore file",
            f"Restore this file to its original location?\n\n{q.original_path}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            original_dir = os.path.dirname(q.original_path) or "."
            if not os.path.isdir(original_dir):
                os.makedirs(original_dir, exist_ok=True)

            if os.path.exists(q.original_path):
                QMessageBox.warning(
                    self,
                    "Restore blocked",
                    f"Original path already has a file:\n{q.original_path}\n\nRestore aborted.",
                )
                return

            os.replace(q.quarantine_path, q.original_path)
        except Exception as e:
            QMessageBox.critical(
                self,
                "Restore failed",
                f"Could not restore file:\n{e}",
            )
            return

        q.restored = True
        q.deleted = False
        q.quarantine_path = ""
        q.save()

        QMessageBox.information(
            self,
            "Restore complete",
            f"File restored to:\n{q.original_path}",
        )

        self.load_quarantine_table()

    def on_delete_clicked(self):
        q = self._get_selected_quarantine()
        if not q:
            QMessageBox.information(
                self, "No selection", "Select a quarantined file row first."
            )
            return

        reply = QMessageBox.question(
            self,
            "Delete permanently",
            "Delete the quarantined copy from disk?\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        if q.quarantine_path and os.path.exists(q.quarantine_path):
            try:
                os.remove(q.quarantine_path)
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Delete failed",
                    f"Could not delete file:\n{e}",
                )
                return

        q.deleted = True
        q.restored = False
        q.quarantine_path = ""
        q.save()

        QMessageBox.information(
            self,
            "Deleted",
            "Quarantined file has been deleted from disk.",
        )

        self.load_quarantine_table()

    def _get_selected_watched(self):
        row = self.w_table.currentRow()
        if row < 0 or row >= len(self.watched_entries):
            return None
        return self.watched_entries[row]

    def on_add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select folder to watch")
        if not folder:
            return

        folder = os.path.abspath(folder)

        existing = WatchedFolder.objects.filter(path=folder).first()
        if existing:
            QMessageBox.information(
                self,
                "Already watched",
                f"This folder is already in the list:\n{folder}",
            )
            return

        WatchedFolder.objects.create(
            path=folder,
            recursive=True,
            auto_quarantine=False,
            enabled=True,
            created_at=timezone.now(),
        )

        self.load_watched_table()

    def on_remove_folder(self):
        wf = self._get_selected_watched()
        if not wf:
            QMessageBox.information(
                self, "No selection", "Select a folder row to remove."
            )
            return

        reply = QMessageBox.question(
            self,
            "Remove watched folder",
            f"Stop watching this folder?\n\n{wf.path}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        wf.delete()
        self.load_watched_table()

    def on_toggle_auto_quarantine(self):
        wf = self._get_selected_watched()
        if not wf:
            QMessageBox.information(
                self, "No selection", "Select a folder row to toggle."
            )
            return

        wf.auto_quarantine = not wf.auto_quarantine
        wf.save()
        self.load_watched_table()

    def on_toggle_enabled(self):
        wf = self._get_selected_watched()
        if not wf:
            QMessageBox.information(
                self, "No selection", "Select a folder row to toggle."
            )
            return

        wf.enabled = not wf.enabled
        wf.save()
        self.load_watched_table()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.q_col_manager.handle_resize()
        self.w_col_manager.handle_resize()


