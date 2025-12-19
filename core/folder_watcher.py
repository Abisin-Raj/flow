import os
import threading
import time
from pathlib import Path

from django.db import close_old_connections

from core.models import WatchedFolder  # noqa: E402
from core.file_scan_service import scan_and_record

_LAST_SEEN = {}
_INITIALIZED_ROOTS = set()


def iter_files(root: str, recursive: bool):
    root_path = Path(root)
    if not root_path.is_dir():
        return

    if recursive:
        for dirpath, dirnames, filenames in os.walk(root):
            for name in filenames:
                yield os.path.join(dirpath, name)
    else:
        for name in os.listdir(root):
            full = root_path / name
            if full.is_file():
                yield str(full)


def _index_existing_files_once(root: str, recursive: bool):
    for path in iter_files(root, recursive):
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        _LAST_SEEN[path] = mtime


def folder_watcher_loop(interval: int = 5):
    """
    Poll watched folders every few seconds.
    Detect new or modified files.
    Scan them and optionally auto quarantine.
    """
    while True:
        try:
            close_old_connections()
            watched = list(WatchedFolder.objects.filter(enabled=True))
        except Exception:
            time.sleep(interval)
            continue

        for wf in watched:
            root = wf.path
            recursive = wf.recursive
            auto_q = wf.auto_quarantine

            if not os.path.isdir(root):
                continue

            if root not in _INITIALIZED_ROOTS:
                _index_existing_files_once(root, recursive)
                _INITIALIZED_ROOTS.add(root)
                continue

            for path in iter_files(root, recursive):
                try:
                    mtime = os.path.getmtime(path)
                except OSError:
                    continue

                last = _LAST_SEEN.get(path)
                if last is None or mtime > last:
                    _LAST_SEEN[path] = mtime
                    try:
                        scan_and_record(path, auto_quarantine=auto_q)
                    except Exception:
                        continue

        time.sleep(interval)


import logging


from django.db import OperationalError  # noqa: E402

log = logging.getLogger(__name__)

def initial_full_scan():
    """
    Scan all files in enabled watched folders once at startup.
    This catches malware that was already present before the watcher began.
    """
    logger = logging.getLogger("core.folder_watcher")
    try:
        folders = WatchedFolder.objects.filter(enabled=True)
    except Exception:
        logger.exception("initial_full_scan: Failed to load WatchedFolder entries")
        return

    for wf in folders:
        root = wf.path
        recursive = wf.recursive
        auto_quarantine = wf.auto_quarantine

        if not root or not os.path.isdir(root):
            logger.warning(
                "initial_full_scan: Skipping invalid folder path: %s", root
            )
            continue

        logger.info(
            "initial_full_scan: Scanning folder %s (recursive=%s, auto_quarantine=%s)",
            root,
            recursive,
            auto_quarantine,
        )

        try:
            if recursive:
                walker = os.walk(root)
            else:
                walker = [(root, [], os.listdir(root))]

            for dirpath, _dirnames, filenames in walker:
                for name in filenames:
                    full_path = os.path.join(dirpath, name)
                    try:
                        scan_and_record(full_path, auto_quarantine=auto_quarantine)
                    except OperationalError as e:
                        logger.warning(
                            "initial_full_scan: DB OperationalError scanning %s: %s",
                            full_path,
                            e,
                        )
                        time.sleep(1)
                    except Exception:
                        logger.exception(
                            "initial_full_scan: Failed to scan file %s", full_path
                        )
        except Exception:
            logger.exception(
                "initial_full_scan: Error walking folder %s", root
            )

def scan_all_watched_folders():
    log.info("scan_all_watched_folders: starting full rescan of watched folders")
    try:
        watched = WatchedFolder.objects.filter(enabled=True)
    except Exception as e:
        log.exception("scan_all_watched_folders: failed to query WatchedFolder: %s", e)
        return

    for wf in watched:
        root = wf.path
        recursive = wf.recursive

        if not os.path.isdir(root):
            log.warning("scan_all_watched_folders: %s is not a directory", root)
            continue

        log.info("scan_all_watched_folders: scanning %s (recursive=%s)", root, recursive)

        for dirpath, dirs, files in os.walk(root):
            for fname in files:
                fpath = os.path.join(dirpath, fname)
                try:
                    scan_and_record(fpath)
                except Exception:
                    log.exception(
                        "scan_all_watched_folders: failed to scan %s", fpath
                    )

            if not recursive:
                break

    log.info("scan_all_watched_folders: completed full rescan")

def _folder_watcher_thread_entry(interval: int):
    log.info("Folder watcher: starting initial full scan")
    initial_full_scan()
    log.info("Folder watcher: starting background watcher loop")
    folder_watcher_loop(interval)


def start_folder_watcher():
    t = threading.Thread(
        target=_folder_watcher_thread_entry, kwargs={"interval": 5}, daemon=True
    )
    t.start()
