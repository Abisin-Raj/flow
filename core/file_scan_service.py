import logging
import shutil
import time
from pathlib import Path

from django.db import transaction

from core.file_scanner import scan_file
from core.models import QuarantinedFile
from core.alert_engine import create_alert_with_geo

log = logging.getLogger("core.file_scan_service")

QUARANTINE_DIR = Path.home() / ".flow_quarantine"


def _ensure_quarantine_dir() -> None:
    try:
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        log.exception("Failed to create quarantine dir %s: %s", QUARANTINE_DIR, e)
        raise


def _move_to_quarantine(path: str) -> str:
    """
    Move file to quarantine with collision handling and bounded retries.
    Raises if it fails after a few attempts.
    """
    src = Path(path)

    if not src.exists():
        raise FileNotFoundError(f"Source file not found: {src}")

    _ensure_quarantine_dir()

    base_name = src.name
    target = QUARANTINE_DIR / base_name

    counter = 1
    max_collisions = 1000

    while target.exists() and counter < max_collisions:
        stem = src.stem
        suffix = src.suffix
        target = QUARANTINE_DIR / f"{stem}_{counter}{suffix}"
        counter += 1

    if target.exists():
        raise RuntimeError(f"Too many name collisions for quarantine path of {src}")

    retries = 0
    max_retries = 5

    while retries < max_retries:
        try:
            shutil.move(str(src), str(target))
            log.info("Moved %s to quarantine %s", src, target)
            return str(target)
        except Exception as e:
            retries += 1
            log.warning(
                "Move to quarantine failed for %s (attempt %s/%s): %s",
                src,
                retries,
                max_retries,
                e,
            )
            time.sleep(0.5)

    log.error(
        "Move to quarantine failed for %s after %s attempts",
        src,
        max_retries,
    )
    raise RuntimeError("Quarantine move failed")


def scan_and_record(path: str, auto_quarantine: bool = False, progress_cb=None) -> dict:
    """
    Scan a file, optionally auto-quarantine, and record in QuarantinedFile if malicious.
    Returns the scan result dict from scan_file.
    progress_cb is an optional callback for scan progress.
    """
    from django.db import connection
    connection.close()
    
    filename = Path(path).name

    if progress_cb:
        progress_cb(5)

    result = scan_file(path, progress_cb=progress_cb)

    if not result.get("is_malicious"):
        if progress_cb:
            progress_cb(100)
        return result

    # Malicious file found
    sha256 = result.get("sha256", "")
    
    quarantine_path = ""
    
    # Check if we already have a record for this file
    # We check original_path and sha256 to ensure it's the same file content at the same place
    existing_q = QuarantinedFile.objects.filter(
        original_path=path, 
        sha256=sha256, 
        deleted=False
    ).first()

    if existing_q:
        q_obj = existing_q
        # If auto_quarantine is requested but it wasn't quarantined before (or failed), try again
        if auto_quarantine and not q_obj.quarantine_path:
            try:
                if progress_cb:
                    progress_cb(90)
                quarantine_path = _move_to_quarantine(path)
                q_obj.quarantine_path = quarantine_path
                q_obj.save()
            except Exception:
                log.exception("Failed to move %s to quarantine (retry)", path)
    else:
        if auto_quarantine:
            try:
                if progress_cb:
                    progress_cb(90)
                quarantine_path = _move_to_quarantine(path)
            except Exception:
                log.exception("Failed to move %s to quarantine", path)
                quarantine_path = ""

        # Record in database
        try:
            with transaction.atomic():
                q_obj = QuarantinedFile.objects.create(
                    filename=filename,
                    original_path=path,
                    quarantine_path=quarantine_path,
                    reason=result.get("reason", ""),
                    sha256=sha256,
                    tlsh=result.get("tlsh", ""),
                    matched_signature=result.get("matched_signature"),
                    match_distance=result.get("match_distance"),
                    match_type=result.get("match_type", ""),
                )
        except Exception:
            log.exception("Failed to record quarantine entry for %s", path)
            # If we failed to create the record, we probably shouldn't proceed to alert 
            # or we might spam alerts without records. 
            # But let's try to alert anyway as a fallback safety.
            q_obj = None

    # Create alert if one doesn't already exist
    try:
        from core.models import Alert
        
        msg = result.get("reason") or "Malicious file detected"
        alert_msg = f"{msg} (file: {filename})"
        
        # Check for existing unresolved alert for this file
        # We use src_ip='local-file' and match the message content
        existing_alert = Alert.objects.filter(
            src_ip="local-file",
            message=alert_msg,
            resolved=False
        ).exists()
        
        if not existing_alert:
            severity = "high" if result.get("match_type") in ("exact", "heuristic") else "medium"

            create_alert_with_geo(
                src_ip="local-file",
                message=alert_msg,
                severity=severity,
                category="file",
                alert_type="File Threat",
            )
        else:
            log.info("Skipping duplicate alert for %s", filename)
            
    except Exception:
        log.exception("Failed to create Alert for malicious file %s", path)

    if progress_cb:
        progress_cb(100)

    return result
