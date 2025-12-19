import hashlib
import json
import logging
import re
import os
from pathlib import Path

try:
    import tlsh
except ImportError:
    tlsh = None
from django.db import OperationalError

from core.models import MalwareSignature

log = logging.getLogger(__name__)

CHUNK_SIZE = 1024 * 1024

MANUAL_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "malware_db.json"
_MANUAL_HASHES = None


def _reverse_shell_heuristic(path: str):
    """
    Simple heuristic detector for script-based reverse shells.
    Looks for classic patterns in text files.
    Returns (is_suspicious: bool, reason: str).
    """
    try:
        # Only inspect reasonably small files for this demo
        if not os.path.isfile(path):
            return False, ""
        if os.path.getsize(path) > 2 * 1024 * 1024:
            return False, ""

        with open(path, "r", errors="ignore") as f:
            content = f.read()

        patterns = [
            r"bash\s+-i\s+>&\s*/dev/tcp/",
            r"nc\s+-e\s+/bin/sh",
            r"nc\s+-e\s+/bin/bash",
            r"ncat\s+-e",
            r"powershell\s+-nop",
            r"Invoke-Expression",
            r"System\.Net\.Sockets\.TcpClient",
        ]

        for pat in patterns:
            if re.search(pat, content):
                return True, f"Reverse shell pattern matched: {pat}"

        return False, ""
    except Exception:
        log.exception("reverse_shell_heuristic: Failed to inspect %s", path)
        return False, ""


def _load_manual_hashes():
    global _MANUAL_HASHES
    if _MANUAL_HASHES is not None:
        return _MANUAL_HASHES

    try:
        if MANUAL_DB_PATH.exists():
            with MANUAL_DB_PATH.open("r", encoding="utf-8") as f:
                data = json.load(f)
            result = {}
            for entry in data:
                sha = str(entry.get("sha256", "")).strip().lower()
                if sha:
                    result[sha] = {
                        "name": entry.get("name") or entry.get("label") or "Manual entry",
                        "severity": entry.get("severity", "high"),
                        "description": entry.get("description")
                        or entry.get("reason")
                        or "Matched manual malware database",
                    }
            _MANUAL_HASHES = result
        else:
            _MANUAL_HASHES = {}
    except Exception as e:
        log.warning("Failed to load manual malware DB %s: %s", MANUAL_DB_PATH, e)
        _MANUAL_HASHES = {}
    return _MANUAL_HASHES


def _lookup_manual_by_sha(sha256: str):
    db = _load_manual_hashes()
    return db.get(sha256.lower())


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _file_tlsh(path: str) -> str:
    """
    Compute TLSH fuzzy hash.
    Returns empty string on failure.
    """
    if tlsh is None:
        return ""
    try:
        tl = tlsh.Tlsh()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                tl.update(chunk)
        tl.final()
        return tl.hexdigest()
    except Exception:
        return ""


def _lookup_signature_by_sha(sha256: str):
    if not sha256:
        return None
    try:
        return MalwareSignature.objects.filter(sha256=sha256).first()
    except OperationalError:
        return None
    except Exception:
        return None


def _lookup_signature_by_fuzzy(tlsh_string: str, max_distance: int = 50):
    """
    Fuzzy match using TLSH.
    We use MalwareSignature.tlsh field as the TLSH string storage.
    Returns (signature, distance) or (None, None).
    """
    if not tlsh_string or tlsh is None:
        return None, None

    best_sig = None
    best_dist = None

    try:
        # CORRECTED: Use 'tlsh' field instead of 'ssdeep' to match actual DB schema
        candidates = MalwareSignature.objects.exclude(tlsh__isnull=True).exclude(
            tlsh=""
        )
    except OperationalError:
        return None, None
    except Exception:
        return None, None

    for sig in candidates:
        try:
            # CORRECTED: Use 'tlsh' field
            sig_hash = (sig.tlsh or "").strip()
            if not sig_hash:
                continue
            dist = tlsh.diff(tlsh_string, sig_hash)
        except Exception:
            continue

        if dist < 0:
            continue

        if best_dist is None or dist < best_dist:
            best_dist = dist
            best_sig = sig

    if best_sig is None:
        return None, None

    if best_dist is not None and best_dist <= max_distance:
        return best_sig, best_dist

    return None, None


def scan_file(path: str, progress_cb=None) -> dict:
    """
    Scan a single file and return a result dict:
    {
        "is_malicious": bool,
        "reason": str,
        "sha256": str,
        "tlsh": str,
        "match_type": "exact" | "fuzzy" | "manual" | "none",
        "match_distance": int | None,
        "matched_signature": MalwareSignature | None,
        "severity": str,
        "name": str | None,
    }
    progress_cb, if given, is called with integer percentages 0–100.
    """
    if progress_cb:
        progress_cb(1)

    try:
        sha256 = _file_sha256(path)
    except Exception as e:
        if progress_cb:
            progress_cb(100)
        return {
            "is_malicious": False,
            "reason": f"Failed to hash file: {e}",
            "sha256": "",
            "tlsh": "",
            "match_type": "none",
            "match_distance": None,
            "matched_signature": None,
            "severity": "low",
            "name": None,
        }

    if progress_cb:
        progress_cb(30)

    manual_match = _lookup_manual_by_sha(sha256)
    if manual_match:
        if progress_cb:
            progress_cb(100)
        return {
            "is_malicious": True,
            "reason": manual_match["description"],
            "sha256": sha256,
            "tlsh": "",
            "match_type": "manual",
            "match_distance": None,
            "matched_signature": None,
            "severity": manual_match.get("severity", "high"),
            "name": manual_match.get("name"),
        }

    if progress_cb:
        progress_cb(45)

    sig = _lookup_signature_by_sha(sha256)
    if sig:
        if progress_cb:
            progress_cb(100)
        return {
            "is_malicious": True,
            "reason": "Matched known malware signature (SHA256)",
            "sha256": sha256,
            "tlsh": "",
            "match_type": "exact",
            "match_distance": 0,
            "matched_signature": sig,
            "severity": sig.severity or "high",
            "name": sig.family or "Known malware",
        }

    if progress_cb:
        progress_cb(60)

    tlsh_string = ""
    best_match = None
    best_distance = None
    try:
        tlsh_string = _file_tlsh(path)
        if tlsh_string:
            best_match, best_distance = _lookup_signature_by_fuzzy(tlsh_string)
    except Exception as e:
        log.warning("TLSH fuzzy scan failed for %s: %s", path, e)

    if best_match is not None:
        if progress_cb:
            progress_cb(100)
        return {
            "is_malicious": True,
            "reason": "Fuzzy match to known malware (TLSH)",
            "sha256": sha256,
            "tlsh": tlsh_string,
            "match_type": "fuzzy",
            "match_distance": best_distance,
            "matched_signature": best_match,
            "severity": best_match.severity or "medium",
            "name": best_match.family or "Suspicious file",
        }

    # Heuristic reverse shell detection if no signature match
    suspicious, reason = _reverse_shell_heuristic(path)
    if suspicious:
        if progress_cb:
            progress_cb(100)
        return {
            "is_malicious": True,
            "reason": reason or "Reverse shell heuristic match",
            "sha256": sha256,
            "tlsh": tlsh_string,
            "match_type": "heuristic",
            "match_distance": None,
            "matched_signature": None,
            "severity": "high",
            "name": "Suspicious Script",
        }

    if progress_cb:
        progress_cb(100)

    return {
        "is_malicious": False,
        "reason": "No known malware signatures matched",
        "sha256": sha256,
        "tlsh": tlsh_string,
        "match_type": "none",
        "match_distance": None,
        "matched_signature": None,
        "severity": "low",
        "name": None,
    }
