"""
Process Tree Utility.

This module provides functionality to reconstruct the process ancestry chain
for a given PID. This helps in understanding the context of malicious processes
(e.g., seeing that `nc` was spawned by `bash` which was spawned by `python`).
"""

from pathlib import Path
import logging

log = logging.getLogger("core.process_tree")

PROC = Path("/proc")


def _read_status_field(pid: int, key: str) -> str | None:
    """
    Read a specific field from `/proc/[pid]/status`.
    """
    try:
        with open(PROC / str(pid) / "status", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith(key + ":"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        return None
    return None


def get_process_info(pid: int) -> dict | None:
    """
    Retrieve basic process info (pid, ppid, name) from procfs.

    Args:
        pid (int): Process ID.

    Returns:
        dict: {pid, ppid, name} or None if not found.
    """
    if pid <= 0:
        return None

    name = _read_status_field(pid, "Name")
    ppid_str = _read_status_field(pid, "PPid")

    if ppid_str is None and name is None:
        return None

    try:
        ppid = int(ppid_str) if ppid_str else 0
    except Exception:
        ppid = 0

    return {
        "pid": pid,
        "ppid": ppid,
        "name": name or "",
    }


def build_process_chain(pid: int, max_depth: int = 6) -> str:
    """
    Construct a string representation of the process ancestry chain.
    
    Example return: "bash -> python3 -> revshell.py"
    
    Args:
        pid (int): The starting child PID.
        max_depth (int): Maximum levels to traverse up.

    Returns:
        str: Arrow-separated chain string.
    """
    chain = []
    seen = set()
    current = pid

    for _ in range(max_depth):
        if current in seen or current <= 0:
            break
        seen.add(current)

        info = get_process_info(current)
        if not info:
            break

        name = info.get("name") or f"pid:{current}"
        chain.append(name)

        current = info.get("ppid") or 0

    if not chain:
        return ""

    # reverse so parent -> child
    chain = list(reversed(chain))
    return " -> ".join(chain)
