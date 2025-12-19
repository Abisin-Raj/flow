from pathlib import Path
import logging

log = logging.getLogger("core.process_tree")

PROC = Path("/proc")


def _read_status_field(pid: int, key: str) -> str | None:
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
    Return {pid, ppid, name} for a PID if available.
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
    Walk parent chain up to max_depth and return "bash -> python3 -> revshell.py".
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
