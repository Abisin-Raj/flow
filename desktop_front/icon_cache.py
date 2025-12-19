# desktop_front/icon_cache.py
import os
from pathlib import Path
from functools import lru_cache
from configparser import ConfigParser
from PyQt6.QtGui import QIcon

# Standard locations for .desktop files
DESKTOP_DIRS = [
    Path.home() / ".local/share/applications",
    Path("/usr/share/applications"),
    Path("/var/lib/flatpak/exports/share/applications"),
    Path("/snap/bin"),  # Sometimes snaps expose them elsewhere, but usually exported to /usr/share/applications or similar
]

def _get_icon_from_desktop_file(base_name: str) -> str | None:
    """
    Look for {base_name}.desktop in common locations and extract Icon=...
    Returns the icon string (path or name) or None.
    """
    candidate_files = []
    
    # Try exact match first
    for d in DESKTOP_DIRS:
        f = d / f"{base_name}.desktop"
        if f.exists():
            candidate_files.append(f)
            
    # Try case-insensitive or partial if no exact match (optional, but let's stick to exact for speed first)
    # Also try wildcard for things like org.mozilla.firefox.desktop matching firefox
    if not candidate_files:
         for d in DESKTOP_DIRS:
             if d.exists():
                 # Match *base_name*.desktop
                 # This helps with Flatpak IDs e.g. org.gimp.GIMP
                 matches = list(d.glob(f"*{base_name}*.desktop"))
                 candidate_files.extend(matches)
    
    # Process the first valid candidate
    for desktop_file in candidate_files:
        try:
            # cfg = ConfigParser(interpolation=None) # Unused
            # .desktop files are INI-like but often have no section headers or start with [Desktop Entry]
            # Since ConfigParser requires sections, we'll manually grep it to be safer and faster
            with open(desktop_file, 'r', errors='ignore') as f:
                for line in f:
                    if line.strip().startswith("Icon="):
                        return line.split("=", 1)[1].strip()
        except Exception:
            continue
            
    return None


def _manual_fallback_icon_lookup(name: str) -> str | None:
    """
    If QIcon.fromTheme fails, check standard paths manually.
    """
    search_paths = [
        Path("/usr/share/pixmaps"),
        Path("/usr/share/icons/hicolor/48x48/apps"),
        Path("/usr/share/icons/hicolor/scalable/apps"),
        Path.home() / ".icons",
        Path.home() / ".local/share/icons",
    ]
    
    extensions = [".png", ".svg", ".xpm", ".ico"]
    
    for d in search_paths:
        if not d.exists():
            continue
        for ext in extensions:
            f = d / f"{name}{ext}"
            if f.exists():
                return str(f)
    return None


@lru_cache(maxsize=512)
def _make_icon_from_name(name: str) -> QIcon:
    # prefer stripped basename
    base = os.path.basename(name) if name else ""
    
    if not base:
        return QIcon()

    # 1. Try theme lookup using base directly
    if QIcon.hasThemeIcon(base):
        return QIcon.fromTheme(base)
    
    # 2. Try looking up the .desktop file to get the real icon name/path
    desktop_icon_val = _get_icon_from_desktop_file(base)
    if desktop_icon_val:
        # It could be a path (/path/to/icon.png) or a name (firefox)
        if "/" in desktop_icon_val and os.path.exists(desktop_icon_val):
            return QIcon(desktop_icon_val)
        elif QIcon.hasThemeIcon(desktop_icon_val):
             return QIcon.fromTheme(desktop_icon_val)
        else:
            # Fallback: Check if it exists as a file in pixmaps
            manual_path = _manual_fallback_icon_lookup(desktop_icon_val)
            if manual_path:
                return QIcon(manual_path)

            # Last ditch: try loading as file even if it looks like name
            ico = QIcon(desktop_icon_val)
            if not ico.isNull():
                return ico

    # 3. Try name without extension
    noext = os.path.splitext(base)[0]
    if noext and noext != base:
        if QIcon.hasThemeIcon(noext):
            return QIcon.fromTheme(noext)
        # Also try manual lookup for noext
        manual_path = _manual_fallback_icon_lookup(noext)
        if manual_path:
            return QIcon(manual_path)

    # 4. Fallback generic names
    for fallback in ("application-x-executable", "application-x-shellscript", "system-run", "utilities-terminal"):
        if QIcon.hasThemeIcon(fallback):
            return QIcon.fromTheme(fallback)
            
    # final fallback simple lookups
    manual_path = _manual_fallback_icon_lookup(base)
    if manual_path:
        return QIcon(manual_path)
            
    # final fallback: generated icon
    return _generated_fallback_icon()


def _generated_fallback_icon() -> QIcon:
    """
    Generate a simple grey placeholder icon if no system icon is found.
    """
    from PyQt6.QtGui import QPixmap, QPainter, QColor
    
    pixmap = QPixmap(32, 32)
    pixmap.fill(QColor("transparent"))
    
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    
    # Draw grey circle background
    painter.setBrush(QColor("#555555"))
    painter.setPen(QColor("transparent"))
    painter.drawEllipse(2, 2, 28, 28)
    
    painter.end()
    return QIcon(pixmap)


@lru_cache(maxsize=1024)
def get_icon_for_process(proc_name: str | None, exe_path: str | None) -> QIcon:
    """
    Fast cached icon lookup by process name or exe path.
    proc_name: process binary name like 'chrome' or 'python'
    exe_path: absolute path to binary. Not used to load icon file but used for cache key.
    """
    # key logic is handled by lru_cache arguments automatically, so we don't need manual keys
    
    # choose candidate name order
    candidates = []
    if proc_name:
        candidates.append(proc_name)
        if proc_name.lower() != proc_name:
            candidates.append(proc_name.lower())

    if exe_path:
        candidates.append(Path(exe_path).name)
        candidates.append(Path(exe_path).stem)
        
    for cand in candidates:
        ico = _make_icon_from_name(cand)
        if not ico.isNull():
            return ico
            
    # try generic lookups
    generic = _make_icon_from_name("application-x-executable")
    if not generic.isNull():
        return generic
        
    # last resort generated
    return _generated_fallback_icon()
