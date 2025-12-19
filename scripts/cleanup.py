import os
import sys
import glob
import shutil
import ast
from pathlib import Path

# Define patterns for junk files
JUNK_PATTERNS = [
    "__pycache__",
    "*.pyc",
    "debug_log*.txt",
    "startup_log*.txt",
    "debug_output.txt",
    "git_log.txt",
    "dir_list.txt",
    "*.egg-info",
    "dist",
    "build",
    ".pytest_cache",
    ".coverage"
]

# Essential files that should NEVER be deleted even if they match patterns
PROTECTED_FILES = [
    "requirements.txt",
    "manage.py",
    "db.sqlite3", # Keep the database unless explicitly asked
]

def find_junk_files(root_dir):
    junk_files = []
    for pattern in JUNK_PATTERNS:
        # Use recursive globbing
        for path in Path(root_dir).rglob(pattern):
            # Exclude venv directory
            if "venv" in path.parts:
                continue
            if path.name in PROTECTED_FILES:
                continue
            junk_files.append(path)
    return junk_files

def get_imports(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        try:
            tree = ast.parse(f.read())
        except SyntaxError:
            return set()
    
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split('.')[0])
    return imports

def check_dependencies(root_dir):
    all_imports = set()
    for path in Path(root_dir).rglob("*.py"):
        if "venv" in path.parts:
            continue
        all_imports.update(get_imports(path))
    
    # Filter out standard library (approximate) and local modules
    # This is a basic check.
    # A better way is to check against installed packages or a known stdlib list.
    # For now, we'll just list what we found and compare with requirements.txt
    
    print("\n--- Dependency Check ---")
    print(f"Found {len(all_imports)} unique top-level imports in code.")
    
    req_path = Path(root_dir) / "requirements.txt"
    if req_path.exists():
        with open(req_path, "r") as f:
            reqs = {line.strip().split('==')[0].split('>=')[0].lower() for line in f if line.strip() and not line.startswith('#')}
        
        print(f"Found {len(reqs)} requirements in requirements.txt")
        
        # This is tricky because import names don't always match package names (e.g. PIL vs Pillow)
        # So we just print a summary for the user to review.
    else:
        print("No requirements.txt found.")

def main():
    root_dir = Path(__file__).resolve().parent.parent
    print(f"Scanning {root_dir}...")
    
    junk_files = find_junk_files(root_dir)
    
    if not junk_files:
        print("No junk files found.")
    else:
        print(f"\nFound {len(junk_files)} junk files/directories:")
        for f in junk_files:
            print(f"  {f.relative_to(root_dir)}")
        
        if "--dry-run" in sys.argv:
            print("\nDry run complete. No files deleted.")
        else:
            confirm = input("\nDelete these files? (y/N): ")
            if confirm.lower() == 'y':
                for f in junk_files:
                    try:
                        if f.is_dir():
                            shutil.rmtree(f)
                        else:
                            f.unlink()
                        print(f"Deleted {f.name}")
                    except Exception as e:
                        print(f"Error deleting {f}: {e}")
                print("Cleanup complete.")
            else:
                print("Operation cancelled.")

    check_dependencies(root_dir)

if __name__ == "__main__":
    main()
