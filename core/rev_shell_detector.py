"""
Reverse Shell Detector.

This module monitors running processes to detect potential reverse shells.
It looks for suspicious processes (like netcat, bash, python) that have established
connections to remote IPs, indicating a potential attacker controlling the system.
"""

import threading
import time
import logging
import psutil
from core.alert_engine import create_alert_for_connection
from django.db import close_old_connections

log = logging.getLogger("core.rev_shell_detector")

# set of process names that are commonly used for reverse shells
SUSPICIOUS_PROCESS_NAMES = {
    "nc", "ncat", "netcat", "bash", "sh", "zsh", "dash", "python", "python3", "perl", "ruby", "php"
}

class ReverseShellDetector(threading.Thread):
    """
    Background thread to periodically check for reverse shell patterns.
    """
    def __init__(self, interval=5):
        """
        Initialize the detector.

        Args:
            interval (int): Seconds to sleep between checks.
        """
        super().__init__(daemon=True)
        self.interval = interval
        self.running = True
        self.known_shells = set()  # Track PIDs to avoid spamming alerts for the same process

    def run(self):
        """
        Main loop for the detector thread.
        """
        log.info("ReverseShellDetector started")
        while self.running:
            try:
                self.check_processes()
            except Exception as e:
                log.exception("Error in ReverseShellDetector loop: %s", e)
            finally:
                # Ensure DB connections are closed to prevent leaks
                close_old_connections()
            time.sleep(self.interval)

    def check_processes(self):
        """
        Iterate over running processes and check for suspicious network connections.
        
        It looks for processes in `SUSPICIOUS_PROCESS_NAMES` that have established
        external TCP connections.
        """
        current_pids = set()
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                pinfo = proc.info
                pid = pinfo['pid']
                name = pinfo['name']
                cmdline = pinfo['cmdline'] or []
                
                # Debug logging: trace python processes as they are common targets/vectors
                if "python" in name:
                    log.info("Found python process: %s (pid %s)", name, pid)
                
                # Check if process name is suspicious
                if name in SUSPICIOUS_PROCESS_NAMES:
                    # Check for network connections associated with this process
                    connections = proc.connections(kind='inet')
                    for conn in connections:
                        if conn.status == 'ESTABLISHED':
                            remote_ip = conn.raddr.ip
                            remote_port = conn.raddr.port
                            
                            # Ignore local connections (localhost)
                            if remote_ip.startswith("127.") or remote_ip == "::1":
                                continue
                                
                            # If it's a shell/interpreter with an established remote connection, it's suspicious
                            # Especially if it's not a known safe tool (this is a heuristic)
                            
                            local_ip = conn.laddr.ip
                            
                            # Unique key for this potential shell instance
                            shell_key = (pid, remote_ip, remote_port)
                            current_pids.add(shell_key)
                            
                            if shell_key not in self.known_shells:
                                log.warning(f"Potential Reverse Shell detected: {name} ({pid}) -> {remote_ip}:{remote_port}")
                                
                                msg = f"Potential Reverse Shell: {name} (PID {pid}) connected to {remote_ip}:{remote_port}"
                                if cmdline:
                                    msg += f" | Cmd: {' '.join(cmdline[:5])}..."
                                
                                create_alert_for_connection(
                                    src_ip=local_ip,    # Source is the local infected machine
                                    dst_ip=remote_ip,   # Destination is the attacker
                                    dst_port=remote_port,
                                    message=msg,
                                    alert_type="Reverse Shell",
                                    severity="critical",
                                    category="intrusion",
                                    pid=pid,
                                    process_name=name
                                )
                                self.known_shells.add(shell_key)
                                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Process might have ended during iteration
                continue
                
        # Cleanup old PIDs from the known set if they are no longer active
        self.known_shells = self.known_shells.intersection(current_pids)

def start_rev_shell_detector():
    """
    Start the Reverse Shell Detector.

    Returns:
        ReverseShellDetector: The started detector instance.
    """
    detector = ReverseShellDetector()
    detector.start()
    return detector
