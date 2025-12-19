import threading
import time
import logging
import psutil
from core.alert_engine import create_alert_for_connection
from django.db import close_old_connections

log = logging.getLogger("core.rev_shell_detector")

SUSPICIOUS_PROCESS_NAMES = {
    "nc", "ncat", "netcat", "bash", "sh", "zsh", "dash", "python", "python3", "perl", "ruby", "php"
}

class ReverseShellDetector(threading.Thread):
    def __init__(self, interval=5):
        super().__init__(daemon=True)
        self.interval = interval
        self.running = True
        self.known_shells = set()  # Track PIDs to avoid spamming alerts

    def run(self):
        log.info("ReverseShellDetector started")
        while self.running:
            try:
                self.check_processes()
            except Exception as e:
                log.exception("Error in ReverseShellDetector loop: %s", e)
            finally:
                close_old_connections()
            time.sleep(self.interval)

    def check_processes(self):
        current_pids = set()
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                pinfo = proc.info
                pid = pinfo['pid']
                name = pinfo['name']
                cmdline = pinfo['cmdline'] or []
                
                # Debug logging: trace python processes
                if "python" in name:
                    log.info("Found python process: %s (pid %s)", name, pid)
                
                # Check if process name is suspicious
                if name in SUSPICIOUS_PROCESS_NAMES:
                    # Check for network connections
                    connections = proc.connections(kind='inet')
                    for conn in connections:
                        if conn.status == 'ESTABLISHED':
                            remote_ip = conn.raddr.ip
                            remote_port = conn.raddr.port
                            
                            # Ignore local connections
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
                continue
                
        # Cleanup old PIDs
        self.known_shells = self.known_shells.intersection(current_pids)

def start_rev_shell_detector():
    detector = ReverseShellDetector()
    detector.start()
    return detector
