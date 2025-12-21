#!/usr/bin/env python3
"""
Flow Firewall Helper - Privileged nftables service
Runs as root via systemd, accepts commands via Unix socket
"""

import os
import sys
import socket
import logging
import signal
import subprocess
import ipaddress
import re
from pathlib import Path

# Configuration
SOCKET_PATH = "/run/flow/firewall.sock"
SOCKET_DIR = "/run/flow"
NFT_TABLE = "flow_table"
NFT_CHAIN = "blocked_ips"
MAX_MESSAGE_LENGTH = 1024
ALLOWED_REASON_CHARS = re.compile(r'^[a-zA-Z0-9_]+$')
AUDIT_LOG = "/var/log/flow/audit.log"

def audit_log(message: str):
    """Write a timestamped audit entry to the audit log file."""
    from datetime import datetime
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(AUDIT_LOG, "a") as f:
            f.write(f"{timestamp} {message}\n")
    except Exception as e:
        logging.getLogger("firewall_helper").warning(f"Audit log write failed: {e}")

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("firewall_helper")

class FirewallHelper:
    def __init__(self):
        self.running = True
        self.socket = None
        self.setup_nftables()
        
    def setup_nftables(self):
        """
        Ensure nftables infrastructure exists idempotently.
        Creates table 'flow_table' and separate sets for IPv4 and IPv6.
        """
        try:
            # 1. Create Table (check=False for idempotency - won't fail if exists)
            subprocess.run(["nft", "add", "table", "inet", NFT_TABLE], 
                         capture_output=True, check=False)
            
            # 2. Create IPv4 Set with timeout support
            subprocess.run([
                "nft", "add", "set", "inet", NFT_TABLE, "flow_blocked_ipv4",
                "{ type ipv4_addr; flags timeout; }"
            ], capture_output=True, check=False)
            
            # 3. Create IPv6 Set with timeout support
            subprocess.run([
                "nft", "add", "set", "inet", NFT_TABLE, "flow_blocked_ipv6",
                "{ type ipv6_addr; flags timeout; }"
            ], capture_output=True, check=False)

            # 4. Create Chain
            subprocess.run([
                "nft", "add", "chain", "inet", NFT_TABLE, NFT_CHAIN,
                "{ type filter hook input priority 0; policy accept; }"
            ], capture_output=True, check=False)
            
            # 5. Add drop rules for both sets
            subprocess.run([
                "nft", "add", "rule", "inet", NFT_TABLE, NFT_CHAIN,
                "ip", "saddr", "@flow_blocked_ipv4", "drop"
            ], capture_output=True, check=False)
            
            subprocess.run([
                "nft", "add", "rule", "inet", NFT_TABLE, NFT_CHAIN,
                "ip6", "saddr", "@flow_blocked_ipv6", "drop"
            ], capture_output=True, check=False)

            logger.info("nftables configuration verified/updated")
            
        except Exception as e:
            logger.error(f"Failed to setup nftables: {e}")

    def validate_ip(self, ip_str):
        """
        Validate IP address format strictly.
        
        Args:
            ip_str (str): IP string input.
            
        Returns:
            ipaddress object or None.
        """
        try:
            return ipaddress.ip_address(ip_str)
        except ValueError:
            return None
    
    def sanitize_reason(self, reason):
        """
        Sanitize reason string to prevent command injection or log spoofing.
        Strict: Alphanumeric and underscore only.
        """
        if not reason or len(reason) > 50:
            return None
        if not ALLOWED_REASON_CHARS.match(reason):
            return None
        return reason
    
    def block_ip(self, ip, reason, timeout_seconds=None):
        """
        Add an IP to the block list via nftables.
        
        Args:
            ip (str): IP address to block.
            reason (str): Logging reason.
            timeout_seconds (int, optional): Duration to block.
        
        Returns:
            str: "OK <msg>" or "ERROR <msg>".
        """
        ip_obj = self.validate_ip(ip)
        if not ip_obj:
            return f"ERROR Invalid IP address: {ip}"
        
        # Layer 2: Protected IP guard - refuse to block critical system IPs
        # This is defense-in-depth: even if Layer 1 (Flow core) is bypassed
        if (
            ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            audit_log(f"[DENY] protected_ip ip={ip}")
            logger.warning(f"Refused to block protected IP: {ip}")
            return "ERROR Protected IP"
        
        reason = self.sanitize_reason(reason)
        if reason is None:
            return "ERROR Invalid reason format (alphanumeric_only)"
            
        timeout_str = ""
        if timeout_seconds:
            try:
                ts = int(timeout_seconds)
                if ts < 10 or ts > 86400:
                    return "ERROR Timeout must be between 10 and 86400 seconds"
                timeout_str = f" timeout {ts}s"
            except Exception:
                return "ERROR Invalid timeout"

        # Select correct set based on IP version
        target_set = "flow_blocked_ipv4" if ip_obj.version == 4 else "flow_blocked_ipv6"
        
        try:
            # nft add element inet table set { ip [timeout X] }
            cmd = ["nft", "add", "element", "inet", NFT_TABLE, target_set, f"{{ {ip}{timeout_str} }}"]
            subprocess.run(cmd, check=True, capture_output=True)
            
            logger.info(f"Blocked IP: {ip} (reason: {reason}, timeout: {timeout_seconds or 'forever'})")
            audit_log(f"[BLOCK] ip={ip} timeout={timeout_seconds or 0}s reason={reason}")
            return f"OK Blocked {ip}"
        except subprocess.CalledProcessError as e:
            error_msg = f"nftables command failed: {e.stderr.decode()}"
            logger.error(error_msg)
            return f"ERROR {error_msg}"
    
    def unblock_ip(self, ip):
        """
        Remove an IP from the block list (nftables set).
        
        Args:
            ip (str): IP address to unblock.
            
        Returns:
            str: "OK <msg>" or "ERROR <msg>".
        """
        ip_obj = self.validate_ip(ip)
        if not ip_obj:
            return f"ERROR Invalid IP address: {ip}"
            
        # Select correct set based on IP version
        target_set = "flow_blocked_ipv4" if ip_obj.version == 4 else "flow_blocked_ipv6"
        
        try:
            # nft delete element inet table set { ip }
            cmd = ["nft", "delete", "element", "inet", NFT_TABLE, target_set, f"{{ {ip} }}"]
            subprocess.run(cmd, check=True, capture_output=True)
            
            logger.info(f"Unblocked IP: {ip}")
            audit_log(f"[UNBLOCK] ip={ip}")
            return f"OK Unblocked {ip}"
        except subprocess.CalledProcessError as e:
            # If it doesn't exist, nft might error? yes 'No such file or directory' equivalent
            error_msg = f"nftables command failed: {e.stderr.decode()}"
            # Check if it was just "does not exist"
            if "does not exist" in error_msg or "multicast" in error_msg: # multicast? sometimes weird errors
                 return f"ERROR IP {ip} not found"
            logger.error(error_msg)
            return f"ERROR {error_msg}"
            
    def list_blocked(self):
        """List all currently blocked IPs from both IPv4 and IPv6 sets"""
        try:
            output = []
            
            # List from IPv4 set
            res4 = subprocess.run(["nft", "list", "set", "inet", NFT_TABLE, "flow_blocked_ipv4"], capture_output=True, text=True)
            if res4.returncode == 0:
                ips_v4 = re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', res4.stdout)
                output.extend(ips_v4)
            
            # List from IPv6 set
            res6 = subprocess.run(["nft", "list", "set", "inet", NFT_TABLE, "flow_blocked_ipv6"], capture_output=True, text=True)
            if res6.returncode == 0:
                # Simplified IPv6 pattern
                ips_v6 = re.findall(r'[0-9a-fA-F:]+::[0-9a-fA-F:]*|[0-9a-fA-F]+:[0-9a-fA-F:]+', res6.stdout)
                output.extend(ips_v6)
                
            return f"OK {','.join(output)}"
        except Exception as e:
            return f"ERROR {e}"

    def get_status(self):
        """
        Get the health status of the helper and nftables state.
        """
        try:
            subprocess.run(
                ["nft", "list", "table", "inet", NFT_TABLE],
                capture_output=True,
                check=True
            )
            return "OK Helper running, nftables initialized"
        except subprocess.CalledProcessError:
            return "ERROR nftables not initialized"

    def start_cleanup_thread(self):
        # No-op, kernel handles timeouts
        pass
    
    def handle_command(self, message):
        """
        Parse and execute a text command from the socket.
        
        Commands:
        - BLOCK_IP <ip> <reason> [timeout]
        - UNBLOCK_IP <ip>
        - LIST_BLOCKED
        - STATUS
        """
        message = message.strip()
        
        if not message:
            return "ERROR Empty command"
        
        parts = message.split(None, 3)  # Split into max 4 parts for timeout
        command = parts[0].upper()
        
        if command == "BLOCK_IP":
            if len(parts) < 3:
                return "ERROR BLOCK_IP requires: BLOCK_IP <ip> <reason> [timeout_seconds]"
            ip = parts[1]
            reason = parts[2]
            timeout = parts[3] if len(parts) == 4 else None
            return self.block_ip(ip, reason, timeout)
        
        elif command == "UNBLOCK_IP":
            if len(parts) < 2:
                return "ERROR UNBLOCK_IP requires: UNBLOCK_IP <ip>"
            ip = parts[1]
            return self.unblock_ip(ip)
        
        elif command == "LIST_BLOCKED":
            return self.list_blocked()
        
        elif command == "STATUS":
            return self.get_status()
        
        else:
            return f"ERROR Unknown command: {command}"
    
    def handle_client(self, client_socket):
        """
        Handle a single client connection until EOF or timeout.
        Reads one message, sends one response, closes connection.
        """
        try:
            # Receive message (with size limit)
            data = client_socket.recv(MAX_MESSAGE_LENGTH)
            if not data:
                return
            
            message = data.decode('utf-8').strip()
            logger.debug(f"Received command: {message}")
            
            # Process command
            response = self.handle_command(message)
            
            # Send response
            client_socket.sendall((response + '\n').encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error handling client: {e}")
            try:
                client_socket.sendall("ERROR Internal error\n".encode('utf-8'))
            except Exception:
                pass
        finally:
            client_socket.close()
    
    def setup_socket(self):
        """Create Unix domain socket with proper permissions"""
        # Create directory if needed
        Path(SOCKET_DIR).mkdir(parents=True, exist_ok=True)
        
        # Remove old socket if exists
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)
        
        # Create socket
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(SOCKET_PATH)
        self.socket.listen(5)
        
        # Get flow group GID
        try:
            import grp
            flow_group = grp.getgrnam('flow')
            flow_gid = flow_group.gr_gid
            
            # Set ownership to root:flow
            os.chown(SOCKET_PATH, 0, flow_gid)
            logger.info(f"Socket ownership set to root:flow (gid={flow_gid})")
        except KeyError:
            logger.warning("flow group not found, socket will be root:root only")
            logger.warning("Create flow group: sudo groupadd flow")
            logger.warning("Add users: sudo usermod -aG flow <username>")
        
        # Set permissions to 660 (owner and group can read/write)
        os.chmod(SOCKET_PATH, 0o660)
        
        logger.info(f"Socket created at {SOCKET_PATH} with mode 0660")
    
    def run(self):
        """
        Main server loop.
        Initializes socket and accepts connections indefinitely.
        """
        self.setup_socket()
        
        logger.info("Flow Firewall Helper started")
        logger.info("Waiting for commands...")
        
        while self.running:
            try:
                client_socket, _ = self.socket.accept()
                self.handle_client(client_socket)
            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting connection: {e}")
        
        logger.info("Shutting down")
        self.cleanup()
    
    def cleanup(self):
        """Clean up resources"""
        if self.socket:
            self.socket.close()
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down")
        self.running = False


def main():
    # Check if running as root
    if os.geteuid() != 0:
        logger.error("This helper must run as root")
        sys.exit(1)
    
    # Create helper instance
    helper = FirewallHelper()
    
    # Setup signal handlers
    signal.signal(signal.SIGTERM, helper.signal_handler)
    signal.signal(signal.SIGINT, helper.signal_handler)
    
    # Run server
    try:
        helper.run()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
