"""
Helper functions for parsing /proc/net/tcp and /proc/net/udp
These files show ALL network connections system-wide when run as root,
bypassing network namespace isolation that limits netstat visibility.
"""

import struct
import socket
from pathlib import Path


def hex_to_ip(hex_str):
    """
    Convert hex IP address from /proc/net/tcp to dotted decimal.
    Format: Little-endian hex, e.g., '0100007F' = 127.0.0.1
    """
    try:
        # Convert hex string to integer, then to 4 bytes (little-endian)
        ip_int = int(hex_str, 16)
        ip_bytes = struct.pack("<I", ip_int)
        return socket.inet_ntoa(ip_bytes)
    except Exception:
        return ""


def hex_to_port(hex_str):
    """
    Convert hex port from /proc/net/tcp to integer.
    Format: Big-endian hex, e.g., '01BB' = 443
    """
    try:
        return int(hex_str, 16)
    except Exception:
        return 0


def parse_proc_net_line(line):
    """
    Parse a single line from /proc/net/tcp or /proc/net/udp.
    
    Format:
      sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
      0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 28990 1 0000000000000000 100 0 0 10 0
    
    Returns dict with: src_ip, src_port, dst_ip, dst_port, state, inode
    """
    parts = line.split()
    if len(parts) < 10:
        return None
    
    try:
        # Parse local and remote addresses
        local_addr, local_port_hex = parts[1].split(":")
        remote_addr, remote_port_hex = parts[2].split(":")
        
        src_ip = hex_to_ip(local_addr)
        src_port = hex_to_port(local_port_hex)
        dst_ip = hex_to_ip(remote_addr)
        dst_port = hex_to_port(remote_port_hex)
        
        # State (hex value, e.g., 01 = ESTABLISHED, 0A = LISTEN)
        state_hex = parts[3]
        inode = int(parts[9])
        
        # Map TCP state codes to names
        tcp_states = {
            "01": "ESTABLISHED",
            "02": "SYN_SENT",
            "03": "SYN_RECV",
            "04": "FIN_WAIT1",
            "05": "FIN_WAIT2",
            "06": "TIME_WAIT",
            "07": "CLOSE",
            "08": "CLOSE_WAIT",
            "09": "LAST_ACK",
            "0A": "LISTEN",
            "0B": "CLOSING",
        }
        state = tcp_states.get(state_hex, "UNKNOWN")
        
        return {
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "state": state,
            "inode": inode,
        }
    except Exception:
        return None


def find_pid_by_inode(inode):
    """
    Find the PID that owns a socket inode by scanning /proc/*/fd/*
    This maps the connection to a process.
    """
    socket_str = f"socket:[{inode}]"
    
    try:
        for proc_dir in Path("/proc").iterdir():
            if not proc_dir.is_dir() or not proc_dir.name.isdigit():
                continue
            
            pid = int(proc_dir.name)
            fd_dir = proc_dir / "fd"
            
            if not fd_dir.exists():
                continue
                
            try:
                for fd in fd_dir.iterdir():
                    try:
                        link = fd.read_link()
                        if str(link) == socket_str:
                            return pid
                    except (OSError, PermissionError):
                        continue
            except (OSError, PermissionError):
                continue
                
    except Exception:
        pass
        
    return None


def parse_proc_net():
    """
    Read /proc/net/tcp and /proc/net/udp directly to get ALL connections.
    Returns list of dicts with format similar to parse_netstat_output().
    """
    results = []
    
    # Read TCP connections
    try:
        with open("/proc/net/tcp", "r") as f:
            lines = f.readlines()[1:]  # Skip header
            for line in lines:
                conn = parse_proc_net_line(line)
                if conn:
                    conn["protocol"] = "tcp"
                    results.append(conn)
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to read /proc/net/tcp: {e}")
    
    # Read UDP connections
    try:
        with open("/proc/net/udp", "r") as f:
            lines = f.readlines()[1:]  # Skip header
            for line in lines:
                conn = parse_proc_net_line(line)
                if conn:
                    conn["protocol"] = "udp"
                    # UDP doesn't have meaningful state in /proc
                    conn["state"] = "LISTEN"
                    results.append(conn)
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to read /proc/net/udp: {e}")
    
    # Map inodes to PIDs and process names
    for conn in results:
        inode = conn.get("inode")
        if inode:
            pid = find_pid_by_inode(inode)
            if pid:
                conn["pid"] = pid
                # Get process name from /proc/[pid]/comm
                try:
                    with open(f"/proc/{pid}/comm", "r") as f:
                        conn["process_name"] = f.read().strip()
                except Exception:
                    conn["process_name"] = ""
            else:
                conn["pid"] = None
                conn["process_name"] = ""
        
        # Convert to format matching parse_netstat_output
        conn["local_address"] = f"{conn['src_ip']}:{conn['src_port']}"
        conn["remote_address"] = f"{conn['dst_ip']}:{conn['dst_port']}"
    
    return results
