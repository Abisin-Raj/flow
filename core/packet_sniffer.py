"""
Packet Sniffer Module.

This module implements a raw socket sniffer to capture and analyze network packets.
It supports:
1.  AF_PACKET sockets for capturing Ethernet frames (Layer 2).
2.  AF_INET raw sockets for capturing IP packets (Layer 3).
3.  Parsing IP, TCP, and UDP headers.
4.  Detecting SYN flags for port scan detection.
5.  Extracting DNS payloads for analysis.
"""

import socket
import struct
import threading
import time
import logging
import select

# Global control variables for the sniffer thread
_sniffer_running = False
_sniffer_lock = threading.Lock()
_pkt_sock = None  # Raw socket for AF_PACKET (Layer 2)
_ip_sock = None   # Raw socket for AF_INET (Layer 3)
_sniffer_thread = None


from core.scan_detector import detector  # noqa: E402
from core.alert_engine import create_alert_with_geo  # noqa: E402

log = logging.getLogger("core.packet_sniffer")


def _parse_ip_packet_and_process(buf: bytes):
    """
    Parse a raw IP packet buffer and process it for detection.

    Args:
        buf (bytes): The raw packet data starting with the IP header.
    """
    # buf starts at IP header
    # Minimum IP header (20) + Minimum TCP header (20) = 40 bytes required for analysis
    if len(buf) < 40:
        return
    try:
        version_ihl = buf[0]
        version = version_ihl >> 4
        if version != 4:
            return
        ihl = (version_ihl & 0x0F) * 4
        if len(buf) < ihl + 20:
            return
        protocol = buf[9]
        if protocol == 6:
            # TCP
            src_ip = socket.inet_ntoa(buf[12:16])
            dst_ip = socket.inet_ntoa(buf[16:20])
            tcp_start = ihl
            tcp_header = buf[tcp_start : tcp_start + 20]
            if len(tcp_header) < 20:
                return
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)
            flags = tcph[5]
            syn_flag = flags & 0x02
            ack_flag = flags & 0x10
            if syn_flag and not ack_flag:
                dst_port = tcph[1]
                now_ts = time.time()
                try:
                    detector.note_packet(
                        src_ip=str(src_ip),
                        dst_port=int(dst_port),
                        ts=now_ts,
                        dst_ip=str(dst_ip),
                    )
                except Exception:
                    pass
                _record_syn(src_ip, dst_port, now_ts)
        elif protocol == 17:
             # UDP
            src_ip = socket.inet_ntoa(buf[12:16])
            dst_ip = socket.inet_ntoa(buf[16:20])
            udp_start = ihl
            udp_header = buf[udp_start : udp_start + 8]
            if len(udp_header) < 8:
                return
            udph = struct.unpack("!HHHH", udp_header)
            src_port = udph[0]
            dst_port = udph[1]
            
            # Check for DNS (usually port 53)
            if dst_port == 53 or src_port == 53:
                # payload is after UDP header
                dns_start = udp_start + 8
                dns_data = buf[dns_start:]
                _process_dns_payload(src_ip, dns_data)
            if syn_flag and not ack_flag:
                dst_port = tcph[1]
                now_ts = time.time()
                try:
                    detector.note_packet(
                        src_ip=str(src_ip),
                        dst_port=int(dst_port),
                        ts=now_ts,
                        dst_ip=str(dst_ip),
                    )
                except Exception:
                    pass
                _record_syn(src_ip, dst_port, now_ts)
    except Exception:
        return


def _parse_ipv6_packet_and_process(buf: bytes):
    """
    Parse a raw IPv6 packet buffer and process it.
    """
    # Minimum IPv6 header is 40 bytes
    if len(buf) < 40:
        return

    try:
        # Version (4 bits) + Traffic Class (8 bits) + Flow Label (20 bits) = 4 bytes
        # Payload Length (2 bytes) = 4-6
        # Next Header (1 byte) = 6
        # Hop Limit (1 byte) = 7
        # Source Address (16 bytes) = 8-24
        # Dest Address (16 bytes) = 24-40
        
        first_word = struct.unpack("!I", buf[0:4])[0]
        version = first_word >> 28
        if version != 6:
            return

        next_header = buf[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, buf[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, buf[24:40])
        
        # We only handle TCP (6) and UDP (17) for now.
        # IPv6 Extension headers complicates "Next Header" significantly since it's a chain.
        # For MVP, we presume no extension headers or only basic ones. 
        # Making a full parser is complex; let's handle direct TCP/UDP.
        
        payload_offset = 40
        if next_header == 6: # TCP
             # ... Logic similar to IPv4 ...
             # Minimal TCP header is 20 bytes
            if len(buf) < payload_offset + 20: 
                return
            tcp_header = buf[payload_offset : payload_offset + 20]
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)
            flags = tcph[5]
            syn_flag = flags & 0x02
            ack_flag = flags & 0x10
            
            if syn_flag and not ack_flag:
                dst_port = tcph[1]
                now_ts = time.time()
                try:
                    detector.note_packet(
                        src_ip=str(src_ip),
                        dst_port=int(dst_port),
                        ts=now_ts,
                        dst_ip=str(dst_ip)
                    )
                except Exception:
                    pass
                _record_syn(src_ip, dst_port, now_ts)

        elif next_header == 17: # UDP
            if len(buf) < payload_offset + 8:
                return
            udp_header = buf[payload_offset : payload_offset + 8]
            udph = struct.unpack("!HHHH", udp_header)
            src_port = udph[0]
            dst_port = udph[1]
            
            if dst_port == 53 or src_port == 53:
                dns_data = buf[payload_offset+8:]
                _process_dns_payload(src_ip, dns_data)

    except Exception:
        pass

def _parse_eth_frame_and_process(raw_data: bytes):
    """
    Parse a raw Ethernet frame and process the encapsulated IP packet.

    Args:
        raw_data (bytes): The raw frame data starting with the Ethernet header.
    """
    # ethernet header (14) + ip header (20) + tcp header (20) = 54 bytes minimum
    if len(raw_data) < 54:
        return
    try:
        eth_proto = struct.unpack("!H", raw_data[12:14])[0]
    except struct.error:
        return
    if eth_proto == 0x0800:
        # IPv4
        pass  # Proceed to IPv4 logic below
    elif eth_proto == 0x86DD:
        # IPv6
        _parse_ipv6_packet_and_process(raw_data[14:])
        return
    else:
        # Unknown/Ignored
        return

    # IPv4 Logic continues here...
    ip_start = 14
    ip_base = raw_data[ip_start : ip_start + 20]
    if len(ip_base) < 20:
        return
    version_ihl = ip_base[0]
    version = version_ihl >> 4
    if version != 4:
        return
    ihl_words = version_ihl & 0x0F
    ihl = ihl_words * 4
    if len(raw_data) < ip_start + ihl + 20:
        return
    protocol = ip_base[9]
    if protocol != 6:
        return
    try:
        src_ip = socket.inet_ntoa(ip_base[12:16])
        dst_ip = socket.inet_ntoa(ip_base[16:20])
    except Exception:
        return
    tcp_start = ip_start + ihl
    tcp_header = raw_data[tcp_start : tcp_start + 20]
    if len(tcp_header) < 20:
        return
    try:
        tcph = struct.unpack("!HHLLBBHHH", tcp_header)
    except struct.error:
        return
    flags = tcph[5]
    syn_flag = flags & 0x02
    ack_flag = flags & 0x10
    if syn_flag and not ack_flag:
        dst_port = tcph[1]
        now_ts = time.time()
        try:
            detector.note_packet(
                src_ip=str(src_ip),
                dst_port=int(dst_port),
                ts=now_ts,
                dst_ip=str(dst_ip),
            )
        except Exception:
            pass
        _record_syn(src_ip, dst_port, now_ts)


def packet_sniffer_loop():
    """
    Main loop for the packet sniffer thread.

    It initializes raw sockets (AF_PACKET and AF_INET), uses `select` to monitor them,
    and dispatches received data to the appropriate parsing function.
    """
    global _pkt_sock, _ip_sock, _sniffer_running
    log.info("Packet sniffer starting (AF_PACKET + AF_INET)")

    _pkt_sock = None
    _ip_sock = None

    try:
        try:
            _pkt_sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)
            )
        except PermissionError:
            log.error(
                "Packet sniffer permission error on AF_PACKET. Need root or CAP_NET_RAW."
            )
        except OSError as e:
            log.error("AF_PACKET socket error: %s", e)

        try:
            _ip_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP
            )
            # We also need TCP for the scan detector, but a single IPPROTO_TCP will miss UDP.
            # Ideally we want IPPROTO_IP to capture all, but that's often not supported for reading.
            # Linux SOCK_RAW usually requires specific protocol.
            # To get both, we might need two sockets or just use AF_PACKET for everything.
            # THE CURRENT IMPLEMENTATION uses _ip_sock primarily for IP processing.
            # Let's switch AF_INET socket to IPPROTO_UDP to catch DNS since 
            # AF_PACKET is also running and catches ETH frames (including IP).
            # Actually, `socket.IPPROTO_TCP` only gets TCP.
            # We want headers. AF_PACKET (SOCK_RAW) gets everything including link layer.
            # If AF_PACKET works, we don't strictly need _ip_sock unless for fallback.
            # But let's add a second RAW socket for UDP if needed, or better yet:
            # We already have AF_PACKET which reads EVERYTHING.
            # `_parse_eth_frame_and_process` handles `raw_data`. 
            # `_parse_ip_packet_and_process` handles `s` if it is `_ip_sock`.
            # Let's start a UDP socket too.
        except Exception:
            pass

        try:
            _ip_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
            )
        except PermissionError:
            log.error(
                "Packet sniffer permission error on AF_INET. Need root or CAP_NET_RAW."
            )
        except OSError as e:
            log.error("AF_INET raw socket error: %s", e)

        if not _pkt_sock and not _ip_sock:
            log.error("No usable sniffer socket available, aborting sniffer.")
            return

        log.info("Packet sniffer listening on available raw sockets")

        sockets = [s for s in (_pkt_sock, _ip_sock) if s]

        while True:
            with _sniffer_lock:
                if not _sniffer_running:
                    break

            try:
                r, _, _ = select.select(sockets, [], [], 1.0)
            except Exception:
                time.sleep(0.5)
                continue

            if not r:
                continue

            for s in r:
                try:
                    raw_data, addr = s.recvfrom(65535)
                except OSError:
                    log.warning("Packet sniffer recvfrom error on socket, skipping")
                    continue

                if s is _ip_sock:
                    _parse_ip_packet_and_process(raw_data)
                else:
                    _parse_eth_frame_and_process(raw_data)

    finally:
        try:
            if _pkt_sock:
                _pkt_sock.close()
        except Exception:
            pass
        try:
            if _ip_sock:
                _ip_sock.close()
        except Exception:
            pass
        _pkt_sock = None
        _ip_sock = None
        log.info("Packet sniffer stopped")


def start_packet_sniffer():
    """
    Start the packet sniffer in a background thread.
    """
    global _sniffer_running, _sniffer_thread
    with _sniffer_lock:
        if _sniffer_running:
            return
        _sniffer_running = True
        _sniffer_thread = threading.Thread(target=packet_sniffer_loop, daemon=True)
        _sniffer_thread.start()
        log.info("Packet sniffer thread launched")


def stop_packet_sniffer(timeout: float = 2.0):
    """
    Stop the packet sniffer thread and close sockets.
    Safe to call multiple times.
    """
    global _sniffer_running, _pkt_sock, _ip_sock, _sniffer_thread
    with _sniffer_lock:
        if not _sniffer_running:
            return
        _sniffer_running = False

    # close sockets to wake select/recvfrom
    try:
        if _pkt_sock:
            try:
                _pkt_sock.close()
            except Exception:
                pass
        if _ip_sock:
            try:
                _ip_sock.close()
            except Exception:
                pass
    except Exception:
        log.exception("Error closing sniffer sockets")

    # join thread if possible
    try:
        if _sniffer_thread is not None:
            _sniffer_thread.join(timeout)
    except Exception:
        pass

    log.info("stop_packet_sniffer requested")


def _record_syn(src_ip: str, dst_port: int, now_ts: float, window_seconds: int = 10):
    """Ask detector if this source needs an alert and create it."""
    try:
        if not src_ip or dst_port is None or dst_port <= 0:
            return

        try:
            category = detector.evaluate(src_ip, now_ts)
        except Exception:
            category = None

        if not category:
            return

        try:
            events = detector.recent(src_ip, now_ts, window_seconds)
        except Exception:
            events = [(now_ts, dst_port, "")]

        count_events = len(events)
        if category == "syn_flood":
            note = f"SYN flood pattern detected, about {count_events} SYN packets in last few seconds."
        elif category == "sweep":
            note = f"Port sweep detected, {count_events} recent connection attempts across hosts."
        else:
            note = f"Port scan detected, category: {category}, recent {count_events} ports."

        severity = (
            "high" if category in ("fast", "brute", "syn_flood", "sweep") else "medium"
        )

        try:
            create_alert_with_geo(
                src_ip=src_ip,
                alert_type="Port Scan" if category != "syn_flood" else "SYN Flood",
                message=note,
                severity=severity,
                category=category,
            )
        except Exception:
            log.exception("Failed to create port scan alert for %s", src_ip)

    except Exception:
        log.exception("_record_syn error")
        return

def _process_dns_payload(src_ip: str, payload: bytes):
    """
    Parse DNS payload to extract the Query Name (QNAME).
    
    This is a minimal parser sufficient for extracting domain names.

    Args:
        src_ip (str): Source IP of the DNS query.
        payload (bytes): The UDP payload containing the DNS message.
    """
    try:
        if len(payload) < 12:
            return
            
        # extract QDCOUNT at offset 4 (2 bytes)
        # header = struct.unpack("!HHHHHH", payload[:12])
        # qdcount = header[2]
        
        # skip header (12 bytes) to get to Question Section
        offset = 12
        # Parse QNAME
        # sequence of labels: len-byte + label. ends with 0x00.
        
        qname_parts = []
        while offset < len(payload):
            length = payload[offset]
            offset += 1
            if length == 0:
                break
            if length > 63: 
                # Pointer or invalid (pointers start with 11xxxxxx)
                # We don't handle compression in simple query usually because
                # the first qname in a query is rarely compressed.
                break
                
            if offset + length > len(payload):
                break
                
            label = payload[offset : offset+length]
            qname_parts.append(label.decode('utf-8', errors='ignore'))
            offset += length
            
        qname = ".".join(qname_parts)
        
        # After QNAME is QTYPE (2 bytes) + QCLASS (2 bytes)
        # QNAME could be used for future analysis if needed
        _ = qname  # Parsed but not currently used

    except Exception:
        # Malformed packet or parsing error, safely ignore
        pass
