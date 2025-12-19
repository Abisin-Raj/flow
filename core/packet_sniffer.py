import socket
import struct
import threading
import time
import logging
import select

# add globals for control
_sniffer_running = False
_sniffer_lock = threading.Lock()
_pkt_sock = None
_ip_sock = None
_sniffer_thread = None


from core.scan_detector import detector  # noqa: E402
from core.alert_engine import create_alert_with_geo  # noqa: E402
from core import dns_tunneling_detector

log = logging.getLogger("core.packet_sniffer")


def _parse_ip_packet_and_process(buf: bytes):
    # buf starts at IP header
    if len(buf) < 20 + 20:
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


def _parse_eth_frame_and_process(raw_data: bytes):
    # ethernet + ip + tcp
    if len(raw_data) < 14 + 20 + 20:
        return
    try:
        eth_proto = struct.unpack("!H", raw_data[12:14])[0]
    except struct.error:
        return
    if eth_proto != 0x0800:
        return
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
    Minimal DNS parser to extract Query Name.
    DNS Header is 12 bytes.
    """
    try:
        if len(payload) < 12:
            return
            
        # extract QDCOUNT at offset 4 (2 bytes)
        # header = struct.unpack("!HHHHHH", payload[:12])
        # qdcount = header[2]
        
        # skip header
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
                # We don't handle compression in simple query usually
                break
                
            if offset + length > len(payload):
                break
                
            label = payload[offset : offset+length]
            qname_parts.append(label.decode('utf-8', errors='ignore'))
            offset += length
            
        qname = ".".join(qname_parts)
        
        # After QNAME is QTYPE (2 bytes) + QCLASS (2 bytes)
        # We can try to read QTYPE if needed.
        
        if qname:
             dns_tunneling_detector.note_query(src_ip, qname, 0)
             res = dns_tunneling_detector.evaluate(src_ip)
             if res == "dns_tunneling":
                 _alert_tunneling(src_ip)

    except Exception:
        # Malformed packet or parsing error
        pass

def _alert_tunneling(src_ip: str):
    try:
        create_alert_with_geo(
            src_ip=src_ip,
            alert_type="DNS Tunneling",
            message=f"Possible DNS tunneling detected from {src_ip} (long/frequent queries)",
            severity="high",
            category="dns_tunneling"
        )
    except Exception:
        pass

