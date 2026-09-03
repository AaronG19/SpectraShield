import platform
import socket
import struct
from typing import Dict, List, Optional

import psutil

from agent_lib.logger import log


# Rare / high-risk ports for external connections
HIGH_RISK_PORTS = {
    22: "SSH", 23: "Telnet", 445: "SMB", 135: "RPC", 139: "NetBIOS",
    3389: "RDP", 5900: "VNC", 5901: "VNC", 5985: "WinRM", 5986: "WinRM-SSL",
    4444: "C2 (Metasploit)", 1337: "C2 (common)", 6666: "C2 (IRC)",
    6667: "C2 (IRC)", 6668: "C2 (IRC)", 6669: "C2 (IRC)",
    12345: "C2 (NetBus)", 31337: "C2 (BackOrifice)", 4443: "C2 (HTTPS alt)",
    1443: "C2 (SQL alt)", 8081: "C2 (HTTP alt)", 8443: "C2 (HTTPS alt)",
    # Beaconing / exfil
    53: "DNS exfil risk", 110: "POP3 exfil", 143: "IMAP exfil",
    443: "HTTPS beacon", 80: "HTTP beacon",
}

# Countries with lower trust for EDR purposes (not political, based on abuse data)
# Note: This is a simple heuristic — integration with GeoIP service recommended
RARE_COUNTRY_CODES = set()

# Internal IP ranges as tuple of (ip_int_min, ip_int_max) for fast checking
_PRIVATE_RANGES = [
    (0x0A000000, 0x0AFFFFFF),      # 10.0.0.0/8
    (0xAC100000, 0xAC1FFFFF),      # 172.16.0.0/12
    (0xC0A80000, 0xC0A8FFFF),      # 192.168.0.0/16
    (0x7F000000, 0x7FFFFFFF),      # 127.0.0.0/8
    (0x00000000, 0x00FFFFFF),      # 0.0.0.0/8
    (0xA9FE0000, 0xA9FEFFFF),      # 169.254.0.0/16
    (0x64400000, 0x647FFFFF),      # 100.64.0.0/10 (CGNAT)
    (0xC0000000, 0xC00000FF),      # 192.0.0.0/24
    (0xC0000200, 0xC00002FF),      # 192.0.2.0/24 (TEST-NET-1)
    (0xC0586300, 0xC05863FF),      # 192.58.128.0/17
    (0xC0B85800, 0xC0B85BFF),      # 192.88.99.0/24
    (0xF0000000, 0xFFFFFFFF),      # 240.0.0.0/4
]


def _ip_to_int(ip: str) -> int:
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except (OSError, struct.error):
        return 0


def is_private_ip(ip: str) -> bool:
    ip_int = _ip_to_int(ip)
    for low, high in _PRIVATE_RANGES:
        if low <= ip_int <= high:
            return True
    return False


def get_network_connections() -> List[dict]:
    connections = []
    system = platform.system().lower()
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.family == 2:
                try:
                    pname = ""
                    if conn.pid:
                        try:
                            p = psutil.Process(conn.pid)
                            pname = p.name() or ""
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                    raddr_ip = conn.raddr.ip if conn.raddr else ""
                    raddr_port = conn.raddr.port if conn.raddr else 0
                    connections.append({
                        "process_name": pname,
                        "pid": conn.pid or 0,
                        "local_address": laddr,
                        "local_ip": conn.laddr.ip if conn.laddr else "",
                        "local_port": conn.laddr.port if conn.laddr else 0,
                        "remote_ip": raddr_ip,
                        "remote_port": raddr_port,
                        "protocol": "TCP" if conn.type == 1 else "UDP",
                        "state": conn.status or "",
                    })
                except Exception:
                    pass
    except Exception:
        pass
    return connections


def get_suspicious_connections(connections: List[dict]) -> List[dict]:
    suspicious = []
    for c in connections:
        rip = c.get("remote_ip", "")
        rport = c.get("remote_port", 0)
        if not rip or is_private_ip(rip):
            continue
        if rport in HIGH_RISK_PORTS:
            c["suspicious_reason"] = f"{HIGH_RISK_PORTS[rport]} — {rport}"
            suspicious.append(c)
    return suspicious


def get_rare_external_connections(
    connections: List[dict],
    known_ips: Optional[set] = None,
) -> List[dict]:
    known = known_ips or set()
    rare = []
    for c in connections:
        rip = c.get("remote_ip", "")
        if not rip or is_private_ip(rip):
            continue
        if rip not in known:
            c["suspicious_reason"] = "Rare external connection"
            rare.append(c)
    return rare


def reverse_dns_lookup(ip: str) -> Optional[str]:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return None


def get_connection_domain_intel(remote_ip: str) -> dict:
    result = {
        "ip": remote_ip,
        "hostname": None,
        "is_dynamic_dns": False,
    }
    hostname = reverse_dns_lookup(remote_ip)
    result["hostname"] = hostname
    if hostname:
        dynamic_dns_indicators = {
            "duckdns", "no-ip", "dyndns", "dnsdynamic",
            "ddns", "servehttp", "servehttps", "serveftp",
            "servegame", "sytes", "zapto", "hopto",
            "strangled", "dnsalias", "dnsdojo", "dynalias",
            "myftp", "changeip", "freedns", "afraid",
        }
        hostname_lower = hostname.lower()
        for indicator in dynamic_dns_indicators:
            if indicator in hostname_lower:
                result["is_dynamic_dns"] = True
                break
    return result
