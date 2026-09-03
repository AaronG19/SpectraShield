import os
import platform
import socket
import subprocess
import re
from agent_lib.logger import log

SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".win", ".bid", ".download", ".review", ".date", ".faith", ".science", ".party", ".racing", ".gdn", ".work", ".men", ".loan", ".click", ".link", ".site", ".online"}
SUSPICIOUS_KEYWORDS = ["free", "win", "prize", "bonus", "casino", "crypt", "bitcoin", "wallet", "login", "secure", "verify", "account", "update", "bank", "paypal"]

_known_suspicious = set()


def _get_dns_servers():
    servers = []
    if os.name == "nt":
        out, _, _ = _run(["nslookup", "-type=ns", "localhost"])
        for line in out.splitlines():
            m = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
            if m:
                servers.append(m.group(1))
        try:
            import ctypes
            import ctypes.wintypes
            buf = ctypes.create_unicode_buffer(256)
            ctypes.windll.dnsapi.DnsQueryConfig(0, 0, None, None, ctypes.byref(buf), ctypes.byref(ctypes.c_int(256)))
            servers_str = buf.value
            if servers_str:
                for s in servers_str.split(","):
                    s = s.strip()
                    if s:
                        servers.append(s)
        except Exception:
            pass
    else:
        with open("/etc/resolv.conf") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
    return list(set(servers))


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return "", str(e), -1


def _is_suspicious_domain(domain):
    domain_lower = domain.lower()
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            return tld
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in domain_lower:
            return f"keyword:{kw}"
    return None


def check_dns_requests():
    events = []
    local_domains = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
    try:
        hostname = platform.node().lower()
        local_domains.add(hostname)
        local_domains.add(socket.gethostbyname(hostname))
    except Exception:
        pass

    dns_servers = _get_dns_servers()
    log.debug("DNS servers", servers=dns_servers)

    sniffer_events = []
    if os.name == "nt":
        try:
            out, _, _ = _run(["powershell", "-Command",
                "Get-DnsClientCache | Select-Object -Property Entry,Name | Format-Table -AutoSize"])
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    domain = parts[0].lower().strip()
                    if domain and domain not in local_domains and not domain.startswith("entry"):
                        match = _is_suspicious_domain(domain)
                        if match:
                            sniffer_events.append({
                                "domain": domain,
                                "url": "",
                                "action": "ALERT",
                                "matched_pattern": f"suspicious_{match}",
                            })
                            _known_suspicious.add(domain)
        except Exception as e:
            log.debug("DNS cache check failed", error=str(e))
    else:
        try:
            out, _, _ = _run(["resolvectl", "query"] if subprocess.run(["which", "resolvectl"], capture_output=True).returncode == 0 else ["systemd-resolve", "--statistics"])
        except Exception:
            pass

    events.extend(sniffer_events)
    if events:
        log.info("Suspicious DNS queries detected", count=len(events))
    return events


def check_blocked_domains():
    events = []
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts" if os.name == "nt" else "/etc/hosts"
    try:
        with open(hosts_path) as f:
            content = f.read()
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("127.0.0.1", "0.0.0.1"):
                domain = parts[1].lower()
                events.append({
                    "domain": domain,
                    "url": "",
                    "action": "BLOCK",
                    "matched_pattern": "hosts_block",
                })
    except Exception as e:
        log.debug("Hosts file check failed", error=str(e))
    return events


def check_web_dns():
    events = []
    events.extend(check_dns_requests())
    events.extend(check_blocked_domains())
    return events
