import re
import socket
from typing import Optional

from agent_lib.logger import log


DYNAMIC_DNS_DOMAINS = {
    "duckdns.org", "no-ip.org", "noip.com", "dyndns.org",
    "dyn.com", "dnsdynamic.org", "changeip.com", "free-my-ip.com",
    "myftp.org", "myftp.biz", "ddns.net", "servehttp.com",
    "servehttps.com", "serveftp.com", "serveftp.net", "servegame.com",
    "serveminecraft.net", "sytes.net", "zapto.org", "zapto.net",
    "hopto.org", "hopto.net", "strangled.net", "blogdns.com",
    "dnsalias.com", "dnsalias.net", "dnsdojo.com", "dnsdojo.net",
    "dynalias.org", "dynalias.net", "dynalias.com",
    "No-IP.com", "noip", "afraid.org", "freedns",
}

SUSPICIOUS_TLD = {".xyz", ".top", ".club", ".gq", ".ml", ".cf", ".tk", "work"}

RARE_ASNS = {  # ASNs commonly associated with bulletproof hosting / abuse
    20473,  # AS-CHOOPA
    60068,  # CDNEXT
    58061,  # Scalaxy
    47869,  # QUANTIL
    45014,  # CORE-SERVER
    39798,  # MIVATECH
    36351,  # SOFTLAYER
    36236,  # NETMASS
    32748,  # STEADFAST
    32244,  # LIQUIDWEB
    31863,  # DACEN
    29838,  # SINGLEHOP
    26496,  # AS-26496-GO-DADDY
    23352,  # SERVERCENTRAL
    21844,  # THEPLANET
    21399,  # PRIVATESYSTEM
    20940,  # AKAMAI (frequently abused)
    20454,  # AMAZON-AWS
    19527,  # MADGEN
    19318,  # IS-AS-1
    19148,  # LEASEWEB
    16509,  # AMAZON-02
    16276,  # OVH
    14618,  # AMAZON-AES
    14061,  # DIGITALOCEAN
    13335,  # CLOUDFLARE
    12876,  # ONLINE-SAS
    12874,  # FASTWEB
    12322,  # PROXAD
}


class DomainIntel:
    def __init__(self):
        self._rdns_cache = {}
        self._asn_cache = {}

    def reverse_dns(self, ip: str) -> Optional[str]:
        if ip in self._rdns_cache:
            return self._rdns_cache[ip]
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            self._rdns_cache[ip] = host
            return host
        except (socket.herror, socket.gaierror, OSError):
            self._rdns_cache[ip] = None
            return None

    def is_dynamic_dns(self, hostname: str) -> bool:
        if not hostname:
            return False
        parts = hostname.lower().split(".")
        domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname.lower()
        return domain in DYNAMIC_DNS_DOMAINS

    def is_suspicious_tld(self, hostname: str) -> bool:
        if not hostname:
            return False
        hostname_lower = hostname.lower()
        for tld in SUSPICIOUS_TLD:
            if hostname_lower.endswith(tld):
                return True
        return False

    def is_typosquatted(self, hostname: str, known_domains: Optional[set] = None) -> bool:
        if not hostname or not known_domains:
            return False
        hostname_lower = hostname.lower()
        for known in known_domains:
            known_lower = known.lower()
            if hostname_lower == known_lower:
                continue
            edits = self._levenshtein(hostname_lower, known_lower)
            if 0 < edits <= 2:
                return True
            known_parts = known_lower.split(".")
            host_parts = hostname_lower.split(".")
            if len(known_parts) == 2 and len(host_parts) == 2:
                if known_parts[0] in host_parts[0] or host_parts[0] in known_parts[0]:
                    return True
        return False

    def _levenshtein(self, a: str, b: str) -> int:
        m, n = len(a), len(b)
        dp = list(range(n + 1))
        for i in range(1, m + 1):
            prev = dp[0]
            dp[0] = i
            for j in range(1, n + 1):
                temp = dp[j]
                if a[i-1] == b[j-1]:
                    dp[j] = prev
                else:
                    dp[j] = 1 + min(prev, dp[j], dp[j-1])
                prev = temp
        return dp[n]

    def enrich_connection(self, remote_ip: str) -> dict:
        result = {
            "ip": remote_ip,
            "hostname": None,
            "is_dynamic_dns": False,
            "is_suspicious_tld": False,
            "is_typosquatted": False,
        }
        hostname = self.reverse_dns(remote_ip)
        result["hostname"] = hostname
        if hostname:
            result["is_dynamic_dns"] = self.is_dynamic_dns(hostname)
            result["is_suspicious_tld"] = self.is_suspicious_tld(hostname)
        return result
