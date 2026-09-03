import json, socket, time as _time, re
import concurrent.futures
import threading
from datetime import datetime
from typing import Optional
import requests

# ---------------------------------------------------------------------------
# Configuration (loaded from caller or env)
# ---------------------------------------------------------------------------
VT_API_KEY = ""
ABUSEIPDB_API_KEY = ""
OTX_API_KEY = ""
GREYNOISE_API_KEY = ""

def configure(**kwargs):
    global VT_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY, GREYNOISE_API_KEY
    VT_API_KEY = kwargs.get("VT_API_KEY", VT_API_KEY)
    ABUSEIPDB_API_KEY = kwargs.get("ABUSEIPDB_API_KEY", ABUSEIPDB_API_KEY)
    OTX_API_KEY = kwargs.get("OTX_API_KEY", OTX_API_KEY)
    GREYNOISE_API_KEY = kwargs.get("GREYNOISE_API_KEY", GREYNOISE_API_KEY)

# ---------------------------------------------------------------------------
# IOC Detection
# ---------------------------------------------------------------------------
def detect_ioc_type(val: str) -> str:
    if val.startswith("http://") or val.startswith("https://"):
        return "url"
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val):
        return "ip"
    if re.match(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", val):
        return "hash"
    if "." in val:
        return "domain"
    return "unknown"

# ---------------------------------------------------------------------------
# Rate limiter helper
# ---------------------------------------------------------------------------
_timestamps = []
def _rate_limit(limit=4, window=60):
    now = _time.time()
    global _timestamps
    _timestamps = [t for t in _timestamps if t > now - window]
    if len(_timestamps) >= limit:
        sleep_for = min(max(0, _timestamps[0] + window - now) + 0.5, 5)
        _time.sleep(sleep_for)
        _timestamps = [t for t in _timestamps if t > _time.time() - window]
    _timestamps.append(_time.time())

# ---------------------------------------------------------------------------
# In-memory cache for ThreatIntelService.lookup()
# ---------------------------------------------------------------------------
_lookup_cache = {}
_lookup_cache_lock = threading.Lock()
_LOOKUP_CACHE_TTL = 600  # 10 minutes

def _get_cached_lookup(indicator: str):
    key = indicator.strip().lower()
    with _lookup_cache_lock:
        entry = _lookup_cache.get(key)
        if entry is None:
            return None
        result, ts = entry
        if _time.time() - ts < _LOOKUP_CACHE_TTL:
            return result
        del _lookup_cache[key]
        return None

def _set_cached_lookup(indicator: str, result: dict):
    key = indicator.strip().lower()
    with _lookup_cache_lock:
        _lookup_cache[key] = (result, _time.time())

# ---------------------------------------------------------------------------
# Provider Base
# ---------------------------------------------------------------------------
class ThreatIntelProvider:
    name = "base"
    def lookup(self, indicator: str, ioc_type: str) -> dict:
        return {"provider": self.name, "found": False}

# ---------------------------------------------------------------------------
# DNSBL Provider
# ---------------------------------------------------------------------------
SPAMHAUS_CODES = {
    "127.0.0.2": "Direct spam source (SBL)",
    "127.0.0.3": "Hijacked IP / spam source (CSS)",
    "127.0.0.4": "Exploit / proxy / malware (XBL)",
    "127.0.0.5": "Passive malware detection",
    "127.0.0.6": "Passive spam detection",
    "127.0.0.7": "Domain blocklist (DBL)",
    "127.0.0.9": "Passive spam source",
    "127.0.0.10": "Dynamic / residential IP (PBL)",
    "127.0.0.11": "Passive dynamic IP",
}

class DNSBLProvider(ThreatIntelProvider):
    name = "dnsbl"
    def lookup(self, indicator: str, ioc_type: str) -> dict:
        if ioc_type != "ip":
            return {"provider": self.name, "found": False}
        parts = indicator.strip().split(".")
        if len(parts) != 4:
            return {"provider": self.name, "found": False, "checked": [], "hits": []}
        reversed_ip = ".".join(reversed(parts))
        lists = [("spamhaus", "zen.spamhaus.org"), ("tor_exit", "tor.dan.me.uk")]
        checked, hits = [], []
        for name, domain in lists:
            checked.append(name)
            try:
                result = socket.getaddrinfo(f"{reversed_ip}.{domain}", 0)
                code_ip = result[0][4][0] if result else ""
                category = SPAMHAUS_CODES.get(code_ip, "Listed (unknown reason)")
                if name == "tor_exit":
                    category = "Tor exit node"
                hits.append({"list": name, "code": code_ip, "category": category})
            except socket.gaierror:
                pass
        return {"provider": self.name, "found": len(hits) > 0, "checked": checked, "hits": hits}

# ---------------------------------------------------------------------------
# VirusTotal Provider
# ---------------------------------------------------------------------------
class VirusTotalProvider(ThreatIntelProvider):
    name = "virustotal"

    def _extract_engines(self, data, results_key="last_analysis_results"):
        engines = {}
        results = data.get("attributes", {}).get(results_key, {}) if isinstance(data, dict) else {}
        for engine, info in results.items():
            verdict = info.get("category", "") if isinstance(info, dict) else ""
            detail = info.get("result", "") if isinstance(info, dict) else ""
            if verdict in ("malicious", "suspicious"):
                engines[engine] = {"verdict": verdict, "detail": detail}
        return engines

    def lookup(self, indicator: str, ioc_type: str) -> dict:
        if not VT_API_KEY:
            return {"provider": self.name, "found": False, "error": "no_key"}
        _rate_limit(4, 60)
        headers = {"x-apikey": VT_API_KEY}
        try:
            if ioc_type == "url":
                r = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": indicator}, timeout=(5, 10))
                if r.status_code == 200:
                    analysis_id = r.json()["data"]["id"]
                    r2 = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=(5, 10))
                    if r2.status_code == 200:
                        data = r2.json()["data"]
                        stats = data["attributes"]["stats"]
                        engines = self._extract_engines(data["attributes"], "results")
                        return {"provider": self.name, "found": stats.get("malicious", 0) > 0, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "total": sum(stats.values()), "engines": engines}
                return {"provider": self.name, "found": False, "error": f"http_{r.status_code}"}
            elif ioc_type == "ip":
                r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}", headers=headers, timeout=(5, 10))
                if r.status_code == 200:
                    attrs = r.json()["data"]["attributes"]
                    stats = attrs["last_analysis_stats"]
                    engines = self._extract_engines(attrs)
                    return {"provider": self.name, "found": stats.get("malicious", 0) > 0, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "total": sum(stats.values()), "engines": engines, "country": attrs.get("country", ""), "asn": attrs.get("asn", 0), "network": attrs.get("network", ""), "tags": attrs.get("tags", []), "reputation": attrs.get("reputation", 0), "regional_internet_registry": attrs.get("regional_internet_registry", "")}
                return {"provider": self.name, "found": False, "error": f"http_{r.status_code}"}
            elif ioc_type == "domain":
                r = requests.get(f"https://www.virustotal.com/api/v3/domains/{indicator}", headers=headers, timeout=(5, 10))
                if r.status_code == 200:
                    attrs = r.json()["data"]["attributes"]
                    stats = attrs["last_analysis_stats"]
                    engines = self._extract_engines(attrs)
                    return {"provider": self.name, "found": stats.get("malicious", 0) > 0, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "total": sum(stats.values()), "engines": engines, "tags": attrs.get("tags", []), "reputation": attrs.get("reputation", 0), "categories": attrs.get("categories", {}), "popular_threat_classification": attrs.get("popular_threat_classification", {})}
                return {"provider": self.name, "found": False, "error": f"http_{r.status_code}"}
            elif ioc_type == "hash":
                r = requests.get(f"https://www.virustotal.com/api/v3/files/{indicator}", headers=headers, timeout=(5, 10))
                if r.status_code == 200:
                    attrs = r.json()["data"]["attributes"]
                    stats = attrs["last_analysis_stats"]
                    engines = self._extract_engines(attrs)
                    return {"provider": self.name, "found": stats.get("malicious", 0) > 0, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "total": sum(stats.values()), "engines": engines, "tags": attrs.get("tags", []), "reputation": attrs.get("reputation", 0), "type_description": attrs.get("type_description", ""), "names": attrs.get("names", []), "meaningful_name": attrs.get("meaningful_name", ""), "popular_threat_classification": attrs.get("popular_threat_classification", {}), "size": attrs.get("size", 0), "first_submission_date": attrs.get("first_submission_date", 0), "last_submission_date": attrs.get("last_submission_date", 0), "last_modification_date": attrs.get("last_modification_date", 0)}
                return {"provider": self.name, "found": False, "error": f"http_{r.status_code}"}
            return {"provider": self.name, "found": False, "error": f"unknown_type_{ioc_type}"}
        except Exception as e:
            return {"provider": self.name, "found": False, "error": str(e)}

# ---------------------------------------------------------------------------
# AbuseIPDB Provider
# ---------------------------------------------------------------------------
class AbuseIPDBProvider(ThreatIntelProvider):
    name = "abuseipdb"
    def lookup(self, indicator: str, ioc_type: str) -> dict:
        if ioc_type != "ip":
            return {"provider": self.name, "found": False}
        _rate_limit(10, 60)
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"} if ABUSEIPDB_API_KEY else {"User-Agent": "Mozilla/5.0"}
        params = {"ipAddress": indicator, "maxAgeInDays": 90, "verbose": True}
        try:
            if ABUSEIPDB_API_KEY:
                r = requests.get(url, headers=headers, params=params, timeout=(5, 10))
                if r.status_code == 200:
                    d = r.json().get("data", {})
                    score = d.get("abuseConfidenceScore", 0)
                    return {"provider": self.name, "found": score > 0, "abuse_confidence_score": score, "total_reports": d.get("totalReports", 0), "country": d.get("countryCode", ""), "isp": d.get("isp", ""), "domain": d.get("domain", ""), "usage_type": d.get("usageType", ""), "is_whitelisted": d.get("isWhitelisted", False), "last_reported_at": d.get("lastReportedAt", "")}
                return {"provider": self.name, "found": False, "error": f"http_{r.status_code}"}
            else:
                r = requests.get(f"https://www.abuseipdb.com/check/{indicator}", timeout=(5, 8), headers={"User-Agent": "Mozilla/5.0"})
                if r.status_code == 200:
                    return {"provider": self.name, "found": True, "note": "web_scrape", "abuse_confidence_score": 50, "total_reports": 1}
                return {"provider": self.name, "found": False}
        except Exception as e:
            return {"provider": self.name, "found": False, "error": str(e)}

# ---------------------------------------------------------------------------
# AlienVault OTX Provider
# ---------------------------------------------------------------------------
class OTXProvider(ThreatIntelProvider):
    name = "alienvault_otx"
    def lookup(self, indicator: str, ioc_type: str) -> dict:
        if not OTX_API_KEY:
            return {"provider": self.name, "found": False, "note": "Requires OTX_API_KEY"}
        _rate_limit(10, 60)
        headers = {"X-OTX-API-KEY": OTX_API_KEY, "Accept": "application/json"}
        endpoint_map = {"ip": f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}", "domain": f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}", "hash": f"https://otx.alienvault.com/api/v1/indicators/file/{indicator}"}
        url = endpoint_map.get(ioc_type)
        if not url:
            return {"provider": self.name, "found": False}
        try:
            r = requests.get(url, headers=headers, timeout=(5, 10))
            if r.status_code == 200:
                d = r.json()
                pulses = d.get("pulse_info", {}).get("pulses", [])
                tags = list(set(t for p in pulses for t in p.get("tags", [])))
                return {"provider": self.name, "found": len(pulses) > 0, "pulses": [{"name": p.get("name", ""), "description": p.get("description", ""), "tags": p.get("tags", []), "created": p.get("created", ""), "threat_type": p.get("TLP", "")} for p in pulses[:5]], "tags": tags, "pulse_count": len(pulses), "reputation": d.get("reputation", 0), "country": d.get("country_code", "") if ioc_type == "ip" else "", "whois": d.get("whois", "")}
            return {"provider": self.name, "found": False, "error": f"http_{r.status_code}"}
        except Exception as e:
            return {"provider": self.name, "found": False, "error": str(e)}

# ---------------------------------------------------------------------------
# GreyNoise Provider
# ---------------------------------------------------------------------------
class GreyNoiseProvider(ThreatIntelProvider):
    name = "greynoise"
    def lookup(self, indicator: str, ioc_type: str) -> dict:
        if ioc_type != "ip":
            return {"provider": self.name, "found": False}
        headers = {"User-Agent": "Mozilla/5.0"}
        if GREYNOISE_API_KEY:
            headers["key"] = GREYNOISE_API_KEY
            url = f"https://api.greynoise.io/v3/community/{indicator}"
        else:
            url = f"https://api.greynoise.io/v3/community/{indicator}"
        try:
            r = requests.get(url, headers=headers, timeout=(5, 8))
            if r.status_code == 200:
                d = r.json()
                if d.get("noise"):
                    return {"provider": self.name, "found": True, "classification": d.get("classification", "unknown"), "noise": d["noise"], "riot": d.get("riot", False), "name": d.get("name", ""), "last_seen": d.get("last_seen", "")}
            return {"provider": self.name, "found": False}
        except Exception as e:
            return {"provider": self.name, "found": False, "error": str(e)}

# ---------------------------------------------------------------------------
# MalwareBazaar Provider (free, no key needed)
# ---------------------------------------------------------------------------
class MalwareBazaarProvider(ThreatIntelProvider):
    name = "malwarebazaar"
    def lookup(self, indicator: str, ioc_type: str) -> dict:
        if ioc_type != "hash":
            return {"provider": self.name, "found": False}
        _rate_limit(10, 60)
        try:
            r = requests.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": indicator}, timeout=(5, 10))
            if r.status_code == 200:
                d = r.json()
                if d.get("query_status") == "ok" and d.get("data"):
                    entry = d["data"][0]
                    tags = entry.get("tags", [])
                    return {"provider": self.name, "found": True, "malware_family": entry.get("signature", ""), "malware_type": entry.get("file_type", ""), "tags": tags, "first_seen": entry.get("first_seen", ""), "last_seen": entry.get("last_seen", ""), "file_name": entry.get("file_name", ""), "file_size": entry.get("file_size", 0), "reporter": entry.get("reporter", ""), "sha256": entry.get("sha256_hash", ""), "md5": entry.get("md5_hash", ""), "sha1": entry.get("sha1_hash", "")}
            return {"provider": self.name, "found": False}
        except Exception as e:
            return {"provider": self.name, "found": False, "error": str(e)}

# ---------------------------------------------------------------------------
# URLhaus Provider (free, no key needed)
# ---------------------------------------------------------------------------
class URLHausProvider(ThreatIntelProvider):
    name = "urlhaus"
    def lookup(self, indicator: str, ioc_type: str) -> dict:
        if ioc_type not in ("domain", "url"):
            return {"provider": self.name, "found": False}
        _rate_limit(10, 60)
        try:
            r = requests.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": indicator}, timeout=(5, 10))
            if r.status_code == 200:
                d = r.json()
                if d.get("query_status") == "ok":
                    urls = d.get("urls", [])
                    return {"provider": self.name, "found": len(urls) > 0, "url_count": len(urls), "urls": [{"url": u.get("url", ""), "threat": u.get("threat", ""), "tags": u.get("tags", []), "date_added": u.get("date_added", "")} for u in urls[:10]], "blacklist": d.get("blacklists", {})}
            return {"provider": self.name, "found": False}
        except Exception as e:
            return {"provider": self.name, "found": False, "error": str(e)}

# ---------------------------------------------------------------------------
# Reputation Scoring Engine
# ---------------------------------------------------------------------------
class ReputationScoringEngine:
    """Aggregate scores from all providers into a unified reputation score (0-100)."""

    @staticmethod
    def score(provider_results: dict, ioc_type: str) -> dict:
        score = 0
        components = {}

        # VirusTotal
        vt = provider_results.get("virustotal", {})
        if vt.get("found") and "error" not in vt:
            mal = vt.get("malicious", 0)
            total = vt.get("total", 1)
            if mal > 0:
                vt_score = min(int((mal / max(total, 1)) * 60), 60)
                score += vt_score
                components["virustotal"] = vt_score
            if mal > 15: score += 10; components["vt_high_detection"] = 10
            elif mal > 5: score += 5; components["vt_medium_detection"] = 5

        # AbuseIPDB
        abuse = provider_results.get("abuseipdb", {})
        if abuse.get("found") and "error" not in abuse:
            abuse_score = abuse.get("abuse_confidence_score", 0)
            if abuse_score > 80: add = 30
            elif abuse_score > 50: add = 20
            elif abuse_score > 0: add = 10
            else: add = 0
            score += add
            components["abuseipdb"] = add

        # DNSBL
        dnsbl = provider_results.get("dnsbl", {})
        if dnsbl.get("found"):
            hits = len(dnsbl.get("hits", []))
            dnsbl_score = min(hits * 10, 20)
            score += dnsbl_score
            components["dnsbl"] = dnsbl_score

        # OTX
        otx = provider_results.get("alienvault_otx", {})
        if otx.get("found") and "error" not in otx:
            pulses = otx.get("pulse_count", 0)
            if pulses > 5: otx_score = 15
            elif pulses > 2: otx_score = 10
            elif pulses > 0: otx_score = 5
            else: otx_score = 0
            score += otx_score
            components["otx"] = otx_score

        # GreyNoise malicious
        gn = provider_results.get("greynoise", {})
        if gn.get("found") and gn.get("classification") == "malicious":
            score += 15
            components["greynoise_malicious"] = 15

        # MalwareBazaar
        mb = provider_results.get("malwarebazaar", {})
        if mb.get("found") and "error" not in mb:
            score += 40
            components["malwarebazaar"] = 40

        # URLhaus
        uh = provider_results.get("urlhaus", {})
        if uh.get("found") and "error" not in uh:
            score += 25
            components["urlhaus"] = 25

        score = min(int(score), 100)

        if score >= 81: label = "critical"
        elif score >= 51: label = "malicious"
        elif score >= 21: label = "suspicious"
        else: label = "clean"

        return {"score": score, "label": label, "components": components}

# ---------------------------------------------------------------------------
# MITRE ATT&CK mappings
# ---------------------------------------------------------------------------
MITRE_MAP = {
    "ip": [
        {"id": "T1071", "technique": "Application Layer Protocol", "tactic": "Command and Control"},
        {"id": "T1090", "technique": "Proxy", "tactic": "Command and Control"},
        {"id": "T1041", "technique": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
        {"id": "T1219", "technique": "Remote Access Software", "tactic": "Command and Control"},
    ],
    "hash": [
        {"id": "T1204", "technique": "User Execution", "tactic": "Execution"},
        {"id": "T1036", "technique": "Masquerading", "tactic": "Defense Evasion"},
        {"id": "T1547", "technique": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
        {"id": "T1027", "technique": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    ],
    "domain": [
        {"id": "T1071.001", "technique": "Web Protocols", "tactic": "Command and Control"},
        {"id": "T1071", "technique": "Application Layer Protocol", "tactic": "Command and Control"},
        {"id": "T1568", "technique": "Domain Generation Algorithms", "tactic": "Resource Development"},
    ],
    "url": [
        {"id": "T1566", "technique": "Phishing", "tactic": "Initial Access"},
        {"id": "T1071.001", "technique": "Web Protocols", "tactic": "Command and Control"},
    ],
}

def generate_mitre(ioc_type: str, provider_results: dict) -> list:
    base = MITRE_MAP.get(ioc_type, [])
    extra = []
    vt = provider_results.get("virustotal", {})
    tags = vt.get("tags", []) if "error" not in vt else []
    if "ransomware" in tags:
        extra.append({"id": "T1486", "technique": "Data Encrypted for Impact", "tactic": "Impact"})
    if "trojan" in tags:
        extra.append({"id": "T1027", "technique": "Obfuscated Files or Information", "tactic": "Defense Evasion"})
    if "downloader" in tags:
        extra.append({"id": "T1105", "technique": "Ingress Tool Transfer", "tactic": "Command and Control"})
    if "botnet" in tags or "c2" in tags:
        extra.append({"id": "T1571", "technique": "Non-Application Layer Protocol", "tactic": "Command and Control"})
    if any(p.get("found") for p in provider_results.values() if isinstance(p, dict) and p.get("found")):
        if ioc_type == "hash":
            extra.append({"id": "T1003", "technique": "OS Credential Dumping", "tactic": "Credential Access"})
    seen = set()
    result = []
    for m in base + extra:
        key = m["id"]
        if key not in seen:
            seen.add(key)
            result.append(m)
    return result

# ---------------------------------------------------------------------------
# Dynamic threat-intelligence-driven explanation generators
# No static IOC-type templates. All content is derived from provider data.
# ---------------------------------------------------------------------------

# Full MITRE ATT&CK reference for dynamic lookup
MITRE_REFERENCE = {
    "T1003": {"id": "T1003", "technique": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1021": {"id": "T1021", "technique": "Remote Services", "tactic": "Lateral Movement"},
    "T1027": {"id": "T1027", "technique": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1036": {"id": "T1036", "technique": "Masquerading", "tactic": "Defense Evasion"},
    "T1041": {"id": "T1041", "technique": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1055": {"id": "T1055", "technique": "Process Injection", "tactic": "Defense Evasion"},
    "T1071": {"id": "T1071", "technique": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1071.001": {"id": "T1071.001", "technique": "Web Protocols", "tactic": "Command and Control"},
    "T1090": {"id": "T1090", "technique": "Proxy", "tactic": "Command and Control"},
    "T1105": {"id": "T1105", "technique": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1110": {"id": "T1110", "technique": "Brute Force", "tactic": "Credential Access"},
    "T1190": {"id": "T1190", "technique": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1204": {"id": "T1204", "technique": "User Execution", "tactic": "Execution"},
    "T1219": {"id": "T1219", "technique": "Remote Access Software", "tactic": "Command and Control"},
    "T1486": {"id": "T1486", "technique": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1547": {"id": "T1547", "technique": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    "T1548": {"id": "T1548", "technique": "Abuse Elevation Control Mechanism", "tactic": "Defense Evasion"},
    "T1566": {"id": "T1566", "technique": "Phishing", "tactic": "Initial Access"},
    "T1568": {"id": "T1568", "technique": "Domain Generation Algorithms", "tactic": "Resource Development"},
    "T1571": {"id": "T1571", "technique": "Non-Application Layer Protocol", "tactic": "Command and Control"},
    "T1574": {"id": "T1574", "technique": "Hijack Execution Flow", "tactic": "Persistence"},
}

# Keyword → MITRE technique ID mapping (fed by tags, OTX pulses, etc.)
TAG_TO_MITRE = {
    "ransomware": ["T1486"],
    "trojan": ["T1027", "T1204"],
    "downloader": ["T1105", "T1204"],
    "worm": ["T1021", "T1041"],
    "backdoor": ["T1219", "T1071"],
    "botnet": ["T1071", "T1571"],
    "c2": ["T1071", "T1571"],
    "keylogger": ["T1003", "T1055"],
    "spyware": ["T1003", "T1055"],
    "miner": ["T1496"],
    "dropper": ["T1204", "T1105"],
    "phishing": ["T1566"],
    "exploit": ["T1190"],
    "proxy": ["T1090"],
    "ddos": ["T1498"],
    "stealer": ["T1003", "T1041"],
    "loader": ["T1105"],
    "rat": ["T1219", "T1071"],
    "mimikatz": ["T1003"],
    "brute-force": ["T1110"],
    "scanner": ["T1046"],
    "coinminer": ["T1496"],
    "injector": ["T1055"],
    "bypass": ["T1548"],
    "persistence": ["T1547"],
    "lateral": ["T1021"],
}

OTX_PULSE_KEYWORDS = {
    "ransom": ["T1486"],
    "banking": ["T1003"],
    "apt": ["T1071", "T1105"],
    "phish": ["T1566"],
    "ddos": ["T1498"],
    "infosteal": ["T1003", "T1041"],
    "loader": ["T1105"],
    "botnet": ["T1071", "T1571"],
    "worm": ["T1021"],
}

def _collect_tags(provider_results: dict) -> list:
    """Aggregate all tags from all providers."""
    tags = []
    vt = provider_results.get("virustotal", {})
    if "error" not in vt:
        tags.extend(vt.get("tags", []))
    otx = provider_results.get("alienvault_otx", {})
    if "error" not in otx:
        tags.extend(otx.get("tags", []))
    mb = provider_results.get("malwarebazaar", {})
    if "error" not in mb:
        tags.extend(mb.get("tags", []))
    uh = provider_results.get("urlhaus", {})
    if "error" not in uh:
        for u in uh.get("urls", []):
            tags.extend(u.get("tags", []))
    return list(set(tags))

def _source_count(provider_results: dict) -> int:
    return sum(1 for p in provider_results.values() if isinstance(p, dict) and p.get("found") and "error" not in p)

# ---------------------------------------------------------------------------
# Why Is This Malicious? — fully dynamic per provider
# ---------------------------------------------------------------------------
def generate_why_malicious(provider_results: dict, ioc_type: str, rep_score: int) -> list:
    reasons = []
    vt = provider_results.get("virustotal", {})
    abuse = provider_results.get("abuseipdb", {})
    dnsbl = provider_results.get("dnsbl", {})
    otx = provider_results.get("alienvault_otx", {})
    gn = provider_results.get("greynoise", {})
    mb = provider_results.get("malwarebazaar", {})
    uh = provider_results.get("urlhaus", {})
    tags = _collect_tags(provider_results)

    # --- VirusTotal ---
    if "error" not in vt and vt.get("malicious", 0) > 0:
        mal, total = vt["malicious"], vt.get("total", 1)
        reasons.append(f"Flagged as malicious by {mal}/{total} antivirus engines on VirusTotal")
        if vt.get("popular_threat_classification", {}).get("suggested_threat_label"):
            label = vt["popular_threat_classification"]["suggested_threat_label"]
            reasons.append(f"VirusTotal classifies this as '{label}'")

    # --- AbuseIPDB (IP-specific: brute-force, web attack, etc.) ---
    if "error" not in abuse and abuse.get("abuse_confidence_score", 0) > 0:
        score = abuse["abuse_confidence_score"]
        reports = abuse.get("total_reports", 0)
        usage = abuse.get("usage_type", "")
        reasons.append(f"AbuseIPDB reports {reports} abuse incidents with {score}% confidence score")
        if usage:
            if "brute" in usage.lower():
                reasons.append("Reported for brute-force login attempts — credential attack infrastructure")
            elif "web" in usage.lower() or "hosting" in usage.lower():
                reasons.append("Hosting infrastructure reported for abuse — potential malware or phishing host")
            elif "scan" in usage.lower():
                reasons.append("Reported for port scanning or reconnaissance activity")
            elif "vpn" in usage.lower() or "proxy" in usage.lower():
                reasons.append("Anonymous VPN/proxy — commonly abused for C2 infrastructure")
            else:
                reasons.append(f"Usage type: {usage}")

    # --- DNSBL (spam / reputation) ---
    if dnsbl.get("found"):
        for hit in dnsbl.get("hits", []):
            cat = hit.get("category", "")
            list_name = hit.get("list", "")
            if "spam" in cat.lower():
                reasons.append(f"Listed on {list_name} as a spam source — reputation severely damaged")
            elif "tor" in cat.lower():
                reasons.append(f"Listed as a Tor exit node on {list_name} — anonymity network exit point")
            elif "exploit" in cat.lower() or "malware" in cat.lower():
                reasons.append(f"Listed on {list_name} — associated with exploit hosting or malware distribution")
            elif "dynamic" in cat.lower() or "residential" in cat.lower():
                reasons.append(f"Listed on {list_name} as dynamic/residential IP — typically abused for C2")
            else:
                reasons.append(f"Listed on {list_name}: {cat}")

    # --- AlienVault OTX (campaign intelligence) ---
    if "error" not in otx and otx.get("pulse_count", 0) > 0:
        pc = otx["pulse_count"]
        reasons.append(f"Appears in {pc} AlienVault OTX threat pulse{'s' if pc > 1 else ''}")
        for pulse in otx.get("pulses", [])[:3]:
            pname = pulse.get("name", "")
            ptags = pulse.get("tags", [])
            if pname:
                reasons.append(f"OTX pulse: '{pname}'" + (f" [tags: {', '.join(ptags[:5])}]" if ptags else ""))

    # --- GreyNoise (scanning behavior classification) ---
    if gn.get("found"):
        cls = gn.get("classification", "")
        if cls == "malicious":
            reasons.append("GreyNoise classifies this IP as malicious — actively conducting attacks")
        elif cls == "suspicious":
            reasons.append("GreyNoise classifies this IP as suspicious — exhibits ambiguous scanning")
        else:
            reasons.append("GreyNoise detects internet scanning activity — not targeted malware behavior")
        if gn.get("name"):
            reasons.append(f"GreyNoise identifies this as '{gn['name']}'")

    # --- MalwareBazaar (specific malware behavior) ---
    if "error" not in mb and mb.get("found"):
        family = mb.get("malware_family", "") or "unknown"
        ftype = mb.get("malware_type", "")
        reasons.append(f"Identified as '{family}' malware on MalwareBazaar" + (f" (type: {ftype})" if ftype else ""))
        if "ransom" in family.lower():
            reasons.append("Ransomware — encrypts victim files and demands payment for decryption")
        elif "steal" in family.lower() or "infosteal" in family.lower():
            reasons.append("Information stealer — harvests credentials, cookies, and sensitive data")
        elif "loader" in family.lower():
            reasons.append("Malware loader — downloads and executes additional payloads")
        elif "bot" in family.lower():
            reasons.append("Botnet agent — joins infected hosts to a command-and-control network")
        elif "rat" in family.lower() or "remote" in family.lower():
            reasons.append("Remote access trojan — provides unauthorized remote control of the host")
        elif "bank" in family.lower():
            reasons.append("Banking trojan — targets financial credentials and transactions")
        elif "mine" in family.lower() or "coin" in family.lower():
            reasons.append("Cryptominer — hijacks system resources for cryptocurrency mining")

    # --- URLhaus (malware hosting) ---
    if "error" not in uh and uh.get("found"):
        reasons.append(f"URLhaus reports {uh.get('url_count', 0)} malware-hosting URLs on this domain")
        for u in uh.get("urls", [])[:3]:
            threat = u.get("threat", "")
            if threat:
                reasons.append(f"URLhaus threat: {threat}")
        if uh.get("blacklist"):
            bl = uh.get("blacklist", {})
            listed_bls = [k for k, v in bl.items() if v == "yes"]
            if listed_bls:
                reasons.append(f"Blacklisted by: {', '.join(listed_bls)}")

    # --- Aggregated tag-based explanations ---
    threat_keywords = {
        "ransomware": "Ransomware behavior — file encryption for extortion",
        "trojan": "Trojan — malicious software disguised as legitimate",
        "botnet": "Botnet agent — part of a distributed command-and-control network",
        "c2": "Command-and-control beaconing — maintaining attacker access",
        "phishing": "Phishing infrastructure — used in credential harvesting campaigns",
        "exploit": "Exploit kit — delivers malware through browser/software vulnerabilities",
        "keylogger": "Keystroke logging — steals credentials and sensitive input",
        "backdoor": "Backdoor access — allows unauthorized remote control",
        "downloader": "Payload downloader — fetches additional malware stages",
        "spyware": "Spyware — monitors user activity and exfiltrates data",
        "ddos": "DDoS bot — used in distributed denial-of-service attacks",
        "miner": "Cryptocurrency miner — consumes CPU/GPU resources",
    }
    for tag in tags:
        lower_tag = tag.lower()
        if lower_tag in threat_keywords:
            reasons.append(threat_keywords[lower_tag])

    # --- Reputation score summary ---
    if rep_score >= 80:
        reasons.append("Critically high reputation score — active and verified threat infrastructure")
    elif rep_score >= 50:
        reasons.append("Elevated reputation score — consistent with malicious activity")

    if not reasons:
        reasons.append("Insufficient threat intelligence available to determine why this indicator is malicious")
    return list(dict.fromkeys(reasons))

# ---------------------------------------------------------------------------
# Impact Assessment — provider-driven, no static IOC-type fallback
# ---------------------------------------------------------------------------
def generate_impact(provider_results: dict, ioc_type: str) -> list:
    impacts = []
    tags = _collect_tags(provider_results)
    vt = provider_results.get("virustotal", {})
    abuse = provider_results.get("abuseipdb", {})
    otx = provider_results.get("alienvault_otx", {})
    mb = provider_results.get("malwarebazaar", {})
    gn = provider_results.get("greynoise", {})
    dnsbl = provider_results.get("dnsbl", {})

    tag_str = " ".join(tags).lower()

    # --- From VirusTotal tags ---
    tag_impact_map = {
        "credential_theft": ["keylogger", "cred", "password", "mimikatz", "stealer", "pwdump"],
        "cookie_theft": ["cookie", "browser"],
        "remote_access": ["backdoor", "trojan", "remote", "rat", "c2", "vnc", "rdp"],
        "data_exfiltration": ["exfiltrat", "upload", "data", "steal"],
        "lateral_movement": ["worm", "lateral", "spread", "psexec", "wmi"],
        "ransomware": ["ransomware", "locker", "encrypt", "crypt"],
        "system_compromise": ["rootkit", "bootkit", "dropper", "downloader", "loader", "inject"],
        "credential_access": ["brute", "password", "hash", "ntlm", "kerberos"],
    }
    for impact_key, keywords in tag_impact_map.items():
        if any(k in tag_str for k in keywords):
            impacts.append(impact_key.replace("_", " ").title())

    # --- From AbuseIPDB usage type ---
    if "error" not in abuse and abuse.get("abuse_confidence_score", 0) > 0:
        usage = (abuse.get("usage_type") or "").lower()
        if "brute" in usage:
            impacts.append("Credential Theft")
            impacts.append("Account Takeover")
        if "scan" in usage:
            impacts.append("Network Reconnaissance")
        if "web" in usage or "hosting" in usage:
            impacts.append("Malware Hosting")
        if "vpn" in usage or "proxy" in usage:
            impacts.append("Anonymized C2 Communication")

    # --- From DNSBL categories ---
    if dnsbl.get("found"):
        for hit in dnsbl.get("hits", []):
            cat = hit.get("category", "").lower()
            if "spam" in cat:
                impacts.append("Email Reputation Damage")
                impacts.append("Spam Campaigns")
            if "hijack" in cat:
                impacts.append("Infrastructure Hijacking")
            if "exploit" in cat or "malware" in cat:
                impacts.append("Malware Distribution")
            if "tor" in cat:
                impacts.append("Anonymized Network Access")

    # --- From GreyNoise ---
    if gn.get("found"):
        cls = gn.get("classification", "")
        if cls == "malicious":
            impacts.append("Active Targeted Attack")
        elif cls == "suspicious":
            impacts.append("Reconnaissance Activity")
        else:
            impacts.append("Internet Background Noise")

    # --- From MalwareBazaar family ---
    if "error" not in mb and mb.get("found"):
        family = (mb.get("malware_family") or "").lower()
        if "ransom" in family:
            impacts.append("File Encryption")
            impacts.append("Business Disruption")
        if "steal" in family or "infosteal" in family:
            impacts.append("Credential Theft")
            impacts.append("Data Exfiltration")
        if "bot" in family:
            impacts.append("DDoS Participation")
            impacts.append("C2 Network Membership")
        if "bank" in family:
            impacts.append("Financial Fraud")
            impacts.append("Credential Theft")
        if "mine" in family or "coin" in family:
            impacts.append("Resource Hijacking")
        if "loader" in family or "dropper" in family:
            impacts.append("Multi-stage Malware Deployment")

    # --- From OTX pulse names ---
    if "error" not in otx and otx.get("pulses"):
        pulse_names = " ".join(p.get("name", "") for p in otx["pulses"]).lower()
        if "ransom" in pulse_names:
            impacts.append("Ransomware Deployment")
        if "bank" in pulse_names or "finance" in pulse_names:
            impacts.append("Financial System Targeting")
        if "apt" in pulse_names:
            impacts.append("Advanced Persistent Threat Activity")
        if "phish" in pulse_names:
            impacts.append("Credential Harvesting")

    # --- From URLhaus ---
    uh = provider_results.get("urlhaus", {})
    if "error" not in uh and uh.get("found"):
        impacts.append("Malware Payload Delivery")
        for u in uh.get("urls", []):
            threat = (u.get("threat") or "").lower()
            if "ransom" in threat:
                impacts.append("Ransomware Distribution")
            if "bank" in threat:
                impacts.append("Financial Malware Distribution")

    # --- From VT malicious count ---
    if "error" not in vt and vt.get("malicious", 0) > 15:
        impacts.append("Widespread Industry Detection")

    if not impacts:
        impacts.append("Insufficient threat intelligence available to determine impact on victim")
    return list(dict.fromkeys(impacts))

# ---------------------------------------------------------------------------
# MITRE ATT&CK — dynamic selection from tags, OTX pulses, malware family, sources
# ---------------------------------------------------------------------------
def generate_mitre(ioc_type: str, provider_results: dict) -> list:
    tags = _collect_tags(provider_results)
    mb = provider_results.get("malwarebazaar", {})
    otx = provider_results.get("alienvault_otx", {})
    gn = provider_results.get("greynoise", {})
    abuse = provider_results.get("abuseipdb", {})
    dnsbl = provider_results.get("dnsbl", {})
    vt = provider_results.get("virustotal", {})

    selected_ids = set()

    # 1. From VT tags
    for tag in tags:
        lower_tag = tag.lower()
        if lower_tag in TAG_TO_MITRE:
            selected_ids.update(TAG_TO_MITRE[lower_tag])

    # 2. From OTX pulse names
    if "error" not in otx and otx.get("pulses"):
        pulse_names = " ".join(p.get("name", "") for p in otx["pulses"]).lower()
        for keyword, mitres in OTX_PULSE_KEYWORDS.items():
            if keyword in pulse_names:
                selected_ids.update(mitres)

    # 3. From MalwareBazaar family
    if "error" not in mb and mb.get("found"):
        family = (mb.get("malware_family") or "").lower()
        if any(w in family for w in ["ransom", "locker"]):
            selected_ids.add("T1486")
        if any(w in family for w in ["steal", "infosteal"]):
            selected_ids.update(["T1003", "T1041"])
        if any(w in family for w in ["bot", "andromeda", "emotet", "qbot"]):
            selected_ids.update(["T1071", "T1571"])
        if any(w in family for w in ["loader", "dridex", "bumblebee"]):
            selected_ids.update(["T1105", "T1204"])
        if any(w in family for w in ["rat", "agenttesla", "njrat", "nanocore"]):
            selected_ids.update(["T1219", "T1071"])
        if any(w in family for w in ["bank", "zeus", "zbot"]):
            selected_ids.update(["T1003", "T1071"])

    # 4. From GreyNoise classification
    if gn.get("found"):
        cls = gn.get("classification", "")
        if cls == "malicious":
            selected_ids.update(["T1071", "T1046"])
        else:
            selected_ids.add("T1046")

    # 5. From AbuseIPDB usage type
    if "error" not in abuse and abuse.get("abuse_confidence_score", 0) > 0:
        usage = (abuse.get("usage_type") or "").lower()
        if "brute" in usage:
            selected_ids.add("T1110")
        if "scan" in usage:
            selected_ids.add("T1046")
        if "web" in usage or "hosting" in usage:
            selected_ids.add("T1190")

    # 6. From DNSBL
    if dnsbl.get("found"):
        for hit in dnsbl.get("hits", []):
            cat = hit.get("category", "").lower()
            if "spam" in cat:
                selected_ids.add("T1071")
            if "tor" in cat:
                selected_ids.add("T1090")
            if "exploit" in cat:
                selected_ids.update(["T1190", "T1105"])

    # 7. From URLhaus
    uh = provider_results.get("urlhaus", {})
    if "error" not in uh and uh.get("found"):
        selected_ids.update(["T1071.001", "T1105"])

    # 8. From high VT detection
    if "error" not in vt and vt.get("malicious", 0) > 10:
        selected_ids.add("T1204")

    # Deduplicate with order preservation
    ordered = []
    for mid in ["T1071", "T1071.001", "T1105", "T1204", "T1003", "T1110", "T1046",
                 "T1486", "T1027", "T1036", "T1055", "T1090", "T1219", "T1190",
                 "T1566", "T1547", "T1571", "T1041", "T1021", "T1496", "T1498"]:
        if mid in selected_ids and mid in MITRE_REFERENCE:
            ordered.append(MITRE_REFERENCE[mid])

    if not ordered or _source_count(provider_results) == 0:
        return []
    return ordered

# ---------------------------------------------------------------------------
# Recommendations — IOC-type actions enriched by provider-specific data
# ---------------------------------------------------------------------------
def generate_recommendations(ioc_type: str, rep_score: int, severity: str, provider_results: dict = None) -> list:
    provider_results = provider_results or {}
    actions = {
        "ip": [
            "Block IP at firewall / edge gateway immediately",
            "Add to blocklist in SIEM / XDR policy",
            "Review firewall logs for outbound connections to this IP",
            "Isolate affected endpoints that communicated with this IP",
        ],
        "hash": [
            "Block file hash via application control / allowlist",
            "Delete quarantined file from all endpoints",
            "Run full host scan on affected systems",
            "Review process execution logs for this hash",
        ],
        "domain": [
            "Block domain via DNS sinkhole / content filtering",
            "Add domain to threat intelligence blocklist",
            "Review DNS logs for resolution requests",
            "Isolate hosts that queried this domain",
        ],
        "url": [
            "Block URL via web proxy / secure web gateway",
            "Add to URL filtering policy",
            "Review web access logs for visits to this URL",
        ],
    }
    result = list(actions.get(ioc_type, []))
    if severity in ("critical", "high") or rep_score >= 70:
        result.insert(0, "Escalate to CIRT/SOC Tier 3 for immediate investigation")
        result.insert(1, "Hunt for related IOCs across the entire environment via VT, OTX, and MISP")

    # Provider-specific recommendations
    # AbuseIPDB brute-force → reset creds
    abuse = provider_results.get("abuseipdb", {})
    if "error" not in abuse and abuse.get("abuse_confidence_score", 0) > 0:
        usage = (abuse.get("usage_type") or "").lower()
        if "brute" in usage:
            result.append("Reset all credentials for accounts associated with this host")

    # MalwareBazaar → host scan
    mb = provider_results.get("malwarebazaar", {})
    if "error" not in mb and mb.get("found"):
        family = (mb.get("malware_family") or "").lower()
        result.append("Perform memory and disk forensics on affected endpoints")
        if "ransom" in family:
            result.append("Check for encrypted files and initiate recovery from offline backups")
        if "steal" in family or "infosteal" in family:
            result.append("Rotate all secrets, tokens, and certificates on affected systems")
        if "bank" in family:
            result.append("Audit financial transactions for unauthorized activity")

    # DNSBL → check mail logs
    dnsbl = provider_results.get("dnsbl", {})
    if dnsbl.get("found"):
        if any("spam" in h.get("category", "").lower() for h in dnsbl.get("hits", [])):
            result.append("Review mail server logs for outbound spam campaigns")

    if not result:
        result.append("Insufficient intelligence for targeted recommendations — apply general blocking")
    return result

# ---------------------------------------------------------------------------
# Malware family extraction from all providers
# ---------------------------------------------------------------------------
def extract_malware_family(provider_results: dict) -> Optional[str]:
    # MalwareBazaar has the most reliable family info
    mb = provider_results.get("malwarebazaar", {})
    if mb.get("found") and mb.get("malware_family"):
        return mb["malware_family"]
    # VT popular threat classification
    vt = provider_results.get("virustotal", {})
    if "error" not in vt:
        ptc = vt.get("popular_threat_classification", {})
        if ptc:
            suggested = ptc.get("suggested_threat_label", "")
            if suggested: return suggested
            cats = ptc.get("popular_threat_category", [])
            if cats and isinstance(cats, list):
                if isinstance(cats[0], dict): return cats[0].get("value", "")
                return cats[0]
        tags = vt.get("tags", [])
        family_tags = [t for t in tags if not t.startswith("capr-") and not t.startswith("pt-") and t not in ("dynamic", "peexe", "elf", "macho", "pdf")]
        if family_tags: return family_tags[0]
    # OTX pulses
    otx = provider_results.get("alienvault_otx", {})
    if otx.get("found") and otx.get("pulses"):
        for p in otx["pulses"]:
            if p.get("name"): return p["name"]
    return None

# ---------------------------------------------------------------------------
# Geographic info aggregation
# ---------------------------------------------------------------------------
def extract_geo(provider_results: dict, ioc_type: str) -> dict:
    geo = {}
    vt = provider_results.get("virustotal", {})
    abuse = provider_results.get("abuseipdb", {})
    if "error" not in vt:
        if vt.get("country"): geo["country"] = vt["country"]
        if vt.get("asn"): geo["asn"] = vt["asn"]
        if vt.get("network"): geo["network"] = vt["network"]
    if "error" not in abuse:
        if abuse.get("country"): geo["country"] = geo.get("country") or abuse["country"]
        if abuse.get("isp"): geo["isp"] = abuse["isp"]
        if abuse.get("usage_type"): geo["usage_type"] = abuse["usage_type"]
    otx = provider_results.get("alienvault_otx", {})
    if "error" not in otx and otx.get("country"):
        geo["country"] = geo.get("country") or otx["country"]
    return geo

# ---------------------------------------------------------------------------
# ThreatIntelService - aggregator
# ---------------------------------------------------------------------------
class ThreatIntelService:
    def __init__(self):
        self.providers = {
            "dnsbl": DNSBLProvider(),
            "virustotal": VirusTotalProvider(),
            "abuseipdb": AbuseIPDBProvider(),
            "alienvault_otx": OTXProvider(),
            "greynoise": GreyNoiseProvider(),
            "malwarebazaar": MalwareBazaarProvider(),
            "urlhaus": URLHausProvider(),
        }
        self.scoring_engine = ReputationScoringEngine()

    def lookup(self, indicator: str) -> dict:
        ioc_type = detect_ioc_type(indicator)
        if ioc_type == "unknown":
            return {"error": "Could not detect indicator type", "value": indicator, "indicator_type": "unknown"}

        # Check cache
        cached = _get_cached_lookup(indicator)
        if cached is not None:
            return cached

        t_total = _time.time()
        results = {}

        def _lookup_provider(name, provider):
            try:
                return name, provider.lookup(indicator, ioc_type)
            except Exception as e:
                return name, {"provider": name, "found": False, "error": str(e)}

        with concurrent.futures.ThreadPoolExecutor(max_workers=7) as pool:
            futs = {pool.submit(_lookup_provider, name, p): name for name, p in self.providers.items()}
            for fut in concurrent.futures.as_completed(futs, timeout=30):
                name = futs[fut]
                try:
                    results[name] = fut.result()
                except Exception as e:
                    results[name] = {"provider": name, "found": False, "error": str(e)}

        # Scoring
        rep = self.scoring_engine.score(results, ioc_type)

        # Enrichments
        malware_family = extract_malware_family(results)
        why_malicious = generate_why_malicious(results, ioc_type, rep["score"])
        impact = generate_impact(results, ioc_type)
        mitre = generate_mitre(ioc_type, results)
        recommendations = generate_recommendations(ioc_type, rep["score"], rep["label"])
        geo = extract_geo(results, ioc_type)

        elapsed = _time.time() - t_total

        # Source tracking
        found_sources = [name for name, r in results.items() if isinstance(r, dict) and r.get("found") and "error" not in r]
        primary_source = found_sources[0] if found_sources else ""
        found = len(found_sources) > 0

        result = {
            "indicator": indicator,
            "type": ioc_type,
            "found": found,
            "primary_source": primary_source,
            "reputation": rep["label"],
            "reputation_score": rep["score"],
            "reputation_components": rep["components"],
            "confidence": rep["label"],
            "country": geo.get("country", ""),
            "organization": geo.get("isp") or geo.get("organization", ""),
            "asn": geo.get("asn", 0),
            "network": geo.get("network", ""),
            "usage_type": geo.get("usage_type", ""),
            "threat_type": malware_family or "",
            "malware_family": malware_family,
            "why_malicious": why_malicious,
            "impact": impact,
            "recommendations": recommendations,
            "mitre": mitre,
            "providers": results,
            "geo": geo,
        }

        _set_cached_lookup(indicator, result)
        print(f"[ThreatIntelService] lookup {indicator} ({ioc_type}) in {elapsed:.2f}s "
              f"found={found} score={rep['score']} sources={len(found_sources)}")
        return result
