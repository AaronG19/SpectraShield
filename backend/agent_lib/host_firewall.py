import os
import platform
import subprocess
from agent_lib.logger import log


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return "", str(e), -1


def _check_windows_firewall():
    events = []
    profiles = ["Domain", "Private", "Public"]
    for profile in profiles:
        out, _, _ = _run(["netsh", "advfirewall", "show", f"{profile}profile"])
        enabled = "State                                 ON" in out
        log.debug("Windows firewall profile", profile=profile, enabled=enabled)

    out, _, _ = _run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all", "verbose"])
    if out:
        rules = []
        current_rule = {}
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Rule Name:"):
                if current_rule:
                    rules.append(current_rule)
                current_rule = {"name": line.split(":", 1)[1].strip()}
            elif ":" in line and current_rule is not None:
                k, v = line.split(":", 1)
                k = k.strip().lower().replace(" ", "_")
                current_rule[k] = v.strip()

        if current_rule:
            rules.append(current_rule)

        block_rules = [r for r in rules if r.get("action", "").upper() == "BLOCK"]
        for r in block_rules:
            remote_ip = r.get("remoteip", "")
            if remote_ip:
                events.append({
                    "chain": r.get("rule_name", ""),
                    "rule": r.get("name", ""),
                    "ip_blocked": remote_ip,
                    "action": "block",
                })

    log.info("Windows firewall checked", block_rules=len(events))
    return events


def _check_linux_firewall():
    events = []
    import subprocess
    has_iptables = False
    try:
        subprocess.run(["iptables", "--version"], capture_output=True, timeout=5)
        has_iptables = True
    except Exception:
        pass

    if has_iptables:
        out, _, _ = _run(["iptables", "-L", "INPUT", "-n", "--line-numbers"])
        if out:
            for line in out.splitlines():
                if "DROP" in line or "REJECT" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[3] if "DROP" in parts else parts[3]
                        events.append({
                            "chain": "INPUT",
                            "rule": line.strip(),
                            "ip_blocked": parts[3] if len(parts) > 3 else "",
                            "action": "block",
                        })
        out, _, _ = _run(["iptables", "-L", "OUTPUT", "-n", "--line-numbers"])
        if out:
            for line in out.splitlines():
                if "DROP" in line or "REJECT" in line:
                    parts = line.split()
                    events.append({
                        "chain": "OUTPUT",
                        "rule": line.strip(),
                        "ip_blocked": parts[3] if len(parts) > 3 else "",
                        "action": "block",
                    })

    log.info("Linux firewall checked", iptables_block_rules=len(events))
    return events


def _check_macos_firewall():
    events = []
    # Check socketfilterfw status
    out, _, _ = _run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    enabled = "Enabled" in out
    log.info("macOS Application Firewall checked", enabled=enabled)
    
    # Check pfctl (packet filter) status
    out_pf, _, _ = _run(["pfctl", "-s", "info"])
    pf_enabled = "Status: Enabled" in out_pf or "pf is enabled" in out_pf.lower()
    log.info("macOS PF Firewall checked", enabled=pf_enabled)
    
    if not enabled and not pf_enabled:
        events.append({
            "chain": "GLOBAL",
            "rule": "Application & PF firewalls disabled",
            "ip_blocked": "",
            "action": "warning",
        })
    return events


def check_firewall():
    os_name = platform.system().lower()
    if os_name == "windows":
        return _check_windows_firewall()
    elif os_name == "darwin":
        return _check_macos_firewall()
    else:
        return _check_linux_firewall()
