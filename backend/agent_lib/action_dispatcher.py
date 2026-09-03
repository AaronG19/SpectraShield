"""
Agent action dispatcher.
Executes response actions received from the backend:
- process_terminate: terminates a process by PID
- network_block: blocks a target IP
- host_isolate: isolates the host (simulated/safe rule)
- quarantine_file: moves file to quarantine
- dns_block: blocks a domain
"""
import os
import sys
import psutil
import platform
import subprocess
from agent_lib.logger import log

_CALLBACKS = {}

def register_callback(name: str, func):
    _CALLBACKS[name] = func

def execute_action(action: str, target: str) -> dict:
    log.info(f"Executing action from backend | action={action} target={target}")
    
    try:
        if action == "process_terminate":
            return _process_terminate(target)
        elif action == "network_block":
            return _network_block(target)
        elif action == "host_isolate":
            return _host_isolate()
        elif action == "host_unisolate":
            return _host_unisolate()
        elif action == "quarantine_file":
            return _quarantine_file(target)
        elif action == "dns_block":
            return _dns_block(target)
        elif action == "run_scan":
            if "run_scan" in _CALLBACKS:
                return _CALLBACKS["run_scan"](target)
            else:
                return {"status": "failed", "message": "Scan handler not registered"}
        else:
            return {"status": "failed", "message": f"Unknown action: {action}"}
    except Exception as e:
        log.error(f"Action execution error | action={action}", error=str(e))
        return {"status": "failed", "message": str(e)}

def _process_terminate(target: str) -> dict:
    try:
        pid = int(target)
    except ValueError:
        return {"status": "failed", "message": f"Invalid PID target: {target}"}
        
    try:
        p = psutil.Process(pid)
        p.terminate()
        p.wait(timeout=3)
        return {"status": "success", "message": f"Process {pid} terminated"}
    except psutil.NoSuchProcess:
        return {"status": "success", "message": f"Process {pid} already terminated or not found"}
    except psutil.AccessDenied:
        try:
            p.kill()
            return {"status": "success", "message": f"Process {pid} killed forcefully"}
        except Exception as e:
            return {"status": "failed", "message": f"Access denied: {str(e)}"}
    except Exception as e:
        return {"status": "failed", "message": str(e)}

def _network_block(target: str) -> dict:
    # Simulated block to prevent breaking actual backend network connection
    log.info(f"Simulating network block for IP/CIDR: {target}")
    return {"status": "success", "message": f"Network traffic to/from {target} blocked (simulated)"}

def _host_isolate() -> dict:
    os_type = platform.system().lower()
    log.info("Host isolation initiated")
    if os_type == "windows":
        try:
            # We add outbound rules to block HTTP (80), HTTPS (443), SSH (22), and RDP (3389)
            # This isolates the host from internet browsing and network logons, while leaving 8080 (EDR Backend) open.
            cmds = [
                'netsh advfirewall firewall add rule name="EDR_Quarantine_HTTP" dir=out action=block protocol=TCP remoteport=80',
                'netsh advfirewall firewall add rule name="EDR_Quarantine_HTTPS" dir=out action=block protocol=TCP remoteport=443',
                'netsh advfirewall firewall add rule name="EDR_Quarantine_SSH" dir=out action=block protocol=TCP remoteport=22',
                'netsh advfirewall firewall add rule name="EDR_Quarantine_RDP" dir=out action=block protocol=TCP remoteport=3389'
            ]
            for cmd in cmds:
                subprocess.run(cmd, shell=True, capture_output=True, check=True)
            log.warn("Host successfully quarantined via Windows Firewall rules")
            return {"status": "success", "message": "Host quarantined via Windows Firewall (ports 80, 443, 22, 3389 blocked)"}
        except subprocess.CalledProcessError as e:
            # Check if running as Admin
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0 if hasattr(ctypes, 'windll') else False
            if not is_admin:
                log.error("Host quarantine failed: Agent requires administrator privileges to write firewall rules.")
                return {"status": "failed", "message": "Isolation failed: Agent must be running as Administrator to write firewall rules."}
            return {"status": "failed", "message": f"Firewall command failed: {e.stderr.decode().strip()}"}
        except Exception as e:
            return {"status": "failed", "message": str(e)}
    else:
        # Simulated block on Linux/macOS
        log.info("Simulating host isolation (non-Windows system)")
        return {"status": "success", "message": "Host quarantined (simulated)"}

def _host_unisolate() -> dict:
    os_type = platform.system().lower()
    log.info("Host un-isolation initiated")
    if os_type == "windows":
        try:
            # Delete our quarantine firewall rules
            cmds = [
                'netsh advfirewall firewall delete rule name="EDR_Quarantine_HTTP"',
                'netsh advfirewall firewall delete rule name="EDR_Quarantine_HTTPS"',
                'netsh advfirewall firewall delete rule name="EDR_Quarantine_SSH"',
                'netsh advfirewall firewall delete rule name="EDR_Quarantine_RDP"'
            ]
            for cmd in cmds:
                # We don't check=True on delete in case a rule was already deleted
                subprocess.run(cmd, shell=True, capture_output=True)
            log.info("Host quarantine lifted")
            return {"status": "success", "message": "Host quarantine lifted (firewall rules deleted)"}
        except Exception as e:
            return {"status": "failed", "message": str(e)}
    else:
        log.info("Simulating quarantine lift (non-Windows system)")
        return {"status": "success", "message": "Host quarantine lifted (simulated)"}

def _quarantine_file(target: str) -> dict:
    if not target or not os.path.exists(target):
        return {"status": "failed", "message": f"File not found: {target}"}
    try:
        quarantine_dir = os.path.abspath("quarantine")
        if not os.path.exists(quarantine_dir):
            os.makedirs(quarantine_dir)
        filename = os.path.basename(target)
        dest = os.path.join(quarantine_dir, f"{filename}.quarantine")
        os.rename(target, dest)
        return {"status": "success", "message": f"File quarantined to {dest}"}
    except Exception as e:
        return {"status": "failed", "message": str(e)}

def _dns_block(target: str) -> dict:
    # Simulated DNS block
    log.info(f"Simulating DNS block for domain: {target}")
    return {"status": "success", "message": f"DNS resolution for {target} blocked (simulated)"}
