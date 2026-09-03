"""Targeted cleanup of the current main.py file.

Fixes:
1. Split bad merges where multiple statements got concatenated
2. Indent function-body statements that are at column 0
"""
import re

with open("main.py", "r") as f:
    content = f.read()

# Fix 1: Split bad merges of separate statements
# Pattern: number followed immediately by a Python keyword/identifier at column 0
# e.g., "* 15score -= " -> "* 15\nscore -= "
# The bad merges happened when lines that should be separate got concatenated

# Split merges of: `statement1statement2` where statement1 ends with a digit and statement2 starts with a letter
# Examples from the current state:
# "* 15score -= open_alerts * 1.5score -= critical_alerts * 3.0"
# "* 5score -= unapproved * 1.0score -= suspicious_connections * 2.0"

# More general: split on patterns like <number><word_start> where word_start is a keyword-like word
fixes = [
    # Split merged score statements (most common pattern)
    (r'(\d)(score\s*[-+*/]?=)', r'\1\n    \2'),
    # Split on `return ` after other code
    (r'(\S)(return\s)', r'\1\n    \2'),
    # Split on `if ` after other code 
    (r'(\S)(if\s)', r'\1\n    \2'),
    # Split on `for ` after other code
    (r'(\S)(for\s)', r'\1\n    \2'),
    # Split on `while ` after other code
    (r'(\S)(while\s)', r'\1\n    \2'),
    # Split on `with ` after other code
    (r'(\S)(with\s)', r'\1\n    \2'),
    # Split on `try:` after other code
    (r'(\S)(try:)', r'\1\n    \2'),
    # Split on `else:` after other code
    (r'(\S)(else:)', r'\1\n    \2'),
    # Split on `elif ` after other code
    (r'(\S)(elif\s)', r'\1\n    \2'),
    # Split on `class ` after other code
    (r'(\S)(class\s)', r'\1\n\2'),
    # Split on `def ` after other code  
    (r'(\S)(def\s)', r'\1\n\2'),
    # Split on `from ` after other code
    (r'(\S)(from\s)', r'\1\n\2'),
    # Split on `import ` after other code
    (r'(\S)(import\s)', r'\1\n\2'),
    # Split on `async def ` after other code
    (r'(\S)(async\s+def\s)', r'\1\n\2'),
    # Split on `@` decorator after other code
    (r'(\S)(@\w)', r'\1\n\2'),
    # Split on `#` comment after other code
    (r'(\S)(#)', r'\1\n\2'),
]

for pattern, replacement in fixes:
    content = re.sub(pattern, replacement, content)

# Fix 2: Properly indent function-body statements that are at column 0
# Strategy: if a line at column 0 is NOT a top-level statement and is NOT a
# continuation of the previous line, it should be indented by 4 spaces.

lines = content.split('\n')
result = []
i = 0
while i < len(lines):
    line = lines[i]
    prev = result[-1] if result else ""
    prev_stripped = prev.rstrip()
    
    # Check if this line at column 0 should be indented
    if line and not line.startswith(' ') and not line.startswith('\t'):
        stripped = line.strip()
        
        # These are top-level - don't touch
        if (stripped.startswith(('def ', 'class ', 'import ', 'from ', '@', '#', '"""', "'''")) or
            not stripped or
            stripped.startswith(('if __name__', 'app = ', 'engine = ', 'SessionLocal = ', 'Base = ', 
                                  'MITRE_', 'ALERT_', 'ACTIONS_BY_', 'SPAMHAUS_', 'JWT_',
                                  'oauth2_scheme ', 'ws_', 'threat_intel_', 'platform_',
                                  'behavioral_', 'risk_', 'correlation_', 'response_',
                                  'iforest_', 'svm_', 'behavioral_')) or
            stripped.startswith(('config', 'oauth2_scheme', 'get_db', 'hash_password', 'verify_password',
                                  'create_access_token', 'decode_access_token', 'get_current_user',
                                  'get_optional_user', 'get_owned_agent', 'verify_agent_self',
                                  'calculate_security_score', 'ConnectionManager', 'get_mitre_',
                                  'generate_mac', 'generate_memory_scan', 'generate_misconfig',
                                  'generate_vulnerability', 'generate_file_integrity',
                                  'generate_behavioral', 'generate_patch', 'generate_software',
                                  'generate_asset_discovery', 'generate_watchdog',
                                  'generate_monitoring_stats', 'generate_execution_prevention',
                                  'generate_zero_day', 'generate_registry_monitoring',
                                  'generate_fileless', 'generate_memory_scan',
                                  'generate_usb_disk', 'generate_c2', 'generate_threat_intel',
                                  'generate_offline', 'generate_vuln', 'generate_process_tree',
                                  'generate_shadow_it', 'generate_exploit_mitigation',
                                  'generate_installation', 'generate_network_dpi',
                                  'generate_privilege_escalation', 'generate_silent_deployment',
                                  'generate_lateral_movement', 'generate_port_scan',
                                  'generate_host_firewall', 'generate_web_dns_filter',
                                  'generate_script_monitor', 'generate_ransomware_canary',
                                  'generate_credential_dumping', 'generate_next_gen_av',
                                  'generate_user_behaviour'))):
            result.append(line)
            i += 1
            continue
        
        # Check if previous line needs continuation (ends with =, ,, (, etc.)
        prev_needs_continuation = bool(re.search(r'[=,\(\[\{:\+\-\*\/\%\|&\^]\s*$', prev_stripped))
        prev_ends_operator = bool(re.search(r'(==|!=|<=|>=|or\b|and\b|not\b|is\b|\bis\b|\bnot\b)\s*$', prev_stripped))
        
        if prev_needs_continuation or prev_ends_operator:
            # Merge with previous line
            result[-1] = prev + ' ' + line
        else:
            # This is a function-body statement at column 0 - indent it
            result.append('    ' + line)
    else:
        result.append(line)
    
    i += 1

content = '\n'.join(result)

# Fix 3: More specific fixes for remaining merged statements
# Look for lines where statements are still merged without proper separation
additional_fixes = [
    # Split remaining merged score/return/etc patterns
    (r'(\d)(return\s)', r'\1\n    \2'),
    (r'(\d)(if\s)', r'\1\n    \2'),
    (r'(\})(if\s)', r'\1\n    \2'),
    (r'(\})(return\s)', r'\1\n    \2'),
    (r'(\})(for\s)', r'\1\n    \2'),
    (r'(\)else\b)', r')\nelse'),
    (r'(\}else\b)', r'}\nelse'),
]

for pattern, replacement in additional_fixes:
    content = re.sub(pattern, replacement, content)

with open("main.py", "w") as f:
    f.write(content)

print(f"Cleanup complete: {len(lines)} -> {len(result)} lines")
