/*
    Sample starter ruleset for Agent Security's YARA integration.
    Drop real rules (e.g. from a maintained feed) into yara_rules/*.yar
    or *.yara — every file in this directory is auto-loaded on startup.

    meta.severity supported values: low | medium | high | critical
*/

rule Suspicious_Base64_PowerShell_Download
{
    meta:
        description = "PowerShell command with base64-encoded download/execute pattern"
        severity = "high"
        author = "agent-security"
    strings:
        $a = "FromBase64String" nocase
        $b = "DownloadString" nocase
        $c = "IEX(" nocase
        $d = "-EncodedCommand" nocase
    condition:
        2 of ($a, $b, $c, $d)
}

rule Generic_UPX_Packed_Executable
{
    meta:
        description = "UPX-packed PE — common malware packing technique, flag for review"
        severity = "low"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $mz = { 4D 5A }
    condition:
        $mz at 0 and $upx0 and $upx1
}

rule Known_Mimikatz_Strings
{
    meta:
        description = "Strings commonly found in Mimikatz builds"
        severity = "critical"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "mimikatz(powershell)" nocase
        $s3 = "gentilkiwi" nocase
    condition:
        any of them
}

rule EICAR_Anti_Malware_Test_File
{
    meta:
        description = "Standard EICAR Anti-Malware Test File"
        severity = "critical"
        author = "EICAR"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_Webshell_PHP
{
    meta:
        description = "Detects common PHP webshell functions and inputs"
        severity = "high"
    strings:
        $p1 = "eval($_POST[" nocase
        $p2 = "system($_GET[" nocase
        $p3 = "shell_exec(" nocase
        $p4 = "passthru(" nocase
    condition:
        any of them
}

rule Cobalt_Strike_Beacon_Strings
{
    meta:
        description = "Detects common strings associated with Cobalt Strike Beacons"
        severity = "critical"
        reference = "https://www.cobaltstrike.com/"
    strings:
        $s1 = "ReflectiveLoader"
        $s2 = "%s as %s" // standard named pipe format
        $s3 = "msagent_" // default Cobalt Strike pipe prefix
        $s4 = "Keep-Alive, User-Agent: Mozilla/5.0 (compat" nocase
    condition:
        2 of them
}

rule WannaCry_Ransomware_Strings
{
    meta:
        description = "Detects strings associated with WannaCry ransomware"
        severity = "critical"
    strings:
        $w1 = "WanaCrypt0r" nocase
        $w2 = "tasksche.exe" nocase
        $w3 = "00000000.eky"
        $w4 = "00000000.res"
        $w5 = "wnry" nocase
        $btc = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" // WannaCry hardcoded bitcoin address
    condition:
        any of ($w1, $btc) or 3 of ($w2, $w3, $w4, $w5)
}

rule Log4j_JNDI_Exploit_Pattern
{
    meta:
        description = "Detects JNDI injection payloads used in Log4j CVE-2021-44228 attacks"
        severity = "high"
    strings:
        $jndi1 = "${jndi:ldap://" nocase
        $jndi2 = "${jndi:rmi://" nocase
        $jndi3 = "${jndi:dns://" nocase
        $jndi4 = "${jndi:nis://" nocase
        $jndi5 = "${jndi:nds://" nocase
        $jndi6 = "${jndi:corba://" nocase
    condition:
        any of them
}

