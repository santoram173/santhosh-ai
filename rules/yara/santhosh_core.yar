/*
 * Santhosh AI — Example YARA Rule Pack
 * Category: Malware & Threat Detection
 * Version: 1.0.0
 * Author: Santhosh AI Security Team
 */

rule SanthoshAI_Webshell_Generic {
    meta:
        id          = "YARA-001"
        description = "Detects common PHP/ASP web shell patterns"
        severity    = "CRITICAL"
        category    = "Webshell"
        author      = "Santhosh AI"
        version     = "1.0"
    strings:
        $php_eval   = /eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/
        $php_system = /system\s*\(\s*\$_(POST|GET|REQUEST)/
        $asp_exec   = /Execute\s*\(Request\./
        $jsp_exec   = /Runtime\.getRuntime\(\)\.exec\(/
    condition:
        any of them
}

rule SanthoshAI_Cryptominer_Payload {
    meta:
        id          = "YARA-002"
        description = "Detects cryptominer process names and pool connections"
        severity    = "HIGH"
        category    = "Cryptominer"
        author      = "Santhosh AI"
    strings:
        $pool1  = "stratum+tcp://"
        $pool2  = "stratum+ssl://"
        $miner1 = "xmrig"    nocase
        $miner2 = "nicehash" nocase
        $miner3 = "minerd"   nocase
        $miner4 = "cpuminer" nocase
    condition:
        2 of them
}

rule SanthoshAI_DataExfil_Base64Curl {
    meta:
        id          = "YARA-003"
        description = "Detects base64-encoded data being sent via curl"
        severity    = "HIGH"
        category    = "DataExfiltration"
        author      = "Santhosh AI"
    strings:
        $b64_curl = /curl\s+.*-d\s+['"]?[A-Za-z0-9+\/]{40,}={0,2}['"]?/
        $base64_pipe = /base64\s*(-w\s*0\s*)?\|\s*curl/
    condition:
        any of them
}

rule SanthoshAI_PromptInjection_Classic {
    meta:
        id          = "YARA-004"
        description = "Detects common prompt injection patterns in text files"
        severity    = "HIGH"
        category    = "PromptInjection"
        author      = "Santhosh AI"
    strings:
        $ignore     = "ignore previous instructions" nocase
        $override   = "disregard all prior instructions" nocase
        $new_role   = "you are now a" nocase
        $sys_tag    = "<system>" nocase
        $inst_tag   = "[INST]"
        $forget     = "forget everything you know" nocase
    condition:
        any of them
}

rule SanthoshAI_Ransomware_FileOps {
    meta:
        id          = "YARA-005"
        description = "Detects ransomware-style bulk file encryption patterns"
        severity    = "CRITICAL"
        category    = "Ransomware"
        author      = "Santhosh AI"
    strings:
        $encrypt1 = /AES\.encrypt|Fernet\.encrypt|RSA\.encrypt/
        $walk     = /os\.walk|glob\.glob/
        $rename   = /os\.rename.*\.(enc|locked|crypto|ransom)/
        $readme   = "README_DECRYPT"
        $ransom   = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
    condition:
        ($walk and $encrypt1) or $readme or $ransom
}

rule SanthoshAI_SupplyChain_PostInstall {
    meta:
        id          = "YARA-006"
        description = "Detects malicious postInstall scripts in npm packages"
        severity    = "CRITICAL"
        category    = "SupplyChain"
        author      = "Santhosh AI"
    strings:
        $postinstall    = "\"postinstall\""
        $curl_sh        = /curl\s+http.*\|\s*(bash|sh)/
        $wget_sh        = /wget\s+.*-O\s*-\s*\|\s*(bash|sh)/
        $env_steal      = /process\.env.*\.(key|secret|token|password)/i
        $http_post_env  = /require\(['"]https?['"]\)\.request.*process\.env/
    condition:
        $postinstall and (1 of ($curl_sh, $wget_sh, $env_steal, $http_post_env))
}
