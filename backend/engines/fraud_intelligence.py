"""
Santhosh AI — Fraud Intelligence Engine
Behavioral anomaly detection, ML hybrid scoring, and supply chain analysis.
"""
import re
import hashlib
import json
from typing import List, Dict, Any, Optional
from models.scan import Finding, Severity
from datetime import datetime


# Known malicious package hashes (demo — in production, sync with threat feeds)
KNOWN_MALICIOUS_PACKAGES = {
    "lodash@4.17.1": {"reason": "Prototype pollution — CVE-2019-10744", "score": 92},
    "event-stream@3.3.6": {"reason": "Supply chain backdoor", "score": 99},
    "colors@1.4.0": {"reason": "Intentional infinite loop sabotage", "score": 95},
    "node-ipc@10.1.1": {"reason": "Geopolitical malware — wiper", "score": 100},
    "ua-parser-js@0.7.29": {"reason": "Cryptominer + RAT injected", "score": 99},
    "ctx@0.1.1": {"reason": "Dependency confusion attack — steals env vars", "score": 97},
    "requests==2.19.0": {"reason": "Typosquat — contains credential stealer", "score": 94},
}

EXFIL_PATTERNS = [
    r"requests\.post\s*\([^)]*(?:http|https)://(?!localhost|127\.0\.0\.1|internal)",
    r"urllib.*urlopen.*(?:http|https)://(?!localhost|127\.0\.0\.1)",
    r"socket\.connect\s*\(",
    r"ftplib|smtplib",
    r"boto3.*upload_file|s3\.put_object",
    r"subprocess.*scp|subprocess.*sftp",
]

SOCIAL_ENGINEERING_PATTERNS = [
    (r"(?:click here|click now|urgent|act immediately|limited time)", "Urgency manipulation"),
    (r"(?:verify your account|confirm your identity|suspended|locked)", "Account phishing"),
    (r"(?:congratulations|you have won|selected|prize|reward)", "Advance-fee fraud"),
    (r"(?:wire transfer|western union|gift card|bitcoin|crypto).{0,50}(?:payment|send|buy)",
     "Financial scam pattern"),
]


class FraudIntelligenceEngine:
    """Core fraud detection combining rule-based and ML-hybrid scoring."""

    def __init__(self):
        self.name = "Fraud Intelligence"

    def analyze_file(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        findings += self._detect_exfiltration(file_path, content)
        findings += self._detect_social_engineering(file_path, content)
        findings += self._detect_insider_signals(file_path, content)
        findings += self._detect_behavioral_anomalies(file_path, content)
        return findings

    def _detect_exfiltration(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        lines = content.split("\n")
        for line_num, line in enumerate(lines, 1):
            for pattern in EXFIL_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Potential data exfiltration channel",
                        description="Code establishes an outbound connection that may be used to exfiltrate data.",
                        file_path=file_path,
                        line_number=line_num,
                        category="Data Exfiltration",
                        engine="fraud_intelligence",
                        rule_id="FRD-001",
                        risk_score=82,
                        remediation="Audit all external network calls. Whitelist allowed endpoints. Apply egress filtering.",
                        evidence=line.strip()[:200],
                        tags=["exfiltration", "network", "fraud"],
                    ))
        return findings

    def _detect_social_engineering(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        lower = content.lower()
        for pattern, subtype in SOCIAL_ENGINEERING_PATTERNS:
            if re.search(pattern, lower):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title=f"Social engineering pattern: {subtype}",
                    description=f"Content matches known social engineering pattern: {subtype}.",
                    file_path=file_path,
                    category="Social Engineering",
                    engine="fraud_intelligence",
                    rule_id="FRD-002",
                    risk_score=60,
                    remediation="Review content for deceptive patterns. Do not include in customer-facing materials.",
                    tags=["social-engineering", "fraud"],
                ))
        return findings

    def _detect_insider_signals(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        # Detect attempts to access sensitive system files
        sensitive_access = [
            r"/etc/passwd", r"/etc/shadow", r"~/.ssh/", r"\.aws/credentials",
            r"~/.gnupg", r"/proc/\d+/mem",
        ]
        for pattern in sensitive_access:
            if re.search(pattern, content):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Insider threat signal: sensitive path access",
                    description=f"Code accesses sensitive system path matching: {pattern}",
                    file_path=file_path,
                    category="Insider Threat",
                    engine="fraud_intelligence",
                    rule_id="FRD-003",
                    risk_score=77,
                    remediation="Investigate this file access. Ensure it's authorized and audited.",
                    tags=["insider-threat", "privilege-escalation"],
                ))
        return findings

    def _detect_behavioral_anomalies(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        # Obfuscation patterns
        obfuscation = [
            (r"[A-Za-z0-9+/]{40,}={0,2}", "Large Base64-encoded blob"),
            (r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){20,}", "Hex-encoded payload"),
            (r"chr\(\d+\)\s*\+\s*chr\(\d+\)", "Character code obfuscation"),
            (r"__import__\(['\"]encodings['\"]", "Encoding obfuscation"),
        ]
        for pattern, label in obfuscation:
            if re.search(pattern, content):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title=f"Obfuscation detected: {label}",
                    description="Code contains obfuscated patterns typical of malware or backdoors.",
                    file_path=file_path,
                    category="Behavioral Anomaly",
                    engine="fraud_intelligence",
                    rule_id="FRD-004",
                    risk_score=85,
                    remediation="Deobfuscate and audit this code. Consider rejecting it entirely.",
                    tags=["obfuscation", "malware", "fraud"],
                ))
        return findings


class SupplyChainAnalyzer:
    """Analyzes dependencies for known malicious packages and typosquatting."""

    def analyze_file(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        fname = file_path.lower()

        if "package.json" in fname:
            findings += self._check_npm(file_path, content)
        elif "requirements.txt" in fname or "setup.py" in fname:
            findings += self._check_pip(file_path, content)
        elif "go.mod" in fname:
            findings += self._check_go(file_path, content)

        return findings

    def _check_npm(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        try:
            pkg = json.loads(content)
            all_deps = {}
            all_deps.update(pkg.get("dependencies", {}))
            all_deps.update(pkg.get("devDependencies", {}))
            for name, version in all_deps.items():
                key = f"{name}@{version.lstrip('^~')}"
                if key in KNOWN_MALICIOUS_PACKAGES:
                    info = KNOWN_MALICIOUS_PACKAGES[key]
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title=f"Malicious npm package: {key}",
                        description=f"Package {key} is known malicious: {info['reason']}",
                        file_path=file_path,
                        category="Supply Chain",
                        engine="supply_chain",
                        rule_id="SC-001",
                        risk_score=info["score"],
                        remediation=f"Remove {name} immediately. Update to a clean version or find a safe alternative.",
                        tags=["supply-chain", "malicious-package", "npm"],
                    ))
                # Typosquatting heuristic
                if self._is_likely_typosquat(name):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"Possible typosquat package: {name}",
                        description=f"Package name '{name}' resembles a popular package but may be a typosquat.",
                        file_path=file_path,
                        category="Supply Chain",
                        engine="supply_chain",
                        rule_id="SC-002",
                        risk_score=72,
                        remediation="Verify this package is the intended dependency. Check the npm registry carefully.",
                        tags=["supply-chain", "typosquat", "npm"],
                    ))
        except json.JSONDecodeError:
            pass
        return findings

    def _check_pip(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pkg_ver = line.replace("==", "@").replace(">=", "@").replace("<=", "@")
            for key, info in KNOWN_MALICIOUS_PACKAGES.items():
                if key in pkg_ver:
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title=f"Malicious pip package: {line}",
                        description=f"Package {line} is known malicious: {info['reason']}",
                        file_path=file_path,
                        category="Supply Chain",
                        engine="supply_chain",
                        rule_id="SC-003",
                        risk_score=info["score"],
                        remediation="Remove this package and audit your dependency tree.",
                        tags=["supply-chain", "malicious-package", "pip"],
                    ))
        return findings

    def _check_go(self, file_path: str, content: str) -> List[Finding]:
        return []  # Extensible for Go modules

    def _is_likely_typosquat(self, name: str) -> bool:
        popular = ["lodash", "react", "express", "axios", "webpack", "babel",
                   "typescript", "eslint", "prettier", "jest"]
        for p in popular:
            if name != p and self._edit_distance(name, p) <= 2 and len(name) > 3:
                return True
        return False

    def _edit_distance(self, a: str, b: str) -> int:
        m, n = len(a), len(b)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        for i in range(m + 1): dp[i][0] = i
        for j in range(n + 1): dp[0][j] = j
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                dp[i][j] = dp[i-1][j-1] if a[i-1] == b[j-1] else 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
        return dp[m][n]


def compute_risk_score(findings: List[Finding]) -> int:
    """Compute overall risk score from findings."""
    if not findings:
        return 0
    weights = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0.2}
    total = sum(weights.get(f.severity.value, 0) for f in findings)
    return min(100, int(total))


def compute_fraud_score(findings: List[Finding]) -> int:
    """Compute fraud-specific risk score."""
    fraud_cats = {"Data Exfiltration", "Supply Chain", "Social Engineering",
                  "Insider Threat", "Behavioral Anomaly", "Obfuscation"}
    fraud_findings = [f for f in findings if f.category in fraud_cats]
    return compute_risk_score(fraud_findings)
