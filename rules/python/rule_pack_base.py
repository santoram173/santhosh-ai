"""
Santhosh AI — Python Rule Pack Module
Custom extensible rule definitions using Python for complex logic.
"""
import re
import ast
from typing import List
from dataclasses import dataclass, field


@dataclass
class RuleMatch:
    rule_id: str
    title: str
    severity: str
    category: str
    line_number: int
    evidence: str
    remediation: str
    tags: List[str] = field(default_factory=list)


class PythonRulePack:
    """
    Base class for custom Python rule packs.
    Extend this to create your own Santhosh AI rule packs.
    """
    PACK_ID = "custom"
    PACK_NAME = "Custom Rule Pack"
    PACK_VERSION = "1.0.0"
    AUTHOR = "Unknown"

    def analyze(self, file_path: str, content: str) -> List[RuleMatch]:
        raise NotImplementedError


class OWASPRulePack(PythonRulePack):
    """OWASP Top 10 rule pack — Python module variant."""
    PACK_ID = "owasp-python"
    PACK_NAME = "OWASP Top 10 (Python)"
    PACK_VERSION = "2024.1"
    AUTHOR = "Santhosh AI"

    # A01: Broken Access Control
    ACCESS_CONTROL_PATTERNS = [
        (r"@app\.route.*methods=\[.*\](?!.*@login_required)", "Missing authentication on route", "A01"),
        (r"request\.user\.is_admin\s*==\s*False\s*or", "Insecure authorization logic", "A01"),
    ]

    # A03: Injection
    INJECTION_PATTERNS = [
        (r"\.raw\s*\(.*%.*\)", "Raw SQL with string formatting", "A03"),
        (r"format_map\s*\(.*request\.", "Format string injection", "A03"),
        (r"Template\s*\(\s*request\.", "Server-side template injection", "A03"),
    ]

    # A09: Security Logging and Monitoring Failures
    LOGGING_ANTI_PATTERNS = [
        (r"except\s+Exception\s*:\s*\n\s*pass", "Silent exception swallowing", "A09"),
        (r"except\s*:\s*\n\s*pass", "Bare except with pass", "A09"),
    ]

    def analyze(self, file_path: str, content: str) -> List[RuleMatch]:
        matches = []
        if not file_path.endswith(".py"):
            return matches

        lines = content.split("\n")
        all_patterns = (
            [(p, t, cat, "HIGH") for p, t, cat in self.ACCESS_CONTROL_PATTERNS] +
            [(p, t, cat, "CRITICAL") for p, t, cat in self.INJECTION_PATTERNS] +
            [(p, t, cat, "MEDIUM") for p, t, cat in self.LOGGING_ANTI_PATTERNS]
        )

        for pattern, title, owasp_cat, severity in all_patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    matches.append(RuleMatch(
                        rule_id=f"OWASP-{owasp_cat}-{i:04d}",
                        title=title,
                        severity=severity,
                        category=f"OWASP {owasp_cat}",
                        line_number=i,
                        evidence=line.strip()[:200],
                        remediation=self._get_remediation(owasp_cat),
                        tags=["owasp", owasp_cat.lower()],
                    ))
        return matches

    def _get_remediation(self, cat: str) -> str:
        return {
            "A01": "Implement proper access controls. Use @login_required decorators consistently.",
            "A03": "Use parameterized queries and avoid dynamic string formatting in SQL/templates.",
            "A09": "Log all exceptions with context. Never silently swallow errors.",
        }.get(cat, "Review and apply security best practices.")


class CryptoRulePack(PythonRulePack):
    """Cryptography vulnerability rule pack."""
    PACK_ID = "crypto-vulns"
    PACK_NAME = "Cryptography Vulnerabilities"
    PACK_VERSION = "1.0.0"
    AUTHOR = "Santhosh AI"

    WEAK_CRYPTO = [
        ("DES", "DES cipher is 56-bit and broken", "CRITICAL"),
        ("RC4", "RC4 stream cipher is cryptographically broken", "CRITICAL"),
        ("MD2|MD4|MD5", "MD2/MD4/MD5 are collision-vulnerable", "HIGH"),
        ("SHA1(?!_96|_160)", "SHA-1 is deprecated for security use", "MEDIUM"),
        ("ECB", "ECB mode reveals patterns in encrypted data", "HIGH"),
        ("PKCS1v15", "PKCS#1 v1.5 padding is vulnerable to Bleichenbacher", "MEDIUM"),
    ]

    def analyze(self, file_path: str, content: str) -> List[RuleMatch]:
        matches = []
        lines = content.split("\n")
        for pattern, title, severity in self.WEAK_CRYPTO:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    matches.append(RuleMatch(
                        rule_id=f"CRYPTO-{pattern[:6].upper().replace('|','-')}",
                        title=f"Weak cryptography: {title}",
                        severity=severity,
                        category="Cryptography",
                        line_number=i,
                        evidence=line.strip()[:200],
                        remediation="Use AES-256-GCM, SHA-256 or stronger. Consult NIST guidelines.",
                        tags=["cryptography", "weak-cipher"],
                    ))
        return matches


# Registry of all available Python rule packs
REGISTRY: List[PythonRulePack] = [
    OWASPRulePack(),
    CryptoRulePack(),
]


def run_all_packs(file_path: str, content: str) -> List[RuleMatch]:
    """Run all registered rule packs against a file."""
    all_matches = []
    for pack in REGISTRY:
        try:
            all_matches.extend(pack.analyze(file_path, content))
        except Exception as e:
            pass  # Isolated failures don't block other packs
    return all_matches
