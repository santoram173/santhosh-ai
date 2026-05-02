"""
Santhosh AI — Static Analyzer Engine
Multi-pass static analysis with pattern matching and AST inspection.
"""
import re
import ast
import os
from pathlib import Path
from typing import List, Dict, Any
from models.scan import Finding, Severity, CommandSafety


# Rule definitions: (rule_id, pattern, severity, title, description, category, remediation)
STATIC_RULES = [
    ("SA-001", r"eval\s*\(", Severity.CRITICAL, "Use of eval()",
     "eval() executes arbitrary code and is a critical injection risk.",
     "Code Injection", "Replace eval() with safe alternatives like ast.literal_eval() for data."),

    ("SA-002", r"exec\s*\(", Severity.CRITICAL, "Use of exec()",
     "exec() executes arbitrary Python code, enabling remote code execution.",
     "Code Injection", "Avoid exec(). Use subprocess with explicit args or importlib."),

    ("SA-003", r"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True",
     Severity.HIGH, "Shell=True in subprocess",
     "shell=True enables shell injection if any argument is user-controlled.",
     "Command Injection", "Use shell=False and pass args as a list."),

    ("SA-004", r"pickle\.(loads?|load)\s*\(", Severity.HIGH, "Unsafe pickle deserialization",
     "Deserializing untrusted pickle data can execute arbitrary code.",
     "Deserialization", "Use JSON or other safe serialization formats."),

    ("SA-005", r"yaml\.load\s*\([^)]+\)", Severity.HIGH, "Unsafe YAML load",
     "yaml.load() without Loader=yaml.SafeLoader can execute arbitrary code.",
     "Deserialization", "Use yaml.safe_load() instead of yaml.load()."),

    ("SA-006", r"os\.system\s*\(", Severity.HIGH, "Use of os.system()",
     "os.system() passes commands to the shell and is vulnerable to injection.",
     "Command Injection", "Use subprocess.run() with a list of arguments."),

    ("SA-007", r"__import__\s*\(", Severity.MEDIUM, "Dynamic import via __import__",
     "Dynamic imports can be used to load malicious modules.",
     "Code Injection", "Use importlib.import_module() with a validated module name."),

    ("SA-008", r"request\.(args|form|data|json|values)\[['\"]", Severity.MEDIUM,
     "Unvalidated user input access",
     "Accessing user input without validation can lead to injection attacks.",
     "Input Validation", "Validate and sanitize all user inputs before use."),

    ("SA-009", r"(password|passwd|secret|api_key|token)\s*=\s*['\"][^'\"]{8,}['\"]",
     Severity.CRITICAL, "Hardcoded credential",
     "Credentials hardcoded in source code are a critical security risk.",
     "Secrets", "Use environment variables or a secrets manager."),

    ("SA-010", r"hashlib\.md5\s*\(|hashlib\.sha1\s*\(",
     Severity.LOW, "Weak cryptographic hash",
     "MD5 and SHA1 are cryptographically broken and should not be used for security.",
     "Cryptography", "Use SHA-256 or stronger hashing algorithms."),

    ("SA-011", r"random\.(random|randint|choice|shuffle)\s*\(",
     Severity.LOW, "Insecure random number generator",
     "random module is not cryptographically secure.",
     "Cryptography", "Use secrets module or os.urandom() for security-sensitive randomness."),

    ("SA-012", r"SSL_VERIFY\s*=\s*False|verify\s*=\s*False",
     Severity.HIGH, "SSL verification disabled",
     "Disabling SSL verification exposes connections to MITM attacks.",
     "Cryptography", "Always enable SSL certificate verification in production."),
]

JS_RULES = [
    ("JS-001", r"eval\s*\(", Severity.CRITICAL, "JavaScript eval()",
     "eval() in JavaScript executes arbitrary code.", "Code Injection",
     "Avoid eval(). Use JSON.parse() for data or Function constructors cautiously."),

    ("JS-002", r"innerHTML\s*=", Severity.HIGH, "Direct innerHTML assignment",
     "Setting innerHTML with user data enables XSS attacks.", "XSS",
     "Use textContent or DOMPurify to sanitize HTML before insertion."),

    ("JS-003", r"document\.write\s*\(", Severity.HIGH, "document.write() usage",
     "document.write() can be exploited for XSS.", "XSS",
     "Use DOM manipulation methods instead of document.write()."),

    ("JS-004", r"require\s*\(\s*['\"][^'\"]+['\"].*\+", Severity.HIGH,
     "Dynamic require() with concatenation", "Dynamic module loading can load attacker-controlled modules.",
     "Code Injection", "Use static require() calls with known module names."),
]

BASH_RULES = [
    ("SH-001", r"curl\s+.*\|\s*(bash|sh|python|perl)",
     Severity.CRITICAL, "Pipe curl to shell",
     "Piping remote content directly to a shell is extremely dangerous.",
     "Command Injection", "Download, verify signature, then execute in separate steps."),

    ("SH-002", r"curl\s+-k\s|wget\s+--no-check-certificate",
     Severity.HIGH, "HTTP request with SSL disabled",
     "Disabling SSL certificate validation enables MITM attacks.",
     "Cryptography", "Remove -k / --no-check-certificate flags."),

    ("SH-003", r"chmod\s+777|chmod\s+-R\s+777",
     Severity.HIGH, "Overly permissive file permissions",
     "chmod 777 grants all users full read/write/execute access.",
     "Access Control", "Use least-privilege permissions (e.g., 644 for files, 755 for scripts)."),

    ("SH-004", r"sudo\s+", Severity.MEDIUM, "sudo usage detected",
     "Unexpected sudo usage may indicate privilege escalation.",
     "Privilege Escalation", "Audit all sudo usage and apply least privilege."),

    ("SH-005", r"echo\s+.*\|\s*base64\s+-d\s*\|\s*(bash|sh)",
     Severity.CRITICAL, "Base64 encoded command execution",
     "Executing base64-decoded commands is a common malware evasion technique.",
     "Code Injection", "Remove this pattern entirely. Investigate its origin."),
]


class StaticAnalyzer:
    """Multi-pass static code analyzer."""

    def __init__(self):
        self.name = "Static Analyzer"

    def analyze_file(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        ext = Path(file_path).suffix.lower()

        if ext in [".py"]:
            findings += self._apply_rules(file_path, content, STATIC_RULES, "static_analyzer")
            findings += self._analyze_python_ast(file_path, content)
        elif ext in [".js", ".ts", ".jsx", ".tsx"]:
            findings += self._apply_rules(file_path, content, JS_RULES, "static_analyzer")
        elif ext in [".sh", ".bash"]:
            findings += self._apply_rules(file_path, content, BASH_RULES, "bash_analyzer")

        return findings

    def _apply_rules(self, file_path: str, content: str, rules: list, engine: str) -> List[Finding]:
        findings = []
        lines = content.split("\n")

        for rule_id, pattern, severity, title, description, category, remediation in rules:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    risk_score = {"CRITICAL": 95, "HIGH": 80, "MEDIUM": 55, "LOW": 30}.get(severity.value, 20)
                    findings.append(Finding(
                        severity=severity,
                        title=title,
                        description=description,
                        file_path=file_path,
                        line_number=line_num,
                        category=category,
                        engine=engine,
                        rule_id=rule_id,
                        risk_score=risk_score,
                        remediation=remediation,
                        evidence=line.strip()[:200],
                        tags=[category.lower().replace(" ", "-")],
                    ))
        return findings

    def _analyze_python_ast(self, file_path: str, content: str) -> List[Finding]:
        """AST-based Python analysis for deeper inspection."""
        findings = []
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                # Detect assert statements used for security checks
                if isinstance(node, ast.Assert):
                    findings.append(Finding(
                        severity=Severity.LOW,
                        title="Security check via assert statement",
                        description="assert is stripped in optimized mode (-O). Do not use for security checks.",
                        file_path=file_path,
                        line_number=node.lineno,
                        category="Logic Error",
                        engine="static_analyzer",
                        rule_id="SA-013",
                        risk_score=25,
                        remediation="Replace assert with explicit if/raise statements.",
                    ))
        except SyntaxError:
            pass
        return findings


class TaintFlowAnalyzer:
    """Source-to-sink taint flow tracker."""

    SOURCES = [
        r"request\.(args|form|data|json|values|cookies|headers)",
        r"os\.environ\.get\(",
        r"input\s*\(",
        r"sys\.argv",
    ]
    SINKS = [
        (r"execute\s*\(|cursor\.execute", "SQL Injection", Severity.CRITICAL, "TF-001"),
        (r"os\.system|subprocess\.(run|call|Popen)", "Command Injection", Severity.CRITICAL, "TF-002"),
        (r"open\s*\([^)]*['\"]w['\"]", "File Write", Severity.HIGH, "TF-003"),
        (r"eval\s*\(|exec\s*\(", "Code Injection", Severity.CRITICAL, "TF-004"),
        (r"render_template_string\s*\(", "Template Injection", Severity.CRITICAL, "TF-005"),
    ]

    def analyze_file(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        has_source = any(re.search(s, content) for s in self.SOURCES)
        if not has_source:
            return findings

        lines = content.split("\n")
        for line_num, line in enumerate(lines, 1):
            for sink_pattern, category, severity, rule_id in self.SINKS:
                if re.search(sink_pattern, line):
                    findings.append(Finding(
                        severity=severity,
                        title=f"Taint flow: user input → {category}",
                        description=f"User-controlled data may reach a {category} sink without sanitization.",
                        file_path=file_path,
                        line_number=line_num,
                        category=category,
                        engine="taint_flow",
                        rule_id=rule_id,
                        risk_score=90,
                        remediation="Sanitize all user inputs before passing to sinks.",
                        evidence=line.strip()[:200],
                        tags=["taint-flow", category.lower().replace(" ", "-")],
                    ))
        return findings


class SecretsScanner:
    """Credential and secret detection engine."""

    SECRET_PATTERNS = [
        ("SS-001", r"AKIA[0-9A-Z]{16}", Severity.CRITICAL, "AWS Access Key ID"),
        ("SS-002", r"['\"](?:aws_secret|secret_access_key)['\"]?\s*[=:]\s*['\"][A-Za-z0-9/+]{40}['\"]",
         Severity.CRITICAL, "AWS Secret Key"),
        ("SS-003", r"AIza[0-9A-Za-z\-_]{30,40}", Severity.CRITICAL, "Google API Key"),
        ("SS-004", r"sk-[a-zA-Z0-9]{48}", Severity.CRITICAL, "OpenAI API Key"),
        ("SS-005", r"gh[pousr]_[A-Za-z0-9_]{36,255}", Severity.CRITICAL, "GitHub Token"),
        ("SS-006", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", Severity.CRITICAL, "Private Key"),
        ("SS-007", r"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
         Severity.HIGH, "Hardcoded Password"),
        ("SS-008", r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"][^'\"]{16,}['\"]",
         Severity.HIGH, "Hardcoded API Key"),
        ("SS-009", r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", Severity.HIGH, "Bearer Token"),
        ("SS-010", r"mysql://[^:]+:[^@]+@|postgresql://[^:]+:[^@]+@",
         Severity.CRITICAL, "Database Connection String with Credentials"),
    ]

    def analyze_file(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        lines = content.split("\n")
        for rule_id, pattern, severity, title in self.SECRET_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        severity=severity,
                        title=f"Secret detected: {title}",
                        description=f"A {title} was found hardcoded in the source file.",
                        file_path=file_path,
                        line_number=line_num,
                        category="Secrets",
                        engine="secrets_scanner",
                        rule_id=rule_id,
                        risk_score=97 if severity == Severity.CRITICAL else 80,
                        remediation="Remove secrets from code. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).",
                        evidence="[REDACTED — secret pattern matched]",
                        tags=["secrets", "credentials"],
                    ))
        return findings


class PromptInjectionDetector:
    """Detects prompt injection patterns in documents and assets."""

    INJECTION_PATTERNS = [
        ("PI-001", r"ignore (all )?previous instructions?", Severity.CRITICAL,
         "Direct prompt injection: override instructions"),
        ("PI-002", r"you are now (a|an|the)", Severity.HIGH, "Role hijacking attempt"),
        ("PI-003", r"forget (everything|all|your) (you know|instructions|rules)",
         Severity.CRITICAL, "Instruction reset attempt"),
        ("PI-004", r"<\s*system\s*>|<\s*instructions?\s*>", Severity.HIGH,
         "Fake system prompt tag injection"),
        ("PI-005", r"\[INST\]|\[SYS\]|<\|im_start\|>", Severity.HIGH,
         "LLM special token injection"),
        ("PI-006", r"disregard (all |your )?(previous |prior )?instructions?",
         Severity.CRITICAL, "Instruction override"),
    ]

    def analyze_file(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        lower = content.lower()
        lines = content.split("\n")
        for rule_id, pattern, severity, title in self.INJECTION_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line.lower()):
                    findings.append(Finding(
                        severity=severity,
                        title=f"Prompt injection: {title}",
                        description="A prompt injection pattern was detected that could manipulate LLM behavior.",
                        file_path=file_path,
                        line_number=line_num,
                        category="Prompt Injection",
                        engine="prompt_injection",
                        rule_id=rule_id,
                        risk_score=88,
                        remediation="Remove or sanitize this content before passing to LLMs. Use input validation and output filtering.",
                        evidence=line.strip()[:200],
                        tags=["prompt-injection", "llm-security"],
                    ))
        return findings
