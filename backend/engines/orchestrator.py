"""
Santhosh AI — Scan Orchestrator
Coordinates all analysis engines and produces unified results.
"""
import asyncio
import os
import time
import zipfile
import tempfile
from pathlib import Path
from typing import List, Dict, Optional
from models.scan import ScanResult, ScanRequest, ScanStatus, Finding, ScanPolicy
from engines.analyzers import StaticAnalyzer, TaintFlowAnalyzer, SecretsScanner, PromptInjectionDetector
from engines.fraud_intelligence import FraudIntelligenceEngine, SupplyChainAnalyzer, compute_risk_score, compute_fraud_score

# Global scan store (in production, use Redis or DB)
_scan_store: Dict[str, ScanResult] = {}

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash",
    ".yaml", ".yml", ".json", ".env", ".txt", ".md",
    ".java", ".go", ".rb", ".php", ".cs", ".cpp", ".c",
    ".html", ".xml", ".toml", ".cfg", ".ini",
}

TEXT_ENCODINGS = ["utf-8", "latin-1", "cp1252"]

# Engine configuration per policy
ENGINE_CONFIG = {
    ScanPolicy.STRICT: {
        "static": True, "taint": True, "secrets": True,
        "fraud": True, "supply_chain": True, "prompt_injection": True,
        "max_file_size_kb": 10240,
    },
    ScanPolicy.BALANCED: {
        "static": True, "taint": True, "secrets": True,
        "fraud": True, "supply_chain": True, "prompt_injection": True,
        "max_file_size_kb": 5120,
    },
    ScanPolicy.PERMISSIVE: {
        "static": True, "taint": False, "secrets": True,
        "fraud": False, "supply_chain": True, "prompt_injection": False,
        "max_file_size_kb": 2048,
    },
}


class ScanOrchestrator:
    def __init__(self):
        self.static = StaticAnalyzer()
        self.taint = TaintFlowAnalyzer()
        self.secrets = SecretsScanner()
        self.prompt = PromptInjectionDetector()
        self.fraud = FraudIntelligenceEngine()
        self.supply_chain = SupplyChainAnalyzer()

    async def run_scan(self, scan_id: str, file_path: str, request: ScanRequest):
        result = _scan_store.get(scan_id)
        if not result:
            return

        config = ENGINE_CONFIG.get(request.policy, ENGINE_CONFIG[ScanPolicy.BALANCED])
        start = time.time()

        try:
            result.status = ScanStatus.RUNNING
            files = self._collect_files(file_path)
            result.files_analyzed = len(files)

            all_findings: List[Finding] = []

            for idx, fpath in enumerate(files):
                content = self._read_file(fpath, config["max_file_size_kb"])
                if content is None:
                    continue

                rel_path = os.path.relpath(fpath, os.path.dirname(file_path))

                if config["static"]:
                    all_findings += self.static.analyze_file(rel_path, content)
                    result.engines_used = list(set(result.engines_used + ["static_analyzer"]))

                if config["taint"]:
                    all_findings += self.taint.analyze_file(rel_path, content)
                    result.engines_used = list(set(result.engines_used + ["taint_flow"]))

                if config["secrets"]:
                    all_findings += self.secrets.analyze_file(rel_path, content)
                    result.engines_used = list(set(result.engines_used + ["secrets_scanner"]))

                if config["prompt_injection"]:
                    all_findings += self.prompt.analyze_file(rel_path, content)
                    result.engines_used = list(set(result.engines_used + ["prompt_injection"]))

                if config["fraud"]:
                    all_findings += self.fraud.analyze_file(rel_path, content)
                    result.engines_used = list(set(result.engines_used + ["fraud_intelligence"]))

                if config["supply_chain"]:
                    all_findings += self.supply_chain.analyze_file(rel_path, content)
                    result.engines_used = list(set(result.engines_used + ["supply_chain"]))

                # Update progress periodically
                if idx % 10 == 0:
                    result.findings = all_findings
                    await asyncio.sleep(0)  # yield

            # Deduplicate findings
            seen = set()
            deduped = []
            for f in all_findings:
                key = (f.rule_id, f.file_path, f.line_number)
                if key not in seen:
                    seen.add(key)
                    deduped.append(f)

            result.findings = deduped
            result.findings_summary = {
                sev: sum(1 for f in deduped if f.severity.value == sev)
                for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            }
            result.risk_score = compute_risk_score(deduped)
            result.fraud_score = compute_fraud_score(deduped)
            result.analyzability_score = min(100, max(0, 100 - len(result.errors) * 5))
            result.status = ScanStatus.COMPLETE

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.errors.append(str(e))
        finally:
            result.duration_seconds = round(time.time() - start, 2)
            from datetime import datetime
            result.completed_at = datetime.utcnow()

    def _collect_files(self, path: str) -> List[str]:
        p = Path(path)
        if p.is_file():
            if p.suffix.lower() == ".zip":
                return self._extract_zip(str(p))
            return [str(p)]
        elif p.is_dir():
            files = []
            for f in p.rglob("*"):
                if f.is_file() and f.suffix.lower() in SUPPORTED_EXTENSIONS:
                    if not any(part.startswith(".") or part in ["node_modules", "__pycache__", ".git", "dist", "build"]
                               for part in f.parts):
                        files.append(str(f))
            return files[:2000]  # cap for safety
        return []

    def _extract_zip(self, zip_path: str) -> List[str]:
        tmpdir = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(zip_path, "r") as z:
                for name in z.namelist()[:500]:
                    if Path(name).suffix.lower() in SUPPORTED_EXTENSIONS:
                        z.extract(name, tmpdir)
            return self._collect_files(tmpdir)
        except Exception:
            return []

    def _read_file(self, path: str, max_kb: int) -> Optional[str]:
        try:
            size_kb = os.path.getsize(path) / 1024
            if size_kb > max_kb:
                return None
            for enc in TEXT_ENCODINGS:
                try:
                    with open(path, "r", encoding=enc) as f:
                        return f.read()
                except UnicodeDecodeError:
                    continue
        except Exception:
            pass
        return None


def get_scan(scan_id: str) -> Optional[ScanResult]:
    return _scan_store.get(scan_id)

def store_scan(result: ScanResult):
    _scan_store[result.scan_id] = result

def list_scans() -> List[ScanResult]:
    return list(_scan_store.values())
