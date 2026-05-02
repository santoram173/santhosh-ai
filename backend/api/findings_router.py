"""Santhosh AI — Findings API Router"""
from fastapi import APIRouter, HTTPException, Query
from engines.orchestrator import list_scans
from models.scan import Severity
from typing import Optional, List
import json

router = APIRouter()

@router.get("/")
async def get_all_findings(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    engine: Optional[str] = None,
    limit: int = Query(100, le=1000),
):
    all_findings = []
    for scan in list_scans():
        all_findings.extend(scan.findings)

    if severity:
        all_findings = [f for f in all_findings if f.severity.value == severity.upper()]
    if category:
        all_findings = [f for f in all_findings if f.category.lower() == category.lower()]
    if engine:
        all_findings = [f for f in all_findings if f.engine == engine]

    return {
        "total": len(all_findings),
        "findings": [f.dict() for f in all_findings[:limit]]
    }

@router.get("/export/sarif")
async def export_sarif():
    """Export findings in SARIF 2.1.0 format."""
    all_findings = []
    for scan in list_scans():
        all_findings.extend(scan.findings)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Santhosh AI", "version": "2.0.0",
                                "rules": [{"id": f.rule_id, "name": f.title} for f in all_findings[:50]]}},
            "results": [{
                "ruleId": f.rule_id,
                "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                          "LOW": "note", "INFO": "none"}.get(f.severity.value, "warning"),
                "message": {"text": f.description},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                    "region": {"startLine": f.line_number or 1}
                }}]
            } for f in all_findings]
        }]
    }
    return sarif
