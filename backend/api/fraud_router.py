"""Santhosh AI — Fraud Intelligence API Router"""
from fastapi import APIRouter
from engines.orchestrator import list_scans

router = APIRouter()

@router.get("/summary")
async def fraud_summary():
    all_findings = []
    for scan in list_scans():
        all_findings.extend(scan.findings)

    fraud_cats = {"Data Exfiltration", "Supply Chain", "Social Engineering",
                  "Insider Threat", "Behavioral Anomaly"}
    fraud_findings = [f for f in all_findings if f.category in fraud_cats]

    return {
        "total_fraud_findings": len(fraud_findings),
        "by_category": {cat: sum(1 for f in fraud_findings if f.category == cat) for cat in fraud_cats},
        "high_risk_files": list({f.file_path for f in fraud_findings if f.risk_score >= 80}),
        "ml_anomaly_score": min(100, len(fraud_findings) * 8),
    }

@router.get("/alerts")
async def active_alerts():
    all_findings = []
    for scan in list_scans():
        all_findings.extend(scan.findings)
    critical_fraud = [f for f in all_findings
                      if f.severity.value in ("CRITICAL", "HIGH")
                      and f.category in {"Data Exfiltration", "Supply Chain", "Insider Threat"}]
    return {"alerts": [f.dict() for f in critical_fraud[:20]], "count": len(critical_fraud)}
