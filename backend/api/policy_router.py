"""Santhosh AI — Policy API Router"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Dict, Any, Optional
import yaml

router = APIRouter()

DEFAULT_POLICIES = {
    "balanced": {
        "version": "2.0.0", "preset": "balanced",
        "engines": {"static_analyzer": True, "taint_flow": True, "secrets_scanner": True,
                    "fraud_detection": True, "supply_chain": True, "prompt_injection": True},
        "thresholds": {"fail_on": "HIGH", "max_risk_score": 70},
        "fraud": {"behavioral_anomaly": True, "ml_scoring": True, "exfil_detection": True, "supply_chain_check": True},
        "llm_enrichment": {"enabled": True, "phase": 2, "false_positive_reduction": True},
    },
    "strict": {
        "version": "2.0.0", "preset": "strict",
        "engines": {"static_analyzer": True, "taint_flow": True, "secrets_scanner": True,
                    "fraud_detection": True, "supply_chain": True, "prompt_injection": True,
                    "bytecode_integrity": True, "bash_analyzer": True},
        "thresholds": {"fail_on": "MEDIUM", "max_risk_score": 40},
        "fraud": {"behavioral_anomaly": True, "ml_scoring": True, "exfil_detection": True,
                  "supply_chain_check": True, "insider_threat": True},
        "llm_enrichment": {"enabled": True, "phase": 2, "false_positive_reduction": True},
    },
    "permissive": {
        "version": "2.0.0", "preset": "permissive",
        "engines": {"static_analyzer": True, "secrets_scanner": True, "supply_chain": True},
        "thresholds": {"fail_on": "CRITICAL", "max_risk_score": 90},
        "fraud": {"behavioral_anomaly": False, "ml_scoring": False, "exfil_detection": False,
                  "supply_chain_check": True},
        "llm_enrichment": {"enabled": False},
    },
}

class PolicyUpdate(BaseModel):
    config: Dict[str, Any]

@router.get("/{preset}")
async def get_policy(preset: str):
    if preset not in DEFAULT_POLICIES:
        from fastapi import HTTPException
        raise HTTPException(404, f"Policy preset '{preset}' not found")
    return DEFAULT_POLICIES[preset]

@router.get("/{preset}/yaml")
async def get_policy_yaml(preset: str):
    if preset not in DEFAULT_POLICIES:
        from fastapi import HTTPException
        raise HTTPException(404, "Policy not found")
    return {"yaml": yaml.dump(DEFAULT_POLICIES[preset], default_flow_style=False)}

@router.get("/")
async def list_policies():
    return {"presets": list(DEFAULT_POLICIES.keys()), "policies": DEFAULT_POLICIES}
