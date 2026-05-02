"""Santhosh AI — Rule Packs API Router"""
from fastapi import APIRouter

router = APIRouter()

RULE_PACKS = [
    {"id": "owasp-top10", "name": "OWASP Top 10", "rules": 127, "author": "Santhosh AI",
     "version": "2024.1", "tags": ["injection", "xss", "broken-auth", "deserialization"], "active": True},
    {"id": "secrets-sentinel", "name": "Secrets Sentinel", "rules": 84, "author": "Santhosh AI",
     "version": "1.5.0", "tags": ["api-keys", "tokens", "credentials", "pem"], "active": True},
    {"id": "fraudshield-pro", "name": "FraudShield Pro", "rules": 63, "author": "Santhosh AI",
     "version": "2.1.0", "tags": ["exfiltration", "behavioral", "supply-chain"], "active": True},
    {"id": "yara-malware", "name": "YARA Malware Pack", "rules": 218, "author": "Community",
     "version": "3.0.0", "tags": ["malware", "ransomware", "trojan", "rootkit"], "active": True},
    {"id": "ai-prompt-guard", "name": "AI Prompt Guard", "rules": 41, "author": "Santhosh AI",
     "version": "1.0.0", "tags": ["prompt-injection", "llm", "jailbreak"], "active": True},
    {"id": "supply-chain-intel", "name": "Supply Chain Intel", "rules": 56, "author": "Santhosh AI",
     "version": "1.3.0", "tags": ["dependency", "typosquatting", "compromise"], "active": True},
]

@router.get("/")
async def list_rule_packs():
    return {"packs": RULE_PACKS, "total": len(RULE_PACKS),
            "total_rules": sum(p["rules"] for p in RULE_PACKS)}

@router.get("/{pack_id}")
async def get_rule_pack(pack_id: str):
    pack = next((p for p in RULE_PACKS if p["id"] == pack_id), None)
    if not pack:
        from fastapi import HTTPException
        raise HTTPException(404, "Rule pack not found")
    return pack
