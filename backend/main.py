"""
Santhosh AI — Security & Fraud Intelligence Platform
Backend API Server (FastAPI)
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
import uvicorn
import asyncio
import uuid
import json
import os
from datetime import datetime
from pathlib import Path

from api.scan_router import router as scan_router
from api.policy_router import router as policy_router
from api.findings_router import router as findings_router
from api.fraud_router import router as fraud_router
from api.rules_router import router as rules_router
from models.scan import ScanStatus
from config.settings import Settings

settings = Settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Santhosh AI starting up...")
    yield
    print("🛑 Santhosh AI shutting down...")

app = FastAPI(
    title="Santhosh AI — Security & Fraud Intelligence Platform",
    description="Enterprise-grade codebase security scanning, fraud detection, and threat intelligence.",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router, prefix="/api/v1/scan", tags=["Scan"])
app.include_router(policy_router, prefix="/api/v1/policy", tags=["Policy"])
app.include_router(findings_router, prefix="/api/v1/findings", tags=["Findings"])
app.include_router(fraud_router, prefix="/api/v1/fraud", tags=["Fraud Intelligence"])
app.include_router(rules_router, prefix="/api/v1/rules", tags=["Rule Packs"])

@app.get("/", tags=["Health"])
async def root():
    return {
        "platform": "Santhosh AI",
        "version": "2.0.0",
        "status": "operational",
        "engines": [
            "static_analyzer", "taint_flow", "bash_analyzer",
            "bytecode_integrity", "file_type_detection", "content_extractor",
            "prompt_injection", "secrets_scanner", "fraud_intelligence"
        ],
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
