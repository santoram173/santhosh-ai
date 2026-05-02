"""Santhosh AI — Scan API Router"""
from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks, Form
from models.scan import ScanResult, ScanRequest, ScanPolicy, ScanStatus, ScanProgress
from engines.orchestrator import ScanOrchestrator, get_scan, store_scan, list_scans
import uuid, os, time, tempfile
from datetime import datetime
from typing import List, Optional

router = APIRouter()
orchestrator = ScanOrchestrator()

@router.post("/", response_model=ScanResult)
async def start_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    policy: ScanPolicy = Form(ScanPolicy.BALANCED),
    llm_enrichment: bool = Form(True),
):
    scan_id = str(uuid.uuid4())
    tmpdir = tempfile.mkdtemp()
    safe_name = os.path.basename(file.filename or "upload")
    dest = os.path.join(tmpdir, safe_name)

    content = await file.read()
    with open(dest, "wb") as f:
        f.write(content)

    request = ScanRequest(policy=policy, llm_enrichment=llm_enrichment)
    result = ScanResult(
        scan_id=scan_id,
        policy=policy,
        target=safe_name,
        status=ScanStatus.PENDING,
    )
    store_scan(result)
    background_tasks.add_task(orchestrator.run_scan, scan_id, dest, request)
    return result

@router.get("/", response_model=List[ScanResult])
async def get_all_scans():
    return list_scans()

@router.get("/{scan_id}", response_model=ScanResult)
async def get_scan_result(scan_id: str):
    result = get_scan(scan_id)
    if not result:
        raise HTTPException(404, "Scan not found")
    return result

@router.get("/{scan_id}/progress", response_model=ScanProgress)
async def get_scan_progress(scan_id: str):
    result = get_scan(scan_id)
    if not result:
        raise HTTPException(404, "Scan not found")
    elapsed = (datetime.utcnow() - result.started_at).total_seconds()
    pct = 100 if result.status == ScanStatus.COMPLETE else min(95, int(elapsed * 5))
    return ScanProgress(
        scan_id=scan_id,
        status=result.status,
        progress_pct=pct,
        current_engine=result.engines_used[-1] if result.engines_used else "initializing",
        files_processed=result.files_analyzed,
        findings_so_far=len(result.findings),
        elapsed_seconds=elapsed,
    )

@router.delete("/{scan_id}")
async def delete_scan(scan_id: str):
    from engines.orchestrator import _scan_store
    if scan_id not in _scan_store:
        raise HTTPException(404, "Scan not found")
    del _scan_store[scan_id]
    return {"deleted": scan_id}
