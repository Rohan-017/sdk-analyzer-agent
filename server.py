"""
FastAPI Server — exposes the SDK Analyzer Agent as a REST service.

Endpoints
---------
POST /analyze          Upload a source archive, or a single code file; returns analysis_id (async job)
GET  /status/{id}      Poll job status
GET  /report/{id}      Download JSON report
GET  /report/{id}/html Download HTML report
GET  /health           Liveness check
"""

import asyncio
import logging
import os
import shutil
import tempfile
import uuid
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Dict, Optional

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel

from agent import SDKAnalyzerAgent

logger = logging.getLogger("sdk-analyzer.server")

# ---------------------------------------------------------------------------
# In-memory job store  (swap for Redis/DB in production)
# ---------------------------------------------------------------------------

class JobStatus(BaseModel):
    analysis_id: str
    status: str          # queued | running | done | failed
    sdk_name: Optional[str] = None
    risk_level: Optional[str] = None
    risk_score: Optional[float] = None
    compliance_status: Optional[str] = None
    total_components: Optional[int] = None
    total_vulnerabilities: Optional[int] = None
    output_dir: Optional[str] = None
    error: Optional[str] = None


_jobs: Dict[str, JobStatus] = {}
_BASE_OUTPUT = Path(os.getenv("OUTPUT_DIR", "./output"))


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    _BASE_OUTPUT.mkdir(parents=True, exist_ok=True)
    logger.info("SDK Analyzer API started. Output dir: %s", _BASE_OUTPUT)
    yield
    logger.info("SDK Analyzer API shutting down")


app = FastAPI(
    title="SDK Analyzer Agent API",
    description="Analyzes source-code ZIPs for SBOM, license compliance, and vulnerabilities.",
    version="1.0.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Background job runner
# ---------------------------------------------------------------------------

async def _run_analysis(analysis_id: str, zip_path: str, output_dir: str) -> None:
    job = _jobs[analysis_id]
    job.status = "running"
    try:
        agent = SDKAnalyzerAgent(
            output_dir=output_dir,
            fossology_url=os.getenv("FOSSOLOGY_URL"),
            fossology_token=os.getenv("FOSSOLOGY_TOKEN"),
        )
        report = await agent.analyze(zip_path)

        job.status               = "done"
        job.sdk_name             = report.sdk_name
        job.risk_level           = report.risk_level
        job.risk_score           = report.risk_score
        job.compliance_status    = report.compliance_status
        job.total_components     = report.total_components
        job.total_vulnerabilities= report.total_vulnerabilities
        job.output_dir           = output_dir

    except Exception as exc:
        logger.exception("Analysis %s failed", analysis_id)
        job.status = "failed"
        job.error  = str(exc)
    finally:
        # Clean up the uploaded temp zip
        try:
            os.unlink(zip_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "active_jobs": sum(1 for j in _jobs.values() if j.status == "running")}


@app.post("/analyze", response_model=JobStatus, status_code=202)
async def analyze(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Source code archive (ZIP/7z/tar.gz) or a single code file"),
):
    """Upload a source-code archive or a single code file for analysis. Returns a job ID to poll for results."""
    ARCHIVE_EXTS = (".zip", ".7z", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")
    # Any recognised source-code extension (from the language map) is accepted too
    from stages.extractor import EXTENSION_LANGUAGE_MAP
    ALLOWED_EXTS = ARCHIVE_EXTS + tuple(EXTENSION_LANGUAGE_MAP.keys())

    filename = file.filename or ""
    if not any(filename.endswith(ext) for ext in ALLOWED_EXTS):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported file type. Accepted archives: {', '.join(ARCHIVE_EXTS)}; "
                f"or a single code file with one of: {', '.join(sorted(EXTENSION_LANGUAGE_MAP.keys()))}"
            ),
        )

    analysis_id = str(uuid.uuid4())
    output_dir  = str(_BASE_OUTPUT / analysis_id)
    os.makedirs(output_dir, exist_ok=True)

    # Save uploaded file, preserving the original extension
    upload_filename = "upload" + "".join(Path(filename).suffixes)
    tmp_zip = os.path.join(output_dir, upload_filename)
    with open(tmp_zip, "wb") as f:
        content = await file.read()
        f.write(content)

    job = JobStatus(analysis_id=analysis_id, status="queued", sdk_name=filename)
    _jobs[analysis_id] = job

    background_tasks.add_task(_run_analysis, analysis_id, tmp_zip, output_dir)
    return job


@app.get("/status/{analysis_id}", response_model=JobStatus)
async def get_status(analysis_id: str):
    """Poll job status."""
    job = _jobs.get(analysis_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis ID not found")
    return job


@app.get("/report/{analysis_id}")
async def get_json_report(analysis_id: str):
    """Download the full JSON analysis report."""
    job = _jobs.get(analysis_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis ID not found")
    if job.status != "done":
        raise HTTPException(status_code=409, detail=f"Analysis is '{job.status}', not done yet")

    report_path = Path(job.output_dir) / "sdk_analysis_report.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")
    return FileResponse(str(report_path), media_type="application/json", filename="sdk_analysis_report.json")


@app.get("/report/{analysis_id}/html", response_class=HTMLResponse)
async def get_html_report(analysis_id: str):
    """View the HTML analysis dashboard."""
    job = _jobs.get(analysis_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis ID not found")
    if job.status != "done":
        raise HTTPException(status_code=409, detail=f"Analysis is '{job.status}', not done yet")

    report_path = Path(job.output_dir) / "sdk_analysis_report.html"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="HTML report not found")
    return HTMLResponse(content=report_path.read_text())


@app.get("/report/{analysis_id}/sbom/spdx")
async def get_spdx_sbom(analysis_id: str):
    """Download the SPDX SBOM."""
    return _serve_output_file(analysis_id, "sbom.spdx.json", "application/json")


@app.get("/report/{analysis_id}/sbom/cyclonedx")
async def get_cyclonedx_sbom(analysis_id: str):
    """Download the CycloneDX SBOM."""
    return _serve_output_file(analysis_id, "sbom.cyclonedx.json", "application/json")


@app.get("/jobs")
async def list_jobs():
    """List all analysis jobs."""
    return list(_jobs.values())


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _serve_output_file(analysis_id: str, filename: str, media_type: str):
    job = _jobs.get(analysis_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis ID not found")
    if job.status != "done":
        raise HTTPException(status_code=409, detail=f"Analysis is '{job.status}'")
    path = Path(job.output_dir) / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"{filename} not found")
    return FileResponse(str(path), media_type=media_type, filename=filename)


# ---------------------------------------------------------------------------
# Dev runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=bool(os.getenv("DEV", "")),
        log_level="info",
    )
