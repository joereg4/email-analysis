from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Optional
import os
import hashlib
import shutil
from datetime import datetime
import redis
import json

from models import EmailAnalysis, Attachment, URLAnalysis, ScanLog, get_db
from schema import (
    EmailAnalysis as EmailAnalysisSchema,
    EmailAnalysisCreate,
    EmailAnalysisUpdate,
    AnalysisResponse,
    FileUploadResponse,
    AnalysisSummary,
    Attachment as AttachmentSchema,
    URLAnalysis as URLAnalysisSchema,
    ScanLog as ScanLogSchema
)

# Initialize FastAPI app
app = FastAPI(
    title="Email Analysis Sandbox",
    description="A secure email analysis platform with AI-powered threat detection",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Redis connection
redis_client = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))

# File paths
INBOX_PATH = os.getenv("INBOX_PATH", "/app/data/inbox")
ARTIFACTS_PATH = os.getenv("ARTIFACTS_PATH", "/app/data/artifacts")
QUARANTINE_PATH = os.getenv("QUARANTINE_PATH", "/app/data/quarantine")

# Ensure directories exist
os.makedirs(INBOX_PATH, exist_ok=True)
os.makedirs(ARTIFACTS_PATH, exist_ok=True)
os.makedirs(QUARANTINE_PATH, exist_ok=True)

def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA256 hash of a file"""
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def queue_analysis_task(analysis_id: int, task_type: str, data: dict = None):
    """Queue a background task for processing"""
    task = {
        "analysis_id": analysis_id,
        "task_type": task_type,
        "data": data or {},
        "timestamp": datetime.utcnow().isoformat()
    }
    redis_client.lpush("analysis_queue", json.dumps(task))

@app.get("/", response_model=AnalysisResponse)
async def root():
    """Health check endpoint"""
    return AnalysisResponse(
        success=True,
        message="Email Analysis Sandbox is running",
        data={"version": "1.0.0", "status": "healthy"}
    )

@app.post("/upload", response_model=FileUploadResponse)
async def upload_email(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Upload an email file for analysis"""
    
    # Validate file type
    if not file.filename.lower().endswith('.eml'):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")
    
    # Save file to inbox
    file_path = os.path.join(INBOX_PATH, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    # Calculate file hash
    file_hash = calculate_file_hash(file_path)
    
    # Check if file already exists
    existing = db.query(EmailAnalysis).filter(EmailAnalysis.file_hash == file_hash).first()
    if existing:
        return FileUploadResponse(
            success=True,
            message="File already analyzed",
            analysis_id=existing.id,
            file_hash=file_hash
        )
    
    # Create database record
    analysis = EmailAnalysis(
        filename=file.filename,
        file_path=file_path,
        file_hash=file_hash,
        status="pending"
    )
    
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
    
    # Queue for processing
    queue_analysis_task(analysis.id, "parse_email")
    
    return FileUploadResponse(
        success=True,
        message="File uploaded successfully",
        analysis_id=analysis.id,
        file_hash=file_hash
    )

@app.get("/analyses", response_model=List[EmailAnalysisSchema])
async def get_analyses(
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    risk_level: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get list of email analyses"""
    query = db.query(EmailAnalysis)
    
    if status:
        query = query.filter(EmailAnalysis.status == status)
    if risk_level:
        query = query.filter(EmailAnalysis.risk_level == risk_level)
    
    analyses = query.offset(skip).limit(limit).all()
    return analyses

@app.get("/analyses/{analysis_id}", response_model=EmailAnalysisSchema)
async def get_analysis(analysis_id: int, db: Session = Depends(get_db)):
    """Get specific email analysis"""
    analysis = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis

@app.get("/analyses/{analysis_id}/attachments", response_model=List[AttachmentSchema])
async def get_attachments(analysis_id: int, db: Session = Depends(get_db)):
    """Get attachments for an analysis"""
    attachments = db.query(Attachment).filter(Attachment.email_id == analysis_id).all()
    return attachments

@app.get("/analyses/{analysis_id}/urls", response_model=List[URLAnalysisSchema])
async def get_urls(analysis_id: int, db: Session = Depends(get_db)):
    """Get URL analyses for an analysis"""
    urls = db.query(URLAnalysis).filter(URLAnalysis.email_id == analysis_id).all()
    return urls

@app.get("/analyses/{analysis_id}/logs", response_model=List[ScanLogSchema])
async def get_scan_logs(analysis_id: int, db: Session = Depends(get_db)):
    """Get scan logs for an analysis"""
    logs = db.query(ScanLog).filter(ScanLog.email_id == analysis_id).all()
    return logs

@app.get("/summary", response_model=AnalysisSummary)
async def get_summary(db: Session = Depends(get_db)):
    """Get analysis summary statistics"""
    total = db.query(EmailAnalysis).count()
    pending = db.query(EmailAnalysis).filter(EmailAnalysis.status == "pending").count()
    processing = db.query(EmailAnalysis).filter(EmailAnalysis.status == "processing").count()
    completed = db.query(EmailAnalysis).filter(EmailAnalysis.status == "completed").count()
    failed = db.query(EmailAnalysis).filter(EmailAnalysis.status == "failed").count()
    quarantined = db.query(EmailAnalysis).filter(EmailAnalysis.quarantined == True).count()
    high_risk = db.query(EmailAnalysis).filter(EmailAnalysis.risk_level == "high").count()
    critical_risk = db.query(EmailAnalysis).filter(EmailAnalysis.risk_level == "critical").count()
    
    return AnalysisSummary(
        total_emails=total,
        pending=pending,
        processing=processing,
        completed=completed,
        failed=failed,
        quarantined=quarantined,
        high_risk=high_risk,
        critical_risk=critical_risk
    )

@app.post("/analyses/{analysis_id}/quarantine")
async def quarantine_analysis(
    analysis_id: int,
    reason: str,
    db: Session = Depends(get_db)
):
    """Quarantine an analysis"""
    analysis = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    analysis.quarantined = True
    analysis.quarantine_reason = reason
    
    # Move file to quarantine
    if os.path.exists(analysis.file_path):
        quarantine_file = os.path.join(QUARANTINE_PATH, analysis.filename)
        shutil.move(analysis.file_path, quarantine_file)
        analysis.file_path = quarantine_file
    
    db.commit()
    
    return AnalysisResponse(
        success=True,
        message=f"Analysis {analysis_id} quarantined: {reason}"
    )

@app.delete("/analyses/{analysis_id}")
async def delete_analysis(analysis_id: int, db: Session = Depends(get_db)):
    """Delete an analysis and its files"""
    analysis = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    # Delete files
    if os.path.exists(analysis.file_path):
        os.remove(analysis.file_path)
    
    if analysis.artifacts_path and os.path.exists(analysis.artifacts_path):
        shutil.rmtree(analysis.artifacts_path, ignore_errors=True)
    
    # Delete database records
    db.query(Attachment).filter(Attachment.email_id == analysis_id).delete()
    db.query(URLAnalysis).filter(URLAnalysis.email_id == analysis_id).delete()
    db.query(ScanLog).filter(ScanLog.email_id == analysis_id).delete()
    db.delete(analysis)
    db.commit()
    
    return AnalysisResponse(
        success=True,
        message=f"Analysis {analysis_id} deleted successfully"
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", 8080)),
        reload=True
    )
