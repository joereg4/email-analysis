#!/usr/bin/env python3

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import json
import os
from datetime import datetime

app = FastAPI(title="Email Analysis Sandbox - Simple API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple in-memory storage for testing
analyses = []
analysis_counter = 1

@app.get("/")
async def root():
    return {
        "success": True,
        "message": "Email Analysis Sandbox is running",
        "data": {"version": "1.0.0", "status": "healthy"}
    }

@app.get("/summary")
async def get_summary():
    total = len(analyses)
    completed = len([a for a in analyses if a.get('status') == 'completed'])
    quarantined = len([a for a in analyses if a.get('quarantined', False)])
    high_risk = len([a for a in analyses if a.get('risk_level') == 'high'])
    
    return {
        "total_emails": total,
        "pending": len([a for a in analyses if a.get('status') == 'pending']),
        "processing": len([a for a in analyses if a.get('status') == 'processing']),
        "completed": completed,
        "failed": len([a for a in analyses if a.get('status') == 'failed']),
        "quarantined": quarantined,
        "high_risk": high_risk,
        "critical_risk": len([a for a in analyses if a.get('risk_level') == 'critical'])
    }

@app.get("/analyses")
async def get_analyses():
    return analyses

@app.post("/upload")
async def upload_email(file: UploadFile = File(...)):
    global analysis_counter
    
    if not file.filename.lower().endswith('.eml'):
        return {"success": False, "message": "Only .eml files are supported"}
    
    # Create a simple analysis record
    analysis = {
        "id": analysis_counter,
        "filename": file.filename,
        "subject": f"Test Email {analysis_counter}",
        "sender": "test@example.com",
        "status": "completed",
        "risk_score": 75.0,
        "risk_level": "high",
        "summary": "This is a test email analysis. The system detected suspicious patterns including urgency language and potential phishing indicators.",
        "ai_risk_assessment": "High risk email detected. Contains multiple suspicious elements including urgency language, potential phishing keywords, and suspicious URLs.",
        "recommendations": "1. Quarantine this email immediately. 2. Do not click any links. 3. Report to security team. 4. Scan system for malware.",
        "threats_detected": [
            "Phishing keywords detected",
            "Urgency language found",
            "Suspicious URL patterns",
            "Potential malware indicators"
        ],
        "quarantined": False,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }
    
    analyses.append(analysis)
    analysis_counter += 1
    
    return {
        "success": True,
        "message": "Email uploaded and analyzed successfully",
        "analysis_id": analysis["id"],
        "file_hash": f"test_hash_{analysis_counter}"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
