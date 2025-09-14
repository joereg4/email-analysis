#!/usr/bin/env python3
"""
Email Analysis API with Database Storage - Feature 4: Database Integration
"""

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import email
import re
import sqlite3
import json
import os
from datetime import datetime
from typing import Optional

app = FastAPI(title="Email Analysis API - Feature 4")

# Enable CORS for testing - including file:// protocol
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*", "null"],  # Allow file:// protocol
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
DATABASE_PATH = "/app/data/email_analysis.db"

def init_database():
    """Initialize the database and create tables"""
    # Create data directory if it doesn't exist
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Create analysis results table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_size INTEGER,
            content_type TEXT,
            subject TEXT,
            sender TEXT,
            recipient TEXT,
            date TEXT,
            message_id TEXT,
            body_preview TEXT,
            body_length INTEGER,
            risk_score INTEGER,
            risk_level TEXT,
            risk_reasons TEXT,  -- JSON string
            total_checks INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
    print(f"Database initialized at {DATABASE_PATH}")

def save_analysis_result(data):
    """Save analysis result to database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Extract data
    email_info = data.get('email_info', {})
    risk_analysis = data.get('risk_analysis', {})
    
    cursor.execute('''
        INSERT INTO email_analyses (
            filename, file_size, content_type, subject, sender, recipient,
            date, message_id, body_preview, body_length, risk_score,
            risk_level, risk_reasons, total_checks
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data['filename'],
        data['file_size'],
        data['content_type'],
        email_info.get('subject', ''),
        email_info.get('sender', ''),
        email_info.get('recipient', ''),
        email_info.get('date', ''),
        email_info.get('message_id', ''),
        email_info.get('body_preview', ''),
        email_info.get('body_length', 0),
        risk_analysis.get('risk_score', 0),
        risk_analysis.get('risk_level', 'UNKNOWN'),
        json.dumps(risk_analysis.get('risk_reasons', [])),
        risk_analysis.get('total_checks', 0)
    ))
    
    analysis_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return analysis_id

def get_analysis_history(limit: int = 10):
    """Get recent analysis history"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, filename, subject, sender, risk_score, risk_level, created_at
        FROM email_analyses
        ORDER BY created_at DESC
        LIMIT ?
    ''', (limit,))
    
    results = cursor.fetchall()
    conn.close()
    
    return [
        {
            'id': row[0],
            'filename': row[1],
            'subject': row[2],
            'sender': row[3],
            'risk_score': row[4],
            'risk_level': row[5],
            'created_at': row[6]
        }
        for row in results
    ]

def get_analysis_by_id(analysis_id: int):
    """Get detailed analysis by ID"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM email_analyses WHERE id = ?
    ''', (analysis_id,))
    
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
    
    return {
        'id': row[0],
        'filename': row[1],
        'file_size': row[2],
        'content_type': row[3],
        'subject': row[4],
        'sender': row[5],
        'recipient': row[6],
        'date': row[7],
        'message_id': row[8],
        'body_preview': row[9],
        'body_length': row[10],
        'risk_score': row[11],
        'risk_level': row[12],
        'risk_reasons': json.loads(row[13]) if row[13] else [],
        'total_checks': row[14],
        'created_at': row[15]
    }

# Initialize database on startup
init_database()

@app.get("/")
async def health_check():
    """Test endpoint to verify API is running"""
    return {"status": "ok", "message": "Email Analysis API with Database is running"}

@app.get("/history")
async def get_history(limit: int = 10):
    """Get analysis history"""
    history = get_analysis_history(limit)
    return {"history": history, "count": len(history)}

@app.get("/analysis/{analysis_id}")
async def get_analysis(analysis_id: int):
    """Get detailed analysis by ID"""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        return {"error": "Analysis not found"}
    return analysis

def parse_email_content(content: bytes) -> dict:
    """
    Feature 2: Basic email parsing
    Extract basic email headers and content
    """
    try:
        # Parse the email
        msg = email.message_from_bytes(content)
        
        # Extract basic headers
        subject = msg.get('Subject', 'No Subject')
        sender = msg.get('From', 'Unknown Sender')
        recipient = msg.get('To', 'Unknown Recipient')
        date = msg.get('Date', 'Unknown Date')
        message_id = msg.get('Message-ID', 'No Message ID')
        
        # Extract body content
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    break
        else:
            body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        
        return {
            "subject": subject,
            "sender": sender,
            "recipient": recipient,
            "date": date,
            "message_id": message_id,
            "body_preview": body[:200] + "..." if len(body) > 200 else body,
            "body_length": len(body)
        }
    except Exception as e:
        return {"error": f"Failed to parse email: {str(e)}"}

def calculate_risk_score(email_info: dict) -> dict:
    """
    Feature 3: Simple risk scoring based on basic rules
    Returns risk score (0-100) and reasons
    """
    risk_score = 0
    risk_reasons = []
    
    # Check for suspicious subject patterns
    subject = email_info.get("subject", "").lower()
    suspicious_subjects = [
        "urgent", "act now", "limited time", "click here", "verify account",
        "suspended", "expired", "congratulations", "winner", "free money"
    ]
    
    for pattern in suspicious_subjects:
        if pattern in subject:
            risk_score += 15
            risk_reasons.append(f"Suspicious subject pattern: '{pattern}'")
    
    # Check for suspicious sender patterns
    sender = email_info.get("sender", "").lower()
    if "noreply" in sender or "no-reply" in sender:
        risk_score += 10
        risk_reasons.append("No-reply sender address")
    
    # Check for suspicious domains in sender
    suspicious_domains = ["gmail.com", "yahoo.com", "hotmail.com"]
    for domain in suspicious_domains:
        if domain in sender:
            risk_score += 5
            risk_reasons.append(f"Personal email domain: {domain}")
    
    # Check for international domains (potential red flag)
    international_domains = [".fj", ".ru", ".cn", ".in", ".br", ".mx", ".ng", ".za"]
    for domain in international_domains:
        if domain in sender.lower():
            risk_score += 15
            risk_reasons.append(f"International domain detected: {domain}")
    
    # Check for forwarded emails
    if "fwd:" in subject.lower() or "fw:" in subject.lower():
        risk_score += 10
        risk_reasons.append("Email appears to be forwarded")
    
    # Check for suspicious body content
    body = email_info.get("body_preview", "").lower()
    suspicious_body_patterns = [
        "click here", "verify", "password", "account", "suspended",
        "expired", "urgent", "act now", "limited time"
    ]
    
    # Check for personal information requests
    personal_info_patterns = [
        "social security", "ssn", "credit card", "bank account", "routing number",
        "personal information", "student id", "student number", "date of birth",
        "mother's maiden name", "security question", "pin number"
    ]
    
    for pattern in personal_info_patterns:
        if pattern in body:
            risk_score += 20
            risk_reasons.append(f"Request for personal information: '{pattern}'")
    
    for pattern in suspicious_body_patterns:
        if pattern in body:
            risk_score += 10
            risk_reasons.append(f"Suspicious body content: '{pattern}'")
    
    # Check for excessive urgency indicators
    urgency_words = ["urgent", "immediately", "asap", "right now", "act now"]
    urgency_count = sum(1 for word in urgency_words if word in body)
    if urgency_count >= 2:
        risk_score += 20
        risk_reasons.append(f"Excessive urgency indicators ({urgency_count} found)")
    
    # Determine risk level
    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    elif risk_score >= 20:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"
    
    return {
        "risk_score": min(risk_score, 100),  # Cap at 100
        "risk_level": risk_level,
        "risk_reasons": risk_reasons,
        "total_checks": len(risk_reasons)
    }

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Feature 4: File upload with email parsing, risk scoring, and database storage
    """
    if not file.filename:
        return {"error": "No filename provided"}
    
    # Get file content
    content = await file.read()
    file_size = len(content)
    
    # Basic file info
    result = {
        "success": True,
        "filename": file.filename,
        "content_type": file.content_type,
        "file_size": file_size,
        "message": f"Successfully received {file.filename} ({file_size} bytes)"
    }
    
    # If it's an .eml file, try to parse it and calculate risk
    if file.filename.lower().endswith('.eml'):
        email_info = parse_email_content(content)
        result["email_info"] = email_info
        
        # Calculate risk score
        if "error" not in email_info:
            risk_analysis = calculate_risk_score(email_info)
            result["risk_analysis"] = risk_analysis
            result["message"] += f", parsed email content, and calculated risk score ({risk_analysis['risk_level']})"
            
            # Save to database
            try:
                analysis_id = save_analysis_result(result)
                result["analysis_id"] = analysis_id
                result["message"] += f" (saved to database as ID {analysis_id})"
            except Exception as e:
                result["database_error"] = f"Failed to save to database: {str(e)}"
        else:
            result["message"] += " and attempted email parsing (failed)"
    else:
        result["message"] += " (not an .eml file, no email parsing performed)"
    
    return result

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
