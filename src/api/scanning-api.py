#!/usr/bin/env python3
"""
Email Analysis API with Advanced Scanning - Feature 5: ClamAV + YARA
"""

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import email
import re
import sqlite3
import json
import os
import tempfile
import subprocess
from datetime import datetime
from typing import Optional, List, Dict

app = FastAPI(title="Email Analysis API - Feature 5")

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
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Create analysis results table with scanning results
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
            clamav_result TEXT,  -- JSON string
            yara_result TEXT,    -- JSON string
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Add new columns if they don't exist (for existing databases)
    try:
        cursor.execute('ALTER TABLE email_analyses ADD COLUMN clamav_result TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    try:
        cursor.execute('ALTER TABLE email_analyses ADD COLUMN yara_result TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    conn.commit()
    conn.close()
    print(f"Database initialized at {DATABASE_PATH}")

def scan_with_clamav(file_content: bytes, filename: str) -> Dict:
    """
    Scan file content with ClamAV
    Returns scan results including virus detection
    """
    try:
        # Create temporary file for scanning
        with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{filename}") as temp_file:
            temp_file.write(file_content)
            temp_file_path = temp_file.name
        
        try:
            # Run ClamAV scan using clamscan (standalone scanner)
            result = subprocess.run(
                ['clamscan', '--no-summary', temp_file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Parse results
            if result.returncode == 0:
                return {
                    "status": "clean",
                    "message": "No threats detected",
                    "details": result.stdout.strip() or "File is clean"
                }
            elif result.returncode == 1:
                # Virus detected
                return {
                    "status": "infected",
                    "message": "Threat detected",
                    "details": result.stdout.strip(),
                    "threat_name": result.stdout.strip().split(": ")[-1] if ": " in result.stdout else "Unknown threat"
                }
            else:
                return {
                    "status": "error",
                    "message": "Scan failed",
                    "details": result.stderr.strip() or "Unknown error"
                }
                
        finally:
            # Clean up temporary file
            os.unlink(temp_file_path)
            
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "message": "Scan timed out",
            "details": "ClamAV scan took too long"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": "Scan failed",
            "details": str(e)
        }

def scan_with_yara(file_content: bytes, filename: str) -> Dict:
    """
    Scan file content with YARA rules
    Returns rule matches and patterns found
    """
    try:
        # Create temporary file for scanning
        with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{filename}") as temp_file:
            temp_file.write(file_content)
            temp_file_path = temp_file.name
        
        try:
            # Run YARA scan with our custom rules
            yara_rules_path = "/app/yara_rules/malware_signatures.yar"
            
            if not os.path.exists(yara_rules_path):
                return {
                    "status": "no_rules",
                    "message": "No YARA rules found",
                    "details": "YARA rules file not available"
                }
            
            result = subprocess.run(
                ['yara', yara_rules_path, temp_file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # No matches found
                return {
                    "status": "clean",
                    "message": "No YARA rule matches",
                    "details": "File does not match any known patterns"
                }
            elif result.returncode == 1:
                # Matches found
                matches = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        parts = line.split(' ')
                        if len(parts) >= 2:
                            matches.append({
                                "rule": parts[0],
                                "file": parts[1],
                                "description": "Pattern match detected"
                            })
                
                return {
                    "status": "matched",
                    "message": f"Found {len(matches)} YARA rule matches",
                    "details": "File matches known malicious patterns",
                    "matches": matches
                }
            else:
                return {
                    "status": "error",
                    "message": "YARA scan failed",
                    "details": result.stderr.strip() or "Unknown error"
                }
                
        finally:
            # Clean up temporary file
            os.unlink(temp_file_path)
            
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "message": "YARA scan timed out",
            "details": "YARA scan took too long"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": "YARA scan failed",
            "details": str(e)
        }

def save_analysis_result(data):
    """Save analysis result to database with scanning results"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Extract data
    email_info = data.get('email_info', {})
    risk_analysis = data.get('risk_analysis', {})
    clamav_result = data.get('clamav_result', {})
    yara_result = data.get('yara_result', {})
    
    cursor.execute('''
        INSERT INTO email_analyses (
            filename, file_size, content_type, subject, sender, recipient,
            date, message_id, body_preview, body_length, risk_score,
            risk_level, risk_reasons, total_checks, clamav_result, yara_result
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        risk_analysis.get('total_checks', 0),
        json.dumps(clamav_result),
        json.dumps(yara_result)
    ))
    
    analysis_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return analysis_id

def get_analysis_history(limit: int = 10):
    """Get recent analysis history with scanning results"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, filename, subject, sender, risk_score, risk_level, 
               clamav_result, yara_result, created_at
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
            'clamav_result': json.loads(row[6]) if row[6] else {},
            'yara_result': json.loads(row[7]) if row[7] else {},
            'created_at': row[8]
        }
        for row in results
    ]

def get_analysis_by_id(analysis_id: int):
    """Get detailed analysis by ID with scanning results"""
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
        'clamav_result': json.loads(row[15]) if row[15] else {},
        'yara_result': json.loads(row[16]) if row[16] else {},
        'created_at': row[17]
    }

# Initialize database on startup
init_database()

@app.get("/")
async def health_check():
    """Test endpoint to verify API is running"""
    return {"status": "ok", "message": "Email Analysis API with Advanced Scanning is running"}

@app.get("/history")
async def get_history(limit: int = 10):
    """Get analysis history with scanning results"""
    history = get_analysis_history(limit)
    return {"history": history, "count": len(history)}

@app.get("/analysis/{analysis_id}")
async def get_analysis(analysis_id: int):
    """Get detailed analysis by ID with scanning results"""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        return {"error": "Analysis not found"}
    return analysis

def parse_email_content(content: bytes) -> dict:
    """Parse email content and extract headers"""
    try:
        msg = email.message_from_bytes(content)
        
        subject = str(msg.get('Subject', 'No Subject'))
        sender = str(msg.get('From', 'Unknown Sender'))
        recipient = str(msg.get('To', 'Unknown Recipient'))
        date = str(msg.get('Date', 'Unknown Date'))
        message_id = str(msg.get('Message-ID', 'No Message ID'))
        
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
    """Calculate risk score with enhanced rules"""
    risk_score = 0
    risk_reasons = []
    
    subject = email_info.get("subject", "").lower()
    sender = email_info.get("sender", "").lower()
    body = email_info.get("body_preview", "").lower()
    
    # Existing risk patterns...
    suspicious_subjects = [
        "urgent", "act now", "limited time", "click here", "verify account",
        "suspended", "expired", "congratulations", "winner", "free money"
    ]
    
    for pattern in suspicious_subjects:
        if pattern in subject:
            risk_score += 15
            risk_reasons.append(f"Suspicious subject pattern: '{pattern}'")
    
    if "noreply" in sender or "no-reply" in sender:
        risk_score += 10
        risk_reasons.append("No-reply sender address")
    
    suspicious_domains = ["gmail.com", "yahoo.com", "hotmail.com"]
    for domain in suspicious_domains:
        if domain in sender:
            risk_score += 5
            risk_reasons.append(f"Personal email domain: {domain}")
    
    international_domains = [".fj", ".ru", ".cn", ".in", ".br", ".mx", ".ng", ".za"]
    for domain in international_domains:
        if domain in sender.lower():
            risk_score += 15
            risk_reasons.append(f"International domain detected: {domain}")
    
    if "fwd:" in subject.lower() or "fw:" in subject.lower():
        risk_score += 10
        risk_reasons.append("Email appears to be forwarded")
    
    suspicious_body_patterns = [
        "click here", "verify", "password", "account", "suspended",
        "expired", "urgent", "act now", "limited time"
    ]
    
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
    
    urgency_words = ["urgent", "immediately", "asap", "right now", "act now"]
    urgency_count = sum(1 for word in urgency_words if word in body)
    if urgency_count >= 2:
        risk_score += 20
        risk_reasons.append(f"Excessive urgency indicators ({urgency_count} found)")
    
    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    elif risk_score >= 20:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"
    
    return {
        "risk_score": min(risk_score, 100),
        "risk_level": risk_level,
        "risk_reasons": risk_reasons,
        "total_checks": len(risk_reasons)
    }

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Feature 5: File upload with email parsing, risk scoring, and advanced scanning
    """
    if not file.filename:
        return {"error": "No filename provided"}
    
    content = await file.read()
    file_size = len(content)
    
    result = {
        "success": True,
        "filename": file.filename,
        "content_type": file.content_type,
        "file_size": file_size,
        "message": f"Successfully received {file.filename} ({file_size} bytes)"
    }
    
    if file.filename.lower().endswith('.eml'):
        # Parse email
        email_info = parse_email_content(content)
        result["email_info"] = email_info
        
        if "error" not in email_info:
            # Calculate risk score
            risk_analysis = calculate_risk_score(email_info)
            result["risk_analysis"] = risk_analysis
            
            # Perform advanced scanning
            print(f"Scanning {file.filename} with ClamAV...")
            clamav_result = scan_with_clamav(content, file.filename)
            result["clamav_result"] = clamav_result
            
            print(f"Scanning {file.filename} with YARA...")
            yara_result = scan_with_yara(content, file.filename)
            result["yara_result"] = yara_result
            
            # Update risk score based on scanning results
            if clamav_result.get("status") == "infected":
                risk_analysis["risk_score"] = 100
                risk_analysis["risk_level"] = "CRITICAL"
                risk_analysis["risk_reasons"].append(f"VIRUS DETECTED: {clamav_result.get('threat_name', 'Unknown threat')}")
            
            if yara_result.get("status") == "matched":
                risk_analysis["risk_score"] = min(risk_analysis["risk_score"] + 30, 100)
                if risk_analysis["risk_level"] != "CRITICAL":
                    risk_analysis["risk_level"] = "HIGH"
                risk_analysis["risk_reasons"].append(f"YARA MATCH: {len(yara_result.get('matches', []))} malicious patterns detected")
            
            result["message"] += f", parsed email content, calculated risk score ({risk_analysis['risk_level']})"
            result["message"] += f", scanned with ClamAV ({clamav_result['status']}) and YARA ({yara_result['status']})"
            
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
