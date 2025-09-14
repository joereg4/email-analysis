#!/usr/bin/env python3

import os
import sqlite3
from pathlib import Path

# Create database directory if it doesn't exist
db_dir = Path("/app/data/db")
db_dir.mkdir(parents=True, exist_ok=True)

# Create the database file
db_path = db_dir / "email_analysis.db"

# Create tables
conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()

# Create email_analyses table
cursor.execute('''
CREATE TABLE IF NOT EXISTS email_analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    file_path TEXT,
    file_hash TEXT,
    subject TEXT,
    sender TEXT,
    recipients TEXT,
    date_sent TEXT,
    message_id TEXT,
    status TEXT DEFAULT 'pending',
    risk_score REAL DEFAULT 0.0,
    risk_level TEXT DEFAULT 'low',
    clamav_result TEXT,
    yara_matches TEXT,
    exif_data TEXT,
    ocr_text TEXT,
    url_analysis TEXT,
    summary TEXT,
    ai_risk_assessment TEXT,
    recommendations TEXT,
    created_at TEXT,
    updated_at TEXT,
    completed_at TEXT,
    quarantined BOOLEAN DEFAULT 0,
    quarantine_reason TEXT,
    artifacts_path TEXT
)
''')

# Create attachments table
cursor.execute('''
CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER,
    filename TEXT,
    content_type TEXT,
    size INTEGER,
    file_hash TEXT,
    clamav_result TEXT,
    yara_matches TEXT,
    exif_data TEXT,
    ocr_text TEXT,
    quarantined BOOLEAN DEFAULT 0,
    quarantine_reason TEXT,
    file_path TEXT,
    created_at TEXT
)
''')

# Create url_analyses table
cursor.execute('''
CREATE TABLE IF NOT EXISTS url_analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER,
    url TEXT,
    domain TEXT,
    virustotal_result TEXT,
    whois_data TEXT,
    reputation_score REAL,
    risk_level TEXT,
    created_at TEXT
)
''')

# Create scan_logs table
cursor.execute('''
CREATE TABLE IF NOT EXISTS scan_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER,
    scan_type TEXT,
    status TEXT,
    result TEXT,
    error_message TEXT,
    duration_seconds REAL,
    created_at TEXT
)
''')

conn.commit()
conn.close()

print(f"Database initialized at {db_path}")
print("Tables created successfully!")
