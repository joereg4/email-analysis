from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Float, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from datetime import datetime
import os

Base = declarative_base()

class EmailAnalysis(Base):
    __tablename__ = "email_analyses"
    
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, index=True)
    file_path = Column(String)
    file_hash = Column(String, index=True)
    
    # Email metadata
    subject = Column(String)
    sender = Column(String, index=True)
    recipients = Column(JSON)
    date_sent = Column(DateTime)
    message_id = Column(String, index=True)
    
    # Analysis results
    status = Column(String, default="pending")  # pending, processing, completed, failed
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String, default="low")  # low, medium, high, critical
    
    # Scanning results
    clamav_result = Column(JSON)
    yara_matches = Column(JSON)
    exif_data = Column(JSON)
    ocr_text = Column(Text)
    url_analysis = Column(JSON)
    
    # OpenAI analysis
    summary = Column(Text)
    ai_risk_assessment = Column(Text)
    recommendations = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = Column(DateTime)
    
    # File handling
    quarantined = Column(Boolean, default=False)
    quarantine_reason = Column(String)
    artifacts_path = Column(String)

class Attachment(Base):
    __tablename__ = "attachments"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, index=True)
    filename = Column(String)
    content_type = Column(String)
    size = Column(Integer)
    file_hash = Column(String, index=True)
    
    # Analysis results
    clamav_result = Column(JSON)
    yara_matches = Column(JSON)
    exif_data = Column(JSON)
    ocr_text = Column(Text)
    
    # File handling
    quarantined = Column(Boolean, default=False)
    quarantine_reason = Column(String)
    file_path = Column(String)
    
    created_at = Column(DateTime, default=datetime.utcnow)

class URLAnalysis(Base):
    __tablename__ = "url_analyses"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, index=True)
    url = Column(String, index=True)
    domain = Column(String, index=True)
    
    # Analysis results
    virustotal_result = Column(JSON)
    whois_data = Column(JSON)
    reputation_score = Column(Float)
    risk_level = Column(String)
    
    created_at = Column(DateTime, default=datetime.utcnow)

class ScanLog(Base):
    __tablename__ = "scan_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, index=True)
    scan_type = Column(String)  # clamav, yara, exif, ocr, url, openai
    status = Column(String)  # started, completed, failed
    result = Column(JSON)
    error_message = Column(Text)
    duration_seconds = Column(Float)
    
    created_at = Column(DateTime, default=datetime.utcnow)

# Database setup
def get_database_url():
    return os.getenv("DATABASE_URL", "sqlite:///app/data/db/email_analysis.db")

def create_engine_and_session():
    database_url = get_database_url()
    engine = create_engine(database_url)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return engine, SessionLocal

def get_db():
    engine, SessionLocal = create_engine_and_session()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
