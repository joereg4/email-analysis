import os
import sys
import json
import time
import logging
import redis
from datetime import datetime
from typing import Dict, Any, Optional
import traceback

# Add parent directories to path for imports
sys.path.append('/app/parsers')
sys.path.append('/app/scanners')

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from models import EmailAnalysis, Attachment, URLAnalysis, ScanLog, get_db
from parse_email import EmailParser
from scan import EmailScanner
from urls import URLAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EmailAnalysisWorker:
    def __init__(self):
        self.redis_client = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))
        self.database_url = os.getenv("DATABASE_URL", "sqlite:///./data/db/email_analysis.db")
        
        # Initialize components
        self.email_parser = EmailParser()
        self.email_scanner = EmailScanner()
        self.url_analyzer = URLAnalyzer()
        
        # Database setup
        self.engine = create_engine(self.database_url)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        
        logger.info("EmailAnalysisWorker initialized successfully")
    
    def run(self):
        """Main worker loop"""
        logger.info("Starting email analysis worker...")
        
        while True:
            try:
                # Get task from queue
                task_data = self.redis_client.brpop("analysis_queue", timeout=10)
                
                if task_data:
                    task_json = task_data[1].decode('utf-8')
                    task = json.loads(task_json)
                    
                    logger.info(f"Processing task: {task}")
                    self.process_task(task)
                
            except KeyboardInterrupt:
                logger.info("Worker shutting down...")
                break
            except Exception as e:
                logger.error(f"Error in worker loop: {e}")
                logger.error(traceback.format_exc())
                time.sleep(5)  # Wait before retrying
    
    def process_task(self, task: Dict[str, Any]):
        """Process a single analysis task"""
        task_type = task.get('task_type')
        analysis_id = task.get('analysis_id')
        
        if not analysis_id:
            logger.error("No analysis_id in task")
            return
        
        db = self.SessionLocal()
        
        try:
            # Get analysis record
            analysis = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
            if not analysis:
                logger.error(f"Analysis {analysis_id} not found")
                return
            
            # Update status to processing
            analysis.status = "processing"
            analysis.updated_at = datetime.utcnow()
            db.commit()
            
            # Process based on task type
            if task_type == "parse_email":
                self.process_email_parsing(analysis, db)
            elif task_type == "scan_attachments":
                self.process_attachment_scanning(analysis, db)
            elif task_type == "analyze_urls":
                self.process_url_analysis(analysis, db)
            elif task_type == "openai_analysis":
                self.process_openai_analysis(analysis, db)
            else:
                logger.error(f"Unknown task type: {task_type}")
                analysis.status = "failed"
                db.commit()
                return
            
            # Mark as completed
            analysis.status = "completed"
            analysis.completed_at = datetime.utcnow()
            analysis.updated_at = datetime.utcnow()
            db.commit()
            
            logger.info(f"Successfully completed analysis {analysis_id}")
            
        except Exception as e:
            logger.error(f"Error processing task {task}: {e}")
            logger.error(traceback.format_exc())
            
            # Mark as failed
            analysis.status = "failed"
            analysis.updated_at = datetime.utcnow()
            db.commit()
            
        finally:
            db.close()
    
    def process_email_parsing(self, analysis: EmailAnalysis, db):
        """Parse email content and extract metadata"""
        logger.info(f"Parsing email for analysis {analysis.id}")
        
        try:
            # Parse email file
            parsed_data = self.email_parser.parse_email_file(analysis.file_path)
            
            if 'error' in parsed_data:
                raise Exception(f"Email parsing error: {parsed_data['error']}")
            
            # Update analysis with parsed data
            analysis.subject = parsed_data.get('headers', {}).get('Subject', '')
            analysis.sender = parsed_data.get('headers', {}).get('From', '')
            
            # Parse recipients
            recipients = []
            for header in ['To', 'Cc', 'Bcc']:
                if header in parsed_data.get('headers', {}):
                    recipients.append(parsed_data['headers'][header])
            analysis.recipients = recipients
            
            # Parse date
            date_str = parsed_data.get('headers', {}).get('Date', '')
            if date_str:
                try:
                    from email.utils import parsedate_to_datetime
                    analysis.date_sent = parsedate_to_datetime(date_str)
                except:
                    pass
            
            analysis.message_id = parsed_data.get('headers', {}).get('Message-ID', '')
            
            # Save parsed data as JSON
            artifacts_dir = os.path.join('/app/data/artifacts', str(analysis.id))
            os.makedirs(artifacts_dir, exist_ok=True)
            
            parsed_file = os.path.join(artifacts_dir, 'parsed_data.json')
            with open(parsed_file, 'w') as f:
                json.dump(parsed_data, f, indent=2, default=str)
            
            analysis.artifacts_path = artifacts_dir
            
            # Create attachment records
            for attachment_data in parsed_data.get('attachments', []):
                attachment = Attachment(
                    email_id=analysis.id,
                    filename=attachment_data['filename'],
                    content_type=attachment_data['content_type'],
                    size=attachment_data['size'],
                    file_hash=attachment_data['hash'],
                    file_path=os.path.join(artifacts_dir, attachment_data['filename'])
                )
                db.add(attachment)
            
            # Create URL analysis records
            for url_data in parsed_data.get('urls', []):
                url_analysis = URLAnalysis(
                    email_id=analysis.id,
                    url=url_data['url'],
                    domain=url_data['domain']
                )
                db.add(url_analysis)
            
            db.commit()
            
            # Queue next tasks
            self.queue_task(analysis.id, "scan_attachments")
            self.queue_task(analysis.id, "analyze_urls")
            self.queue_task(analysis.id, "openai_analysis")
            
            logger.info(f"Email parsing completed for analysis {analysis.id}")
            
        except Exception as e:
            logger.error(f"Error parsing email {analysis.id}: {e}")
            raise
    
    def process_attachment_scanning(self, analysis: EmailAnalysis, db):
        """Scan email attachments for threats"""
        logger.info(f"Scanning attachments for analysis {analysis.id}")
        
        try:
            attachments = db.query(Attachment).filter(Attachment.email_id == analysis.id).all()
            
            for attachment in attachments:
                # Scan attachment file
                scan_result = self.email_scanner.scan_file(attachment.file_path, "attachment")
                
                # Update attachment with scan results
                attachment.clamav_result = scan_result.get('clamav')
                attachment.yara_matches = scan_result.get('yara', {}).get('matches', [])
                attachment.exif_data = scan_result.get('exif')
                attachment.ocr_text = scan_result.get('ocr', {}).get('extracted_text', '')
                
                # Check if quarantine is needed
                if scan_result.get('clamav', {}).get('infected') or scan_result.get('yara', {}).get('threats_found'):
                    attachment.quarantined = True
                    attachment.quarantine_reason = "Threat detected during scanning"
                
                # Log scan result
                scan_log = ScanLog(
                    email_id=analysis.id,
                    scan_type="attachment_scan",
                    status="completed",
                    result=scan_result,
                    duration_seconds=scan_result.get('clamav', {}).get('duration_seconds', 0) + 
                                   scan_result.get('yara', {}).get('duration_seconds', 0)
                )
                db.add(scan_log)
            
            db.commit()
            logger.info(f"Attachment scanning completed for analysis {analysis.id}")
            
        except Exception as e:
            logger.error(f"Error scanning attachments {analysis.id}: {e}")
            raise
    
    def process_url_analysis(self, analysis: EmailAnalysis, db):
        """Analyze URLs found in email"""
        logger.info(f"Analyzing URLs for analysis {analysis.id}")
        
        try:
            url_analyses = db.query(URLAnalysis).filter(URLAnalysis.email_id == analysis.id).all()
            
            for url_analysis in url_analyses:
                # Analyze URL
                analysis_result = self.url_analyzer.analyze_single_url(url_analysis.url)
                
                # Update URL analysis record
                url_analysis.virustotal_result = analysis_result.get('virustotal_analysis')
                url_analysis.whois_data = analysis_result.get('whois_analysis')
                url_analysis.reputation_score = analysis_result.get('reputation_score', 0.0)
                url_analysis.risk_level = analysis_result.get('risk_level', 'unknown')
                
                # Log analysis result
                scan_log = ScanLog(
                    email_id=analysis.id,
                    scan_type="url_analysis",
                    status="completed",
                    result=analysis_result
                )
                db.add(scan_log)
            
            db.commit()
            logger.info(f"URL analysis completed for analysis {analysis.id}")
            
        except Exception as e:
            logger.error(f"Error analyzing URLs {analysis.id}: {e}")
            raise
    
    def process_openai_analysis(self, analysis: EmailAnalysis, db):
        """Perform OpenAI analysis and summarization"""
        logger.info(f"Performing OpenAI analysis for analysis {analysis.id}")
        
        try:
            # Get parsed data
            parsed_file = os.path.join(analysis.artifacts_path, 'parsed_data.json')
            if not os.path.exists(parsed_file):
                raise Exception("Parsed data not found")
            
            with open(parsed_file, 'r') as f:
                parsed_data = json.load(f)
            
            # Prepare content for OpenAI analysis
            content = self._prepare_content_for_openai(parsed_data, analysis)
            
            # Get OpenAI analysis
            openai_result = self._get_openai_analysis(content)
            
            # Update analysis with OpenAI results
            analysis.summary = openai_result.get('summary', '')
            analysis.ai_risk_assessment = openai_result.get('risk_assessment', '')
            analysis.recommendations = openai_result.get('recommendations', '')
            analysis.risk_score = openai_result.get('risk_score', 0.0)
            analysis.risk_level = openai_result.get('risk_level', 'low')
            
            # Log OpenAI analysis
            scan_log = ScanLog(
                email_id=analysis.id,
                scan_type="openai_analysis",
                status="completed",
                result=openai_result
            )
            db.add(scan_log)
            
            db.commit()
            logger.info(f"OpenAI analysis completed for analysis {analysis.id}")
            
        except Exception as e:
            logger.error(f"Error in OpenAI analysis {analysis.id}: {e}")
            raise
    
    def _prepare_content_for_openai(self, parsed_data: Dict[str, Any], analysis: EmailAnalysis) -> str:
        """Prepare content for OpenAI analysis"""
        content_parts = []
        
        # Email headers
        headers = parsed_data.get('headers', {})
        content_parts.append("EMAIL HEADERS:")
        for key, value in headers.items():
            content_parts.append(f"{key}: {value}")
        
        # Email body
        body = parsed_data.get('body', {})
        if body.get('text'):
            content_parts.append("\nEMAIL BODY (TEXT):")
            content_parts.append(body['text'])
        
        if body.get('html'):
            content_parts.append("\nEMAIL BODY (HTML):")
            content_parts.append(body['html'])
        
        # Attachments
        attachments = parsed_data.get('attachments', [])
        if attachments:
            content_parts.append("\nATTACHMENTS:")
            for attachment in attachments:
                content_parts.append(f"- {attachment['filename']} ({attachment['content_type']}, {attachment['size']} bytes)")
        
        # URLs
        urls = parsed_data.get('urls', [])
        if urls:
            content_parts.append("\nURLS FOUND:")
            for url_data in urls:
                content_parts.append(f"- {url_data['url']}")
        
        return "\n".join(content_parts)
    
    def _get_openai_analysis(self, content: str) -> Dict[str, Any]:
        """Get OpenAI analysis of email content"""
        try:
            import openai
            
            openai.api_key = os.getenv("OPENAI_API_KEY")
            if not openai.api_key:
                return {
                    'error': 'OpenAI API key not configured',
                    'summary': 'OpenAI analysis not available',
                    'risk_assessment': 'Unable to assess risk without OpenAI',
                    'recommendations': 'Configure OpenAI API key for analysis',
                    'risk_score': 0.0,
                    'risk_level': 'unknown'
                }
            
            # Truncate content if too long
            max_content_length = 4000  # Leave room for prompt
            if len(content) > max_content_length:
                content = content[:max_content_length] + "..."
            
            prompt = f"""
            Analyze the following email for security threats and provide a comprehensive assessment:
            
            {content}
            
            Please provide:
            1. A brief summary of the email content
            2. A risk assessment identifying potential threats
            3. Specific recommendations for handling this email
            4. A risk score from 0-100 (0 = safe, 100 = extremely dangerous)
            5. A risk level (low, medium, high, critical)
            
            Format your response as JSON with the following structure:
            {{
                "summary": "Brief summary of the email",
                "risk_assessment": "Detailed risk assessment",
                "recommendations": "Specific recommendations",
                "risk_score": 75,
                "risk_level": "high"
            }}
            """
            
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert analyzing emails for threats. Provide accurate, detailed analysis in JSON format."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.3
            )
            
            # Parse response
            response_text = response.choices[0].message.content.strip()
            
            # Try to extract JSON from response
            try:
                # Find JSON in response
                start_idx = response_text.find('{')
                end_idx = response_text.rfind('}') + 1
                if start_idx != -1 and end_idx != -1:
                    json_text = response_text[start_idx:end_idx]
                    result = json.loads(json_text)
                    return result
                else:
                    raise ValueError("No JSON found in response")
            except:
                # Fallback: return structured response
                return {
                    'summary': response_text[:200] + "..." if len(response_text) > 200 else response_text,
                    'risk_assessment': 'Unable to parse detailed assessment',
                    'recommendations': 'Review email manually',
                    'risk_score': 50.0,
                    'risk_level': 'medium'
                }
                
        except Exception as e:
            logger.error(f"Error in OpenAI analysis: {e}")
            return {
                'error': str(e),
                'summary': 'OpenAI analysis failed',
                'risk_assessment': 'Unable to assess risk',
                'recommendations': 'Review email manually',
                'risk_score': 50.0,
                'risk_level': 'medium'
            }
    
    def queue_task(self, analysis_id: int, task_type: str, data: Dict[str, Any] = None):
        """Queue a new task for processing"""
        task = {
            "analysis_id": analysis_id,
            "task_type": task_type,
            "data": data or {},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        self.redis_client.lpush("analysis_queue", json.dumps(task))
        logger.info(f"Queued task: {task_type} for analysis {analysis_id}")

def main():
    """Main entry point"""
    worker = EmailAnalysisWorker()
    worker.run()

if __name__ == "__main__":
    main()
