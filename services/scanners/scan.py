import os
import json
import time
import yara
import clamd
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime

# Import other scanner modules
from .meta import EXIFScanner
from .ocr import OCRScanner

logger = logging.getLogger(__name__)

class EmailScanner:
    def __init__(self, yara_rules_dir: str = "/app/scanners/yara_rules"):
        self.yara_rules_dir = yara_rules_dir
        self.clamav_host = os.getenv("CLAMAV_HOST", "clamav")
        self.clamav_port = int(os.getenv("CLAMAV_PORT", 3310))
        
        # Initialize scanners
        self.yara_rules = self._load_yara_rules()
        self.clamav_client = self._init_clamav()
        self.exif_scanner = EXIFScanner()
        self.ocr_scanner = OCRScanner()
        
        logger.info("EmailScanner initialized successfully")
    
    def _load_yara_rules(self) -> Optional[yara.Rules]:
        """Load YARA rules from directory"""
        try:
            if not os.path.exists(self.yara_rules_dir):
                logger.warning(f"YARA rules directory not found: {self.yara_rules_dir}")
                return None
            
            # Find all .yar files
            yar_files = []
            for root, dirs, files in os.walk(self.yara_rules_dir):
                for file in files:
                    if file.endswith('.yar') or file.endswith('.yara'):
                        yar_files.append(os.path.join(root, file))
            
            if not yar_files:
                logger.warning("No YARA rule files found")
                return None
            
            # Compile rules
            rules = yara.compile(filepaths={f"rule_{i}": yar_file for i, yar_file in enumerate(yar_files)})
            logger.info(f"Loaded {len(yar_files)} YARA rule files")
            return rules
            
        except Exception as e:
            logger.error(f"Error loading YARA rules: {e}")
            return None
    
    def _init_clamav(self) -> Optional[clamd.ClamdUnixSocket]:
        """Initialize ClamAV client"""
        try:
            # Try Unix socket first
            client = clamd.ClamdUnixSocket()
            client.ping()
            logger.info("Connected to ClamAV via Unix socket")
            return client
        except:
            try:
                # Try TCP connection
                client = clamd.ClamdNetworkSocket(self.clamav_host, self.clamav_port)
                client.ping()
                logger.info(f"Connected to ClamAV via TCP {self.clamav_host}:{self.clamav_port}")
                return client
            except Exception as e:
                logger.error(f"Failed to connect to ClamAV: {e}")
                return None
    
    def scan_file(self, file_path: str, file_type: str = "email") -> Dict[str, Any]:
        """Perform comprehensive scan of a file"""
        scan_results = {
            'file_path': file_path,
            'file_type': file_type,
            'scan_timestamp': datetime.utcnow().isoformat(),
            'clamav': None,
            'yara': None,
            'exif': None,
            'ocr': None,
            'overall_risk_score': 0.0,
            'threats_detected': [],
            'scan_errors': []
        }
        
        try:
            # ClamAV scan
            scan_results['clamav'] = self._scan_clamav(file_path)
            
            # YARA scan
            scan_results['yara'] = self._scan_yara(file_path)
            
            # EXIF scan (for images)
            if self._is_image_file(file_path):
                scan_results['exif'] = self._scan_exif(file_path)
            
            # OCR scan (for images and PDFs)
            if self._is_scanable_for_ocr(file_path):
                scan_results['ocr'] = self._scan_ocr(file_path)
            
            # Calculate overall risk score
            scan_results['overall_risk_score'] = self._calculate_risk_score(scan_results)
            scan_results['threats_detected'] = self._identify_threats(scan_results)
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            scan_results['scan_errors'].append(str(e))
        
        return scan_results
    
    def _scan_clamav(self, file_path: str) -> Dict[str, Any]:
        """Scan file with ClamAV"""
        if not self.clamav_client:
            return {'error': 'ClamAV not available'}
        
        try:
            start_time = time.time()
            result = self.clamav_client.scan(file_path)
            duration = time.time() - start_time
            
            if result:
                file_name, scan_result = list(result.items())[0]
                return {
                    'status': scan_result[0],
                    'virus_name': scan_result[1] if len(scan_result) > 1 else None,
                    'duration_seconds': duration,
                    'infected': scan_result[0] == 'FOUND'
                }
            else:
                return {
                    'status': 'OK',
                    'virus_name': None,
                    'duration_seconds': duration,
                    'infected': False
                }
                
        except Exception as e:
            return {'error': str(e), 'infected': False}
    
    def _scan_yara(self, file_path: str) -> Dict[str, Any]:
        """Scan file with YARA rules"""
        if not self.yara_rules:
            return {'error': 'YARA rules not available'}
        
        try:
            start_time = time.time()
            matches = self.yara_rules.match(file_path)
            duration = time.time() - start_time
            
            match_data = []
            for match in matches:
                match_data.append({
                    'rule_name': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': [{'name': s.identifier, 'data': s.data} for s in match.strings]
                })
            
            return {
                'matches': match_data,
                'match_count': len(matches),
                'duration_seconds': duration,
                'threats_found': len(matches) > 0
            }
            
        except Exception as e:
            return {'error': str(e), 'threats_found': False}
    
    def _scan_exif(self, file_path: str) -> Dict[str, Any]:
        """Scan image file for EXIF data"""
        try:
            return self.exif_scanner.scan_file(file_path)
        except Exception as e:
            return {'error': str(e)}
    
    def _scan_ocr(self, file_path: str) -> Dict[str, Any]:
        """Scan file for OCR text extraction"""
        try:
            return self.ocr_scanner.scan_file(file_path)
        except Exception as e:
            return {'error': str(e)}
    
    def _is_image_file(self, file_path: str) -> bool:
        """Check if file is an image"""
        image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg', '.webp'}
        return os.path.splitext(file_path)[1].lower() in image_extensions
    
    def _is_scanable_for_ocr(self, file_path: str) -> bool:
        """Check if file can be scanned for OCR"""
        ocr_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.pdf'}
        return os.path.splitext(file_path)[1].lower() in ocr_extensions
    
    def _calculate_risk_score(self, scan_results: Dict[str, Any]) -> float:
        """Calculate overall risk score based on scan results"""
        risk_score = 0.0
        
        # ClamAV results
        if scan_results.get('clamav', {}).get('infected'):
            risk_score += 50.0
        
        # YARA results
        yara_matches = scan_results.get('yara', {}).get('match_count', 0)
        risk_score += min(yara_matches * 10, 30)  # Max 30 points for YARA
        
        # EXIF suspicious data
        exif_data = scan_results.get('exif', {})
        if exif_data.get('suspicious_metadata'):
            risk_score += 15.0
        if exif_data.get('gps_data'):
            risk_score += 5.0
        
        # OCR suspicious content
        ocr_data = scan_results.get('ocr', {})
        if ocr_data.get('suspicious_text_detected'):
            risk_score += 20.0
        
        return min(risk_score, 100.0)  # Cap at 100
    
    def _identify_threats(self, scan_results: Dict[str, Any]) -> List[str]:
        """Identify specific threats from scan results"""
        threats = []
        
        # ClamAV threats
        if scan_results.get('clamav', {}).get('infected'):
            virus_name = scan_results['clamav'].get('virus_name', 'Unknown')
            threats.append(f"Virus detected: {virus_name}")
        
        # YARA threats
        yara_matches = scan_results.get('yara', {}).get('matches', [])
        for match in yara_matches:
            rule_name = match.get('rule_name', 'Unknown')
            threats.append(f"YARA rule match: {rule_name}")
        
        # EXIF threats
        exif_data = scan_results.get('exif', {})
        if exif_data.get('suspicious_metadata'):
            threats.append("Suspicious EXIF metadata detected")
        if exif_data.get('gps_data'):
            threats.append("GPS location data found in image")
        
        # OCR threats
        ocr_data = scan_results.get('ocr', {})
        if ocr_data.get('suspicious_text_detected'):
            threats.append("Suspicious text content detected")
        
        return threats
    
    def scan_email_content(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Scan email content for threats"""
        content_scan = {
            'headers_analysis': self._analyze_headers(email_data.get('headers', {})),
            'body_analysis': self._analyze_body(email_data.get('body', {})),
            'url_analysis': self._analyze_urls(email_data.get('urls', [])),
            'attachment_analysis': self._analyze_attachments(email_data.get('attachments', [])),
            'overall_content_risk': 0.0
        }
        
        # Calculate content risk score
        content_scan['overall_content_risk'] = self._calculate_content_risk(content_scan)
        
        return content_scan
    
    def _analyze_headers(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email headers for suspicious patterns"""
        analysis = {
            'suspicious_patterns': [],
            'risk_score': 0.0
        }
        
        # Check for suspicious patterns
        suspicious_patterns = [
            ('X-Spam-Score', lambda x: float(x) > 5.0, 'High spam score'),
            ('X-Spam-Status', lambda x: 'YES' in x.upper(), 'Marked as spam'),
            ('X-Originating-IP', lambda x: self._is_suspicious_ip(x), 'Suspicious originating IP'),
            ('X-Mailer', lambda x: 'suspicious' in x.lower(), 'Suspicious mailer'),
            ('Reply-To', lambda x: x != headers.get('From', ''), 'Reply-To differs from From'),
        ]
        
        for header, check_func, description in suspicious_patterns:
            if header in headers:
                try:
                    if check_func(headers[header]):
                        analysis['suspicious_patterns'].append(description)
                        analysis['risk_score'] += 10.0
                except:
                    pass
        
        return analysis
    
    def _analyze_body(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email body for suspicious content"""
        analysis = {
            'suspicious_patterns': [],
            'risk_score': 0.0
        }
        
        # Combine text and HTML content
        content = (body.get('text', '') + ' ' + body.get('html', '')).lower()
        
        # Check for suspicious patterns
        suspicious_patterns = [
            ('urgent', 'Urgency language detected'),
            ('click here', 'Suspicious call-to-action'),
            ('verify account', 'Account verification request'),
            ('password', 'Password-related content'),
            ('bank', 'Banking-related content'),
            ('lottery', 'Lottery/prize content'),
            ('winner', 'Prize/winner content'),
        ]
        
        for pattern, description in suspicious_patterns:
            if pattern in content:
                analysis['suspicious_patterns'].append(description)
                analysis['risk_score'] += 5.0
        
        return analysis
    
    def _analyze_urls(self, urls: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze URLs for suspicious patterns"""
        analysis = {
            'suspicious_urls': [],
            'risk_score': 0.0
        }
        
        for url_data in urls:
            url = url_data.get('url', '')
            suspicious_patterns = url_data.get('suspicious_patterns', [])
            
            if suspicious_patterns:
                analysis['suspicious_urls'].append({
                    'url': url,
                    'patterns': suspicious_patterns
                })
                analysis['risk_score'] += len(suspicious_patterns) * 5.0
        
        return analysis
    
    def _analyze_attachments(self, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze attachments for suspicious characteristics"""
        analysis = {
            'suspicious_attachments': [],
            'risk_score': 0.0
        }
        
        for attachment in attachments:
            suspicious = []
            
            if attachment.get('is_executable'):
                suspicious.append('Executable file')
                analysis['risk_score'] += 20.0
            
            if attachment.get('is_archive'):
                suspicious.append('Archive file')
                analysis['risk_score'] += 10.0
            
            if not attachment.get('is_supported'):
                suspicious.append('Unsupported file type')
                analysis['risk_score'] += 5.0
            
            if suspicious:
                analysis['suspicious_attachments'].append({
                    'filename': attachment.get('filename'),
                    'suspicious_reasons': suspicious
                })
        
        return analysis
    
    def _calculate_content_risk(self, content_scan: Dict[str, Any]) -> float:
        """Calculate overall content risk score"""
        total_risk = 0.0
        
        total_risk += content_scan['headers_analysis']['risk_score']
        total_risk += content_scan['body_analysis']['risk_score']
        total_risk += content_scan['url_analysis']['risk_score']
        total_risk += content_scan['attachment_analysis']['risk_score']
        
        return min(total_risk, 100.0)
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP address is suspicious"""
        # Simple check for private IPs (could be expanded)
        private_ranges = [
            '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'
        ]
        
        return any(ip.startswith(range_prefix) for range_prefix in private_ranges)

# Example usage
if __name__ == "__main__":
    scanner = EmailScanner()
    
    # Test with a sample file
    sample_file = "sample.eml"
    if os.path.exists(sample_file):
        result = scanner.scan_file(sample_file)
        print(json.dumps(result, indent=2, default=str))
    else:
        print("No sample file found for testing")
