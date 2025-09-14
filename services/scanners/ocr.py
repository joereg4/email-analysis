import os
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

try:
    import pytesseract
    from PIL import Image
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False

try:
    import fitz  # PyMuPDF
    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False

logger = logging.getLogger(__name__)

class OCRScanner:
    def __init__(self):
        if not TESSERACT_AVAILABLE:
            logger.warning("Tesseract not available. OCR scanning will be limited.")
        
        # Configure Tesseract if available
        if TESSERACT_AVAILABLE:
            # Set Tesseract path if needed (adjust for your system)
            # pytesseract.pytesseract.tesseract_cmd = r'/usr/bin/tesseract'
            pass
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scan file for OCR text extraction"""
        result = {
            'file_path': file_path,
            'text_extracted': False,
            'extracted_text': '',
            'confidence_scores': [],
            'suspicious_text_detected': False,
            'suspicious_patterns': [],
            'risk_score': 0.0,
            'scan_timestamp': datetime.utcnow().isoformat()
        }
        
        file_ext = os.path.splitext(file_path)[1].lower()
        
        try:
            if file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff']:
                result = self._scan_image(file_path, result)
            elif file_ext == '.pdf' and PYMUPDF_AVAILABLE:
                result = self._scan_pdf(file_path, result)
            else:
                result['error'] = f'Unsupported file type for OCR: {file_ext}'
                
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Error performing OCR on {file_path}: {e}")
        
        # Analyze extracted text for suspicious patterns
        if result.get('extracted_text'):
            result['suspicious_patterns'] = self._analyze_text_patterns(result['extracted_text'])
            result['suspicious_text_detected'] = len(result['suspicious_patterns']) > 0
            result['risk_score'] = self._calculate_text_risk_score(result)
        
        return result
    
    def _scan_image(self, file_path: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """Perform OCR on image file"""
        if not TESSERACT_AVAILABLE or not PIL_AVAILABLE:
            result['error'] = 'Tesseract or PIL not available'
            return result
        
        try:
            # Open image
            with Image.open(file_path) as image:
                # Convert to RGB if necessary
                if image.mode != 'RGB':
                    image = image.convert('RGB')
                
                # Perform OCR
                text = pytesseract.image_to_string(image)
                result['extracted_text'] = text.strip()
                result['text_extracted'] = bool(text.strip())
                
                # Get confidence scores
                try:
                    data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
                    confidences = [int(conf) for conf in data['conf'] if int(conf) > 0]
                    if confidences:
                        result['confidence_scores'] = confidences
                        result['average_confidence'] = sum(confidences) / len(confidences)
                except:
                    pass
                    
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _scan_pdf(self, file_path: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract text from PDF file"""
        if not PYMUPDF_AVAILABLE:
            result['error'] = 'PyMuPDF not available'
            return result
        
        try:
            doc = fitz.open(file_path)
            text_parts = []
            
            for page_num in range(doc.page_count):
                page = doc[page_num]
                text = page.get_text()
                if text.strip():
                    text_parts.append(text.strip())
            
            doc.close()
            
            result['extracted_text'] = '\n'.join(text_parts)
            result['text_extracted'] = bool(result['extracted_text'])
            result['page_count'] = doc.page_count
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _analyze_text_patterns(self, text: str) -> List[str]:
        """Analyze extracted text for suspicious patterns"""
        suspicious_patterns = []
        text_lower = text.lower()
        
        # Define suspicious patterns
        patterns = {
            'phishing_indicators': [
                'verify your account', 'account suspended', 'click here to verify',
                'urgent action required', 'security alert', 'account locked',
                'verify your identity', 'confirm your details'
            ],
            'financial_scams': [
                'lottery winner', 'congratulations you won', 'claim your prize',
                'inheritance', 'unclaimed funds', 'bank transfer',
                'wire transfer', 'bitcoin', 'cryptocurrency'
            ],
            'malware_indicators': [
                'download now', 'click to download', 'install software',
                'update your browser', 'security update', 'antivirus update'
            ],
            'suspicious_requests': [
                'send money', 'wire transfer', 'gift cards', 'itunes cards',
                'amazon cards', 'google play cards', 'paypal', 'venmo'
            ],
            'urgency_language': [
                'act now', 'limited time', 'expires soon', 'immediate action',
                'urgent', 'asap', 'hurry', 'don\'t delay'
            ],
            'authority_impersonation': [
                'irs', 'fbi', 'cia', 'police', 'court', 'legal notice',
                'government', 'official', 'authorized'
            ]
        }
        
        # Check for each pattern category
        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                if pattern in text_lower:
                    suspicious_patterns.append(f'{category}: {pattern}')
        
        # Check for suspicious URLs in text
        import re
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        
        for url in urls:
            if self._is_suspicious_url(url):
                suspicious_patterns.append(f'suspicious_url: {url}')
        
        # Check for phone numbers (potential scam indicators)
        phone_pattern = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        phones = re.findall(phone_pattern, text)
        if phones:
            suspicious_patterns.append(f'phone_numbers_found: {len(phones)} numbers')
        
        # Check for email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, text)
        if emails:
            suspicious_patterns.append(f'email_addresses_found: {len(emails)} addresses')
        
        return suspicious_patterns
    
    def _is_suspicious_url(self, url: str) -> bool:
        """Check if URL is suspicious"""
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check for suspicious domains
        suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'short.link', 't.co', 'goo.gl',
            'ow.ly', 'buff.ly', 'is.gd', 'v.gd', 'shorturl.at'
        ]
        
        if any(sus_domain in domain for sus_domain in suspicious_domains):
            return True
        
        # Check for IP addresses
        import ipaddress
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            pass
        
        # Check for suspicious patterns
        suspicious_patterns = [
            'free', 'win', 'prize', 'lottery', 'congratulations',
            'click', 'verify', 'account', 'security', 'update'
        ]
        
        if any(pattern in domain for pattern in suspicious_patterns):
            return True
        
        return False
    
    def _calculate_text_risk_score(self, result: Dict[str, Any]) -> float:
        """Calculate risk score based on text analysis"""
        risk_score = 0.0
        
        # Base score for having text
        if result.get('text_extracted'):
            risk_score += 5.0
        
        # Score for suspicious patterns
        suspicious_patterns = result.get('suspicious_patterns', [])
        risk_score += len(suspicious_patterns) * 3.0
        
        # Additional scoring for specific high-risk patterns
        text = result.get('extracted_text', '').lower()
        
        high_risk_indicators = [
            'password', 'login', 'username', 'account',
            'credit card', 'ssn', 'social security',
            'bank account', 'routing number'
        ]
        
        for indicator in high_risk_indicators:
            if indicator in text:
                risk_score += 10.0
        
        # Score for urgency language
        urgency_words = ['urgent', 'immediate', 'asap', 'hurry', 'now']
        urgency_count = sum(1 for word in urgency_words if word in text)
        risk_score += urgency_count * 2.0
        
        return min(risk_score, 50.0)  # Cap at 50 points for OCR
    
    def extract_text_with_confidence(self, file_path: str) -> Dict[str, Any]:
        """Extract text with detailed confidence information"""
        result = {
            'file_path': file_path,
            'text_blocks': [],
            'overall_confidence': 0.0,
            'text_extracted': False
        }
        
        if not TESSERACT_AVAILABLE or not PIL_AVAILABLE:
            result['error'] = 'Tesseract or PIL not available'
            return result
        
        try:
            with Image.open(file_path) as image:
                if image.mode != 'RGB':
                    image = image.convert('RGB')
                
                # Get detailed OCR data
                data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
                
                text_blocks = []
                confidences = []
                
                for i in range(len(data['text'])):
                    text = data['text'][i].strip()
                    if text:
                        confidence = int(data['conf'][i])
                        if confidence > 0:
                            text_blocks.append({
                                'text': text,
                                'confidence': confidence,
                                'left': data['left'][i],
                                'top': data['top'][i],
                                'width': data['width'][i],
                                'height': data['height'][i]
                            })
                            confidences.append(confidence)
                
                result['text_blocks'] = text_blocks
                result['text_extracted'] = len(text_blocks) > 0
                
                if confidences:
                    result['overall_confidence'] = sum(confidences) / len(confidences)
                
        except Exception as e:
            result['error'] = str(e)
        
        return result

# Example usage
if __name__ == "__main__":
    scanner = OCRScanner()
    
    # Test with a sample file
    sample_file = "sample.jpg"
    if os.path.exists(sample_file):
        result = scanner.scan_file(sample_file)
        print(json.dumps(result, indent=2, default=str))
    else:
        print("No sample file found for testing")
