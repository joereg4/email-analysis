import email
import os
import json
import hashlib
import mimetypes
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from typing import Dict, List, Any, Optional, Tuple
import re
from urllib.parse import urlparse
import base64

class EmailParser:
    def __init__(self):
        self.supported_attachments = {
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.txt', '.rtf', '.zip', '.rar', '.7z', '.tar', '.gz',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg',
            '.exe', '.msi', '.bat', '.cmd', '.scr', '.com', '.pif'
        }
    
    def parse_email_file(self, file_path: str) -> Dict[str, Any]:
        """Parse an email file and extract all relevant information"""
        try:
            with open(file_path, 'rb') as f:
                raw_email = f.read()
            
            # Parse email
            msg = email.message_from_bytes(raw_email)
            
            # Extract basic information
            parsed_data = {
                'headers': self._extract_headers(msg),
                'body': self._extract_body(msg),
                'attachments': self._extract_attachments(msg, file_path),
                'urls': self._extract_urls(msg),
                'metadata': self._extract_metadata(msg, file_path)
            }
            
            return parsed_data
            
        except Exception as e:
            return {
                'error': str(e),
                'headers': {},
                'body': {},
                'attachments': [],
                'urls': [],
                'metadata': {}
            }
    
    def _extract_headers(self, msg: email.message.Message) -> Dict[str, Any]:
        """Extract and decode email headers"""
        headers = {}
        
        # Important headers to extract
        important_headers = [
            'From', 'To', 'Cc', 'Bcc', 'Subject', 'Date', 'Message-ID',
            'Reply-To', 'Return-Path', 'X-Originating-IP', 'X-Mailer',
            'User-Agent', 'X-Priority', 'Importance', 'X-Spam-Score',
            'X-Spam-Status', 'Received', 'DKIM-Signature', 'SPF',
            'Authentication-Results', 'X-Forwarded-For'
        ]
        
        for header in important_headers:
            if header in msg:
                value = msg[header]
                if value:
                    # Decode header if needed
                    decoded_value = self._decode_header(value)
                    headers[header] = decoded_value
        
        # Extract all received headers
        received_headers = msg.get_all('Received', [])
        if received_headers:
            headers['Received'] = [self._decode_header(r) for r in received_headers]
        
        return headers
    
    def _extract_body(self, msg: email.message.Message) -> Dict[str, Any]:
        """Extract email body content"""
        body_data = {
            'text': '',
            'html': '',
            'text_encoding': None,
            'html_encoding': None
        }
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))
                
                # Skip attachments
                if 'attachment' in content_disposition:
                    continue
                
                if content_type == 'text/plain':
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or 'utf-8'
                            body_data['text'] = payload.decode(charset, errors='ignore')
                            body_data['text_encoding'] = charset
                    except Exception as e:
                        body_data['text'] = f"Error decoding text: {str(e)}"
                
                elif content_type == 'text/html':
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or 'utf-8'
                            body_data['html'] = payload.decode(charset, errors='ignore')
                            body_data['html_encoding'] = charset
                    except Exception as e:
                        body_data['html'] = f"Error decoding HTML: {str(e)}"
        else:
            # Single part message
            content_type = msg.get_content_type()
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    if content_type == 'text/plain':
                        body_data['text'] = payload.decode(charset, errors='ignore')
                        body_data['text_encoding'] = charset
                    elif content_type == 'text/html':
                        body_data['html'] = payload.decode(charset, errors='ignore')
                        body_data['html_encoding'] = charset
            except Exception as e:
                body_data['text'] = f"Error decoding content: {str(e)}"
        
        return body_data
    
    def _extract_attachments(self, msg: email.message.Message, base_path: str) -> List[Dict[str, Any]]:
        """Extract attachment information"""
        attachments = []
        
        if not msg.is_multipart():
            return attachments
        
        for part in msg.walk():
            content_disposition = str(part.get('Content-Disposition', ''))
            
            if 'attachment' in content_disposition:
                filename = part.get_filename()
                if filename:
                    # Decode filename
                    filename = self._decode_header(filename)
                    
                    # Get content type
                    content_type = part.get_content_type()
                    
                    # Get file size
                    payload = part.get_payload(decode=True)
                    file_size = len(payload) if payload else 0
                    
                    # Calculate hash
                    file_hash = hashlib.sha256(payload).hexdigest() if payload else None
                    
                    # Check if file type is supported
                    file_ext = os.path.splitext(filename)[1].lower()
                    is_supported = file_ext in self.supported_attachments
                    
                    attachment_data = {
                        'filename': filename,
                        'content_type': content_type,
                        'size': file_size,
                        'hash': file_hash,
                        'extension': file_ext,
                        'is_supported': is_supported,
                        'is_executable': self._is_executable(file_ext),
                        'is_archive': self._is_archive(file_ext),
                        'is_image': self._is_image(file_ext)
                    }
                    
                    attachments.append(attachment_data)
        
        return attachments
    
    def _extract_urls(self, msg: email.message.Message) -> List[Dict[str, Any]]:
        """Extract URLs from email content"""
        urls = []
        
        # Get all text content
        text_content = ""
        html_content = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))
                
                if 'attachment' in content_disposition:
                    continue
                
                if content_type == 'text/plain':
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or 'utf-8'
                            text_content += payload.decode(charset, errors='ignore')
                    except:
                        pass
                
                elif content_type == 'text/html':
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or 'utf-8'
                            html_content += payload.decode(charset, errors='ignore')
                    except:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    content = payload.decode(charset, errors='ignore')
                    if msg.get_content_type() == 'text/html':
                        html_content = content
                    else:
                        text_content = content
            except:
                pass
        
        # Extract URLs from text
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        
        for url in re.findall(url_pattern, text_content + html_content):
            try:
                parsed_url = urlparse(url)
                domain = parsed_url.netloc
                
                url_data = {
                    'url': url,
                    'domain': domain,
                    'scheme': parsed_url.scheme,
                    'path': parsed_url.path,
                    'query': parsed_url.query,
                    'fragment': parsed_url.fragment,
                    'is_ip': self._is_ip_address(domain),
                    'is_shortened': self._is_shortened_url(domain),
                    'suspicious_patterns': self._check_suspicious_patterns(url)
                }
                
                urls.append(url_data)
            except:
                continue
        
        return urls
    
    def _extract_metadata(self, msg: email.message.Message, file_path: str) -> Dict[str, Any]:
        """Extract additional metadata"""
        metadata = {
            'file_size': os.path.getsize(file_path),
            'is_multipart': msg.is_multipart(),
            'content_type': msg.get_content_type(),
            'encoding': msg.get_content_charset(),
            'boundary': msg.get_boundary(),
            'date_parsed': None,
            'sender_parsed': None,
            'recipients_parsed': []
        }
        
        # Parse date
        date_header = msg.get('Date')
        if date_header:
            try:
                metadata['date_parsed'] = parsedate_to_datetime(date_header).isoformat()
            except:
                pass
        
        # Parse sender
        from_header = msg.get('From')
        if from_header:
            try:
                name, email_addr = parseaddr(from_header)
                metadata['sender_parsed'] = {
                    'name': name,
                    'email': email_addr
                }
            except:
                pass
        
        # Parse recipients
        for header in ['To', 'Cc', 'Bcc']:
            header_value = msg.get(header)
            if header_value:
                try:
                    recipients = email.utils.getaddresses([header_value])
                    for name, email_addr in recipients:
                        metadata['recipients_parsed'].append({
                            'name': name,
                            'email': email_addr,
                            'type': header.lower()
                        })
                except:
                    pass
        
        return metadata
    
    def _decode_header(self, header_value: str) -> str:
        """Decode email header value"""
        try:
            decoded_parts = decode_header(header_value)
            decoded_string = ""
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_string += part.decode(encoding, errors='ignore')
                    else:
                        decoded_string += part.decode('utf-8', errors='ignore')
                else:
                    decoded_string += part
            return decoded_string
        except:
            return str(header_value)
    
    def _is_executable(self, file_ext: str) -> bool:
        """Check if file extension is executable"""
        executable_extensions = {'.exe', '.msi', '.bat', '.cmd', '.scr', '.com', '.pif', '.jar'}
        return file_ext.lower() in executable_extensions
    
    def _is_archive(self, file_ext: str) -> bool:
        """Check if file extension is an archive"""
        archive_extensions = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'}
        return file_ext.lower() in archive_extensions
    
    def _is_image(self, file_ext: str) -> bool:
        """Check if file extension is an image"""
        image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg', '.webp'}
        return file_ext.lower() in image_extensions
    
    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False
    
    def _is_shortened_url(self, domain: str) -> bool:
        """Check if domain is a known URL shortener"""
        shorteners = {
            'bit.ly', 'tinyurl.com', 'short.link', 't.co', 'goo.gl',
            'ow.ly', 'buff.ly', 'is.gd', 'v.gd', 'shorturl.at'
        }
        return domain.lower() in shorteners
    
    def _check_suspicious_patterns(self, url: str) -> List[str]:
        """Check for suspicious URL patterns"""
        suspicious = []
        
        # Check for suspicious patterns
        if re.search(r'\d+\.\d+\.\d+\.\d+', url):
            suspicious.append('contains_ip_address')
        
        if re.search(r'[^\w\.-]', urlparse(url).netloc):
            suspicious.append('suspicious_characters_in_domain')
        
        if len(urlparse(url).netloc) > 50:
            suspicious.append('very_long_domain')
        
        if url.count('.') > 5:
            suspicious.append('many_subdomains')
        
        return suspicious

# Example usage
if __name__ == "__main__":
    parser = EmailParser()
    
    # Test with a sample email file
    sample_file = "sample.eml"
    if os.path.exists(sample_file):
        result = parser.parse_email_file(sample_file)
        print(json.dumps(result, indent=2, default=str))
    else:
        print("No sample email file found")
