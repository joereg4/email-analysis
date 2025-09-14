import os
import json
import requests
import time
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from urllib.parse import urlparse
import ipaddress
import re

logger = logging.getLogger(__name__)

class URLAnalyzer:
    def __init__(self):
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'EmailAnalysisSandbox/1.0'
        })
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 1.0  # 1 second between requests
    
    def analyze_urls(self, urls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze a list of URLs"""
        results = []
        
        for url_data in urls:
            url = url_data.get('url', '')
            if url:
                result = self.analyze_single_url(url)
                result.update(url_data)  # Include original URL data
                results.append(result)
        
        return results
    
    def analyze_single_url(self, url: str) -> Dict[str, Any]:
        """Analyze a single URL"""
        result = {
            'url': url,
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'domain_analysis': {},
            'virustotal_analysis': {},
            'whois_analysis': {},
            'reputation_score': 0.0,
            'risk_level': 'unknown',
            'threats_detected': [],
            'analysis_errors': []
        }
        
        try:
            # Parse URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Domain analysis
            result['domain_analysis'] = self._analyze_domain(domain)
            
            # VirusTotal analysis
            if self.virustotal_api_key:
                result['virustotal_analysis'] = self._analyze_virustotal(url)
            
            # WHOIS analysis
            result['whois_analysis'] = self._analyze_whois(domain)
            
            # Calculate reputation score
            result['reputation_score'] = self._calculate_reputation_score(result)
            result['risk_level'] = self._determine_risk_level(result['reputation_score'])
            result['threats_detected'] = self._identify_threats(result)
            
        except Exception as e:
            result['analysis_errors'].append(str(e))
            logger.error(f"Error analyzing URL {url}: {e}")
        
        return result
    
    def _analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze domain characteristics"""
        analysis = {
            'domain': domain,
            'is_ip_address': False,
            'is_shortened': False,
            'is_suspicious': False,
            'suspicious_patterns': [],
            'age_indicators': {},
            'dns_analysis': {}
        }
        
        # Check if domain is an IP address
        try:
            ipaddress.ip_address(domain)
            analysis['is_ip_address'] = True
            analysis['suspicious_patterns'].append('uses_ip_address')
        except ValueError:
            pass
        
        # Check for URL shorteners
        shorteners = {
            'bit.ly', 'tinyurl.com', 'short.link', 't.co', 'goo.gl',
            'ow.ly', 'buff.ly', 'is.gd', 'v.gd', 'shorturl.at',
            'tiny.cc', 'short.to', 'clck.ru', 'cutt.ly'
        }
        
        if domain.lower() in shorteners:
            analysis['is_shortened'] = True
            analysis['suspicious_patterns'].append('url_shortener')
        
        # Check for suspicious patterns
        suspicious_patterns = [
            ('free', 'contains_free'),
            ('win', 'contains_win'),
            ('prize', 'contains_prize'),
            ('lottery', 'contains_lottery'),
            ('congratulations', 'contains_congratulations'),
            ('click', 'contains_click'),
            ('verify', 'contains_verify'),
            ('account', 'contains_account'),
            ('security', 'contains_security'),
            ('update', 'contains_update')
        ]
        
        domain_lower = domain.lower()
        for pattern, description in suspicious_patterns:
            if pattern in domain_lower:
                analysis['suspicious_patterns'].append(description)
        
        # Check for typosquatting patterns
        if self._check_typosquatting(domain):
            analysis['suspicious_patterns'].append('possible_typosquatting')
        
        # Check for subdomain abuse
        if domain.count('.') > 3:
            analysis['suspicious_patterns'].append('many_subdomains')
        
        # DNS analysis
        analysis['dns_analysis'] = self._analyze_dns(domain)
        
        analysis['is_suspicious'] = len(analysis['suspicious_patterns']) > 0
        
        return analysis
    
    def _analyze_virustotal(self, url: str) -> Dict[str, Any]:
        """Analyze URL with VirusTotal"""
        if not self.virustotal_api_key:
            return {'error': 'VirusTotal API key not configured'}
        
        # Rate limiting
        self._rate_limit()
        
        try:
            # Submit URL for analysis
            submit_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
            submit_data = {
                'apikey': self.virustotal_api_key,
                'url': url
            }
            
            response = self.session.post(submit_url, data=submit_data, timeout=30)
            
            if response.status_code == 200:
                submit_result = response.json()
                scan_id = submit_result.get('scan_id')
                
                if scan_id:
                    # Wait a bit for analysis to complete
                    time.sleep(2)
                    
                    # Get report
                    report_url = 'https://www.virustotal.com/vtapi/v2/url/report'
                    report_data = {
                        'apikey': self.virustotal_api_key,
                        'resource': scan_id
                    }
                    
                    report_response = self.session.get(report_url, params=report_data, timeout=30)
                    
                    if report_response.status_code == 200:
                        report = report_response.json()
                        
                        return {
                            'scan_id': scan_id,
                            'positives': report.get('positives', 0),
                            'total': report.get('total', 0),
                            'scan_date': report.get('scan_date'),
                            'permalink': report.get('permalink'),
                            'scans': report.get('scans', {}),
                            'detected': report.get('positives', 0) > 0
                        }
                    else:
                        return {'error': f'Failed to get report: {report_response.status_code}'}
                else:
                    return {'error': 'No scan ID returned'}
            else:
                return {'error': f'Failed to submit URL: {response.status_code}'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_whois(self, domain: str) -> Dict[str, Any]:
        """Analyze domain WHOIS information"""
        # Note: This is a simplified WHOIS analysis
        # In a production environment, you'd want to use a proper WHOIS library
        
        analysis = {
            'domain': domain,
            'registrar': 'unknown',
            'creation_date': 'unknown',
            'expiration_date': 'unknown',
            'name_servers': [],
            'registrant_country': 'unknown',
            'suspicious_indicators': []
        }
        
        try:
            # This is a placeholder - you would implement actual WHOIS lookup here
            # For now, we'll do basic pattern analysis
            
            # Check for suspicious domain patterns
            if domain.count('.') > 2:
                analysis['suspicious_indicators'].append('many_subdomains')
            
            # Check for recently registered domains (would need actual WHOIS data)
            # This is just a placeholder
            analysis['suspicious_indicators'].append('whois_analysis_placeholder')
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_dns(self, domain: str) -> Dict[str, Any]:
        """Analyze DNS records for the domain"""
        dns_analysis = {
            'domain': domain,
            'a_records': [],
            'mx_records': [],
            'txt_records': [],
            'suspicious_indicators': []
        }
        
        try:
            import socket
            
            # Get A records
            try:
                a_records = socket.gethostbyname_ex(domain)
                dns_analysis['a_records'] = a_records[2]
            except:
                dns_analysis['suspicious_indicators'].append('no_a_records')
            
            # Check for suspicious IP ranges
            for ip in dns_analysis['a_records']:
                if self._is_suspicious_ip(ip):
                    dns_analysis['suspicious_indicators'].append(f'suspicious_ip: {ip}')
            
        except Exception as e:
            dns_analysis['error'] = str(e)
        
        return dns_analysis
    
    def _check_typosquatting(self, domain: str) -> bool:
        """Check for potential typosquatting"""
        # This is a simplified check - in production you'd want more sophisticated analysis
        
        # Common typosquatting patterns
        suspicious_patterns = [
            r'[a-z]{1,3}[0-9]{1,3}[a-z]{1,3}',  # Mixed letters and numbers
            r'[0-9]{4,}',  # Many numbers
            r'[a-z]{10,}',  # Very long domain names
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain):
                return True
        
        return False
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP address is suspicious"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check for private IPs
            if ip_obj.is_private:
                return True
            
            # Check for reserved IPs
            if ip_obj.is_reserved:
                return True
            
            # Check for loopback
            if ip_obj.is_loopback:
                return True
            
            # Check for link-local
            if ip_obj.is_link_local:
                return True
            
        except ValueError:
            pass
        
        return False
    
    def _calculate_reputation_score(self, analysis: Dict[str, Any]) -> float:
        """Calculate reputation score based on analysis results"""
        score = 50.0  # Start with neutral score
        
        # Domain analysis scoring
        domain_analysis = analysis.get('domain_analysis', {})
        
        if domain_analysis.get('is_ip_address'):
            score -= 20.0
        
        if domain_analysis.get('is_shortened'):
            score -= 10.0
        
        suspicious_patterns = domain_analysis.get('suspicious_patterns', [])
        score -= len(suspicious_patterns) * 5.0
        
        # VirusTotal scoring
        vt_analysis = analysis.get('virustotal_analysis', {})
        if vt_analysis.get('detected'):
            positives = vt_analysis.get('positives', 0)
            total = vt_analysis.get('total', 1)
            detection_rate = positives / total if total > 0 else 0
            score -= detection_rate * 50.0
        
        # DNS analysis scoring
        dns_analysis = domain_analysis.get('dns_analysis', {})
        dns_suspicious = dns_analysis.get('suspicious_indicators', [])
        score -= len(dns_suspicious) * 5.0
        
        return max(0.0, min(100.0, score))  # Clamp between 0 and 100
    
    def _determine_risk_level(self, reputation_score: float) -> str:
        """Determine risk level based on reputation score"""
        if reputation_score >= 80:
            return 'low'
        elif reputation_score >= 60:
            return 'medium'
        elif reputation_score >= 40:
            return 'high'
        else:
            return 'critical'
    
    def _identify_threats(self, analysis: Dict[str, Any]) -> List[str]:
        """Identify specific threats from analysis"""
        threats = []
        
        # Domain threats
        domain_analysis = analysis.get('domain_analysis', {})
        if domain_analysis.get('is_ip_address'):
            threats.append('Uses IP address instead of domain')
        
        if domain_analysis.get('is_shortened'):
            threats.append('URL shortener detected')
        
        suspicious_patterns = domain_analysis.get('suspicious_patterns', [])
        for pattern in suspicious_patterns:
            threats.append(f'Suspicious domain pattern: {pattern}')
        
        # VirusTotal threats
        vt_analysis = analysis.get('virustotal_analysis', {})
        if vt_analysis.get('detected'):
            positives = vt_analysis.get('positives', 0)
            threats.append(f'Detected by {positives} antivirus engines')
        
        # DNS threats
        dns_analysis = domain_analysis.get('dns_analysis', {})
        dns_suspicious = dns_analysis.get('suspicious_indicators', [])
        for indicator in dns_suspicious:
            threats.append(f'DNS issue: {indicator}')
        
        return threats
    
    def _rate_limit(self):
        """Implement rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def batch_analyze_urls(self, urls: List[str], max_concurrent: int = 5) -> List[Dict[str, Any]]:
        """Analyze multiple URLs with concurrency control"""
        results = []
        
        for i in range(0, len(urls), max_concurrent):
            batch = urls[i:i + max_concurrent]
            batch_results = []
            
            for url in batch:
                result = self.analyze_single_url(url)
                batch_results.append(result)
            
            results.extend(batch_results)
            
            # Rate limiting between batches
            if i + max_concurrent < len(urls):
                time.sleep(2)
        
        return results

# Example usage
if __name__ == "__main__":
    analyzer = URLAnalyzer()
    
    # Test with sample URLs
    test_urls = [
        {'url': 'https://example.com'},
        {'url': 'https://bit.ly/shortlink'},
        {'url': 'http://192.168.1.1'}
    ]
    
    results = analyzer.analyze_urls(test_urls)
    print(json.dumps(results, indent=2, default=str))
