#!/usr/bin/env python3
"""
Comprehensive Test Suite for Email Analysis System
Tests all components: API, Database, Scanning, UI
"""

import requests
import json
import time
import os
import sys
from typing import Dict, List, Any

class EmailAnalysisTestSuite:
    def __init__(self, api_base: str = "http://localhost:8080"):
        self.api_base = api_base
        self.test_results = []
        self.sample_files = {
            "safe": "samples/safe_email.eml",
            "suspicious": "samples/suspicious_email.eml", 
            "fiji": "samples/fiji_suspicious.eml",
            "yara": "samples/test_yara.eml"
        }
    
    def log_test(self, test_name: str, success: bool, message: str = ""):
        """Log test result"""
        status = "✅ PASS" if success else "❌ FAIL"
        result = {
            "test": test_name,
            "status": status,
            "success": success,
            "message": message,
            "timestamp": time.time()
        }
        self.test_results.append(result)
        print(f"{status} {test_name}: {message}")
    
    def test_api_health(self) -> bool:
        """Test API health endpoint"""
        try:
            response = requests.get(f"{self.api_base}/", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if "Advanced Scanning" in data.get("message", ""):
                    self.log_test("API Health Check", True, "API is running with advanced scanning")
                    return True
                else:
                    self.log_test("API Health Check", False, "API running but not advanced scanning version")
                    return False
            else:
                self.log_test("API Health Check", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_test("API Health Check", False, str(e))
            return False
    
    def test_file_upload(self, filename: str, expected_risk: str = None) -> Dict:
        """Test file upload and analysis"""
        if not os.path.exists(filename):
            self.log_test(f"Upload {filename}", False, "File not found")
            return {}
        
        try:
            with open(filename, 'rb') as f:
                files = {'file': (filename, f, 'application/octet-stream')}
                response = requests.post(f"{self.api_base}/upload", files=files, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    risk_level = data.get('risk_analysis', {}).get('risk_level', 'UNKNOWN')
                    analysis_id = data.get('analysis_id')
                    
                    message = f"Uploaded successfully, Risk: {risk_level}"
                    if analysis_id:
                        message += f", ID: {analysis_id}"
                    
                    success = True
                    if expected_risk and risk_level != expected_risk:
                        success = False
                        message += f" (Expected: {expected_risk})"
                    
                    self.log_test(f"Upload {os.path.basename(filename)}", success, message)
                    return data
                else:
                    self.log_test(f"Upload {os.path.basename(filename)}", False, "Upload failed")
                    return {}
            else:
                self.log_test(f"Upload {os.path.basename(filename)}", False, f"HTTP {response.status_code}")
                return {}
        except Exception as e:
            self.log_test(f"Upload {os.path.basename(filename)}", False, str(e))
            return {}
    
    def test_scanning_results(self, analysis_data: Dict) -> bool:
        """Test that scanning results are present"""
        if not analysis_data:
            return False
        
        clamav_result = analysis_data.get('clamav_result', {})
        yara_result = analysis_data.get('yara_result', {})
        
        clamav_ok = clamav_result.get('status') in ['clean', 'infected', 'error']
        yara_ok = yara_result.get('status') in ['clean', 'matched', 'error']
        
        if clamav_ok and yara_ok:
            self.log_test("Scanning Results", True, 
                         f"ClamAV: {clamav_result.get('status')}, YARA: {yara_result.get('status')}")
            return True
        else:
            self.log_test("Scanning Results", False, 
                         f"ClamAV: {clamav_result.get('status')}, YARA: {yara_result.get('status')}")
            return False
    
    def test_database_storage(self, analysis_data: Dict) -> bool:
        """Test database storage"""
        if not analysis_data:
            return False
        
        analysis_id = analysis_data.get('analysis_id')
        if analysis_id:
            self.log_test("Database Storage", True, f"Analysis saved with ID {analysis_id}")
            return True
        else:
            self.log_test("Database Storage", False, "No analysis ID returned")
            return False
    
    def test_history_endpoint(self) -> bool:
        """Test history endpoint"""
        try:
            response = requests.get(f"{self.api_base}/history", timeout=10)
            if response.status_code == 200:
                data = response.json()
                history = data.get('history', [])
                count = data.get('count', 0)
                
                if len(history) > 0:
                    self.log_test("History Endpoint", True, f"Retrieved {count} analyses")
                    return True
                else:
                    self.log_test("History Endpoint", False, "No history found")
                    return False
            else:
                self.log_test("History Endpoint", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_test("History Endpoint", False, str(e))
            return False
    
    def test_detailed_analysis(self, analysis_id: int) -> bool:
        """Test detailed analysis retrieval"""
        try:
            response = requests.get(f"{self.api_base}/analysis/{analysis_id}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'error' not in data:
                    self.log_test("Detailed Analysis", True, f"Retrieved analysis {analysis_id}")
                    return True
                else:
                    self.log_test("Detailed Analysis", False, data.get('error', 'Unknown error'))
                    return False
            else:
                self.log_test("Detailed Analysis", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Detailed Analysis", False, str(e))
            return False
    
    def test_risk_scoring(self, analysis_data: Dict, expected_level: str = None) -> bool:
        """Test risk scoring accuracy"""
        if not analysis_data:
            return False
        
        risk_analysis = analysis_data.get('risk_analysis', {})
        risk_level = risk_analysis.get('risk_level', 'UNKNOWN')
        risk_score = risk_analysis.get('risk_score', 0)
        risk_reasons = risk_analysis.get('risk_reasons', [])
        
        # Basic validation
        if risk_level in ['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] and 0 <= risk_score <= 100:
            success = True
            message = f"Risk: {risk_level} ({risk_score}/100), {len(risk_reasons)} reasons"
            
            if expected_level and risk_level != expected_level:
                success = False
                message += f" (Expected: {expected_level})"
            
            self.log_test("Risk Scoring", success, message)
            return success
        else:
            self.log_test("Risk Scoring", False, f"Invalid risk data: {risk_level}, {risk_score}")
            return False
    
    def run_all_tests(self) -> Dict:
        """Run complete test suite"""
        print("🧪 Email Analysis Test Suite")
        print("=" * 50)
        
        # Test API health
        if not self.test_api_health():
            print("\n❌ API not available, stopping tests")
            return self.get_summary()
        
        # Test file uploads with different risk levels
        test_files = [
            ("safe", "SAFE"),
            ("suspicious", "HIGH"), 
            ("fiji", "HIGH"),
            ("yara", "HIGH")
        ]
        
        uploaded_analyses = []
        for file_key, expected_risk in test_files:
            if file_key in self.sample_files:
                analysis_data = self.test_file_upload(self.sample_files[file_key], expected_risk)
                if analysis_data:
                    uploaded_analyses.append(analysis_data)
                    self.test_scanning_results(analysis_data)
                    self.test_database_storage(analysis_data)
                    self.test_risk_scoring(analysis_data, expected_risk)
        
        # Test API endpoints
        self.test_history_endpoint()
        
        # Test detailed analysis retrieval
        if uploaded_analyses:
            first_analysis = uploaded_analyses[0]
            analysis_id = first_analysis.get('analysis_id')
            if analysis_id:
                self.test_detailed_analysis(analysis_id)
        
        return self.get_summary()
    
    def get_summary(self) -> Dict:
        """Get test summary"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['success'])
        failed_tests = total_tests - passed_tests
        
        summary = {
            "total": total_tests,
            "passed": passed_tests,
            "failed": failed_tests,
            "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0,
            "results": self.test_results
        }
        
        print("\n" + "=" * 50)
        print("📊 TEST SUMMARY")
        print("=" * 50)
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success Rate: {summary['success_rate']:.1f}%")
        
        if failed_tests > 0:
            print("\n❌ Failed Tests:")
            for result in self.test_results:
                if not result['success']:
                    print(f"  - {result['test']}: {result['message']}")
        
        if summary['success_rate'] == 100:
            print("\n🎉 All tests passed! System is working correctly.")
        elif summary['success_rate'] >= 80:
            print("\n⚠️  Most tests passed, but some issues detected.")
        else:
            print("\n🚨 Multiple test failures detected. Check system status.")
        
        return summary

def main():
    """Main test runner"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Email Analysis Test Suite')
    parser.add_argument('--api-base', default='http://localhost:8080', 
                       help='API base URL (default: http://localhost:8080)')
    parser.add_argument('--output', help='Output results to JSON file')
    
    args = parser.parse_args()
    
    # Run tests
    test_suite = EmailAnalysisTestSuite(args.api_base)
    summary = test_suite.run_all_tests()
    
    # Save results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(summary, f, indent=2)
        print(f"\n📄 Results saved to {args.output}")
    
    # Exit with appropriate code
    sys.exit(0 if summary['failed'] == 0 else 1)

if __name__ == "__main__":
    main()
