#!/usr/bin/env python3
"""
Comprehensive test script for Email Analysis API
Tests all features: File Upload, Email Parsing, Risk Scoring
"""

import requests
import json
import time

API_BASE = "http://localhost:8080"

def test_api_health():
    """Test that the API is running"""
    print("🔍 Testing API Health...")
    try:
        response = requests.get(f"{API_BASE}/")
        if response.status_code == 200:
            print("✅ API is running")
            print(f"   Response: {response.json()}")
            return True
        else:
            print(f"❌ API health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ API health check failed: {e}")
        return False

def test_file_upload(filename, expected_type="email"):
    """Test file upload and analysis"""
    print(f"\n📧 Testing {filename}...")
    
    try:
        with open(filename, 'rb') as f:
            files = {'file': (filename, f, 'application/octet-stream')}
            response = requests.post(f"{API_BASE}/upload", files=files)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Upload successful")
            print(f"   File: {data['filename']} ({data['file_size']} bytes)")
            
            if 'email_info' in data:
                email_info = data['email_info']
                print(f"   Subject: {email_info['subject']}")
                print(f"   From: {email_info['sender']}")
                print(f"   To: {email_info['recipient']}")
                
                if 'risk_analysis' in data:
                    risk = data['risk_analysis']
                    print(f"   Risk Score: {risk['risk_score']}/100 ({risk['risk_level']})")
                    if risk['risk_reasons']:
                        print(f"   Risk Reasons:")
                        for reason in risk['risk_reasons']:
                            print(f"     - {reason}")
                    else:
                        print(f"   Risk Reasons: None (clean email)")
            else:
                print(f"   Message: {data['message']}")
            
            return True
        else:
            print(f"❌ Upload failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Upload failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 Email Analysis API - Comprehensive Test Suite")
    print("=" * 50)
    
    # Test API health
    if not test_api_health():
        print("\n❌ API is not running. Please start it first:")
        print("   docker run -d --name minimal-api -p 8080:8080 minimal-api")
        return
    
    # Test different email types
    test_files = [
        ("safe_email.eml", "Safe business email"),
        ("suspicious_email.eml", "Suspicious phishing email"),
        ("sample.eml", "Basic test email"),
        ("test.txt", "Non-email file")
    ]
    
    results = []
    for filename, description in test_files:
        print(f"\n📋 {description}")
        print("-" * 30)
        success = test_file_upload(filename)
        results.append((filename, success))
        time.sleep(1)  # Brief pause between tests
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 TEST SUMMARY")
    print("=" * 50)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for filename, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {filename}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The Email Analysis API is working correctly.")
    else:
        print("⚠️  Some tests failed. Check the output above for details.")

if __name__ == "__main__":
    main()
