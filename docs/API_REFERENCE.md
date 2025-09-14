# API Reference

## Base URL
```
http://localhost:8080
```

## Authentication
Currently no authentication required. All endpoints are publicly accessible.

## Endpoints

### Health Check
```http
GET /
```

**Response:**
```json
{
  "status": "ok",
  "message": "Email Analysis API with Advanced Scanning is running"
}
```

### Upload Email for Analysis
```http
POST /upload
Content-Type: multipart/form-data
```

**Parameters:**
- `file` (required): Email file (.eml format recommended)

**Response:**
```json
{
  "success": true,
  "filename": "email.eml",
  "content_type": "application/octet-stream",
  "file_size": 1024,
  "message": "Successfully received email.eml (1024 bytes), parsed email content, calculated risk score (HIGH), scanned with ClamAV (clean) and YARA (clean) (saved to database as ID 1)",
  "analysis_id": 1,
  "email_info": {
    "subject": "Email Subject",
    "sender": "sender@example.com",
    "recipient": "recipient@example.com",
    "date": "Mon, 14 Sep 2024 10:30:00 +0000",
    "message_id": "<message@example.com>",
    "body_preview": "Email body content...",
    "body_length": 500
  },
  "risk_analysis": {
    "risk_score": 75,
    "risk_level": "HIGH",
    "risk_reasons": [
      "Suspicious subject pattern: 'urgent'",
      "International domain detected: .fj"
    ],
    "total_checks": 2
  },
  "clamav_result": {
    "status": "clean",
    "message": "No threats detected",
    "details": "/tmp/file.eml: OK"
  },
  "yara_result": {
    "status": "clean",
    "message": "No YARA rule matches",
    "details": "File does not match any known patterns"
  }
}
```

### Get Analysis History
```http
GET /history?limit=10
```

**Parameters:**
- `limit` (optional): Number of analyses to return (default: 10)

**Response:**
```json
{
  "history": [
    {
      "id": 1,
      "filename": "email.eml",
      "subject": "Email Subject",
      "sender": "sender@example.com",
      "risk_score": 75,
      "risk_level": "HIGH",
      "clamav_result": {
        "status": "clean",
        "message": "No threats detected"
      },
      "yara_result": {
        "status": "clean",
        "message": "No YARA rule matches"
      },
      "created_at": "2024-09-14 16:51:12"
    }
  ],
  "count": 1
}
```

### Get Detailed Analysis
```http
GET /analysis/{id}
```

**Parameters:**
- `id` (required): Analysis ID

**Response:**
```json
{
  "id": 1,
  "filename": "email.eml",
  "file_size": 1024,
  "content_type": "application/octet-stream",
  "subject": "Email Subject",
  "sender": "sender@example.com",
  "recipient": "recipient@example.com",
  "date": "Mon, 14 Sep 2024 10:30:00 +0000",
  "message_id": "<message@example.com>",
  "body_preview": "Email body content...",
  "body_length": 500,
  "risk_score": 75,
  "risk_level": "HIGH",
  "risk_reasons": [
    "Suspicious subject pattern: 'urgent'",
    "International domain detected: .fj"
  ],
  "total_checks": 2,
  "clamav_result": {
    "status": "clean",
    "message": "No threats detected",
    "details": "/tmp/file.eml: OK"
  },
  "yara_result": {
    "status": "clean",
    "message": "No YARA rule matches",
    "details": "File does not match any known patterns"
  },
  "created_at": "2024-09-14 16:51:12"
}
```

## Error Responses

### File Not Found
```json
{
  "error": "Analysis not found"
}
```

### Upload Error
```json
{
  "error": "No filename provided"
}
```

### Database Error
```json
{
  "success": true,
  "filename": "email.eml",
  "database_error": "Failed to save to database: table email_analyses has no column named clamav_result"
}
```

## Risk Levels

| Level | Score Range | Description |
|-------|-------------|-------------|
| SAFE | 0-19 | No suspicious patterns detected |
| LOW | 20-39 | Minor concerns, low risk |
| MEDIUM | 40-69 | Moderate risk indicators |
| HIGH | 70-99 | Significant threat indicators |
| CRITICAL | 100 | Virus detected or severe threat |

## Scanning Results

### ClamAV Status
- `clean`: No threats detected
- `infected`: Virus or malware found
- `error`: Scan failed
- `timeout`: Scan timed out

### YARA Status
- `clean`: No rule matches
- `matched`: One or more rules triggered
- `error`: Scan failed
- `timeout`: Scan timed out
- `no_rules`: YARA rules file not found

## Example Usage

### cURL Examples

```bash
# Health check
curl http://localhost:8080/

# Upload email
curl -X POST -F "file=@email.eml" http://localhost:8080/upload

# Get history
curl http://localhost:8080/history

# Get specific analysis
curl http://localhost:8080/analysis/1
```

### Python Example

```python
import requests

# Upload email
with open('email.eml', 'rb') as f:
    response = requests.post('http://localhost:8080/upload', 
                           files={'file': f})
    result = response.json()
    print(f"Risk Level: {result['risk_analysis']['risk_level']}")

# Get history
response = requests.get('http://localhost:8080/history')
history = response.json()
for analysis in history['history']:
    print(f"ID {analysis['id']}: {analysis['subject']} - {analysis['risk_level']}")
```

### JavaScript Example

```javascript
// Upload email
const formData = new FormData();
formData.append('file', fileInput.files[0]);

fetch('http://localhost:8080/upload', {
    method: 'POST',
    body: formData
})
.then(response => response.json())
.then(data => {
    console.log('Risk Level:', data.risk_analysis.risk_level);
    console.log('ClamAV:', data.clamav_result.status);
    console.log('YARA:', data.yara_result.status);
});

// Get history
fetch('http://localhost:8080/history')
.then(response => response.json())
.then(data => {
    data.history.forEach(analysis => {
        console.log(`ID ${analysis.id}: ${analysis.subject}`);
    });
});
```

## Rate Limits
Currently no rate limits implemented. Consider implementing for production use.

## CORS
CORS is enabled for all origins to support web UI development. Restrict in production.

## Timeouts
- File upload: 30 seconds
- ClamAV scan: 30 seconds  
- YARA scan: 30 seconds
- Database operations: 10 seconds
