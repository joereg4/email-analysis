# Email Analysis Sandbox

A comprehensive email security analysis platform built with Docker, featuring AI-powered threat detection, multiple scanning engines, and automated processing workflows.

## Features

- **Automated Email Processing**: Drop `.eml` files into the inbox folder for automatic analysis
- **Multi-Engine Scanning**: ClamAV, YARA, EXIF, OCR, and URL analysis
- **AI-Powered Analysis**: OpenAI integration for intelligent threat assessment
- **Real-time Monitoring**: File watcher automatically processes new emails
- **Comprehensive Reporting**: Detailed analysis results with risk scoring
- **Quarantine System**: Automatic isolation of suspicious content
- **REST API**: Full API for integration and management
- **SQLite Database**: Persistent storage of analysis results

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   File Watcher  │    │   FastAPI API   │    │  Background     │
│                 │    │                 │    │  Worker         │
│ Monitors inbox  │───▶│ Orchestrates    │───▶│ Processes       │
│ for new emails  │    │ analysis flow   │    │ analysis tasks  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │   SQLite DB     │    │  Scanning       │
                       │                 │    │  Engines        │
                       │ Stores results  │    │ ClamAV/YARA/OCR │
                       └─────────────────┘    └─────────────────┘
```

## Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd email-analysis
```

### 2. Configure Environment

Copy the example configuration and update with your API keys:

```bash
cp config.env .env
# Edit .env with your API keys
```

Required API keys:
- `OPENAI_API_KEY`: Your OpenAI API key for AI analysis
- `VIRUSTOTAL_API_KEY`: Your VirusTotal API key for URL analysis

### 3. Start the Services

```bash
docker-compose up -d
```

### 4. Upload Emails

Drop `.eml` files into the `data/inbox/` directory. The system will automatically:
1. Parse the email content
2. Scan attachments with ClamAV and YARA
3. Extract EXIF data from images
4. Perform OCR on images and PDFs
5. Analyze URLs with VirusTotal
6. Generate AI-powered risk assessment

### 5. View Results

**🌐 Streamlit Web UI (Recommended)**: `http://localhost:8501`
- User-friendly interface for uploading emails
- Visual dashboards and charts
- Easy-to-understand risk indicators
- One-click actions (quarantine, delete, etc.)

**📡 API Access**: `http://localhost:8080`
- REST API for programmatic access
- Interactive documentation at `/docs`

## API Endpoints

### Core Endpoints

- `GET /` - Health check
- `POST /upload` - Upload email file
- `GET /analyses` - List all analyses
- `GET /analyses/{id}` - Get specific analysis
- `GET /summary` - Get analysis summary statistics

### Analysis Endpoints

- `GET /analyses/{id}/attachments` - Get attachment details
- `GET /analyses/{id}/urls` - Get URL analysis results
- `GET /analyses/{id}/logs` - Get scan logs
- `POST /analyses/{id}/quarantine` - Quarantine analysis
- `DELETE /analyses/{id}` - Delete analysis

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key for AI analysis | Required |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key for URL analysis | Optional |
| `DATABASE_URL` | SQLite database path | `sqlite:///app/data/db/email_analysis.db` |
| `REDIS_URL` | Redis connection URL | `redis://redis:6379` |
| `CLAMAV_HOST` | ClamAV server host | `clamav` |
| `CLAMAV_PORT` | ClamAV server port | `3310` |

### File Paths

- `INBOX_PATH`: Directory to monitor for new emails
- `QUARANTINE_PATH`: Directory for quarantined files
- `ARTIFACTS_PATH`: Directory for analysis artifacts
- `DB_PATH`: Database directory
- `LOGS_PATH`: Log files directory

## Scanning Engines

### ClamAV
- Antivirus scanning of email files and attachments
- Real-time virus detection
- Automatic quarantine of infected files

### YARA
- Custom rule-based detection
- Malware signature matching
- Suspicious pattern detection
- Extensible rule system

### EXIF Analysis
- Image metadata extraction
- GPS location detection
- Camera information analysis
- Suspicious metadata detection

### OCR (Optical Character Recognition)
- Text extraction from images and PDFs
- Suspicious content detection
- Phishing keyword analysis
- Malware indicator identification

### URL Analysis
- VirusTotal integration
- Domain reputation checking
- Suspicious URL pattern detection
- WHOIS information analysis

### OpenAI Integration
- Intelligent content analysis
- Risk assessment and scoring
- Threat identification
- Actionable recommendations

## Database Schema

### EmailAnalysis
- Core email analysis record
- Metadata, headers, and content
- Risk scoring and assessment
- Processing status and timestamps

### Attachment
- Attachment details and scan results
- File hashes and metadata
- Quarantine status

### URLAnalysis
- URL analysis results
- VirusTotal and WHOIS data
- Reputation scores

### ScanLog
- Detailed scan operation logs
- Performance metrics
- Error tracking

## Security Features

### Quarantine System
- Automatic isolation of suspicious content
- Configurable quarantine triggers
- Safe storage of potentially malicious files

### Risk Scoring
- Multi-factor risk assessment
- Weighted scoring algorithm
- Configurable risk thresholds

### Access Control
- API-based access control
- Secure file handling
- Audit logging

## Development

### Adding New Scanners

1. Create scanner module in `services/scanners/`
2. Implement scanner interface
3. Add to `EmailScanner` class
4. Update worker to use new scanner

### Adding New YARA Rules

1. Add `.yar` files to `services/scanners/yara_rules/`
2. Rules are automatically loaded on startup
3. Use YARA syntax for rule definition

### Customizing Analysis

1. Modify `EmailParser` for email parsing
2. Update `URLAnalyzer` for URL analysis
3. Customize OpenAI prompts in worker
4. Add new risk scoring factors

## Troubleshooting

### Common Issues

1. **ClamAV Connection Failed**
   - Check ClamAV service status
   - Verify network connectivity
   - Check firewall settings

2. **OpenAI API Errors**
   - Verify API key configuration
   - Check API quota and limits
   - Review rate limiting

3. **File Upload Issues**
   - Check file permissions
   - Verify disk space
   - Review file size limits

4. **Database Errors**
   - Check database file permissions
   - Verify disk space
   - Review SQLite configuration

### Logs

- API logs: `data/logs/api.log`
- Worker logs: `data/logs/worker.log`
- Watcher logs: `data/logs/watcher.log`

### Monitoring

- Health check: `GET /`
- Service status: `docker-compose ps`
- Resource usage: `docker stats`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the logs
3. Open an issue on GitHub
4. Contact the maintainers

## Changelog

### Version 1.0.0
- Initial release
- Core email analysis functionality
- Multi-engine scanning
- AI-powered threat detection
- REST API and web interface
- Docker containerization
