# Email Analysis Sandbox

A comprehensive email security analysis platform built with Docker, featuring advanced threat detection, multiple scanning engines, and a modern web interface.

## Features

- **Streamlit Web Dashboard**: Modern, responsive interface for email analysis
- **Multi-Engine Scanning**: ClamAV antivirus and YARA rule-based detection
- **One-Click Analysis**: Simple dropdown interface to view complete details
- **Risk Assessment**: Color-coded risk levels with interactive gauges
- **Comprehensive Reporting**: Detailed analysis results with threat indicators
- **REST API**: Full API for integration and programmatic access
- **SQLite Database**: Persistent storage of analysis results and history
- **Docker Containerization**: Isolated, secure scanning environment

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Streamlit     │    │   FastAPI       │    │   Database      │
│   Web Dashboard │◄──►│   (Python)      │◄──►│   (SQLite)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   ClamAV        │
                       │   + YARA        │
                       └─────────────────┘
```

## Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd email-analysis
```

### 2. Configure Environment (Optional)

Create a `.env` file for optional API keys:

```bash
# Optional: External APIs
OPENAI_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```

Note: The system works without these keys, but they enable additional features.

### 3. Start the Services

```bash
docker-compose up -d
```

### 4. Upload and Analyze Emails

**🌐 Streamlit Web Dashboard (Recommended)**: `http://localhost:8501`
1. Go to the "📧 Upload Email" tab
2. Drag and drop a `.eml` file or click to browse
3. Click "Analyze Email" and wait for processing
4. View results in the "📊 Email List" tab:
   - Click any dropdown arrow to see complete analysis
   - Risk assessment with color-coded levels
   - ClamAV and YARA scan results
   - Interactive risk score gauge

**📡 API Access**: `http://localhost:8080`
- REST API for programmatic access
- Interactive documentation at `/docs`

## API Endpoints

### Core Endpoints

- `GET /` - Health check
- `POST /upload` - Upload and analyze email file
- `GET /history` - Get analysis history
- `GET /analysis/{id}` - Get detailed analysis results

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key for AI analysis | Optional |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key for URL analysis | Optional |
| `DATABASE_URL` | SQLite database path | `sqlite:///app/data/email_analysis.db` |

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

### Risk Assessment
- Multi-factor risk scoring algorithm
- Color-coded risk levels (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
- International domain detection
- Phishing pattern recognition
- Suspicious content analysis

## Database Schema

### EmailAnalysis
- Core email analysis record
- Metadata, headers, and content
- Risk scoring and assessment
- Processing status and timestamps
- ClamAV and YARA scan results

## Security Features

### Risk Scoring
- Multi-factor risk assessment
- Weighted scoring algorithm
- Configurable risk thresholds

### Secure Scanning
- Docker containerization for isolation
- ClamAV antivirus protection
- YARA rule-based detection
- Safe handling of potentially malicious files

## Development

### Adding New YARA Rules

1. Add `.yar` files to `yara_rules/`
2. Rules are automatically loaded on startup
3. Use YARA syntax for rule definition

### Customizing Analysis

1. Modify `scanning-api.py` for API changes
2. Update `web-ui/app.py` for UI changes
3. Add new risk scoring factors
4. Customize threat detection patterns

## Troubleshooting

### Common Issues

1. **ClamAV Connection Failed**
   - Check ClamAV service status: `docker-compose logs api`
   - Verify network connectivity
   - Check firewall settings

2. **Web Dashboard Not Loading**
   - Check Streamlit service: `docker-compose logs web-ui`
   - Verify port 8501 is available
   - Check browser console for errors

3. **File Upload Issues**
   - Check file permissions
   - Verify disk space
   - Review file size limits

4. **Database Errors**
   - Check database file permissions
   - Verify disk space
   - Review SQLite configuration

### Logs

- API logs: `docker-compose logs api`
- Web UI logs: `docker-compose logs web-ui`
- All services: `docker-compose logs`

### Monitoring

- Health check: `GET http://localhost:8080/`
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
