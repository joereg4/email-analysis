# 📧 Email Analysis Sandbox

A comprehensive email security analysis platform with advanced scanning capabilities, built with Docker for isolated testing environments.

## 🚀 Features

### Core Analysis
- **Email Parsing**: Extract headers, body content, and metadata
- **Risk Scoring**: Rule-based analysis with configurable thresholds
- **Advanced Scanning**: ClamAV antivirus + YARA rule-based detection
- **Database Storage**: SQLite with full analysis history
- **Web Interface**: Clean, responsive UI for analysis and history

### Security Scanning
- **ClamAV Integration**: Real-time antivirus scanning
- **YARA Rules**: Custom pattern matching for threats
- **Risk Categories**: SAFE, LOW, MEDIUM, HIGH, CRITICAL
- **International Domain Detection**: Flags suspicious geographic origins
- **Phishing Detection**: Identifies common attack patterns

### User Interface
- **Drag & Drop Upload**: Easy file handling
- **Real-time Analysis**: Live scanning results
- **History View**: Browse past analyses
- **Detailed Reports**: Comprehensive threat assessment
- **Responsive Design**: Works on desktop and mobile

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web UI        │    │   FastAPI       │    │   Database      │
│   (HTML/JS)     │◄──►│   (Python)      │◄──►│   (SQLite)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   ClamAV        │
                       │   + YARA        │
                       └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- 2GB+ available RAM
- Internet connection (for ClamAV updates)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/joereg4/email-analysis.git
   cd email-analysis
   ```

2. **Start the services**
   ```bash
   ./setup.sh
   ```
   
   Or manually:
   ```bash
   docker-compose up -d
   ```

3. **Access the application**
   - **Web UI**: `http://localhost:8501` (Streamlit dashboard)
   - **Simple UI**: Open `src/ui/simple-ui.html` in your browser
   - **API**: `http://localhost:8080`
   - **API Docs**: `http://localhost:8080/docs`

### First Analysis

1. Open the Web UI
2. Drag and drop a `.eml` file
3. Click "Analyze Email"
4. View results including:
   - Email details
   - Risk assessment
   - ClamAV scan results
   - YARA rule matches

## 📁 Project Structure

```
email-analysis/
├── src/
│   ├── api/                 # API source code
│   │   └── scanning-api.py  # Main API with scanning
│   ├── ui/                  # Web interface
│   │   └── simple-ui.html   # Main UI
│   └── tests/               # Test scripts
├── samples/                 # Sample email files
├── scripts/                 # Build and utility scripts
├── docs/                    # Documentation
├── yara_rules/              # YARA rule definitions
├── data/                    # Database and logs
├── docker-compose.yml       # Service orchestration
└── README.md               # This file
```

## 🔧 Configuration

### Environment Variables
Create a `.env` file (see `env.sample`):
```bash
# API Configuration
DATABASE_URL=sqlite:///app/data/email_analysis.db

# Optional: External APIs
OPENAI_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```

### YARA Rules
Customize threat detection in `yara_rules/malware_signatures.yar`:
- Suspicious email patterns
- Phishing attempts
- International domains
- Urgency indicators
- Suspicious links

## 📊 API Endpoints

### Core Endpoints
- `GET /` - Health check
- `POST /upload` - Upload and analyze email
- `GET /history` - Get analysis history
- `GET /analysis/{id}` - Get detailed analysis

### Example Usage
```bash
# Upload email for analysis
curl -X POST -F "file=@email.eml" http://localhost:8080/upload

# Get analysis history
curl http://localhost:8080/history

# Get specific analysis
curl http://localhost:8080/analysis/1
```

## 🧪 Testing

### Run Test Suite
```bash
# Test all features
./src/tests/test-scanning.sh

# Test specific components
./src/tests/test-database.sh
./src/tests/test_features.sh
```

### Sample Files
Test with provided samples in `samples/`:
- `safe_email.eml` - Clean business email
- `suspicious_email.eml` - Phishing attempt
- `fiji_suspicious.eml` - International threat
- `test_yara.eml` - YARA rule triggers

## 🔍 Risk Analysis

### Risk Levels
- **SAFE (0-19)**: No suspicious patterns
- **LOW (20-39)**: Minor concerns
- **MEDIUM (40-69)**: Moderate risk
- **HIGH (70-99)**: Significant threat indicators
- **CRITICAL (100)**: Virus detected or severe threat

### Detection Patterns
- Suspicious subject lines
- International domains (.fj, .ru, .cn, etc.)
- Personal information requests
- Urgency indicators
- Forwarded emails
- No-reply addresses
- Malware signatures (ClamAV)
- Custom threat patterns (YARA)

## 🛠️ Development

### Adding New Features
1. Update API in `src/api/`
2. Modify UI in `src/ui/`
3. Add tests in `src/tests/`
4. Update documentation

### Custom YARA Rules
Add new rules to `yara_rules/malware_signatures.yar`:
```yara
rule NewThreatPattern {
    meta:
        description = "Detects new threat pattern"
    
    strings:
        $s1 = "suspicious_pattern" nocase
    
    condition:
        1 of them
}
```

## 📈 Monitoring

### Logs
```bash
# View API logs
docker-compose logs -f api

# View all services
docker-compose logs -f
```

### Database
SQLite database stored in `data/email_analysis.db`:
- Analysis results
- Scanning data
- Timestamps
- Full audit trail

## 🔒 Security Considerations

- **Isolation**: All scanning in Docker containers
- **No Network Access**: ClamAV/YARA run offline
- **Data Privacy**: No external data transmission
- **Sandboxed**: Safe for testing malicious samples

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new features
4. Update documentation
5. Submit pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Issues**: Report bugs via GitHub Issues
- **Documentation**: Check `docs/` directory
- **Tests**: Run test suite for troubleshooting

## 🎯 Roadmap

- [ ] Batch processing
- [ ] Email management interface
- [ ] Advanced threat intelligence
- [ ] Machine learning integration
- [ ] Multi-user support
- [ ] API authentication
- [ ] Cloud deployment options
