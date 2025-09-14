# Deployment Guide

## Production Deployment

### Prerequisites
- Docker and Docker Compose
- 4GB+ RAM recommended
- 10GB+ disk space
- Linux server (Ubuntu 20.04+ recommended)

### Quick Deployment

1. **Clone and setup**
   ```bash
   git clone <repository-url>
   cd email-analysis
   cp env.sample .env
   # Edit .env with your configuration
   ```

2. **Start services**
   ```bash
   docker-compose up -d
   ```

3. **Verify deployment**
   ```bash
   curl http://localhost:8080/
   ```

### Environment Configuration

Create `.env` file:
```bash
# Database
DATABASE_URL=sqlite:///app/data/email_analysis.db

# Optional: External APIs
OPENAI_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here

# Security (for production)
SECRET_KEY=your_secret_key_here
ALLOWED_HOSTS=yourdomain.com,localhost

# Performance
MAX_FILE_SIZE=10MB
SCAN_TIMEOUT=60
```

### Production Optimizations

#### Docker Compose Override
Create `docker-compose.prod.yml`:
```yaml
version: '3.8'

services:
  api:
    restart: always
    environment:
      - ENVIRONMENT=production
    volumes:
      - ./data:/app/data:rw
      - ./logs:/app/logs:rw
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - api
```

#### Nginx Configuration
Create `nginx.conf`:
```nginx
events {
    worker_connections 1024;
}

http {
    upstream api {
        server api:8080;
    }

    server {
        listen 80;
        server_name yourdomain.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl;
        server_name yourdomain.com;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;

        location / {
            proxy_pass http://api;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        client_max_body_size 10M;
    }
}
```

### Security Hardening

#### 1. Network Security
```bash
# Firewall rules
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

#### 2. Container Security
```yaml
# In docker-compose.yml
services:
  api:
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    user: "1000:1000"
```

#### 3. Database Security
```bash
# Backup database regularly
docker-compose exec api sqlite3 /app/data/email_analysis.db ".backup /app/data/backup_$(date +%Y%m%d).db"
```

### Monitoring

#### Health Checks
```bash
#!/bin/bash
# health_check.sh
API_URL="http://localhost:8080"

if curl -f -s "$API_URL/" > /dev/null; then
    echo "✅ API is healthy"
    exit 0
else
    echo "❌ API is down"
    exit 1
fi
```

#### Log Monitoring
```bash
# View logs
docker-compose logs -f api

# Log rotation
docker-compose exec api logrotate /etc/logrotate.conf
```

#### Metrics Collection
Add to `docker-compose.yml`:
```yaml
services:
  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

### Backup Strategy

#### Database Backup
```bash
#!/bin/bash
# backup.sh
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups"
mkdir -p $BACKUP_DIR

# Backup database
docker-compose exec -T api sqlite3 /app/data/email_analysis.db ".backup /app/data/backup_$DATE.db"
docker cp $(docker-compose ps -q api):/app/data/backup_$DATE.db $BACKUP_DIR/

# Backup YARA rules
cp -r yara_rules $BACKUP_DIR/yara_rules_$DATE

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "backup_*.db" -mtime +30 -delete
find $BACKUP_DIR -name "yara_rules_*" -mtime +30 -exec rm -rf {} \;
```

#### Automated Backups
Add to crontab:
```bash
# Daily backup at 2 AM
0 2 * * * /path/to/backup.sh
```

### Scaling

#### Horizontal Scaling
```yaml
# docker-compose.scale.yml
services:
  api:
    deploy:
      replicas: 3
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/email_analysis

  db:
    image: postgres:13
    environment:
      - POSTGRES_DB=email_analysis
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    # For job queue

volumes:
  postgres_data:
```

#### Load Balancer
```yaml
services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx-lb.conf:/etc/nginx/nginx.conf
    depends_on:
      - api

  api:
    deploy:
      replicas: 3
```

### Troubleshooting

#### Common Issues

1. **ClamAV not updating**
   ```bash
   docker-compose exec api freshclam
   ```

2. **Database locked**
   ```bash
   docker-compose restart api
   ```

3. **YARA rules not loading**
   ```bash
   docker-compose exec api ls -la /app/yara_rules/
   ```

4. **Memory issues**
   ```bash
   # Increase Docker memory limit
   docker-compose down
   docker system prune -a
   docker-compose up -d
   ```

#### Debug Mode
```bash
# Enable debug logging
docker-compose exec api python -c "
import logging
logging.basicConfig(level=logging.DEBUG)
"
```

#### Performance Tuning
```bash
# Optimize SQLite
docker-compose exec api sqlite3 /app/data/email_analysis.db "
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=10000;
PRAGMA temp_store=MEMORY;
"
```

### Updates

#### Rolling Updates
```bash
# Update without downtime
docker-compose pull
docker-compose up -d --no-deps api
```

#### Database Migrations
```bash
# Backup before migration
./backup.sh

# Run migration
docker-compose exec api python migrate.py

# Verify migration
docker-compose exec api python verify_migration.py
```

### Disaster Recovery

#### Recovery Procedure
1. Stop services: `docker-compose down`
2. Restore database from backup
3. Restore YARA rules
4. Start services: `docker-compose up -d`
5. Verify functionality

#### RTO/RPO Targets
- **Recovery Time Objective (RTO)**: 15 minutes
- **Recovery Point Objective (RPO)**: 1 hour (backup frequency)

### Compliance

#### Data Retention
```sql
-- Clean up old analyses (keep 90 days)
DELETE FROM email_analyses 
WHERE created_at < datetime('now', '-90 days');
```

#### Audit Logging
```python
# Add to API
import logging
logging.basicConfig(
    filename='/app/logs/audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
```
