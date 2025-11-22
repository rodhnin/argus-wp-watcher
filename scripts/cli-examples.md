# Argus CLI Examples

Comprehensive command-line usage examples for Argus WordPress security scanner.

---

## Basic Scanning

### Quick Scan (Safe Mode)

```bash
# Minimal command - safe, non-intrusive checks
python -m argus --target https://example.com

# Same with explicit safe mode
python -m argus --target https://example.com --safe
```

### With HTML Report

```bash
# Generate both JSON and HTML reports
python -m argus --target https://example.com --html
```

### Custom Output Directory

```bash
# Save reports to specific directory
python -m argus --target https://example.com --report-dir ./client-reports --html
```

---

## Verbosity & Logging

### Increase Verbosity

```bash
# INFO level (-v)
python -m argus --target https://example.com -v

# DEBUG level (-vv)
python -m argus --target https://example.com -vv

# DEBUG + library logs (-vvv)
python -m argus --target https://example.com -vvv
```

### Logging to File

```bash
# Log to custom file
python -m argus --target https://example.com --log-file ./logs/scan.log -vv

# JSON formatted logs (for parsing)
python -m argus --target https://example.com --log-json --log-file ./logs/scan.json
```

### Quiet Mode (CI/CD)

```bash
# Suppress console output (only warnings+)
python -m argus --target https://example.com --quiet

# Disable colors (for log files)
python -m argus --target https://example.com --no-color
```

---

## Consent Token Management

### Generate Consent Token

```bash
# Generate token for domain
python -m argus --gen-consent example.com

# Example output:
# Token: verify-a3f9b2c1d8e4
# Place at: https://example.com/.well-known/verify-a3f9b2c1d8e4.txt
```

### Verify via HTTP

```bash
# After placing token file
python -m argus --verify-consent http \
  --domain example.com \
  --token verify-a3f9b2c1d8e4
```

### Verify via DNS

```bash
# After adding TXT record
python -m argus --verify-consent dns \
  --domain example.com \
  --token verify-a3f9b2c1d8e4
```

---

## Aggressive Scanning

### Full Workflow

```bash
# 1. Generate token
python -m argus --gen-consent example.com

# 2. Verify consent (HTTP method)
python -m argus --verify-consent http \
  --domain example.com \
  --token verify-abc123

# 3. Run aggressive scan
python -m argus --target https://example.com --aggressive --html
```

### With Custom Rate Limit

```bash
# Scan faster (10 req/sec)
python -m argus --target https://example.com \
  --aggressive \
  --rate 10 \
  --threads 10
```

---

## AI-Powered Analysis

### Basic AI Scan

```bash
# Set API key
export OPENAI_API_KEY="sk-..."

# Generate both summaries
python -m argus --target https://example.com --use-ai --html
```

### Technical Summary Only

```bash
# For engineers (cheaper, faster)
python -m argus --target https://example.com \
  --use-ai \
  --ai-tone technical \
  --html
```

### Executive Summary Only

```bash
# For stakeholders
python -m argus --target https://example.com \
  --use-ai \
  --ai-tone non_technical \
  --html
```

### Custom API Key Variable

```bash
# Use different env var
export MY_CUSTOM_KEY="sk-..."

python -m argus --target https://example.com \
  --use-ai \
  --api-key-env MY_CUSTOM_KEY
```

---

## WordPress-Specific Options

### Plugin Enumeration

```bash
# Check specific number of plugins
python -m argus --target https://example.com --max-plugins 50

# Enumerate plugins, themes, users
python -m argus --target https://example.com --enumerate p,t,u
```

### User Enumeration Limits

```bash
# Check more users
python -m argus --target https://example.com --max-users 20
```

---

## Advanced Options

### Custom Timeout

```bash
# Increase timeout for slow servers
python -m argus --target https://example.com --timeout 60
```

### Custom User-Agent

```bash
# Spoof user agent
python -m argus --target https://example.com \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."
```

### Skip SSL Verification (Local Testing)

```bash
# For self-signed certs
python -m argus --target https://localhost:8443 --no-verify-ssl
```

---

## Database Operations

### Custom Database Path

```bash
# Use separate DB for this scan
python -m argus --target https://example.com \
  --db ./projects/client-a/scans.db
```

### View Scan History (SQLite)

```bash
# Query recent scans
sqlite3 ~/.argos/argos.db "SELECT * FROM v_recent_scans LIMIT 10"

# Critical findings
sqlite3 ~/.argos/argos.db "SELECT * FROM v_critical_findings"

# Verified domains
sqlite3 ~/.argos/argos.db "SELECT * FROM v_verified_domains"
```

---

## Docker Usage

### Run in Container

```bash
# Build image
docker build -f docker/Dockerfile -t argus:latest .

# help
docker run --rm argus:latest --help

# Simple scan
docker run --rm \
  -v $(pwd)/reports:/reports \
  argus:latest \
  --target https://example.com

# With AI
docker run --rm \
  -v $(pwd)/reports:/reports \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  argus:latest \
  --target https://example.com --use-ai --html
```

### Scan Docker Lab

```bash
# Option 1: Start testing lab only (WordPress + DB)
cd docker && ./deploy.sh
# Select option 2

# Scan from host
python -m argus --target http://localhost:8080

# Option 2: Start both (Scanner + Testing Lab)
cd docker && ./deploy.sh
# Select option 3

# Scan from testing lab container
docker compose -f compose.testing.yml exec argus python -m argus --target http://wordpress

# Scan from production container
docker compose exec argus python -m argus --target https://example.com
```

---

## Production Workflows

### Full Client Scan

```bash
#!/bin/bash
# client-scan.sh

TARGET="$1"
CLIENT="$2"

echo "Scanning $TARGET for $CLIENT..."

# 1. Generate consent
python -m argus --gen-consent $TARGET

# 2. Wait for client to place token
read -p "Press enter after token is placed..."

# 3. Verify
python -m argus --verify-consent http \
  --domain $TARGET \
  --token $(cat token.txt)

# 4. Scan with AI
python -m argus \
  --target https://$TARGET \
  --use-ai \
  --ai-tone both \
  --html \
  --report-dir ./clients/$CLIENT/reports \
  -vv

echo "Scan complete! Check ./clients/$CLIENT/reports/"
```

### CI/CD Integration (GitHub Actions)

```bash
# .github/workflows/security-scan.yml
name: Security Scan

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install Argus
        run: pip install -r requirements.txt

      - name: Run Scan
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          python -m argus \
            --target ${{ secrets.TARGET_URL }} \
            --use-ai \
            --html \
            --quiet \
            --no-color

      - name: Upload Reports
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: ~/.argus/reports/
```

### Cron Job (Linux)

```bash
# Add to crontab
crontab -e

# Scan every Sunday at 2 AM
0 2 * * 0 cd /opt/argus && python -m argus --target https://mysite.com --html >> /var/log/argus.log 2>&1
```

---

## Troubleshooting

### Debug Connection Issues

```bash
# Maximum verbosity + keep-alive
python -m argus --target https://example.com -vvv --timeout 120
```

### Test Consent Token Manually

```bash
# Check if token file is accessible
curl https://example.com/.well-known/verify-abc123.txt

# Should return: verify-abc123

# Check DNS TXT record
dig TXT example.com +short
# Or: nslookup -type=TXT example.com
```

### Verify Installation

```bash
# Check version
python -m argus --version

# Check dependencies
pip list | grep -E 'requests|beautifulsoup4|langchain'

# Test database creation
python -c "from argus.core.db import get_db; db = get_db(); print('DB OK')"
```

---

## Quick Reference

### Common Patterns

```bash
# Quick safe scan
argus --target $URL

# Client deliverable
argus --target $URL --use-ai --html -vv

# Local testing
argus --target http://localhost:8080 --no-verify-ssl

# Fast aggressive scan
argus --target $URL --aggressive --rate 20 --threads 15

# Quiet (for scripts)
argus --target $URL --quiet --no-color --log-json --log-file scan.json

# Minimal AI (save money)
argus --target $URL --use-ai --ai-tone technical
```

### Environment Variables

```bash
# Common env vars
export OPENAI_API_KEY="sk-..."
export ARGUS_PATHS_REPORT_DIR="./reports"
export ARGUS_PATHS_DATABASE="./argus.db"
export ARGUS_LOG_LEVEL="DEBUG"
export ARGUS_SCAN_RATE_LIMIT_SAFE_MODE="5.0"
```

---

## Getting Help

```bash
# Show all options
python -m argus --help

# Show version
python -m argus --version

# Validate config
python -c "from argus.core.config import Config; c = Config.load(); print('Config OK')"
```

---

## Tips & Tricks

### 1. Scan Multiple Sites

```bash
# Loop through file
while read url; do
  python -m argus --target "$url" --html
done < urls.txt
```

### 2. Compare Scans

```bash
# Scan twice
python -m argus --target https://example.com --html
# (Make changes)
python -m argus --target https://example.com --html

# Compare JSON reports with jq
jq -s '.[0].summary as $before | .[1].summary as $after |
  {before: $before, after: $after}' \
  report1.json report2.json
```

### 3. Filter Critical Only

```bash
# Use jq to extract critical findings
jq '.findings[] | select(.severity=="critical")' report.json
```

### 4. Generate Token Batch

```bash
# Generate tokens for multiple domains
for domain in example.com test.com demo.com; do
  python -m argus --gen-consent $domain | tee tokens-$domain.txt
done
```

### 5. Auto-Verify Consent

```bash
#!/bin/bash
# auto-verify.sh
DOMAIN=$1
TOKEN=$2

# Upload token file (requires ssh access)
echo "$TOKEN" | ssh user@$DOMAIN "cat > /var/www/html/.well-known/$TOKEN.txt"

# Verify
python -m argus --verify-consent http --domain $DOMAIN --token $TOKEN
```

---

**More examples?** Check the [docs/](../docs/) folder or open an issue!
