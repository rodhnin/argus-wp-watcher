# Safe Testing Guide for Argus

This guide explains how to safely test Argus without scanning unauthorized systems.

## ⚠️ Testing Ethics

**CRITICAL RULES:**

1. ✅ **ONLY** test against systems you own or have explicit permission
2. ✅ Use the provided Docker lab environment
3. ✅ Use isolated VMs with snapshots
4. ❌ **NEVER** scan production sites without authorization
5. ❌ **NEVER** scan third-party WordPress sites "for practice"

Unauthorized scanning is **illegal** in most jurisdictions.

---

## 🐳 Method 1: Docker Lab (Recommended)

The safest and fastest way to test Argus features.

### Quick Start

```bash
# 1. Navigate to docker directory
cd docker

# 2. Start the lab (Option A: Interactive script)
./deploy.sh
# Select option 2 (Testing Lab)

# Or (Option B: Direct command)
docker compose -f compose.testing.yml up -d

# 3. Wait for WordPress to be ready (60-90 seconds)
docker compose -f compose.testing.yml logs -f wordpress
# Look for: "WordPress is ready"

# 4. Access WordPress
# Open browser: http://localhost:8080
```

### Initial WordPress Setup

1. **Visit**: http://localhost:8080
2. **Language**: English (or your preference)
3. **Site Configuration**:
    - Site Title: `Argus Test Lab`
    - Username: `admin` (for testing only!)
    - Password: **Use a strong password** (even for testing)
    - Email: `test@localhost.local`
    - Uncheck "discourage search engines"
4. **Install WordPress**

### Creating Vulnerable Conditions

After WordPress is installed, intentionally create vulnerabilities for testing:

#### A. Expose wp-config.php Backup (CRITICAL Finding)

```bash
docker compose -f compose.testing.yml exec wordpress bash -c \
  "cp /var/www/html/wp-config.php /var/www/html/wp-config.php.bak"
```

**Expected Finding**: `ARGUS-WP-030` - Critical severity

#### B. Enable Directory Listing

```bash
docker compose -f compose.testing.yml exec wordpress bash -c \
  "rm -f /var/www/html/wp-content/uploads/index.html"

docker compose -f compose.testing.yml exec wordpress bash -c \
  "rm -f /var/www/html/wp-content/plugins/index.php"
```

**Expected Finding**: `ARGUS-WP-061` - Medium severity

#### C. Create Exposed Debug Log

```bash
docker compose -f compose.testing.yml exec wordpress bash -c \
  "echo '[10-Oct-2025 18:45:30 UTC] PHP Warning: Undefined variable' > /var/www/html/wp-content/debug.log"
```

**Expected Finding**: `ARGUS-WP-063` - High severity

#### D. Create Database Backup Exposure

```bash
docker compose -f compose.testing.yml exec wordpress bash -c \
  "echo 'CREATE TABLE wp_users...' > /var/www/html/backup.sql"
```

**Expected Finding**: `ARGUS-WP-030` - Critical severity

#### E. Create .env File Exposure

```bash
docker compose -f compose.testing.yml exec wordpress bash -c \
  "echo 'DB_PASSWORD=secret123' > /var/www/html/.env"
```

**Expected Finding**: `ARGUS-WP-030` - Critical severity

#### F. Install Old Plugin (Simulate Outdated Software)

```bash
# Via WordPress admin:
# 1. Go to Plugins > Add New
# 2. Search for "Contact Form 7"
# 3. Install version 5.0 (or download older version manually)

# OR via CLI:
docker compose -f compose.testing.yml exec wordpress bash -c \
  "wp plugin install contact-form-7 --version=5.0 --activate --allow-root"
```

**Expected Finding**: `ARGUS-WP-010` - Info/Medium severity

### Running Test Scans

#### Test 1: Basic Fingerprinting

```bash
# From host machine
python -m argus --target http://localhost:8080

# Expected findings:
# - ARGUS-WP-000: WordPress detected
# - ARGUS-WP-001: Version disclosed (6.0)
```

#### Test 2: Sensitive Files Detection

```bash
python -m argus --target http://localhost:8080 -v

# Expected findings:
# - ARGUS-WP-030: wp-config.php.bak (CRITICAL)
# - ARGUS-WP-030: backup.sql (CRITICAL)
# - ARGUS-WP-030: .env file (CRITICAL)
# - ARGUS-WP-063: debug.log accessible (HIGH)
```

#### Test 3: User Enumeration

```bash
python -m argus --target http://localhost:8080 -vv

# Expected findings:
# - ARGUS-WP-040: User 'admin' enumerated (HIGH)
# - ARGUS-WP-041: 1 user(s) enumerated
```

#### Test 4: Configuration Issues

```bash
python -m argus --target http://localhost:8080

# Expected findings:
# - ARGUS-WP-060: XML-RPC enabled (MEDIUM)
# - ARGUS-WP-061: Directory listing enabled (MEDIUM)
# - ARGUS-WP-065: Admin login accessible (INFO)
```

#### Test 5: Security Headers

```bash
python -m argus --target http://localhost:8080 --html

# Expected findings:
# - ARGUS-WP-050: Missing HSTS (MEDIUM)
# - ARGUS-WP-050: Missing CSP (MEDIUM)
# - ARGUS-WP-050: Missing X-Frame-Options (MEDIUM)
```

#### Test 6: Full Scan with HTML Report

```bash
python -m argus \
  --target http://localhost:8080 \
  --html \
  --report-dir ./test-reports \
  -vv

# Check output:
ls -lh ./test-reports/
open ./test-reports/argus_report_*.html
```

### Testing Consent Token System

#### Generate Token

```bash
python -m argus --gen-consent localhost:8080

# Example output:
# ======================================================================
# DOMAIN OWNERSHIP VERIFICATION REQUIRED
# ======================================================================
# Domain: localhost:8080
# Token: verify-a3f9b2c1d8e4f5a6
# Expires: 48 hours from now
```

#### Place Token (HTTP Method)

```bash
docker compose -f compose.testing.yml exec wordpress bash -c \
  "mkdir -p /var/www/html/.well-known && \
   echo 'verify-a3f9b2c1d8e4f5a6' > /var/www/html/.well-known/verify-a3f9b2c1d8e4f5a6.txt"
```

#### Verify Token

```bash
python -m argus \
  --verify-consent http \
  --domain localhost:8080 \
  --token verify-a3f9b2c1d8e4f5a6

# Expected output:
# ✓ CONSENT VERIFICATION SUCCESSFUL
```

#### Test Aggressive Mode

```bash
# Now that consent is verified, test aggressive mode
python -m argus \
  --target http://localhost:8080 \
  --aggressive \
  --html

# Should complete successfully with consent
```

### Testing AI Features (Optional)

⚠️ **Requires OpenAI API key** (costs money)

```bash
# Set API key
export OPENAI_API_KEY=sk-...

# Run AI-powered scan
python -m argus \
  --target http://localhost:8080 \
  --use-ai \
  --ai-tone both \
  --html \
  -v

# Check AI sections in report:
# - Executive Summary (non-technical)
# - Technical Remediation Guide
```

### Containerized Scanning (Optional)

Scan from inside Docker network (requires deploying both environments):

```bash
# First, deploy both environments (from docker/ directory)
./deploy.sh
# Select option 3 (Both)

# Run scan from production scanner container
docker compose exec argus python -m argus --target http://wordpress

# View results
docker compose exec argus ls -lh /reports
```

### Cleanup

```bash
# Stop services (keep data)
docker compose -f compose.testing.yml down

# Stop and delete all data (reset lab)
docker compose -f compose.testing.yml down -v

# Remove images (optional)
docker compose -f compose.testing.yml down -v --rmi all
```

---

## 🧪 Test Cases & Expected Results

### Test Suite Overview

| Test Case            | Severity     | Expected Finding ID |
| -------------------- | ------------ | ------------------- |
| WordPress Detection  | Info         | ARGUS-WP-000        |
| Version Disclosure   | Medium       | ARGUS-WP-001        |
| wp-config.php.bak    | **Critical** | ARGUS-WP-030        |
| backup.sql Exposed   | **Critical** | ARGUS-WP-030        |
| .env Exposed         | **Critical** | ARGUS-WP-030        |
| debug.log Accessible | High         | ARGUS-WP-063        |
| Plugin Enumeration   | Info         | ARGUS-WP-011        |
| User Enumeration     | High         | ARGUS-WP-041        |
| XML-RPC Enabled      | Medium       | ARGUS-WP-060        |
| Directory Listing    | Medium       | ARGUS-WP-061        |
| Missing HSTS         | Medium       | ARGUS-WP-050        |
| Missing CSP          | Medium       | ARGUS-WP-050        |

### Acceptance Criteria

✅ **Pass Conditions:**

-   All expected findings detected
-   Severity levels match expectations
-   No false positives on clean install
-   JSON validates against schema
-   HTML renders correctly
-   Consent system blocks aggressive mode without verification
-   AI analysis completes without errors (if enabled)

❌ **Fail Conditions:**

-   Critical findings missed (wp-config.php.bak)
-   False positives on secure configuration
-   JSON schema validation fails
-   Crash or unhandled exceptions
-   Consent bypass possible

---

## 📊 Regression Testing

Before each release, run full test suite:

```bash
# 1. Reset lab to vulnerable state
cd docker
docker compose -f compose.testing.yml down -v
docker compose -f compose.testing.yml up -d
# (Re-create vulnerable conditions)

# 2. Run test suite
./scripts/run_tests.sh  # TODO: Create automated test script

# 3. Verify all findings
cd ..
python -m argus --target http://localhost:8080 --html -vv

# 4. Check report
open reports/argus_report_*.html

# 5. Test consent system
python -m argus --gen-consent localhost:8080
# (Verify token manually)

# 6. Test AI (if key available)
python -m argus --target http://localhost:8080 --use-ai --html
```

---

## 🐛 Troubleshooting

### WordPress Not Starting

```bash
# Check logs
docker compose -f compose.testing.yml logs wordpress

# Common issues:
# - Port 8080 already in use: Change in compose.testing.yml
# - Database not ready: Wait 30s, then restart
docker compose -f compose.testing.yml restart wordpress
```

### "Permission Denied" Scanning Localhost

```bash
# Ensure target is accessible
curl http://localhost:8080

# Check firewall
sudo ufw status

# Check Docker network
docker compose exec argus ping wordpress
```

### No Findings Detected

```bash
# Verify vulnerable conditions exist
curl http://localhost:8080/wp-config.php.bak
curl http://localhost:8080/wp-content/debug.log

# If 404, recreate vulnerable files
```

### Consent Verification Fails

```bash
# Check token file exists
docker compose exec wordpress cat /var/www/html/.well-known/verify-*.txt

# Check token matches
python -m argus --verify-consent http --domain localhost:8080 --token [exact-token]

# Use correct token format: verify-[16 hex chars]
```

---

## 📝 Testing Checklist

Before deploying Argus or reporting issues:

-   [ ] Lab starts successfully
-   [ ] WordPress accessible at http://localhost:8080
-   [ ] Vulnerable conditions created
-   [ ] Safe scan detects all critical issues
-   [ ] User enumeration works (finds 'admin')
-   [ ] Plugin/theme enumeration finds installed items
-   [ ] Security headers check reports missing headers
-   [ ] JSON report validates against schema
-   [ ] HTML report renders correctly
-   [ ] Consent token generation works
-   [ ] HTTP verification succeeds
-   [ ] Aggressive mode blocked without consent
-   [ ] AI analysis completes (if key available)
-   [ ] Database stores scan results
-   [ ] Logs redact sensitive data
-   [ ] Cleanup command works (docker compose down -v)

---

## 🔒 Security Reminders

1. **Docker lab ports are localhost-only** (127.0.0.1:8080)
2. **Never expose vulnerable lab to network**
3. **Use snapshots for VM testing** (revert after each test)
4. **Don't reuse lab credentials** in production
5. **Delete lab data after testing** (docker compose down -v)

---

## 📚 Further Reading

-   [WordPress Hardening Guide](https://wordpress.org/documentation/article/hardening-wordpress/)
-   [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
-   [Docker Security Best Practices](https://docs.docker.com/engine/security/)

---

**Happy (Safe) Testing!** 🛡️

If you find any issues with the testing guide or lab setup, please report them at:
https://github.com/rodhnin/argus-wp-watcher/issues
