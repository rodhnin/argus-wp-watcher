# Changelog

All notable changes to Argus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2025-10-20

**Initial Production Release** 🎉

Argus v0.1.0 is a comprehensive WordPress security scanner with ethical scanning practices, AI-powered analysis, and professional reporting. This release includes 130+ security checks, multi-provider AI integration, and robust error handling.

---

### Added

#### Core Security Scanner

**WordPress Detection & Fingerprinting**

-   Multi-method version detection via meta tags, readme.html, RSS feeds, and asset fingerprinting
-   Accurate detection with zero false positives
-   Support for WordPress 4.x through 6.x

**Plugin & Theme Enumeration**

-   Detection of 100+ popular WordPress plugins
-   Theme identification (20+ popular themes)
-   Concurrent scanning for improved performance
-   Passive enumeration to minimize server load

**Sensitive File Detection**

-   70+ critical file paths monitored:
    -   Configuration backups (`wp-config.php.bak`, `.old`, `.save`, `~`)
    -   Database dumps (`dump.sql`, `database.sql`, `backup.sql`)
    -   Environment files (`.env`)
    -   Version control artifacts (`.git/`, `.svn/`)
    -   Debug logs (`wp-content/debug.log`)
    -   Backup archives (`backup.zip`, `backup.tar.gz`)

**User Enumeration**

-   Three detection methods:
    -   Author IDOR enumeration (`/?author=N`)
    -   REST API user listing
    -   HTML parsing (WordPress 6.x+ compatible)
-   Configurable user range (default: 1-10)

**Security Headers Analysis**

-   Checks for critical security headers:
    -   Content-Security-Policy (CSP)
    -   HTTP Strict Transport Security (HSTS)
    -   X-Frame-Options
    -   X-Content-Type-Options
    -   X-XSS-Protection
    -   Referrer-Policy
    -   Permissions-Policy

**Configuration Auditing**

-   XML-RPC status detection
-   Directory listing exposure
-   Debug mode detection
-   File editor accessibility
-   Database prefix enumeration

---

#### AI-Powered Analysis

**Multi-Provider Support**

-   **OpenAI GPT-4 Turbo**: Premium quality, ~35 seconds per analysis
-   **Anthropic Claude**: Privacy-focused alternative, ~45 seconds
-   **Ollama (Local Models)**: 100% offline, no data leaves your machine

**Analysis Modes**

-   **Technical Tone**: Detailed remediation guides with commands and configuration snippets
-   **Non-Technical Tone**: Executive summaries in plain language for stakeholders
-   **Both Modes**: Combined analysis in a single report

**Security & Privacy**

-   Automatic sanitization removes sensitive data before AI processing
-   No credentials, tokens, or PII sent to AI providers
-   Configurable via environment variables and YAML

**Standalone Testing**

```bash
# Test AI providers before scanning
python -m argus.core.ai openai
python -m argus.core.ai anthropic
python -m argus.core.ai ollama
```

---

#### Infrastructure & Reporting

**Ethical Scanning Framework**

-   **Consent Token System**: Verify domain ownership before aggressive scanning
    -   HTTP verification (`.well-known/verify-{token}.txt`)
    -   DNS TXT record verification
    -   48-hour token expiration
    -   Database tracking of verified domains

**Dual Report Formats**

-   **JSON Reports**: Machine-readable with schema validation

    -   Complete scan metadata
    -   Structured findings with evidence
    -   AI analysis (when enabled)
    -   ~50-65KB per scan

-   **HTML Reports**: Professional, self-contained
    -   Responsive design
    -   Inline CSS (no external dependencies)
    -   Severity-color-coded findings
    -   Expandable sections
    -   AI analysis beautifully formatted
    -   ~208-221KB per scan

**Database Persistence**

-   SQLite database for scan history
-   Tracks all findings across scans
-   Consent token management
-   SQL views for common queries
-   Automatic corruption recovery
-   Read-only mode support

**Advanced Logging**

-   Automatic secret redaction (passwords, tokens, API keys)
-   Multiple verbosity levels (`-v`, `-vv`, `-vvv`)
-   JSON and text format support
-   Timestamped with severity levels

---

#### Performance & Control

**Rate Limiting**

-   Configurable request throttling (1-20 req/s)
-   Thread-safe implementation
-   Respects server load
-   Default: 5 req/s (safe) / 10 req/s (aggressive)

**Concurrent Scanning**

-   Thread pool management (1-20 workers)
-   Parallel checks for faster scans
-   Intelligent retry logic
-   Graceful degradation on failures

**Scan Modes**

-   **Safe Mode** (default): Non-intrusive checks, no consent required
-   **Aggressive Mode**: Deep scanning, requires verified ownership

---

#### Docker Support

**Production-Ready Container**

-   Optimized 379MB image (multi-stage build)
-   Non-root user execution (security best practice)
-   Volume mounts for persistence
-   Environment variable configuration
-   Compatible with Docker Compose

**Vulnerable WordPress Lab**

-   Pre-configured test environment
-   Safe testing without targeting real sites
-   Docker Compose setup included
-   MariaDB + WordPress 6.x

---

#### Error Handling & Resilience

**Connection Error Management**

-   Handles timeouts gracefully
-   DNS resolution failure recovery
-   Connection refused detection
-   Network error handling
-   Configurable timeout values

**Database Resilience**

-   Automatic corruption detection
-   Backup and recovery system
-   Read-only mode support
-   Graceful degradation when DB unavailable
-   Foreign key integrity enforcement

**Partial Scan Support**

-   Continues scanning despite individual check failures
-   Preserves partial results if target goes offline
-   Handles target restarts mid-scan
-   Comprehensive error reporting

**Standardized Exit Codes**

-   `0`: Scan completed successfully
-   `1`: Technical error (connection, timeout, database)
-   `2`: Target is not WordPress (early abort)
-   `130`: User cancelled (Ctrl+C)

---

#### Developer Experience

**Rich CLI Interface**

-   30+ command-line flags
-   Colored output with progress indicators
-   ASCII art branding
-   Comprehensive `--help` documentation
-   Tab completion support (oh-my-zsh)

**Configuration Management**

-   YAML configuration files
-   Environment variable overrides
-   CLI flag priority system
-   Multi-environment support

---

### Performance

**Scan Speed**

-   Core checks: 6-42 seconds (depending on target)
-   With AI analysis: +30-50 seconds
-   Average requests per scan: 150-200

**AI Analysis Performance**
| Provider | Duration | Quality | Cost per Scan |
|----------|----------|---------|---------------|
| OpenAI GPT-4 | ~35s | ⭐⭐⭐⭐⭐ | $0.25 |
| Anthropic Claude | ~45s | ⭐⭐⭐⭐⭐ | $0.30 |
| Ollama (CPU) | ~28min | ⭐⭐⭐ | Free |
| Ollama (GPU) | ~75s\* | ⭐⭐⭐ | Free |

\*GPU time is estimated

**Resource Usage**

-   Memory: <500MB peak
-   Database: <20MB for 150+ scans
-   Report size: 50-221KB depending on format and AI
-   Concurrent scans: Tested up to 3 simultaneous without issues

---

### Security

**Safe by Default**

-   Non-intrusive checks unless explicitly authorized
-   Consent enforcement for aggressive mode
-   Automatic secret redaction in all outputs
-   AI data sanitization (removes tokens, credentials, PII)

**Privacy Options**

-   Ollama support for 100% offline operation
-   No telemetry or tracking
-   Local database storage only
-   Configurable data retention

**Best Practices**

-   Non-root Docker execution
-   Schema validation for all reports
-   Foreign key constraints enforced
-   No information leakage in error messages
-   Secure credential handling

---

### Known Limitations

These limitations are documented and tracked for future versions:

**Detection Accuracy**

-   Plugin version detection is limited (shows "None" for most plugins)
-   Planned improvement: IMPROV-003 in v0.2.0

**Scan Modes**

-   Aggressive mode currently differs from safe mode only in rate limit
-   Planned improvement: IMPROV-004 in v0.2.0 (deeper checks, more wordlists)

**AI Features**

-   Provider switching requires manual YAML editing
-   No cost tracking or budget limits
-   No streaming responses
-   Planned improvements: IMPROV-005, IMPROV-006, IMPROV-009 in v0.2.0-v0.3.0

**Ollama Performance**

-   Extremely slow on CPU (~28 minutes vs 35 seconds for OpenAI)
-   Recommended only for privacy-critical scenarios or when using GPU

**Database Management**

-   Requires SQL knowledge for advanced queries
-   Planned improvement: IMPROV-011 in v0.3.0 (interactive CLI)

---

## Installation

### Requirements

-   Python 3.11+
-   pip (Python package manager)
-   Docker (optional, for containerized scanning)

### Quick Start

**1. Clone the repository**

```bash
git clone https://github.com/rodhnin/argus-wp-watcher.git
cd argus-wp-watcher
```

**2. (Optional) Install `venv` if you don’t have it**

```bash
# For Debian/Ubuntu and similar distros
sudo apt update && sudo apt install -y python3-venv
```

**3. Create and activate a virtual environment**

```bash
python3 -m venv .venv
source .venv/bin/activate
# You should see (.venv) in your terminal prompt
```

**4. Upgrade pip inside the environment**

```bash
python -m pip install --upgrade pip
```

**5. Install dependencies**

```bash
python -m pip install -r requirements.txt
```

**6. (Optional) For Ollama support**

```bash
python -m pip install "langchain-ollama>=0.3.0,<0.4.0"
```

**7. Configure API Keys (Optional)**

```bash
# For OpenAI
export OPENAI_API_KEY="sk-..."

# For Anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
```

**8. Run First Scan**

```bash
# Basic scan (no AI)
python -m argus --target https://example.com

# With AI analysis
python -m argus --target https://example.com --use-ai --html
```

---

## Usage Examples

### Basic Scanning

```bash
# Safe mode scan (default)
python -m argus --target https://example.com

# Generate HTML report
python -m argus --target https://example.com --html

# Verbose output
python -m argus --target https://example.com -v
```

### AI-Powered Analysis

```bash
# Technical analysis
python -m argus --target https://example.com \
  --use-ai \
  --ai-tone technical \
  --html

# Executive summary
python -m argus --target https://example.com \
  --use-ai \
  --ai-tone non_technical \
  --html

# Both analyses
python -m argus --target https://example.com \
  --use-ai \
  --ai-tone both \
  --html
```

### Aggressive Mode (Requires Consent)

```bash
# 1. Generate consent token
python -m argus --gen-consent --domain example.com

# 2. Place token on server
# HTTP: Create file at https://example.com/.well-known/verify-{token}.txt
# OR DNS: Add TXT record "argus-verify={token}"

# 3. Verify consent
python -m argus --verify-consent --domain example.com --token verify-{token}

# 4. Run aggressive scan
python -m argus --target https://example.com --aggressive
```

### Docker Deployment

```bash
# Build image
docker build -f docker/Dockerfile -t argus:0.1.0 .

# Run scan
docker run --rm \
  --network host \
  -v $(pwd)/reports:/reports \
  -v $(pwd)/data:/data \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  argus:0.1.0 \
  --target https://example.com \
  --report-dir /reports \
  --db /data/argus.db \
  --use-ai \
  --html
```

### Test Lab Setup

```bash
# Option 1: Using interactive script (Recommended)
cd docker
./deploy.sh
# Select option 2 (Testing Lab)

# Option 2: Manual
cd docker
docker compose -f compose.testing.yml up -d

# Scan the lab from host
python -m argus --target http://localhost:8080
```

---

## Configuration

### AI Provider Selection

Edit `config/defaults.yaml`:

```yaml
ai:
    langchain:
        provider: "openai" # Options: openai, anthropic, ollama
        model: "gpt-4-turbo-preview"
        temperature: 0.3
```

Or use environment variables:

```bash
export LANGCHAIN_PROVIDER="anthropic"
export LANGCHAIN_MODEL="claude-3-5-sonnet"
```

**Note:** Dynamic provider switching will be available in v0.3.0 (IMPROV-009)

### Rate Limiting

```bash
# Slow scan (1 req/s)
python -m argus --target example.com --rate 1

# Fast scan (20 req/s, requires consent)
python -m argus --target example.com --rate 20 --aggressive
```

### Thread Control

```bash
# Single-threaded
python -m argus --target example.com --threads 1

# Multi-threaded (10 workers)
python -m argus --target example.com --threads 10
```

---

## Database Management

### Query Examples

**View recent scans:**

```sql
sqlite3 ~/.argos/argos.db "SELECT * FROM v_recent_scans LIMIT 10;"
```

**Find critical findings:**

```sql
sqlite3 ~/.argos/argos.db "SELECT * FROM v_critical_findings;"
```

**Check verified domains:**

```sql
sqlite3 ~/.argos/argos.db "SELECT * FROM v_verified_domains;"
```

For complete database reference, see `docs/DATABASE_GUIDE.md`

**Note:** Interactive database CLI will be available in v0.3.0 (IMPROV-011)

---

## Migration Notes

### Upgrading from Pre-Release

This is the first production release. No migration required.

### Future Upgrades

**v0.2.0** (Q2 2026):

-   Backward compatible
-   New features: Plugin version detection, AI cost tracking, improved HTML reports
-   No database migration required

**v0.3.0** (Q3 2026):

-   Database schema v2 (automatic migration provided)
-   Breaking change: Configuration file format (migration tool included)
-   New features: Interactive config, database CLI, AI chat

---

## Support & Contributing

**Found a bug?**  
Open an issue: https://github.com/rodhnin/argus-wp-watcher/issues

**Feature request?**  
Start a discussion: https://github.com/rodhnin/argus-wp-watcher/discussions

**Want to contribute?**  
See `CONTRIBUTING.md` for guidelines

**Need help?**  
Check documentation in `docs/` or ask in Discussions

---

## Roadmap

**v0.2.0** (Q2 2026) - Enhanced Detection & AI

-   Plugin version detection
-   AI cost tracking & budget limits
-   HTML report enrichment
-   WPScan integration

**v0.3.0** (Q3 2026) - Enterprise Features

-   Interactive config management
-   Database CLI interface
-   Multi-site scanning
-   AI chat interface

**v0.4.0** (Q1 2027) - Intelligence & Automation

-   ML-based detection
-   Automated remediation
-   Distributed scanning

See `ROADMAP.md` for complete feature list

---

## License

See `LICENSE` file for details.

---

## Acknowledgments

-   WordPress community for security research
-   LangChain team for AI framework
-   OpenAI, Anthropic, and Ollama for AI models
-   All contributors and testers

---

**Generated:** November 22, 2025  
**Version:** 0.1.0  
**Status:** Production Release

[0.1.0]: https://github.com/rodhnin/argus-wp-watcher/releases/tag/v0.1.0
