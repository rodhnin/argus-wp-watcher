# Changelog

All notable changes to Argus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] — 2026-04-15

v0.2.0 is a major feature release adding real-time CVE correlation, OWASP Top 10 2021 mapping, CVSS scoring, latest version detection, aggressive mode enhancements (login security, web crawl, 447 plugins), AI cost tracking, streaming, multi-LLM comparison, AI agent with external tools, enhanced HTML reporting, and scan diff reports.

### Added

#### CVE Correlation & Vulnerability Detection

- **New module `argus/core/vuln_db.py`** — WPVulnerability.net API client:
    - Real-time CVE/CWE lookup for plugins, themes, and WordPress core versions
    - CWE-based severity engine: SQL injection/RCE/file upload → Critical; XSS/CSRF/auth bypass → High
    - Version range matching with `lt`/`lte`/`gt`/`gte` operators and semver pre-release support
    - In-memory cache (1-hour TTL); graceful failure if API is unreachable
- **New finding `ARGUS-WP-012`**: Vulnerable plugin detected — severity auto-upgraded to critical/high based on CVE data
- **New finding `ARGUS-WP-022`**: Vulnerable theme detected
- **Enhanced `ARGUS-WP-001`**: WordPress core version now queried against CVE database; severity upgraded when CVEs are present

#### OWASP Top 10 2021 Mapping

- **New module `argus/core/owasp.py`**: maps all 84 ARGUS-WP-XXX finding IDs to their OWASP Top 10 2021 category (A01–A10); applied centrally at report time — no changes needed in individual check modules
- **HTML report**: purple OWASP badge per finding, links to the relevant OWASP Top10 page

#### Latest Version Detection

- WordPress.org API integration in `argus/core/vuln_db.py`: `get_plugin_latest_version()` and `get_theme_latest_version()` — cached, graceful on failure
- Vulnerable findings now include `latest_version` field with the current stable release
- **HTML report**: green "vX.Y.Z" badge per outdated/vulnerable component

#### CVSS Score Enrichment

- NVD NIST API v2.0 integration — `get_cvss_score(cve_id)`; tries V3.1 → V3.0 → V2 base score in order
- CVSS scores fetched in parallel (max 10 CVEs per scan to respect NVD rate limits)
- `cvss` field added to each vulnerability record in the report schema
- **HTML report**: color-coded CVSS badge per CVE — Red ≥9.0, Orange ≥7.0, Yellow ≥4.0, Green <4.0

#### Scan Diff Reports (`--diff`)

- **New CLI flag `--diff SCAN_ID`**: compare the current scan against any prior scan in the database
    - `--diff last` — selects the most recent completed scan for the same domain automatically
    - `--diff 42` — references a specific scan by ID
- **New module `argus/core/diff.py`**: categorizes findings as new / fixed / persisting (matched by ARGUS-WP-XXX code)
- Tool mismatch guard: refuses to diff scans from different tools with a clear error message
- Mode mismatch detection: safe vs aggressive diffs add `mode_mismatch: true` and show an amber warning banner in HTML explaining that "fixed" findings may simply reflect checks not run in the other mode
- Schema: new top-level `diff` object with `ref_scan_id`, `ref_date`, `ref_mode`, `current_mode`, `mode_mismatch`, `new`, `fixed`, `persisting`
- **HTML report**: diff section with summary counters (red New / green Fixed / gray Persisting), tables per category, and mode mismatch warning banner

#### Enhanced HTML Report

- **Severity filter bar**: interactive All / Critical / High / Medium / Low / Info buttons with live counts per severity
- **CVE badges**: red pills per finding linking directly to NVD
- **CWE badges**: purple pills, deduplicated across all vulnerability records for the same finding
- **CVSS score badges**: color-coded inside expandable CVE detail panels
- **Latest stable version badge**: green badge per outdated/vulnerable component
- **OWASP Top 10 2021 badge**: purple badge per finding, links to OWASP site
- **Expandable CVE detail panels**: collapsible accordion showing all vulnerability records per finding
- **Security header config snippets**: ready-to-paste Apache / Nginx / WordPress code blocks per missing header finding (HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, and more)
- **Expandable recommendations**: truncated at 200 characters with "Show more ▼" toggle
- **Diff section**: new / fixed / persisting tables with mode mismatch warning

#### Login Security Checks (Aggressive Mode Only)

New module `argus/checks/login.py` — runs only with `--aggressive`:

- **ARGUS-WP-070**: Login page accessibility (custom URL or block detected)
- **ARGUS-WP-071**: 2FA/MFA — dual detection: login page HTML scan + plugin directory probe for 13 known 2FA slugs (catches post-login plugins that leave no HTML trace)
- **ARGUS-WP-072**: CAPTCHA — reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile, common plugins
- **ARGUS-WP-073**: Brute force protection — single controlled probe detecting lockout messages and known security plugin responses
- **ARGUS-WP-074**: Open user registration (`/wp-login.php?action=register`)
- **ARGUS-WP-075**: Password policy — plugin found (info) / strength meter JS only (low) / no enforcement (medium)

#### Web Crawl & Content Discovery (Aggressive Mode Only)

New module `argus/checks/crawl.py` — runs only with `--aggressive`:

- **ARGUS-WP-080**: `robots.txt` — flags sensitive Disallow paths; ignores standard WP paths to prevent false positives
- **ARGUS-WP-081**: `sitemap.xml` — parses XML `<loc>` entries and flags security-relevant URLs
- **ARGUS-WP-082**: HTML comment extraction — regex scan of homepage for 40+ sensitive keywords (credentials, tokens, debug info, staging references)
- **ARGUS-WP-083**: Link crawl (depth 1, up to 50 links) — flags interesting internal paths with deduplication

#### Aggressive Mode Enhancements

- **Plugins**: 100 (safe) → 447 unique plugins (aggressive) — covers page builders, WooCommerce extensions, forms, SEO, backup tools, security, membership, caching, LMS, and more
- **Themes**: 25 (safe) → 43 themes (aggressive)
- **File paths**: 74 (safe) → 437 paths (aggressive) — adds git/SVN artifacts, IDE files, staging dirs, SSL keys, backup plugin artifacts
- **Directory brute-force**: 38 directory paths via HEAD requests — ARGUS-WP-032 on HTTP 200
- **User enumeration** (aggressive only): oEmbed post author extraction, login error differentiation (15 common usernames), XML-RPC `wp.getUsersBlogs` probe
- Rate limit floor: 10 req/s in aggressive mode; thread pool floor: 10 workers

#### AI Enhancements

- **AI cost tracking**: `AICostTracker` calculates real token cost per scan using a verified pricing table; results saved to `~/.argos/costs.json` and the `ai_costs` database table
- **`--ai-budget USD`**: enforce a maximum cost per scan; warns at 80% of budget, aborts AI analysis if exceeded
- **`--ai-stream`**: stream AI tokens to stdout in real time (works with all providers via LangChain LCEL `.stream()`)
- **`--ai-compare PROVIDERS`**: run analysis through multiple providers in parallel — format: `openai,anthropic` or `openai:model,anthropic:model`
- **`--ai-agent`**: agent mode with tool-calling loop using two APIs — NVD CVE lookup and WPVulnerability.net plugin search (no extra API keys required)
- **`--ai-provider` / `--ai-model`**: override provider and model at runtime without editing config files
- Default model changed: `gpt-4-turbo-preview` → `gpt-4o-mini-2024-07-18` (67x cheaper, same quality for security analysis)

#### Automated Lab Setup

- **New `docker/setup-lab.sh`**: automates turning a fresh WordPress container into a full vulnerable demo site — installs Contact Form 7 v5.3.1 and Elementor v3.5.0 (real CVE histories), creates two enumerable users, enables open registration and debug logging, adds sensitive `robots.txt` entries; integrated into `docker/deploy.sh`

---

### Changed

- **Plugin version detection** (`argus/checks/plugins.py`): 4-method cascade — HTML `?ver=` assets, `readme.txt` Stable tag, `changelog.txt` heading, PHP file header comment
- **Plugin enumeration scope** (`argus/checks/plugins.py`): safe list expanded from 8 to 100 real plugin slugs
- **Report generation** (`argus/core/report.py`): OWASP enrichment applied centrally before summary calculation; `diff` variable passed to HTML template
- **Scanner orchestration** (`argus/scanner.py`): per-scan effective config created via `copy.copy()` (no global mutation); login and crawl phases added for aggressive mode; findings saved to DB before diff computation (required for `--diff last` resolution); JSON/HTML written only after diff is computed and appended
- **AI analysis** (`argus/core/ai.py`): `analyze_report()` extended to support streaming, compare, and agent modes; `sanitize_report()` injects `_total_findings` counter to prevent LLM count hallucination (never persisted to output)
- **AI prompts** (`config/prompts/`): explicit instruction to use `_total_findings` for accurate finding count
- **Schema** (`schema/report.schema.json`): added `vulnerabilities`, `owasp`, `latest_version`, `cvss` to finding items; new top-level `diff` object; extended `ai_analysis` with compare and agent fields

---

### Fixed

- **Vulnerability title deduplication**: WPVulnerability.net reuses generic names across CVE records — fixed with 4-priority title picker (WPScan advisory name → hex source name → CVE ID → API name as last resort)
- **HTML entities in vulnerability titles**: API returns HTML-encoded strings; fixed with `html.unescape()` throughout
- **Diff computed after report was saved**: findings must be persisted to DB before `compute_diff()` can resolve `"last"` — fixed by reordering: save findings → compute diff → save JSON/HTML
- **PHP admin tool false negatives** (`files.py`): `adminer.php`, `phpinfo.php` return HTML interfaces; blanket HTML rejection suppressed them — fixed with explicit keyword check
- **`robots.txt` false positive on `/wp-content/uploads/`**: keyword `upload` matched a standard WP directive — fixed with `ROBOT_SAFE_PATHS` whitelist
- **2FA detection gap**: modern 2FA plugins inject nothing into the initial login form — fixed with plugin directory probe fallback for 13 known slugs
- **ThreadPoolExecutor capped at 5**: `min(5, max_workers)` prevented aggressive mode from reaching 10 workers — fixed to use `effective_config.max_workers` directly
- **`--threads` override overwritten by aggressive floor**: fixed with `max(self.config.max_workers, 10)` to enforce floor without overriding higher user values
- **`rate_limit_safe` mismatch**: `config.py` had `3.0`, `defaults.yaml` had `5.0` — aligned to `5.0`
- **`~` not expanded in YAML paths**: `Path('~/.argos/...')` was not resolving — fixed with `.expanduser()` on all path fields
- **`costs.json` parent directory not created**: fixed with `mkdir(parents=True, exist_ok=True)` in `save_to_file()`
- **Compare mode cost recorded as $0.00**: main tracker was never incremented in compare mode — fixed by summing `cost_by_provider`
- **Schema validation failures after AI expansion**: 6 new `ai_analysis` fields were missing from the schema — added
- **Finding ID collision**: login checks were initially assigned IDs 060-064 (conflict with config.py) — reassigned to 070-074

---

## [0.1.0] - 2025-10-20

**Initial Production Release** 🎉

Argus v0.1.0 is a comprehensive WordPress security scanner with ethical scanning practices, AI-powered analysis, and professional reporting. This release includes 130+ security checks, multi-provider AI integration, and robust error handling.

---

### Added

#### Core Security Scanner

**WordPress Detection & Fingerprinting**

- Multi-method version detection via meta tags, readme.html, RSS feeds, and asset fingerprinting
- Accurate detection with zero false positives
- Support for WordPress 4.x through 6.x

**Plugin & Theme Enumeration**

- Detection of 100+ popular WordPress plugins
- Theme identification (20+ popular themes)
- Concurrent scanning for improved performance
- Passive enumeration to minimize server load

**Sensitive File Detection**

- 70+ critical file paths monitored:
    - Configuration backups (`wp-config.php.bak`, `.old`, `.save`, `~`)
    - Database dumps (`dump.sql`, `database.sql`, `backup.sql`)
    - Environment files (`.env`)
    - Version control artifacts (`.git/`, `.svn/`)
    - Debug logs (`wp-content/debug.log`)
    - Backup archives (`backup.zip`, `backup.tar.gz`)

**User Enumeration**

- Three detection methods:
    - Author IDOR enumeration (`/?author=N`)
    - REST API user listing
    - HTML parsing (WordPress 6.x+ compatible)
- Configurable user range (default: 1-10)

**Security Headers Analysis**

- Checks for critical security headers:
    - Content-Security-Policy (CSP)
    - HTTP Strict Transport Security (HSTS)
    - X-Frame-Options
    - X-Content-Type-Options
    - X-XSS-Protection
    - Referrer-Policy
    - Permissions-Policy

**Configuration Auditing**

- XML-RPC status detection
- Directory listing exposure
- Debug mode detection
- File editor accessibility
- Database prefix enumeration

---

#### AI-Powered Analysis

**Multi-Provider Support**

- **OpenAI GPT-4 Turbo**: Premium quality, ~35 seconds per analysis
- **Anthropic Claude**: Privacy-focused alternative, ~45 seconds
- **Ollama (Local Models)**: 100% offline, no data leaves your machine

**Analysis Modes**

- **Technical Tone**: Detailed remediation guides with commands and configuration snippets
- **Non-Technical Tone**: Executive summaries in plain language for stakeholders
- **Both Modes**: Combined analysis in a single report

**Security & Privacy**

- Automatic sanitization removes sensitive data before AI processing
- No credentials, tokens, or PII sent to AI providers
- Configurable via environment variables and YAML

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

- **Consent Token System**: Verify domain ownership before aggressive scanning
    - HTTP verification (`.well-known/verify-{token}.txt`)
    - DNS TXT record verification
    - 48-hour token expiration
    - Database tracking of verified domains

**Dual Report Formats**

- **JSON Reports**: Machine-readable with schema validation
    - Complete scan metadata
    - Structured findings with evidence
    - AI analysis (when enabled)
    - ~50-65KB per scan

- **HTML Reports**: Professional, self-contained
    - Responsive design
    - Inline CSS (no external dependencies)
    - Severity-color-coded findings
    - Expandable sections
    - AI analysis beautifully formatted
    - ~208-221KB per scan

**Database Persistence**

- SQLite database for scan history
- Tracks all findings across scans
- Consent token management
- SQL views for common queries
- Automatic corruption recovery
- Read-only mode support

**Advanced Logging**

- Automatic secret redaction (passwords, tokens, API keys)
- Multiple verbosity levels (`-v`, `-vv`, `-vvv`)
- JSON and text format support
- Timestamped with severity levels

---

#### Performance & Control

**Rate Limiting**

- Configurable request throttling (1-20 req/s)
- Thread-safe implementation
- Respects server load
- Default: 5 req/s (safe) / 10 req/s (aggressive)

**Concurrent Scanning**

- Thread pool management (1-20 workers)
- Parallel checks for faster scans
- Intelligent retry logic
- Graceful degradation on failures

**Scan Modes**

- **Safe Mode** (default): Non-intrusive checks, no consent required
- **Aggressive Mode**: Deep scanning, requires verified ownership

---

#### Docker Support

**Production-Ready Container**

- Optimized 379MB image (multi-stage build)
- Non-root user execution (security best practice)
- Volume mounts for persistence
- Environment variable configuration
- Compatible with Docker Compose

**Vulnerable WordPress Lab**

- Pre-configured test environment
- Safe testing without targeting real sites
- Docker Compose setup included
- MariaDB + WordPress 6.x

---

#### Error Handling & Resilience

**Connection Error Management**

- Handles timeouts gracefully
- DNS resolution failure recovery
- Connection refused detection
- Network error handling
- Configurable timeout values

**Database Resilience**

- Automatic corruption detection
- Backup and recovery system
- Read-only mode support
- Graceful degradation when DB unavailable
- Foreign key integrity enforcement

**Partial Scan Support**

- Continues scanning despite individual check failures
- Preserves partial results if target goes offline
- Handles target restarts mid-scan
- Comprehensive error reporting

**Standardized Exit Codes**

- `0`: Scan completed successfully
- `1`: Technical error (connection, timeout, database)
- `2`: Target is not WordPress (early abort)
- `130`: User cancelled (Ctrl+C)

---

#### Developer Experience

**Rich CLI Interface**

- 30+ command-line flags
- Colored output with progress indicators
- ASCII art branding
- Comprehensive `--help` documentation
- Tab completion support (oh-my-zsh)

**Configuration Management**

- YAML configuration files
- Environment variable overrides
- CLI flag priority system
- Multi-environment support

---

### Performance

**Scan Speed**

- Core checks: 6-42 seconds (depending on target)
- With AI analysis: +30-50 seconds
- Average requests per scan: 150-200

**AI Analysis Performance**
| Provider | Duration | Quality | Cost per Scan |
|----------|----------|---------|---------------|
| OpenAI GPT-4 | ~35s | ⭐⭐⭐⭐⭐ | $0.25 |
| Anthropic Claude | ~45s | ⭐⭐⭐⭐⭐ | $0.30 |
| Ollama (CPU) | ~28min | ⭐⭐⭐ | Free |
| Ollama (GPU) | ~75s\* | ⭐⭐⭐ | Free |

\*GPU time is estimated

**Resource Usage**

- Memory: <500MB peak
- Database: <20MB for 150+ scans
- Report size: 50-221KB depending on format and AI
- Concurrent scans: Tested up to 3 simultaneous without issues

---

### Security

**Safe by Default**

- Non-intrusive checks unless explicitly authorized
- Consent enforcement for aggressive mode
- Automatic secret redaction in all outputs
- AI data sanitization (removes tokens, credentials, PII)

**Privacy Options**

- Ollama support for 100% offline operation
- No telemetry or tracking
- Local database storage only
- Configurable data retention

**Best Practices**

- Non-root Docker execution
- Schema validation for all reports
- Foreign key constraints enforced
- No information leakage in error messages
- Secure credential handling

---

### Known Limitations

These limitations are documented and tracked for future versions:

**Detection Accuracy**

- Plugin version detection is limited (shows "None" for most plugins)
- Planned improvement: IMPROV-003 in v0.2.0

**Scan Modes**

- Aggressive mode currently differs from safe mode only in rate limit
- Planned improvement: IMPROV-004 in v0.2.0 (deeper checks, more wordlists)

**AI Features**

- Provider switching requires manual YAML editing
- No cost tracking or budget limits
- No streaming responses
- Planned improvements: IMPROV-005, IMPROV-006, IMPROV-009 in v0.2.0-v0.3.0

**Ollama Performance**

- Extremely slow on CPU (~28 minutes vs 35 seconds for OpenAI)
- Recommended only for privacy-critical scenarios or when using GPU

**Database Management**

- Requires SQL knowledge for advanced queries
- Planned improvement: IMPROV-011 in v0.3.0 (interactive CLI)

---

## Installation

### Requirements

- Python 3.11+
- pip (Python package manager)
- Docker (optional, for containerized scanning)

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
        model: "gpt-4o-mini-2024-07-18" # default since v0.2.0
        temperature: 0.3
```

Or use CLI flags (v0.2.0+):

```bash
python -m argus --target example.com --use-ai --ai-provider anthropic --ai-model claude-3-5-haiku-20241022
```

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

- Backward compatible
- New features: Plugin version detection, AI cost tracking, improved HTML reports
- No database migration required

**v0.3.0** (Q3 2026):

- Database schema v2 (automatic migration provided)
- Breaking change: Configuration file format (migration tool included)
- New features: Interactive config, database CLI, AI chat

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

- Plugin version detection
- AI cost tracking & budget limits
- HTML report enrichment
- WPScan integration

**v0.3.0** (Q3 2026) - Enterprise Features

- Interactive config management
- Database CLI interface
- Multi-site scanning
- AI chat interface

**v0.4.0** (Q1 2027) - Intelligence & Automation

- ML-based detection
- Automated remediation
- Distributed scanning

See `ROADMAP.md` for complete feature list

---

## License

See `LICENSE` file for details.

---

## Acknowledgments

- WordPress community for security research
- LangChain team for AI framework
- OpenAI, Anthropic, and Ollama for AI models
- All contributors and testers

---

**Generated:** May 15, 2026
**Version:** 0.2.0
**Status:** Production Release

[0.2.0]: https://github.com/rodhnin/argus-wp-watcher/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rodhnin/argus-wp-watcher/releases/tag/v0.1.0
