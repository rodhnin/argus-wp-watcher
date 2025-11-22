# Argus Development Roadmap

## Current Version: v0.1.0 ✅ RELEASED

**Release Date:** November 2025  
**Status:** ✅ **PRODUCTION READY**

### Features Included

#### Core Scanning

-   ✅ **WordPress Fingerprinting**: Multi-method version detection (meta tags, readme.html, RSS feeds, CSS/JS)
-   ✅ **Plugin Enumeration**: Concurrent scanning with wordlist-based detection (100+ common plugins)
-   ✅ **Theme Detection**: Active and inactive theme enumeration (20+ popular themes)
-   ✅ **Sensitive File Detection**: 70+ critical paths including:
    -   Configuration backups (`wp-config.php.bak`, `.old`, `.save`, `~`)
    -   Database dumps (`dump.sql`, `database.sql`, `backup.sql`)
    -   Environment files (`.env`, `.git/`)
    -   Debug logs (`wp-content/debug.log`)
-   ✅ **User Enumeration**: Three detection methods (Author IDOR, REST API, HTML parsing for WordPress 6.x+)
-   ✅ **Security Headers Analysis**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and more
-   ✅ **Configuration Issues**: XML-RPC status, directory listing, debug mode, file editor access

#### Performance & Control

-   ✅ **Rate Limiting**: Configurable request throttling (1-20 req/s) with thread-safe implementation
-   ✅ **Thread Pool Management**: Concurrent scanning with 1-20 worker threads
-   ✅ **Intelligent Retry Logic**: Automatic retry on transient failures
-   ✅ **Graceful Degradation**: Continues scanning even if components fail

#### Infrastructure

-   ✅ **Consent Token System**: Ethical scanning with HTTP/.well-known or DNS TXT verification
-   ✅ **SQLite Database**: Complete scan history, findings tracking, verified domain management
-   ✅ **Dual Reporting**: JSON (machine-readable) and HTML (human-readable) formats
-   ✅ **Professional HTML Reports**: Responsive, self-contained, 200+ KB with AI analysis
-   ✅ **Automatic Secret Redaction**: Logging system prevents credential leaks
-   ✅ **Multi-Source Configuration**: YAML defaults + environment variables + CLI overrides
-   ✅ **Docker Support**: Production-ready containerized scanning (379MB optimized image)

#### AI-Powered Analysis (3 Providers)

-   ✅ **OpenAI GPT-4 Turbo**: Premium quality analysis (~35s, $0.25/scan)
-   ✅ **Anthropic Claude**: Privacy-focused alternative (~45s, $0.30/scan)
-   ✅ **Ollama (Local Models)**: 100% offline analysis (free, no data leaves your machine)
-   ✅ **Executive Summaries**: Business-friendly language for non-technical stakeholders
-   ✅ **Technical Remediation Guides**: Step-by-step instructions with commands and configuration
-   ✅ **Dual-Tone Mode**: Both executive and technical analysis in single report
-   ✅ **Automatic Sanitization**: Zero secrets leaked to AI providers

#### Resilience & Error Handling

-   ✅ **Connection Error Recovery**: Handles timeouts, DNS failures, refused connections
-   ✅ **Database Corruption Recovery**: Automatic backup and recreation
-   ✅ **Read-Only Mode**: Graceful degradation when database is locked
-   ✅ **Partial Scan Support**: Preserves results even if target goes offline mid-scan
-   ✅ **Standardized Exit Codes**: 0=success, 1=error, 2=not-wordpress, 130=cancelled

#### Developer Experience

-   ✅ **Rich CLI Interface**: Colored output, progress tracking, ASCII art branding
-   ✅ **Verbosity Levels**: `-v` (INFO), `-vv` (DEBUG) for troubleshooting
-   ✅ **Comprehensive Help**: Built-in documentation with examples
-   ✅ **Flexible Deployment**: Native Python, Docker, or containerized scanning

### Performance Benchmarks (v0.1.0)

-   **Scan Duration**: 6-42 seconds (depending on configuration)
-   **Database Efficiency**: 2.0 MB for 5,000+ findings
-   **Query Performance**: 5-50ms for complex aggregations
-   **Concurrent Scanning**: 3+ simultaneous scans without race conditions
-   **Scalability**: Tested up to 1,000+ scans with linear performance

---

## v0.2.0 - Enhanced Detection & AI Features

**Theme:** Deep Vulnerability Analysis + Advanced AI Capabilities  
**Target Release:** Q2 2026 (April-May)  
**Focus:** Detection accuracy, AI enhancements, reporting improvements

---

### 🎯 Enhanced HTML Reporting

**Ticket:** IMPROV-002  
**Priority:** High

#### Current Limitations

-   No CVE/CWE mapping for detected plugins
-   References lack metadata (title, domain, type)
-   Security headers shown without configuration examples
-   Recommendations are truncated
-   No grouping or filtering by category/severity

#### Planned Improvements

**1. CVE/CWE Badges**

```html
<!-- Before -->
<tr>
    <td>contact-form-7</td>
    <td>Version unknown</td>
</tr>

<!-- After -->
<tr>
    <td>contact-form-7</td>
    <td>v5.5.3 <span class="badge badge-critical">CVE-2023-4734</span></td>
    <td><span class="badge">CWE-79: XSS</span></td>
    <td><a href="https://nvd.nist.gov/vuln/detail/CVE-2023-4734">NVD</a></td>
</tr>
```

**2. Reference Enrichment**

```json
{
    "references": [
        {
            "url": "https://wordpress.org/plugins/contact-form-7/",
            "title": "Contact Form 7 - WordPress Plugin",
            "domain": "wordpress.org",
            "type": "official_documentation",
            "year": 2024
        }
    ]
}
```

**3. Security Headers with Snippets**

```html
<div class="finding">
    <h4>❌ Missing: Content-Security-Policy</h4>
    <p>Protect against XSS attacks with CSP header</p>

    <!-- Apache -->
    <pre><code>Header set Content-Security-Policy "default-src 'self'"</code></pre>

    <!-- Nginx -->
    <pre><code>add_header Content-Security-Policy "default-src 'self'";</code></pre>

    <!-- WordPress -->
    <pre><code>add_action('send_headers', function() {
    header("Content-Security-Policy: default-src 'self'");
});</code></pre>
</div>
```

**4. Expandable Recommendations**

```html
<!-- No more truncation -->
<div class="recommendation">
    <button class="expand-btn">Show full recommendation</button>
    <div class="content" style="display:none">
        <!-- Full 2000+ character recommendation -->
    </div>
</div>
```

**5. Findings Grouping**

```javascript
// Filter by severity
[Critical: 9] [High: 6] [Medium: 14] [Low: 4] [Info: 66]

// Group by category
📁 Sensitive Files (13)
📁 Security Headers (6)
📁 Configuration Issues (9)
📁 Plugins Detected (49)
```

**Benefits:**

-   Actionable insights (copy-paste configuration snippets)
-   Clear vulnerability correlation (CVE/CWE mapping)
-   Better organization (filtering and grouping)
-   Enhanced credibility (reference metadata)

---

### 🔍 Plugin Version Detection

**Ticket:** IMPROV-003  
**Priority:** High

#### Current Limitations

All plugins detected but version shows "None":

```json
{
    "title": "Plugin detected: contact-form-7",
    "version": "None" // ❌ Not actionable
}
```

#### Detection Methods

**1. Changelog Parsing**

```bash
GET /wp-content/plugins/contact-form-7/changelog.txt

Response:
= 5.8.4 =
* Fix: XSS vulnerability in admin panel
* Release date: 2024-01-15
```

**2. Asset URL Fingerprinting**

```bash
GET /wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.8.4
                                                                   ^^^^^^
# Extract version from query parameter
```

**3. Readme.txt Parsing**

```bash
GET /wp-content/plugins/contact-form-7/readme.txt

Stable tag: 5.8.4
Requires at least: 5.9
Tested up to: 6.4
```

**4. Header Comment Inspection**

```bash
GET /wp-content/plugins/contact-form-7/wp-contact-form-7.php

/*
Plugin Name: Contact Form 7
Version: 5.8.4
Author: Takayuki Miyoshi
*/
```

**5. SVN/Git Tags (if exposed)**

```bash
GET /wp-content/plugins/contact-form-7/.git/HEAD
GET /wp-content/plugins/contact-form-7/.svn/entries
```

#### Enhanced Output

**Before:**

```json
{
    "title": "Plugin detected: contact-form-7",
    "version": "None",
    "severity": "info"
}
```

**After:**

```json
{
    "title": "Vulnerable plugin: contact-form-7",
    "version": "5.5.3",
    "latest_version": "5.8.4",
    "severity": "critical",
    "vulnerabilities": [
        {
            "cve": "CVE-2023-4734",
            "cvss": 7.5,
            "description": "Stored XSS in admin dashboard",
            "exploit_available": true,
            "exploit_db_id": "51234"
        }
    ],
    "recommendation": "Update to version 5.8.4 immediately"
}
```

#### Additional Features

-   **Inactive Plugin Detection**: Find plugins in `/wp-content/plugins/` not active
-   **Must-Use Plugins**: Check `/wp-content/mu-plugins/`
-   **Drop-ins**: Detect custom `db.php`, `advanced-cache.php`, etc.
-   **Custom Wordlists**: Import from WPScan, SecLists, or user-provided lists

**Target Accuracy:** ≥70% version detection rate

**Benefits:**

-   Transform "info" findings into "critical" vulnerabilities
-   Enable CVE correlation
-   Prioritize patching efforts
-   Reduce false negatives

---

### ⚡ Aggressive Mode Enhancement

**Ticket:** IMPROV-004  
**Priority:** High

#### Current Limitations

Aggressive mode only differs in rate limiting:

-   Safe mode: 5 req/s, 5 threads
-   Aggressive mode: 10 req/s, 10 threads
-   **Same 99 findings** (no additional checks)

#### Planned Enhancements

**1. Plugin Enumeration**

```yaml
safe_mode:
    max_plugins_check: 100 # Top 100 popular plugins

aggressive_mode:
    max_plugins_check: 500 # Extended wordlist
    custom_wordlists:
        - wpscan_popular.txt # Official WPScan list
        - seclists_plugins.txt # SecLists collection
        - user_custom.txt # User-provided list
```

**2. User Enumeration**

```yaml
safe_mode:
    max_users_check: 10 # Users 1-10

aggressive_mode:
    max_users_check: 50 # Users 1-50
    methods:
        - author_idor # /?author=1
        - rest_api # /wp-json/wp/v2/users
        - oembed # /wp-json/oembed/1.0/embed
        - login_error_messages # Different errors for valid/invalid users
        - xmlrpc_enumeration # system.multicall method
```

**3. Sensitive Files**

```yaml
safe_mode:
    sensitive_files: 70 # Common files

aggressive_mode:
    sensitive_files: 400+ # Comprehensive list
    additional_paths:
        # Backup files
        - wp-config.{bak,old,save,swp,tmp,~,1,2}
        - database.{sql,gz,zip,tar,tar.gz}

        # Version control
        - .git/{HEAD,config,index,logs/HEAD}
        - .svn/{entries,wc.db}
        - .hg/{requires,store}

        # Development files
        - composer.{json,lock}
        - package.{json,lock}
        - yarn.lock
        - .env.{local,development,production}

        # Editor files
        - .idea/
        - .vscode/
        - .project
        - .settings/
```

**4. Directory Brute-Force**

```yaml
aggressive_mode:
    directory_bruteforce: true
    wordlists:
        - common_dirs.txt # /admin, /backup, /old
        - developer_dirs.txt # /dev, /test, /staging
        - year_based.txt # /2023, /2024
```

**5. Login Detection**

```yaml
aggressive_mode:
    login_checks:
        - brute_force_detection: # Is rate limiting enabled?
              attempts: 5
              delay: 1s
        - two_factor_detection: # 2FA enabled?
        - captcha_detection: # CAPTCHA present?
        - password_policy: # Weak passwords allowed?
```

**6. Advanced Crawling**

```yaml
aggressive_mode:
    crawling:
        enabled: true
        max_depth: 3
        follow_redirects: true
        parse_sitemap: true # sitemap.xml
        parse_robots: true # robots.txt
        extract_comments: true # HTML comments with TODOs
```

**7. Per-Module Behaviors**

```python
# Example: Aggressive file checking
def check_sensitive_files(aggressive=False):
    if aggressive:
        # Try multiple extensions
        for backup in ['.bak', '.old', '.save', '~', '.1']:
            check(f'wp-config.php{backup}')

        # Try timestamped backups
        for year in range(2020, 2025):
            check(f'backup-{year}.sql')

        # Try common naming patterns
        check('wp-config.php.20241019')
        check('wp-config-backup.php')
```

#### Expected Results

| Mode           | Plugins | Users | Files | Duration | Findings |
| -------------- | ------- | ----- | ----- | -------- | -------- |
| **Safe**       | 100     | 10    | 70    | ~40s     | 99       |
| **Aggressive** | 500     | 50    | 400+  | ~180s    | 200-300  |

**Benefits:**

-   Real value differentiation between modes
-   Deeper coverage for penetration testing
-   Configurable aggression levels
-   Respects consent requirements

---

### 💰 AI Cost Tracking & Budget Limits

**Ticket:** IMPROV-005  
**Priority:** Medium

#### Problem Statement

No visibility into AI costs per scan. Enterprises need cost controls.

#### Configuration

```yaml
# config/defaults.yaml
ai:
    budget:
        enabled: true
        max_cost_per_scan: 0.50 # USD
        max_tokens_per_request: 3000 # Hard limit
        warn_threshold: 0.80 # Warn at 80% ($0.40)
        abort_on_exceed: true # Stop if budget exceeded

    tracking:
        log_costs: true
        cost_report: ~/.argos/costs.json
```

#### Runtime Output

```bash
python -m argus --target example.com --use-ai --ai-tone both

[Phase 6/6] AI Analysis...
  ├─ Executive Summary: 1,250 tokens → $0.12
  ├─ Technical Guide: 1,580 tokens → $0.16
  └─ Total AI Cost: $0.28 / $0.50 budget (56% used)

⚠️  WARNING: 80% budget threshold reached ($0.40 / $0.50)
```

#### Cost Report

```json
// ~/.argos/costs.json
{
    "scans": [
        {
            "scan_id": 45,
            "timestamp": "2025-10-19T18:52:43Z",
            "provider": "openai",
            "model": "gpt-4-turbo-preview",
            "executive_summary": {
                "tokens_input": 1500,
                "tokens_output": 1250,
                "cost": 0.12
            },
            "technical_guide": {
                "tokens_input": 1500,
                "tokens_output": 1580,
                "cost": 0.16
            },
            "total_cost": 0.28,
            "budget_remaining": 0.22
        }
    ],
    "totals": {
        "total_scans": 45,
        "total_cost": 12.6,
        "avg_cost_per_scan": 0.28,
        "monthly_projection": 25.2
    }
}
```

#### Budget Enforcement

```bash
# Scenario: Budget exceeded
python -m argus --target example.com --use-ai --ai-tone both

[Phase 6/6] AI Analysis...
  ├─ Executive Summary: 1,250 tokens → $0.12
  ├─ Technical Guide: Starting...

❌ ERROR: Budget exceeded ($0.52 > $0.50 limit)
   Aborting AI analysis to prevent overspending.

   Scan completed without AI analysis.
   Report saved: argus_report_20251019_185243.json
```

#### CLI Commands

```bash
# View cost statistics
argus costs show --last 30d

# Set budget limits
argus costs set-budget --max 1.00 --warn 0.80

# Export cost report
argus costs export --format csv --output costs.csv
```

**Benefits:**

-   Cost transparency (know exactly what you spend)
-   Budget enforcement (prevent surprise bills)
-   Monthly projections (plan AI usage)
-   Enterprise compliance (required for procurement)

---

### 🌊 AI Streaming Responses

**Ticket:** IMPROV-006  
**Priority:** Low

#### Current Behavior

```bash
[Phase 6/6] AI Analysis...
  ⏳ Generating insights... (user waits 30+ seconds)
  ✓ Analysis complete
```

#### Streaming Behavior

```bash
[Phase 6/6] AI Analysis...
  [Executive Summary] Analyzing security posture...
  [Executive Summary] ████████░░ 80% - Identifying key risks...
  [Executive Summary] ✓ Complete (2,500 chars in 19s)

  [Technical Guide] Generating remediation steps...
  [Technical Guide] ████░░░░░░ 40% - WordPress core hardening...
  [Technical Guide] ████████░░ 80% - Plugin security...
  [Technical Guide] ✓ Complete (5,200 chars in 33s)
```

#### Implementation

```python
# LangChain streaming API
from langchain.callbacks.streaming_stdout import StreamingStdOutCallbackHandler

chain = prompt | llm.stream()

for chunk in chain:
    print(chunk.content, end='', flush=True)
    # Update progress bar in real-time
```

#### Benefits

-   **Improved UX**: See progress instead of blank screen
-   **Reduced Perceived Latency**: 30s feels faster when you see output
-   **Better for Slow Models**: Critical for Ollama (28 min → see progress)
-   **Error Detection**: Know immediately if AI stalls

**Trade-off:** Slightly more complex code (async handling)

---

### 🤖 Multi-LLM Comparison Mode

**Ticket:** IMPROV-007  
**Priority:** Low

#### Use Case

Compare outputs from multiple LLMs to reduce hallucinations and improve quality.

#### Configuration

```yaml
# config/defaults.yaml
ai:
    comparison_mode:
        enabled: true
        models:
            - provider: openai
              model: gpt-4-turbo-preview
              weight: 0.5 # 50% weight in consensus

            - provider: anthropic
              model: claude-3-5-sonnet
              weight: 0.3 # 30% weight

            - provider: ollama
              model: llama3.2
              weight: 0.2 # 20% weight

        consensus_method: weighted_vote
        min_agreement: 0.7 # 70% agreement required
```

#### Output

```json
{
    "ai_analysis": {
        "comparison_mode": true,
        "models_compared": 3,

        "gpt4_executive_summary": "Your WordPress site has 9 critical issues...",
        "claude_executive_summary": "Security assessment reveals 9 high-priority vulnerabilities...",
        "llama_executive_summary": "Found 9 serious security problems...",

        "consensus_summary": {
            "text": "Analysis from 3 AI models agrees: 9 critical security issues require immediate attention...",
            "agreement_score": 0.85,
            "key_points": [
                "Outdated plugins (100% agreement)",
                "Missing security headers (100% agreement)",
                "Exposed configuration files (67% agreement)"
            ]
        },

        "cost_breakdown": {
            "gpt4": 0.25,
            "claude": 0.3,
            "llama": 0.0,
            "total": 0.55
        }
    }
}
```

#### CLI Usage

```bash
# Compare 2 models
python -m argus --target example.com \
  --use-ai \
  --ai-compare openai,anthropic

# Compare all 3
python -m argus --target example.com \
  --use-ai \
  --ai-compare all
```

#### Consensus Algorithm

```python
def generate_consensus(responses):
    # Extract key facts from each response
    facts_gpt4 = extract_facts(responses['gpt4'])
    facts_claude = extract_facts(responses['claude'])
    facts_llama = extract_facts(responses['llama'])

    # Find common facts (agreement)
    consensus_facts = facts_gpt4 & facts_claude & facts_llama

    # Find disputed facts (disagreement)
    disputed_facts = (facts_gpt4 ^ facts_claude) | (facts_gpt4 ^ facts_llama)

    # Generate merged summary with confidence scores
    return merge_with_weights(consensus_facts, weights)
```

**Benefits:**

-   **Quality Assurance**: Cross-validation between models
-   **Reduced Hallucinations**: 30-40% fewer false statements
-   **Confidence Scoring**: Know when models agree/disagree
-   **Best of All Worlds**: GPT-4 speed + Claude safety + Llama privacy

**Trade-offs:**

-   Higher cost (3x API calls)
-   Longer duration (~2-3 minutes)
-   Complexity (managing multiple responses)

---

### 🛠️ AI Agent Enhancement

**Ticket:** IMPROV-008  
**Priority:** Medium  
**Effort:** 6-8 hours (v0.2.0 foundation, full expansion in v0.3.0)

#### Vision

Transform AI from passive analyzer to active research agent with tools and memory.

#### External Tools

**1. WPScan Vulnerability Database**

```python
@tool
def search_wpscan(plugin_name: str, version: str) -> dict:
    """Search WPScan database for known vulnerabilities"""
    response = requests.get(
        f"https://wpscan.com/api/v3/plugins/{plugin_name}",
        headers={"Authorization": f"Token {WPSCAN_API_KEY}"}
    )
    return response.json()

# Agent usage:
# "I found contact-form-7 version 5.5.3. Let me check WPScan..."
# → Finds CVE-2023-4734
```

**2. NVD CVE Lookup**

```python
@tool
def lookup_cve(cve_id: str) -> dict:
    """Get CVE details from National Vulnerability Database"""
    response = requests.get(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    )
    return {
        "cvss_score": data['cvss_v3_score'],
        "severity": data['severity'],
        "description": data['description'],
        "published": data['published_date']
    }
```

**3. ExploitDB Search**

```python
@tool
def search_exploitdb(query: str) -> list:
    """Search Exploit Database for public exploits"""
    # Search exploitdb.com API
    return [
        {
            "edb_id": "51234",
            "title": "WordPress Contact Form 7 5.5.3 - Stored XSS",
            "url": "https://www.exploit-db.com/exploits/51234",
            "platform": "php/webapps"
        }
    ]
```

#### Persistent Memory

```python
class AgentMemory:
    def __init__(self):
        self.short_term = []   # Last 10 interactions
        self.long_term = {}    # Learned patterns

    def remember(self, finding):
        """Store finding in memory"""
        self.short_term.append(finding)

        # Learn patterns
        if finding['plugin'] in self.long_term:
            self.long_term[finding['plugin']]['occurrences'] += 1

    def recall(self, query):
        """Retrieve relevant memories"""
        return [m for m in self.short_term if query in m['description']]

# Agent usage:
# "I remember seeing this plugin vulnerable in previous scan..."
```

#### Enhanced Prompts

```python
system_prompt = """
You are an AI security researcher with access to:
- WPScan vulnerability database
- NVD CVE lookup
- ExploitDB search

When analyzing findings:
1. Check WPScan for plugin vulnerabilities
2. Look up CVE details if found
3. Search ExploitDB for public exploits
4. Provide specific remediation steps

You have memory of previous scans. Connect related findings.
"""
```

#### Example Agent Workflow

```
User Query: "Analyze contact-form-7"

Agent Reasoning:
1. "Let me check what version was detected..."
   → Recall from findings: version 5.5.3

2. "Let me search WPScan database..."
   → Tool call: search_wpscan("contact-form-7", "5.5.3")
   → Found: CVE-2023-4734

3. "Let me get CVE details..."
   → Tool call: lookup_cve("CVE-2023-4734")
   → CVSS: 7.5 (High), Type: Stored XSS

4. "Let me check for exploits..."
   → Tool call: search_exploitdb("contact-form-7 5.5.3")
   → Found: EDB-51234 (public exploit available)

Agent Response:
"🚨 CRITICAL: Contact Form 7 version 5.5.3 is vulnerable to Stored XSS (CVE-2023-4734, CVSS 7.5).

A public exploit is available (ExploitDB #51234). This allows attackers to inject malicious JavaScript in the admin dashboard.

IMMEDIATE ACTION REQUIRED:
1. Update to version 5.8.4+: `wp plugin update contact-form-7`
2. Review admin accounts for suspicious activity
3. Check database for injected scripts: `wp db search '<script'`

This vulnerability was added to WPScan database on 2023-09-15."
```

**Benefits:**

-   **Real-time Vulnerability Correlation**: No manual CVE lookup
-   **Contextual Analysis**: Connects findings across scans
-   **Automated Research**: Agent does the investigation work
-   **Foundation for v0.3.0**: Enables interactive chat features

---

### 📚 Additional v0.2.0 Features

#### WPScan API Integration

-   Vulnerability database correlation
-   CVE matching for detected plugins/themes/core
-   Automatic exploit availability checking
-   Known vulnerability severity mapping

#### Advanced Crawling

-   Spider mode: `--crawl` flag
-   Configurable depth: `--max-depth 3`
-   Same-domain restriction
-   Sitemap.xml and robots.txt parsing
-   Link extraction and form discovery

#### Improved Reporting

-   PDF export with custom branding
-   CVSS scoring for vulnerabilities
-   Compliance mapping (OWASP Top 10, CWE)
-   Trend graphs (security posture over time)
-   Diff reports (compare two scans)

**Breaking Changes:** None (fully backward compatible)

---

## v0.3.0 - Enterprise & Interactive Features

**Theme:** Scale, Automation, and Conversational AI  
**Target Release:** Q3 2026 (July-August)  
**Focus:** Enterprise needs, multi-site scanning, interactive AI

---

### 🛠️ Interactive Config Management

**Ticket:** IMPROV-009  
**Priority:** Medium

#### Problem Statement

Currently, changing AI provider requires manual YAML editing and application restart. No runtime configuration or profiles.

#### Metasploit-Style Interface

```bash
# Show current configuration
$ argus --show-options

╔═══════════════════════════════════════════════╗
║         ARGUS CONFIGURATION                   ║
╠═══════════════════════════════════════════════╣
║ SCAN SETTINGS                                 ║
╠═══════════════════════════════════════════════╣
║ mode             safe          [safe|aggressive]
║ rate_limit.safe  5.0           req/s          ║
║ rate_limit.aggr  10.0          req/s          ║
║ max_workers      5             threads        ║
║ timeout          30            seconds        ║
╠═══════════════════════════════════════════════╣
║ AI SETTINGS                                   ║
╠═══════════════════════════════════════════════╣
║ ai.provider      openai        [openai|anthropic|ollama]
║ ai.model         gpt-4-turbo   string         ║
║ ai.temperature   0.3           0.0-1.0        ║
║ ai.max_tokens    3000          integer        ║
╠═══════════════════════════════════════════════╣
║ DATABASE                                      ║
╠═══════════════════════════════════════════════╣
║ db.path          ~/.argos/     path           ║
║ db.backup        true           bool          ║
╚═══════════════════════════════════════════════╝
```

#### Modify Settings

```bash
# Set individual values
$ argus --set rate_limit.safe=3.0
✓ Updated: rate_limit.safe = 3.0

$ argus --set ai.provider=anthropic
✓ Updated: ai.provider = anthropic
✓ Updated: ai.model = claude-3-5-sonnet (auto-adjusted)

# Set multiple at once
$ argus --set rate_limit.safe=3.0 --set max_workers=10
✓ Updated 2 settings

# Reset to defaults
$ argus --reset-config
⚠️  This will reset ALL settings to factory defaults.
Continue? [y/N]: y
✓ Configuration reset

$ argus --reset-config ai
✓ Reset AI section to defaults
```

#### Configuration Profiles

```bash
# Save current config as profile
$ argus --save-profile fast-scan
✓ Saved profile: fast-scan
  - rate_limit: 20 req/s
  - max_workers: 10
  - ai: disabled

# Create specialized profiles
$ argus --set ai.provider=ollama --save-profile privacy-mode
✓ Saved profile: privacy-mode (100% offline, no data leaves machine)

$ argus --set mode=aggressive --set rate_limit.aggr=20 --save-profile pentest
✓ Saved profile: pentest (deep scanning, requires consent)

# List profiles
$ argus --list-profiles
Available profiles:
  ├─ default        (Factory settings)
  ├─ fast-scan      (High speed, no AI)
  ├─ privacy-mode   (Ollama local, 100% offline)
  └─ pentest        (Aggressive mode, deep scan)

# Load profile
$ argus --load-profile privacy-mode
✓ Loaded profile: privacy-mode
  - ai.provider: ollama
  - ai.model: llama3.2
  - No data sent to external APIs

# Use profile for single scan
$ argus --target example.com --profile pentest
[Using profile: pentest]
Mode: aggressive
Rate: 20 req/s
Findings: 245
```

#### Export/Import Profiles

```bash
# Export profile to file
$ argus --export-profile pentest --output pentest-config.yaml
✓ Exported to: pentest-config.yaml

# Import from file
$ argus --import-profile pentest-config.yaml --name company-standard
✓ Imported profile: company-standard

# Share with team
$ cat pentest-config.yaml
name: pentest
description: Penetration testing configuration
settings:
  mode: aggressive
  rate_limit:
    aggressive: 20
  max_workers: 10
  ai:
    enabled: true
    provider: openai
    model: gpt-4-turbo-preview
```

**Benefits:**

-   **No YAML editing**: User-friendly CLI interface
-   **Real-time validation**: Instant feedback on invalid values
-   **Reusable profiles**: Save configurations for different scenarios
-   **Team collaboration**: Share profiles as files
-   **Runtime switching**: Change AI provider without restart

---

### 💾 Interactive Database CLI

**Ticket:** IMPROV-011  
**Priority:** Medium

#### Problem Statement

Database management requires SQL knowledge. No user-friendly interface for querying scans, findings, or domains.

#### Management Commands

**Clients**

```bash
# List all clients
$ argus db clients list
ID  Name            Domain              Email                  Created
1   Acme Corp       acme.com            security@acme.com      2025-01-15
2   Beta Inc        beta.org            admin@beta.org         2025-02-20
3   Gamma LLC       gamma.io            team@gamma.io          2025-03-10

# Filter clients
$ argus db clients list --filter acme
ID  Name            Domain              Email
1   Acme Corp       acme.com            security@acme.com

# Show client details
$ argus db clients show 1
╔═══════════════════════════════════════════════╗
║ CLIENT #1: Acme Corp                          ║
╠═══════════════════════════════════════════════╣
║ Domain:        acme.com                       ║
║ Email:         security@acme.com              ║
║ Created:       2025-01-15 10:30:45            ║
║ Last Scan:     2025-10-19 18:52:43            ║
║ Total Scans:   23                             ║
║ Total Findings: 2,277                         ║
╚═══════════════════════════════════════════════╝

Verified Domains:
  ✓ acme.com (verified 2025-01-15, expires 2025-01-17)
  ✓ staging.acme.com (verified 2025-02-01)
```

**Scans**

```bash
# List recent scans
$ argus db scans list --limit 10
ID   Target              Mode        Status     Findings  Date
61   localhost:8080      safe        completed  99        2025-10-19 18:52
60   localhost:8080      safe        completed  99        2025-10-19 18:51
59   acme.com            aggressive  completed  245       2025-10-18 14:30
58   beta.org            safe        completed  87        2025-10-17 09:15

# Show scan details
$ argus db scans show 59
╔═══════════════════════════════════════════════╗
║ SCAN #59                                      ║
╠═══════════════════════════════════════════════╣
║ Target:        acme.com                       ║
║ Mode:          aggressive                     ║
║ Status:        completed                      ║
║ Started:       2025-10-18 14:30:12            ║
║ Completed:     2025-10-18 14:33:45            ║
║ Duration:      3m 33s                         ║
╠═══════════════════════════════════════════════╣
║ FINDINGS BY SEVERITY                          ║
╠═══════════════════════════════════════════════╣
║ Critical:      18                             ║
║ High:          34                             ║
║ Medium:        67                             ║
║ Low:           45                             ║
║ Info:          81                             ║
║ TOTAL:         245                            ║
╚═══════════════════════════════════════════════╝

Reports:
  JSON: ~/.argos/reports/argus_report_acme_20251018_143012.json
  HTML: ~/.argos/reports/argus_report_acme_20251018_143012.html

# Show findings for scan
$ argus db scans show 59 --findings --severity critical
Critical Findings for Scan #59:
  1. wp-config.php.bak exposed
  2. database.sql publicly accessible
  3. contact-form-7 v5.5.3 (CVE-2023-4734)
  ...
```

**Findings**

```bash
# List critical findings
$ argus db findings critical --limit 20
ID    Scan  Severity   Title                              Target
1234  59    critical   wp-config.php.bak exposed          acme.com
1235  59    critical   database.sql accessible            acme.com
1236  58    critical   outdated WordPress core (6.0.0)    beta.org

# Search findings
$ argus db findings search "contact-form"
ID    Scan  Severity   Title                              Target
890   59    critical   contact-form-7 v5.5.3 (CVE-2023-)  acme.com
891   58    info       contact-form-7 detected            beta.org
892   57    high       contact-form-7 v5.6.0 (outdated)   gamma.io

# Filter by code
$ argus db findings list --code ARGUS-WP-010
ID    Scan  Severity   Title                              Date
456   59    critical   Exposed backup file                2025-10-18
457   58    high       Backup file detected               2025-10-17

# Export findings to CSV
$ argus db findings export --format csv --output findings.csv
✓ Exported 2,277 findings to findings.csv
```

**Consent Tokens**

```bash
# List verified domains
$ argus db tokens list
Domain              Method  Verified            Expires
acme.com            http    2025-01-15 10:30    2025-01-17 10:30
staging.acme.com    dns     2025-02-01 14:20    2025-02-03 14:20
beta.org            http    2025-03-10 09:00    EXPIRED

# Check specific domain
$ argus db tokens check --domain acme.com
✓ Domain verified: acme.com
  Method:    HTTP (.well-known)
  Verified:  2025-01-15 10:30:45
  Expires:   2025-01-17 10:30:45
  Status:    VALID (15 hours remaining)

# Remove expired tokens
$ argus db tokens cleanup --expired
Removed 3 expired tokens
```

**Statistics**

```bash
$ argus db stats
╔═══════════════════════════════════════════════╗
║ DATABASE STATISTICS                           ║
╠═══════════════════════════════════════════════╣
║ Total Clients:        3                       ║
║ Total Scans:          61                      ║
║ Total Findings:       5,093                   ║
║ Verified Domains:     7 (2 expired)           ║
╠═══════════════════════════════════════════════╣
║ FINDINGS BY SEVERITY                          ║
╠═══════════════════════════════════════════════╣
║ Critical:             470 (9.2%)              ║
║ High:                 309 (6.1%)              ║
║ Medium:               731 (14.4%)             ║
║ Low:                  213 (4.2%)              ║
║ Info:                 3,370 (66.2%)           ║
╠═══════════════════════════════════════════════╣
║ DATABASE SIZE                                 ║
╠═══════════════════════════════════════════════╣
║ Size:                 2.0 MB                  ║
║ Query Performance:    5-33 ms (avg)           ║
║ Last Backup:          2025-10-19 12:00        ║
╚═══════════════════════════════════════════════╝
```

**Backup & Maintenance**

```bash
# Backup database
$ argus db backup --output ~/backups/argos-$(date +%Y%m%d).db
✓ Database backed up to: ~/backups/argos-20251019.db

# Cleanup old scans
$ argus db cleanup --older-than 90d
Found 12 scans older than 90 days (1,188 findings)
Delete? [y/N]: y
✓ Deleted 12 scans and 1,188 findings

# Vacuum database
$ argus db vacuum
✓ Database optimized (2.0 MB → 1.8 MB)

# Integrity check
$ argus db check
✓ Database integrity OK
✓ Foreign keys consistent
✓ No orphan records
```

**Benefits:**

-   **No SQL knowledge required**: User-friendly commands
-   **Rapid auditing**: Quickly find critical findings
-   **Automation-friendly**: Machine-readable output
-   **Consistent validation**: Built-in data integrity checks

---

### 💬 Interactive AI Chat

Transform AI from batch analyzer to conversational assistant.

```bash
# Start chat session
$ argus chat --scan-id 59

Argus AI Chat (Scan #59: acme.com)
Type 'exit' to quit, 'help' for commands

You: What changed since last scan?
AI: Compared to scan #58, I found 2 new critical findings:
    1. wp-config.php.bak (new file exposed)
    2. contact-form-7 updated to vulnerable version 5.5.3

You: How do I fix the wp-config issue?
AI: To fix exposed wp-config.php.bak:

    1. Remove the backup file:
       $ rm /var/www/html/wp-config.php.bak

    2. Add to .htaccess to prevent future exposure:
       <FilesMatch "wp-config.*">
         Require all denied
       </FilesMatch>

    3. Review server for other backups:
       $ find /var/www/html -name "*.bak" -o -name "*.old"

You: Is there a public exploit for contact-form-7?
AI: Yes, CVE-2023-4734 has a public exploit (ExploitDB #51234).
    It's a Stored XSS vulnerability allowing JavaScript injection
    in the admin dashboard. Update to v5.8.4+ immediately.
```

**Features:**

-   Natural language queries
-   Multi-turn dialogue with context
-   Scan comparison and diff analysis
-   Step-by-step remediation guidance
-   Integration with WPScan, CVE, ExploitDB tools

---

### 📊 Additional v0.3.0 Features

#### Multi-Site Scanning

-   Batch scanning: `--targets-file urls.txt`
-   Network-wide scanning (WordPress Multisite)
-   Aggregate reports across multiple sites
-   Parallel scanning with queue management

#### CI/CD Integration

-   Jenkins plugin/script examples
-   GitHub Actions workflow templates
-   GitLab CI templates
-   Exit codes for CI (fail on severity threshold)
-   JUnit XML output for test reporting

#### REST API Server

-   FastAPI-based REST API
-   Async scan triggering
-   Webhook notifications
-   Multi-user authentication
-   Rate limiting per user
-   OpenAPI/Swagger documentation

**Breaking Changes:** Database schema v2 (auto-migration provided)  
**Migration:** `argus db migrate` (automatic on first run)

---

## v0.4.0 - Intelligence & Automation

**Theme:** Smart Automation with ML and AI Agents  
**Target Release:** Q1 2027
**Focus:** Automated remediation, ML detection, advanced AI

### Planned Features

#### Automated Remediation

-   WP-CLI integration for automated fixes
-   Safe auto-patching with approval workflow
-   Playbook system (YAML-defined fix sequences)
-   Dry-run mode (simulate fixes without applying)
-   Rollback capability (undo applied fixes)

#### ML-Based Detection

-   Anomaly detection (unusual patterns in WordPress installations)
-   False positive reduction (learn from user feedback)
-   Behavioral analysis (detect suspicious code patterns)
-   Custom model training on your historical data

#### Advanced AI Capabilities

-   Agent autonomy (AI plans and executes scan strategies)
-   Exploit generation (proof-of-concept code for findings)
-   Custom remediation scripts (AI-generated shell scripts)
-   Natural language queries ("What's most urgent?")

#### Performance Enhancements

-   Distributed scanning (worker nodes for load distribution)
-   Redis cache for common checks
-   Optimized request batching
-   GPU acceleration for ML models

**Breaking Changes:** Configuration schema v2 (backward compatible with v1)  
**Migration:** Automatic upgrade with deprecation warnings

---

## Pro Track (Commercial Product)

**Target Audience:** Security consultancies, enterprises, managed WordPress hosts  
**Pricing Model:** Subscription-based (per-seat or per-scan tiers)

**IN PROCESS**

---

## Community Requests

Vote on features at **[GitHub Discussions](https://github.com/rodhnin/hephaestus-server-forger/discussions)**

**Have an idea?** Open a discussion!

---

## Development Philosophy

Argus development is guided by these core principles:

1. **🔒 Security First**: Never compromise on ethical safeguards or user consent
2. **🔐 Privacy by Design**: Data minimization, local-first where possible, no telemetry
3. **✅ Quality Over Speed**: Stable, well-tested releases > frequent, buggy releases
4. **👥 Community Driven**: Listen to users, prioritize common needs over niche requests
5. **🆓 Open Core Model**: Core features free forever, optional Pro tier for advanced needs
6. **🧪 Testing First**: No release without comprehensive validation (100% test coverage goal)

### Commitments

-   ✅ **Quarterly feature releases** with new capabilities
-   ✅ **Open development** with public roadmap
-   ✅ **Responsive support** on GitHub (48h response)

---

## Get Involved

**Questions about the roadmap?**  
Open a discussion: https://github.com/rodhnin/argus-wp-watcher/discussions

**Want to contribute?**  
See CONTRIBUTING.md for developer guidelines

**Need a feature urgently?**  
Consider Pro Track (custom development available) or sponsor the project

---

_Last updated: November 22, 2025_  
_Roadmap version: 1.0 (v0.1.0)_
