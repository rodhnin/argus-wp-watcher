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

The safest and fastest way to test Argus features. The lab spins up a realistic vulnerable WordPress site (TechCorp Solutions) with intentional misconfigurations that trigger every Argus finding category.

### Quick Start

```bash
# 1. Navigate to docker directory
cd docker

# 2. Start and configure the lab automatically
./deploy.sh
# Select option 2 (Testing Lab)
# The script starts the containers AND runs setup-lab.sh automatically
```

That's it. The lab is ready when you see `[SUCCESS] Lab setup complete`. No manual browser setup needed.

**Lab credentials:**
- WordPress admin: `admin` / `Admin123!`
- WordPress editor: `editor` / `EditorPass2024!`
- WP-Admin URL: http://localhost:8080/wp-admin

### What the Lab Contains

`setup-lab.sh` configures the following intentional vulnerabilities and misconfigurations:

| Condition | Expected Finding |
|---|---|
| Contact Form 7 v5.3.1 (26 CVEs) | ARGUS-WP-010 / ARGUS-WP-011 |
| Elementor v3.5.0 (31 vulns) | ARGUS-WP-010 / ARGUS-WP-011 |
| Two enumerable users (admin, editor) | ARGUS-WP-040 / ARGUS-WP-041 |
| XML-RPC enabled | ARGUS-WP-060 |
| WP_DEBUG_LOG = true (debug.log exposed) | ARGUS-WP-030 |
| Open user registration | ARGUS-WP-074 |
| No CAPTCHA plugin active | ARGUS-WP-072 |
| No password policy plugin | ARGUS-WP-075 |
| robots.txt with `/backup/` + `/staging/` | ARGUS-WP-080 |
| Missing security headers (no SSL in lab) | ARGUS-WP-050 |

### Resetting the Lab

```bash
# Full reset — wipe data and reinitialize
cd docker
./deploy.sh
# Select option 5 (Remove all containers and data)
# Then select option 2 again to redeploy
```

### Cleanup

```bash
cd docker

# Stop services (keep data)
docker compose -f compose.testing.yml down

# Stop and delete all data
docker compose -f compose.testing.yml down -v

# Remove images too (optional)
docker compose -f compose.testing.yml down -v --rmi all
```

---

## 🔍 Running Test Scans

### Test 1: Safe Mode — Basic Scan

```bash
python -m argus --target http://localhost:8080 -v

# Expected findings (safe mode, ~22 total):
# - ARGUS-WP-000: WordPress detected
# - ARGUS-WP-001: Version disclosed
# - ARGUS-WP-010/011: contact-form-7 5.3.1, elementor 3.5.0 (with CVEs)
# - ARGUS-WP-030: wp-content/debug.log accessible (HIGH)
# - ARGUS-WP-040/041: admin, editor users enumerated
# - ARGUS-WP-050: Missing security headers (×7)
# - ARGUS-WP-060: XML-RPC enabled
# - ARGUS-WP-061: Directory listing (wp-admin)
```

### Test 2: HTML Report

```bash
python -m argus \
  --target http://localhost:8080 \
  --html \
  --report-dir ./test-reports \
  -v

ls -lh ./test-reports/
# Open the generated .html file in your browser
```

### Test 3: Aggressive Mode (Full)

Aggressive mode requires a consent token first:

```bash
# Step 1: Generate token
python -m argus --gen-consent localhost:8080

# Step 2: Place token in lab
docker compose -f compose.testing.yml exec wordpress bash -c \
  "mkdir -p /var/www/html/.well-known && \
   echo 'PASTE_TOKEN_HERE' > /var/www/html/.well-known/PASTE_TOKEN_HERE.txt"

# Step 3: Verify token
python -m argus --verify-consent http --domain localhost:8080 --token PASTE_TOKEN_HERE

# Step 4: Run aggressive scan
python -m argus \
  --target http://localhost:8080 \
  --aggressive \
  --html \
  --report-dir ./test-reports \
  -v

# Expected findings (aggressive mode, ~35 total):
# All safe mode findings PLUS:
# - ARGUS-WP-032: Directory brute-force hits
# - ARGUS-WP-070: Login page accessible
# - ARGUS-WP-071: 2FA not enforced (medium)
# - ARGUS-WP-072: No CAPTCHA (low)
# - ARGUS-WP-073: No brute-force protection (high)
# - ARGUS-WP-074: Open registration (medium)
# - ARGUS-WP-075: No password policy (medium)
# - ARGUS-WP-080: robots.txt sensitive paths (/backup/, /staging/)
# - ARGUS-WP-081: Sitemap found
# - ARGUS-WP-082: HTML comments (if present)
# - ARGUS-WP-083: Crawl interesting paths
# + Extended plugin/file coverage (447 plugins, 437 file paths)
```

### Test 4: Performance — Threads and Rate

```bash
# Slow scan (baseline)
python -m argus --target http://localhost:8080 --threads 1 --rate 2 -v

# Fast scan
python -m argus --target http://localhost:8080 --threads 5 --rate 20 -v

# Or use the timing script
python scripts/test_threads_rate.py
# Expected: ~10x speedup between configurations
```

### Test 5: AI Analysis (v0.2.0 — cost tracking, streaming, agent, compare)

Requires an API key for a supported provider.

```bash
export OPENAI_API_KEY=sk-...

# 5a: Basic AI (both tones — default model gpt-4o-mini-2024-07-18)
python -m argus --target http://localhost:8080 --use-ai --ai-tone both --html -vv

# 5b: Technical only (cheaper)
python -m argus --target http://localhost:8080 --use-ai --ai-tone technical -vv

# 5c: Streaming output
python -m argus --target http://localhost:8080 --use-ai --ai-stream -vv

# 5d: Agent mode with NVD + WPVulnerability.net
python -m argus --target http://localhost:8080 --use-ai --ai-agent --html -vv

# 5e: Budget enforcement — set very low to test abort
python -m argus --target http://localhost:8080 --use-ai --ai-budget 0.0001

# 5f: Override model at runtime
python -m argus --target http://localhost:8080 --use-ai --ai-model gpt-4o -vv

# 5g: Anthropic Claude
export ANTHROPIC_API_KEY=sk-ant-...
python -m argus --target http://localhost:8080 \
  --use-ai --ai-provider anthropic --ai-model claude-3-5-haiku-20241022 --html -v

# 5h: Compare two providers
python -m argus --target http://localhost:8080 \
  --use-ai --ai-compare openai,anthropic --ai-tone technical --html

# 5i: Check cost records
cat ~/.argos/costs.json | python -m json.tool
sqlite3 ~/.argos/argos.db \
  "SELECT provider, model, analysis_type, cost_usd FROM ai_costs ORDER BY cost_id DESC LIMIT 5;"
```

**AI Test Acceptance Criteria:**

| Test | Expected |
|---|---|
| 5a: basic both | executive_summary + technical_remediation in report, cost > 0 |
| 5b: technical only | Only technical_remediation in ai_analysis |
| 5c: streaming | Output appears token by token, report saved |
| 5d: agent mode | agent_analysis in report, NVD/WPVuln data referenced |
| 5e: budget abort | AI aborted, cost = 0 or partial, warning in output |
| 5f: model override | model_used = "openai/gpt-4o" in report |
| 5g: Anthropic | model_used = "anthropic/claude-3-5-haiku-20241022" |
| 5h: compare | ai_analysis.results has 2 keys, cost_by_provider populated |
| 5i: costs | ai_costs table has records, costs.json updated |

### Test 6: Diff Reports (v0.2.0+)

```bash
# Run two scans, then compare
python -m argus --target http://localhost:8080 --html
python -m argus --target http://localhost:8080 --html --diff last

# Compare safe vs aggressive (will trigger mode mismatch warning)
python -m argus --target http://localhost:8080 --html
python -m argus --target http://localhost:8080 --aggressive --html --diff last

# Explicit scan ID
python -m argus --target http://localhost:8080 --html --diff 42

# Invalid ID (graceful error — scan still completes)
python -m argus --target http://localhost:8080 --html --diff 99999
```

**Diff Test Acceptance Criteria:**

| Test | Expected |
|---|---|
| `--diff last` same mode | `new: 0`, `fixed: 0`, `persisting: N`, no warning |
| `--diff last` safe vs aggressive | 7 new (login/crawl findings), mode_mismatch warning in HTML |
| `--diff 99999` | ERROR log, scan completes without diff section |
| Tool mismatch (if ref scan from different tool) | ERROR log, diff skipped |

### Test 7: OWASP, CVSS & Latest Version (v0.2.0+)

```bash
# Run any scan and inspect the JSON
python -m argus --target http://localhost:8080 --html -v

# Verify OWASP badges
python3 -c "
import json
with open('~/.argus/reports/LATEST.json') as f:
    r = json.load(f)
owasp_count = sum(1 for f in r['findings'] if 'owasp' in f)
cvss_count = sum(1 for f in r['findings'] for v in f.get('vulnerabilities',[]) if v.get('cvss'))
latest_count = sum(1 for f in r['findings'] if 'latest_version' in f)
print(f'OWASP mapped: {owasp_count}/{len(r[\"findings\"])}')
print(f'Vulnerabilities with CVSS: {cvss_count}')
print(f'Findings with latest_version: {latest_count}')
"
```

**Expected:**
- All findings have `owasp` field (ARGUS-WP-000 through ARGUS-WP-083)
- Vulnerable plugins (contact-form-7, elementor) have CVSS scores per CVE
- Vulnerable plugin findings have `latest_version` from WordPress.org API
- HTML report shows purple OWASP badge, green version badge, color-coded CVSS badge per CVE

### Test 8: Containerized Scanning

Scan from inside the Docker network (both environments must be running):

```bash
# Deploy both environments
cd docker && ./deploy.sh
# Select option 3 (Both)

# Scan from the argus container
docker compose exec argus python -m argus --target http://wordpress
```

---

## 🧪 Test Suite Overview

### Safe Mode Findings (~27 findings)

| Test Case | Severity | Finding ID | v0.2.0 Enhancements |
|---|---|---|---|
| WordPress detected | Info | ARGUS-WP-000 | OWASP A05 badge |
| Core version + CVEs (WP 6.0.3 — 12 CVEs) | Critical | ARGUS-WP-001 | CVSS + OWASP A05 |
| Plugin detected: contact-form-7 v5.3.1 | Info | ARGUS-WP-010 | Version via readme.txt |
| Plugin detected: elementor v3.5.0 | Info | ARGUS-WP-010 | Version via HTML ?ver= |
| Vulnerable plugin: contact-form-7 (CVEs) | Critical | ARGUS-WP-012 | CVSS + latest_version |
| Vulnerable plugin: elementor (CVEs) | Critical | ARGUS-WP-012 | CVSS + latest_version |
| Plugin summary | High | ARGUS-WP-011 | OWASP A06 badge |
| Theme detected: twentytwentytwo v1.2 | Info | ARGUS-WP-020 | OWASP A06 badge |
| debug.log Exposed | High | ARGUS-WP-030 | OWASP A05 badge |
| readme.html / license.txt Exposed | High/Med | ARGUS-WP-030/065 | OWASP A05 badge |
| User enumeration (admin, editor) | High | ARGUS-WP-040/041 | OWASP A07 badge |
| Missing security headers (×6) | Med/Low | ARGUS-WP-050–053 | OWASP A02/A05 badges |
| XML-RPC restricted | Info | ARGUS-WP-060 | OWASP A05 badge |
| Debug mode potentially enabled | High | ARGUS-WP-063 | OWASP A05 badge |

### Aggressive-Only Findings

| Test Case | Severity | Finding ID |
|---|---|---|
| Directory Brute-force | Medium | ARGUS-WP-032 |
| Login Page Accessible | Info | ARGUS-WP-070 |
| No 2FA Enforcement | Medium | ARGUS-WP-071 |
| No CAPTCHA | Low | ARGUS-WP-072 |
| No Brute-force Protection | High | ARGUS-WP-073 |
| Open User Registration | Medium | ARGUS-WP-074 |
| No Password Policy | Medium | ARGUS-WP-075 |
| robots.txt Sensitive Paths | Low | ARGUS-WP-080 |
| Sitemap Found | Info | ARGUS-WP-081 |
| Sensitive HTML Comments | Low/Medium | ARGUS-WP-082 |
| Crawl: Interesting Paths | Info | ARGUS-WP-083 |

### Acceptance Criteria

✅ **Pass Conditions:**

-   All expected findings detected in respective modes
-   Severity levels match table above
-   No false positives on clean install (especially `/wp-content/uploads/` in robots.txt)
-   JSON validates against schema
-   HTML report renders correctly
-   Consent system blocks aggressive mode without verification
-   AI analysis completes without errors (if enabled)

❌ **Fail Conditions:**

-   Critical findings missed (e.g. debug.log, plugin CVEs)
-   False positives on standard WP paths
-   JSON schema validation fails
-   Crash or unhandled exceptions
-   Consent bypass possible

---

## 📊 Regression Testing

Before each release, run the full suite against a fresh lab:

```bash
# 1. Reset lab to clean vulnerable state
cd docker
./deploy.sh  # option 5 to wipe, then option 2 to redeploy

# 2. Safe mode baseline
cd ..
python -m argus --target http://localhost:8080 --html --report-dir ./test-reports -v
# Verify: ~22 findings, HTML report valid

# 3. Aggressive mode (with consent token placed)
python -m argus --target http://localhost:8080 --aggressive --html --report-dir ./test-reports -v
# Verify: ~35 findings, all expected IDs present

# 4. Schema validation
python -c "
import json, jsonschema
report = json.load(open(sorted(__import__('glob').glob('reports/*.json'))[-1]))
schema = json.load(open('schema/report.schema.json'))
jsonschema.validate(report, schema)
print('Schema: PASS')
"

# 5. Performance check
python scripts/test_threads_rate.py
# Verify: ≥5x speedup between slow/fast configs
```

---

## 🐛 Troubleshooting

### Lab Setup Fails

```bash
# Check container is running
docker compose -f compose.testing.yml ps

# Check wordpress container logs
docker compose -f compose.testing.yml logs wordpress

# Re-run setup manually
bash docker/setup-lab.sh

# Common issue: wp-cli not available
docker compose -f compose.testing.yml exec wordpress wp --info --allow-root
```

### WordPress Not Accessible

```bash
# Check port 8080 is not in use
ss -tlnp | grep 8080

# Check container health
docker compose -f compose.testing.yml logs wordpress

# Restart
docker compose -f compose.testing.yml restart wordpress
```

### No Findings Detected

```bash
# Verify lab is configured (debug.log should exist)
curl -I http://localhost:8080/wp-content/debug.log
# Expected: HTTP 200

# Verify users exist
curl http://localhost:8080/wp-json/wp/v2/users 2>/dev/null | python -m json.tool | grep slug
```

### Consent Verification Fails

```bash
# Check token file exists in container
docker compose -f compose.testing.yml exec wordpress \
  ls /var/www/html/.well-known/

# Check token is accessible via HTTP
curl http://localhost:8080/.well-known/verify-*.txt

# Re-verify with exact token string
python -m argus --verify-consent http --domain localhost:8080 --token verify-[exact-token]
```

---

## 📝 Testing Checklist

Before deploying Argus or reporting issues:

-   [ ] Lab starts and setup-lab.sh completes successfully
-   [ ] WordPress accessible at http://localhost:8080
-   [ ] Safe scan detects ~22 findings including plugin CVEs
-   [ ] debug.log finding detected (ARGUS-WP-030)
-   [ ] User enumeration finds admin and editor
-   [ ] Security headers check reports missing headers
-   [ ] JSON report validates against schema
-   [ ] HTML report renders correctly
-   [ ] Consent token generation works
-   [ ] HTTP verification succeeds
-   [ ] Aggressive mode blocked without consent
-   [ ] Aggressive scan detects ~35 findings
-   [ ] Login checks run (ARGUS-WP-070..075)
-   [ ] Crawl checks run (ARGUS-WP-080..083)
-   [ ] robots.txt /backup/ + /staging/ flagged, /wp-content/uploads/ NOT flagged
-   [ ] AI basic scan completes (if key available), cost recorded in costs.json + ai_costs DB
-   [ ] AI streaming mode shows output in real time
-   [ ] AI agent mode returns enriched analysis (NVD CVSS + WPVuln counts)
-   [ ] AI budget abort triggers when limit exceeded
-   [ ] AI model override `--ai-model` reflected in report model_used field
-   [ ] AI compare mode returns results for all providers in ai_analysis.results
-   [ ] Schema validation passes on all report types (basic, agent, compare)
-   [ ] _total_findings NOT present in output report summary
-   [ ] Cleanup command works (docker compose down -v)

---

## 🔒 Security Reminders

1. **Docker lab ports are localhost-only** (127.0.0.1:8080)
2. **Never expose vulnerable lab to network** — it is intentionally vulnerable
3. **Lab credentials are for testing only** — never reuse in production
4. **Delete lab data after testing** (`docker compose down -v`)

---

## 📚 Further Reading

-   [WordPress Hardening Guide](https://wordpress.org/documentation/article/hardening-wordpress/)
-   [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
-   [Docker Security Best Practices](https://docs.docker.com/engine/security/)

---

**Happy (Safe) Testing!** 🛡️

If you find any issues with the testing guide or lab setup, please report them at:
https://github.com/rodhnin/argus-wp-watcher/issues
