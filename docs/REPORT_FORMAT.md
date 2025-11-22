# Argus Report Format Documentation

## Overview

Argus generates structured security reports in **JSON** (machine-readable) and **HTML** (human-readable) formats for WordPress security assessments. All reports conform to a strict JSON Schema for consistency and validation across the Argos ecosystem.

---

## 📋 JSON Schema

### Location

Reports follow the shared Argos schema at `schema/report.schema.json` (JSON Schema Draft 2020-12)

### Validation

Reports are automatically validated before saving:

```python
from argus.core.report import ReportGenerator

generator = ReportGenerator()
report = {...}
is_valid = generator.validate_report(report)  # True/False
```

### Top-Level Structure

```json
{
  "tool": "argus",
  "version": "0.1.0",
  "target": "https://example-wp-site.com",
  "date": "2025-10-11T18:45:30Z",
  "mode": "safe",
  "summary": {...},
  "findings": [...],
  "notes": {...},
  "consent": {...},
  "ai_analysis": {...}
}
```

---

## 🔍 Field Definitions

### Required Fields

#### `tool` (string)

-   **Value**: `"argus"`
-   **Purpose**: Identifies the WordPress security scanner
-   **Example**: `"argus"`

#### `version` (string)

-   **Format**: Semantic versioning (X.Y.Z)
-   **Purpose**: Tool version for compatibility tracking
-   **Example**: `"0.1.0"`

#### `target` (string)

-   **Format**: Full URL or domain
-   **Purpose**: Scanned WordPress site identifier
-   **Examples**:
    -   `"https://example-wp-site.com"`
    -   `"https://blog.example.com"`
    -   `"http://192.168.1.100/wordpress"`

#### `date` (string)

-   **Format**: ISO 8601 (UTC with Z suffix)
-   **Purpose**: Scan completion timestamp
-   **Example**: `"2025-10-11T18:45:30Z"`

#### `mode` (string)

-   **Values**: `"safe"` or `"aggressive"`
-   **Purpose**: Scan depth indicator
-   **Example**: `"safe"`

#### `summary` (object)

-   **Purpose**: Quick overview of findings by severity
-   **Required keys**: `critical`, `high`, `medium`, `low`, `info`
-   **All values**: Non-negative integers

```json
"summary": {
  "critical": 1,
  "high": 2,
  "medium": 4,
  "low": 3,
  "info": 5
}
```

#### `findings` (array)

-   **Purpose**: Detailed list of WordPress security issues
-   **Items**: Finding objects (see below)

---

## 🎯 Finding Categories

Argus organizes findings into WordPress-specific categories:

### WordPress Core (WP-000 to WP-009)

WordPress installation detection, version disclosure, core vulnerabilities

### Plugins (WP-010 to WP-019)

Installed plugins, vulnerable versions, plugin-specific issues

### Themes (WP-020 to WP-029)

Active/inactive themes, theme vulnerabilities, customization issues

### Sensitive Files (WP-030 to WP-039)

Exposed configuration files, backups, debug files, database dumps

### User Enumeration (WP-040 to WP-049)

Username discovery via REST API, author archives, login errors

### Security Headers (WP-050 to WP-059)

Missing or misconfigured HTTP security headers

### Configuration Issues (WP-060 to WP-069)

XML-RPC, directory listing, debug mode, file permissions

### Custom Findings (WP-070 to WP-099)

Site-specific issues, custom checks

---

## 📝 Finding Object Structure

Each finding in the `findings` array:

```json
{
    "id": "ARGUS-WP-030",
    "title": "wp-config.php backup exposed",
    "description": "WordPress configuration file 'wp-config.php.bak' is publicly accessible. This file contains database credentials, security keys, and other sensitive information.",
    "severity": "critical",
    "confidence": "high",
    "evidence": {
        "type": "url",
        "value": "https://example-wp-site.com/wp-config.php.bak",
        "context": "HTTP 200, Size: 2847 bytes"
    },
    "recommendation": "CRITICAL - Immediate action required:\n1. Remove this file immediately\n2. Change all database credentials\n3. Regenerate WordPress security keys: https://api.wordpress.org/secret-key/1.1/salt/\n4. Review access logs for potential compromise\n5. Add deny rules to prevent future exposure",
    "references": ["https://developer.wordpress.org/advanced-administration/security/hardening/"],
    "affected_component": "wp-config.php.bak"
}
```

#### Finding Fields

| Field                | Required | Type   | Description                                           |
| -------------------- | -------- | ------ | ----------------------------------------------------- |
| `id`                 | ✅ Yes   | string | Unique finding identifier (e.g., `ARGUS-WP-030`)      |
| `title`              | ✅ Yes   | string | Short, descriptive title (max 200 chars)              |
| `description`        | ❌ No    | string | Detailed vulnerability explanation                    |
| `severity`           | ✅ Yes   | enum   | `critical` \| `high` \| `medium` \| `low` \| `info`   |
| `confidence`         | ✅ Yes   | enum   | `high` \| `medium` \| `low`                           |
| `evidence`           | ❌ No    | object | Proof of vulnerability                                |
| `recommendation`     | ✅ Yes   | string | Actionable remediation guidance                       |
| `references`         | ❌ No    | array  | External links (WordPress docs, OWASP, CVE databases) |
| `cve`                | ❌ No    | array  | CVE identifiers (format: `CVE-YYYY-NNNNN`)            |
| `affected_component` | ❌ No    | string | Specific component (plugin name, theme, file path)    |

---

## 🎯 Severity Levels for WordPress Issues

| Level        | Use When                                     | Examples                                                                                        |
| ------------ | -------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| **Critical** | Immediate compromise possible                | Exposed wp-config.php, database credentials accessible, SQL injection with data access          |
| **High**     | Known vulnerable version with public exploit | Outdated plugin with RCE exploit, user enumeration enabling brute force, admin username exposed |
| **Medium**   | Information disclosure, misconfigurations    | WordPress version disclosure, XML-RPC enabled, directory listing, missing security headers      |
| **Low**      | Minor security improvements                  | Non-critical headers missing, informational disclosures, default pages accessible               |
| **Info**     | Informational only                           | WordPress detected, plugin/theme enumerated, scan metadata                                      |

### Confidence Levels

| Level      | Meaning                 | Example                                                                                     |
| ---------- | ----------------------- | ------------------------------------------------------------------------------------------- |
| **High**   | Confirmed vulnerability | File successfully downloaded, version explicitly stated in response, error message observed |
| **Medium** | Strong indicators       | Behavior suggests vulnerability, version inferred from asset fingerprinting                 |
| **Low**    | Heuristic detection     | Pattern matching, assumptions based on common paths                                         |

---

## 📋 Finding ID Scheme

### Format

`ARGUS-WP-{NUMBER}`

### Category Ranges

| ID Range           | Category         | Description                                                      |
| ------------------ | ---------------- | ---------------------------------------------------------------- |
| `ARGUS-WP-000-009` | WordPress Core   | Installation detection, version disclosure, core vulnerabilities |
| `ARGUS-WP-010-019` | Plugins          | Plugin detection, vulnerable plugins, plugin-specific issues     |
| `ARGUS-WP-020-029` | Themes           | Theme detection, theme vulnerabilities                           |
| `ARGUS-WP-030-039` | Sensitive Files  | Exposed configs, backups, debug files                            |
| `ARGUS-WP-040-049` | User Enumeration | Username discovery, author archives, REST API                    |
| `ARGUS-WP-050-059` | Security Headers | Missing headers (HSTS, CSP, X-Frame-Options)                     |
| `ARGUS-WP-060-069` | Config Issues    | XML-RPC, directory listing, debug mode                           |
| `ARGUS-WP-070-099` | Custom Findings  | Site-specific issues                                             |

### Common Finding IDs

| ID             | Meaning                               |
| -------------- | ------------------------------------- |
| `ARGUS-WP-000` | WordPress installation detected       |
| `ARGUS-WP-001` | WordPress core version disclosed      |
| `ARGUS-WP-010` | Individual plugin detected            |
| `ARGUS-WP-011` | Multiple plugins detected (summary)   |
| `ARGUS-WP-012` | Vulnerable plugin version detected    |
| `ARGUS-WP-020` | Individual theme detected             |
| `ARGUS-WP-021` | Multiple themes detected (summary)    |
| `ARGUS-WP-030` | wp-config.php backup exposed          |
| `ARGUS-WP-031` | .env file accessible                  |
| `ARGUS-WP-032` | debug.log exposed                     |
| `ARGUS-WP-033` | SQL dump file accessible              |
| `ARGUS-WP-040` | User enumerated via author archives   |
| `ARGUS-WP-041` | User enumerated via REST API          |
| `ARGUS-WP-042` | Login error messages reveal usernames |
| `ARGUS-WP-050` | Missing HSTS header                   |
| `ARGUS-WP-051` | Missing CSP header                    |
| `ARGUS-WP-052` | Missing X-Frame-Options               |
| `ARGUS-WP-053` | Missing X-Content-Type-Options        |
| `ARGUS-WP-060` | XML-RPC interface enabled             |
| `ARGUS-WP-061` | Directory listing enabled             |
| `ARGUS-WP-062` | Debug mode enabled                    |
| `ARGUS-WP-063` | File editing enabled in admin         |

---

## 🛡️ Evidence Types for WordPress Scans

### Evidence Object Structure

```json
"evidence": {
  "type": "url|header|body|path|other",
  "value": "Evidence value",
  "context": "Additional context"
}
```

### Common Evidence Types

#### URL Evidence (Accessible Resources)

```json
"evidence": {
  "type": "url",
  "value": "https://example-wp-site.com/wp-config.php.bak",
  "context": "HTTP 200, Size: 2847 bytes"
}
```

#### Header Evidence (Version Disclosure)

```json
"evidence": {
  "type": "header",
  "value": "X-Powered-By: PHP/7.4.3",
  "context": "Server technology disclosure"
}
```

#### Body Evidence (HTML/JSON Content)

```json
"evidence": {
  "type": "body",
  "value": "<meta name=\"generator\" content=\"WordPress 5.8\">",
  "context": "Version disclosed in HTML meta tag"
}
```

#### Path Evidence (Directory/File Paths)

```json
"evidence": {
  "type": "path",
  "value": "/wp-content/plugins/contact-form-7/",
  "context": "Version: 5.5.3"
}
```

#### Other Evidence (Complex Findings)

```json
"evidence": {
  "type": "other",
  "value": "Version: 5.8.1",
  "context": "Methods: ['readme.html', 'meta_generator', 'assets']"
}
```

---

## 📊 Complete Example Reports

### Minimal Valid Report

```json
{
    "tool": "argus",
    "version": "0.1.0",
    "target": "https://example.com",
    "date": "2025-10-11T18:45:30Z",
    "mode": "safe",
    "summary": {
        "critical": 0,
        "high": 0,
        "medium": 1,
        "low": 0,
        "info": 1
    },
    "findings": [
        {
            "id": "ARGUS-WP-000",
            "title": "WordPress detected",
            "severity": "info",
            "confidence": "high",
            "recommendation": "WordPress installation confirmed. Proceed with security checks."
        },
        {
            "id": "ARGUS-WP-001",
            "title": "WordPress core version disclosed",
            "severity": "medium",
            "confidence": "high",
            "evidence": {
                "type": "url",
                "value": "https://example.com/readme.html"
            },
            "recommendation": "Remove readme.html or restrict access"
        }
    ]
}
```

### Full Featured Report with AI Analysis

````json
{
    "tool": "argus",
    "version": "0.1.0",
    "target": "https://example-wp-site.com",
    "date": "2025-10-11T18:45:30Z",
    "mode": "aggressive",
    "summary": {
        "critical": 1,
        "high": 2,
        "medium": 4,
        "low": 3,
        "info": 5
    },
    "findings": [
        {
            "id": "ARGUS-WP-030",
            "title": "wp-config.php backup exposed",
            "description": "WordPress configuration backup file is publicly accessible. This file contains database credentials, security keys, and other sensitive information.",
            "severity": "critical",
            "confidence": "high",
            "evidence": {
                "type": "url",
                "value": "https://example-wp-site.com/wp-config.php.bak",
                "context": "HTTP 200, Size: 2847 bytes"
            },
            "recommendation": "CRITICAL - Immediate action required:\n1. Remove this file immediately\n2. Change all database credentials\n3. Regenerate WordPress security keys: https://api.wordpress.org/secret-key/1.1/salt/\n4. Review access logs for potential compromise\n5. Add deny rules to prevent future exposure",
            "references": ["https://wordpress.org/documentation/article/hardening-wordpress/"],
            "affected_component": "wp-config.php.bak"
        },
        {
            "id": "ARGUS-WP-012",
            "title": "Plugin detected: contact-form-7 (vulnerable version)",
            "description": "WordPress plugin 'contact-form-7' version 5.3 is installed. This version has known XSS vulnerability CVE-2020-35489.",
            "severity": "high",
            "confidence": "high",
            "evidence": {
                "type": "path",
                "value": "/wp-content/plugins/contact-form-7/",
                "context": "Version: 5.3"
            },
            "recommendation": "1. Update contact-form-7 to latest version (5.9+)\n2. Check for known CVEs: https://wpscan.com/plugin/contact-form-7/. Review all form submissions for potential XSS exploitation",
            "references": ["https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2020-35489"],
            "cve": ["CVE-2020-35489"],
            "affected_component": "contact-form-7 5.3"
        },
        {
            "id": "ARGUS-WP-040",
            "title": "User enumerated: admin",
            "description": "Username 'admin' discovered via author_idor. User enumeration allows attackers to target brute force attacks.",
            "severity": "high",
            "confidence": "high",
            "evidence": {
                "type": "url",
                "value": "https://example-wp-site.com/author/admin/",
                "context": "Method: author_idor, ID: 1"
            },
            "recommendation": "1. URGENT: Change username (admin/administrator are prime targets)\n2. Disable author IDOR enumeration (security plugin)\n3. Restrict REST API user endpoint\n4. Implement brute force protection\n5. Enable 2FA for all users\n6. Use security plugins like Wordfence or iThemes Security",
            "references": [
                "https://wordpress.org/documentation/article/hardening-wordpress/",
                "https://owasp.org/www-community/attacks/Brute_force_attack"
            ],
            "affected_component": "User: admin"
        },
        {
            "id": "ARGUS-WP-001",
            "title": "WordPress core version disclosed",
            "description": "WordPress version 5.8 detected. Version disclosure helps attackers identify known vulnerabilities for targeted exploits.",
            "severity": "medium",
            "confidence": "high",
            "evidence": {
                "type": "other",
                "value": "Version: 5.8",
                "context": "Methods: ['readme.html', 'meta_generator']"
            },
            "recommendation": "1. Update WordPress to latest version\n2. Hide version info by removing generator tags\n3. Restrict access to readme.html and license.txt\n4. Use security plugins to mask WP fingerprints",
            "references": [
                "https://wordpress.org/documentation/article/hardening-wordpress/",
                "https://developer.wordpress.org/apis/security/"
            ],
            "affected_component": "WordPress Core 5.8"
        },
        {
            "id": "ARGUS-WP-060",
            "title": "XML-RPC interface enabled",
            "description": "WordPress XML-RPC interface is enabled and responding with 43 methods. XML-RPC can be abused for brute force attacks, DDoS amplification, and pingback exploits.",
            "severity": "medium",
            "confidence": "high",
            "evidence": {
                "type": "url",
                "value": "https://example-wp-site.com/xmlrpc.php",
                "context": "HTTP 200, 43 methods available"
            },
            "recommendation": "Disable XML-RPC if not needed:\n1. Add to .htaccess:\n   <Files xmlrpc.php>\n     Order Deny,Allow\n     Deny from all\n   </Files>\n2. Or use security plugin to disable\n3. Or add to wp-config.php: add_filter(\"xmlrpc_enabled\", \"__return_false\");\n4. If needed for Jetpack, restrict to Jetpack IPs only",
            "references": [
                "https://es.wordpress.org/plugins/disable-xml-rpc-api/",
                "https://kinsta.com/blog/xmlrpc-php/"
            ],
            "affected_component": "xmlrpc.php"
        },
        {
            "id": "ARGUS-WP-061",
            "title": "Directory listing enabled: /wp-content/uploads/",
            "description": "Directory listing is enabled for /wp-content/uploads/, exposing 127 items. Attackers can browse and download files.",
            "severity": "medium",
            "confidence": "high",
            "evidence": {
                "type": "url",
                "value": "https://example-wp-site.com/wp-content/uploads/",
                "context": "HTTP 200, 127 items listed"
            },
            "recommendation": "Disable directory listing for /wp-content/uploads/:\n1. Add to .htaccess: Options -Indexes\n2. Or add blank index.html to each directory\n3. Or configure in Apache/Nginx:\n   Apache: <Directory> Options -Indexes </Directory>\n   Nginx: autoindex off;",
            "references": ["https://www.acunetix.com/vulnerabilities/web/directory-listing/"],
            "affected_component": "/wp-content/uploads/"
        },
        {
            "id": "ARGUS-WP-050",
            "title": "Missing security header: HSTS (HTTP Strict Transport Security)",
            "description": "HSTS (HTTP Strict Transport Security) header is not set. Forces browsers to use HTTPS, preventing protocol downgrade attacks.",
            "severity": "medium",
            "confidence": "high",
            "evidence": {
                "type": "header",
                "value": "Strict-Transport-Security: [not set]",
                "context": "Header missing in HTTP response"
            },
            "recommendation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "references": ["https://owasp.org/www-project-secure-headers/", "https://securityheaders.com/"]
        },
        {
            "id": "ARGUS-WP-051",
            "title": "Missing security header: Content Security Policy",
            "description": "CSP header not set. Helps mitigate XSS and code injection attacks.",
            "severity": "low",
            "confidence": "high",
            "evidence": {
                "type": "header",
                "value": "Content-Security-Policy: [not set]",
                "context": "Header missing in HTTP response"
            },
            "recommendation": "Add CSP header with appropriate directives for your site's needs",
            "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"]
        },
        {
            "id": "ARGUS-WP-010",
            "title": "Plugin detected: contact-form-7",
            "description": "WordPress plugin 'contact-form-7' is installed.",
            "severity": "info",
            "confidence": "high",
            "evidence": {
                "type": "path",
                "value": "https://example-wp-site.com/wp-content/plugins/contact-form-7/",
                "context": "Version: 5.5.3"
            },
            "recommendation": "1. Verify contact-form-7 is necessary\n2. Update to latest version\n3. Remove if unused\n4. Check for known CVEs: https://wpscan.com/plugins/",
            "affected_component": "contact-form-7 5.5.3"
        },
        {
            "id": "ARGUS-WP-011",
            "title": "5 plugin(s) detected",
            "description": "Found 5 WordPress plugins installed.",
            "severity": "info",
            "confidence": "high",
            "recommendation": "Review all plugins: remove unused, update all to latest versions",
            "affected_component": "Plugins"
        },
        {
            "id": "ARGUS-WP-021",
            "title": "2 theme(s) detected",
            "description": "Found 2 WordPress themes installed.",
            "severity": "info",
            "confidence": "high",
            "recommendation": "Keep only necessary themes installed and updated.",
            "affected_component": "Themes"
        }
    ],
    "notes": {
        "scan_duration_seconds": 45.32,
        "requests_sent": 127,
        "rate_limit_applied": true,
        "scope_limitations": "Scan limited to publicly accessible pages. No authenticated testing performed.",
        "false_positive_disclaimer": "Manual verification recommended for all findings before remediation."
    },
    "consent": {
        "method": "http",
        "token": "verify-argus-wp-a3f9b2c1d8e4f5a6",
        "verified_at": "2025-10-11T14:30:22Z"
    },
    "ai_analysis": {
        "executive_summary": "Your WordPress site has a **MODERATE** security posture with 1 critical issue requiring immediate attention.\n\n**Key Risks:**\n- **Exposed Configuration Backup:** A wp-config.php backup file is publicly accessible, containing database credentials and security keys. This is like leaving a copy of your safe combination on the front porch.\n- **Outdated Plugin:** Contact Form 7 version 5.3 has a known XSS vulnerability (CVE-2020-35489). Automated tools can easily exploit this.\n- **User Enumeration:** The admin username is publicly discoverable, making brute force attacks much easier.\n\n**Immediate Actions:**\n1. Delete wp-config.php.bak immediately (URGENT - within 1 hour)\n2. Update Contact Form 7 to latest version (within 24 hours)\n3. Change admin username or implement 2FA (within 1 week)",
        "technical_remediation": "## Critical Actions (Within 24 Hours)\n\n### 1. Remove Exposed Configuration File\n```bash\n# SSH into your server\nssh user@yourserver.com\n\n# Locate and remove backup file\ncd /var/www/html\nrm wp-config.php.bak\n\n# Verify removal\nls -la wp-config*\n```\n\n### 2. Change Database Credentials\n```bash\n# Generate new password\nopenssl rand -base64 32\n\n# Update wp-config.php with new credentials\nnano wp-config.php\n# Update DB_PASSWORD line\n\n# Update database user password\nmysql -u root -p\nALTER USER 'wp_user'@'localhost' IDENTIFIED BY 'new_password';\nFLUSH PRIVILEGES;\n```\n\n### 3. Regenerate Security Keys\nVisit https://api.wordpress.org/secret-key/1.1/salt/\nReplace all keys in wp-config.php\n\n## High Priority (Within 1 Week)\n\n### Update Vulnerable Plugin\n```bash\n# Via WP-CLI\nwp plugin update contact-form-7\n\n# Or via WordPress Admin\n# Dashboard > Plugins > Update Now\n```\n\n### Mitigate User Enumeration\n```php\n// Add to functions.php or security plugin\nfunction disable_author_archives() {\n    if (is_author()) {\n        wp_redirect(home_url());\n        exit;\n    }\n}\nadd_action('template_redirect', 'disable_author_archives');\n```\n\n## Medium Priority (Within 2 Weeks)\n\n### Disable XML-RPC\n```apache\n# Add to .htaccess\n<Files xmlrpc.php>\n  Order Deny,Allow\n  Deny from all\n</Files>\n```\n\n### Fix Directory Listing\n```apache\n# Add to .htaccess\nOptions -Indexes\n```\n\n### Add Security Headers\n```apache\n# Add to .htaccess\n<IfModule mod_headers.c>\n  Header set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n  Header set X-Frame-Options \"DENY\"\n  Header set X-Content-Type-Options \"nosniff\"\n  Header set Content-Security-Policy \"default-src 'self'\"\n</IfModule>\n```",
        "generated_at": "2025-10-11T18:45:35Z",
        "model_used": "gpt-4-turbo-preview"
    }
}
````

---

## 🌐 HTML Report

### Template Location

`argus/templates/report.html.j2` (Jinja2)

### Sections

1. **Header**

    - Argus branding with shield emoji
    - Target WordPress site URL
    - Scan date and mode
    - Summary pills with severity counts and colors

2. **Executive Summary** (if `--use-ai` enabled)

    - Non-technical overview for stakeholders
    - Key risks explained in plain language
    - Business impact assessment
    - Priority actions with deadlines

3. **Technical Remediation** (if `--use-ai` enabled)

    - Step-by-step fixes with commands
    - WordPress-specific configuration snippets
    - .htaccess, functions.php, and wp-config.php examples
    - WP-CLI commands for automation

4. **Findings Table**

    - Sortable by ID, Severity, Confidence
    - Expandable evidence sections
    - Color-coded severity badges
    - Copy-paste recommendations
    - Direct links to WordPress documentation

5. **WordPress Information**

    - Detected version
    - Installed plugins and themes count
    - Vulnerable components summary
    - Security headers status

6. **Scan Metadata**

    - Scan duration and request count
    - Rate limiting status
    - Scope limitations (safe vs aggressive)
    - False positive disclaimer

7. **Consent Verification** (if aggressive/AI mode)

    - Verification method used
    - Token displayed
    - Timestamp recorded

8. **Footer**
    - Argus attribution with tagline
    - GitHub repository link
    - Legal disclaimer
    - License information

### Styling Features

-   **WordPress-themed design**: Purple gradient (WordPress colors)
-   **Responsive layout**: Mobile-first, tablet and desktop optimized
-   **Print-friendly**: Clean page breaks, grayscale-optimized
-   **Accessibility**: WCAG 2.1 AA compliant
-   **Interactive elements**: Expandable findings, syntax highlighting
-   **Professional typography**: System font stack for performance

### Example HTML Structure

```html
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <meta name="generator" content="Argus 0.1.0" />
        <title>Argus Security Report — https://example-wp-site.com</title>
        <style>
            /* Embedded CSS for portability */
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                background: #f8f9fa;
                color: #2c3e50;
            }
            header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px 40px;
            }
            .severity-badge.severity-critical {
                background: #dc3545;
                color: white;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🛡️ Argus Security Report</h1>
                <div class="meta">
                    <div class="meta-item"><strong>Target:</strong> https://example-wp-site.com</div>
                    <div class="meta-item"><strong>Date:</strong> 2025-10-11T18:45:30Z</div>
                    <div class="meta-item"><strong>Mode:</strong> SAFE</div>
                </div>
                <div class="summary-pills">
                    <span class="pill pill-critical">Critical: 1</span>
                    <span class="pill pill-high">High: 2</span>
                    <span class="pill pill-medium">Medium: 4</span>
                    <span class="pill pill-low">Low: 3</span>
                    <span class="pill pill-info">Info: 5</span>
                </div>
            </header>

            <div class="content">
                <!-- Executive Summary (AI) -->
                <section id="executive-summary">
                    <h2>📊 Executive Summary</h2>
                    <div class="ai-summary">
                        <!-- AI-generated content rendered as HTML -->
                    </div>
                </section>

                <!-- Findings Table -->
                <section id="findings">
                    <h2>🔍 Security Findings</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Finding</th>
                                <th>Severity</th>
                                <th>Confidence</th>
                                <th>Recommendation</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td><code>ARGUS-WP-030</code></td>
                                <td>
                                    <strong>wp-config.php backup exposed</strong>
                                    <p>Configuration backup publicly accessible...</p>
                                    <div class="evidence">
                                        <strong>url:</strong> https://example.com/wp-config.php.bak <br /><small
                                            >HTTP 200, Size: 2847 bytes</small
                                        >
                                    </div>
                                </td>
                                <td>
                                    <span class="severity-badge severity-critical">CRITICAL</span>
                                </td>
                                <td>
                                    <span class="confidence-badge">high</span>
                                </td>
                                <td>Remove file immediately, change credentials...</td>
                            </tr>
                            <!-- More findings... -->
                        </tbody>
                    </table>
                </section>

                <!-- Scan Notes -->
                <section id="notes">
                    <h2>📝 Scan Notes</h2>
                    <table>
                        <tr>
                            <td><strong>Scan Duration</strong></td>
                            <td>45.32 seconds</td>
                        </tr>
                        <tr>
                            <td><strong>HTTP Requests</strong></td>
                            <td>187</td>
                        </tr>
                        <tr>
                            <td><strong>False Positive Warning</strong></td>
                            <td>Manual verification recommended...</td>
                        </tr>
                    </table>
                </section>
            </div>

            <footer>
                <p><strong>Generated by Argus v0.1.0</strong> — WordPress Security Scanner</p>
                <p>Use only on authorized targets. Report is for informational purposes.</p>
                <p>© 2025 Rodney Dhavid Jimenez Chacin (rodhnin) — MIT License</p>
            </footer>
        </div>
    </body>
</html>
```

---

## 🔧 Programmatic Usage

### Generating Reports

```python
from argus.core.report import ReportGenerator
from argus.scanners.wordpress import WordPressScanner

# Perform WordPress scan
scanner = WordPressScanner(target='https://example-wp-site.com')
findings = scanner.scan()

# Generate report
generator = ReportGenerator()
report = generator.create_report(
    tool='argus',
    version='0.1.0',
    target='https://example-wp-site.com',
    mode='safe',
    findings=findings,
    scan_duration=45.32,
    requests_sent=187
)

# Validate
if generator.validate_report(report):
    # Save JSON
    json_path = generator.save_json(report)
    print(f"JSON report: {json_path}")

    # Generate HTML
    html_path = generator.generate_html(report, json_path)
    print(f"HTML report: {html_path}")
```

### Creating WordPress-Specific Findings

```python
# Core version disclosure
finding = {
    'id': 'ARGUS-WP-001',
    'title': 'WordPress core version disclosed',
    'description': 'WordPress version 5.8 detected via multiple methods',
    'severity': 'medium',
    'confidence': 'high',
    'evidence': {
        'type': 'other',
        'value': 'Version: 5.8',
        'context': "Methods: ['readme.html', 'meta_generator']"
    },
    'recommendation': '1. Update WordPress to latest version\n2. Hide version info\n3. Restrict readme.html access',
    'references': [
        'https://wordpress.org/documentation/article/hardening-wordpress/'
    ],
    'affected_component': 'WordPress Core 5.8'
}

# Vulnerable plugin
finding = {
    'id': 'ARGUS-WP-012',
    'title': 'Plugin detected: contact-form-7 (vulnerable version)',
    'description': 'Contact Form 7 v5.3 has known XSS vulnerability',
    'severity': 'high',
    'confidence': 'high',
    'evidence': {
        'type': 'path',
        'value': '/wp-content/plugins/contact-form-7/',
        'context': 'Version: 5.3'
    },
    'recommendation': 'Update to version 5.9+ immediately',
    'references': [
        'https://wpscan.com/themes/'
    ],
    'cve': ['CVE-2020-35489'],
    'affected_component': 'contact-form-7 5.3'
}

# User enumeration
finding = {
    'id': 'ARGUS-WP-040',
    'title': 'User enumerated: admin',
    'description': 'Username admin discovered via author archives',
    'severity': 'high',
    'confidence': 'high',
    'evidence': {
        'type': 'url',
        'value': 'https://example.com/author/admin/',
        'context': 'Method: author_idor, ID: 1'
    },
    'recommendation': 'Change admin username, disable author enumeration, enable 2FA',
    'references': [
        'https://owasp.org/www-community/attacks/Brute_force_attack'
    ],
    'affected_component': 'User: admin'
}

# Sensitive file exposure
finding = {
    'id': 'ARGUS-WP-030',
    'title': 'wp-config.php backup exposed',
    'description': 'Configuration backup file publicly accessible',
    'severity': 'critical',
    'confidence': 'high',
    'evidence': {
        'type': 'url',
        'value': 'https://example.com/wp-config.php.bak',
        'context': 'HTTP 200, Size: 2847 bytes'
    },
    'recommendation': 'CRITICAL: Remove file immediately, change all credentials, regenerate security keys',
    'references': [
        'https://wordpress.org/documentation/article/hardening-wordpress/'
    ],
    'affected_component': 'wp-config.php.bak'
}
```

---

## 📈 Report Analysis

### SQLite Queries for WordPress Security Trends

```sql
-- Most common WordPress vulnerabilities
SELECT
    finding_code,
    title,
    COUNT(*) as occurrence_count,
    AVG(CASE severity
        WHEN 'critical' THEN 4
        WHEN 'high' THEN 3
        WHEN 'medium' THEN 2
        WHEN 'low' THEN 1
        ELSE 0
    END) as avg_severity_score
FROM findings
WHERE tool = 'argus'
    AND severity IN ('critical', 'high', 'medium')
GROUP BY finding_code, title
ORDER BY occurrence_count DESC, avg_severity_score DESC
LIMIT 10;

-- WordPress sites with critical issues
SELECT
    s.domain,
    COUNT(f.finding_id) as total_findings,
    SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) as critical,
    SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) as high,
    MAX(s.started_at) as last_scan
FROM scans s
JOIN findings f ON s.scan_id = f.scan_id
WHERE s.tool = 'argus'
    AND s.status = 'completed'
GROUP BY s.domain
HAVING critical > 0 OR high > 2
ORDER BY critical DESC, high DESC;

-- Plugin vulnerability trends
SELECT
    SUBSTR(finding_code, 1, 13) as category,
    COUNT(*) as count,
    GROUP_CONCAT(DISTINCT affected_component) as components
FROM findings
WHERE tool = 'argus'
    AND finding_code LIKE 'ARGUS-WP-01%'
    AND severity IN ('critical', 'high')
GROUP BY category
ORDER BY count DESC;

-- Security header adoption rate
SELECT
    f.title as header,
    COUNT(DISTINCT s.scan_id) as missing_count,
    (SELECT COUNT(*) FROM scans WHERE tool = 'argus' AND status = 'completed') as total_scans,
    ROUND(COUNT(DISTINCT s.scan_id) * 100.0 / (SELECT COUNT(*) FROM scans WHERE tool = 'argus'), 2) as missing_percentage
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE f.tool = 'argus'
    AND f.finding_code LIKE 'ARGUS-WP-05%'
GROUP BY f.title
ORDER BY missing_count DESC;

-- Average findings by severity per site
SELECT
    AVG(JSON_EXTRACT(summary, '$.critical')) as avg_critical,
    AVG(JSON_EXTRACT(summary, '$.high')) as avg_high,
    AVG(JSON_EXTRACT(summary, '$.medium')) as avg_medium,
    AVG(JSON_EXTRACT(summary, '$.low')) as avg_low,
    COUNT(*) as total_scans
FROM scans
WHERE tool = 'argus'
    AND status = 'completed'
    AND started_at > datetime('now', '-30 days');
```

### Python Analysis Examples

```python
import sqlite3
import json
from collections import Counter, defaultdict

db = sqlite3.connect('~/.argos/argos.db')

# Analyze WordPress version distribution
cursor = db.execute("""
    SELECT affected_component
    FROM findings
    WHERE tool = 'argus'
        AND finding_code = 'ARGUS-WP-001'
        AND affected_component LIKE 'WordPress Core%'
""")

versions = Counter()
for (component,) in cursor:
    version = component.replace('WordPress Core ', '')
    versions[version] += 1

print("WordPress version distribution:")
for version, count in versions.most_common(10):
    print(f"  {version}: {count} sites")

# Find most vulnerable plugins
cursor = db.execute("""
    SELECT affected_component, cve, COUNT(*) as count
    FROM findings
    WHERE tool = 'argus'
        AND finding_code IN ('ARGUS-WP-012', 'ARGUS-WP-010')
        AND cve IS NOT NULL
    GROUP BY affected_component, cve
    ORDER BY count DESC
    LIMIT 10
""")

print("\nMost vulnerable plugins:")
for plugin, cve, count in cursor:
    cves = ', '.join(json.loads(cve)) if cve else 'N/A'
    print(f"  {plugin}: {cves} ({count} occurrences)")

# Calculate risk scores
cursor = db.execute("""
    SELECT
        s.domain,
        s.scan_id,
        s.summary
    FROM scans s
    WHERE s.tool = 'argus'
        AND s.status = 'completed'
    ORDER BY s.started_at DESC
    LIMIT 50
""")

risk_scores = []
for domain, scan_id, summary_json in cursor:
    summary = json.loads(summary_json)
    # Risk score: critical×10 + high×5 + medium×2 + low×1
    risk = (summary['critical'] * 10 +
            summary['high'] * 5 +
            summary['medium'] * 2 +
            summary['low'] * 1)
    risk_scores.append((domain, risk, summary))

print("\nTop 10 highest risk WordPress sites:")
for domain, risk, summary in sorted(risk_scores, key=lambda x: x[1], reverse=True)[:10]:
    print(f"  {domain}: Risk Score {risk} (C:{summary['critical']} H:{summary['high']} M:{summary['medium']})")
```

---

## ✅ Best Practices for WordPress Reports

### 1. Evidence Collection

```python
# Good: Specific WordPress evidence
evidence = {
    'type': 'url',
    'value': 'https://example.com/wp-config.php.bak',
    'context': 'HTTP 200, Size: 2847 bytes, Contains: DB_PASSWORD'
}

# Bad: Vague evidence
evidence = {
    'type': 'other',
    'value': 'Backup file found'
}
```

### 2. WordPress-Specific Recommendations

```python
# Good: Actionable WordPress fixes
recommendation = """CRITICAL - Immediate action required:
1. Remove file: rm /var/www/html/wp-config.php.bak
2. Change DB credentials in wp-config.php
3. Update database user:
   mysql> ALTER USER 'wp_user'@'localhost' IDENTIFIED BY 'new_password';
4. Regenerate security keys: https://api.wordpress.org/secret-key/1.1/salt/
5. Add to .htaccess:
   <FilesMatch "^wp-config\\.php\\.">
     Order Deny,Allow
     Deny from all
   </FilesMatch>
"""

# Bad: Generic advice
recommendation = "Secure configuration files"
```

### 3. Severity Assignment for WordPress

**Critical**: Credentials/data exposure

-   wp-config.php accessible
-   Database dumps exposed
-   .env files with API keys
-   Unrestricted file upload to PHP directories

**High**: Exploitation enabling

-   Known vulnerable plugin with public exploit
-   Admin username enumerated
-   XML-RPC brute force vector
-   Default admin credentials

**Medium**: Information disclosure

-   WordPress version disclosed
-   Plugin/theme versions visible
-   Directory listing enabled
-   Missing security headers

**Low**: Best practice violations

-   Non-critical headers missing
-   Default WordPress pages accessible
-   Informational headers present

**Info**: Detection only

-   WordPress detected
-   Plugin enumerated (no vulnerability)
-   Theme identified

### 4. CVE Integration

```python
# Link to WPScan vulnerability database
finding = {
    'id': 'ARGUS-WP-012',
    'title': 'Vulnerable plugin: contact-form-7',
    'severity': 'high',
    'cve': ['CVE-2020-35489'],
    'references': [
        'https://wpscan.com/wordpresses/',
        'https://nvd.nist.gov/vuln/detail/CVE-2020-35489'
    ],
    'affected_component': 'contact-form-7 5.3',
    'recommendation': 'Update to version 5.9+ which patches this XSS vulnerability'
}
```

### 5. Report Storage and Organization

```python
from pathlib import Path
from datetime import datetime, timezone

# Organize by target domain
target_domain = 'example-wp-site.com'
timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
scan_id = 42

report_dir = Path.home() / '.argus' / 'reports' / target_domain
report_dir.mkdir(parents=True, exist_ok=True)

json_file = report_dir / f"argus_{timestamp}_scan{scan_id}.json"
html_file = report_dir / f"argus_{timestamp}_scan{scan_id}.html"

# Keep historical reports for trend analysis
```

### 6. AI Analysis Prompts

When generating AI summaries for WordPress sites:

```python
executive_prompt = f"""
Analyze this WordPress security scan with {critical} critical, {high} high,
and {medium} medium severity issues.

Create an executive summary that:
1. Explains risks in business terms (no technical jargon)
2. Prioritizes actions by urgency (hours, days, weeks)
3. Uses analogies to explain technical concepts
4. Focuses on "what could happen" rather than "what was found"

Target audience: Business stakeholders, not technical users.
"""

technical_prompt = f"""
Create a technical remediation guide for WordPress with:
1. Numbered priority levels (Critical, High, Medium)
2. Exact commands (SSH, WP-CLI, MySQL)
3. Configuration snippets (.htaccess, functions.php, wp-config.php)
4. Verification steps to confirm fixes
5. Prevention measures for future scans

Target audience: WordPress developers and system administrators.
"""
```

---

## 🎨 Customization

### Custom WordPress Checks

Extend Argus with custom checks:

```python
from argus.checks.base import BaseCheck

class CustomWPCheck(BaseCheck):
    """Custom WordPress security check"""

    def run(self) -> list[dict]:
        findings = []

        # Check for custom vulnerability
        response = self.http_get('/custom-vulnerable-endpoint')

        if self.is_vulnerable(response):
            findings.append({
                'id': 'ARGUS-WP-099',
                'title': 'Custom WordPress vulnerability detected',
                'description': 'Site-specific vulnerability in custom plugin',
                'severity': 'high',
                'confidence': 'high',
                'evidence': {
                    'type': 'url',
                    'value': f'{self.target}/custom-vulnerable-endpoint',
                    'context': f'HTTP {response.status_code}'
                },
                'recommendation': 'Update custom plugin to latest version',
                'references': [],
                'affected_component': 'Custom Plugin'
            })

        return findings
```

### Custom HTML Template

Override default template for branding:

```python
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

# Use custom template
template_dir = Path('/path/to/custom/templates')
env = Environment(loader=FileSystemLoader(template_dir))
template = env.get_template('custom_argus_report.html.j2')

html_output = template.render(
    report=report,
    company_logo='https://yourcompany.com/logo.png',
    custom_branding='YourCompany Security Team'
)
```

---

## 📊 Report Metrics and KPIs

### Key Performance Indicators for WordPress Security

```python
# Security Posture Score (0-100)
def calculate_security_score(summary):
    base_score = 100
    penalties = {
        'critical': 25,  # -25 per critical
        'high': 10,      # -10 per high
        'medium': 3,     # -3 per medium
        'low': 1         # -1 per low
    }

    score = base_score
    for severity, penalty in penalties.items():
        score -= summary[severity] * penalty

    return max(0, score)  # Floor at 0

# Risk Level Classification
def classify_risk(summary):
    critical = summary['critical']
    high = summary['high']

    if critical >= 3 or (critical >= 1 and high >= 3):
        return 'CRITICAL'
    elif critical >= 1 or high >= 3:
        return 'HIGH'
    elif high >= 1 or summary['medium'] >= 5:
        return 'MODERATE'
    elif summary['medium'] >= 1:
        return 'LOW'
    else:
        return 'MINIMAL'

# WordPress Hardening Progress
def calculate_hardening_progress(findings):
    total_checks = 50  # Approximate total WordPress checks
    passed_checks = total_checks - len([f for f in findings if f['severity'] != 'info'])
    return (passed_checks / total_checks) * 100
```

### Trending Analysis Dashboard

```python
import pandas as pd
import matplotlib.pyplot as plt

# Load scan history
df = pd.read_sql("""
    SELECT
        started_at as date,
        JSON_EXTRACT(summary, '$.critical') as critical,
        JSON_EXTRACT(summary, '$.high') as high,
        JSON_EXTRACT(summary, '$.medium') as medium
    FROM scans
    WHERE tool = 'argus'
        AND domain = 'example-wp-site.com'
    ORDER BY started_at
""", db, parse_dates=['date'])

# Calculate risk score
df['risk_score'] = df['critical']*10 + df['high']*5 + df['medium']*2

# Plot trend
plt.figure(figsize=(12, 6))
plt.plot(df['date'], df['risk_score'], marker='o')
plt.title('WordPress Security Risk Trend')
plt.xlabel('Date')
plt.ylabel('Risk Score')
plt.grid(True)
plt.savefig('wordpress_risk_trend.png')
```

---

## 🔐 Security Considerations

### Protecting Sensitive Report Data

```python
from cryptography.fernet import Fernet
import json
import os

class EncryptedReportStorage:
    """Store WordPress security reports encrypted"""

    def __init__(self, key_file=None):
        if key_file and Path(key_file).exists():
            with open(key_file, 'rb') as f:
                self.key = f.read()
        else:
            # Generate new key
            self.key = Fernet.generate_key()
            if key_file:
                with open(key_file, 'wb') as f:
                    f.write(self.key)
                os.chmod(key_file, 0o600)

        self.cipher = Fernet(self.key)

    def encrypt_report(self, report: dict) -> bytes:
        """Encrypt WordPress security report"""
        report_json = json.dumps(report)
        return self.cipher.encrypt(report_json.encode())

    def decrypt_report(self, encrypted: bytes) -> dict:
        """Decrypt WordPress security report"""
        decrypted = self.cipher.decrypt(encrypted)
        return json.loads(decrypted.decode())

# Usage
storage = EncryptedReportStorage('~/.argus/report.key')
encrypted = storage.encrypt_report(report)

# Save encrypted
with open('report_encrypted.bin', 'wb') as f:
    f.write(encrypted)
```

### Access Control for Reports

```python
import os
from pathlib import Path

def secure_report_file(report_path: Path):
    """Set restrictive permissions on report files"""
    # Owner read/write only (0o600)
    os.chmod(report_path, 0o600)

    # Verify permissions
    stat = os.stat(report_path)
    mode = oct(stat.st_mode)[-3:]

    if mode != '600':
        raise PermissionError(f"Failed to set secure permissions on {report_path}")
```

---

## 📚 Additional Resources

### WordPress Security Documentation

-   **WordPress Hardening Guide**: https://wordpress.org/documentation/article/hardening-wordpress/
-   **WPScan Vulnerability Database**: https://wpscan.com/
-   **OWASP WordPress Security**: https://owasp.org/www-community/vulnerabilities/
-   **WordPress Security Plugin Guidelines**: https://wordpress.org/plugins/developers/

### Support and Community

-   **Issues**: https://github.com/rodhnin/argus-wp-watcher/issues
-   **Discussions**: https://github.com/rodhnin/argus-wp-watcher/discussions

### Related Tools

-   **WPScan**: https://wpscan.com/
-   **WordPress Security Plugins**: Wordfence, iThemes Security, Sucuri

---

_Last Updated: November 2025_  
_Version: 1.0_  
_Tool: Argus v0.1.0_  
