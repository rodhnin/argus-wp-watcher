# Security Policy

## 🔒 Our Commitment

Security is at the core of Argus. As a security scanning tool, we take the security of Argus itself very seriously. This document outlines how to report security vulnerabilities and our commitment to responsible disclosure.

## 🛡️ Supported Versions

We actively provide security updates for the following versions:

| Version | Supported | Notes                  |
| ------- | --------- | ---------------------- |
| 0.1.x   | ✅ Yes    | Current stable release |
| < 0.1.0 | ❌ No     | Pre-release versions   |

**Recommendation**: Always use the latest stable release for security and bug fixes.

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability in Argus, please help us maintain the security and integrity of the project by reporting it responsibly.

### DO NOT:

-   ❌ Open a public GitHub issue for security vulnerabilities
-   ❌ Disclose the vulnerability publicly before it's been addressed
-   ❌ Exploit the vulnerability maliciously

### DO:

✅ **Report privately** through one of these channels:

1. **GitHub Security Advisories** (Recommended):

    - Navigate to [Security Advisories](https://github.com/rodhnin/argus-wp-watcher/security/advisories)
    - Click "Report a vulnerability"
    - Provide detailed information using our template below

2. **Direct Contact**:
    - Visit [rodhnin.com](https://rodhnin.com) and use the contact form
    - Mark the subject as "Security Vulnerability Report - Argus"

### Vulnerability Report Template

Please include as much information as possible:

```markdown
### Vulnerability Type

[e.g., SQL Injection, Command Injection, Sensitive Data Exposure, etc.]

### Severity Assessment

[Critical / High / Medium / Low]

### Affected Component

[e.g., AI integration module, consent token validator, report generator]

### Affected Versions

[e.g., 0.1.0, all versions, etc.]

### Description

A clear description of the vulnerability and its potential impact.

### Steps to Reproduce

1. Step one
2. Step two
3. Observe the vulnerability

### Proof of Concept

[Code snippet, screenshots, or demonstration]

### Potential Impact

What could an attacker achieve with this vulnerability?

### Suggested Fix

[Optional - if you have ideas for remediation]

### Discoverer Credit

[Your name/handle if you want to be credited in the fix announcement]
```

## ⏱️ Response Timeline

I am committed to addressing security issues promptly:

| Stage                   | Timeline                 |
| ----------------------- | ------------------------ |
| **Initial Response**    | Within 48 hours          |
| **Triage & Assessment** | Within 7 days            |
| **Fix Development**     | Varies by severity       |
| **Patch Release**       | ASAP for critical issues |
| **Public Disclosure**   | After patch release      |

**Critical vulnerabilities** (remote code execution, authentication bypass, data breach) will be prioritized and addressed immediately.

## 🎯 Scope

### In Scope

The following components are in scope for security reports:

-   ✅ Core Argus scanner engine
-   ✅ AI integration modules (OpenAI, Anthropic, Ollama)
-   ✅ Consent token validation system
-   ✅ Database operations (SQLite)
-   ✅ Report generation (HTML/JSON)
-   ✅ Docker deployment configurations
-   ✅ Configuration parsing and validation
-   ✅ Command injection possibilities
-   ✅ Sensitive data handling

### Out of Scope

The following are **not** considered security vulnerabilities:

-   ❌ Denial of Service (DoS) against the scanner itself
-   ❌ Vulnerabilities in third-party dependencies (report to the upstream project)
-   ❌ Issues requiring physical access to the machine
-   ❌ Social engineering attacks
-   ❌ Vulnerabilities in the test lab WordPress environment (it's intentionally vulnerable)

## 🏅 Recognition

We believe in recognizing security researchers who help improve Argus:

-   **Hall of Fame**: Security researchers will be credited in our security hall of fame
-   **CHANGELOG**: Your contribution will be acknowledged in release notes
-   **CVE Assignment**: We'll work with you to assign CVEs when applicable
-   **Coordination**: We'll coordinate disclosure timing with you

### Security Hall of Fame

_No vulnerabilities reported yet. Be the first to help secure Argus!_

## 🔐 Security Best Practices for Users

### Running Argus Securely

1. **API Keys**:

    - Never commit API keys to version control
    - Use environment variables: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`
    - Rotate keys regularly
    - Use key restrictions when possible

2. **Consent Tokens**:

    - Always verify consent before aggressive scanning
    - Never bypass the consent token system
    - Document authorization in scan reports

3. **Docker Security**:

    - Don't run containers as root (Argus runs as UID 1000)
    - Keep Docker images updated
    - Restrict network access for containers
    - Don't expose testing lab to the internet

4. **Database Security**:

    - Protect `argos.db` file (contains scan history)
    - Don't share database files publicly
    - Back up regularly but securely

5. **Reports**:
    - Reports may contain sensitive information
    - Store reports securely
    - Redact sensitive data before sharing
    - Use encryption for report storage

### Secure Configuration

**Minimum security baseline** (`config/argus.yml`):

```yaml
general:
    version: "0.1.0"
    author: "Rodney Dhavid Jimenez Chacin (rodhnin)"
    github: "https://github.com/rodhnin/argus-wp-watcher"

scanning:
    user_agent: "Argus/0.1.0 Security Scanner"
    timeout: 10
    max_retries: 3
    verify_ssl: true # Always verify SSL in production

rate_limiting:
    enabled: true # Always enable rate limiting
    requests_per_second: 5
    burst_size: 10

consent:
    required_for_aggressive: true # Never disable
    require_https: true # Enforce HTTPS for consent tokens
```

## 🚫 Known Security Limitations

### Design Decisions

1. **SQLite Database**:

    - No encryption at rest by default
    - Users should encrypt the volume if needed

2. **API Keys in Memory**:

    - API keys are loaded into memory during execution
    - Use system-level protections (SELinux, AppArmor)

3. **HTTP Requests**:

    - Scanner makes outbound HTTP requests
    - Firewall rules should restrict destinations

4. **Testing Lab**:
    - Intentionally vulnerable WordPress environment
    - Bound to 127.0.0.1 only
    - Must not be exposed to public internet

## 📋 Security Checklist for Contributors

Before submitting a PR, ensure:

-   [ ] No hardcoded credentials or secrets
-   [ ] Input validation for all user-provided data
-   [ ] No command injection vulnerabilities
-   [ ] Proper error handling (don't leak sensitive info)
-   [ ] Rate limiting for network operations
-   [ ] Consent checks for aggressive operations
-   [ ] Secure defaults in configuration
-   [ ] No SQL injection risks
-   [ ] Dependencies are up-to-date
-   [ ] Security implications documented

## 🔄 Security Update Process

When a security vulnerability is fixed:

1. **Private Development**: Fix is developed in a private branch
2. **Testing**: Thorough testing and validation
3. **CVE Assignment**: Request CVE if applicable
4. **Release**: New version released with security patch
5. **Disclosure**: Public disclosure with credit to reporter
6. **Notification**: Users notified via GitHub releases

### Subscribing to Security Updates

-   **Watch** the repository on GitHub
-   **Star** the project to stay informed
-   **Check** [Releases](https://github.com/rodhnin/argus-wp-watcher/releases) regularly

## 🤝 Security Philosophy

### Responsible Disclosure

We believe in responsible disclosure:

-   We'll acknowledge your report within 48 hours
-   We'll keep you informed of progress
-   We'll credit you in the fix announcement
-   We'll coordinate disclosure timing with you

### Ethics First

Argus is built with ethics at its core:

-   **Consent-based scanning** prevents unauthorized use
-   **Rate limiting** prevents DoS conditions
-   **Transparent logging** maintains accountability
-   **Educational focus** promotes responsible security testing

## 📞 Contact

For security-related inquiries:

-   **Security Issues**: Use GitHub Security Advisories
-   **General Security Questions**: Open a GitHub Discussion
-   **Private Contact**: [rodhnin.com](https://rodhnin.com)

---

**Last Updated**: November 2025

**Thank you for helping keep Argus and its users safe! 🛡️**
