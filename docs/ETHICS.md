# Ethical Use & Legal Guidelines

## Overview

**Argus is designed exclusively for authorized WordPress security testing.** This document outlines the ethical principles, legal requirements, and best practices that govern the use of this tool.

---

## 🚨 Legal Requirements

### You MUST Have Authorization

Before scanning any WordPress site with Argus, you **must** have one of the following:

1. **Ownership**: You own the target WordPress site
2. **Explicit Written Permission**: Signed agreement from the site owner
3. **Professional Engagement**: Formal penetration testing contract with clear scope
4. **Bug Bounty Program**: Participation within defined scope and rules

### What Counts as Authorization?

✅ **Valid Authorization:**

-   Signed penetration testing agreement with defined scope
-   Email from authorized personnel explicitly granting permission
-   Bug bounty program participation (within scope and rules)
-   Internal corporate testing with management approval and documentation
-   Your own personal WordPress site/blog
-   Development/staging WordPress environments you control

❌ **NOT Valid Authorization:**

-   Verbal permission without written documentation
-   Permission from non-authorized users (e.g., content editor without authority)
-   "Just testing security as a favor" without formal approval
-   Public WordPress sites without explicit consent
-   Government/military WordPress installations without proper clearance
-   Third-party WordPress sites (e.g., wordpress.org, woocommerce.com)
-   "It's publicly accessible, so it's okay to scan" (WRONG!)

---

## ⚖️ Legal Frameworks

### United States: Computer Fraud and Abuse Act (CFAA)

The CFAA (18 U.S.C. § 1030) makes it illegal to:

-   Access a computer without authorization or exceed authorized access
-   Intentionally access a computer without authorization and obtain information
-   Knowingly cause transmission of a program/code that causes damage
-   Traffic in passwords or similar access credentials

**Penalties**: Up to 20 years imprisonment + fines up to $250,000

**Notable Cases:**

-   Researchers probing WordPress sites they didn't own: Criminal charges
-   Security researchers testing without permission: Federal prosecution

### United Kingdom: Computer Misuse Act 1990

Prohibits:

-   **Section 1**: Unauthorized access to computer material
-   **Section 2**: Unauthorized access with intent to commit further offenses
-   **Section 3**: Unauthorized modification of computer material
-   **Section 3A**: Making, supplying or obtaining articles for use in offenses

**Penalties**: Up to 10 years imprisonment + unlimited fines

### European Union: GDPR & National Laws

-   **GDPR Article 32**: Requires testing of security measures (BUT testing must be authorized)
-   **Network and Information Systems (NIS) Directive**: Security obligations for operators
-   **Cybersecurity Act**: EU-wide cybersecurity framework
-   Various EU member states have additional cybercrime laws

**Key Points:**

-   Authorized penetration testing is ENCOURAGED for critical infrastructure
-   Unauthorized testing is CRIMINAL regardless of intent

### Other Jurisdictions

Most countries have similar laws:

-   **Canada**: Criminal Code (Section 342.1 - Unauthorized use of computer)
-   **Australia**: Cybercrime Act 2001
-   **India**: IT Act 2000 (Section 66 - Computer-related offenses)
-   **China**: Cybersecurity Law (严格监管)
-   **Brazil**: Marco Civil da Internet + General Data Protection Law (LGPD)

**Universal Principle**: "I didn't know it was illegal" is NOT a defense anywhere.

---

## 🛡️ Argus Built-In Safeguards

### 1. Safe-by-Default Architecture

-   **Default mode**: `--safe` (non-intrusive checks only)

    -   No brute force login attempts
    -   No exploit attempts
    -   No file modifications
    -   No password attacks
    -   Rate limited to 5 req/s (respectful)

-   **Aggressive mode**: `--aggressive` (deeper probing)
    -   **Requires verified consent token**
    -   Extended plugin enumeration (500+ plugins)
    -   Extended user enumeration (50 users)
    -   More sensitive files checked (400+ paths)
    -   Higher rate limit (10 req/s)

### 2. Consent Token Verification System

Argus **requires** ownership verification before:

-   `--aggressive` mode (deep scanning)
-   `--use-ai` (sends sanitized data to external AI API)

**Token Methods:**

-   **HTTP**: Place token file at `https://yourdomain.com/.well-known/verify-{token}.txt`
-   **DNS**: Add TXT record `argus-verify={token}` to your domain

**Token Properties:**

-   48-hour expiration (prevents stale authorizations)
-   Cryptographically random (prevents guessing)
-   Stored in shared database (`~/.argos/argos.db`)
-   Audit trail for compliance

**Purpose**: Technical proof of site control, NOT a replacement for legal authorization.

### 3. Comprehensive Logging & Auditing

All actions are logged with timestamps:

-   Targets scanned (URLs, domains)
-   Scan mode used (safe/aggressive)
-   Consent verification events (success/failure)
-   Findings discovered (with severity levels)
-   Errors and exceptions
-   API calls (when using AI features)

**Log Security:**

-   Automatic secret redaction (passwords, tokens, API keys)
-   Multiple verbosity levels (`-v`, `-vv`, `-vvv`)
-   JSON and text format support
-   Timestamped with severity levels

**Legal Protection**: Logs are evidence of ethical and authorized usage.

---

## 📋 Best Practices

### Before Scanning

1. **Document Authorization**

    - Get written permission from authorized personnel
    - Define scope clearly:
        - Specific domains/subdomains
        - WordPress installations covered
        - Allowed scan types (safe vs aggressive)
        - Time windows (business hours vs off-hours)
    - Specify permitted actions and depth
    - Include emergency contact information

2. **Inform Stakeholders**

    - Notify IT/security operations teams in advance
    - Provide your contact information
    - Establish communication channels (email, Slack, phone)
    - Set up monitoring alerts (so your scans don't trigger false alarms)
    - Document escalation procedures

3. **Verify Consent Token**

    - Always verify domain ownership before aggressive mode
    - Keep proof of verification (screenshot, log output)
    - Verify token hasn't expired
    - Re-verify if scope changes

4. **Test in Non-Production First**
    - Start with development/staging WordPress environments
    - Validate scan behavior and impact
    - Confirm rate limits are appropriate
    - Check for false positives

### During Scanning

1. **Respect Scope Boundaries**

    - Stay within authorized WordPress sites only
    - Don't follow redirects to external domains
    - Don't exceed agreed scan depth
    - Honor time restrictions (avoid peak hours if requested)

2. **Monitor Impact**

    - Watch for service degradation or errors
    - Use rate limiting (`--rate`) appropriately
    - Adjust threads (`--threads`) based on server capacity
    - Stop immediately if issues detected

3. **Avoid Harmful Actions**

    - **Never** modify WordPress files, posts, or configurations
    - **Never** attempt login brute forcing (beyond enumeration)
    - **Never** download user data or private content
    - **Never** disrupt services or cause DoS conditions
    - **Never** attempt to bypass authentication

4. **Maintain Communication**
    - Notify stakeholders when scan starts/ends
    - Report any concerning findings immediately
    - Document any unexpected behavior
    - Keep audit trail of all activities

### After Scanning

1. **Secure Reports**

    - Encrypt sensitive findings before transmission
    - Limit report distribution to authorized personnel only
    - Use secure channels (encrypted email, secure file transfer)
    - Store reports securely with access controls
    - Set retention policies and follow them

2. **Responsible Disclosure**

    - Report vulnerabilities to site owner first (private disclosure)
    - Provide clear description with reproduction steps
    - Allow reasonable time for fixes:
        - **Critical**: 7-14 days
        - **High**: 30 days
        - **Medium/Low**: 90 days
    - Don't publicly disclose before patches are available
    - Coordinate disclosure timeline with site owner

3. **Clean Up**
    - Remove test files if any were created
    - Delete logs on target system (if any)
    - Revoke consent tokens when engagement ends
    - Securely delete local reports when no longer needed
    - Update documentation with lessons learned

---

## 🎓 Ethical Hacking Principles

### The Hacker's Code of Ethics

1. **Do No Harm**: Security testing should improve security, not compromise it
2. **Respect Privacy**: Don't access, copy, or disclose private information unnecessarily
3. **Be Transparent**: Document and disclose methods, tools, and findings appropriately
4. **Act with Integrity**: Never abuse access or findings for personal gain, revenge, or blackmail
5. **Respect the Law**: Comply with all applicable laws, regulations, and contractual obligations
6. **Give Back**: Share knowledge responsibly with the security community
7. **Stay Current**: Keep skills updated and follow evolving ethical standards

### Professional Standards

If you're a professional penetration tester:

-   Follow **OWASP Testing Guide** methodology
-   Adhere to **PTES** (Penetration Testing Execution Standard)
-   Consider **CEH** (Certified Ethical Hacker) code of ethics
-   Follow **SANS Institute** guidelines
-   Respect **Bug Bounty Program** rules (HackerOne, Bugcrowd, Synack)
-   Comply with **PCI DSS**, **HIPAA**, **SOC 2** requirements (if applicable)

---

## ⚠️ Prohibited Activities

**NEVER** use Argus for:

❌ Scanning WordPress sites without explicit authorization
❌ Cyber espionage or competitive intelligence gathering
❌ Credential harvesting, phishing, or password attacks
❌ Data exfiltration or unauthorized data access
❌ Malware deployment or backdoor installation
❌ Denial of service attacks (even "testing" DDoS resistance)
❌ Defacement, sabotage, or data destruction
❌ Exploiting vulnerabilities beyond proof-of-concept
❌ Harassment, intimidation, or extortion
❌ Reselling scan reports without permission
❌ Any illegal activity whatsoever

**Reminder**: Even if you find vulnerabilities "by accident," exploiting them without authorization is illegal.

---

## 🤝 Responsible Disclosure

If you discover vulnerabilities using Argus:

### 1. Private Disclosure (Recommended)

**Steps:**

1. Contact WordPress site owner/administrator privately
2. Use official security contact if available:
    - `security@domain.com`
    - `.well-known/security.txt` (RFC 9116)
    - Bug bounty program contact
3. Provide clear, professional report:
    - Vulnerability description
    - Severity assessment (CVSS score if possible)
    - Reproduction steps
    - Affected plugins/themes/versions
    - Potential impact
    - Remediation recommendations
4. Offer to assist with remediation (within reason)
5. Give reasonable time to fix before any public disclosure

**Timeframes:**

-   **Critical** (RCE, data breach, SQLi): 7-14 days
-   **High** (authentication bypass, XSS): 30 days
-   **Medium** (information disclosure): 60 days
-   **Low** (minor misconfigurations): 90 days

### 2. Coordinated Disclosure

-   Use vendor security contact email
-   Follow published vulnerability disclosure policy
-   Register CVE identifier if applicable (via MITRE, GitHub, etc.)
-   Coordinate public disclosure date
-   Credit researchers appropriately
-   Provide vendor opportunity to prepare patches

### 3. Public Disclosure

**Only after reasonable time has passed:**

-   Redact sensitive details (credentials, admin usernames, etc.)
-   Provide remediation guidance prominently
-   Credit vendor for cooperation (if applicable)
-   Use responsible platforms (WPScan, security mailing lists, blogs)
-   Don't release exploit code publicly without vendor agreement

### Resources

-   **WPScan Vulnerability Database**: https://wpscan.com/
-   **WordPress.org Plugin Team**: plugins@wordpress.org
-   **CERT/CC Disclosure Policy**: https://certcc.github.io/CERT-Guide-to-CVD/
-   **security.txt**: https://securitytxt.org/
-   **HackerOne Disclosure Guidelines**: https://www.hackerone.com/disclosure-guidelines
-   **OWASP Vulnerability Disclosure Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html

---

## 🔍 Argus-Specific Guidelines

### Consent Token Implementation

**Technical Detail**: Argus's consent token is a technical safeguard, NOT a legal authorization.

**What It Is:**

-   Cryptographic proof you control the target WordPress site
-   Prevents accidental scanning of wrong targets
-   Creates audit trail for compliance purposes
-   Required for aggressive mode and AI analysis

**What It Is NOT:**

-   Legal permission (still need written authorization)
-   Protection against prosecution if unauthorized
-   Substitute for proper contracts or bug bounty terms

**Best Practices:**

-   Generate unique token per engagement
-   Document token generation date/time
-   Revoke tokens immediately after engagement ends
-   Keep tokens confidential (treat like passwords)

### AI Analysis Privacy & Security

When using `--use-ai` with cloud providers (OpenAI, Anthropic):

**What Gets Sent:**

-   WordPress version
-   Plugin/theme names and versions
-   List of findings (titles and descriptions)
-   Severity levels
-   Generic remediation context

**What Gets REMOVED (sanitized automatically):**

-   Consent tokens
-   API keys and credentials
-   Database credentials (wp-config.php contents)
-   Session tokens and cookies
-   Admin usernames (when possible)
-   Internal IP addresses
-   Any PII (personally identifiable information)

**Privacy Options:**

1. **Ollama (Local Models)**: 100% offline, no data leaves your machine

    - Recommended for: Government, healthcare, finance, highly sensitive WordPress sites
    - Trade-off: Slower (28 min CPU vs 35s cloud)

2. **OpenAI**: Standard privacy (encrypted in transit, OpenAI privacy policy applies)

    - Recommended for: General commercial use

3. **Anthropic Claude**: Enhanced privacy (Anthropic's privacy-first approach)
    - Recommended for: Privacy-conscious organizations

**Best Practice**: Use Ollama for sensitive WordPress sites (government, healthcare, finance), cloud AI for general testing.

### Database Security & Privacy

`~/.argos/argos.db` contains potentially sensitive information:

-   Scan history with WordPress site URLs
-   Findings (vulnerability details)
-   Consent tokens
-   Enumerated usernames
-   Plugin/theme lists
-   Timestamps and metadata

**Protect This File:**

```bash
# Restrict permissions (owner read/write only)
chmod 600 ~/.argos/argos.db

# Encrypt your home directory (full disk encryption)
# Linux: LUKS, Windows: BitLocker, macOS: FileVault

# Don't commit to version control
echo ".argos/" >> ~/.gitignore

# Securely delete when engagement ends
shred -vfz -n 10 ~/.argos/argos.db
```

**Shared Database Note:**

-   Argus shares database with Hephaestus (server scanner) and future Argos suite tools
-   All tools respect same consent/authorization framework
-   Cross-tool findings correlation for unified vulnerability tracking

### Report Handling

**JSON Reports** (`~/.argus/reports/*.json`):

-   Machine-readable, ~50-65KB
-   Contains full vulnerability details
-   Suitable for automation/CI/CD
-   **Store securely**: Contains sensitive findings

**HTML Reports** (`~/.argus/reports/*.html`):

-   Human-readable, ~208-221KB (depending on AI analysis)
-   Self-contained (no external resources)
-   Suitable for stakeholder presentation
-   **Redact before sharing externally**

**Best Practices:**

```bash
# Encrypt reports before email
gpg --encrypt --recipient client@example.com report.html

# Use secure file transfer
scp -i key.pem report.html user@secure-server:/reports/

# Set retention policy
find ~/.argus/reports -mtime +90 -delete  # Delete after 90 days
```

---

## 📞 Reporting Misuse

If you observe or suspect misuse of Argus:

### 1. To Target Owner

-   Contact WordPress site owner immediately with evidence
-   Provide scan logs, timestamps, source IPs
-   Assist with incident response if appropriate

### 2. To Law Enforcement

-   **US**: FBI Internet Crime Complaint Center (IC3): https://www.ic3.gov
-   **UK**: Action Fraud: https://www.actionfraud.police.uk
-   **EU**: EUROPOL EC3: https://www.europol.europa.eu/about-europol/european-cybercrime-centre-ec3
-   Local police cybercrime units

### 3. To Me (For Documentation Only)

-   GitHub Issues: https://github.com/rodhnin/argus-wp-watcher/issues
-   **Note**: I am not law enforcement, but I will cooperate with legitimate investigations

**I Take Misuse Seriously:**

-   I will cooperate with law enforcement investigations
-   I may block known malicious actors from support channels
-   I maintain ethical use standards in our community

---

## ✅ Ethical Use Checklist

Before every scan with Argus, verify:

-   [ ] I have **written authorization** to test this WordPress site (email, contract, bug bounty terms)
-   [ ] The target is **within the authorized scope** (domain, subdomain, specific WordPress installation)
-   [ ] I have **informed relevant stakeholders** (IT, security operations, management)
-   [ ] I have **verified domain ownership** via consent token (if using `--aggressive` or `--use-ai`)
-   [ ] I understand the **potential impact** of my testing (service degradation, alert fatigue)
-   [ ] I have a **plan for responsible disclosure** of findings
-   [ ] I will **respect the law** and ethical principles at all times
-   [ ] I will **not cause harm or disruption** to the WordPress site or data
-   [ ] I will **protect any sensitive data** discovered during testing (usernames, plugin lists)
-   [ ] I will **properly secure and dispose of reports** after engagement ends
-   [ ] I have **emergency contacts** if something goes wrong
-   [ ] I have **documented this engagement** for audit purposes

**If you can't check ALL boxes, DO NOT SCAN.**

---

## 📚 Additional Resources

### Organizations & Standards Bodies

-   **OWASP** (Open Web Application Security Project): https://owasp.org

    -   OWASP Testing Guide
    -   OWASP Top 10
    -   OWASP WordPress Security Implementation Guide

-   **SANS Institute**: https://www.sans.org/security-resources/

-   **NIST** (National Institute of Standards and Technology): https://www.nist.gov

    -   NIST Cybersecurity Framework
    -   NIST 800-115 (Technical Guide to Information Security Testing)

-   **CREST** (Council of Registered Ethical Security Testers): https://www.crest-approved.org/

-   **PCI Security Standards Council**: https://www.pcisecuritystandards.org/

### Legal & Compliance Resources

-   **EFF** (Electronic Frontier Foundation): https://www.eff.org/issues/coders/reverse-engineering-faq
-   **CFAA Reform**: https://www.eff.org/issues/cfaa
-   **Bug Bounty Legal Safe Harbor**: https://www.hackerone.com/resources/legal-safe-harbor

### Technical Standards & Guides

-   **PTES** (Penetration Testing Execution Standard): http://www.pentest-standard.org/
-   **OSSTMM** (Open Source Security Testing Methodology Manual): https://www.isecom.org/OSSTMM.3.pdf
-   **NIST SP 800-115**: https://csrc.nist.gov/pubs/sp/800/115/final
-   **WPScan Vulnerability Database**: https://wpscan.com/

### Training & Certification

-   **CEH** (Certified Ethical Hacker): https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/
-   **OSCP** (Offensive Security Certified Professional): https://www.offensive-security.com/pwk-oscp/
-   **GPEN** (GIAC Penetration Tester): https://www.giac.org/certification/penetration-tester-gpen
-   **HackerOne University**: https://www.hackerone.com/hackers/hacker101
-   **Bugcrowd University**: https://www.bugcrowd.com/hackers/bugcrowd-university/

### WordPress Security Resources

-   **WordPress Security Team**: https://make.wordpress.org/core/handbook/testing/reporting-security-vulnerabilities/
-   **WordPress Hardening Guide**: https://wordpress.org/support/article/hardening-wordpress/
-   **WPScan**: https://wpscan.com/
-   **Wordfence Blog**: https://www.wordfence.com/blog/
-   **Sucuri Blog**: https://blog.sucuri.net/

---

## 🎯 Conclusion

**Ethical hacking is not just about technical skill—it's about integrity, responsibility, and respect for the law.**

Argus is a powerful tool designed to improve WordPress security. With great power comes great responsibility. Use it wisely, legally, and ethically.

### Key Takeaways

1. **Authorization is mandatory**: Always get written permission before scanning
2. **Consent tokens are not permission**: They prove technical control, not legal authority
3. **Document everything**: Logs, authorization, findings, communications
4. **Do no harm**: Never exploit, modify, or disrupt beyond authorized scope
5. **Disclose responsibly**: Give WordPress site owners time to fix before public disclosure
6. **Respect privacy**: Use local AI (Ollama) for sensitive WordPress sites
7. **Stay legal**: One mistake can end your career and result in prosecution

### Final Reminder

**If you're unsure whether you have permission to scan a WordPress site, YOU DON'T.**

When in doubt:

1. Stop immediately
2. Get written authorization
3. Document the authorization
4. Verify scope clearly
5. Only then proceed

**Remember**: Your reputation and freedom depend on following these guidelines. Always err on the side of caution and proper authorization.

---

## 📧 Questions or Concerns?

**Author & Maintainer:**  
Rodney Dhavid Jimenez Chacin (rodhnin)

**Contact:**

-   🌐 Website: https://rodhnin.com (for questions, feedback, or collaboration)
-   🐙 GitHub: https://github.com/rodhnin
-   💬 Discussions: https://github.com/rodhnin/argus-wp-watcher/discussions

**For Security Issues with Argus itself:**

-   Report vulnerabilities privately via GitHub Security Advisories
-   Allow 90 days for patching before public disclosure
-   I follow coordinated disclosure practices

---

## 📜 Legal Disclaimer

**IMPORTANT LEGAL NOTICE**

This software is provided for **authorized security testing only**. By using Argus, you agree that:

1. You will only scan WordPress sites you own or have explicit written permission to test
2. You accept full legal responsibility for your use of this tool
3. The author and contributors assume **NO LIABILITY** for misuse or damages
4. You will comply with all applicable laws and regulations in your jurisdiction
5. Unauthorized use may result in civil and criminal penalties

**The author of Argus:**

-   Do not endorse or encourage illegal activity
-   Will cooperate with law enforcement in cases of misuse
-   Reserve the right to restrict access to this tool
-   Make no warranties about the accuracy or completeness of scan results

**USE AT YOUR OWN RISK. YOU HAVE BEEN WARNED.**

---

_Version: 1.0_  
_Applies to: Argus v0.1.0 and later_
