"""
OWASP Top 10 2021 Compliance Mapping for Argus Findings

Maps each ARGUS-WP-XXX finding ID to its corresponding OWASP Top 10 2021 category.
Applied automatically during report generation — no changes needed in check modules.

Reference: https://owasp.org/Top10/

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

# OWASP Top 10 2021 categories
OWASP_CATEGORIES = {
    'A01': 'Broken Access Control',
    'A02': 'Cryptographic Failures',
    'A03': 'Injection',
    'A04': 'Insecure Design',
    'A05': 'Security Misconfiguration',
    'A06': 'Vulnerable and Outdated Components',
    'A07': 'Identification and Authentication Failures',
    'A08': 'Software and Data Integrity Failures',
    'A09': 'Security Logging and Monitoring Failures',
    'A10': 'Server-Side Request Forgery (SSRF)',
}

# Mapping: finding ID → OWASP category ID
FINDING_TO_OWASP = {
    # WordPress fingerprinting
    'ARGUS-WP-000': 'A05',   # WordPress detected — info disclosure / misconfiguration
    'ARGUS-WP-001': 'A05',   # Version disclosed — security misconfiguration

    # Plugins & themes
    'ARGUS-WP-010': 'A06',   # Plugin detected (may be outdated)
    'ARGUS-WP-011': 'A06',   # Plugins summary
    'ARGUS-WP-012': 'A06',   # Vulnerable plugin with known CVEs
    'ARGUS-WP-020': 'A06',   # Theme detected
    'ARGUS-WP-021': 'A06',   # Themes summary
    'ARGUS-WP-022': 'A06',   # Vulnerable theme with known CVEs

    # Sensitive files & directories
    'ARGUS-WP-030': 'A05',   # Sensitive file exposed (debug.log, wp-config.bak, etc.)
    'ARGUS-WP-031': 'A05',   # Config backup accessible
    'ARGUS-WP-032': 'A05',   # Directory brute-force hit

    # User enumeration
    'ARGUS-WP-040': 'A07',   # User enumeration via author IDOR
    'ARGUS-WP-041': 'A07',   # User enumeration via REST API
    'ARGUS-WP-042': 'A07',   # User enumeration via login errors

    # Security headers
    'ARGUS-WP-050': 'A05',   # Missing security header (generic)
    'ARGUS-WP-051': 'A02',   # Missing HSTS — cryptographic / transport failure
    'ARGUS-WP-052': 'A05',   # Missing CSP — security misconfiguration
    'ARGUS-WP-053': 'A05',   # Missing X-Frame-Options

    # Configuration issues
    'ARGUS-WP-060': 'A05',   # XML-RPC enabled
    'ARGUS-WP-061': 'A05',   # Directory listing enabled
    'ARGUS-WP-062': 'A05',   # WP_DEBUG exposed
    'ARGUS-WP-063': 'A05',   # File editor enabled in wp-admin
    'ARGUS-WP-064': 'A05',   # wp-config.php accessible
    'ARGUS-WP-065': 'A05',   # Readme.html / license.txt exposed

    # Login & authentication
    'ARGUS-WP-070': 'A07',   # Login page accessible
    'ARGUS-WP-071': 'A07',   # No 2FA enforced
    'ARGUS-WP-072': 'A07',   # No CAPTCHA on login
    'ARGUS-WP-073': 'A07',   # No brute-force protection
    'ARGUS-WP-074': 'A01',   # Open user registration (broken access control)
    'ARGUS-WP-075': 'A07',   # No password policy

    # Crawl findings
    'ARGUS-WP-080': 'A05',   # robots.txt exposes sensitive paths
    'ARGUS-WP-081': 'A05',   # Sitemap found (info disclosure)
    'ARGUS-WP-082': 'A05',   # Sensitive HTML comments
    'ARGUS-WP-083': 'A05',   # Interesting paths found via crawl
}


def get_owasp(finding_id: str) -> dict:
    """
    Return OWASP Top 10 2021 mapping for a finding ID.

    Returns a dict with 'id' and 'name', or None if no mapping exists.

    Example:
        get_owasp('ARGUS-WP-012')
        → {'id': 'A06', 'name': 'Vulnerable and Outdated Components'}
    """
    category_id = FINDING_TO_OWASP.get(finding_id)
    if category_id is None:
        return None
    return {
        'id': category_id,
        'name': OWASP_CATEGORIES[category_id],
    }


def enrich_findings_with_owasp(findings: list) -> list:
    """
    Add 'owasp' field to each finding that has a known mapping.
    Modifies findings in-place and returns the list.
    """
    for finding in findings:
        fid = finding.get('id', '')
        mapping = get_owasp(fid)
        if mapping:
            finding['owasp'] = mapping
    return findings
