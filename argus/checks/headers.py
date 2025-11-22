"""
Security Headers Check Module

Verifies presence and configuration of:
- HSTS (Strict-Transport-Security)
- CSP (Content-Security-Policy)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection (legacy)
- Referrer-Policy
- Permissions-Policy
- Cookie security flags

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

from typing import List, Dict, Optional
from urllib.parse import urlparse

import requests

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


class SecurityHeadersChecker:
    """
    Checks security-related HTTP headers.
    """
    
    # Header importance and recommendations
    HEADER_CONFIGS = {
        'Strict-Transport-Security': {
            'severity_missing': 'medium',
            'name_display': 'HSTS (HTTP Strict Transport Security)',
            'description': 'Forces browsers to use HTTPS, preventing protocol downgrade attacks.',
            'recommendation': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            'only_https': True,
        },
        'Content-Security-Policy': {
            'severity_missing': 'medium',
            'name_display': 'Content Security Policy (CSP)',
            'description': 'Mitigates XSS, clickjacking, and other code injection attacks.',
            'recommendation': "Add CSP header with appropriate directives (e.g., default-src 'self')",
            'only_https': False,
        },
        'X-Frame-Options': {
            'severity_missing': 'medium',
            'name_display': 'X-Frame-Options',
            'description': 'Prevents clickjacking attacks by controlling iframe embedding.',
            'recommendation': 'Add header: X-Frame-Options: SAMEORIGIN or DENY',
            'only_https': False,
        },
        'X-Content-Type-Options': {
            'severity_missing': 'low',
            'name_display': 'X-Content-Type-Options',
            'description': 'Prevents MIME-sniffing attacks.',
            'recommendation': 'Add header: X-Content-Type-Options: nosniff',
            'only_https': False,
        },
        'X-XSS-Protection': {
            'severity_missing': 'low',
            'name_display': 'X-XSS-Protection (Legacy)',
            'description': 'Legacy XSS filter (modern browsers use CSP instead).',
            'recommendation': 'Add header: X-XSS-Protection: 1; mode=block (or rely on CSP)',
            'only_https': False,
        },
        'Referrer-Policy': {
            'severity_missing': 'low',
            'name_display': 'Referrer-Policy',
            'description': 'Controls how much referrer information is shared.',
            'recommendation': 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
            'only_https': False,
        },
        'Permissions-Policy': {
            'severity_missing': 'info',
            'name_display': 'Permissions-Policy',
            'description': 'Controls which browser features can be used.',
            'recommendation': 'Add header with appropriate feature restrictions',
            'only_https': False,
        },
    }
    
    def __init__(self, config=None, http_client=None):
        """
        Initialize headers checker.
        
        Args:
            config: Config instance
            http_client: RateLimitedSession instance
        """
        self.config = config or get_config()
        self.session = http_client  # Use rate-limited client
        
        # Fallback to regular session if no client provided (for backward compatibility)
        if self.session is None:
            self.session = requests.Session()
            self.session.headers.update({'User-Agent': self.config.user_agent})
            logger.warning("No HTTP client provided, using non-rate-limited session")
    
    def check_headers(self, target: str) -> Dict[str, Optional[str]]:
        """
        Fetch and return security headers from target.
        
        Args:
            target: Target URL
        
        Returns:
            Dictionary of header_name: header_value
        """
        headers = {}
        
        try:
            response = self.session.get(target, allow_redirects=True)
            
            # Extract security-related headers (case-insensitive)
            for header_name in self.HEADER_CONFIGS.keys():
                value = response.headers.get(header_name)
                headers[header_name] = value
            
            # Also check for alternative/deprecated names
            if not headers.get('Content-Security-Policy'):
                headers['Content-Security-Policy'] = (
                    response.headers.get('X-Content-Security-Policy') or
                    response.headers.get('X-WebKit-CSP')
                )
            
            logger.debug(f"Retrieved {len([v for v in headers.values() if v])} security headers")
        
        except requests.RequestException as e:
            logger.error(f"Failed to fetch headers: {e}")
        
        return headers
    
    def check_cookies(self, target: str) -> List[Dict]:
        """
        Check cookie security flags.
        
        Args:
            target: Target URL
        
        Returns:
            List of cookie findings
        """
        findings = []
        
        try:
            response = self.session.get(target)
            
            cookies = response.cookies
            is_https = urlparse(target).scheme == 'https'
            
            if cookies:
                for cookie in cookies:
                    issues = []
                    
                    # Check Secure flag (only relevant for HTTPS sites)
                    if is_https and not cookie.secure:
                        issues.append('missing Secure flag')
                    
                    # Check HttpOnly flag
                    if not cookie.has_nonstandard_attr('HttpOnly'):
                        issues.append('missing HttpOnly flag')
                    
                    # Check SameSite attribute
                    samesite = cookie.get_nonstandard_attr('SameSite')
                    if not samesite:
                        issues.append('missing SameSite attribute')
                    elif samesite.lower() == 'none' and not cookie.secure:
                        issues.append('SameSite=None without Secure flag')
                    
                    if issues:
                        findings.append({
                            'id': 'ARGUS-WP-052',
                            'title': f'Insecure cookie: {cookie.name}',
                            'severity': 'medium' if 'Secure' in issues[0] or 'HttpOnly' in issues[0] else 'low',
                            'confidence': 'high',
                            'description': f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}.",
                            'evidence': {
                                'type': 'header',
                                'value': f'Set-Cookie: {cookie.name}',
                                'context': f'Issues: {", ".join(issues)}'
                            },
                            'recommendation': (
                                f"Set proper cookie flags for '{cookie.name}':\n"
                                f"{'- Add Secure flag (HTTPS only)' if 'Secure' in ' '.join(issues) else ''}\n"
                                f"{'- Add HttpOnly flag (prevent JavaScript access)' if 'HttpOnly' in ' '.join(issues) else ''}\n"
                                f"{'- Add SameSite attribute (Strict or Lax)' if 'SameSite' in ' '.join(issues) else ''}"
                            ),
                            'references': [
                                'https://owasp.org/www-community/controls/SecureCookieAttribute',
                                'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies'
                            ]
                        })
        
        except Exception as e:
            logger.debug(f"Cookie check failed: {e}")
        
        return findings
    
    def scan(self, target: str) -> List[Dict]:
        """
        Run full security headers scan.
        
        Args:
            target: Target URL
        
        Returns:
            List of findings
        """
        findings = []
        is_https = urlparse(target).scheme == 'https'
        
        # Fetch headers
        headers = self.check_headers(target)
        
        # Check each header
        missing_headers = []
        present_headers = []
        weak_headers = []
        
        for header_name, config in self.HEADER_CONFIGS.items():
            value = headers.get(header_name)
            
            # Skip HTTPS-only headers if site is HTTP
            if config['only_https'] and not is_https:
                continue
            
            if not value:
                missing_headers.append(header_name)
                
                findings.append({
                    'id': 'ARGUS-WP-050',
                    'title': f'Missing security header: {config["name_display"]}',
                    'severity': config['severity_missing'],
                    'confidence': 'high',
                    'description': (
                        f"{config['name_display']} header is not set. "
                        f"{config['description']}"
                    ),
                    'evidence': {
                        'type': 'header',
                        'value': f'{header_name}: [not set]',
                        'context': 'Header missing in HTTP response'
                    },
                    'recommendation': config['recommendation'],
                    'references': [
                        'https://owasp.org/www-project-secure-headers/',
                        'https://securityheaders.com/'
                    ]
                })
            
            else:
                present_headers.append(header_name)
                
                # Validate header value
                issues = self._validate_header(header_name, value)
                
                if issues:
                    weak_headers.append(header_name)
                    
                    findings.append({
                        'id': 'ARGUS-WP-051',
                        'title': f'Weak {config["name_display"]} configuration',
                        'severity': 'low',
                        'confidence': 'medium',
                        'description': f"{config['name_display']}: {', '.join(issues)}",
                        'evidence': {
                            'type': 'header',
                            'value': f'{header_name}: {value[:100]}...' if len(value) > 100 else f'{header_name}: {value}',
                            'context': f'Issues: {", ".join(issues)}'
                        },
                        'recommendation': f'Review and strengthen {header_name} configuration. ' + config['recommendation']
                    })
        
        # Check cookies
        cookie_findings = self.check_cookies(target)
        findings.extend(cookie_findings)
        
        # Summary finding
        if missing_headers or weak_headers or cookie_findings:
            total_issues = len(missing_headers) + len(weak_headers) + len(cookie_findings)
            
            findings.append({
                'id': 'ARGUS-WP-053',
                'title': f'{total_issues} security header/cookie issue(s) detected',
                'severity': 'medium' if missing_headers else 'low',
                'confidence': 'high',
                'description': (
                    f"Found {len(missing_headers)} missing headers, "
                    f"{len(weak_headers)} weak headers, "
                    f"and {len(cookie_findings)} insecure cookies."
                ),
                'recommendation': (
                    'Implement security headers best practices:\n'
                    '1. Add all missing security headers\n'
                    '2. Strengthen weak header configurations\n'
                    '3. Set proper cookie security flags\n'
                    '4. Test configuration at https://securityheaders.com/\n'
                    '5. Use WordPress security plugins for easy header management'
                )
            })
        
        else:
            # Good security posture
            findings.append({
                'id': 'ARGUS-WP-050',
                'title': 'Security headers properly configured',
                'severity': 'info',
                'confidence': 'high',
                'description': f'All {len(present_headers)} critical security headers are present.',
                'recommendation': 'Continue monitoring and updating security header configurations.'
            })
        
        return findings
    
    def _validate_header(self, header_name: str, value: str) -> List[str]:
        """
        Validate header value and return list of issues.
        
        Args:
            header_name: Header name
            value: Header value
        
        Returns:
            List of issue descriptions
        """
        issues = []
        value_lower = value.lower()
        
        if header_name == 'Strict-Transport-Security':
            # Check max-age
            if 'max-age' not in value_lower:
                issues.append('missing max-age directive')
            elif 'max-age=0' in value_lower:
                issues.append('max-age set to 0 (ineffective)')
            else:
                import re
                match = re.search(r'max-age=(\d+)', value_lower)
                if match:
                    max_age = int(match.group(1))
                    if max_age < 31536000:  # 1 year
                        issues.append(f'max-age too short ({max_age}s, recommend 31536000+)')
            
            # Check includeSubDomains
            if 'includesubdomains' not in value_lower:
                issues.append('missing includeSubDomains (recommended)')
        
        elif header_name == 'Content-Security-Policy':
            # Very basic CSP validation
            if 'unsafe-inline' in value_lower:
                issues.append("'unsafe-inline' allows inline scripts (reduces CSP effectiveness)")
            if 'unsafe-eval' in value_lower:
                issues.append("'unsafe-eval' allows eval() (security risk)")
            if value_lower.strip() == '':
                issues.append('CSP is empty')
        
        elif header_name == 'X-Frame-Options':
            valid_values = ['deny', 'sameorigin']
            if value_lower not in valid_values and not value_lower.startswith('allow-from'):
                issues.append(f'invalid value (should be DENY, SAMEORIGIN, or ALLOW-FROM)')
        
        elif header_name == 'X-Content-Type-Options':
            if value_lower != 'nosniff':
                issues.append('should be set to "nosniff"')
        
        return issues


if __name__ == "__main__":
    # Test headers check
    from ..core.config import Config
    
    config = Config.load()
    checker = SecurityHeadersChecker(config)
    
    test_target = "https://wordpress.org"
    
    print(f"Testing security headers on {test_target}")
    findings = checker.scan(test_target)
    
    for finding in findings:
        print(f"\n[{finding['severity'].upper()}] {finding['title']}")
