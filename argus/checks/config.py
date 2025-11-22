"""
WordPress Configuration Issues Module

Checks for:
- XML-RPC enabled (abuse potential)
- Directory listing enabled
- Debug mode enabled
- WP-Cron exposure
- File editing enabled in admin
- Default admin URL

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

from typing import List, Dict, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


class ConfigChecker:
    """
    WordPress configuration security checks.
    """
    
    # Directories to check for listing
    COMMON_DIRECTORIES = [
        '/wp-content/',
        '/wp-content/uploads/',
        '/wp-content/uploads/2024/',
        '/wp-content/uploads/2025/',
        '/wp-content/plugins/',
        '/wp-content/themes/',
        '/wp-includes/',
    ]
    
    def __init__(self, config=None, http_client=None):
        """
        Initialize config checker.
        
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
    
    def check_xmlrpc(self, target: str) -> List[Dict]:
        """
        Check if XML-RPC is enabled and responding.
        
        Args:
            target: Target URL
        
        Returns:
            List of findings
        """
        findings = []
        xmlrpc_url = urljoin(target, '/xmlrpc.php')
        
        logger.info("Checking XML-RPC interface")
        
        try:
            # Try GET request first
            response = self.session.get(xmlrpc_url)
            
            if response.status_code == 200 and 'xml-rpc' in response.text.lower():
                # Try a simple XML-RPC call to confirm it's functional
                xml_payload = """<?xml version="1.0"?>
                <methodCall>
                    <methodName>system.listMethods</methodName>
                    <params></params>
                </methodCall>"""
                
                rpc_response = self.session.post(
                    xmlrpc_url,
                    data=xml_payload,
                    headers={'Content-Type': 'text/xml'}
                )
                
                if rpc_response.status_code == 200:
                    # Count available methods
                    methods_count = rpc_response.text.count('<string>')
                    
                    findings.append({
                        'id': 'ARGUS-WP-060',
                        'title': 'XML-RPC interface enabled',
                        'severity': 'medium',
                        'confidence': 'high',
                        'description': (
                            f'WordPress XML-RPC interface is enabled and responding with {methods_count} methods. '
                            'XML-RPC can be abused for brute force attacks, DDoS amplification, and pingback exploits.'
                        ),
                        'evidence': {
                            'type': 'url',
                            'value': xmlrpc_url,
                            'context': f'HTTP {rpc_response.status_code}, {methods_count} methods available'
                        },
                        'recommendation': (
                            'Disable XML-RPC if not needed:\n'
                            '1. Add to .htaccess:\n'
                            '   <Files xmlrpc.php>\n'
                            '     Order Deny,Allow\n'
                            '     Deny from all\n'
                            '   </Files>\n'
                            '2. Or use security plugin to disable\n'
                            '3. Or add to wp-config.php: add_filter("xmlrpc_enabled", "__return_false");\n'
                            '4. If needed for Jetpack, restrict to Jetpack IPs only'
                        ),
                        'references': [
                            'https://kinsta.com/blog/xmlrpc-php/'
                        ],
                        'affected_component': 'xmlrpc.php'
                    })
                    
                    logger.warning(f"XML-RPC enabled with {methods_count} methods")
            
            elif response.status_code == 405:  # Method not allowed
                findings.append({
                    'id': 'ARGUS-WP-060',
                    'title': 'XML-RPC partially restricted (Good)',
                    'severity': 'info',
                    'confidence': 'high',
                    'description': 'XML-RPC file exists but returns 405, indicating some restriction.',
                    'recommendation': 'Verify XML-RPC is fully disabled or properly restricted.'
                })
        
        except requests.RequestException as e:
            logger.debug(f"XML-RPC check failed: {e}")
        
        return findings
    
    def check_directory_listing(self, target: str) -> List[Dict]:
        """
        Check for directory listing vulnerabilities.
        
        Args:
            target: Target URL
        
        Returns:
            List of findings
        """
        findings = []
        exposed_dirs = []
        
        logger.info(f"Checking {len(self.COMMON_DIRECTORIES)} directories for listing")
        
        for directory in self.COMMON_DIRECTORIES:
            dir_url = urljoin(target, directory)
            
            try:
                response = self.session.get(dir_url, allow_redirects=False)
                
                if response.status_code == 200:
                    # Check if it's an actual directory listing
                    if self._is_directory_listing(response.text):
                        exposed_dirs.append({
                            'path': directory,
                            'url': dir_url,
                            'file_count': response.text.count('<a href=')
                        })
                        
                        logger.warning(f"✗ Directory listing enabled: {directory}")
            
            except requests.RequestException as e:
                logger.debug(f"Directory check failed for {directory}: {e}")
        
        # Create findings for exposed directories
        if exposed_dirs:
            for dir_info in exposed_dirs:
                findings.append({
                    'id': 'ARGUS-WP-061',
                    'title': f'Directory listing enabled: {dir_info["path"]}',
                    'severity': 'medium',
                    'confidence': 'high',
                    'description': (
                        f"Directory listing is enabled for {dir_info['path']}, exposing "
                        f"{dir_info['file_count']} items. Attackers can browse and download files."
                    ),
                    'evidence': {
                        'type': 'url',
                        'value': dir_info['url'],
                        'context': f"HTTP 200, {dir_info['file_count']} items listed"
                    },
                    'recommendation': (
                        f"Disable directory listing for {dir_info['path']}:\n"
                        '1. Add to .htaccess: Options -Indexes\n'
                        '2. Or add blank index.html to each directory\n'
                        '3. Or configure in Apache/Nginx:\n'
                        '   Apache: <Directory> Options -Indexes </Directory>\n'
                        '   Nginx: autoindex off;'
                    ),
                    'references': [
                        'https://www.acunetix.com/vulnerabilities/web/directory-listings/',
                    ],
                    'affected_component': dir_info['path']
                })
            
            # Summary
            findings.append({
                'id': 'ARGUS-WP-062',
                'title': f'{len(exposed_dirs)} directory/directories exposed',
                'severity': 'medium',
                'confidence': 'high',
                'description': f"Found {len(exposed_dirs)} directories with listing enabled.",
                'recommendation': 'Disable directory indexing globally across the WordPress installation.'
            })
        
        return findings
    
    def check_debug_mode(self, target: str) -> List[Dict]:
        """
        Check if WP_DEBUG is enabled (from debug.log or HTML).
        
        Args:
            target: Target URL
        
        Returns:
            List of findings
        """
        findings = []
        
        # Check for debug.log (already checked in files.py but verify here)
        debug_url = urljoin(target, '/wp-content/debug.log')
        
        try:
            response = self.session.get(debug_url)
            
            if response.status_code == 200 and len(response.content) > 100:
                findings.append({
                    'id': 'ARGUS-WP-063',
                    'title': 'Debug mode potentially enabled',
                    'severity': 'high',
                    'confidence': 'high',
                    'description': 'debug.log file is accessible and contains error logs, indicating WP_DEBUG is enabled.',
                    'evidence': {
                        'type': 'url',
                        'value': debug_url,
                        'context': f'File size: {len(response.content)} bytes'
                    },
                    'recommendation': (
                        'Disable debug mode in production:\n'
                        '1. Edit wp-config.php:\n'
                        "   define('WP_DEBUG', false);\n"
                        "   define('WP_DEBUG_LOG', false);\n"
                        "   define('WP_DEBUG_DISPLAY', false);\n"
                        '2. Delete existing debug.log file\n'
                        '3. Use error logging to secure location outside webroot'
                    ),
                    'references': [
                        'https://wordpress.org/documentation/article/debugging-in-wordpress/'
                    ]
                })
        
        except requests.RequestException:
            pass
        
        # Check HTML for debug output
        try:
            response = self.session.get(target)
            
            if response.status_code == 200:
                debug_indicators = [
                    'Call Stack',
                    'Fatal error:',
                    'Warning: ',
                    'Notice: ',
                    '/var/www/',
                    '/home/',
                    'wp-config.php',
                ]
                
                found_indicators = [ind for ind in debug_indicators if ind in response.text]
                
                if found_indicators:
                    findings.append({
                        'id': 'ARGUS-WP-064',
                        'title': 'PHP errors/warnings visible in HTML',
                        'severity': 'medium',
                        'confidence': 'medium',
                        'description': f'PHP error output detected in HTML: {", ".join(found_indicators[:3])}',
                        'evidence': {
                            'type': 'body',
                            'value': f'Found: {", ".join(found_indicators[:3])}...',
                            'context': 'Debug output in page source'
                        },
                        'recommendation': (
                            'Disable error display in production:\n'
                            "1. Set display_errors = Off in php.ini\n"
                            "2. Set WP_DEBUG_DISPLAY to false in wp-config.php\n"
                            "3. Log errors to file instead of displaying"
                        )
                    })
        
        except Exception:
            pass
        
        return findings
    
    def check_admin_access(self, target: str) -> List[Dict]:
        """
        Check if wp-admin is openly accessible.
        
        Args:
            target: Target URL
        
        Returns:
            List of findings
        """
        findings = []
        admin_url = urljoin(target, '/wp-admin/')
        
        try:
            response = self.session.get(admin_url, allow_redirects=True)
            
            # If we get login page (not 403), admin is accessible
            if response.status_code == 200 and 'wp-login' in response.url.lower():
                findings.append({
                    'id': 'ARGUS-WP-065',
                    'title': 'Admin login page publicly accessible',
                    'severity': 'info',
                    'confidence': 'high',
                    'description': 'WordPress admin login page is accessible at default URL.',
                    'evidence': {
                        'type': 'url',
                        'value': response.url,
                        'context': f'HTTP {response.status_code}'
                    },
                    'recommendation': (
                        'Harden admin access:\n'
                        '1. Consider changing wp-admin URL (security plugin)\n'
                        '2. Implement login attempt limiting\n'
                        '3. Enable 2FA for all admin users\n'
                        '4. Use IP whitelisting if possible\n'
                        '5. Monitor for brute force attempts'
                    ),
                    'references': [
                        'https://wordpress.org/documentation/article/hardening-wordpress/#securing-wp-admin'
                    ]
                })
        
        except Exception:
            pass
        
        return findings
    
    def _is_directory_listing(self, html: str) -> bool:
        """
        Check if HTML content is a directory listing.
        
        Args:
            html: HTML content
        
        Returns:
            True if directory listing detected
        """
        indicators = [
            'Index of /',
            'Parent Directory',
            '<title>Index of',
            'Directory Listing',
        ]
        
        html_lower = html.lower()
        
        # Check for indicators
        if any(ind.lower() in html_lower for ind in indicators):
            return True
        
        # Check for Apache/Nginx directory listing pattern
        soup = BeautifulSoup(html, 'lxml')
        
        # Apache style: <pre> with multiple <a href>
        pre_tags = soup.find_all('pre')
        for pre in pre_tags:
            links = pre.find_all('a')
            if len(links) > 2: 
                return True
        
        return False
    
    def scan(self, target: str) -> List[Dict]:
        """
        Run full configuration checks.
        
        Args:
            target: Target URL
        
        Returns:
            List of findings
        """
        all_findings = []
        
        # Check XML-RPC
        xmlrpc_findings = self.check_xmlrpc(target)
        all_findings.extend(xmlrpc_findings)
        
        # Check directory listing
        dirlist_findings = self.check_directory_listing(target)
        all_findings.extend(dirlist_findings)
        
        # Check debug mode
        debug_findings = self.check_debug_mode(target)
        all_findings.extend(debug_findings)
        
        # Check admin access
        admin_findings = self.check_admin_access(target)
        all_findings.extend(admin_findings)
        
        return all_findings


if __name__ == "__main__":
    # Test config checks
    from ..core.config import Config
    
    config = Config.load()
    checker = ConfigChecker(config)
    
    test_target = "https://wordpress.org"
    
    print(f"Testing configuration checks on {test_target}")
    findings = checker.scan(test_target)
    
    for finding in findings:
        print(f"\n[{finding['severity'].upper()}] {finding['title']}")
