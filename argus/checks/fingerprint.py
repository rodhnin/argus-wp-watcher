"""
WordPress Fingerprinting Module

Detects:
- WordPress presence
- Core version via multiple methods
- Generator meta tags
- README files
- RSS feed generator

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import re
from typing import Optional, Dict, List, Tuple
from urllib.parse import urljoin

from bs4 import BeautifulSoup
import requests  # BUG-015: Import for exception types

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


class WordPressFingerprint:
    """
    WordPress detection and version identification.
    """
    
    # Version extraction patterns
    VERSION_PATTERNS = [
        # readme.html: "Version 5.8"
        r'Version\s+(\d+\.\d+(?:\.\d+)?)',
        # Meta generator: "WordPress 5.8"
        r'WordPress\s+(\d+\.\d+(?:\.\d+)?)',
        # RSS feed: "https://wordpress.org/?v=5.8"
        r'\?v=(\d+\.\d+(?:\.\d+)?)',
        # JS/CSS URLs: "wp-includes/js/...?ver=5.8"
        r'ver=(\d+\.\d+(?:\.\d+)?)',
    ]
    
    # WordPress indicators
    WP_INDICATORS = [
        '/wp-content/',
        '/wp-includes/',
        '/wp-admin/',
        'wp-json',
        'xmlrpc.php',
    ]
    
    def __init__(self, config=None, http_client=None):
        """
        Initialize fingerprint module.
        
        Args:
            config: Config instance
            http_client: RateLimitedSession instance
        """
        self.config = config or get_config()
        self.session = http_client  # Use rate-limited client
        
        # Fallback to regular session if no client provided
        if self.session is None:
            import requests
            self.session = requests.Session()
            self.session.headers.update({'User-Agent': self.config.user_agent})
            logger.warning("No HTTP client provided, using non-rate-limited session")
    
    def detect_wordpress(self, target: str) -> Tuple[bool, List[Dict]]:
        """
        Detect if target is running WordPress.
        
        Args:
            target: Target URL
        
        Returns:
            Tuple of (is_wordpress, findings_list)
        
        Raises:
            requests.RequestException: On connection/network errors
        """
        findings = []
        is_wp = False
        
        response = self.session.get(target)
        
        if response.status_code != 200:
            logger.warning(f"Target returned {response.status_code}")
            # Non-200 status is NOT a connection error, just not WordPress
            return False, findings
        
        html = response.text
        
        # Check for WordPress indicators
        wp_count = 0
        for indicator in self.WP_INDICATORS:
            if indicator in html:
                wp_count += 1
        
        if wp_count >= 2:  # At least 2 indicators
            is_wp = True
            
            findings.append({
                'id': 'ARGUS-WP-000',
                'title': 'WordPress detected',
                'severity': 'info',
                'confidence': 'high',
                'evidence': {
                    'type': 'body',
                    'value': f'Found {wp_count}/{len(self.WP_INDICATORS)} WP indicators',
                    'context': f'Indicators: {", ".join(self.WP_INDICATORS[:3])}'
                },
                'recommendation': 'WordPress installation confirmed. Proceed with security checks.'
            })
            
            logger.info(f"WordPress detected on {target}")
        else:
            logger.info(f"WordPress not detected on {target}")
        
        return is_wp, findings
    
    def get_version(self, target: str) -> Tuple[Optional[str], List[Dict]]:
        """
        Detect WordPress version using multiple methods.
        
        Args:
            target: Target URL
        
        Returns:
            Tuple of (version_string, findings_list)
        """
        findings = []
        version = None
        methods_tried = []
        
        # Method 1: Meta generator tag
        v = self._check_meta_generator(target)
        methods_tried.append(('meta_generator', v))
        if v and not version:
            version = v
        
        # Method 2: readme.html
        v = self._check_readme(target)
        methods_tried.append(('readme.html', v))
        if v and not version:
            version = v
        
        # Method 3: RSS feed
        v = self._check_rss_feed(target)
        methods_tried.append(('rss_feed', v))
        if v and not version:
            version = v
        
        # Method 4: Asset version parameters
        v = self._check_assets(target)
        methods_tried.append(('assets', v))
        if v and not version:
            version = v
        
        # Create finding
        if version:
            findings.append({
                'id': 'ARGUS-WP-001',
                'title': 'WordPress core version disclosed',
                'severity': 'medium',
                'confidence': 'high',
                'description': (
                    f'WordPress version {version} detected. Version disclosure helps '
                    'attackers identify known vulnerabilities for targeted exploits.'
                ),
                'evidence': {
                    'type': 'other',
                    'value': f'Version: {version}',
                    'context': f'Methods: {[m for m, v in methods_tried if v]}'
                },
                'recommendation': (
                    '1. Update WordPress to latest version\n'
                    '2. Hide version info by removing generator tags\n'
                    '3. Restrict access to readme.html and license.txt\n'
                    '4. Use security plugins to mask WP fingerprints'
                ),
                'references': [
                    'https://wordpress.org/documentation/article/hardening-wordpress/',
                    'https://developer.wordpress.org/apis/security/'
                ],
                'affected_component': f'WordPress Core {version}'
            })
            
            logger.info(f"WordPress version detected: {version}")
        else:
            # Even if version not found, it's good practice
            findings.append({
                'id': 'ARGUS-WP-001',
                'title': 'WordPress version hidden (Good practice)',
                'severity': 'info',
                'confidence': 'high',
                'description': 'WordPress version is not publicly disclosed, which is a security best practice.',
                'recommendation': 'Continue hiding version information and keep WordPress updated.',
            })
            
            logger.info("WordPress version not disclosed (good!)")
        
        return version, findings
    
    def _check_meta_generator(self, target: str) -> Optional[str]:
        """Check meta generator tag for version."""
        try:
            response = self.session.get(target)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'lxml')
                generator = soup.find('meta', {'name': 'generator'})
                
                if generator and generator.get('content'):
                    content = generator['content']
                    for pattern in self.VERSION_PATTERNS:
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match:
                            logger.debug(f"Version found in meta generator: {match.group(1)}")
                            return match.group(1)
        
        except Exception as e:
            logger.debug(f"Meta generator check failed: {e}")
        
        return None
    
    def _check_readme(self, target: str) -> Optional[str]:
        """Check readme.html for version."""
        readme_url = urljoin(target, '/readme.html')
        
        try:
            response = self.session.get(readme_url)
            
            if response.status_code == 200:
                for pattern in self.VERSION_PATTERNS:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match:
                        logger.debug(f"Version found in readme.html: {match.group(1)}")
                        return match.group(1)
        
        except Exception as e:
            logger.debug(f"readme.html check failed: {e}")
        
        return None
    
    def _check_rss_feed(self, target: str) -> Optional[str]:
        """Check RSS feed for version."""
        feed_urls = [
            urljoin(target, '/feed/'),
            urljoin(target, '/feed/atom/'),
            urljoin(target, '/?feed=rss2'),
        ]
        
        for feed_url in feed_urls:
            try:
                response = self.session.get(feed_url)
                
                if response.status_code == 200:
                    # Look for generator tag in RSS
                    for pattern in self.VERSION_PATTERNS:
                        match = re.search(pattern, response.text, re.IGNORECASE)
                        if match:
                            logger.debug(f"Version found in RSS feed: {match.group(1)}")
                            return match.group(1)
            
            except Exception as e:
                logger.debug(f"RSS feed check failed for {feed_url}: {e}")
        
        return None
    
    def _check_assets(self, target: str) -> Optional[str]:
        """Check JS/CSS assets for version parameters."""
        try:
            response = self.session.get(target)
            
            if response.status_code == 200:
                # Look for wp-includes/js or wp-includes/css with ver= parameter
                matches = re.findall(
                    r'/wp-(?:includes|content)/(?:js|css)/[^"\']*\?ver=(\d+\.\d+(?:\.\d+)?)',
                    response.text,
                    re.IGNORECASE
                )
                
                if matches:
                    # Return most common version
                    from collections import Counter
                    version = Counter(matches).most_common(1)[0][0]
                    logger.debug(f"Version found in assets: {version}")
                    return version
        
        except Exception as e:
            logger.debug(f"Assets check failed: {e}")
        
        return None
    
    def scan(self, target: str) -> List[Dict]:
        """
        Run full fingerprinting scan.
        
        Args:
            target: Target URL
        
        Returns:
            List of findings
        
        Raises:
            requests.RequestException: On connection/network errors
        """
        all_findings = []
        
        # Let them propagate to scanner.py for proper error handling
        is_wp, wp_findings = self.detect_wordpress(target)
        all_findings.extend(wp_findings)
        
        if not is_wp:
            logger.warning(f"{target} does not appear to be a WordPress site")
            all_findings.append({
                'id': 'ARGUS-WP-000',
                'title': 'WordPress not detected',
                'severity': 'info',
                'confidence': 'high',
                'description': 'Target does not appear to be running WordPress. Argus is optimized for WordPress scanning.',
                'recommendation': 'Verify target is correct or use a different scanner for non-WordPress sites.'
            })
            return all_findings
        
        # Get version
        version, version_findings = self.get_version(target)
        all_findings.extend(version_findings)
        
        return all_findings