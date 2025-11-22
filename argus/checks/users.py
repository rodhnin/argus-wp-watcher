"""
WordPress User Enumeration Module

Detects users via:
- Author IDOR (/?author=N)
- REST API (/wp-json/wp/v2/users)
- Author archive pages
- Comment authors

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import re
from typing import List, Dict, Set, Optional
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


class UserEnumerator:
    """
    WordPress user enumeration via multiple methods.
    """
    
    def __init__(self, config=None, http_client=None):
        """
        Initialize user enumeration module.
        
        Args:
            config: Config instance
            http_client: RateLimitedSession instance
        """
        self.config = config or get_config()
        self.session = http_client  # Use rate-limited client
        self.discovered_users = set()
        
        # Fallback to regular session if no client provided
        if self.session is None:
            import requests
            self.session = requests.Session()
            self.session.headers.update({'User-Agent': self.config.user_agent})
            logger.warning("No HTTP client provided, using non-rate-limited session")
    
    def enumerate_via_author_idor(self, target: str, max_users: Optional[int] = None) -> List[Dict]:
        """
        Enumerate users via author IDOR (/?author=N).
        
        WordPress redirects /?author=N to /author/username/ (older versions)
        or displays author page directly without redirect (WordPress 6.x+)
        
        Args:
            target: Target URL
            max_users: Maximum user IDs to check
        
        Returns:
            List of user dictionaries
        """
        max_users = max_users or self.config.wp_max_users_check
        users = []
        
        logger.info(f"Checking author IDOR enumeration (max: {max_users} users)")
        
        for user_id in range(1, max_users + 1):
            user_url = urljoin(target, f'/?author={user_id}')
            
            try:
                response = self.session.get(user_url, allow_redirects=True)
                
                username = None
                method = None
                final_url = response.url
                
                # Check if there was a redirect (older WordPress behavior)
                if response.history and '/author/' in final_url:
                    # Redirected from /?author=N to /author/username/
                    username = self._extract_username_from_url(final_url)
                    method = 'author_idor_redirect'
                    logger.debug(f"Detected redirect: {user_url} -> {final_url}")
                
                # Check final URL even without redirect (WordPress 6.x+)
                elif '/author/' in final_url and final_url != user_url:
                    username = self._extract_username_from_url(final_url)
                    method = 'author_idor_url'
                
                # Check HTML content for username (WordPress 6.x+ direct response)
                elif response.status_code == 200:
                    username = self._extract_username_from_html(response.text, user_id)
                    method = 'author_idor_html'
                
                if username:
                    users.append({
                        'id': user_id,
                        'username': username,
                        'method': method,
                        'url': final_url
                    })
                    
                    logger.info(f"✓ User found via IDOR: {username} (ID: {user_id}, method: {method})")
            
            except Exception as e:
                logger.debug(f"IDOR check failed for ID {user_id}: {e}")
        
        return users
    
    def enumerate_via_rest_api(self, target: str) -> List[Dict]:
        """
        Enumerate users via WordPress REST API.
        
        Args:
            target: Target URL
        
        Returns:
            List of user dictionaries
        """
        users = []
        rest_url = urljoin(target, '/wp-json/wp/v2/users')
        
        logger.info("Checking REST API user enumeration")
        
        try:
            response = self.session.get(rest_url)
            
            if response.status_code == 200:
                try:
                    users_data = response.json()
                    
                    if isinstance(users_data, list):
                        for user in users_data:
                            username = user.get('slug') or user.get('name')
                            user_id = user.get('id')
                            
                            if username:
                                users.append({
                                    'id': user_id,
                                    'username': username,
                                    'name': user.get('name'),
                                    'method': 'rest_api',
                                    'url': rest_url
                                })
                                
                                logger.info(f"✓ User found via REST: {username} (ID: {user_id})")
                
                except ValueError:
                    logger.debug("REST API response not valid JSON")
            
            elif response.status_code == 401:
                logger.info("REST API user endpoint requires authentication (good!)")
            
            elif response.status_code == 404:
                logger.info("REST API not available or disabled")
        
        except Exception as e:
            logger.debug(f"REST API check failed: {e}")
        
        return users
    
    def enumerate_from_posts(self, target: str) -> List[Dict]:
        """
        Extract usernames from blog posts/comments.
        
        Args:
            target: Target URL
        
        Returns:
            List of user dictionaries
        """
        users = []
        
        try:
            response = self.session.get(target)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'lxml')
                
                # Look for author links
                author_links = soup.find_all('a', href=re.compile(r'/author/'))
                
                for link in author_links:
                    href = link.get('href')
                    username = self._extract_username_from_url(href)
                    
                    if username and username not in [u['username'] for u in users]:
                        users.append({
                            'username': username,
                            'method': 'post_author',
                            'url': href
                        })
                        logger.debug(f"User found in posts: {username}")
        
        except Exception as e:
            logger.debug(f"Post enumeration failed: {e}")
        
        return users
    
    def _extract_username_from_url(self, url: str) -> Optional[str]:
        """Extract username from author URL."""
        # /author/username/ or /author/username
        match = re.search(r'/author/([^/]+)', url)
        if match:
            return match.group(1).rstrip('/')
        return None
    
    def _extract_username_from_html(self, html: str, user_id: Optional[int] = None) -> Optional[str]:
        """
        Extract username from HTML content.
        
        Enhanced for WordPress 6.x+ which doesn't redirect but shows author page directly.
        
        Args:
            html: HTML content
            user_id: User ID being checked (for body class extraction)
        
        Returns:
            Username if found
        """
        soup = BeautifulSoup(html, 'lxml')
        
        # WordPress 6.x+ - Check H1 title "Author: <span>username</span>"
        h1_patterns = [
            soup.find('h1', class_=re.compile(r'wp-block-query-title')),
            soup.find('h1', class_=re.compile(r'archive-title|page-title')),
        ]
        
        for h1 in h1_patterns:
            if h1:
                text = h1.get_text(strip=True)
                # Match "Author: username" or "Author username"
                match = re.search(r'Author[:\s]+(\w+)', text, re.IGNORECASE)
                if match:
                    username = match.group(1)
                    if username.lower() not in ['author', 'by']:  # Avoid false positives
                        logger.debug(f"Username extracted from H1: {username}")
                        return username
                
                # Also check span inside H1
                span = h1.find('span')
                if span:
                    username = span.get_text(strip=True)
                    if username and len(username) < 50 and username.lower() not in ['author']:
                        logger.debug(f"Username extracted from H1 span: {username}")
                        return username
        
        # WordPress 6.x+ - Check body classes "author author-USERNAME author-ID"
        body = soup.find('body')
        if body and user_id:
            classes = body.get('class', [])
            if isinstance(classes, str):
                classes = classes.split()
            
            # Look for "author-USERNAME" pattern
            for cls in classes:
                # Match "author-username" but not "author-1" (ID)
                if cls.startswith('author-') and not cls.replace('author-', '').isdigit():
                    username = cls.replace('author-', '')
                    logger.debug(f"Username extracted from body class: {username}")
                    return username
        
        # Original patterns (fallback for older WordPress)
        patterns = [
            ('meta', {'name': 'author'}),
            ('span', {'class': re.compile(r'author|vcard')}),
            ('a', {'rel': 'author'}),
        ]
        
        for tag, attrs in patterns:
            element = soup.find(tag, attrs)
            if element:
                content = element.get('content') or element.get_text(strip=True)
                if content and len(content) < 50:  # Reasonable username length
                    logger.debug(f"Username extracted from {tag}: {content}")
                    return content
        
        return None
    
    def scan(self, target: str) -> List[Dict]:
        """
        Run full user enumeration scan.
        
        Args:
            target: Target URL
        
        Returns:
            List of findings
        """
        findings = []
        all_users = []
        
        # Method 1: Author IDOR
        if self.config.wp_check_author_idor:
            idor_users = self.enumerate_via_author_idor(target)
            all_users.extend(idor_users)
        
        # Method 2: REST API
        if self.config.wp_check_rest_api:
            rest_users = self.enumerate_via_rest_api(target)
            all_users.extend(rest_users)
        
        # Method 3: From posts
        post_users = self.enumerate_from_posts(target)
        all_users.extend(post_users)
        
        # Deduplicate users
        unique_users = {}
        for user in all_users:
            username = user['username']
            if username not in unique_users:
                unique_users[username] = user
        
        # Create findings
        if unique_users:
            # Check for common admin usernames
            risky_usernames = ['admin', 'administrator', 'root', 'test', 'demo']
            found_risky = [u for u in unique_users.keys() if u.lower() in risky_usernames]
            
            # Main finding for each user
            for username, user_info in unique_users.items():
                severity = 'high' if username.lower() in risky_usernames else 'medium'
                
                findings.append({
                    'id': 'ARGUS-WP-040',
                    'title': f'User enumerated: {username}',
                    'severity': severity,
                    'confidence': 'high',
                    'description': (
                        f"Username '{username}' discovered via {user_info['method']}. "
                        "User enumeration allows attackers to target brute force attacks."
                    ),
                    'evidence': {
                        'type': 'url',
                        'value': user_info.get('url', target),
                        'context': f"Method: {user_info['method']}, ID: {user_info.get('id', 'N/A')}"
                    },
                    'recommendation': (
                        f"1. {'URGENT: Change username (admin/administrator are prime targets)' if severity == 'high' else 'Consider changing predictable username'}\n"
                        "2. Disable author IDOR enumeration (security plugin)\n"
                        "3. Restrict REST API user endpoint\n"
                        "4. Implement brute force protection\n"
                        "5. Enable 2FA for all users\n"
                        "6. Use security plugins like Wordfence or iThemes Security"
                    ),
                    'references': [
                        'https://wordpress.org/documentation/article/hardening-wordpress/',
                        'https://owasp.org/www-community/attacks/Brute_force_attack'
                    ],
                    'affected_component': f'User: {username}'
                })
            
            # Summary finding
            severity = 'high' if found_risky else 'medium'
            findings.append({
                'id': 'ARGUS-WP-041',
                'title': f'{len(unique_users)} user(s) enumerated',
                'severity': severity,
                'confidence': 'high',
                'description': (
                    f"Successfully enumerated {len(unique_users)} WordPress users. "
                    f"{len(found_risky)} have risky/default usernames: {', '.join(found_risky) if found_risky else 'none'}."
                ),
                'evidence': {
                    'type': 'other',
                    'value': f"Usernames: {', '.join(list(unique_users.keys())[:10])}" + 
                             ('...' if len(unique_users) > 10 else ''),
                    'context': f"Methods: {', '.join(set(u['method'] for u in unique_users.values()))}"
                },
                'recommendation': (
                    'Implement user enumeration protection:\n'
                    '1. Use security plugins to block author IDOR\n'
                    '2. Disable REST API user endpoint: add_filter("rest_endpoints", function($endpoints) { unset($endpoints["/wp/v2/users"]); return $endpoints; });\n'
                    '3. Enable login attempt limiting\n'
                    '4. Change all default/obvious usernames\n'
                    '5. Enable 2FA site-wide\n'
                    '6. Monitor for brute force attempts'
                ),
                'references': [
                    'https://perishablepress.com/stop-user-enumeration-wordpress/',
                    'https://es.wordpress.org/plugins/stop-user-enumeration/'
                ]
            })
        
        else:
            # Good practice - no users enumerated
            findings.append({
                'id': 'ARGUS-WP-040',
                'title': 'User enumeration prevented (Good practice)',
                'severity': 'info',
                'confidence': 'medium',
                'description': 'No users could be enumerated, indicating proper security measures.',
                'recommendation': 'Continue blocking user enumeration and maintain strong authentication policies.'
            })
        
        return findings
