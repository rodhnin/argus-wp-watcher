"""
WordPress Web Crawl & Content Discovery

Aggressive-mode only. Discovers information through:
- robots.txt: sensitive path disclosure
- sitemap.xml: URL enumeration and structure exposure
- HTML comments: hardcoded secrets/debug info/TODOs
- Link crawl (depth 1): internal page discovery

Finding IDs: ARGUS-WP-080 to ARGUS-WP-083

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import re
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


class CrawlChecker:
    """
    Passive web crawling for information disclosure.
    Runs exclusively in aggressive mode.
    """

    # Keywords that make an HTML comment security-relevant
    SENSITIVE_COMMENT_KEYWORDS = [
        'password', 'passwd', 'pass=', 'secret', 'api_key', 'apikey',
        'api key', 'token', 'credential', 'private', 'auth', 'authorization',
        'todo', 'fixme', 'hack', 'debug', 'test', 'staging', 'dev ',
        'internal', 'remove', 'delete this', 'key=', 'mysql', 'db_pass',
        'wp-config', 'admin', 'hardcoded', 'temporary', 'disabled',
    ]

    # Disallow patterns in robots.txt that suggest sensitive paths
    SENSITIVE_ROBOT_KEYWORDS = [
        'admin', 'backup', 'private', 'secret', 'api', 'config',
        'database', 'db', '.env', 'wp-config', 'install', 'setup',
        'staging', 'dev', 'test', 'old', 'temp', 'export',
        'log', 'logs', '.git', '.svn', 'internal',
    ]

    # Standard WordPress paths that appear in robots.txt but are NOT security issues
    # (present on virtually every WP site — flagging them creates noise / false positives)
    ROBOT_SAFE_PATHS = [
        '/wp-content/uploads/',
        '/wp-includes/',
        '/feed/',
        '/comments/feed/',
        '/?s=',
        '/search/',
    ]

    def __init__(self, config=None, http_client=None):
        self.config = config or get_config()
        self.session = http_client

        if self.session is None:
            import requests
            self.session = requests.Session()
            self.session.headers.update({'User-Agent': self.config.user_agent})
            logger.warning("No HTTP client provided, using non-rate-limited session")

    def scan(self, target: str) -> List[Dict]:
        """
        Run all crawl-based checks.

        Args:
            target: Target URL

        Returns:
            List of findings
        """
        findings = []
        logger.info("Running crawl checks (aggressive mode)")

        findings.extend(self._check_robots(target))
        findings.extend(self._check_sitemap(target))
        findings.extend(self._check_html_comments(target))
        findings.extend(self._crawl_links(target, max_depth=1))

        return findings

    # ------------------------------------------------------------------
    # robots.txt analysis
    # ------------------------------------------------------------------

    def _check_robots(self, target: str) -> List[Dict]:
        """
        Fetch robots.txt and identify sensitive paths disclosed via Disallow directives.
        """
        findings = []
        robots_url = urljoin(target, '/robots.txt')

        try:
            resp = self.session.get(robots_url, allow_redirects=True)
            if resp.status_code != 200 or not resp.text.strip():
                logger.debug("robots.txt not found or empty")
                return findings

            content = resp.text
            disallow_paths = re.findall(r'^Disallow:\s*(.+)$', content, re.MULTILINE | re.IGNORECASE)

            # Find sensitive Disallow paths (skip common WP paths — false positives)
            sensitive_paths = []
            for path in disallow_paths:
                path = path.strip()
                if not path or path == '/':
                    continue
                # Skip standard WP paths that appear in virtually every robots.txt
                if any(path.lower().startswith(safe.lower()) for safe in self.ROBOT_SAFE_PATHS):
                    continue
                if any(kw in path.lower() for kw in self.SENSITIVE_ROBOT_KEYWORDS):
                    sensitive_paths.append(path)

            if sensitive_paths:
                findings.append({
                    'id': 'ARGUS-WP-080',
                    'title': f'robots.txt discloses {len(sensitive_paths)} sensitive path(s)',
                    'severity': 'low',
                    'confidence': 'high',
                    'description': (
                        f'robots.txt reveals {len(sensitive_paths)} potentially sensitive path(s) '
                        f'via Disallow directives: {", ".join(sensitive_paths[:5])}'
                        + (f' (+{len(sensitive_paths)-5} more)' if len(sensitive_paths) > 5 else '')
                        + '. While robots.txt is a hint to bots, not a security control, '
                        'disclosing admin/backup/config paths helps attackers map the site structure.'
                    ),
                    'evidence': {
                        'type': 'url',
                        'value': robots_url,
                        'context': f'Sensitive Disallow paths: {", ".join(sensitive_paths[:10])}',
                    },
                    'recommendation': (
                        '1. Avoid listing sensitive admin/backup paths in robots.txt\n'
                        '2. Protect sensitive paths via server authentication, not by obscurity\n'
                        '3. Use a generic "Disallow: /wp-admin/" if needed rather than listing specific backup dirs\n'
                        '4. Regularly audit robots.txt for unintentional disclosures'
                    ),
                    'references': [
                        'https://developers.google.com/search/docs/crawling-indexing/robots/robots_txt',
                        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage',
                    ],
                    'affected_component': 'robots.txt',
                })
                logger.warning(f"robots.txt discloses {len(sensitive_paths)} sensitive paths")
            else:
                logger.debug(f"robots.txt found but no sensitive paths ({len(disallow_paths)} Disallow entries)")

        except Exception as e:
            logger.debug(f"robots.txt check failed: {e}")

        return findings

    # ------------------------------------------------------------------
    # sitemap.xml analysis
    # ------------------------------------------------------------------

    def _check_sitemap(self, target: str) -> List[Dict]:
        """
        Fetch sitemap.xml and analyze URL exposure for sensitive paths.
        """
        findings = []
        urls_found = []
        sensitive_urls = []

        # Try main sitemap and sitemap_index
        sitemap_candidates = [
            urljoin(target, '/sitemap.xml'),
            urljoin(target, '/sitemap_index.xml'),
            urljoin(target, '/wp-sitemap.xml'),  # WP 5.5+ native sitemap
        ]

        content = None
        sitemap_url = None
        for candidate in sitemap_candidates:
            try:
                resp = self.session.get(candidate, allow_redirects=True)
                if resp.status_code == 200 and resp.text.strip():
                    content = resp.text
                    sitemap_url = candidate
                    logger.debug(f"Sitemap found: {candidate}")
                    break
            except Exception:
                pass

        if not content or not sitemap_url:
            logger.debug("No sitemap found")
            return findings

        # Parse XML — extract all <loc> URLs
        try:
            root = ElementTree.fromstring(content)

            for loc in root.iter('{http://www.sitemaps.org/schemas/sitemap/0.9}loc'):
                url = loc.text.strip() if loc.text else ''
                if url:
                    urls_found.append(url)
                    # Flag URLs with sensitive keywords
                    if any(kw in url.lower() for kw in ['admin', 'login', 'backup', 'private', 'secret', 'api', 'config', 'export', 'internal']):
                        sensitive_urls.append(url)
        except ElementTree.ParseError as e:
            logger.debug(f"sitemap XML parse error: {e}")
            return findings

        if not urls_found:
            return findings

        # Build finding
        severity = 'low' if sensitive_urls else 'info'
        description = (
            f'A sitemap was found at {sitemap_url} containing {len(urls_found)} URL(s). '
        )
        if sensitive_urls:
            description += (
                f'{len(sensitive_urls)} URL(s) appear sensitive: '
                f'{", ".join(sensitive_urls[:3])}'
                + (f' (+{len(sensitive_urls)-3} more)' if len(sensitive_urls) > 3 else '')
                + '.'
            )
        else:
            description += 'No obviously sensitive URLs detected in sitemap.'

        findings.append({
            'id': 'ARGUS-WP-081',
            'title': f'Sitemap found: {len(urls_found)} URL(s) indexed' + (f', {len(sensitive_urls)} sensitive' if sensitive_urls else ''),
            'severity': severity,
            'confidence': 'high',
            'description': description,
            'evidence': {
                'type': 'url',
                'value': sitemap_url,
                'context': f'{len(urls_found)} total URLs, {len(sensitive_urls)} flagged',
            },
            'recommendation': (
                '1. Review sitemap for unintended URL exposure\n'
                '2. Exclude admin, login, backup, and private URLs from sitemaps\n'
                '3. Use X-Robots-Tag: noindex for sensitive pages\n'
                '4. Ensure sensitive pages require authentication — sitemaps are public by design'
            ),
            'references': [
                'https://developers.google.com/search/docs/crawling-indexing/sitemaps/overview',
            ],
            'affected_component': 'sitemap.xml',
        })

        return findings

    # ------------------------------------------------------------------
    # HTML comment analysis
    # ------------------------------------------------------------------

    def _check_html_comments(self, target: str) -> List[Dict]:
        """
        Fetch homepage and extract HTML comments containing sensitive keywords.
        """
        findings = []

        try:
            resp = self.session.get(target, allow_redirects=True)
            if resp.status_code != 200:
                return findings

            html = resp.text
            # Extract all HTML comments
            comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
            if not comments:
                return findings

            sensitive_comments = []
            for comment in comments:
                comment_lower = comment.lower()
                matched_keywords = [kw for kw in self.SENSITIVE_COMMENT_KEYWORDS if kw in comment_lower]
                if matched_keywords:
                    # Truncate long comments for the report
                    excerpt = comment.strip()[:200].replace('\n', ' ')
                    sensitive_comments.append({
                        'excerpt': excerpt,
                        'keywords': matched_keywords[:3],
                    })

            if sensitive_comments:
                severity = 'medium' if any(
                    any(kw in c['keywords'] for kw in ['password', 'secret', 'api_key', 'token', 'credential', 'key='])
                    for c in sensitive_comments
                ) else 'low'

                # Deduplicate by excerpt
                seen = set()
                unique_comments = []
                for c in sensitive_comments:
                    if c['excerpt'] not in seen:
                        seen.add(c['excerpt'])
                        unique_comments.append(c)

                findings.append({
                    'id': 'ARGUS-WP-082',
                    'title': f'Sensitive information in HTML comments ({len(unique_comments)} instance(s))',
                    'severity': severity,
                    'confidence': 'medium',
                    'description': (
                        f'{len(unique_comments)} HTML comment(s) on the homepage contain '
                        f'potentially sensitive keywords. Snippets: '
                        + ' | '.join(f'"{c["excerpt"][:80]}"' for c in unique_comments[:3])
                    ),
                    'evidence': {
                        'type': 'body',
                        'value': target,
                        'context': f'Keywords matched: {", ".join(set(kw for c in unique_comments for kw in c["keywords"]))}'
                    },
                    'recommendation': (
                        '1. Remove all HTML comments from production code\n'
                        '2. Never store credentials, API keys, or TODOs in source HTML\n'
                        '3. Use server-side template comments that are stripped before serving\n'
                        '4. Audit all theme and plugin templates for debug comments'
                    ),
                    'references': [
                        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage',
                    ],
                    'affected_component': 'homepage HTML',
                })
                logger.warning(f"Found {len(unique_comments)} sensitive HTML comment(s)")

        except Exception as e:
            logger.debug(f"HTML comment check failed: {e}")

        return findings

    # ------------------------------------------------------------------
    # Link crawl (depth 1)
    # ------------------------------------------------------------------

    def _crawl_links(self, target: str, max_depth: int = 1) -> List[Dict]:
        """
        Follow internal links from homepage up to max_depth levels.
        Report interesting/unexpected paths discovered.
        """
        findings = []
        parsed_target = urlparse(target)
        base_domain = parsed_target.netloc

        visited: Set[str] = set()
        interesting_paths = []

        INTERESTING_PATH_KEYWORDS = [
            'admin', 'login', 'backup', 'upload', 'export', 'import',
            'install', 'setup', 'config', 'debug', 'test', 'staging',
            'api', 'secret', 'private', 'internal', 'old', 'dev',
        ]

        def _fetch_links(url: str) -> List[str]:
            """Fetch a page and extract internal links."""
            try:
                resp = self.session.get(url, allow_redirects=True)
                if resp.status_code != 200:
                    return []
                links = re.findall(r'href=["\']([^"\']+)["\']', resp.text)
                internal = []
                for link in links:
                    if link.startswith('http'):
                        parsed = urlparse(link)
                        if parsed.netloc == base_domain:
                            internal.append(link)
                    elif link.startswith('/') and not link.startswith('//'):
                        internal.append(urljoin(target, link))
                return list(set(internal))
            except Exception:
                return []

        # Depth 0: homepage
        visited.add(target)
        depth0_links = _fetch_links(target)

        # Depth 1: follow links from homepage
        for link in depth0_links[:50]:  # cap at 50 to avoid explosion
            if link in visited:
                continue
            visited.add(link)

            parsed_link = urlparse(link)
            path = parsed_link.path.lower()

            if any(kw in path for kw in INTERESTING_PATH_KEYWORDS):
                interesting_paths.append(link)

            if max_depth >= 2:
                depth1_links = _fetch_links(link)
                for link2 in depth1_links[:20]:
                    if link2 in visited:
                        continue
                    visited.add(link2)
                    parsed2 = urlparse(link2)
                    path2 = parsed2.path.lower()
                    if any(kw in path2 for kw in INTERESTING_PATH_KEYWORDS):
                        interesting_paths.append(link2)

        if interesting_paths:
            # Deduplicate
            interesting_paths = list(dict.fromkeys(interesting_paths))
            findings.append({
                'id': 'ARGUS-WP-083',
                'title': f'Crawl discovered {len(interesting_paths)} interesting path(s)',
                'severity': 'info',
                'confidence': 'medium',
                'description': (
                    f'Web crawl (depth {max_depth}) found {len(interesting_paths)} '
                    f'internal URLs with potentially sensitive path components: '
                    + ', '.join(interesting_paths[:5])
                    + (f' (+{len(interesting_paths)-5} more)' if len(interesting_paths) > 5 else '')
                ),
                'evidence': {
                    'type': 'url',
                    'value': target,
                    'context': f'{len(visited)} pages visited, {len(interesting_paths)} flagged',
                },
                'recommendation': (
                    '1. Review discovered paths to confirm they require authentication\n'
                    '2. Remove development/staging URLs from production navigation\n'
                    '3. Ensure admin paths are protected by IP restriction or 2FA\n'
                    '4. Audit internal links in themes and plugins for unintended exposure'
                ),
                'references': [
                    'https://owasp.org/www-project-web-security-testing-guide/',
                ],
                'affected_component': 'site crawl',
            })
            logger.info(f"Crawl found {len(interesting_paths)} interesting paths from {len(visited)} visited")
        else:
            logger.debug(f"Crawl complete: {len(visited)} pages visited, no interesting paths flagged")

        return findings
