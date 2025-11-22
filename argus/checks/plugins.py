"""
WordPress Plugin & Theme Enumeration Module

Detects:
- Installed plugins (active and inactive)
- Installed themes
- Plugin/theme versions
- Outdated or vulnerable components

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import re
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


class PluginThemeEnumerator:
    """
    WordPress plugin and theme detection.
    """
    
    # Top vulnerable/popular plugins (from config + extras)
    COMMON_PLUGINS = [
        # Security & Performance
        'wordfence', 'jetpack', 'akismet', 'all-in-one-wp-security-and-firewall',
        'sucuri-scanner', 'ithemes-security', 'wp-super-cache', 'w3-total-cache',
        
        # SEO & Marketing
        'yoast-seo', 'google-analytics-for-wordpress', 'wordpress-seo',
        'all-in-one-seo-pack', 'redirection',
        
        # Forms & Contact
        'contact-form-7', 'wpforms-lite', 'ninja-forms', 'formidable',
        'gravityforms', 'contact-form-by-supsystic',
        
        # Page Builders
        'elementor', 'wpbakery-visual-composer', 'beaver-builder', 'divi-builder',
        'siteorigin-panels',
        
        # E-commerce
        'woocommerce', 'woocommerce-gateway-stripe', 'woocommerce-services',
        'easy-digital-downloads', 'wp-ecommerce',
        
        # Backup & Migration
        'updraftplus', 'all-in-one-wp-migration', 'duplicator', 'backwpup',
        
        # Media & Gallery
        'nextgen-gallery', 'envira-gallery-lite', 'smush', 'regenerate-thumbnails',
        
        # Social
        'social-media-share-buttons', 'instagram-feed', 'facebook-for-wordpress',
        
        # Historically Vulnerable (check these!)
        'slider-revolution', 'revslider', 'wpdatatables', 'wp-file-manager',
        'simple-file-list', 'email-subscribers', 'wp-google-maps',
        'wordpress-importer', 'duplicator', 'classic-editor',
    ]
    
    # Common themes
    COMMON_THEMES = [
        # Default WP themes
        'twentytwentyfour', 'twentytwentythree', 'twentytwentytwo',
        'twentytwentyone', 'twentytwenty', 'twentynineteen',
        
        # Popular premium/free
        'astra', 'generatepress', 'oceanwp', 'neve', 'kadence',
        'hello-elementor', 'storefront', 'divi', 'avada', 'enfold',
    ]
    
    def __init__(self, config=None, http_client=None):
        """
        Initialize enumeration module.
        
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
        
        # Merge config plugins with built-in
        self.plugins_to_check = list(set(
            self.COMMON_PLUGINS + 
            getattr(self.config, 'wp_common_plugins', [])
        ))
        
        self.themes_to_check = list(set(
            self.COMMON_THEMES +
            getattr(self.config, 'wp_common_themes', [])
        ))
    
    def enumerate_plugins(self, target: str, max_check: Optional[int] = None) -> List[Dict]:
        """
        Enumerate WordPress plugins.
        
        Args:
            target: Target URL
            max_check: Maximum plugins to check (default from config)
        
        Returns:
            List of findings
        """
        findings = []
        max_check = max_check or self.config.wp_max_plugins_check
        
        logger.info(f"Enumerating plugins (max: {max_check})")
        
        # Limit plugins to check
        plugins_subset = self.plugins_to_check[:max_check]
        
        # Discover plugins from HTML first
        discovered_plugins = self._discover_from_html(target, 'plugin')
        
        # Add discovered to check list (unique)
        all_plugins = list(set(plugins_subset + discovered_plugins))[:max_check]
        
        logger.info(f"Checking {len(all_plugins)} plugins ({len(discovered_plugins)} discovered from HTML)")
        
        # Check plugins concurrently
        found_plugins = []
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            future_to_plugin = {
                executor.submit(self._check_plugin, target, plugin): plugin
                for plugin in all_plugins
            }
            
            for future in as_completed(future_to_plugin):
                plugin = future_to_plugin[future]
                try:
                    result = future.result()
                    if result:
                        found_plugins.append(result)
                        logger.info(f"✓ Plugin found: {result['name']} {result.get('version', 'unknown version')}")
                except Exception as e:
                    logger.debug(f"Error checking plugin {plugin}: {e}")
        
        # Create findings for discovered plugins
        if found_plugins:
            for plugin in found_plugins:
                severity = 'info'
                confidence = 'high'
                title = f"Plugin detected: {plugin['name']}"
                
                # Check if plugin is known vulnerable (basic check)
                if plugin['name'] in ['slider-revolution', 'revslider', 'wp-file-manager']:
                    severity = 'medium'
                    title += " (historically vulnerable)"
                
                finding = {
                    'id': 'ARGUS-WP-010',
                    'title': title,
                    'severity': severity,
                    'confidence': confidence,
                    'description': f"WordPress plugin '{plugin['name']}' is installed.",
                    'evidence': {
                        'type': 'path',
                        'value': plugin['path'],
                        'context': f"Version: {plugin.get('version', 'unknown')}"
                    },
                    'recommendation': (
                        f"1. Verify {plugin['name']} is necessary\n"
                        "2. Update to latest version\n"
                        "3. Remove if unused\n"
                        "4. Check for known CVEs: https://wpscan.com/plugins/"
                    ),
                    'affected_component': plugin['name']
                }
                
                if plugin.get('version'):
                    finding['affected_component'] += f" {plugin['version']}"
                
                findings.append(finding)
            
            # Summary finding
            findings.append({
                'id': 'ARGUS-WP-011',
                'title': f'{len(found_plugins)} plugin(s) detected',
                'severity': 'info',
                'confidence': 'high',
                'description': f"Found {len(found_plugins)} WordPress plugins installed.",
                'recommendation': (
                    'Review all plugins:\n'
                    '- Remove unused plugins\n'
                    '- Update all plugins to latest versions\n'
                    '- Monitor for security updates\n'
                    '- Use only reputable plugins from WordPress.org'
                )
            })
        
        return findings
    
    def enumerate_themes(self, target: str, max_check: Optional[int] = None) -> List[Dict]:
        """
        Enumerate WordPress themes.
        
        Args:
            target: Target URL
            max_check: Maximum themes to check (default from config)
        
        Returns:
            List of findings
        """
        findings = []
        max_check = max_check or self.config.wp_max_themes_check
        
        logger.info(f"Enumerating themes (max: {max_check})")
        
        # Discover from HTML
        discovered_themes = self._discover_from_html(target, 'theme')
        
        # Combine with common themes
        all_themes = list(set(self.themes_to_check[:max_check] + discovered_themes))[:max_check]
        
        logger.info(f"Checking {len(all_themes)} themes ({len(discovered_themes)} discovered from HTML)")
        
        # Check themes concurrently
        found_themes = []
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            future_to_theme = {
                executor.submit(self._check_theme, target, theme): theme
                for theme in all_themes
            }
            
            for future in as_completed(future_to_theme):
                theme = future_to_theme[future]
                try:
                    result = future.result()
                    if result:
                        found_themes.append(result)
                        logger.info(f"✓ Theme found: {result['name']} {result.get('version', '')}")
                except Exception as e:
                    logger.debug(f"Error checking theme {theme}: {e}")
        
        # Create findings
        if found_themes:
            for theme in found_themes:
                findings.append({
                    'id': 'ARGUS-WP-020',
                    'title': f"Theme detected: {theme['name']}",
                    'severity': 'info',
                    'confidence': 'high',
                    'description': f"WordPress theme '{theme['name']}' is installed.",
                    'evidence': {
                        'type': 'path',
                        'value': theme['path'],
                        'context': f"Version: {theme.get('version', 'unknown')}"
                    },
                    'recommendation': (
                        f"1. Update {theme['name']} to latest version\n"
                        "2. Remove unused themes (keep only active + one backup)\n"
                        "3. Use child themes for customizations"
                    ),
                    'affected_component': f"{theme['name']} theme"
                })
            
            findings.append({
                'id': 'ARGUS-WP-021',
                'title': f'{len(found_themes)} theme(s) detected',
                'severity': 'info',
                'confidence': 'high',
                'description': f"Found {len(found_themes)} WordPress themes installed.",
                'recommendation': 'Keep only necessary themes installed and updated.'
            })
        
        return findings
    
    def _discover_from_html(self, target: str, component_type: str) -> List[str]:
        """
        Discover plugins/themes from HTML source.
        
        Args:
            target: Target URL
            component_type: 'plugin' or 'theme'
        
        Returns:
            List of discovered component names
        """
        discovered = set()
        
        try:
            response = self.session.get(target)
            
            if response.status_code == 200:
                if component_type == 'plugin':
                    # Look for /wp-content/plugins/NAME/
                    pattern = r'/wp-content/plugins/([a-z0-9-_]+)/'
                else:  # theme
                    # Look for /wp-content/themes/NAME/
                    pattern = r'/wp-content/themes/([a-z0-9-_]+)/'
                
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                discovered.update(matches)
        
        except Exception as e:
            logger.debug(f"HTML discovery failed: {e}")
        
        return list(discovered)
    
    def _check_plugin(self, target: str, plugin_name: str) -> Optional[Dict]:
        """
        Check if a specific plugin exists.
        
        Args:
            target: Target URL
            plugin_name: Plugin directory name
        
        Returns:
            Dict with plugin info or None if not found
        """
        plugin_url = urljoin(target, f'/wp-content/plugins/{plugin_name}/')
        
        # Try to access plugin directory
        try:
            response = self.session.get(plugin_url, allow_redirects=False)
            
            # 200 = directory listing, 403 = exists but forbidden
            if response.status_code in [200, 403]:
                # Try to get version from readme.txt
                version = self._get_plugin_version(target, plugin_name)
                
                return {
                    'name': plugin_name,
                    'path': plugin_url,
                    'version': version,
                    'status_code': response.status_code
                }
        
        except Exception as e:
            logger.debug(f"Plugin check failed for {plugin_name}: {e}")
        
        return None
    
    def _check_theme(self, target: str, theme_name: str) -> Optional[Dict]:
        """
        Check if a specific theme exists.
        
        Args:
            target: Target URL
            theme_name: Theme directory name
        
        Returns:
            Dict with theme info or None if not found
        """
        theme_url = urljoin(target, f'/wp-content/themes/{theme_name}/')
        
        try:
            response = self.session.get(theme_url, allow_redirects=False)
            
            if response.status_code in [200, 403]:
                version = self._get_theme_version(target, theme_name)
                
                return {
                    'name': theme_name,
                    'path': theme_url,
                    'version': version,
                    'status_code': response.status_code
                }
        
        except Exception as e:
            logger.debug(f"Theme check failed for {theme_name}: {e}")
        
        return None
    
    def _get_plugin_version(self, target: str, plugin_name: str) -> Optional[str]:
        """Extract plugin version from readme.txt."""
        readme_url = urljoin(target, f'/wp-content/plugins/{plugin_name}/readme.txt')
        
        try:
            response = self.session.get(readme_url)
            
            if response.status_code == 200:
                # Look for "Stable tag: X.Y.Z"
                match = re.search(r'Stable tag:\s*(\d+\.\d+(?:\.\d+)?)', response.text, re.IGNORECASE)
                if match:
                    return match.group(1)
        
        except Exception:
            pass
        
        return None
    
    def _get_theme_version(self, target: str, theme_name: str) -> Optional[str]:
        """Extract theme version from style.css."""
        style_url = urljoin(target, f'/wp-content/themes/{theme_name}/style.css')
        
        try:
            response = self.session.get(style_url)
            
            if response.status_code == 200:
                # Look for "Version: X.Y.Z" in CSS header
                match = re.search(r'Version:\s*(\d+\.\d+(?:\.\d+)?)', response.text, re.IGNORECASE)
                if match:
                    return match.group(1)
        
        except Exception:
            pass
        
        return None
    
    def scan(self, target: str) -> List[Dict]:
        """
        Run full plugin/theme enumeration.
        
        Args:
            target: Target URL
        
        Returns:
            List of findings
        """
        all_findings = []
        
        # Enumerate plugins
        plugin_findings = self.enumerate_plugins(target)
        all_findings.extend(plugin_findings)
        
        # Enumerate themes
        theme_findings = self.enumerate_themes(target)
        all_findings.extend(theme_findings)
        
        return all_findings
