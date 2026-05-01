"""
WordPress Plugin & Theme Enumeration Module

Detects installed plugins and themes, extracts their versions via
multiple methods, and correlates with the WPVulnerability.net database
to surface known CVEs without requiring an API key.

Version detection methods (in priority order):
  1. HTML source asset URL (?ver=X.Y.Z) — extracted during HTML parse
  2. readme.txt / readme.md — "Stable tag: X.Y.Z"
  3. changelog.txt — first version number in file
  4. Main PHP file header — "Version: X.Y.Z" comment block

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.logging import get_logger
from ..core.config import get_config
from ..core.vuln_db import get_vuln_db

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Plugin / theme wordlists
# ---------------------------------------------------------------------------

COMMON_PLUGINS = [
    # Security & Performance
    'wordfence', 'jetpack', 'akismet', 'all-in-one-wp-security-and-firewall',
    'sucuri-scanner', 'ithemes-security', 'wp-super-cache', 'w3-total-cache',
    'really-simple-ssl', 'loginizer', 'login-lockdown',
    # SEO & Marketing
    'yoast-seo', 'google-analytics-for-wordpress', 'all-in-one-seo-pack',
    'redirection', 'broken-link-checker',
    # Forms & Contact
    'contact-form-7', 'wpforms-lite', 'ninja-forms', 'formidable',
    'gravityforms', 'contact-form-by-supsystic', 'caldera-forms',
    # Page Builders
    'elementor', 'beaver-builder', 'siteorigin-panels',
    'visual-composer', 'divi-builder',
    # E-commerce
    'woocommerce', 'woocommerce-gateway-stripe', 'woocommerce-services',
    'easy-digital-downloads', 'wp-ecommerce',
    # Backup & Migration
    'updraftplus', 'all-in-one-wp-migration', 'duplicator', 'backwpup',
    'wp-db-backup', 'backupbuddy',
    # Media & Gallery
    'nextgen-gallery', 'envira-gallery-lite', 'smush', 'regenerate-thumbnails',
    # Social
    'instagram-feed', 'facebook-for-wordpress',
    'social-media-share-buttons', 'wp-to-buffer',
    # Utilities
    'classic-editor', 'advanced-custom-fields', 'wp-mail-smtp',
    'tablepress', 'the-events-calendar', 'custom-post-type-ui',
    'post-smtp', 'user-role-editor', 'wp-optimize',
    # Historically Vulnerable (high priority to check)
    'slider-revolution', 'revslider', 'wp-file-manager',
    'simple-file-list', 'email-subscribers', 'wp-google-maps',
    'wpdb', 'wordpress-importer', 'wp-fastest-cache',
    'coming-soon', 'under-construction-page', 'maintenance',
    'wp-live-chat-support', 'tidio-live-chat',
    'cookie-notice', 'complianz', 'gdpr-cookie-consent',
    'woodmart', 'flatsome', 'woodmart-core',
    # Safe mode additions — all 100K+ installs with security history
    'seo-by-rank-math',              # Rank Math SEO — 1M+ installs
    'google-site-kit',               # Google Site Kit — 3M+ installs
    'give',                          # GiveWP donations — 100K+, payment handling
    'learnpress',                    # LearnPress LMS — 100K+
    'cloudflare',                    # Cloudflare plugin — 200K+
    'ultimate-member',               # Ultimate Member — 200K+, many CVEs (RCE history)
    'gwolle-gb',                     # Gwolle Guestbook — SQL injection history
    'profilepress',                  # ProfilePress — RCE history
    'store-locator-le',              # Store Locator LE — SQL injection history
    'ai-engine',                     # AI Engine by Jordy Meow — 100K+, API key exposure
    'ottokit',                       # OttoKit/SureTriggers — CVE-2025-27007 (CVSS 9.8)
    'limit-login-attempts-reloaded', # 700K+ installs, brute force protection
    'wps-hide-login',                # 1M+ installs, login URL obfuscation
    'autoptimize',                   # 1M+ installs, performance
    'litespeed-cache',               # 5M+ installs, many CVEs in history
    'wp-statistics',                 # 600K+ installs, analytics
    'newsletter',                    # Newsletter — 300K+ installs, email handling
    'insert-headers-and-footers',    # WPCode — 2M+ installs, code injection risk
    'disable-xml-rpc',               # 1M+ installs, XML-RPC hardening
    'wp-2fa',                        # WP 2FA — security, 2FA enforcement
    'popup-maker',                   # 700K+ installs, JS injection history
    'acf-extended',                  # ACF Extended — 100K+, custom fields
    'wp-migrate-db',                 # WP Migrate DB — dev tool often left active
    'wordfence-login-security',      # Wordfence Login Security — standalone 2FA module
]

COMMON_THEMES = [
    # Default WP themes
    'twentytwentyfour', 'twentytwentythree', 'twentytwentytwo',
    'twentytwentyone', 'twentytwenty', 'twentynineteen',
    'twentyeighteen', 'twentyseventeen',
    # Popular premium/free
    'astra', 'generatepress', 'oceanwp', 'neve', 'kadence',
    'hello-elementor', 'storefront', 'divi', 'avada', 'enfold',
    'flatsome', 'woodmart', 'shopkeeper',
    'blocksy', 'colibri-wp', 'hestia', 'sydney',
]

# Extended list for aggressive mode (adds to COMMON_PLUGINS, not replaces)
AGGRESSIVE_EXTRA_PLUGINS = [
    # Page builders
    'beaver-builder-lite-version', 'brizy', 'cornerstone', 'fusion-builder',
    'live-composer-page-builder', 'page-builder-sandwich', 'thrive-architect',
    # Security (extended)
    'anti-malware', 'bbq-firewall', 'better-wp-security', 'fail2ban',
    'hide-my-wp', 'limit-login-attempts', 'limit-login-attempts-reloaded',
    'loginizer', 'minirange-sms-otp-two-factor-authentication', 'ninjafirewall',
    'rename-wp-login', 'shield-security', 'two-factor', 'wp-cerber',
    'wp-hide-login', 'wp-simple-firewall', 'wps-hide-login', 'wp2fa',
    'melapress-login-security', 'wordfence-login-security',
    # Forms (extended)
    'contact-form-cfdb7', 'everest-forms', 'fluentform', 'formcraft',
    'forminator', 'happyforms', 'mailchimp-for-wp', 'weforms', 'ws-form',
    # E-commerce (extended)
    'cart-abandonment-recovery', 'checkout-plugins-stripe-woo',
    'dokan-lite', 'wc-vendors', 'wcfm-marketplace',
    'woocommerce-abandoned-cart-recovery', 'woocommerce-germanized',
    'woocommerce-memberships', 'woocommerce-pdf-invoices-packing-slips',
    'woocommerce-product-addons', 'woocommerce-product-bundles',
    'woocommerce-subscriptions', 'yith-woocommerce-ajax-navigation',
    'yith-woocommerce-compare', 'yith-woocommerce-wishlist',
    # Membership & LMS
    'academy', 'learndash', 'learnpress', 'lifter-lms',
    'memberpress', 'paid-memberships-pro', 'restrict-content',
    's2member', 'sensei-lms', 'tutor', 'wp-courseware',
    # Social & Sharing
    'addtoany', 'blog2social', 'facebook-for-woocommerce',
    'monarch', 'pinterest-for-woocommerce', 'sassy-social-share',
    'simple-social-icons', 'social-warfare', 'ultimate-social-media-icons',
    'wp-social-sharing',
    # Email & Newsletter
    'convertpro', 'mailpoet', 'newsletter', 'newsletters',
    'optinmonster', 'sumo', 'wp-email',
    # Cache & Performance (extended)
    'asset-cleanup', 'autoptimize', 'comet-cache', 'flying-press',
    'hummingbird-performance', 'litespeed-cache', 'nitropack',
    'perfmatters', 'sg-cachepress', 'swift-performance-lite', 'wp-rocket',
    # Backup & Migration (extended)
    'akeeba-backup-for-wordpress', 'backup-by-supsystic', 'backup-guard',
    'blogvault-real-time-backup', 'migrate-guru', 'wp-staging', 'wpvivid-backups',
    # Media (extended)
    'enable-media-replace', 'ewww-image-optimizer', 'filester', 'imagify',
    'real-media-library', 'shortpixel-image-optimiser', 'wp-file-manager-advanced',
    'wp-media-folder',
    # Sliders (extended, historically vulnerable)
    'foobox-image-lightbox', 'layerslider', 'lightbox-plus', 'masterslider',
    'meta-slider', 'ml-slider', 'modula-best-grid-gallery', 'photo-gallery',
    'sliderpro', 'smart-slider-3', 'slider-wd', 'soliloquy',
    # Multi-language
    'codestyling-localization', 'loco-translate', 'polylang',
    'translatepress-multilingual', 'weglot', 'wp-multilang', 'wpml',
    # Analytics & Cookie
    'complianz-gdpr', 'cookie-law-info', 'cookiebot', 'ga-google-analytics',
    'gdpr-cookie-compliance', 'gtm4wp', 'matomo', 'moove-gdpr-cookie-compliance',
    'wp-piwik',
    # Chat & Support
    '3cx-live-chat', 'crisp', 'freshdesk', 'live-chat', 'tawkto-live-chat',
    'wp-chatbot', 'zendesk',
    # Tables & Data
    'data-tables-generator-by-supsystic', 'ninja-tables', 'pods',
    'wp-table-builder',
    # Custom Fields (extended)
    'acf-to-rest-api', 'codepress-admin-columns', 'mb-custom-post-type',
    'meta-box', 'secure-custom-fields', 'toolset-blocks', 'types', 'wp-types',
    # High-CVE history (critical to check)
    'advanced-access-manager', 'appointment-hour-booking', 'avada',
    'db-backup', 'duplicator-pro', 'formcraft-form-builder',
    'gwolle-gb', 'kama-click-counter', 'layerslider-wp', 'nextgen-plus',
    'photo-contest', 'pie-register', 'postman-smtp', 'profilepress',
    'store-locator-le', 'the-newsletter-plugin', 'ultimate-member',
    'wp-client', 'wp-editor', 'wp-job-manager', 'wp-mail-logging',
    'wp-statistics', 'ws-form-pro', 'wpdb',
    # REST API
    'jwt-authentication-for-wp-rest-api', 'rest-api-toolbox',
    'wp-json-exporter', 'wp-rest-api-controller',
    # Search & Filter
    'ajax-search-pro', 'facet-wp', 'filter-everything', 'relevanssi', 'searchwp',
    'wp-search-with-algolia',
    # Reviews & Ratings
    'customer-reviews-woocommerce', 'review-schema', 'trustpilot-reviews',
    'wp-customer-reviews',
    # Payments
    'charitable', 'give', 'gravity-forms-stripe', 'paypal-for-woocommerce',
    'stripe', 'woocommerce-paypal-payments', 'wp-simple-pay',
    # Popups
    'hello-bar', 'hustle', 'optin-forms', 'popup-builder', 'popup-maker',
    # Maps & Events
    'event-list', 'events-manager', 'google-maps-widget',
    'modern-events-calendar-lite', 'my-calendar',
    'the-events-calendar-community-events', 'wpmaps',
    # Gutenberg Blocks
    'atomic-blocks', 'builderius', 'cwicly', 'genesis-blocks',
    'otter-blocks', 'qubely', 'spectra', 'stackable-ultimate-gutenberg-blocks',
    'ultimate-blocks',
    # Admin & Utilities
    'admin-columns-pro', 'admin-menu-editor', 'adminimize',
    'clone', 'copy-delete-posts', 'custom-sidebars', 'duplicate-post',
    'envato-market', 'my-wp-customize', 'ocdi', 'one-click-demo-import',
    'post-duplicator', 'white-label-cms', 'widget-importer-exporter',
    'wp-custom-admin-interface', 'wp-help', 'yoast-duplicate-post',
    # CAPTCHA
    'advanced-nocaptcha-recaptcha', 'bws-captcha', 'captcha-bank',
    'really-simple-captcha', 'really-simple-recaptcha', 'wp-recaptcha-integration',
    # Misc security-related
    'hide-my-wp', 'maintenance-mode', 'site-offline', 'wp-hide-security-enhancer',
    'wp-maintenance-mode', 'coming-soon-wp',
    # CRM
    'hubspot', 'pipedrive', 'salesforce-wordpress', 'wp-crm', 'zero-bs-crm',
    # PDF & Documents
    'dompdf-plugin', 'easy-pdf-generator', 'pdf-embedder', 'wp-pdf-templates',
    # Additional security plugins
    'security-malware-firewall', 'wp-security-audit-log', 'loginpress',
    'cerber-security',
    # SEO and analytics
    'wordpress-seo', 'seo-by-rank-math', 'google-site-kit', 'analytify',
    'pixel-cat', 'insert-headers-and-footers', 'custom-css-js',
    'header-footer-code-manager',
    # Performance and caching
    'fast-velocity-minify', 'async-javascript', 'a3-lazy-load', 'lazy-load',
    'bj-lazy-load',
    # E-commerce extended
    'woocommerce-gateway-paypal-powered-by-braintree', 'woocommerce-stripe',
    'woocommerce-square', 'woocommerce-amazon-payments-advanced',
    'woo-gutenberg-products-block', 'woocommerce-blocks',
    'product-import-export-for-woo', 'woo-product-feed-pro',
    # Content and media
    'wp-smushit', 'tinypng-for-wordpress', 'imagerecycle-pdf-image-compression',
    'compress-jpeg-png-images', 'media-cleaner', 'real-media-library-lite',
    # Forms extended
    'quform', 'machform', 'wp-polls', 'survey-maker', 'quiz-maker',
    # Page builders extended
    'kingcomposer', 'js-composer', 'visual-composer-website-builder', 'oxygen',
    'generateblocks', 'ultimate-addons-for-gutenberg', 'kadence-blocks',
    # Sliders and galleries
    'master-slider', 'cyclone-slider-2', 'nivo-slider', 'slideshow-se',
    'maxslider', 'envira-gallery', 'justified-image-grid', 'robo-gallery',
    # Membership and access
    'membermouse', 'wishlist-member', 'lifterlms', 'masteriyo',
    'tutor-lms', 'wpcourseware',
    # Multi-language
    'qtranslate-xt', 'transposh-translation-filter', 'gtranslate',
    # Social and sharing
    'wp-to-twitter', 'addthis', 'shareaholic', 'revive-old-post',
    # Widgets and sidebars
    'black-studio-tinymce-widget', 'wp-widget-disable', 'q2w3-fixed-widget',
    'enhanced-text-widget',
    # Mail and SMTP
    'easy-wp-smtp', 'wp-smtp', 'gmail-smtp', 'fluentcrm', 'sendinblue', 'omnisend',
    # Redirect and migration
    'simple-301-redirects', 'safe-redirect-manager', 'wp-all-import',
    'wp-all-export', 'export-wp-page-to-static-html',
    # Comments and community
    'disqus-comment-system', 'wpDiscuz', 'thrive-comments', 'jetpack-comments',
    'intense-comment', 'comment-guestbook',
    # Maintenance and coming soon
    'seed-prod', 'underconstructionpage', 'ultimate-coming-soon-page',
    'wp-maintenance',
    # Schema and structured data
    'schema-and-structured-data-for-wp', 'wp-schema-pro',
    'schema-markup-rich-snippets', 'wpsso', 'all-in-one-schemaorg-rich-snippets',
    # Notifications and alerts
    'push-notification-for-wp', 'onesignal-free-web-push-notifications',
    'wp-web-push', 'pushassist', 'subscriber',
    # API and integration
    'wp-rest-api', 'json-api', 'graphql-api', 'wp-graphql',
    'zapier', 'uncanny-automator', 'automate-woo', 'wp-fusion',
    # Database and optimization
    'xtreme-one', 'better-delete-revision', 'wp-sweep', 'advanced-database-cleaner',
]

AGGRESSIVE_EXTRA_THEMES = [
    'betheme', 'bridge', 'divi-child', 'genesis', 'jupiter',
    'kallyas', 'layers', 'parent', 'porto', 'rehub',
    'salient', 'the7', 'theone', 'total', 'ultra',
    'uncode', 'x', 'zerif-lite', 'hestia', 'sydney',
    'colibri-wp', 'blocksy', 'kadence', 'neve',
]


class PluginThemeEnumerator:
    """
    WordPress plugin and theme detection with version extraction and CVE correlation.
    """

    def __init__(self, config=None, http_client=None):
        self.config = config or get_config()
        self.session = http_client
        self.vuln_db = get_vuln_db()

        if self.session is None:
            import requests as _req
            self.session = _req.Session()
            self.session.headers.update({'User-Agent': self.config.user_agent})
            logger.warning("No HTTP client provided, using non-rate-limited session")

        # Merge built-in list with config extras, extend for aggressive mode
        base_plugins = list(dict.fromkeys(COMMON_PLUGINS + getattr(self.config, 'wp_common_plugins', [])))
        base_themes = list(dict.fromkeys(COMMON_THEMES + getattr(self.config, 'wp_common_themes', [])))

        if getattr(self.config, 'scan_mode', 'safe') == 'aggressive':
            self.plugins_to_check = list(dict.fromkeys(base_plugins + AGGRESSIVE_EXTRA_PLUGINS))
            self.themes_to_check = list(dict.fromkeys(base_themes + AGGRESSIVE_EXTRA_THEMES))
        else:
            self.plugins_to_check = base_plugins
            self.themes_to_check = base_themes

    # ------------------------------------------------------------------
    # Main scan entry point
    # ------------------------------------------------------------------

    def scan(self, target: str) -> List[Dict]:
        """Run full plugin and theme enumeration with CVE correlation."""
        all_findings = []
        all_findings.extend(self.enumerate_plugins(target))
        all_findings.extend(self.enumerate_themes(target))
        return all_findings

    # ------------------------------------------------------------------
    # Plugin enumeration
    # ------------------------------------------------------------------

    def enumerate_plugins(self, target: str, max_check: Optional[int] = None) -> List[Dict]:
        """
        Enumerate WordPress plugins installed on the target.

        Steps:
        1. Parse homepage HTML to discover plugins and extract ?ver= versions
        2. Combine with built-in wordlist
        3. Check each candidate for existence (200/403)
        4. For found plugins, run enhanced version detection
        5. Query WPVulnerability.net for CVEs
        """
        max_check = max_check or self.config.wp_max_plugins_check

        # Step 1: Parse HTML for discovered plugins + asset-URL versions
        html_plugins, _ = self._parse_html_components(target)

        # Step 2: Combine lists (discovered first, they're higher confidence)
        candidates = list(dict.fromkeys(
            list(html_plugins.keys()) + self.plugins_to_check[:max_check]
        ))[:max_check]

        logger.info(
            f"Enumerating plugins (max: {max_check}, "
            f"{len(html_plugins)} discovered from HTML)"
        )
        logger.info(f"Checking {len(candidates)} plugins")

        # Step 3 & 4: Check existence + detect version concurrently
        found_plugins: List[Dict] = []
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {
                executor.submit(
                    self._check_plugin, target, slug, html_plugins.get(slug)
                ): slug
                for slug in candidates
            }
            for future in as_completed(futures):
                slug = futures[future]
                try:
                    result = future.result()
                    if result:
                        found_plugins.append(result)
                        ver = result.get('version') or 'unknown version'
                        logger.info(f"  Plugin found: {slug} {ver}")
                except Exception as e:
                    logger.debug(f"Plugin check error ({slug}): {e}")

        # Step 5: Build findings with CVE correlation
        return self._build_plugin_findings(found_plugins)

    def _check_plugin(
        self,
        target: str,
        slug: str,
        html_version: Optional[str] = None
    ) -> Optional[Dict]:
        """
        Check if a plugin exists and detect its version.

        Returns a dict with plugin metadata, or None if not found.
        """
        plugin_url = urljoin(target, f'/wp-content/plugins/{slug}/')
        try:
            resp = self.session.get(plugin_url, allow_redirects=False)
            if resp.status_code not in (200, 403):
                return None
        except Exception as e:
            logger.debug(f"Plugin existence check failed ({slug}): {e}")
            return None

        # Version detection — try methods in priority order
        version = (
            html_version
            or self._version_from_readme(target, 'plugin', slug)
            or self._version_from_changelog(target, 'plugin', slug)
            or self._version_from_php_header(target, slug)
        )

        # Latest version lookup (WordPress.org API — fast, cached)
        latest_version = None
        if version and getattr(self.config, 'vuln_db_enabled', True):
            try:
                latest_version = self.vuln_db.get_plugin_latest_version(slug)
            except Exception:
                pass

        return {
            'slug': slug,
            'path': plugin_url,
            'version': version,
            'latest_version': latest_version,
            'status_code': resp.status_code,
        }

    def _build_plugin_findings(self, found_plugins: List[Dict]) -> List[Dict]:
        """
        Build findings list from detected plugins, enriched with CVE data,
        latest version, and CVSS scores.
        """
        if not found_plugins:
            return []

        # Step A: Query CVEs for each plugin, collect unique CVE IDs
        plugin_data: List[tuple] = []
        all_cve_ids: List[str] = []

        for plugin in found_plugins:
            slug = plugin['slug']
            version = plugin.get('version')
            vulns = []
            if version and getattr(self.config, 'vuln_db_enabled', True):
                try:
                    vulns = self.vuln_db.get_plugin_vulns(slug, version)
                    for v in vulns:
                        for src in v.get('sources', []):
                            cid = src.get('id', '')
                            if cid.startswith('CVE-') and cid not in all_cve_ids:
                                all_cve_ids.append(cid)
                except Exception as e:
                    logger.debug(f"VulnDB query failed for {slug}: {e}")
            plugin_data.append((plugin, vulns))

        # Step B: Fetch CVSS for unique CVE IDs in parallel (max 10 to respect NVD rate limits)
        cvss_cache: Dict[str, Optional[float]] = {}
        cve_ids_to_fetch = all_cve_ids[:10]
        if cve_ids_to_fetch:
            logger.debug(f"Fetching CVSS scores for {len(cve_ids_to_fetch)} CVE(s) from NVD")
            with ThreadPoolExecutor(max_workers=3) as pool:
                futures = {
                    pool.submit(self.vuln_db.get_cvss_score, cve_id): cve_id
                    for cve_id in cve_ids_to_fetch
                }
                for future in as_completed(futures):
                    cve_id = futures[future]
                    try:
                        cvss_cache[cve_id] = future.result()
                    except Exception:
                        cvss_cache[cve_id] = None

        # Step C: Build findings
        findings = []
        vuln_count = 0

        for plugin, vulns in plugin_data:
            slug = plugin['slug']
            version = plugin.get('version')
            path = plugin['path']
            latest_version = plugin.get('latest_version')

            if vulns:
                vuln_count += 1
                findings.append(self._make_vulnerable_plugin_finding(
                    slug, version, path, vulns,
                    latest_version=latest_version,
                    cvss_cache=cvss_cache,
                ))
            else:
                findings.append(self._make_plugin_info_finding(slug, version, path))

        # Summary finding
        findings.append({
            'id': 'ARGUS-WP-011',
            'title': f'{len(found_plugins)} plugin(s) detected'
                     + (f', {vuln_count} with known CVEs' if vuln_count else ''),
            'severity': 'high' if vuln_count else 'info',
            'confidence': 'high',
            'description': (
                f"Found {len(found_plugins)} WordPress plugins installed. "
                + (f"{vuln_count} have known CVEs from WPVulnerability.net." if vuln_count else "")
            ),
            'recommendation': (
                'Review all plugins:\n'
                '- Update all plugins to their latest versions immediately\n'
                '- Remove unused plugins to reduce attack surface\n'
                '- Monitor security advisories for installed plugins\n'
                '- Use only plugins from the official WordPress.org repository'
            ),
        })

        return findings

    def _make_vulnerable_plugin_finding(
        self,
        slug: str,
        version: str,
        path: str,
        vulns: List[Dict],
        latest_version: Optional[str] = None,
        cvss_cache: Optional[Dict] = None,
    ) -> Dict:
        """Build a finding for a plugin with known CVEs."""
        cve_ids = self.vuln_db.extract_cve_ids(vulns)
        severity = self.vuln_db.get_severity_for_vulns(vulns)
        vuln_report = self.vuln_db.format_for_report(vulns, cvss_cache=cvss_cache)

        cve_label = f" ({', '.join(cve_ids[:3])}{'...' if len(cve_ids) > 3 else ''})" if cve_ids else ""
        title = f"Vulnerable plugin: {slug} v{version}{cve_label}"

        refs = [f"https://www.wpvulnerability.net/plugin/{slug}/"]
        for vid in cve_ids[:5]:
            refs.append(f"https://www.cve.org/CVERecord?id={vid}")
        refs.append(f"https://wordpress.org/plugins/{slug}/")

        update_note = (
            f"Update to {latest_version}" if latest_version else
            f"Check https://wordpress.org/plugins/{slug}/ for latest version"
        )

        finding = {
            'id': 'ARGUS-WP-012',
            'title': title,
            'severity': severity,
            'confidence': 'high',
            'description': (
                f"Plugin '{slug}' version {version} has {len(vulns)} known "
                f"vulnerability/vulnerabilities (source: WPVulnerability.net). "
                f"CVEs: {', '.join(cve_ids) if cve_ids else 'see references'}."
            ),
            'evidence': {
                'type': 'path',
                'value': path,
                'context': f"Version: {version} | CVEs: {len(cve_ids)} | Vulns: {len(vulns)}",
            },
            'recommendation': (
                f"1. {update_note} immediately\n"
                "2. Review CVE details in references for specific impact\n"
                "3. Consider temporary deactivation if update not immediately possible\n"
                f"4. Monitor https://www.wpvulnerability.net/plugin/{slug}/ for future advisories"
            ),
            'references': refs,
            'affected_component': f"{slug} {version}",
        }

        if cve_ids:
            finding['cve'] = cve_ids

        if latest_version:
            finding['latest_version'] = latest_version

        if vuln_report:
            finding['vulnerabilities'] = vuln_report

        return finding

    def _make_plugin_info_finding(
        self,
        slug: str,
        version: Optional[str],
        path: str
    ) -> Dict:
        """Build an informational finding for a detected (non-vulnerable) plugin."""
        ver_ctx = f"Version: {version}" if version else "Version: not detected"

        # Flag historically vulnerable plugins even without specific version CVEs
        historically_vuln = slug in {
            'slider-revolution', 'revslider', 'wp-file-manager', 'simple-file-list',
            'email-subscribers', 'wp-google-maps',
        }
        severity = 'medium' if historically_vuln else 'info'
        note = ' (historically vulnerable plugin — verify it is up to date)' if historically_vuln else ''

        return {
            'id': 'ARGUS-WP-010',
            'title': f"Plugin detected: {slug}{' v' + version if version else ''}{note}",
            'severity': severity,
            'confidence': 'high',
            'description': f"WordPress plugin '{slug}' is installed.{' ' + ver_ctx + '.' if version else ''}",
            'evidence': {
                'type': 'path',
                'value': path,
                'context': ver_ctx,
            },
            'recommendation': (
                f"1. Verify {slug} is necessary and actively maintained\n"
                "2. Update to latest version\n"
                "3. Remove if unused\n"
                f"4. Monitor: https://www.wpvulnerability.net/plugin/{slug}/"
            ),
            'references': [
                f"https://wordpress.org/plugins/{slug}/",
                f"https://www.wpvulnerability.net/plugin/{slug}/",
            ],
            'affected_component': f"{slug}{' ' + version if version else ''}",
        }

    # ------------------------------------------------------------------
    # Theme enumeration
    # ------------------------------------------------------------------

    def enumerate_themes(self, target: str, max_check: Optional[int] = None) -> List[Dict]:
        """
        Enumerate WordPress themes installed on the target.
        """
        max_check = max_check or self.config.wp_max_themes_check

        _, html_themes = self._parse_html_components(target)

        candidates = list(dict.fromkeys(
            list(html_themes.keys()) + self.themes_to_check[:max_check]
        ))[:max_check]

        logger.info(
            f"Enumerating themes (max: {max_check}, "
            f"{len(html_themes)} discovered from HTML)"
        )
        logger.info(f"Checking {len(candidates)} themes")

        found_themes: List[Dict] = []
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {
                executor.submit(
                    self._check_theme, target, slug, html_themes.get(slug)
                ): slug
                for slug in candidates
            }
            for future in as_completed(futures):
                slug = futures[future]
                try:
                    result = future.result()
                    if result:
                        found_themes.append(result)
                        ver = result.get('version') or ''
                        logger.info(f"  Theme found: {slug} {ver}")
                except Exception as e:
                    logger.debug(f"Theme check error ({slug}): {e}")

        return self._build_theme_findings(found_themes)

    def _check_theme(
        self,
        target: str,
        slug: str,
        html_version: Optional[str] = None
    ) -> Optional[Dict]:
        """Check if a theme exists and detect its version."""
        theme_url = urljoin(target, f'/wp-content/themes/{slug}/')
        try:
            resp = self.session.get(theme_url, allow_redirects=False)
            if resp.status_code not in (200, 403):
                return None
        except Exception as e:
            logger.debug(f"Theme existence check failed ({slug}): {e}")
            return None

        version = (
            html_version
            or self._version_from_style_css(target, slug)
            or self._version_from_changelog(target, 'theme', slug)
        )

        # Latest version lookup (WordPress.org API)
        latest_version = None
        if version and getattr(self.config, 'vuln_db_enabled', True):
            try:
                latest_version = self.vuln_db.get_theme_latest_version(slug)
            except Exception:
                pass

        return {
            'slug': slug,
            'path': theme_url,
            'version': version,
            'latest_version': latest_version,
            'status_code': resp.status_code,
        }

    def _build_theme_findings(self, found_themes: List[Dict]) -> List[Dict]:
        """Build findings for detected themes with CVE correlation, latest version, and CVSS."""
        if not found_themes:
            return []

        # Step A: Query CVEs, collect unique CVE IDs
        theme_data: List[tuple] = []
        all_cve_ids: List[str] = []

        for theme in found_themes:
            slug = theme['slug']
            version = theme.get('version')
            vulns = []
            if version and getattr(self.config, 'vuln_db_enabled', True):
                try:
                    vulns = self.vuln_db.get_theme_vulns(slug, version)
                    for v in vulns:
                        for src in v.get('sources', []):
                            cid = src.get('id', '')
                            if cid.startswith('CVE-') and cid not in all_cve_ids:
                                all_cve_ids.append(cid)
                except Exception as e:
                    logger.debug(f"VulnDB theme query failed for {slug}: {e}")
            theme_data.append((theme, vulns))

        # Step B: Fetch CVSS in parallel (max 10)
        cvss_cache: Dict[str, Optional[float]] = {}
        cve_ids_to_fetch = all_cve_ids[:10]
        if cve_ids_to_fetch:
            logger.debug(f"Fetching CVSS scores for {len(cve_ids_to_fetch)} theme CVE(s)")
            with ThreadPoolExecutor(max_workers=3) as pool:
                futures = {
                    pool.submit(self.vuln_db.get_cvss_score, cve_id): cve_id
                    for cve_id in cve_ids_to_fetch
                }
                for future in as_completed(futures):
                    cve_id = futures[future]
                    try:
                        cvss_cache[cve_id] = future.result()
                    except Exception:
                        cvss_cache[cve_id] = None

        # Step C: Build findings
        findings = []

        for theme, vulns in theme_data:
            slug = theme['slug']
            version = theme.get('version')
            path = theme['path']
            latest_version = theme.get('latest_version')

            if vulns:
                cve_ids = self.vuln_db.extract_cve_ids(vulns)
                severity = self.vuln_db.get_severity_for_vulns(vulns)
                vuln_report = self.vuln_db.format_for_report(vulns, cvss_cache=cvss_cache)

                refs = [f"https://www.wpvulnerability.net/theme/{slug}/"]
                for vid in cve_ids[:5]:
                    refs.append(f"https://www.cve.org/CVERecord?id={vid}")

                update_note = (
                    f"Update to {latest_version}" if latest_version else
                    f"Update {slug} to the latest version"
                )

                finding = {
                    'id': 'ARGUS-WP-022',
                    'title': f"Vulnerable theme: {slug} v{version} ({len(vulns)} CVEs)",
                    'severity': severity,
                    'confidence': 'high',
                    'description': (
                        f"Theme '{slug}' version {version} has {len(vulns)} known "
                        f"vulnerability/vulnerabilities."
                    ),
                    'evidence': {
                        'type': 'path',
                        'value': path,
                        'context': f"Version: {version} | CVEs: {len(cve_ids)}",
                    },
                    'recommendation': (
                        f"1. {update_note} immediately\n"
                        "2. Remove unused themes (keep only active + one backup)\n"
                        "3. Review CVE details in references\n"
                        f"4. Monitor: https://www.wpvulnerability.net/theme/{slug}/"
                    ),
                    'references': refs,
                    'affected_component': f"{slug} theme {version}",
                }
                if cve_ids:
                    finding['cve'] = cve_ids
                if latest_version:
                    finding['latest_version'] = latest_version
                if vuln_report:
                    finding['vulnerabilities'] = vuln_report
                findings.append(finding)
            else:
                findings.append({
                    'id': 'ARGUS-WP-020',
                    'title': f"Theme detected: {slug}{' v' + version if version else ''}",
                    'severity': 'info',
                    'confidence': 'high',
                    'description': f"WordPress theme '{slug}' is installed.",
                    'evidence': {
                        'type': 'path',
                        'value': path,
                        'context': f"Version: {version or 'not detected'}",
                    },
                    'recommendation': (
                        f"1. Update {slug} to latest version\n"
                        "2. Remove unused themes\n"
                        "3. Use child themes for customizations"
                    ),
                    'references': [
                        f"https://wordpress.org/themes/{slug}/",
                        f"https://www.wpvulnerability.net/theme/{slug}/",
                    ],
                    'affected_component': f"{slug} theme",
                })

        # Summary
        findings.append({
            'id': 'ARGUS-WP-021',
            'title': f'{len(found_themes)} theme(s) detected',
            'severity': 'info',
            'confidence': 'high',
            'description': f"Found {len(found_themes)} WordPress themes installed.",
            'recommendation': (
                'Keep only necessary themes installed and updated. '
                'Delete all unused themes.'
            ),
        })

        return findings

    # ------------------------------------------------------------------
    # Version detection methods
    # ------------------------------------------------------------------

    def _parse_html_components(
        self,
        target: str
    ) -> Tuple[Dict[str, Optional[str]], Dict[str, Optional[str]]]:
        """
        Fetch the target homepage and extract plugin/theme slugs + versions
        from asset URLs in one pass.

        Returns: (plugins_dict, themes_dict) → {slug: version_or_None}
        """
        plugins: Dict[str, Optional[str]] = {}
        themes: Dict[str, Optional[str]] = {}

        try:
            resp = self.session.get(target)
            if resp.status_code != 200:
                return plugins, themes
            html = resp.text
        except Exception as e:
            logger.debug(f"HTML parse failed for {target}: {e}")
            return plugins, themes

        # Single regex pass: captures slug and optional ?ver= from any asset URL
        for m in re.finditer(
            r'/wp-content/(plugins|themes)/([a-z0-9][a-z0-9\-_]*)/([^\s"\'<>]*)',
            html,
            re.IGNORECASE,
        ):
            kind = m.group(1).lower()
            slug = m.group(2).lower()
            rest = m.group(3)

            ver_m = re.search(r'[?&]ver=(\d+\.\d+(?:\.\d+)?)', rest)
            version = ver_m.group(1) if ver_m else None

            target_dict = plugins if kind == 'plugins' else themes
            # Keep version if we already have the slug but no version yet
            if slug not in target_dict or (version and not target_dict[slug]):
                target_dict[slug] = version

        return plugins, themes

    def _version_from_readme(
        self,
        target: str,
        kind: str,
        slug: str
    ) -> Optional[str]:
        """
        Extract version from readme.txt (plugins) or readme.md.
        Looks for 'Stable tag: X.Y.Z'.
        """
        base = f'/wp-content/{kind}s/{slug}/'
        for filename in ('readme.txt', 'README.txt', 'readme.md'):
            url = urljoin(target, base + filename)
            try:
                resp = self.session.get(url)
                if resp.status_code == 200:
                    m = re.search(
                        r'Stable\s+tag\s*:\s*(\d+\.\d+(?:\.\d+)?)',
                        resp.text,
                        re.IGNORECASE,
                    )
                    if m:
                        return m.group(1)
            except Exception:
                pass
        return None

    def _version_from_changelog(
        self,
        target: str,
        kind: str,
        slug: str
    ) -> Optional[str]:
        """
        Extract version from changelog.txt — first version number in the file.
        """
        url = urljoin(target, f'/wp-content/{kind}s/{slug}/changelog.txt')
        try:
            resp = self.session.get(url)
            if resp.status_code == 200:
                m = re.search(
                    r'(?:^|\n)\s*(?:=+|#+|v\.?)\s*v?(\d+\.\d+(?:\.\d+)?)',
                    resp.text,
                    re.IGNORECASE,
                )
                if m:
                    return m.group(1)
        except Exception:
            pass
        return None

    def _version_from_php_header(
        self,
        target: str,
        slug: str
    ) -> Optional[str]:
        """
        Extract version from the plugin's main PHP file header comment.
        Tries {slug}.php and index.php.
        """
        for filename in (f'{slug}.php', 'index.php'):
            url = urljoin(target, f'/wp-content/plugins/{slug}/{filename}')
            try:
                resp = self.session.get(url)
                if resp.status_code == 200:
                    # WordPress plugin header: "Version: X.Y.Z"
                    m = re.search(
                        r'^[ \t]*\*?\s*Version\s*:\s*(\d+\.\d+(?:\.\d+)?)',
                        resp.text,
                        re.IGNORECASE | re.MULTILINE,
                    )
                    if m:
                        return m.group(1)
            except Exception:
                pass
        return None

    def _version_from_style_css(
        self,
        target: str,
        slug: str
    ) -> Optional[str]:
        """
        Extract theme version from style.css header comment.
        """
        url = urljoin(target, f'/wp-content/themes/{slug}/style.css')
        try:
            resp = self.session.get(url)
            if resp.status_code == 200:
                m = re.search(
                    r'^[ \t]*\*?\s*Version\s*:\s*(\d+\.\d+(?:\.\d+)?)',
                    resp.text,
                    re.IGNORECASE | re.MULTILINE,
                )
                if m:
                    return m.group(1)
        except Exception:
            pass
        return None
