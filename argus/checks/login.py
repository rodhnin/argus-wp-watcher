"""
WordPress Login Security Checker

Checks for login page security measures including brute force protection,
two-factor authentication, CAPTCHA, and open registration.

Only runs in aggressive mode (requires consent).
Finding IDs: ARGUS-WP-070 to ARGUS-WP-074

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

from typing import List, Dict, Optional
from urllib.parse import urljoin

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


class LoginSecurityChecker:
    """
    Analyzes WordPress login page security hardening.
    Tests brute force protection, 2FA, CAPTCHA, and registration status.
    """

    PASSWORD_POLICY_PLUGIN_SLUGS = [
        'password-policy-manager',
        'force-strong-passwords',
        'passwords-evolved',
        'wp-password-policy-manager',
        'password-strength-requirements',
        'melapress-login-security',     # has password policy module
        'wp-cerber',                    # has password rules
        'ithemes-security',             # iThemes/Solid Security has password enforcement
        'solid-security',               # same plugin new name
        'better-wp-security',           # older name
    ]

    # Strings that appear in the login page *HTML* when certain 2FA plugins
    # inject a visible field or script into the initial login form.
    # Note: most modern 2FA plugins work post-login and do NOT inject here —
    #       so we also probe plugin directories below (TWO_FACTOR_PLUGIN_SLUGS).
    TWO_FACTOR_INDICATORS = [
        'two_factor_nonce',           # Official "Two Factor" plugin (pre-6.8)
        'wp2fa_nonce', 'wp-2fa',      # WP 2FA plugin (injects nonce in some configs)
        'wordfence_ls_',              # Wordfence Login Security
        'miniorange-2fa', 'mo_2fa',   # miniOrange (some versions inject field)
        'duo_security', 'duo-iframe', # Duo Security
        'google-authenticator',       # Google Authenticator plugin
        'tfa_code', 'otp_code',       # Various OTP field names
        'mfa_code', 'wc-2fa',         # WooCommerce 2FA
        'melapress-login-security',   # Melapress Login Security
    ]

    # Known 2FA plugin slugs — we probe their readme.txt to detect presence
    # even when they don't inject indicators into the initial login page.
    TWO_FACTOR_PLUGIN_SLUGS = [
        'wp-2fa',
        'two-factor',
        'miniorange-2-factor-authentication',
        'wordfence',                          # Includes Login Security / 2FA
        'wordfence-login-security',
        'google-authenticator',
        'duo-wordpress',
        'shield-security',
        'better-wp-security',                 # iThemes / Solid Security
        'all-in-one-wp-security-and-firewall',
        'melapress-login-security',
        'two-factor-authentication',
        'really-simple-ssl',                  # Has 2FA module
    ]

    CAPTCHA_INDICATORS = [
        'g-recaptcha', 'recaptcha/api.js', 'hcaptcha', 'cf-turnstile',
        'really-simple-captcha', 'math_captcha', 'bws_captcha',
        'captcha', 'turnstile', 'challenge',
    ]

    BRUTE_FORCE_INDICATORS = [
        'wordfence', 'login_limit', 'login-lockdown', 'loginizer',
        'too many failed', 'account locked', 'blocked due to',
        'cerber-shield', 'limit_login', 'slow down', 'attempts exceeded',
        'temporarily locked', 'rate limit',
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
        Run login security checks. Designed for aggressive mode only.

        Args:
            target: Target URL

        Returns:
            List of findings (ARGUS-WP-070 to ARGUS-WP-074)
        """
        findings = []
        login_url = urljoin(target, '/wp-login.php')

        logger.info("Running login security checks (aggressive mode)")

        # Step 1: Fetch login page
        login_page = self._fetch_login_page(login_url)

        if login_page is None:
            findings.append({
                'id': 'ARGUS-WP-070',
                'title': 'WordPress login page not accessible',
                'severity': 'info',
                'confidence': 'medium',
                'description': 'wp-login.php is blocked or returns a non-standard response. This may indicate URL renaming or IP restriction — a good security practice.',
                'recommendation': 'If login URL was renamed using a plugin (e.g. WPS Hide Login), ensure the custom URL is also protected.',
            })
            return findings

        # Step 2: Login page is accessible
        findings.append({
            'id': 'ARGUS-WP-070',
            'title': 'WordPress login page publicly accessible',
            'severity': 'info',
            'confidence': 'high',
            'description': 'wp-login.php is accessible from the internet. This is standard but increases brute force attack surface.',
            'evidence': {'type': 'url', 'value': login_url, 'context': 'HTTP 200, WordPress login form found'},
            'recommendation': (
                'Consider restricting wp-login.php by IP (via .htaccess or server config) or '
                'rename the login URL using a plugin like WPS Hide Login.'
            ),
            'references': ['https://wordpress.org/documentation/article/hardening-wordpress/'],
        })

        # Step 3: 2FA detection
        # Two strategies:
        #   a) Login page HTML — works when plugin injects directly into the form
        #   b) Plugin directory probe — works for post-login 2FA plugins that leave
        #      no trace in the initial login page HTML (the common modern pattern)
        html_2fa = any(ind.lower() in login_page.lower() for ind in self.TWO_FACTOR_INDICATORS)
        plugin_2fa, plugin_name = self._probe_2fa_plugins(target)
        has_2fa = html_2fa or plugin_2fa

        if has_2fa:
            if plugin_2fa:
                source = f'plugin found: {plugin_name}'
                tfa_desc = (
                    f'A 2FA plugin is installed on this server ({plugin_name}). '
                    'If the plugin is active and configured for admin accounts, login requires a second factor. '
                    'Verify the plugin is active and enforced for all privileged roles.'
                )
            else:
                source = 'login page HTML indicator'
                tfa_desc = 'Two-factor authentication indicators detected on the login page.'
            tfa_ctx = source
        else:
            tfa_desc = (
                'No 2FA/MFA plugin was detected (login page checked + known plugin directories probed). '
                'Admin accounts appear to be protected only by password.'
            )
            tfa_ctx = 'login page + plugin directories probed — no 2FA found'

        findings.append({
            'id': 'ARGUS-WP-071',
            'title': '2FA/MFA plugin installed' if has_2fa else 'No 2FA/MFA detected',
            'severity': 'info' if has_2fa else 'medium',
            'confidence': 'high' if has_2fa else 'medium',
            'description': tfa_desc,
            'evidence': {'type': 'body', 'value': login_url, 'context': tfa_ctx},
            'recommendation': (
                'Good — ensure the 2FA plugin is active and enforced for all admin and editor roles. '
                'Verify configuration in the plugin settings.'
                if has_2fa else
                'Enable 2FA for all privileged accounts. Recommended: WP 2FA, Wordfence Login Security, or miniOrange 2FA.'
            ),
            'references': ['https://wordpress.org/plugins/wp-2fa/'],
        })

        # Step 4: CAPTCHA detection
        has_captcha = any(ind.lower() in login_page.lower() for ind in self.CAPTCHA_INDICATORS)
        findings.append({
            'id': 'ARGUS-WP-072',
            'title': 'CAPTCHA present on login page' if has_captcha else 'No CAPTCHA on login page',
            'severity': 'info' if has_captcha else 'low',
            'confidence': 'medium',
            'description': (
                'CAPTCHA is active, helping prevent automated login attempts.'
                if has_captcha else
                'No CAPTCHA detected on the login page, making it easier for bots to attempt logins.'
            ),
            'evidence': {'type': 'body', 'value': login_url, 'context': 'CAPTCHA indicators: ' + ('present' if has_captcha else 'absent')},
            'recommendation': (
                'Good — CAPTCHA is an effective first line of defence against bots.'
                if has_captcha else
                'Add CAPTCHA to the login page. reCAPTCHA v3 or Cloudflare Turnstile have minimal UX impact.'
            ),
        })

        # Step 5: Brute force protection (single controlled probe)
        bf = self._check_brute_force(login_url)
        findings.append({
            'id': 'ARGUS-WP-073',
            'title': 'Brute force protection detected' if bf['protected'] else 'No brute force protection detected',
            'severity': 'info' if bf['protected'] else 'high',
            'confidence': bf['confidence'],
            'description': bf['description'],
            'evidence': {'type': 'body', 'value': login_url, 'context': bf.get('context', '')},
            'recommendation': (
                'Good — ensure lockout thresholds are set to 3-5 attempts and durations are at least 15 minutes.'
                if bf['protected'] else
                'Implement brute force protection:\n'
                '1. Install Loginizer, Login LockDown, or Wordfence\n'
                '2. Limit to 3-5 login attempts before lockout\n'
                '3. Set lockout duration to 15-30 minutes minimum\n'
                '4. Send email alerts on lockout events\n'
                '5. Consider IP allowlisting for wp-login.php'
            ),
            'references': [
                'https://wordpress.org/plugins/loginizer/',
                'https://owasp.org/www-community/attacks/Brute_force_attack',
            ],
        })

        # Step 6: Open registration
        reg = self._check_registration(target)
        if reg:
            findings.append(reg)

        # Step 7: Password policy
        pw_policy = self._check_password_policy(target, login_page)
        findings.append(pw_policy)

        return findings

    def _probe_2fa_plugins(self, target: str):
        """
        Check if known 2FA plugins are installed by probing their readme.txt.

        Most 2FA plugins work post-login and leave no trace on the initial
        wp-login.php page. This probes /wp-content/plugins/{slug}/readme.txt
        for each known 2FA plugin.

        Returns:
            (True, plugin_name) if a 2FA plugin is found, else (False, '')
        """
        for slug in self.TWO_FACTOR_PLUGIN_SLUGS:
            url = urljoin(target, f'/wp-content/plugins/{slug}/readme.txt')
            try:
                resp = self.session.get(url, allow_redirects=False)
                if resp.status_code == 200 and len(resp.text) > 50:
                    logger.info(f"2FA plugin detected via plugin probe: {slug}")
                    return True, slug
            except Exception:
                pass
        return False, ''

    def _fetch_login_page(self, login_url: str) -> Optional[str]:
        try:
            resp = self.session.get(login_url, allow_redirects=True)
            if resp.status_code == 200 and 'user_login' in resp.text:
                return resp.text
        except Exception as e:
            logger.debug(f"Login page fetch failed: {e}")
        return None

    def _check_brute_force(self, login_url: str) -> Dict:
        """Send one clearly-fake login attempt and inspect the response."""
        try:
            resp = self.session.post(login_url, data={
                'log': 'argus_probe_not_a_real_user_xyz',
                'pwd': 'argus_probe_not_a_real_pass_xyz',
                'wp-submit': 'Log In',
                'redirect_to': '/wp-admin/',
                'testcookie': '1',
            }, allow_redirects=True)

            text_lower = resp.text.lower()

            if any(ind in text_lower for ind in self.BRUTE_FORCE_INDICATORS):
                return {
                    'protected': True,
                    'confidence': 'medium',
                    'description': 'A brute force protection mechanism responded to the login probe.',
                    'context': 'Protection triggered after single login attempt',
                }

            if 'invalid username' in text_lower or 'the password you entered' in text_lower:
                return {
                    'protected': False,
                    'confidence': 'medium',
                    'description': (
                        'Login page returns verbose error messages differentiating invalid username from wrong password. '
                        'No lockout or rate limiting triggered after one probe attempt.'
                    ),
                    'context': 'Standard WP login error — no brute force protection detected',
                }

            return {
                'protected': False,
                'confidence': 'low',
                'description': 'Could not determine brute force protection status from login probe.',
                'context': f'HTTP {resp.status_code}',
            }

        except Exception as e:
            logger.debug(f"Brute force check failed: {e}")
            return {
                'protected': False,
                'confidence': 'low',
                'description': f'Brute force probe request failed: {e}',
                'context': 'Request error',
            }

    def _check_password_policy(self, target: str, login_page: str) -> Dict:
        """
        Check if WordPress enforces a password policy.

        Two signals:
          a) Dedicated password policy plugin installed (probe readme.txt)
          b) Login/registration page contains strength meter references

        Finding: ARGUS-WP-075
        """
        # Signal A: known password policy plugins
        plugin_found = False
        plugin_name = ''
        for slug in self.PASSWORD_POLICY_PLUGIN_SLUGS:
            url = urljoin(target, f'/wp-content/plugins/{slug}/readme.txt')
            try:
                resp = self.session.get(url, allow_redirects=False)
                if resp.status_code == 200 and len(resp.text) > 50:
                    plugin_found = True
                    plugin_name = slug
                    logger.info(f"Password policy plugin detected: {slug}")
                    break
            except Exception:
                pass

        # Signal B: WP default password strength meter in login or registration page
        strength_meter = (
            'wp-password-strength-meter' in login_page or
            'password-strength' in login_page.lower() or
            'strength_indicator' in login_page
        )

        if plugin_found:
            return {
                'id': 'ARGUS-WP-075',
                'title': f'Password policy plugin installed: {plugin_name}',
                'severity': 'info',
                'confidence': 'high',
                'description': (
                    f'A dedicated password policy plugin is installed ({plugin_name}). '
                    'If configured correctly, it enforces minimum password strength for all users.'
                ),
                'evidence': {'type': 'body', 'value': urljoin(target, f'/wp-content/plugins/{plugin_name}/readme.txt'), 'context': 'Plugin readme.txt found'},
                'recommendation': (
                    'Good — verify the plugin is active and enforced for all roles including admin. '
                    'Set minimum length ≥12 chars, require uppercase, number, and special character.'
                ),
                'references': ['https://wordpress.org/plugins/password-policy-manager/'],
            }
        elif strength_meter:
            return {
                'id': 'ARGUS-WP-075',
                'title': 'WordPress default password strength indicator present',
                'severity': 'low',
                'confidence': 'medium',
                'description': (
                    'WordPress shows a password strength meter on the registration/profile page '
                    'but does NOT enforce a minimum policy by default — users can bypass the indicator '
                    'and set any password including "password" or "123456".'
                ),
                'evidence': {'type': 'body', 'value': urljoin(target, '/wp-login.php'), 'context': 'Strength meter indicator found in page source'},
                'recommendation': (
                    'Install a dedicated password policy plugin to enforce minimum requirements:\n'
                    '1. Password Policy Manager (free) — https://wordpress.org/plugins/password-policy-manager/\n'
                    '2. Force Strong Passwords — https://wordpress.org/plugins/force-strong-passwords/\n'
                    '3. iThemes Security — includes password enforcement module'
                ),
                'references': ['https://wordpress.org/plugins/password-policy-manager/'],
            }
        else:
            return {
                'id': 'ARGUS-WP-075',
                'title': 'No password policy enforcement detected',
                'severity': 'medium',
                'confidence': 'medium',
                'description': (
                    'No password policy plugin was found and WordPress\'s default strength meter '
                    'is advisory only. Users can set weak passwords (e.g., "password", "123456"). '
                    'This significantly increases the risk of account takeover via credential stuffing.'
                ),
                'evidence': {'type': 'body', 'value': urljoin(target, '/wp-login.php'), 'context': 'No policy plugin found — login page + 10 known policy plugin dirs probed'},
                'recommendation': (
                    'Install and configure a password policy plugin:\n'
                    '1. Password Policy Manager — https://wordpress.org/plugins/password-policy-manager/\n'
                    '2. Force Strong Passwords — https://wordpress.org/plugins/force-strong-passwords/\n'
                    '3. Set minimum 12 chars, mixed case, number, and special character\n'
                    '4. Enable "Enforce policy on existing users" to force password reset'
                ),
                'references': [
                    'https://wordpress.org/plugins/password-policy-manager/',
                    'https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks',
                ],
            }

    def _check_registration(self, target: str) -> Optional[Dict]:
        """Check if open user registration is enabled."""
        try:
            reg_url = urljoin(target, '/wp-login.php?action=register')
            resp = self.session.get(reg_url, allow_redirects=True)

            if resp.status_code == 200 and 'registration-form' in resp.text:
                return {
                    'id': 'ARGUS-WP-074',
                    'title': 'Open user registration is enabled',
                    'severity': 'medium',
                    'confidence': 'high',
                    'description': (
                        'WordPress open registration is active — any visitor can create an account. '
                        'This increases attack surface and may enable privilege escalation if role settings are weak.'
                    ),
                    'evidence': {'type': 'url', 'value': reg_url, 'context': 'HTTP 200, registration form present'},
                    'recommendation': (
                        '1. Disable in Settings → General → Membership (uncheck "Anyone can register")\n'
                        '2. If registration is required, enforce email confirmation\n'
                        '3. Set new user default role to Subscriber only\n'
                        '4. Add CAPTCHA to the registration form\n'
                        '5. Monitor new user registrations for spam accounts'
                    ),
                    'references': ['https://wordpress.org/documentation/article/hardening-wordpress/'],
                }
        except Exception as e:
            logger.debug(f"Registration check failed: {e}")
        return None
