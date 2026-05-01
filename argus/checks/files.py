"""
Sensitive Files Detection Module

Checks for:
- wp-config.php and backups
- debug.log
- Database backups (.sql, .zip)
- Git repository exposure
- Environment files (.env)
- Default WordPress files (readme.html, license.txt)
- XML-RPC file

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

from typing import List, Dict, Optional
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


class SensitiveFilesChecker:
    """
    Detects exposed sensitive files.
    """
    
    # Additional paths checked only in aggressive mode
    AGGRESSIVE_PATHS = [
        # wp-config variants
        'wp-config.php.swp', 'wp-config.php.1', 'wp-config.php.2',
        'wp-config.php.bkp', 'wp-config.php.tmp', 'wp-config-backup.php',
        'wp-config-local.php', 'wp-config.txt', 'wp-config.json',
        # DB dumps (extended names)
        'db_backup.sql', 'mysql_backup.sql', 'site_backup.sql',
        'wordpress_backup.sql', 'wpdb.sql', 'backup-db.sql',
        'db.zip', 'db_backup.zip', 'backup.tgz', 'site.tar.gz',
        # Timestamp-based backups
        'backup-2020.sql', 'backup-2021.sql', 'backup-2022.sql',
        'backup-2023.sql', 'backup-2024.sql', 'backup-2025.sql',
        'backup-2020.zip', 'backup-2021.zip', 'backup-2022.zip',
        'backup-2023.zip', 'backup-2024.zip',
        'db-2022.sql', 'db-2023.sql', 'db-2024.sql',
        'wp-2023.zip', 'wp-2024.zip', 'wordpress-2024.zip',
        # Git extended
        '.git/config', '.git/index', '.git/COMMIT_EDITMSG',
        '.git/logs/HEAD', '.git/refs/heads/main', '.git/refs/heads/master',
        '.git/packed-refs', '.git/FETCH_HEAD',
        # SVN / Mercurial
        '.svn/entries', '.svn/wc.db', '.hg/requires', '.hg/hgrc',
        # Dev files
        'composer.json', 'composer.lock',
        'package.json', 'package-lock.json', 'yarn.lock',
        '.env.local', '.env.development', '.env.production',
        '.env.staging', '.env.example', '.env.sample', '.env.bak',
        # WordPress specific
        'wp-content/error.log', 'wp-content/uploads/.htaccess',
        'wp-cron.php', 'wp-admin/install.php',
        'wp-content/plugins/error.log', 'wp-content/themes/error.log',
        'wp-content/backup/', 'wp-content/backups/',
        'wp-content/updraft/', 'wp-content/ai1wm-backups/',
        'wp-content/w3tc-config/master.php',
        'wp-content/cache/config.php',
        # Editor / IDE artifacts
        '.idea/workspace.xml', '.vscode/settings.json',
        '.project', '.DS_Store', 'Thumbs.db',
        # Log files
        'error.log', 'access.log', 'errors.log',
        'php_error.log', 'php-error.log', 'app.log',
        # Server info / test files
        'phpinfo.php', 'info.php', 'test.php', 'php-info.php',
        'old.php', 'temp.php', 'check.php',
        # Server config
        '.htpasswd', 'web.config',
        # Admin directories (check accessibility)
        'admin/', 'backend/', 'manage/', 'control/',
        'phpmyadmin/', 'pma/', 'myadmin/', 'dbadmin/',
        # Old/staging directories
        'old/', 'backup/', 'bak/', 'backups/', 'temp/', 'tmp/',
        '_old/', '_backup/', 'old-site/', 'old_site/', 'staging/',
        # WP backup plugin artifacts
        'wp-snapshots/', 'wpb/', 'backwpup/',
        # Keys and certs (should never be in webroot)
        'server.key', 'certificate.pem', 'private.key',
        # Misc WordPress
        'wp-register.php', 'xmlrpc.php.bak',
        'sitemap.xml', 'robots.txt',
        'wp-content/debug-2.log', 'wp-content/php-error.log',
        # Extended backup naming patterns
        'wp-config.php.3', 'wp-config_backup.php', 'wp-config.bkp', 'wp-config.copy',
        '_wp-config.php', 'wp-config.php_', 'Config.php', 'config.php.bak',
        'wp-config.php.20230101', 'wp-config.php.20231001', 'wp-config.php.20240101',
        'wp-config.php.20240601', 'wp-config.php.20241001', 'wp-config.php.20250101',
        # Database backups extended
        'database.sql.gz', 'database.sql.zip', 'database.tar.gz',
        'db-backup.sql', 'dbdump.sql', 'mysqldump.sql',
        'wordpress.sql', 'site.sql', 'backup.tar', 'backup.tar.gz', 'backup.zip',
        'site_backup.zip', 'site-backup.zip', 'www.zip', 'html.zip',
        'files.zip', 'upload.zip', 'media.zip',
        # PHP info and debug
        'debug.php', 'phptest.php', 'wp-test.php', 'status.php', 'health.php',
        'ping.php', 'diagnostic.php',
        # Server configuration exposed
        'nginx.conf', '.nginx.conf', 'apache.conf', '.htaccess.bak',
        '.htaccess.old', 'httpd.conf', '.user.ini', 'php.ini', 'php.ini.bak',
        # WordPress specific
        'wp-content/debug.log', 'wp-content/uploads/debug.log',
        'wp-content/upgrade/', 'wp-content/cache/',
        'wp-admin/setup-config.php',
        'wp-activate.php', 'wp-signup.php',
        'xmlrpc.php', 'wp-trackback.php',
        # Development artifacts
        'Makefile', 'Gruntfile.js', 'Gulpfile.js', 'webpack.config.js',
        '.babelrc', '.eslintrc', '.eslintrc.json', '.prettierrc',
        'tsconfig.json', 'jest.config.js',
        'desktop.ini', '.editorconfig', '.stylelintrc',
        # Git extended
        '.git/refs/heads/develop',
        '.gitmodules', '.gitattributes', '.gitkeep',
        # Docker and CI/CD
        'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
        '.travis.yml', '.circleci/config.yml', 'Jenkinsfile',
        '.github/workflows/deploy.yml',
        'deploy.sh', 'install.sh', 'setup.sh', 'update.sh',
        # Logs extended
        'error_log', 'access_log', 'wp-debug.log', 'debug.log',
        'laravel.log', 'application.log', 'server.log',
        # Backup plugin artifacts extended
        'wp-content/backup-db/', 'wp-content/wphb-cache/',
        'wp-content/w3tc-config/', 'wp-content/et-cache/', 'wp-content/cache/minify/',
        # Old/archive directories
        'archive/', 'archives/', 'test/', 'testing/', 'dev/', 'development/',
        'beta/', 'alpha/', 'demo/', '_archive/', '_test/',
        # Version control markers
        'CVS/', 'CVS/Entries', 'CVS/Repository',
        '.bzr/', '.bzr/branch-format',
        # Composer/NPM artifacts
        'vendor/autoload.php', 'vendor/composer/installed.json',
        'node_modules/.package-lock.json',
        # Old WordPress core files that should be removed (real WP files from older versions)
        'wp-app.php', 'wp-atom.php', 'wp-rdf.php', 'wp-rss.php', 'wp-rss2.php',
        'wp-feed.php', 'wp-commentsrss2.php', 'wp-links-opml.php',
        # Database management tools (found exposed in real servers)
        'adminer.php', 'adminer-4.8.1.php', 'adminer-4.7.9.php',
        'phpmyadmin/index.php', 'phpMyAdmin/index.php', 'phpmyadmin/setup/index.php',
        'db.php', 'database.php', 'sql.php',
        # Webshell filenames (scanner checks for their presence — high value)
        'shell.php', 'cmd.php', 'exec.php', 'c99.php', 'r57.php', 'b374k.php',
        'wso.php', 'alfa.php', 'filemanager.php', 'upload.php', 'uploads.php',
        # Credential/secret files
        'credentials.json', 'credentials.xml', 'secrets.json', 'secrets.yaml',
        'sftp-config.json', 'auth.json', '.npmrc', '.netrc', '.gitconfig',
        '.aws/credentials', '.composer/auth.json', 'config.yaml', 'config.yml',
        # Cloud and IaC
        'terraform.tfstate', 'terraform.tfvars', 'Vagrantfile', 'ansible.cfg',
        '.gitlab-ci.yml', 'bitbucket-pipelines.yml', 'azure-pipelines.yml',
        'serverless.yml', 'serverless.yaml', 'cloudbuild.yaml',
        # SSH keys (should NEVER be in webroot)
        '.ssh/id_rsa', '.ssh/id_rsa.pub', '.ssh/known_hosts', '.ssh/authorized_keys',
        # npm/yarn artifacts
        'yarn-error.log', 'npm-debug.log', 'lerna.json', '.nvmrc',
        # WordPress uploads — plugin-specific exposed directories
        'wp-content/uploads/gravity_forms/', 'wp-content/uploads/wpcf7_uploads/',
        'wp-content/uploads/formidable/', 'wp-content/uploads/ninja-forms/',
        'wp-content/uploads/elementor/', 'wp-content/uploads/wpml/',
        'wp-content/uploads/backup/', 'wp-content/uploads/wpforms/',
        'wp-content/uploads/fl-builder/', 'wp-content/uploads/ngg/',
        'wp-content/uploads/avada/', 'wp-content/uploads/acf/',
        # Backup plugin directories (not already in list)
        'wp-content/snapshots/', 'wp-content/pb_backupbuddy/',
        'wp-content/migrate-guru/', 'wp-content/simple-backup/',
        'wp-content/blogvault-real-time-backup/', 'wp-content/ewww/',
        'wp-content/downloads/', 'wp-content/ngg/dynamic/',
        # More timestamp-based backups (2025-2026)
        'backup-2026.sql', 'backup-2026.zip', 'db-2025.sql', 'db-2026.sql',
        'wp-2025.zip', 'wp-2026.zip', 'wp-config.php.202412', 'wp-config.php.202501',
        # More DB dump names
        'mysql-backup.sql', 'mysql-dump.sql', 'database-dump.sql', 'sqldump.sql',
        'full-backup.sql', 'full_backup.sql', 'wpdump.sql', 'db.tar.gz',
        # More backup archives
        'public_html.tar.gz', 'httpdocs.tar.gz', 'home.tar.gz',
        'backup.tar.bz2', 'db.tar.bz2', 'site.tar.bz2',
        # WordPress REST/JSON API disclosure
        'wp-json/wp/v2/users', 'wp-json/wp/v2/posts', 'wp-json/',
        # Hosting panel artifacts
        'installlog.txt', 'cpanel_backups/', 'softaculous_backup/', '.cpanel.yml',
        # More server config variants
        '.htaccess.backup', '.htaccess_bak', 'httpd.conf.bak', 'nginx.conf.bak',
        'apache.conf.bak', '.htpasswd.bak', 'vhosts.conf', 'config.ini', 'config.cfg',
        # PHP build/tool files
        'composer-setup.php', 'install-wp-tests.sh', 'phpunit.xml',
        'phpstan.neon', 'psalm.xml', 'rector.php', '.phpunit.result.cache',
        # Additional credential/data files
        'app.json', 'app.config', 'settings.json', 'appsettings.json',
        'appsettings.Development.json', 'appsettings.Production.json',
        # WP plugin-specific exposed paths
        'wp-content/plugins/wp-file-manager/lib/php/',
        'wp-content/plugins/all-in-one-wp-migration/storage/',
        'wp-content/plugins/updraftplus/debug.log',
        'wp-content/plugins/duplicator/build/',
        # More log files
        'cron.log', 'mail.log', 'ftp.log', 'smtp.log',
        'install.log', 'wp-cron.log',
        # More archive naming patterns
        'database-backup.zip', 'database-backup.tar.gz',
        'www-backup.zip', 'www-data.zip', 'htdocs.zip',
    ]

    # Directories checked via HEAD request in aggressive mode (directory brute-force)
    BRUTE_FORCE_DIRS = [
        'admin/', 'administrator/', 'wp-admin/',
        'backup/', 'backups/', 'old/', 'archive/', 'temp/', 'tmp/',
        'test/', 'testing/', 'dev/', 'development/', 'staging/', 'beta/',
        'uploads/', 'files/', 'media/', 'images/', 'img/', 'assets/',
        'cgi-bin/', 'scripts/', 'bin/', 'tools/', 'util/', 'utils/',
        'api/', 'rest/', 'v1/', 'v2/', 'console/', 'dashboard/',
        '2023/', '2024/', '2025/', 'new/', 'public/',
    ]

    # Additional backup patterns to check
    BACKUP_PATTERNS = [
        # wp-config backups
        'wp-config.php.bak', 'wp-config.php~', 'wp-config.php.old',
        'wp-config.php.save', 'wp-config.php.swp', 'wp-config.php.txt',
        'wp-config.bak', 'wp-config.old',

        # Database dumps (common names)
        'backup.sql', 'database.sql', 'db.sql', 'dump.sql',
        'mysql.sql', 'wordpress.sql', 'wp.sql', 'site.sql',
        'backup.zip', 'database.zip', 'wp-backup.zip',
        'backup.tar.gz', 'backup.tar',

        # Other sensitive backups
        '.htaccess.bak', '.htaccess~', '.htaccess.old',
        'wp-content.zip', 'wp-content.tar.gz',

        # WordPress config variants (real backup naming conventions)
        'wp-config-local.php', 'wp-config.php.orig', 'wp-config.php.dist',
        'local-config.php', 'wp-config-dev.php', 'wp-config-staging.php',
        'wp-config-prod.php', 'wp-config.inc', 'wp-config.php.ORIG',
        # WordPress core info disclosure
        'wp-includes/version.php', 'wp-admin/upgrade.php',
        # Server configuration (always check in safe mode — high severity if exposed)
        '.htaccess', 'web.config', '.user.ini', 'php.ini', 'config.php',
        # WP-CLI and tool configs
        'wp-cli.yml', 'wp-cli.local.yml',
        # More database dump names
        'db-backup.sql', 'mysql_backup.sql', 'export.sql', 'data.sql',
        # Backup archive naming patterns from cPanel/Plesk
        'home.zip', 'public_html.zip', 'html.zip', 'httpdocs.zip',
        # Sitemap and robots (info disclosure)
        'sitemap.xml', 'sitemap_index.xml', 'robots.txt',
        # Log files
        'error_log', 'access.log', 'php_errors.log',
        # Shell history (should NEVER be in webroot)
        '.bash_history',
        # WordPress plugin backup directories (critical — plugins often store backups here)
        'wp-content/managewp/', 'wp-content/wpvivid/', 'wp-content/backup-guard/',
        # Environment variants
        '.env.test', '.env.prod', '.env.live',
        # Server info pages (Apache)
        'server-status', 'server-info',
    ]
    
    # Dangerous exposed files by severity
    FILE_SEVERITY = {
        # CRITICAL - Contains credentials/secrets
        'wp-config.php': 'critical',
        'wp-config.php.bak': 'critical',
        'wp-config.php~': 'critical',
        'wp-config.php.old': 'critical',
        'wp-config.php.save': 'critical',
        '.env': 'critical',
        'backup.sql': 'critical',
        'database.sql': 'critical',
        'db.sql': 'critical',
        'dump.sql': 'critical',
        
        # HIGH - Version info or debug data
        'readme.html': 'high',
        'wp-content/debug.log': 'high',
        '.git/HEAD': 'high',
        '.git/config': 'high',
        
        # MEDIUM - Informational but shouldn't be public
        'license.txt': 'medium',
        'xmlrpc.php': 'medium',
        'wp-admin': 'medium',
        
        # LOW - Common backup files
        'backup.zip': 'low',
        '.htaccess.bak': 'low',
    }
    
    def __init__(self, config=None, http_client=None, target=None):
        """
        Initialize file checker.
        
        Args:
            config: Config instance
            http_client: RateLimitedSession instance (BUG-012 fix)
            target: Target URL for normalization
        """
        self.config = config or get_config()
        self.session = http_client  # Use rate-limited client
        self.target = target
        
        # Fallback to regular session if no client provided
        if self.session is None:
            import requests
            self.session = requests.Session()
            self.session.headers.update({'User-Agent': self.config.user_agent})
            logger.warning("No HTTP client provided, using non-rate-limited session")
    
    def normalize_path(self, path: str) -> str:
        """
        Normalize file paths to avoid duplicates like /backup.sql vs backup.sql.
        
        Deduplication and Quality of Results.
        
        Args:
            path: File path to normalize
        
        Returns:
            Normalized path without leading/trailing slashes
        """
        if not path:
            return path
        
        # Remove whitespace
        path = path.strip()
        
        # Remove target URL prefix if present
        if self.target and path.startswith(self.target):
            path = path[len(self.target):]
        
        # Remove protocol prefixes
        for prefix in ("http://", "https://"):
            if path.startswith(prefix):
                path = path[len(prefix):]
        
        # Strip leading/trailing slashes
        path = path.lstrip('/').rstrip('/')
        
        return path
    
    def check_file(self, target: str, file_path: str) -> Optional[Dict]:
        """
        Check if a specific file is accessible.
        
        Args:
            target: Target URL
            file_path: Relative file path
        
        Returns:
            Dict with file info or None if not accessible
        """
        file_url = urljoin(target, file_path)
        
        try:
            response = self.session.get(file_url, allow_redirects=False)
            
            # 200 = accessible, others might still be present but forbidden
            if response.status_code == 200:
                # Basic content validation
                content_length = len(response.content)
                
                # Check if it's actually the file (not a 200 error page)
                if content_length > 0:
                    # For critical files, check if it contains expected patterns
                    is_valid = self._validate_file_content(file_path, response.text)
                    
                    if is_valid:
                        return {
                            'path': file_path,
                            'url': file_url,
                            'status_code': response.status_code,
                            'size': content_length,
                            'content_type': response.headers.get('Content-Type', 'unknown')
                        }
        
        except Exception as e:
            logger.debug(f"File check failed for {file_path}: {e}")
        
        return None
    
    def _validate_file_content(self, file_path: str, content: str) -> bool:
        """
        Validate file content to reduce false positives.
        
        Args:
            file_path: File path being checked
            content: Response content
        
        Returns:
            True if content appears valid for this file type
        """
        # For wp-config, check for WordPress constants
        if 'wp-config' in file_path.lower():
            indicators = ['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST']
            return any(ind in content for ind in indicators)
        
        # For .env, check for KEY=VALUE format
        if '.env' in file_path:
            return '=' in content and '\n' in content
        
        # For SQL dumps, check for SQL keywords
        if file_path.endswith('.sql'):
            indicators = ['CREATE TABLE', 'INSERT INTO', 'DROP TABLE', 'SELECT']
            return any(ind in content.upper() for ind in indicators)
        
        # For readme, check for WordPress version
        if 'readme' in file_path.lower():
            return 'wordpress' in content.lower()
        
        # For .git files
        if '.git' in file_path:
            return 'ref:' in content or '[core]' in content
        
        # For debug.log, check for date/error patterns
        if 'debug.log' in file_path:
            return any(x in content for x in ['[', ']', 'PHP', 'Warning', 'Error'])
        
        # PHP admin tools return HTML interfaces — check for known keywords
        if any(kw in file_path.lower() for kw in ['phpinfo', 'php-info', 'info.php', 'adminer', 'phpmyadmin']):
            return any(kw in content.lower() for kw in [
                'php version', 'phpinfo()', 'adminer', 'phpmyadmin',
                'server software', 'php extension', 'configuration'
            ])
        # Webshells and script files — valid if not a standard WP 404 page
        if file_path.lower().endswith('.php') and 'wp-' not in file_path.lower():
            return 'wordpress' not in content[:200].lower() and content.strip() != ''

        # Default: assume valid if not HTML error page
        return '<html' not in content[:500].lower()
    
    def scan_sensitive_files(self, target: str) -> List[Dict]:
        """
        Scan for all sensitive files.
        
        Args:
            target: Target URL
        
        Returns:
            List of findings
        """
        findings = []
        
        # Store target for normalization
        self.target = target
        
        normalized_config_paths = [self.normalize_path(p) for p in self.config.wp_common_paths]
        normalized_backup_patterns = [self.normalize_path(p) for p in self.BACKUP_PATTERNS]
        
        # Combine and deduplicate
        all_paths = list(set(normalized_config_paths + normalized_backup_patterns))

        # In aggressive mode, extend with additional paths
        if getattr(self.config, 'scan_mode', 'safe') == 'aggressive':
            normalized_aggressive = [self.normalize_path(p) for p in self.AGGRESSIVE_PATHS]
            all_paths = list(set(all_paths + normalized_aggressive))
            logger.info(f"Aggressive mode: extended to {len(all_paths)} total paths")

        logger.info(f"Checking {len(all_paths)} sensitive file paths (deduplicated)")
        
        # Check files concurrently
        exposed_files = []
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            future_to_path = {
                executor.submit(self.check_file, target, path): path
                for path in all_paths
            }
            
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    if result:
                        exposed_files.append(result)
                        logger.warning(f"✗ Exposed file: {result['path']}")
                except Exception as e:
                    logger.debug(f"Error checking {path}: {e}")
        
        # Create findings for each exposed file
        for file_info in exposed_files:
            severity = self._get_severity(file_info['path'])
            finding = self._create_finding(file_info, severity)
            findings.append(finding)
        
        # Add summary if files found
        if exposed_files:
            critical_count = sum(1 for f in exposed_files if self._get_severity(f['path']) == 'critical')
            
            findings.append({
                'id': 'ARGUS-WP-031',
                'title': f'{len(exposed_files)} sensitive file(s) exposed',
                'severity': 'critical' if critical_count > 0 else 'high',
                'confidence': 'high',
                'description': (
                    f"Found {len(exposed_files)} publicly accessible sensitive files. "
                    f"{critical_count} are critical (contain credentials/secrets)."
                ),
                'recommendation': (
                    'URGENT: Secure or remove all exposed files:\n'
                    '1. Block access via .htaccess or web server config\n'
                    '2. Move sensitive files outside webroot\n'
                    '3. Delete backup files and database dumps\n'
                    '4. Regenerate compromised credentials\n'
                    '5. Enable proper file permissions (644 for files, 755 for dirs)'
                )
            })
        else:
            # Good practice finding
            findings.append({
                'id': 'ARGUS-WP-030',
                'title': 'No sensitive files exposed (Good practice)',
                'severity': 'info',
                'confidence': 'high',
                'description': 'No sensitive files were publicly accessible.',
                'recommendation': 'Continue protecting sensitive files and regularly audit file permissions.'
            })
        
        return findings
    
    def _get_severity(self, file_path: str) -> str:
        """Determine severity for a file path."""
        # Normalize before checking severity
        normalized = self.normalize_path(file_path)
        
        # Exact match
        if normalized in self.FILE_SEVERITY:
            return self.FILE_SEVERITY[normalized]
        
        # Pattern match
        file_lower = normalized.lower()
        
        if 'wp-config' in file_lower or '.env' in file_lower or '.sql' in file_lower:
            return 'critical'
        
        if 'debug.log' in file_lower or '.git' in file_lower or 'readme' in file_lower:
            return 'high'
        
        if 'backup' in file_lower or '.bak' in file_lower or '.old' in file_lower:
            return 'medium'
        
        return 'low'
    
    def _create_finding(self, file_info: Dict, severity: str) -> Dict:
        """Create a finding dict for an exposed file."""
        file_path = file_info['path']
        
        # Normalize path for affected_component to avoid duplicates
        normalized_path = self.normalize_path(file_path)
        
        # Customize messages based on file type
        if 'wp-config' in file_path.lower():
            title = 'wp-config.php backup exposed'
            description = (
                f"WordPress configuration file '{file_path}' is publicly accessible. "
                "This file contains database credentials, security keys, and other sensitive information."
            )
            recommendation = (
                'CRITICAL - Immediate action required:\n'
                '1. Remove this file immediately\n'
                '2. Change all database credentials\n'
                '3. Regenerate WordPress security keys: https://api.wordpress.org/secret-key/1.1/salt/\n'
                '4. Review access logs for potential compromise\n'
                '5. Add deny rules to prevent future exposure'
            )
        
        elif '.env' in file_path:
            title = 'Environment file (.env) exposed'
            description = 'Environment configuration file contains API keys, secrets, and credentials.'
            recommendation = (
                'CRITICAL:\n'
                '1. Remove or restrict .env file access\n'
                '2. Rotate all API keys and secrets\n'
                '3. Move .env outside webroot\n'
                '4. Add .env to .htaccess deny rules'
            )
        
        elif file_path.endswith('.sql'):
            title = f'Database dump exposed: {normalized_path}'
            description = 'SQL database backup is publicly downloadable, containing all site data.'
            recommendation = (
                'CRITICAL:\n'
                '1. Delete this file immediately\n'
                '2. Store backups outside webroot\n'
                '3. Review for data breach\n'
                '4. Use encrypted backups with restricted access'
            )
        
        elif 'debug.log' in file_path:
            title = 'Debug log file exposed'
            description = 'WordPress debug log may contain sensitive information like file paths, plugin errors, and database queries.'
            recommendation = (
                '1. Disable WP_DEBUG in production (wp-config.php)\n'
                '2. Delete or restrict access to debug.log\n'
                '3. Use proper error logging to secure location'
            )
        
        elif '.git' in file_path:
            title = 'Git repository exposed'
            description = 'Git repository files are accessible, potentially exposing source code and history.'
            recommendation = (
                '1. Block access to .git directory in web server config\n'
                '2. Remove .git folder from webroot\n'
                '3. Review commit history for exposed secrets\n'
                '4. Use deployment processes that exclude .git'
            )
        
        elif 'readme.html' in file_path:
            title = 'WordPress readme.html accessible'
            description = 'Default WordPress readme file exposes version information.'
            recommendation = 'Remove or restrict access to readme.html and license.txt files.'
        
        elif 'xmlrpc.php' in file_path:
            title = 'XML-RPC interface accessible'
            description = 'XML-RPC can be abused for brute force attacks and DDoS amplification.'
            recommendation = (
                '1. Disable XML-RPC if not needed (via plugin or filter)\n'
                '2. Restrict access via .htaccess if required\n'
                '3. Use security plugins to protect against XML-RPC attacks'
            )
        
        else:
            title = f'Sensitive file exposed: {normalized_path}'
            description = f"File '{normalized_path}' is publicly accessible."
            recommendation = 'Remove or restrict access to this file.'
        
        return {
            'id': 'ARGUS-WP-030',
            'title': title,
            'severity': severity,
            'confidence': 'high',
            'description': description,
            'evidence': {
                'type': 'url',
                'value': file_info['url'],
                'context': f"HTTP {file_info['status_code']}, Size: {file_info['size']} bytes"
            },
            'recommendation': recommendation,
            'references': [
                'https://wordpress.org/documentation/article/hardening-wordpress/',
                'https://developer.wordpress.org/advanced-administration/security/hardening/'
            ],
            'affected_component': normalized_path
        }
    
    def _check_directories(self, target: str) -> List[Dict]:
        """
        Brute-force common directories using HEAD requests (aggressive mode only).

        Args:
            target: Target URL

        Returns:
            List of findings for accessible directories
        """
        findings = []
        seen_paths = set()

        for dir_path in self.BRUTE_FORCE_DIRS:
            # Avoid reporting dirs that were already checked as sensitive files
            normalized = self.normalize_path(dir_path)
            if normalized in seen_paths:
                continue
            seen_paths.add(normalized)

            dir_url = urljoin(target, dir_path)
            try:
                response = self.session.head(dir_url, allow_redirects=True)
                status = response.status_code

                # 200 = accessible; 301/302 followed to non-404 counts too
                if status == 200 or (status in (301, 302) and response.headers.get('Location', '') and '404' not in response.headers.get('Location', '')):
                    findings.append({
                        'id': 'ARGUS-WP-032',
                        'title': f'Accessible directory: {dir_path}',
                        'severity': 'medium',
                        'confidence': 'medium',
                        'description': (
                            f"Directory '{dir_path}' is accessible (HTTP {status}). "
                            "Exposed directories may reveal sensitive content or allow directory listing."
                        ),
                        'evidence': {
                            'type': 'url',
                            'value': dir_url,
                            'context': f"HTTP {status}",
                        },
                        'recommendation': (
                            f"1. Restrict access to '{dir_path}' via .htaccess or web server config\n"
                            "2. Disable directory listing (Options -Indexes)\n"
                            "3. Remove the directory if it is not needed"
                        ),
                        'references': [
                            'https://wordpress.org/documentation/article/hardening-wordpress/',
                        ],
                        'affected_component': normalized,
                    })
                    logger.warning(f"✗ Accessible directory: {dir_path} (HTTP {status})")

            except Exception as e:
                logger.debug(f"Directory check failed for {dir_path}: {e}")

        return findings

    def scan(self, target: str) -> List[Dict]:
        """
        Run full sensitive files scan.

        Args:
            target: Target URL

        Returns:
            List of findings
        """
        findings = self.scan_sensitive_files(target)

        # Aggressive mode: also brute-force common directories
        if getattr(self.config, 'scan_mode', 'safe') == 'aggressive':
            dir_findings = self._check_directories(target)
            findings.extend(dir_findings)

        return findings
