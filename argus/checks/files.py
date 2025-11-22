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
        
        This implements IMPROV-001: Deduplication and Quality of Results.
        
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
        
        # IMPROV-001: Normalize path for affected_component to avoid duplicates
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
    
    def scan(self, target: str) -> List[Dict]:
        """
        Run full sensitive files scan.
        
        Args:
            target: Target URL
        
        Returns:
            List of findings
        """
        return self.scan_sensitive_files(target)
