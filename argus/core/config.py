"""
Argus Configuration Loader

Handles configuration from multiple sources with priority:
1. Command-line arguments (highest priority)
2. Environment variables
3. User config file (~/.argus/config.yaml)
4. Default config (config/defaults.yaml)

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class Config:
    """
    Configuration container for Argus.
    
    All settings are accessible as attributes with dot notation.
    """
    
    # ========================================================================
    # CLASS-LEVEL DEFAULTS (for mutable types)
    # ========================================================================
    # These are used as fallbacks when YAML config is missing values
    # Must be defined BEFORE instance attributes to be accessible via cls.XXX
    
    DEFAULT_WP_PATHS = [
        "/readme.html", "/license.txt", "/wp-config.php",
        "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.old",
        "/wp-config.php.save", "/wp-content/debug.log", "/xmlrpc.php",
        "/.git/HEAD", "/.env", "/backup.zip", "/backup.sql",
        "/dump.sql", "/database.sql"
    ]
    
    DEFAULT_COMMON_PLUGINS = [
        "akismet", "jetpack", "wordfence", "contact-form-7",
        "yoast-seo", "elementor", "woocommerce", "all-in-one-wp-migration"
    ]
    
    DEFAULT_COMMON_THEMES = [
        "twentytwentyfour", "twentytwentythree", "twentytwentytwo",
        "twentytwentyone", "astra", "generatepress"
    ]
    
    DEFAULT_CUSTOM_HEADERS = {}
    
    # ========================================================================
    # INSTANCE ATTRIBUTES
    # ========================================================================
    
    # General
    version: str = "0.1.0"
    author: str = "Rodney Dhavid Jimenez Chacin (rodhnin)"
    github: str = "https://github.com/rodhnin/argus-wp-watcher"
    contact: Optional[str] = "https://www.rodhnin.com"
    
    # Paths
    report_dir: Path = Path.home() / ".argus" / "reports"
    database: Path = Path.home() / ".argos" / "argos.db"
    log_file: Optional[Path] = Path.home() / ".argus" / "argus.log"
    consent_proofs_dir: Path = Path.home() / ".argus" / "consent-proofs"
    
    # Scan behavior
    default_mode: str = "safe"
    rate_limit_safe: float = 3.0
    rate_limit_aggressive: float = 10.0
    timeout_connect: int = 10
    timeout_read: int = 30
    user_agent: str = "Argus/0.1.0 (WordPress Security Scanner; +https://github.com/rodhnin/argus-wp-watcher)"
    follow_redirects: bool = True
    max_redirects: int = 5
    verify_ssl: bool = True
    
    # WordPress settings
    wp_common_paths: list = field(default_factory=lambda: Config.DEFAULT_WP_PATHS.copy())
    wp_max_plugins_check: int = 100
    wp_max_themes_check: int = 20
    wp_common_plugins: list = field(default_factory=lambda: Config.DEFAULT_COMMON_PLUGINS.copy())
    wp_common_themes: list = field(default_factory=lambda: Config.DEFAULT_COMMON_THEMES.copy())
    wp_check_author_idor: bool = True
    wp_check_rest_api: bool = True
    wp_max_users_check: int = 10
    
    # Consent token
    token_expiry_hours: int = 48
    token_hex_length: int = 16
    http_verification_path: str = "/.well-known/"
    dns_txt_prefix: str = "argus-verify="
    verification_retries: int = 3
    verification_retry_delay: int = 2
    
    # Reporting
    generate_json: bool = True
    generate_html: bool = False
    json_indent: int = 2
    html_include_evidence: bool = True
    html_css_inline: bool = True
    
    # Logging
    log_level: str = "INFO"
    log_json_format: bool = False
    log_colors: bool = True
    log_redact_secrets: bool = True
    
    # AI integration (LangChain)
    ai_enabled: bool = False
    ai_provider: str = "openai"
    ai_model: str = "gpt-4-turbo-preview"
    ai_temperature: float = 0.3
    ai_max_tokens: int = 2000
    ai_agent_type: str = "zero-shot-react-description"
    ai_memory_enabled: bool = True
    ai_memory_type: str = "buffer"
    ai_memory_max_history: int = 10
    ai_api_key_env: str = "OPENAI_API_KEY"
    ai_prompts_dir: Path = Path("config/prompts")
    ai_remove_urls: bool = False
    ai_remove_tokens: bool = True
    ai_remove_credentials: bool = True
    ai_max_evidence_length: int = 500
    
    # Advanced
    max_workers: int = 5
    cache_responses: bool = False
    cache_ttl_seconds: int = 3600
    custom_headers: Dict[str, str] = field(default_factory=lambda: Config.DEFAULT_CUSTOM_HEADERS.copy())
    proxy_http: Optional[str] = None
    proxy_https: Optional[str] = None
    
    # Docker
    in_container: bool = False
    container_report_dir: Path = Path("/reports")
    container_db_path: Path = Path("/data/argos.db")
    
    @classmethod
    def load(
        cls,
        config_file: Optional[Path] = None,
        cli_overrides: Optional[Dict[str, Any]] = None
    ) -> "Config":
        """
        Load configuration from multiple sources.
        
        Args:
            config_file: Path to user config file (default: ~/.argus/config.yaml)
            cli_overrides: Dictionary of CLI argument overrides
        
        Returns:
            Configured Config instance
        """
        # Start with defaults
        config_dict = cls._load_defaults()
        
        # Merge user config file if exists
        if config_file is None:
            config_file = Path.home() / ".argus" / "config.yaml"
        
        if config_file.exists():
            user_config = cls._load_yaml(config_file)
            config_dict = cls._deep_merge(config_dict, user_config)
        
        # Apply environment variables
        env_config = cls._load_env_vars()
        config_dict = cls._deep_merge(config_dict, env_config)
        
        # Apply CLI overrides (highest priority)
        if cli_overrides:
            config_dict = cls._deep_merge(config_dict, cli_overrides)
        
        # Flatten nested dict to Config attributes
        return cls._dict_to_config(config_dict)

    @staticmethod
    def _load_env_vars() -> Dict[str, Any]:
        """
        Load configuration from environment variables.
        
        Env vars format: ARGUS_SECTION_KEY (e.g., ARGUS_PATHS_DATABASE)
        
        Special handling for Docker:
        - ARGUS_DOCKER_IN_CONTAINER maps to docker.in_container
        """
        env_config = {}
        prefix = "ARGUS_"
        
        for key, value in os.environ.items():
            if key.startswith(prefix):
                # Special case for Docker variables to avoid parsing issues
                if key == "ARGUS_DOCKER_IN_CONTAINER":
                    env_config.setdefault('docker', {})['in_container'] = Config._parse_env_value(value)
                    continue
                if key == "ARGUS_DOCKER_CONTAINER_DB_PATH":
                    env_config.setdefault('docker', {})['container_db_path'] = value
                    continue
                
                # Existing code continues here...
                parts = key[len(prefix):].lower().split('_')
                current = env_config
                for part in parts[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                last_key = parts[-1]
                current[last_key] = Config._parse_env_value(value)
        
        return env_config
    
    @staticmethod
    def _load_defaults() -> Dict[str, Any]:
        """Load default configuration from config/defaults.yaml."""
        defaults_path = Path(__file__).parent.parent.parent / "config" / "defaults.yaml"
        
        if not defaults_path.exists():
            # Return minimal defaults if file not found
            return {
                "general": {"version": "0.1.0"},
                "paths": {},
                "scan": {},
                "wordpress": {},
                "consent": {},
                "reporting": {},
                "logging": {},
                "ai": {},
                "advanced": {},
                "docker": {}
            }
        
        return Config._load_yaml(defaults_path)
    
    @staticmethod
    def _load_yaml(path: Path) -> Dict[str, Any]:
        """Load YAML file safely."""
        try:
            with path.open('r') as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in {path}: {e}")
    
    @staticmethod
    def _parse_env_value(value: str) -> Any:
        """Parse environment variable value to appropriate type."""
        # Boolean
        if value.lower() in ('true', 'yes', '1'):
            return True
        if value.lower() in ('false', 'no', '0'):
            return False
        
        # Integer
        try:
            return int(value)
        except ValueError:
            pass
        
        # Float
        try:
            return float(value)
        except ValueError:
            pass
        
        # String
        return value
    
    @staticmethod
    def _deep_merge(base: Dict, update: Dict) -> Dict:
        """Deep merge two dictionaries."""
        result = base.copy()
        
        for key, value in update.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = Config._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    @classmethod
    def _dict_to_config(cls, config_dict: Dict[str, Any]) -> "Config":
        """Convert nested dict to flat Config instance."""
        # Flatten nested structure
        flat = {}
        
        # General
        if 'general' in config_dict:
            gen = config_dict['general']
            flat['version'] = gen.get('version', cls.version)
            flat['author'] = gen.get('author', cls.author)
            flat['github'] = gen.get('github', cls.github)
            flat['contact'] = gen.get('contact', cls.contact)
        
        # Paths
        if 'paths' in config_dict:
            paths = config_dict['paths']
            flat['report_dir'] = Path(paths.get('report_dir', cls.report_dir))
            flat['database'] = Path(paths.get('database', cls.database))
            log_file = paths.get('log_file')
            flat['log_file'] = Path(log_file) if log_file else None
            flat['consent_proofs_dir'] = Path(paths.get('consent_proofs_dir', cls.consent_proofs_dir))
        
        # Scan
        if 'scan' in config_dict:
            scan = config_dict['scan']
            flat['default_mode'] = scan.get('default_mode', cls.default_mode)
            if 'rate_limit' in scan:
                flat['rate_limit_safe'] = scan['rate_limit'].get('safe_mode', cls.rate_limit_safe)
                flat['rate_limit_aggressive'] = scan['rate_limit'].get('aggressive_mode', cls.rate_limit_aggressive)
            if 'timeout' in scan:
                flat['timeout_connect'] = scan['timeout'].get('connect', cls.timeout_connect)
                flat['timeout_read'] = scan['timeout'].get('read', cls.timeout_read)
            flat['user_agent'] = scan.get('user_agent', cls.user_agent)
            flat['follow_redirects'] = scan.get('follow_redirects', cls.follow_redirects)
            flat['max_redirects'] = scan.get('max_redirects', cls.max_redirects)
            flat['verify_ssl'] = scan.get('verify_ssl', cls.verify_ssl)
        
        # WordPress
        if 'wordpress' in config_dict:
            wp = config_dict['wordpress']
            flat['wp_common_paths'] = wp.get('common_paths', cls.DEFAULT_WP_PATHS.copy())
            
            if 'enumeration' in wp:
                enum = wp['enumeration']
                flat['wp_max_plugins_check'] = enum.get('max_plugins_to_check', cls.wp_max_plugins_check)
                flat['wp_max_themes_check'] = enum.get('max_themes_to_check', cls.wp_max_themes_check)
                # Also handle common_plugins and common_themes
                flat['wp_common_plugins'] = enum.get('common_plugins', cls.DEFAULT_COMMON_PLUGINS.copy())
                flat['wp_common_themes'] = enum.get('common_themes', cls.DEFAULT_COMMON_THEMES.copy())
            
            if 'user_enumeration' in wp:
                user_enum = wp['user_enumeration']
                flat['wp_check_author_idor'] = user_enum.get('check_author_idor', cls.wp_check_author_idor)
                flat['wp_check_rest_api'] = user_enum.get('check_rest_api', cls.wp_check_rest_api)
                flat['wp_max_users_check'] = user_enum.get('max_users_to_check', cls.wp_max_users_check)
        
        # Consent
        if 'consent' in config_dict:
            consent = config_dict['consent']
            flat['token_expiry_hours'] = consent.get('token_expiry_hours', cls.token_expiry_hours)
            flat['token_hex_length'] = consent.get('token_hex_length', cls.token_hex_length)
            flat['http_verification_path'] = consent.get('http_verification_path', cls.http_verification_path)
            flat['dns_txt_prefix'] = consent.get('dns_txt_prefix', cls.dns_txt_prefix)
            flat['verification_retries'] = consent.get('verification_retries', cls.verification_retries)
            flat['verification_retry_delay'] = consent.get('verification_retry_delay', cls.verification_retry_delay)
        
        # Reporting
        if 'reporting' in config_dict:
            reporting = config_dict['reporting']
            if 'format' in reporting:
                flat['generate_json'] = reporting['format'].get('json', cls.generate_json)
                flat['generate_html'] = reporting['format'].get('html', cls.generate_html)
            flat['json_indent'] = reporting.get('json_indent', cls.json_indent)
            if 'html' in reporting:
                flat['html_include_evidence'] = reporting['html'].get('include_evidence', cls.html_include_evidence)
                flat['html_css_inline'] = reporting['html'].get('css_inline', cls.html_css_inline)
        
        # Logging
        if 'logging' in config_dict:
            logging_cfg = config_dict['logging']
            flat['log_level'] = logging_cfg.get('level', cls.log_level)
            flat['log_json_format'] = logging_cfg.get('json_format', cls.log_json_format)
            flat['log_colors'] = logging_cfg.get('colors', cls.log_colors)
            if 'redact' in logging_cfg:
                flat['log_redact_secrets'] = logging_cfg['redact'].get('enabled', cls.log_redact_secrets)
        
        # AI
        if 'ai' in config_dict:
            ai = config_dict['ai']
            flat['ai_enabled'] = ai.get('enabled', cls.ai_enabled)
            if 'langchain' in ai:
                lc = ai['langchain']
                flat['ai_provider'] = lc.get('provider', cls.ai_provider)
                flat['ai_model'] = lc.get('model', cls.ai_model)
                flat['ai_temperature'] = lc.get('temperature', cls.ai_temperature)
                flat['ai_max_tokens'] = lc.get('max_tokens', cls.ai_max_tokens)
                flat['ai_agent_type'] = lc.get('agent_type', cls.ai_agent_type)
                if 'memory' in lc:
                    flat['ai_memory_enabled'] = lc['memory'].get('enabled', cls.ai_memory_enabled)
                    flat['ai_memory_type'] = lc['memory'].get('type', cls.ai_memory_type)
                    flat['ai_memory_max_history'] = lc['memory'].get('max_history', cls.ai_memory_max_history)
            flat['ai_api_key_env'] = ai.get('api_key_env', cls.ai_api_key_env)
            prompts_dir = ai.get('prompts_dir', cls.ai_prompts_dir)
            flat['ai_prompts_dir'] = Path(prompts_dir) if prompts_dir else cls.ai_prompts_dir
            if 'sanitization' in ai:
                san = ai['sanitization']
                flat['ai_remove_urls'] = san.get('remove_urls', cls.ai_remove_urls)
                flat['ai_remove_tokens'] = san.get('remove_tokens', cls.ai_remove_tokens)
                flat['ai_remove_credentials'] = san.get('remove_credentials', cls.ai_remove_credentials)
                flat['ai_max_evidence_length'] = san.get('max_evidence_length', cls.ai_max_evidence_length)
        
        # Advanced
        if 'advanced' in config_dict:
            adv = config_dict['advanced']
            flat['max_workers'] = adv.get('max_workers', cls.max_workers)
            flat['cache_responses'] = adv.get('cache_responses', cls.cache_responses)
            flat['cache_ttl_seconds'] = adv.get('cache_ttl_seconds', cls.cache_ttl_seconds)
            flat['custom_headers'] = adv.get('custom_headers', cls.DEFAULT_CUSTOM_HEADERS.copy())
            if 'proxy' in adv:
                flat['proxy_http'] = adv['proxy'].get('http', cls.proxy_http)
                flat['proxy_https'] = adv['proxy'].get('https', cls.proxy_https)
        
        # Docker
        if 'docker' in config_dict:
            docker = config_dict['docker']
            flat['in_container'] = docker.get('in_container', cls.in_container)
            flat['container_report_dir'] = Path(docker.get('container_report_dir', cls.container_report_dir))
            flat['container_db_path'] = Path(docker.get('container_db_path', cls.container_db_path))
        
        return cls(**flat)
    
    def expand_paths(self):
        """
        Expand ~ and environment variables in paths.

        Auto-detects Docker environment and uses container paths automatically.
        """
        # Docker auto-detection: Use mounted volumes if running in container
        if self.in_container:
            # Check if paths are still at default values (not overridden by user)
            default_report = Path.home() / ".argus" / "reports"
            default_db = Path.home() / ".argos" / "argos.db"

            # Expand paths before comparing
            expanded_report = self.report_dir.expanduser()
            expanded_db = self.database.expanduser()

            # Use container paths if still using defaults
            if expanded_report == default_report:
                self.report_dir = self.container_report_dir  # /reports
            else:
                # User specified custom path, use expanded version
                self.report_dir = expanded_report

            if expanded_db == default_db:
                self.database = self.container_db_path  # /data/argos.db
            else:
                # User specified custom path, use expanded version
                self.database = expanded_db
        else:
            # Not in container, expand all paths normally
            self.report_dir = self.report_dir.expanduser()
            self.database = self.database.expanduser()

        # Always expand log file path if specified
        if self.log_file:
            self.log_file = self.log_file.expanduser()
    
    def ensure_directories(self):
        """Create necessary directories if they don't exist."""
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.consent_proofs_dir.mkdir(parents=True, exist_ok=True)


# Global config instance (loaded on first import)
_global_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global _global_config
    if _global_config is None:
        _global_config = Config.load()
        _global_config.expand_paths()
    return _global_config


def set_config(config: Config):
    """Set the global configuration instance."""
    global _global_config
    _global_config = config


if __name__ == "__main__":
    # Test configuration loading
    config = Config.load()
    config.expand_paths()
    
    print(f"Version: {config.version}")
    print(f"Report Dir: {config.report_dir}")
    print(f"Database: {config.database}")
    print(f"Rate Limit (safe): {config.rate_limit_safe} req/s")
    print(f"WP Common Paths: {len(config.wp_common_paths)} paths")
    print(f"AI Enabled: {config.ai_enabled}")
    print(f"AI Model: {config.ai_model}")
