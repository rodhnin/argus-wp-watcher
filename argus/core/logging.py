"""
Argus Logging Module with Automatic Redaction

Provides structured logging with:
- Automatic redaction of sensitive data (tokens, passwords, cookies)
- Multiple output formats (text, JSON)
- Color support for terminal output
- Verbosity levels (-v, -vv, -vvv)
- File and console handlers

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import logging
import json
import re
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False


class SensitiveDataFilter(logging.Filter):
    """
    Filter that redacts sensitive data from log records.
    
    Searches for patterns matching secrets and replaces them with [REDACTED].
    """
    
    # Patterns to redact (case-insensitive)
    SENSITIVE_PATTERNS = [
        # Tokens and keys
        (r'(token["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', r'\1[REDACTED]'),
        (r'(api[-_]?key["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', r'\1[REDACTED]'),
        (r'(secret["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', r'\1[REDACTED]'),
        (r'(Bearer\s+)([A-Za-z0-9\-_\.]+)', r'\1[REDACTED]'),
        
        # Passwords
        (r'(password["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', r'\1[REDACTED]'),
        (r'(passwd["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', r'\1[REDACTED]'),
        (r'(pwd["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', r'\1[REDACTED]'),
        
        # Cookies and authorization headers
        (r'(Cookie:\s*)([^\n]+)', r'\1[REDACTED]'),
        (r'(Set-Cookie:\s*)([^\n]+)', r'\1[REDACTED]'),
        (r'(Authorization:\s*)([^\n]+)', r'\1[REDACTED]'),
        
        # Database credentials in URLs
        (r'(://[^:]+:)([^@]+)(@)', r'\1[REDACTED]\3'),
    ]
    
    def __init__(self, enabled: bool = True):
        super().__init__()
        self.enabled = enabled
        self._compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE), replacement)
            for pattern, replacement in self.SENSITIVE_PATTERNS
        ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Redact sensitive data from the log record."""
        if not self.enabled:
            return True
        
        # Redact message
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            record.msg = self._redact_text(record.msg)
        
        # Redact args if present
        if hasattr(record, 'args') and record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._redact_value(v) for k, v in record.args.items()}
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(self._redact_value(arg) for arg in record.args)
        
        return True
    
    def _redact_text(self, text: str) -> str:
        """Apply redaction patterns to text."""
        for pattern, replacement in self._compiled_patterns:
            text = pattern.sub(replacement, text)
        return text
    
    def _redact_value(self, value: Any) -> Any:
        """Recursively redact values in nested structures."""
        if isinstance(value, str):
            return self._redact_text(value)
        elif isinstance(value, dict):
            return {k: self._redact_value(v) for k, v in value.items()}
        elif isinstance(value, (list, tuple)):
            return type(value)(self._redact_value(item) for item in value)
        return value


class ColoredFormatter(logging.Formatter):
    """
    Formatter that adds colors to log levels in terminal output.
    """
    
    LEVEL_COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
    }
    
    def __init__(self, fmt: str, datefmt: str, use_colors: bool = True):
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors and HAS_COLORAMA
    
    def format(self, record: logging.LogRecord) -> str:
        if self.use_colors:
            levelname = record.levelname
            if levelname in self.LEVEL_COLORS:
                record.levelname = f"{self.LEVEL_COLORS[levelname]}{levelname}{Style.RESET_ALL}"
        return super().format(record)


class JSONFormatter(logging.Formatter):
    """
    Formatter that outputs log records as JSON lines.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            'timestamp': datetime.now(timezone.utc).isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'created', 'filename', 'funcName',
                           'levelname', 'levelno', 'lineno', 'module', 'msecs',
                           'message', 'pathname', 'process', 'processName',
                           'relativeCreated', 'thread', 'threadName', 'exc_info',
                           'exc_text', 'stack_info']:
                log_data[key] = value
        
        return json.dumps(log_data)


def setup_logging(
    level: str = "INFO",
    log_file: Optional[Path] = None,
    json_format: bool = False,
    use_colors: bool = True,
    redact_secrets: bool = True
) -> logging.Logger:
    """
    Configure logging for Argus.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (None = console only)
        json_format: Use JSON format for structured logging
        use_colors: Use colored output in terminal
        redact_secrets: Enable automatic redaction of sensitive data
    
    Returns:
        Configured root logger
    """
    # Convert string level to logging constant
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create root logger
    logger = logging.getLogger()
    logger.setLevel(numeric_level)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Add sensitive data filter
    if redact_secrets:
        logger.addFilter(SensitiveDataFilter(enabled=True))
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    
    if json_format:
        console_formatter = JSONFormatter()
    else:
        # Detect if running in a terminal
        is_tty = sys.stdout.isatty()
        use_colors_final = use_colors and is_tty
        
        console_formatter = ColoredFormatter(
            fmt='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            use_colors=use_colors_final
        )
    
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(numeric_level)
        
        if json_format:
            file_formatter = JSONFormatter()
        else:
            file_formatter = logging.Formatter(
                fmt='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a specific module.
    
    Args:
        name: Logger name (usually __name__)
    
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def set_verbosity(level: int):
    """
    Set logging verbosity based on -v flags.
    
    Args:
        level: 0 = WARNING, 1 = INFO, 2 = DEBUG, 3+ = DEBUG with verbose libs
    """
    root_logger = logging.getLogger()
    
    if level == 0:
        root_logger.setLevel(logging.WARNING)
    elif level == 1:
        root_logger.setLevel(logging.INFO)
    elif level >= 2:
        root_logger.setLevel(logging.DEBUG)
        
        # At -vvv, also enable debug logging for third-party libraries
        if level >= 3:
            logging.getLogger('urllib3').setLevel(logging.DEBUG)
            logging.getLogger('requests').setLevel(logging.DEBUG)


# Module-level logger for this file
logger = get_logger(__name__)


if __name__ == "__main__":
    # Test the logging module
    test_logger = setup_logging(
        level="DEBUG",
        log_file=Path("/tmp/argus_test.log"),
        json_format=False,
        use_colors=True,
        redact_secrets=True
    )
    
    log = get_logger("test")
    
    # Test various log levels
    log.debug("This is a debug message")
    log.info("This is an info message")
    log.warning("This is a warning message")
    log.error("This is an error message")
    
    # Test redaction
    log.info("Login attempt with password=SuperSecret123")
    log.info("API token=abc123xyz456 should be redacted")
    log.info("Cookie: session_id=secret123; user=admin")
    log.info("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
    
    print("\nCheck /tmp/argus_test.log to verify redaction")