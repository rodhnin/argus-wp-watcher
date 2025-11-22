"""
argus/__init__.py
-----------------
Package initialization for Argus WordPress security scanner.
"""

__version__ = "0.1.0"
__author__ = "Rodney Dhavid Jimenez Chacin (rodhnin)"
__license__ = "MIT"

from .core.config import Config, get_config
from .core.logging import get_logger, setup_logging
from .core.db import Database, get_db
from .core.consent import ConsentToken

__all__ = [
    '__version__',
    'Config',
    'get_config',
    'get_logger',
    'setup_logging',
    'Database',
    'get_db',
    'ConsentToken',
]