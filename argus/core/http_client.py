"""
HTTP Client with Token Bucket Rate Limiting

Provides a shared HTTP session with thread-safe token bucket rate limiting
that allows proper parallelization while respecting rate limits.


Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import time
import threading
from typing import Optional
import requests
from .logging import get_logger
from .config import get_config

logger = get_logger(__name__)


class TokenBucket:
    """
    Token bucket rate limiter for thread-safe request throttling.
    
    Unlike the previous implementation that used a global lock with sleep,
    this allows multiple threads to consume tokens concurrently while
    maintaining accurate rate limiting.
    
    Algorithm:
    - Bucket has a maximum capacity (burst)
    - Tokens regenerate at a steady rate (req/s)
    - Requests consume tokens
    - If insufficient tokens, caller sleeps OUTSIDE the lock
    """
    
    def __init__(self, rate: float, burst: Optional[int] = None):
        """
        Initialize token bucket.
        
        Args:
            rate: Maximum requests per second (e.g., 10.0 = 10 req/s)
            burst: Burst capacity (default: 2x rate, min 10)
        """
        self.rate = max(0.1, rate)  # Minimum 0.1 req/s
        self.burst = burst or max(10, int(rate * 2))
        
        # Current tokens and timing
        self.tokens = float(self.burst)
        self.max_tokens = float(self.burst)
        self.last_update = time.time()
        
        # Lock ONLY for token updates, NOT for sleeping
        self._lock = threading.Lock()
        
        logger.debug(
            f"Token bucket initialized: {self.rate:.2f} req/s, "
            f"burst={self.burst}, tokens={self.tokens:.2f}"
        )
    
    def consume(self, tokens: int = 1) -> float:
        """
        Attempt to consume tokens for a request.
        
        Returns wait time in seconds (0 if tokens available immediately).
        Caller must sleep OUTSIDE this method to avoid blocking other threads.
        
        Args:
            tokens: Number of tokens to consume (typically 1)
        
        Returns:
            Wait time in seconds before request can proceed (0 if no wait needed)
        """
        with self._lock:
            # Refill tokens based on elapsed time
            now = time.time()
            elapsed = now - self.last_update
            
            # Add tokens proportional to elapsed time
            self.tokens = min(
                self.max_tokens,
                self.tokens + elapsed * self.rate
            )
            self.last_update = now
            
            # Check if we have enough tokens
            if self.tokens >= tokens:
                # Consume tokens immediately
                self.tokens -= tokens
                return 0.0  # No wait needed
            
            else:
                # Calculate wait time needed to accumulate tokens
                deficit = tokens - self.tokens
                wait_time = deficit / self.rate
                
                # Reserve these tokens for this request
                self.tokens -= tokens
                
                logger.debug(
                    f"Rate limit: {self.tokens:.2f}/{self.max_tokens:.0f} tokens, "
                    f"wait {wait_time:.3f}s"
                )
                
                return wait_time
    
    def get_stats(self) -> dict:
        """Get current bucket statistics."""
        with self._lock:
            return {
                'tokens': self.tokens,
                'max_tokens': self.max_tokens,
                'rate': self.rate,
                'burst': self.burst
            }


class RateLimitedSession:
    """
    HTTP session with token bucket rate limiting.
    
    Thread-safe: Multiple threads can make concurrent requests while
    respecting the configured rate limit.
    
    """
    
    def __init__(self, rate_limit: float, config=None):
        """
        Initialize rate-limited session.
        
        Args:
            rate_limit: Maximum requests per second (e.g., 3.0 = 3 req/s)
            config: Config instance (optional)
        """
        self.config = config or get_config()
        self.rate_limit = max(0.1, rate_limit)
        
        # Initialize token bucket
        self.token_bucket = TokenBucket(
            rate=self.rate_limit,
            burst=max(10, int(self.rate_limit * 2))
        )
        
        # Create requests session
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.config.user_agent})
        
        # Custom headers from config
        if self.config.custom_headers:
            self.session.headers.update(self.config.custom_headers)
        
        # Proxy settings
        if self.config.proxy_http or self.config.proxy_https:
            proxies = {}
            if self.config.proxy_http:
                proxies['http'] = self.config.proxy_http
            if self.config.proxy_https:
                proxies['https'] = self.config.proxy_https
            self.session.proxies.update(proxies)
        
        logger.info(
            f"HTTP client initialized: {self.rate_limit:.2f} req/s, "
            f"burst={self.token_bucket.burst}"
        )
    
    def _wait_if_needed(self):
        """
        Rate limiting via token bucket.
        
        """
        # Get wait time from token bucket (fast, lock released immediately)
        wait_time = self.token_bucket.consume(tokens=1)
        
        # Sleep OUTSIDE the lock if needed
        if wait_time > 0:
            logger.debug(f"Rate limiting: sleeping {wait_time:.3f}s")
            time.sleep(wait_time)
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """
        HTTP GET with automatic rate limiting.
        
        Args:
            url: Target URL
            **kwargs: Additional arguments for requests.get()
        
        Returns:
            Response object
        """
        # Apply rate limiting (token bucket)
        self._wait_if_needed()
        
        # Set default timeouts if not provided
        if 'timeout' not in kwargs:
            kwargs['timeout'] = (self.config.timeout_connect, self.config.timeout_read)
        
        if 'verify' not in kwargs:
            kwargs['verify'] = self.config.verify_ssl
        
        if 'allow_redirects' not in kwargs:
            kwargs['allow_redirects'] = self.config.follow_redirects
        
        # Make request
        return self.session.get(url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """HTTP POST with rate limiting."""
        self._wait_if_needed()
        
        if 'timeout' not in kwargs:
            kwargs['timeout'] = (self.config.timeout_connect, self.config.timeout_read)
        
        if 'verify' not in kwargs:
            kwargs['verify'] = self.config.verify_ssl
        
        return self.session.post(url, **kwargs)
    
    def head(self, url: str, **kwargs) -> requests.Response:
        """HTTP HEAD with rate limiting."""
        self._wait_if_needed()
        
        if 'timeout' not in kwargs:
            kwargs['timeout'] = (self.config.timeout_connect, self.config.timeout_read)
        
        if 'verify' not in kwargs:
            kwargs['verify'] = self.config.verify_ssl
        
        return self.session.head(url, **kwargs)


def create_http_client(mode: str = 'safe', config=None) -> RateLimitedSession:
    """
    Create HTTP client with appropriate rate limit for scan mode.
    
    Args:
        mode: 'safe' or 'aggressive'
        config: Config instance (optional)
    
    Returns:
        RateLimitedSession instance
    """
    config = config or get_config()
    
    if mode == 'aggressive':
        rate_limit = config.rate_limit_aggressive
    else:
        rate_limit = config.rate_limit_safe
    
    logger.info(f"HTTP client mode: {mode}, rate limit: {rate_limit:.2f} req/s")
    logger.info(f"Thread pool size: {config.max_workers} workers")
    
    return RateLimitedSession(rate_limit, config)