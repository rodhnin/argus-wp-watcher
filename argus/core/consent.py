"""
Argus Consent Token System

Implements ownership verification via:
- HTTP file placement (/.well-known/<token>.txt)
- DNS TXT record verification

Required before --aggressive or --use-ai modes.

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import secrets
import re
import dns.resolver
import dns.exception
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

import requests
import dns.resolver

from .logging import get_logger
from .config import get_config

logger = get_logger(__name__)


class ConsentToken:
    """
    Manages consent token generation and verification.
    """
    
    def __init__(self, config=None):
        self.config = config or get_config()
        self.token_pattern = re.compile(r'^verify-[a-f0-9]{16}$')
    
    def generate_token(self, domain: str) -> Tuple[str, datetime]:
        """
        Generate a unique consent token for a domain.
        
        Args:
            domain: Target domain (e.g., "example.com" or "localhost:8080")
        
        Returns:
            Tuple of (token, expiration_datetime)
        """
        # Clean domain (remove protocol and path, preserve port)
        clean_domain = self._normalize_domain(domain)
        
        # Generate token: verify-<16 hex chars>
        random_hex = secrets.token_hex(self.config.token_hex_length // 2)
        token = f"verify-{random_hex}"
        
        # Calculate expiration
        expiration = datetime.now(timezone.utc) + timedelta(hours=self.config.token_expiry_hours)
        
        logger.info(f"Generated consent token for {clean_domain}: {token}")
        logger.debug(f"Token expires at: {expiration.isoformat()}Z")
        
        return token, expiration
    
    def print_instructions(self, domain: str, token: str):
        """
        Print human-readable instructions for token placement.
        
        Args:
            domain: Target domain
            token: Generated token
        """
        # Preserve port for display
        normalized_domain = self._normalize_domain(domain)
        
        # Construct URL with port if present
        if ':' in normalized_domain:
            # Non-standard port, use http
            http_path = f"http://{normalized_domain}{self.config.http_verification_path}{token}.txt"
        else:
            # Standard domain, use https
            http_path = f"https://{normalized_domain}{self.config.http_verification_path}{token}.txt"
        
        # Display domain without port for simplicity (but keep for commands)
        display_domain = normalized_domain.split(':')[0]
        
        print("\n" + "="*70)
        print("DOMAIN OWNERSHIP VERIFICATION REQUIRED")
        print("="*70)
        print(f"\nDomain: {display_domain}")
        print(f"Token: {token}")
        print(f"Expires: {self.config.token_expiry_hours} hours from now")
        
        print("\n┌─ METHOD 1: HTTP File (Recommended)")
        print("│")
        print("│  1. Create a text file containing EXACTLY this:")
        print(f"│     {token}")
        print("│")
        print("│  2. Upload it to:")
        print(f"│     {http_path}")
        print("│")
        print("│  3. Verify it's accessible in your browser")
        print("│")
        print("│  4. Run verification:")
        print(f"│     argus --verify-consent http --domain {normalized_domain} --token {token}")
        print("└─")
        
        print("\n┌─ METHOD 2: DNS TXT Record (Alternative)")
        print("│")
        print("│  1. Add a TXT record to your DNS:")
        print(f"│     Host: {display_domain}")
        print(f"│     Value: {self.config.dns_txt_prefix}{token}")
        print("│")
        print("│  2. Wait for DNS propagation (5-30 minutes)")
        print("│")
        print("│  3. Run verification:")
        print(f"│     argus --verify-consent dns --domain {normalized_domain} --token {token}")
        print("└─")
        
        print("\n" + "="*70)
        print("NOTE: You must verify ownership before using --aggressive or --use-ai")
        print("="*70 + "\n")
    
    def verify_http(self, domain: str, token: str) -> Tuple[bool, Optional[str]]:
        """
        Verify consent token via HTTP file.
        
        Args:
            domain: Target domain (with port if non-standard)
            token: Token to verify
        
        Returns:
            Tuple of (success, proof_url or error_message)
        """
        if not self._validate_token_format(token):
            return False, f"Invalid token format: {token}"
        
        # Preserve port in domain
        normalized_domain = self._normalize_domain(domain)
        
        # Determine protocol based on port
        has_port = ':' in normalized_domain
        protocols = ['http'] if has_port else ['https', 'http']
        
        # Try protocols
        for protocol in protocols:
            url = f"{protocol}://{normalized_domain}{self.config.http_verification_path}{token}.txt"
            
            logger.info(f"Attempting HTTP verification: {url}")
            
            try:
                response = requests.get(
                    url,
                    timeout=(self.config.timeout_connect, self.config.timeout_read),
                    verify=self.config.verify_ssl,
                    allow_redirects=False
                )
                
                if response.status_code == 200:
                    content = response.text.strip()
                    
                    if content == token:
                        logger.info(f"✓ HTTP verification successful: {url}")
                        return True, url
                    else:
                        logger.warning(f"Token mismatch. Expected: {token}, Got: {content}")
                        return False, f"Token content mismatch at {url}"
                
                elif response.status_code == 404:
                    logger.debug(f"Token file not found at {url}")
                    continue
                
                else:
                    logger.warning(f"Unexpected status code {response.status_code} at {url}")
                    
            except requests.RequestException as e:
                logger.debug(f"Request failed for {url}: {e}")
                continue
        
        return False, f"Token file not accessible at {normalized_domain}{self.config.http_verification_path}{token}.txt"
    
    def verify_dns(self, domain: str, token: str) -> Tuple[bool, Optional[str]]:
        """
        Verify consent token via DNS TXT record.
        """
        if not self._validate_token_format(token):
            return False, f"Invalid token format: {token}"

        domain_for_dns = self._get_base_domain(domain)
        expected_txt = f"{self.config.dns_txt_prefix}{token}"

        logger.info(f"Attempting DNS verification for {domain_for_dns}")
        logger.info(f"Looking for TXT record: {expected_txt}")

        def _mk_resolver(nameservers=None, label="resolver"):
            r = dns.resolver.Resolver()
            if nameservers:
                r.nameservers = nameservers
            r.timeout = 3
            r.lifetime = 5
            logger.debug(f"[{label}] nameservers={list(r.nameservers)}")
            return r

        def _ns_host_to_ips(ns_host: str):
            """Resolve NS hostname to A/AAAA using the system resolver."""
            sysr = _mk_resolver(label="system")
            ips = []
            try:
                for rr in sysr.resolve(ns_host, "A"):
                    ips.append(rr.address)
            except Exception:
                pass
            try:
                for rr in sysr.resolve(ns_host, "AAAA"):
                    ips.append(rr.address)
            except Exception:
                pass
            return ips

        def _txt_match_from_response(resp) -> Tuple[Optional[str], int]:
            """Return (matched_value, count_records)."""
            records = list(resp)
            for rdata in records:
                parts = getattr(rdata, "strings", None)
                if parts is not None:
                    for raw in parts:
                        raw = raw.decode() if isinstance(raw, bytes) else raw
                        clean = raw.strip().strip('"')
                        logger.debug(f"TXT raw=[{raw}] clean=[{clean}] match={clean == expected_txt}")
                        if clean == expected_txt:
                            return clean, len(records)
                else:
                    clean = rdata.to_text().strip().strip('"')
                    logger.debug(f"TXT(to_text)=[{clean}] match={clean == expected_txt}")
                    if clean == expected_txt:
                        return clean, len(records)
            return None, len(records)

        def _query_txt_with(resolver: dns.resolver.Resolver, label: str):
            try:
                resp = resolver.resolve(domain_for_dns, "TXT")
                match, count = _txt_match_from_response(resp)
                logger.debug(f"[{label}] Found {count} TXT record(s) for {domain_for_dns}")
                if match:
                    logger.info(f"✓ DNS verification successful for {domain_for_dns} via {label}")
                    return ("ok", match)
                return (None, None)
            except dns.resolver.NXDOMAIN:
                return ("nx", None)
            except dns.resolver.NoAnswer:
                logger.debug(f"[{label}] No TXT records for {domain_for_dns}")
                return (None, None)
            except dns.exception.DNSException as e:
                logger.debug(f"[{label}] DNS query failed: {e}")
                return (None, None)

        authoritative_resolver = None
        try:
            system_lookup = _mk_resolver(label="system")
            ns_resp = system_lookup.resolve(domain_for_dns, "NS")
            ns_hosts = [ns.target.to_text().rstrip(".") for ns in ns_resp]
            if ns_hosts:
                logger.info(f"Found {len(ns_hosts)} authoritative nameserver(s): {', '.join(ns_hosts)}")
                ns_host = ns_hosts[0]
                ns_ips = _ns_host_to_ips(ns_host)
                if ns_ips:
                    logger.info(f"Using authoritative nameserver: {ns_host} ({', '.join(ns_ips)})")
                    authoritative_resolver = _mk_resolver([ns_ips[0]], label="authoritative NS")
        except Exception as ex:
            logger.warning(f"Could not resolve authoritative nameservers: {ex}")

        if authoritative_resolver:
            status, proof = _query_txt_with(authoritative_resolver, "authoritative NS")
            if status == "ok":
                return True, proof
            if status == "nx":
                return False, f"Domain {domain_for_dns} does not exist"

        sys_res = dns.resolver.Resolver() 
        system_ns = list(sys_res.nameservers)
        logger.debug(f"Falling back to system DNS resolver list: {system_ns}")

        for ns_ip in system_ns:
            per_ns = _mk_resolver([ns_ip], label=f"system DNS ({ns_ip})")
            status, proof = _query_txt_with(per_ns, f"system DNS ({ns_ip})")
            if status == "ok":
                return True, proof
            if status == "nx":
                return False, f"Domain {domain_for_dns} does not exist"

        return False, f"Token not found in TXT records for {domain_for_dns}"

    
    def verify_with_retry(
        self,
        method: str,
        domain: str,
        token: str,
        retries: Optional[int] = None,
        delay: Optional[int] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify token with automatic retries.
        
        Args:
            method: 'http' or 'dns'
            domain: Target domain (with port for http)
            token: Token to verify
            retries: Number of retry attempts (default from config)
            delay: Delay between retries in seconds (default from config)
        
        Returns:
            Tuple of (success, proof or error_message)
        """
        retries = retries or self.config.verification_retries
        delay = delay or self.config.verification_retry_delay
        
        verify_func = self.verify_http if method == 'http' else self.verify_dns
        
        for attempt in range(1, retries + 1):
            logger.info(f"Verification attempt {attempt}/{retries}")
            
            success, result = verify_func(domain, token)
            
            if success:
                return True, result
            
            if attempt < retries:
                import time
                logger.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
        
        return False, result
    
    def save_proof(self, domain: str, token: str, method: str, proof: str) -> Path:
        """
        Save verification proof to file.
        
        Args:
            domain: Verified domain (with port)
            token: Verified token
            method: 'http' or 'dns'
            proof: Proof string (URL or TXT record)
        
        Returns:
            Path to saved proof file
        """
        # For filename, use base domain without port for cleanliness
        base_domain = self._get_base_domain(domain)
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        filename = f"{base_domain}_{method}_{timestamp}.txt"
        
        proof_path = self.config.consent_proofs_dir / filename
        proof_path.parent.mkdir(parents=True, exist_ok=True)
        
        # But save full domain (with port) in proof file content
        normalized_domain = self._normalize_domain(domain)
        
        with proof_path.open('w') as f:
            f.write(f"Domain: {normalized_domain}\n")
            f.write(f"Token: {token}\n")
            f.write(f"Method: {method}\n")
            f.write(f"Verified: {datetime.now(timezone.utc).isoformat()}Z\n")
            f.write(f"Proof: {proof}\n")
        
        logger.info(f"Verification proof saved: {proof_path}")
        return proof_path
    
    def _normalize_domain(self, domain: str) -> str:
        """
        Normalize domain string (remove protocol and path, PRESERVE port).
        
        Args:
            domain: Raw domain string
        
        Returns:
            Normalized domain with port if present (e.g., "localhost:8080" or "example.com")
        """
        # If it looks like a URL, parse it
        if '://' in domain:
            parsed = urlparse(domain)
            domain = parsed.netloc or parsed.path
        
        # Remove path (but keep port)
        if '/' in domain:
            domain = domain.split('/')[0]
        
        return domain.strip().lower()
    
    def _get_base_domain(self, domain: str) -> str:
        """
        Get base domain without port (for DNS queries and display).
        
        Args:
            domain: Domain string (may include port)
        
        Returns:
            Base domain without port (e.g., "localhost" from "localhost:8080")
        """
        normalized = self._normalize_domain(domain)
        
        # Remove port if present
        if ':' in normalized:
            return normalized.split(':')[0]
        
        return normalized
    
    def _validate_token_format(self, token: str) -> bool:
        """Validate token format (verify-<16 hex chars>)."""
        return bool(self.token_pattern.match(token))


if __name__ == "__main__":
    # Test consent token system
    from .config import Config
    
    config = Config.load()
    consent = ConsentToken(config)
    
    # Generate token
    domain = "example.com"
    token, expiration = consent.generate_token(domain)
    print(f"Generated: {token}")
    print(f"Expires: {expiration}")
    
    # Print instructions
    consent.print_instructions(domain, token)
    
    # Test verification (will fail unless token is actually placed)
    print("\n--- Testing HTTP Verification ---")
    success, result = consent.verify_http(domain, token)
    print(f"Success: {success}")
    print(f"Result: {result}")
    
    print("\n--- Testing DNS Verification ---")
    success, result = consent.verify_dns(domain, token)
    print(f"Success: {success}")
    print(f"Result: {result}")