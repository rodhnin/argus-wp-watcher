"""
Argus CLI - Command Line Interface

Main entry point for Argus WordPress security scanner.

Exit codes:
  0 - Success (scan completed)
  1 - Error (connection failed, permission denied, etc.)
  2 - Aborted (not WordPress)
  130 - User interrupted (Ctrl+C)

Usage:
    argus --target https://example.com [options]
    argus --gen-consent example.com
    argus --verify-consent http --domain example.com --token verify-abc123

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import sys
import argparse
from pathlib import Path
from typing import Optional

from .core.config import Config, get_config, set_config
from .core.logging import setup_logging, get_logger, set_verbosity
from .core.consent import ConsentToken
from .core.db import get_db
from .core.report import ReportGenerator

logger = get_logger(__name__)


def print_banner():
    """Display Argus ASCII art banner."""
    banner_path = Path(__file__).parent.parent / "assets" / "ascii.txt"
    
    try:
        with banner_path.open('r', encoding='utf-8') as f:
            print(f.read())
    except FileNotFoundError:
        # Fallback minimal banner
        print("=" * 70)
        print("ARGUS – WP Watch & Evidence Collector")
        print("by Rodney Dhavid Jimenez Chacin (rodhnin)")
        print("GitHub: https://github.com/rodhnin")
        print("=" * 70)
        print("\nUse only on authorized targets.")
        print("Verification required for aggressive or AI actions.\n")


def create_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(
        prog='argus',
        description='Argus – WordPress Security Scanner & Evidence Collector',
        epilog='For detailed documentation, visit: https://github.com/rodhnin/argus-wp-watcher',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Main scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument(
        '--target', '-t',
        type=str,
        metavar='URL',
        help='Target URL or domain to scan (e.g., https://example.com)'
    )
    scan_group.add_argument(
        '--safe',
        action='store_true',
        default=True,
        help='Use safe mode (non-intrusive checks only) [default]'
    )
    scan_group.add_argument(
        '--aggressive',
        action='store_true',
        help='Use aggressive mode (requires consent verification)'
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '--report-dir',
        type=Path,
        metavar='PATH',
        help='Directory to save reports (default: ~/.argus/reports)'
    )
    output_group.add_argument(
        '--html',
        action='store_true',
        help='Generate HTML report in addition to JSON'
    )
    output_group.add_argument(
        '--db',
        type=Path,
        metavar='PATH',
        help='SQLite database path (default: ~/.argos/argos.db)'
    )
    output_group.add_argument(
        '--diff',
        metavar='SCAN_ID',
        help='Compare this scan against a previous scan ID (use "last" for most recent). '
             'Adds a diff section to the report showing new, fixed, and persisting findings.'
    )
    
    # Verbosity options
    verbose_group = parser.add_argument_group('Logging & Verbosity')
    verbose_group.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='Increase verbosity (-v: INFO, -vv: DEBUG, -vvv: DEBUG with libs)'
    )
    verbose_group.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress console output (WARNING level only)'
    )
    verbose_group.add_argument(
        '--log-file',
        type=Path,
        metavar='PATH',
        help='Log file path (default: ~/.argus/argus.log)'
    )
    verbose_group.add_argument(
        '--log-json',
        action='store_true',
        help='Use JSON format for logs'
    )
    verbose_group.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    # AI options
    ai_group = parser.add_argument_group('AI Assistant (LangChain)')
    ai_group.add_argument(
        '--use-ai',
        action='store_true',
        help='Enable AI-powered analysis (requires verified consent)'
    )
    ai_group.add_argument(
        '--ai-tone',
        choices=['technical', 'non_technical', 'both'],
        default='both',
        help='AI report tone: technical, non_technical, or both [default: both]'
    )
    ai_group.add_argument(
        '--api-key-env',
        type=str,
        default='OPENAI_API_KEY',
        metavar='VAR',
        help='Environment variable for AI API key [default: OPENAI_API_KEY]'
    )
    ai_group.add_argument(
        '--ai-provider',
        choices=['openai', 'anthropic', 'ollama'],
        metavar='PROVIDER',
        help='AI provider override: openai, anthropic, or ollama'
    )
    ai_group.add_argument(
        '--ai-model',
        type=str,
        metavar='MODEL',
        help='AI model override (e.g. gpt-4o-mini-2024-07-18)'
    )
    ai_group.add_argument(
        '--ai-stream',
        action='store_true',
        help='Stream AI output token-by-token in real time'
    )
    ai_group.add_argument(
        '--ai-compare',
        type=str,
        metavar='PROVIDERS',
        help=(
            'Run analysis through multiple AI providers in parallel and compare results. '
            'Format: openai,anthropic or openai:gpt-4o-mini,anthropic:claude-3-5-haiku-20241022'
        )
    )
    ai_group.add_argument(
        '--ai-agent',
        action='store_true',
        help='Use AI agent mode with live tool calls: NVD CVE lookup and WPVulnerability.net plugin search'
    )
    ai_group.add_argument(
        '--ai-budget',
        type=float,
        metavar='USD',
        help='Maximum AI cost per scan in USD (enables budget tracking)'
    )
    
    # Consent token options
    consent_group = parser.add_argument_group('Consent Token Management')
    consent_group.add_argument(
        '--gen-consent',
        type=str,
        metavar='DOMAIN',
        help='Generate consent token for domain ownership verification'
    )
    consent_group.add_argument(
        '--verify-consent',
        choices=['http', 'dns'],
        metavar='METHOD',
        help='Verify consent token (http or dns)'
    )
    consent_group.add_argument(
        '--domain',
        type=str,
        metavar='DOMAIN',
        help='Domain for consent verification'
    )
    consent_group.add_argument(
        '--token',
        type=str,
        metavar='TOKEN',
        help='Consent token to verify (format: verify-<hex>)'
    )
    
    # WordPress-specific options
    wp_group = parser.add_argument_group('WordPress-Specific Options')
    wp_group.add_argument(
        '--enumerate',
        type=str,
        metavar='WHAT',
        help='Enumerate: plugins, themes, users (comma-separated, e.g., "p,t,u")'
    )
    wp_group.add_argument(
        '--max-plugins',
        type=int,
        metavar='N',
        help='Maximum plugins to enumerate (default: 100 in safe mode)'
    )
    wp_group.add_argument(
        '--max-users',
        type=int,
        metavar='N',
        help='Maximum users to enumerate (default: 10 in safe mode)'
    )
    
    # Advanced options
    advanced_group = parser.add_argument_group('Advanced Options')
    advanced_group.add_argument(
        '--rate',
        type=float,
        metavar='RATE',
        help='Request rate limit in req/sec (default: 5.0 safe, 10.0 aggressive)'
    )
    advanced_group.add_argument(
        '--timeout',
        type=int,
        metavar='SEC',
        help='HTTP timeout in seconds (default: 30)'
    )
    advanced_group.add_argument(
        '--user-agent',
        type=str,
        metavar='UA',
        help='Custom User-Agent string'
    )
    advanced_group.add_argument(
        '--no-verify-ssl',
        action='store_true',
        help='Disable SSL certificate verification'
    )
    advanced_group.add_argument(
        '--threads',
        type=int,
        metavar='N',
        help='Number of concurrent threads (default: 5)'
    )
    
    # Miscellaneous
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 0.2.0'
    )
    
    return parser


def _parse_compare_arg(compare_str: str):
    """
    Parse --ai-compare argument into list of {provider, model} dicts.

    Formats accepted:
      "openai,ollama"
      "openai:gpt-4o-mini-2024-07-18,anthropic:claude-3-5-haiku-20241022"
      "all"  -> raises ValueError (requires explicit providers)
    """
    DEFAULT_MODELS = {
        'openai':    'gpt-4o-mini-2024-07-18',
        'anthropic': 'claude-3-5-haiku-20241022',
        'ollama':    'llama3.2',
    }
    providers = []
    for entry in compare_str.split(','):
        entry = entry.strip()
        if ':' in entry:
            prov, model = entry.split(':', 1)
        else:
            prov  = entry
            model = DEFAULT_MODELS.get(prov, '')
            if not model:
                raise ValueError(
                    f"Unknown provider '{prov}' in --ai-compare. "
                    f"Supported: {', '.join(DEFAULT_MODELS)}"
                )
        providers.append({'provider': prov.strip(), 'model': model.strip()})
    return providers


def handle_gen_consent(args, config: Config):
    """Handle consent token generation."""
    consent = ConsentToken(config)
    token, expiration = consent.generate_token(args.gen_consent)
    
    # Save to database with method=NULL (pending verification)
    db = get_db()
    db.save_token(args.gen_consent, token, None, expiration)
    
    # Print instructions
    consent.print_instructions(args.gen_consent, token)
    
    return 0


def handle_verify_consent(args, config: Config):
    """Handle consent token verification."""
    if not args.domain or not args.token:
        logger.error("--verify-consent requires --domain and --token")
        return 1
    
    consent = ConsentToken(config)
    method = args.verify_consent
    
    logger.info(f"Verifying consent token for {args.domain} via {method.upper()}")
    
    success, result = consent.verify_with_retry(method, args.domain, args.token)
    
    if success:
        # Save proof
        proof_path = consent.save_proof(args.domain, args.token, method, result)
        
        # Update database with verification and method
        db = get_db()
        db.verify_token(args.domain, args.token, method, str(proof_path))
        
        print("\n" + "="*70)
        print("✓ CONSENT VERIFICATION SUCCESSFUL")
        print("="*70)
        print(f"Domain: {args.domain}")
        print(f"Token: {args.token}")
        print(f"Method: {method.upper()}")
        print(f"Proof: {proof_path}")
        print("\nYou can now use --aggressive and --use-ai modes for this domain.")
        print("="*70 + "\n")
        
        return 0
    else:
        print("\n" + "="*70)
        print("✗ CONSENT VERIFICATION FAILED")
        print("="*70)
        print(f"Domain: {args.domain}")
        print(f"Token: {args.token}")
        print(f"Method: {method.upper()}")
        print(f"Error: {result}")
        print("\nPlease check the token placement and try again.")
        print("="*70 + "\n")
        
        return 1


def handle_scan(args, config: Config):
    """
    Handle main scan operation.
    
    Returns:
        Exit code (0=success, 1=error, 2=aborted)
    """
    if not args.target:
        logger.error("--target is required for scanning")
        return 1
    
    # Determine scan mode
    if args.aggressive:
        mode = 'aggressive'
    else:
        mode = 'safe'
    
    # Check if high rate requires consent (>= 10 req/s = aggressive)
    effective_rate = None
    if args.rate is not None:
        effective_rate = args.rate
    elif mode == 'aggressive':
        effective_rate = config.rate_limit_aggressive
    else:
        effective_rate = config.rate_limit_safe
    
    # If rate >= 10 req/s, treat as aggressive (requires consent)
    if effective_rate >= 10.0:
        logger.info(f"High rate limit detected ({effective_rate} req/s), requiring consent verification")
        
        # Extract domain for consent check
        from urllib.parse import urlparse
        
        # Normalize target
        target = args.target
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        domain = urlparse(target).netloc or target
        
        # Get database instance
        from .core.db import get_db
        db = get_db()
        
        # Check if domain is verified
        if not db.is_domain_verified(domain):
            logger.error(f"High rate ({effective_rate} req/s) requires consent verification for {domain}")
            print(f"\n{'='*70}")
            print(f"ERROR: Rate limit {effective_rate} req/s requires consent verification")
            print(f"{'='*70}")
            print(f"Domain: {domain}")
            print(f"Rate: {effective_rate} req/s (>= 10 req/s is considered aggressive)")
            print(f"\nHigh rate limits can overwhelm servers and require authorization.")
            print(f"\nTo authorize high-rate scanning:")
            print(f"  1. Generate consent token: argus --gen-consent {domain}")
            print(f"  2. Place token file on target server")
            print(f"  3. Verify consent: argus --verify-consent http --domain {domain} --token <token>")
            print(f"{'='*70}\n")
            return 1
    
    # Import scanner
    from .scanner import WordPressScanner
    
    try:
        scanner = WordPressScanner(config)
        
        # Run scan
        # Parse --ai-compare into list of provider configs
        compare_providers = None
        if args.use_ai and args.ai_compare:
            compare_providers = _parse_compare_arg(args.ai_compare)

        result = scanner.scan(
            target=args.target,
            mode=mode,
            use_ai=args.use_ai,
            ai_tone=args.ai_tone if args.use_ai else None,
            compare_providers=compare_providers,
            use_agent=args.ai_agent if args.use_ai else False,
            diff_scan_id=args.diff if hasattr(args, 'diff') else None,
        )
        
        # Return appropriate exit code based on scan status
        if result.get('status') == 'failed':
            # Connection error, timeout, etc.
            logger.error(f"Scan failed: {result.get('error', 'Unknown error')}")
            return 1  # Exit code 1 = error
        
        elif result.get('status') == 'aborted':
            # Not WordPress (already printed message in scanner)
            logger.warning(f"Scan aborted: {result.get('reason', 'unknown')}")
            return 2  # Exit code 2 = aborted (non-WordPress)
        
        # Scan completed successfully
        print("\n" + "="*70)
        print("SCAN COMPLETE")
        print("="*70)
        print(f"Status:   {result['status']}")
        print(f"Findings: {result['findings_count']}")
        print(f"Duration: {result['duration']:.2f}s")
        if result.get('ai_cost_usd') is not None:
            print(f"AI Cost:  ${result['ai_cost_usd']:.4f} ({result.get('ai_model', '')})")
        print(f"\nReports generated:")
        print(f"  JSON: {result['report_json']}")
        if result.get('report_html'):
            print(f"  HTML: {result['report_html']}")
        print("="*70 + "\n")
        
        return 0  # Exit code 0 = success
    
    except PermissionError as e:
        logger.error(str(e))
        return 1  # Exit code 1 = permission error
    
    except Exception as e:
        logger.exception(f"Scan failed: {e}")
        return 1  # Exit code 1 = unexpected error


def main(argv=None):
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)
    
    # Print banner (unless quiet)
    if not args.quiet:
        print_banner()
    
    # Load configuration
    cli_overrides = {}
    
    if args.report_dir:
        cli_overrides.setdefault('paths', {})['report_dir'] = str(args.report_dir)
    
    if args.db:
        cli_overrides.setdefault('paths', {})['database'] = str(args.db)
    
    if args.log_file:
        cli_overrides.setdefault('paths', {})['log_file'] = str(args.log_file)
    
    # Process --html flag
    if args.html:
        cli_overrides.setdefault('reporting', {}).setdefault('format', {})['html'] = True
    
    # Validate and process --rate flag
    if args.rate is not None:
        if args.rate <= 0:
            logger.error(f"Invalid rate limit: {args.rate}. Must be positive (> 0).")
            print(f"ERROR: --rate must be a positive number (got {args.rate})")
            return 1
        
        cli_overrides.setdefault('scan', {}).setdefault('rate_limit', {})
        if args.aggressive:
            cli_overrides['scan']['rate_limit']['aggressive_mode'] = args.rate
        else:
            cli_overrides['scan']['rate_limit']['safe_mode'] = args.rate
        
        logger.debug(f"Rate limit override: {args.rate} req/s")
    
    if args.timeout:
        cli_overrides.setdefault('scan', {}).setdefault('timeout', {})
        cli_overrides['scan']['timeout']['connect'] = args.timeout
        cli_overrides['scan']['timeout']['read'] = args.timeout
    
    if args.user_agent:
        cli_overrides.setdefault('scan', {})['user_agent'] = args.user_agent
    
    if args.no_verify_ssl:
        cli_overrides.setdefault('scan', {})['verify_ssl'] = False
    
    if args.threads is not None:
        if args.threads <= 0:
            logger.error(f"Invalid thread count: {args.threads}. Must be positive (> 0).")
            print(f"ERROR: --threads must be a positive number (got {args.threads})")
            return 1
        
        cli_overrides.setdefault('advanced', {})['max_workers'] = args.threads
        logger.debug(f"Thread pool size override: {args.threads} workers")
    
    if args.use_ai:
        cli_overrides.setdefault('ai', {})['enabled'] = True

    if args.ai_provider:
        cli_overrides.setdefault('ai', {}).setdefault('langchain', {})['provider'] = args.ai_provider

    if args.ai_model:
        cli_overrides.setdefault('ai', {}).setdefault('langchain', {})['model'] = args.ai_model

    if args.ai_stream:
        cli_overrides.setdefault('ai', {})['streaming'] = True

    if args.ai_agent:
        cli_overrides.setdefault('ai', {}).setdefault('agent', {})['enabled'] = True

    if args.ai_budget is not None:
        if args.ai_budget <= 0:
            print(f"ERROR: --ai-budget must be a positive number (got {args.ai_budget})")
            return 1
        cli_overrides.setdefault('ai', {}).setdefault('budget', {})['enabled'] = True
        cli_overrides['ai']['budget']['max_cost_per_scan'] = args.ai_budget

    config = Config.load(cli_overrides=cli_overrides)
    config.expand_paths()
    config.ensure_directories()
    set_config(config)
    
    # Setup logging
    if args.quiet:
        log_level = 'WARNING'
    else:
        # Map verbosity to log level
        verbosity_map = {0: 'WARNING', 1: 'INFO', 2: 'DEBUG', 3: 'DEBUG'}
        log_level = verbosity_map.get(args.verbose, 'DEBUG')
    
    setup_logging(
        level=log_level,
        log_file=config.log_file,
        json_format=args.log_json,
        use_colors=not args.no_color,
        redact_secrets=config.log_redact_secrets
    )
    
    if args.verbose >= 2:
        set_verbosity(args.verbose)
    
    logger.info(f"Argus v{config.version} starting")
    logger.debug(f"Configuration loaded from: {config.report_dir.parent}")
    
    # Route to appropriate handler
    try:
        if args.gen_consent:
            return handle_gen_consent(args, config)
        
        elif args.verify_consent:
            return handle_verify_consent(args, config)
        
        elif args.target:
            return handle_scan(args, config)
        
        else:
            parser.print_help()
            return 0
    
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user (Ctrl+C)\n")
        return 130  # Exit code 130 = Ctrl+C
    
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return 1  # Exit code 1 = unexpected error


if __name__ == '__main__':
    sys.exit(main())