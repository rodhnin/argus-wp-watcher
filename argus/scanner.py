"""
Argus WordPress Scanner

Main orchestrator that coordinates all security checks.

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import time
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests  # BUG-015: Import for exception handling

from .core.logging import get_logger
from .core.config import get_config
from .core.db import get_db
from .core.report import ReportGenerator
from .core.ai import analyze_report
from .core.http_client import create_http_client

from .checks.fingerprint import WordPressFingerprint
from .checks.plugins import PluginThemeEnumerator
from .checks.files import SensitiveFilesChecker
from .checks.users import UserEnumerator
from .checks.headers import SecurityHeadersChecker
from .checks.config import ConfigChecker

logger = get_logger(__name__)


class WordPressScanner:
    """
    Main WordPress security scanner.
    """
    
    def __init__(self, config=None):
        self.config = config or get_config()
        self.db = get_db()
        self.report_gen = ReportGenerator(self.config)
        
        logger.info("WordPress scanner initialized")
    
    def scan(
        self,
        target: str,
        mode: str = 'safe',
        use_ai: bool = False,
        ai_tone: str = 'both'
    ) -> Dict:
        """
        Execute full WordPress security scan.
        
        Args:
            target: Target URL or domain
            mode: 'safe' (non-intrusive) or 'aggressive' (requires consent)
            use_ai: Enable AI analysis
            ai_tone: 'technical', 'non_technical', or 'both'
        
        Returns:
            Scan results dictionary with report path
        """
        start_time = time.time()
        
        # Normalize target
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        domain = urlparse(target).netloc or target
        
        logger.info(f"=" * 70)
        logger.info(f"Starting Argus scan: {target}")
        logger.info(f"Mode: {mode.upper()}")
        logger.info(f"AI Analysis: {'Enabled' if use_ai else 'Disabled'}")
        logger.info(f"Parallel Phases: ENABLED (Thread Pool: {self.config.max_workers} workers)")
        logger.info(f"=" * 70)
        
        # Create HTTP client with rate limiting
        http_client = create_http_client(mode=mode, config=self.config)
        
        # Initialize check modules with HTTP client
        self.fingerprint = WordPressFingerprint(self.config, http_client)
        self.plugins = PluginThemeEnumerator(self.config, http_client)
        self.files = SensitiveFilesChecker(self.config, http_client, target)
        self.users = UserEnumerator(self.config, http_client)
        self.headers = SecurityHeadersChecker(self.config, http_client)
        self.config_checker = ConfigChecker(self.config, http_client)
        
        # Verify consent for aggressive/AI modes
        if mode == 'aggressive' or use_ai:
            if not self.db.is_domain_verified(domain):
                logger.error(f"Domain {domain} not verified for {mode} mode")
                raise PermissionError(
                    f"Domain {domain} requires consent verification. "
                    f"Run: argus --gen-consent {domain}"
                )
        
        # Get or create client
        client = self.db.get_client_by_domain(domain)
        client_id = client['client_id'] if client else None
        
        # Start scan record
        scan_id = self.db.start_scan(
            tool='argus',
            domain=domain,
            target_url=target,
            mode=mode,
            client_id=client_id
        )
        
        logger.info(f"Scan ID: {scan_id}")

        # Store scan_id as instance variable (for cleanup on interrupt)
        self.scan_id = scan_id
        
        # Collect all findings
        all_findings = []
        requests_count = 0
        
        try:
            # Phase 1: Fingerprinting (MUST run first)
            logger.info("\n[Phase 1/6] WordPress Fingerprinting...")
            
            # Catch connection errors separately from "not WordPress"
            try:
                fp_findings = self.fingerprint.scan(target)
                all_findings.extend(fp_findings)
                requests_count += 5
            
            except requests.exceptions.RequestException as e:
                # Connection error (timeout, DNS, refused, etc.)
                error_msg = str(e)
                logger.error(f"Connection failed: {error_msg}")
                
                # Determine error type for user-friendly message
                if "timed out" in error_msg.lower() or "timeout" in error_msg.lower():
                    error_type = "Connection timeout"
                    user_msg = f"Target {target} did not respond within timeout period"
                elif "name resolution" in error_msg.lower() or "nameresolutionerror" in error_msg.lower():
                    error_type = "DNS resolution failed"
                    user_msg = f"Could not resolve domain name: {domain}"
                elif "connection refused" in error_msg.lower():
                    error_type = "Connection refused"
                    user_msg = f"Target {target} refused connection (port may be closed)"
                elif "no route to host" in error_msg.lower():
                    error_type = "Network unreachable"
                    user_msg = f"Cannot reach {target} (network issue)"
                else:
                    error_type = "Connection error"
                    user_msg = f"Failed to connect to {target}"
                
                # Mark scan as failed in database
                self.db.finish_scan(
                    scan_id,
                    status='failed',
                    error_message=f"{error_type}: {error_msg}"
                )
                
                # Print clear error message
                print("\n" + "=" * 70)
                print(f"❌ SCAN FAILED: {error_type}")
                print("=" * 70)
                print(f"Target: {target}")
                print(f"Error: {user_msg}")
                print(f"\nDetails: {error_msg}")
                print("\nPossible causes:")
                if error_type == "Connection timeout":
                    print("  - Server is slow or unresponsive")
                    print("  - Firewall blocking requests")
                    print("  - Try increasing timeout: --timeout 60")
                elif error_type == "DNS resolution failed":
                    print("  - Domain does not exist")
                    print("  - DNS server issue")
                    print("  - Check domain spelling")
                elif error_type == "Connection refused":
                    print("  - Service not running on target port")
                    print("  - Firewall blocking connections")
                    print("  - Wrong port number")
                elif error_type == "Network unreachable":
                    print("  - Target IP address unreachable")
                    print("  - Network connectivity issue")
                    print("  - VPN or routing problem")
                else:
                    print("  - Check network connectivity")
                    print("  - Verify target URL is correct")
                    print("  - Check firewall settings")
                print("=" * 70 + "\n")
                
                # Return failure result
                duration = time.time() - start_time
                return {
                    'scan_id': scan_id,
                    'status': 'failed',
                    'error': error_type,
                    'error_message': error_msg,
                    'duration': duration
                }
            
            # Check if WordPress was detected (exact match to avoid false positive)
            wp_finding = next((f for f in fp_findings if f.get('id') == 'ARGUS-WP-000'), None)
            
            if wp_finding:
                # Check exact title to distinguish "WordPress detected" from "WordPress not detected"
                is_wp = wp_finding.get('title', '').lower() == 'wordpress detected'
            else:
                is_wp = False
            
            if not is_wp:
                logger.warning("WordPress not detected. Aborting scan.")
                
                # Finalize with limited findings (only fingerprint phase)
                result = self._finalize_scan(
                    scan_id, all_findings, start_time, requests_count, 
                    status='aborted', target=target, mode=mode, 
                    use_ai=False, ai_tone=None
                )
                
                # Print clear abort message
                print("\n" + "=" * 70)
                print("❌ SCAN ABORTED: Target is not a WordPress site")
                print("=" * 70)
                print(f"Target: {target}")
                print(f"WordPress indicators: 0/5 found")
                print(f"Duration: {result['duration']:.2f}s")
                print("\nArgus is optimized for WordPress scanning.")
                print("Please verify the target URL is correct.")
                print("=" * 70 + "\n")
                
                return {
                    'scan_id': scan_id,
                    'status': 'aborted',
                    'reason': 'not_wordpress',
                    'wordpress_detected': False,
                    'findings_count': len(all_findings),
                    'duration': result['duration']
                }
            
            # Phases 2-6 now execute IN PARALLEL
            logger.info("\n[Phases 2-6] Running parallel security checks...")
            logger.info(f"Thread pool: {self.config.max_workers} workers")
            
            # Define phases to run concurrently
            phases = {
                'files': (self.files.scan, "Sensitive Files", len(self.config.wp_common_paths)),
                'plugins': (self.plugins.scan, "Plugins & Themes", 
                           self.config.wp_max_plugins_check + self.config.wp_max_themes_check),
                'users': (self.users.scan, "Users", self.config.wp_max_users_check + 2),
                'headers': (self.headers.scan, "Security Headers", 2),
                'config': (self.config_checker.scan, "Configuration", 10),
            }
            
            # Execute phases concurrently
            phase_results = {}
            phase_start = time.time()
            
            with ThreadPoolExecutor(max_workers=min(5, self.config.max_workers)) as executor:
                # Submit all phases
                future_to_phase = {
                    executor.submit(scan_func, target): (phase_name, display_name, req_count)
                    for phase_name, (scan_func, display_name, req_count) in phases.items()
                }
                
                # Collect results as they complete
                for future in as_completed(future_to_phase):
                    phase_name, display_name, req_count = future_to_phase[future]
                    
                    try:
                        findings = future.result()
                        phase_results[phase_name] = {
                            'findings': findings,
                            'requests': req_count
                        }
                        logger.info(f"  ✓ {display_name}: {len(findings)} findings")
                    
                    except Exception as e:
                        logger.error(f"  ✗ {display_name} failed: {e}")
                        phase_results[phase_name] = {
                            'findings': [],
                            'requests': 0,
                            'error': str(e)
                        }
            
            phase_duration = time.time() - phase_start
            logger.info(f"\nParallel phases completed in {phase_duration:.2f}s")
            
            # Aggregate all findings
            for phase_name, result in phase_results.items():
                all_findings.extend(result['findings'])
                requests_count += result['requests']
            
            # Finalize scan
            result = self._finalize_scan(
                scan_id, all_findings, start_time, requests_count,
                status='completed', target=target, mode=mode,
                use_ai=use_ai, ai_tone=ai_tone
            )
            
            logger.info("\n" + "=" * 70)
            logger.info("Scan completed successfully!")
            logger.info(f"Total findings: {result['findings_count']}")
            logger.info(f"Duration: {result['duration']:.2f}s")
            logger.info(f"Report: {result['report_json']}")
            if result.get('report_html'):
                logger.info(f"HTML: {result['report_html']}")
            logger.info("=" * 70 + "\n")
            
            return result
        
        except KeyboardInterrupt:
            # ================================================================
            # Handle Ctrl+C gracefully - Update DB before exit
            # ================================================================
            logger.warning("Scan interrupted by user (KeyboardInterrupt)")
            duration = time.time() - start_time
            
            # Update database: mark scan as 'aborted'
            self.db.finish_scan(
                scan_id,
                status='aborted',
                error_message='Scan interrupted by user (Ctrl+C)'
            )
            
            logger.info(f"Scan {scan_id} marked as 'aborted' in database")
            
            # Re-raise to let cli.py handle exit code 130
            raise
        
        except Exception as e:
            logger.exception(f"Scan failed: {e}")
            
            # Mark scan as failed
            self.db.finish_scan(
                scan_id,
                status='failed',
                error_message=str(e)
            )
            
            raise
    
    def _finalize_scan(
        self,
        scan_id: int,
        findings: List[Dict],
        start_time: float,
        requests_count: int,
        status: str,
        target: str,
        mode: str,
        use_ai: bool = False,
        ai_tone: Optional[str] = None
    ) -> Dict:
        """
        Generate reports, save to DB, and optionally run AI analysis.
        
        Args:
            scan_id: Database scan ID
            findings: List of all findings
            start_time: Scan start timestamp
            requests_count: Total HTTP requests made
            status: 'completed', 'aborted', or 'failed'
            target: Target URL
            mode: Scan mode
            use_ai: Whether to run AI analysis
            ai_tone: AI tone (technical/non_technical/both)
        
        Returns:
            Result summary dictionary
        """
        duration = time.time() - start_time
        
        # Handle aborted scans (non-WordPress targets)
        if status == 'aborted':
            # Create minimal report for aborted scan
            report = self.report_gen.create_report(
                tool='argus',
                target=target,
                mode=mode,
                findings=findings,
                scan_duration=duration,
                requests_sent=requests_count,
                consent=None
            )
            
            # Save JSON only (no HTML for aborted scans)
            json_path = self.report_gen.save_json(report)
            
            # Save minimal findings to database
            for finding in findings:
                self.db.add_finding(
                    scan_id=scan_id,
                    finding_code=finding['id'],
                    title=finding['title'],
                    severity=finding['severity'],
                    confidence=finding['confidence'],
                    recommendation=finding['recommendation'],
                    evidence_type=finding.get('evidence', {}).get('type'),
                    evidence_value=finding.get('evidence', {}).get('value'),
                    references=finding.get('references')
                )
            
            # Mark scan as aborted in database
            self.db.finish_scan(
                scan_id,
                status='aborted',
                report_json_path=str(json_path),
                report_html_path=None,
                summary=report['summary']
            )
            
            return {
                'scan_id': scan_id,
                'status': 'aborted',
                'wordpress_detected': False,
                'findings_count': len(findings),
                'duration': duration,
                'report_json': str(json_path),
            }
        
        # For completed/failed scans, continue with full workflow
        # Get consent info if available
        domain = urlparse(target).netloc
        consent_info = None
        
        if mode == 'aggressive' or use_ai:
            verified_tokens = self.db.get_verified_tokens(domain)
            if verified_tokens:
                latest = verified_tokens[0]
                consent_info = {
                    'method': latest['method'],
                    'token': latest['token'],
                    'verified_at': latest['verified_at']
                }
        
        # Create report
        report = self.report_gen.create_report(
            tool='argus',
            target=target,
            mode=mode,
            findings=findings,
            scan_duration=duration,
            requests_sent=requests_count,
            consent=consent_info
        )
        
        # Run AI analysis if enabled (BEFORE saving reports)
        if use_ai:
            logger.info("\n[AI Analysis] Generating insights...")
            try:
                ai_analysis = analyze_report(report, tone=ai_tone, config=self.config)
                
                if ai_analysis:
                    # Add AI analysis to report dict
                    report['ai_analysis'] = ai_analysis
                    logger.info("✓ AI analysis completed")
            
            except Exception as e:
                logger.error(f"AI analysis failed: {e}")
        
        # Save JSON report ONCE (with or without AI)
        json_path = self.report_gen.save_json(report)
        
        # Generate HTML ONCE (with or without AI)
        html_path = None
        if self.config.generate_html:
            try:
                html_path = self.report_gen.generate_html(report, json_path)
            except Exception as e:
                logger.warning(f"HTML generation failed: {e}")
        
        # Save findings to database
        for finding in findings:
            self.db.add_finding(
                scan_id=scan_id,
                finding_code=finding['id'],
                title=finding['title'],
                severity=finding['severity'],
                confidence=finding['confidence'],
                recommendation=finding['recommendation'],
                evidence_type=finding.get('evidence', {}).get('type'),
                evidence_value=finding.get('evidence', {}).get('value'),
                references=finding.get('references')
            )
        
        # Get summary from report
        summary = report['summary']
        
        # Finish scan in database
        self.db.finish_scan(
            scan_id,
            status=status,
            report_json_path=str(json_path),
            report_html_path=str(html_path) if html_path else None,
            summary=summary
        )
        
        return {
            'scan_id': scan_id,
            'status': status,
            'wordpress_detected': True,
            'findings_count': len(findings),
            'summary': summary,
            'duration': duration,
            'requests_sent': requests_count,
            'report_json': str(json_path),
            'report_html': str(html_path) if html_path else None,
            'ai_analysis': bool(report.get('ai_analysis'))
        }


if __name__ == "__main__":
    # Test scanner
    from .core.config import Config
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python -m argus.scanner <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    config = Config.load()
    config.expand_paths()
    config.ensure_directories()
    
    scanner = WordPressScanner(config)
    
    try:
        result = scanner.scan(target, mode='safe', use_ai=False)
        print(f"\nScan completed: {result['report_json']}")
    
    except Exception as e:
        print(f"Scan failed: {e}")
        sys.exit(1)