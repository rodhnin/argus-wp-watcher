"""
Argus Database Module

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import sqlite3
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager
from urllib.parse import urlparse

from .logging import get_logger
from .config import get_config

logger = get_logger(__name__)


class Database:
    """
    SQLite database manager for Argos suite.
    """

    def _normalize_domain(self, domain: str) -> str:
        """
        Normaliza dominio (quita esquema y path, conserva puerto, minúsculas).
        """
        if '://' in domain:
            parsed = urlparse(domain)
            domain = parsed.netloc or parsed.path
        if '/' in domain:
            domain = domain.split('/')[0]
        return domain.strip().lower()
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file (default from config)
        """
        config = get_config()
        self.db_path = db_path or config.database
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.readonly_mode = False  # BUG-017: Track if DB is read-only
        
        # Check if database exists and is valid
        if self.db_path.exists():
            if not self._validate_database():
                # Database is corrupted - handle it
                logger.warning(f"Database corruption detected: {self.db_path}")
                self._handle_corruption()
                # Now create fresh database
                self._init_schema()
            else:
                # Check write permissions
                if not self._check_write_permissions():
                    logger.warning(f"Database is read-only: {self.db_path}")
                    logger.warning("Scan will continue but results won't be saved to database")
                    self.readonly_mode = True
                else:
                    logger.debug(f"Using existing database: {self.db_path}")
        else:
            # No database exists - create new one
            logger.info(f"Creating new database: {self.db_path}")
            self._init_schema()
    
    def _validate_database(self) -> bool:
        """
        Validate database file integrity.
        
        Returns:
            True if database is valid, False if corrupted
        """
        try:
            # Try to open and query the database
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Simple integrity check - try to read from sqlite_master
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1")
            cursor.fetchone()
            
            conn.close()
            return True
        
        except sqlite3.DatabaseError as e:
            # Database is corrupted
            logger.error(f"Database validation failed: {e}")
            return False
        
        except Exception as e:
            # Other error (permissions, etc.)
            logger.error(f"Database validation error: {e}")
            return False
    
    def _check_write_permissions(self) -> bool:
        """
        Check if database has write permissions.
        
        Returns:
            True if writable, False if read-only
        """
        try:
            # Try a simple write operation
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Try to create a temp table (will be rolled back)
            cursor.execute("CREATE TEMP TABLE _permission_test (id INTEGER)")
            cursor.execute("DROP TABLE _permission_test")
            
            conn.close()
            return True
        
        except sqlite3.OperationalError as e:
            # Permission denied or read-only
            if "readonly" in str(e).lower() or "attempt to write" in str(e).lower():
                return False
            # Other operational errors should raise
            logger.error(f"Database permission check failed: {e}")
            return False
        
        except Exception as e:
            # Unexpected error
            logger.error(f"Unexpected error checking DB permissions: {e}")
            return False
    
    def _handle_corruption(self):
        """
        Handle corrupted database by backing it up and preparing for fresh DB.
        """
        # Generate backup filename with timestamp
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_path = self.db_path.with_suffix(f'.db.corrupted.{timestamp}')
        
        try:
            # Move corrupted database to backup location
            shutil.move(str(self.db_path), str(backup_path))
            logger.warning(f"Corrupted database moved to: {backup_path}")
            logger.warning("Creating fresh database - scan history lost")
            
        except Exception as e:
            logger.error(f"Failed to backup corrupted database: {e}")
            # Try to delete it instead
            try:
                self.db_path.unlink()
                logger.warning(f"Corrupted database deleted: {self.db_path}")
            except Exception as delete_error:
                logger.error(f"Failed to delete corrupted database: {delete_error}")
                raise RuntimeError(f"Cannot recover from database corruption: {delete_error}")
    
    @contextmanager
    def _get_connection(self):
        """
        Context manager for database connections.
        
        Handles database errors gracefully.
        """
        conn = None
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row  # Access columns by name
            conn.execute("PRAGMA foreign_keys = ON")
            yield conn
            conn.commit()
        
        except sqlite3.OperationalError as e:
            # Handle read-only database during operation
            if conn:
                conn.rollback()
            
            if "readonly" in str(e).lower() or "attempt to write" in str(e).lower():
                logger.warning(f"Database write failed (read-only): {e}")
                # Set readonly mode flag
                self.readonly_mode = True
                # Don't raise - allow operation to continue
                return
            
            # Other operational errors should raise
            logger.error(f"Database operational error: {e}")
            raise
        
        except sqlite3.DatabaseError as e:
            # Database error (corruption detected during operation)
            if conn:
                conn.rollback()
            
            logger.error(f"Database error during operation: {e}")
            
            # If this is a "file is not a database" error, we have runtime corruption
            if "not a database" in str(e).lower():
                logger.error("Runtime database corruption detected")
                if conn:
                    conn.close()
                
                # Handle corruption and recreate
                self._handle_corruption()
                self._init_schema()
                
                # Raise a more user-friendly error
                raise RuntimeError(
                    "Database corruption detected and recovered. "
                    "Previous scan history has been backed up. "
                    "Please retry the operation."
                )
            
            # Other database errors
            raise
        
        except Exception as e:
            # Other errors
            if conn:
                conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        
        finally:
            if conn:
                conn.close()
    
    def _init_schema(self):
        """Initialize database schema from migrate.sql."""
        schema_path = Path(__file__).parent.parent.parent / "db" / "migrate.sql"
        
        if not schema_path.exists():
            logger.error(f"Schema file not found: {schema_path}")
            raise FileNotFoundError(f"Database schema missing: {schema_path}")
        
        with schema_path.open('r') as f:
            schema_sql = f.read()
        
        with self._get_connection() as conn:
            conn.executescript(schema_sql)
        
        logger.info("Database schema initialized successfully")
    
    # =========================================================================
    # CLIENT OPERATIONS
    # =========================================================================
    
    def add_client(
        self,
        name: str,
        domain: str,
        contact_email: Optional[str] = None,
        notes: Optional[str] = None
    ) -> int:
        """
        Add a new client/project.
        
        Args:
            name: Client or project name
            domain: Primary domain
            contact_email: Contact email
            notes: Additional notes
        
        Returns:
            client_id (0 if readonly)
        """
        if self.readonly_mode:
            logger.debug(f"Skipping add_client (readonly mode): {name}")
            return 0
        client_id = 0
        domain = self._normalize_domain(domain) 
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO clients (name, domain, contact_email, notes)
                VALUES (?, ?, ?, ?)
                """,
                (name, domain, contact_email, notes)
            )
            client_id = cursor.lastrowid
            logger.info(f"Added client: {name} (ID: {client_id})")
        
        return client_id
    
    def get_client_by_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get client by domain."""
        domain = self._normalize_domain(domain)
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM clients WHERE domain = ? LIMIT 1",
                (domain,)
            )
            row = cursor.fetchone()
        
        return dict(row) if row else None
    
    def list_clients(self) -> List[Dict[str, Any]]:
        """List all clients."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM clients ORDER BY created_at DESC")
            rows = cursor.fetchall()
        
        return [dict(row) for row in rows]
    
    # =========================================================================
    # CONSENT TOKEN OPERATIONS
    # =========================================================================
    
    def save_token(
        self,
        domain: str,
        token: str,
        method: str,
        expires_at: datetime
    ) -> int:
        """
        Save a generated consent token.
        
        Args:
            domain: Target domain
            token: Generated token
            method: 'http' or 'dns'
            expires_at: Token expiration datetime
        
        Returns:
            token_id (0 if readonly)
        """
        if self.readonly_mode:
            logger.debug(f"Skipping save_token (readonly mode): {domain}")
            return 0
        token_id = 0
        domain = self._normalize_domain(domain)
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO consent_tokens (domain, token, method, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (domain, token, method, expires_at.isoformat())
            )
            token_id = cursor.lastrowid
            logger.info(f"Saved consent token for {domain}: {token}")
        
        return token_id
    
    def verify_token(
        self,
        domain: str,
        token: str,
        method: str,
        proof_path: Optional[str] = None
    ) -> bool:
        """
        Mark a token as verified.
        
        Args:
            domain: Target domain
            token: Token to verify
            method: Verification method ('http' or 'dns')
            proof_path: Path to verification proof file
        
        Returns:
            True if token was found and updated (False if readonly)
        """
        if self.readonly_mode:
            logger.debug("Skipping verify_token (readonly mode)")
            return False
            
        domain = self._normalize_domain(domain)
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE consent_tokens
                SET verified_at = ?,
                    method = ?,
                    proof_path = ?
                WHERE domain = ? AND token = ? AND verified_at IS NULL
                """,
                (datetime.now(timezone.utc).isoformat(), method, proof_path, domain, token)
            )
            updated = cursor.rowcount > 0
        
        if updated:
            logger.info(f"✓ Token verified for {domain}: {token} via {method.upper()}")
        else:
            logger.warning(f"Token not found or already verified: {token}")
        
        return updated
    
    def is_domain_verified(self, domain: str) -> bool:
        """
        Check if domain has a valid (non-expired) verified token.
        
        Args:
            domain: Domain to check
        
        Returns:
            True if domain has valid consent
        """
        now = datetime.now(timezone.utc).isoformat()
        domain = self._normalize_domain(domain)
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT COUNT(*) FROM consent_tokens
                WHERE domain = ?
                  AND verified_at IS NOT NULL
                  AND expires_at > ?
                """,
                (domain, now)
            )
            count = cursor.fetchone()[0]
        
        return count > 0
    
    def get_verified_tokens(self, domain: str) -> List[Dict[str, Any]]:
        """Get all verified tokens for a domain (including expired)."""
        domain = self._normalize_domain(domain)
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM consent_tokens
                WHERE domain = ? AND verified_at IS NOT NULL
                ORDER BY verified_at DESC
                """,
                (domain,)
            )
            rows = cursor.fetchall()
        return [dict(row) for row in rows]
    
    # =========================================================================
    # SCAN OPERATIONS
    # =========================================================================
    
    def start_scan(
        self,
        tool: str,
        domain: str,
        target_url: str,
        mode: str,
        client_id: Optional[int] = None
    ) -> int:
        """
        Record the start of a scan.
        
        Args:
            tool: 'argus', 'hephaestus', or 'pythia'
            domain: Domain being scanned
            target_url: Full target URL
            mode: 'safe' or 'aggressive'
            client_id: Associated client ID (optional)
        
        Returns:
            scan_id (0 if readonly)
        """
        if self.readonly_mode:
            logger.debug(f"Skipping start_scan (readonly mode): {domain}")
            return 0
        
        scan_id = 0  # Initialize in case write fails
        domain = self._normalize_domain(domain)
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scans (tool, client_id, domain, target_url, mode, status)
                VALUES (?, ?, ?, ?, ?, 'running')
                """,
                (tool, client_id, domain, target_url, mode)
            )
            scan_id = cursor.lastrowid
            logger.info(f"Started scan {scan_id}: {tool} on {domain} ({mode} mode)")
        
        return scan_id
    
    def finish_scan(
        self,
        scan_id: int,
        status: str = 'completed',
        report_json_path: Optional[str] = None,
        report_html_path: Optional[str] = None,
        summary: Optional[Dict[str, int]] = None,
        error_message: Optional[str] = None
    ):
        """
        Mark scan as finished.
        
        Args:
            scan_id: Scan ID to update
            status: 'completed', 'failed', or 'aborted'
            report_json_path: Path to JSON report
            report_html_path: Path to HTML report
            summary: Severity counts dict
            error_message: Error message if failed
        """
        if self.readonly_mode or scan_id == 0:
            logger.debug("Skipping finish_scan (readonly mode or scan_id=0)")
            return
        
        summary_json = json.dumps(summary) if summary else None
        
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE scans
                SET finished_at = ?,
                    status = ?,
                    report_json_path = ?,
                    report_html_path = ?,
                    summary = ?,
                    error_message = ?
                WHERE scan_id = ?
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    status,
                    report_json_path,
                    report_html_path,
                    summary_json,
                    error_message,
                    scan_id
                )
            )
        
        logger.info(f"Finished scan {scan_id}: {status}")
    
    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """Get scan by ID."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?",
                (scan_id,)
            )
            row = cursor.fetchone()
        
        if row:
            scan = dict(row)
            # Parse summary JSON
            if scan['summary']:
                scan['summary'] = json.loads(scan['summary'])
            return scan
        return None
    
    def list_scans(
        self,
        tool: Optional[str] = None,
        domain: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        List recent scans with optional filters.
        
        Args:
            tool: Filter by tool name
            domain: Filter by domain
            limit: Maximum number of results
        
        Returns:
            List of scan dictionaries
        """
        query = "SELECT * FROM scans WHERE 1=1"
        params = []
        
        if tool:
            query += " AND tool = ?"
            params.append(tool)
        
        if domain:
            domain = self._normalize_domain(domain)
            query += " AND domain = ?"
            params.append(domain)
        
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)
        
        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
        
        scans = []
        for row in rows:
            scan = dict(row)
            if scan['summary']:
                scan['summary'] = json.loads(scan['summary'])
            scans.append(scan)
        
        return scans
    
    # =========================================================================
    # FINDING OPERATIONS
    # =========================================================================
    
    def add_finding(
        self,
        scan_id: int,
        finding_code: str,
        title: str,
        severity: str,
        confidence: str,
        recommendation: str,
        evidence_type: Optional[str] = None,
        evidence_value: Optional[str] = None,
        references: Optional[List[str]] = None
    ) -> int:
        """
        Add a finding to a scan.
        
        Args:
            scan_id: Parent scan ID
            finding_code: Finding identifier (e.g., ARGUS-WP-001)
            title: Finding title
            severity: critical|high|medium|low|info
            confidence: high|medium|low
            recommendation: Remediation guidance
            evidence_type: url|header|body|path|screenshot|other
            evidence_value: Evidence content
            references: List of reference URLs
        
        Returns:
            finding_id (0 if readonly or scan_id=0)
        """
        if self.readonly_mode or scan_id == 0:
            logger.debug(f"Skipping add_finding (readonly mode or scan_id=0): {finding_code}")
            return 0

        finding_id = 0
        
        references_json = json.dumps(references) if references else None
        
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO findings (
                    scan_id, finding_code, title, severity, confidence,
                    evidence_type, evidence_value, recommendation, "references"
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id, finding_code, title, severity, confidence,
                    evidence_type, evidence_value, recommendation, references_json
                )
            )
            finding_id = cursor.lastrowid
            logger.debug(f"Added finding {finding_code} to scan {scan_id}")
        
        return finding_id
    
    def get_findings(self, scan_id: int) -> List[Dict[str, Any]]:
        """Get all findings for a scan."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY created_at",
                (scan_id,)
            )
            rows = cursor.fetchall()
        
        findings = []
        for row in rows:
            finding = dict(row)
            # Access via dict key is OK - doesn't need quotes
            if finding['references']:
                finding['references'] = json.loads(finding['references'])
            findings.append(finding)
        
        return findings
    
    def get_critical_findings(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent critical/high findings across all scans."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT f.*, s.tool, s.domain, s.started_at
                FROM findings f
                JOIN scans s ON f.scan_id = s.scan_id
                WHERE f.severity IN ('critical', 'high')
                ORDER BY f.created_at DESC
                LIMIT ?
                """,
                (limit,)
            )
            rows = cursor.fetchall()
        
        return [dict(row) for row in rows]
    
    # =========================================================================
    # STATISTICS & REPORTS
    # =========================================================================
    
    def get_scan_summary(self, scan_id: int) -> Dict[str, Any]:
        """
        Get summary statistics for a scan.
        
        Returns:
            Dict with counts by severity and total findings
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT severity, COUNT(*) as count
                FROM findings
                WHERE scan_id = ?
                GROUP BY severity
                """,
                (scan_id,)
            )
            rows = cursor.fetchall()
        
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for row in rows:
            summary[row['severity']] = row['count']
        
        summary['total'] = sum(summary.values())
        return summary


# Global database instance
_db_instance: Optional[Database] = None


def get_db() -> Database:
    """Get the global database instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance


if __name__ == "__main__":
    # Test database operations
    db = Database(Path("/tmp/argus_test.db"))
    
    # Test client
    client_id = db.add_client(
        name="Test Client",
        domain="example.com",
        contact_email="test@example.com"
    )
    print(f"Created client: {client_id}")
    
    # Test consent token
    expires = datetime.now(timezone.utc) + timedelta(hours=48)
    token_id = db.save_token("example.com", "verify-abc123", "http", expires)
    print(f"Saved token: {token_id}")
    
    db.verify_token("example.com", "verify-abc123", "/tmp/proof.txt")
    is_verified = db.is_domain_verified("example.com")
    print(f"Domain verified: {is_verified}")
    
    # Test scan
    scan_id = db.start_scan("argus", "example.com", "https://example.com", "safe", client_id)
    print(f"Started scan: {scan_id}")
    
    # Add findings
    db.add_finding(
        scan_id, "ARGUS-WP-001", "WordPress version disclosed",
        "medium", "high", "Hide version information"
    )
    
    summary = db.get_scan_summary(scan_id)
    db.finish_scan(scan_id, "completed", "/tmp/report.json", None, summary)
    
    # List scans
    scans = db.list_scans(limit=10)
    print(f"\nRecent scans: {len(scans)}")
    for scan in scans:
        print(f"  - {scan['tool']}: {scan['domain']} ({scan['status']})")