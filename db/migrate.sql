-- Argos Suite Database Schema (shared by Argus, Hephaestus, Pythia, Asterion)
-- Version: 1
-- Location: ~/.argos/argos.db

-- ============================================================================
-- CLIENTS TABLE
-- Stores project/client information for organizing scans
-- ============================================================================
CREATE TABLE IF NOT EXISTS clients (
    client_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    domain TEXT NOT NULL,
    contact_email TEXT,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    UNIQUE(domain)
);

CREATE INDEX IF NOT EXISTS idx_clients_domain ON clients(domain);

-- ============================================================================
-- CONSENT TOKENS TABLE
-- Stores ownership verification tokens (HTTP file, DNS TXT, SSH SCAN)
-- Required for --aggressive and --use-ai modes
-- ============================================================================
CREATE TABLE IF NOT EXISTS consent_tokens (
    token_id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    method TEXT CHECK(method IN ('http', 'dns', 'ssh')),
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    verified_at TEXT DEFAULT NULL,
    proof_path TEXT DEFAULT NULL,  -- Path to saved verification evidence
    expires_at TEXT NOT NULL,       -- Tokens expire after 48h
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_consent_tokens_domain ON consent_tokens(domain);
CREATE INDEX IF NOT EXISTS idx_consent_tokens_token ON consent_tokens(token);
CREATE INDEX IF NOT EXISTS idx_consent_tokens_verified ON consent_tokens(verified_at);

-- ============================================================================
-- SCANS TABLE
-- Stores metadata for each scan execution
-- ============================================================================
CREATE TABLE IF NOT EXISTS scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL CHECK(tool IN ('argus', 'hephaestus', 'pythia', 'asterion')),
    client_id INTEGER DEFAULT NULL,
    domain TEXT NOT NULL,
    target_url TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('safe', 'aggressive')),
    started_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    finished_at TEXT DEFAULT NULL,
    status TEXT NOT NULL DEFAULT 'running' CHECK(status IN ('running', 'completed', 'failed', 'aborted')),
    report_json_path TEXT,
    report_html_path TEXT,
    summary TEXT,  -- JSON string with counts: {"critical": 0, "high": 1, "medium": 3, ...}
    error_message TEXT DEFAULT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_tool ON scans(tool);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

-- ============================================================================
-- FINDINGS TABLE
-- Stores individual vulnerability findings from scans
-- ============================================================================
CREATE TABLE IF NOT EXISTS findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    finding_code TEXT NOT NULL,  -- E.g., "ARGUS-WP-001"
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence TEXT NOT NULL CHECK(confidence IN ('high', 'medium', 'low')),
    evidence_type TEXT,  -- url, header, body, path, screenshot, other
    evidence_value TEXT,
    recommendation TEXT NOT NULL,
    "references" TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_code ON findings(finding_code);

-- ============================================================================
-- TRIGGERS
-- Auto-update timestamps
-- ============================================================================
CREATE TRIGGER IF NOT EXISTS update_clients_timestamp 
AFTER UPDATE ON clients
BEGIN
    UPDATE clients SET updated_at = datetime('now', 'utc') WHERE client_id = NEW.client_id;
END;

-- ============================================================================
-- VIEWS
-- Convenient queries for common operations
-- ============================================================================

-- Recent scans with summary
CREATE VIEW IF NOT EXISTS v_recent_scans AS
SELECT 
    s.scan_id,
    s.tool,
    s.domain,
    s.mode,
    s.started_at,
    s.finished_at,
    s.status,
    c.name AS client_name,
    s.summary,
    COUNT(f.finding_id) AS total_findings
FROM scans s
LEFT JOIN clients c ON s.client_id = c.client_id
LEFT JOIN findings f ON s.scan_id = f.scan_id
GROUP BY s.scan_id
ORDER BY s.started_at DESC;

-- Critical findings requiring immediate attention
CREATE VIEW IF NOT EXISTS v_critical_findings AS
SELECT 
    f.finding_id,
    s.tool,
    s.domain,
    s.started_at,
    f.finding_code,
    f.title,
    f.severity,
    f.confidence,
    f.evidence_value,
    f.recommendation
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE f.severity IN ('critical', 'high')
ORDER BY 
    CASE f.severity 
        WHEN 'critical' THEN 1 
        WHEN 'high' THEN 2 
    END,
    s.started_at DESC;

-- Verified domains (for consent tracking)
CREATE VIEW IF NOT EXISTS v_verified_domains AS
SELECT 
    domain,
    token,
    method,
    verified_at,
    expires_at,
    CASE 
        WHEN datetime('now', 'utc') < expires_at THEN 'valid'
        ELSE 'expired'
    END AS status
FROM consent_tokens
WHERE verified_at IS NOT NULL
ORDER BY verified_at DESC;

-- ============================================================================
-- INITIAL DATA
-- Optional: Add default client for personal use
-- ============================================================================
INSERT OR IGNORE INTO clients (name, domain, contact_email, notes)
VALUES ('Personal Testing', 'localhost', 'test@localhost', 'Local testing environment');

-- ============================================================================
-- MIGRATION NOTES
-- ============================================================================
-- This schema is version-controlled. For upgrades:
-- 1. Create new migration files: migrate_v1_to_v2.sql
-- 2. Track version in a separate migrations table
-- 3. Apply migrations in order
-- 
-- Future considerations:
-- - Add indexes as needed based on query patterns
-- - Partition findings table if it grows large (>100k rows)
-- - Add full-text search on findings.title and findings.recommendation
-- ============================================================================