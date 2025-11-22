# Argus Database Guide

**Database:** SQLite 3.x  
**Location:** `~/.argos/argos.db` (default)  
**Schema Version:** 1.0

---

## Overview

Argus uses **SQLite** for persistent storage of:

-   Client/project information
-   Scan history and metadata
-   Security findings
-   Consent verification tokens

**Note:** This guide provides SQL query examples until **IMPROV-011 (Interactive Database CLI)** is implemented in v0.3.0.

---

## Database Schema

### Tables

#### 1. `clients`

Stores information about clients or projects.

```sql
CREATE TABLE clients (
    client_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    domain TEXT UNIQUE NOT NULL,
    contact_email TEXT,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
);

CREATE INDEX idx_clients_domain ON clients(domain);
```

**Columns:**

-   `client_id`: Auto-increment primary key
-   `name`: Client or project name
-   `domain`: Primary domain (UNIQUE constraint)
-   `contact_email`: Contact email address
-   `notes`: Additional notes
-   `created_at`: Creation timestamp (UTC)
-   `updated_at`: Last update timestamp (UTC)

---

#### 2. `consent_tokens`

Tracks ownership verification tokens.

```sql
CREATE TABLE consent_tokens (
    token_id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    token TEXT NOT NULL,
    method TEXT NOT NULL CHECK(method IN ('http', 'dns')),
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    expires_at TEXT NOT NULL,
    verified_at TEXT,
    proof_path TEXT
);

CREATE INDEX idx_consent_domain ON consent_tokens(domain);
CREATE INDEX idx_consent_verified ON consent_tokens(verified_at);
```

**Columns:**

-   `token_id`: Auto-increment primary key
-   `domain`: Target domain
-   `token`: Generated verification token (format: `verify-XXXX`)
-   `method`: Verification method (`http` or `dns`)
-   `created_at`: Token generation time (UTC)
-   `expires_at`: Expiration time (48 hours after creation)
-   `verified_at`: Verification timestamp (NULL until verified)
-   `proof_path`: Path to proof file (for HTTP method)

---

#### 3. `scans`

Stores scan execution history.

```sql
CREATE TABLE scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL CHECK(tool IN ('argus', 'hephaestus', 'pythia', 'asterion')),
    client_id INTEGER,
    domain TEXT NOT NULL,
    target_url TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('safe', 'aggressive')),
    started_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    finished_at TEXT,
    status TEXT NOT NULL CHECK(status IN ('running', 'completed', 'failed', 'aborted')),
    report_json_path TEXT,
    report_html_path TEXT,
    summary TEXT,
    error_message TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE SET NULL
);

CREATE INDEX idx_scans_tool ON scans(tool);
CREATE INDEX idx_scans_domain ON scans(domain);
CREATE INDEX idx_scans_started ON scans(started_at);
CREATE INDEX idx_scans_status ON scans(status);
```

**Columns:**

-   `scan_id`: Auto-increment primary key
-   `tool`: Scanner tool name (`argus`, `hephaestus`, or `pythia`)
-   `client_id`: Foreign key to clients table (nullable)
-   `domain`: Scanned domain
-   `target_url`: Full target URL
-   `mode`: Scan mode (`safe` or `aggressive`)
-   `started_at`: Scan start time (UTC)
-   `finished_at`: Scan completion time (UTC)
-   `status`: Current status (`running`, `completed`, `failed`, `aborted`)
-   `report_json_path`: Path to JSON report
-   `report_html_path`: Path to HTML report
-   `summary`: JSON object with severity counts
-   `error_message`: Error description (if failed)

**Status Values:**

-   `running`: Scan in progress
-   `completed`: Scan finished successfully
-   `failed`: Technical error (connection, timeout, DB)
-   `aborted`: Target not WordPress or user cancelled

---

#### 4. `findings`

Stores individual security findings from scans.

```sql
CREATE TABLE findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    finding_code TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence TEXT NOT NULL CHECK(confidence IN ('high', 'medium', 'low')),
    evidence_type TEXT,
    evidence_value TEXT,
    recommendation TEXT NOT NULL,
    "references" TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_code ON findings(finding_code);
```

**Columns:**

-   `finding_id`: Auto-increment primary key
-   `scan_id`: Foreign key to scans table (CASCADE delete)
-   `finding_code`: Finding identifier (e.g., `ARGUS-WP-001`)
-   `title`: Finding title/description
-   `severity`: Severity level (`critical`, `high`, `medium`, `low`, `info`)
-   `confidence`: Confidence level (`high`, `medium`, `low`)
-   `evidence_type`: Type of evidence (`url`, `header`, `body`, `path`, `screenshot`, `other`)
-   `evidence_value`: Evidence content
-   `recommendation`: Remediation guidance
-   `references`: JSON array of reference URLs
-   `created_at`: Finding creation time (UTC)

---

### Views

#### 1. `v_recent_scans`

Recent scans with finding counts.

```sql
CREATE VIEW v_recent_scans AS
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
```

---

#### 2. `v_critical_findings`

Critical and high severity findings.

```sql
CREATE VIEW v_critical_findings AS
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
```

---

#### 3. `v_verified_domains`

Verified domains with expiration status.

```sql
CREATE VIEW v_verified_domains AS
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
```

---

## Common Query Examples

### Client Management

#### List All Clients

```sql
SELECT
    client_id,
    name,
    domain,
    contact_email,
    created_at
FROM clients
ORDER BY created_at DESC;
```

#### Find Client by Domain

```sql
SELECT *
FROM clients
WHERE domain LIKE '%example.com%';
```

#### Add New Client

```sql
INSERT INTO clients (name, domain, contact_email, notes)
VALUES ('Acme Corp', 'acme.com', 'admin@acme.com', 'Main client');
```

#### Update Client

```sql
UPDATE clients
SET contact_email = 'newemail@acme.com',
    updated_at = datetime('now', 'utc')
WHERE client_id = 1;
```

#### Delete Client

```sql
DELETE FROM clients WHERE client_id = 1;
```

---

### Scan Management

#### List Recent Scans (Last 10)

```sql
SELECT
    scan_id,
    tool,
    domain,
    mode,
    status,
    started_at,
    total_findings
FROM v_recent_scans
LIMIT 10;
```

#### Get Scan Details

```sql
SELECT
    s.*,
    c.name AS client_name,
    COUNT(f.finding_id) AS total_findings
FROM scans s
LEFT JOIN clients c ON s.client_id = c.client_id
LEFT JOIN findings f ON s.scan_id = f.scan_id
WHERE s.scan_id = 45
GROUP BY s.scan_id;
```

#### Filter Scans by Domain

```sql
SELECT
    scan_id,
    tool,
    mode,
    status,
    started_at,
    finished_at
FROM scans
WHERE domain = 'example.com'
ORDER BY started_at DESC;
```

#### Filter Scans by Status

```sql
SELECT
    scan_id,
    domain,
    started_at,
    error_message
FROM scans
WHERE status = 'failed'
ORDER BY started_at DESC;
```

#### Get Scan Summary Statistics

```sql
SELECT
    tool,
    mode,
    status,
    COUNT(*) AS scan_count,
    AVG(
        (julianday(finished_at) - julianday(started_at)) * 86400
    ) AS avg_duration_seconds
FROM scans
WHERE finished_at IS NOT NULL
GROUP BY tool, mode, status;
```

---

### Finding Management

#### List All Findings for a Scan

```sql
SELECT
    finding_id,
    finding_code,
    title,
    severity,
    confidence
FROM findings
WHERE scan_id = 45
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
    END;
```

#### Get Critical Findings (Last 20)

```sql
SELECT
    domain,
    finding_code,
    title,
    severity,
    confidence,
    started_at
FROM v_critical_findings
LIMIT 20;
```

#### Search Findings by Code

```sql
SELECT
    s.domain,
    s.scan_id,
    f.title,
    f.severity,
    f.created_at
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE f.finding_code = 'ARGUS-WP-030'
ORDER BY f.created_at DESC;
```

#### Count Findings by Severity for Domain

```sql
SELECT
    f.severity,
    COUNT(*) AS count
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE s.domain = 'example.com'
GROUP BY f.severity
ORDER BY
    CASE f.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
    END;
```

#### Get Findings with Evidence

```sql
SELECT
    finding_code,
    title,
    evidence_type,
    evidence_value,
    recommendation
FROM findings
WHERE scan_id = 45
  AND evidence_value IS NOT NULL
ORDER BY severity;
```

---

### Consent Token Management

#### List Verified Tokens

```sql
SELECT
    domain,
    method,
    verified_at,
    expires_at,
    status
FROM v_verified_domains
ORDER BY verified_at DESC;
```

#### Check Domain Verification Status

```sql
SELECT
    domain,
    token,
    method,
    CASE
        WHEN verified_at IS NOT NULL AND datetime('now', 'utc') < expires_at
        THEN 'verified'
        WHEN verified_at IS NOT NULL AND datetime('now', 'utc') >= expires_at
        THEN 'expired'
        ELSE 'pending'
    END AS status,
    expires_at
FROM consent_tokens
WHERE domain = 'example.com'
ORDER BY created_at DESC
LIMIT 1;
```

#### List Expired Tokens

```sql
SELECT
    domain,
    token,
    verified_at,
    expires_at
FROM consent_tokens
WHERE verified_at IS NOT NULL
  AND datetime('now', 'utc') >= expires_at
ORDER BY expires_at DESC;
```

#### Revoke Token (Delete)

```sql
DELETE FROM consent_tokens
WHERE domain = 'example.com';
```

---

### Statistics & Reports

#### Database Statistics

```sql
SELECT
    'Clients' AS category,
    COUNT(*) AS count
FROM clients
UNION ALL
SELECT
    'Scans',
    COUNT(*)
FROM scans
UNION ALL
SELECT
    'Findings',
    COUNT(*)
FROM findings
UNION ALL
SELECT
    'Critical Findings',
    COUNT(*)
FROM findings
WHERE severity IN ('critical', 'high')
UNION ALL
SELECT
    'Verified Domains',
    COUNT(*)
FROM consent_tokens
WHERE verified_at IS NOT NULL;
```

#### Scan Success Rate

```sql
SELECT
    status,
    COUNT(*) AS count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM scans), 2) AS percentage
FROM scans
GROUP BY status
ORDER BY count DESC;
```

#### Top 10 Domains by Findings

```sql
SELECT
    s.domain,
    COUNT(f.finding_id) AS total_findings,
    SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical,
    SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high
FROM scans s
JOIN findings f ON s.scan_id = f.scan_id
GROUP BY s.domain
ORDER BY total_findings DESC
LIMIT 10;
```

#### Findings Trend Over Time (Last 30 Days)

```sql
SELECT
    DATE(s.started_at) AS scan_date,
    COUNT(DISTINCT s.scan_id) AS scans,
    COUNT(f.finding_id) AS findings,
    SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical
FROM scans s
LEFT JOIN findings f ON s.scan_id = f.scan_id
WHERE s.started_at >= datetime('now', '-30 days')
GROUP BY DATE(s.started_at)
ORDER BY scan_date DESC;
```

---

### Maintenance

#### Backup Database

```bash
# Command line
sqlite3 ~/.argos/argos.db ".backup /tmp/argos-backup-$(date +%Y%m%d).db"
```

#### Database Size

```sql
SELECT page_count * page_size AS size_bytes
FROM pragma_page_count(), pragma_page_size();
```

#### Vacuum (Optimize)

```sql
VACUUM;
```

#### Check Integrity

```sql
PRAGMA integrity_check;
```

#### Delete Old Scans (Older than 90 Days)

```sql
DELETE FROM scans
WHERE started_at < datetime('now', '-90 days');
-- Findings will auto-delete (CASCADE)
```

---

## Database Access from Python

### Using argus.core.db Module

```python
from argus.core.db import get_db

# Get database instance
db = get_db()

# List clients
clients = db.list_clients()
for client in clients:
    print(f"{client['client_id']}: {client['name']} - {client['domain']}")

# Get scan details
scan = db.get_scan(45)
print(f"Scan status: {scan['status']}")

# Get findings for scan
findings = db.get_findings(45)
print(f"Total findings: {len(findings)}")

# Get critical findings
critical = db.get_critical_findings(limit=20)
for finding in critical:
    print(f"{finding['domain']}: {finding['title']}")
```

### Direct SQL Access

```python
import sqlite3
from pathlib import Path

# Connect to database
db_path = Path.home() / ".argos" / "argos.db"
conn = sqlite3.connect(str(db_path))
conn.row_factory = sqlite3.Row  # Access columns by name

# Execute query
cursor = conn.execute("SELECT * FROM scans WHERE status = 'completed' LIMIT 10")
rows = cursor.fetchall()

for row in rows:
    print(f"Scan {row['scan_id']}: {row['domain']} - {row['started_at']}")

conn.close()
```

---

## Future: Interactive CLI (IMPROV-011 - v0.3.0)

In v0.3.0, these SQL queries will be replaced with intuitive commands:

```bash
# Instead of SQL:
sqlite3 ~/.argos/argos.db "SELECT * FROM clients WHERE domain LIKE '%example%'"

# Future (v0.3.0):
argus db clients list --filter example.com

# Instead of:
sqlite3 ~/.argos/argos.db "SELECT scan_id, status FROM scans ORDER BY started_at DESC LIMIT 10"

# Future:
argus db scans list --limit 10 --status completed

# Instead of:
sqlite3 ~/.argos/argos.db "SELECT * FROM findings WHERE severity IN ('critical', 'high') LIMIT 20"

# Future:
argus db findings critical --limit 20
```

**Until then, use the SQL queries provided in this guide.**

---

## Troubleshooting

### Database Locked Error

```
Error: database is locked
```

**Solution:** Another process is using the database. Wait or:

```bash
lsof ~/.argos/argos.db  # Find process
kill <PID>  # Kill if needed
```

### Database Corrupted

```
Error: file is not a database
```

**Solution:** Argus auto-recovers. Manual recovery:

```bash
# Backup corrupted file
mv ~/.argos/argos.db ~/.argos/argos.db.corrupted

# Run scan (creates fresh DB)
python -m argus --target http://example.com
```

### Read-Only Database

```
Warning: Database is read-only
```

**Solution:** Fix permissions:

```bash
chmod 644 ~/.argos/argos.db
```

---

## Schema Version History

| Version | Date     | Changes                             |
| ------- | -------- | ----------------------------------- |
| **1.0** | Nov 2025 | Initial schema (Phase 10 validated) |

---

**Schema Version:** 1.0  
**Next Update:** v0.3.0 (Interactive CLI - IMPROV-011)
**Tool Version:** Argus v0.1.0
