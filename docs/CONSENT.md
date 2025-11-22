# Consent Token System

## Overview

Argus implements a **consent token verification system** to ensure you have technical control over target domains before enabling intrusive scanning or AI analysis.

This system is a **safety mechanism**, not a legal authorization. You still need proper permission to scan any system.

---

## 🎯 When Is Consent Required?

Consent verification is **mandatory** for:

1. **`--aggressive` Mode**

    - Deep enumeration (more users, plugins)
    - Brute force testing (if enabled)
    - Time-based blind detection
    - Any potentially intrusive checks

2. **`--use-ai` Flag**
    - Sends sanitized report data to external AI API
    - Even though data is sanitized, we require consent as an extra safety layer

**Safe mode does NOT require consent** (non-intrusive checks only).

---

## 🔑 How It Works

### Step 1: Generate Token

```bash
python -m argus --gen-consent example.com
```

**Output:**

```
===========================================================================
DOMAIN OWNERSHIP VERIFICATION REQUIRED
===========================================================================

Domain: example.com
Token: verify-a3f9b2c1d8e4f5a6
Expires: 48 hours from now

┌─ METHOD 1: HTTP File (Recommended)
│
│  1. Create a text file containing EXACTLY this:
│     verify-a3f9b2c1d8e4f5a6
│
│  2. Upload it to:
│     https://example.com/.well-known/verify-a3f9b2c1d8e4f5a6.txt
│
│  3. Verify it's accessible in your browser
│
│  4. Run verification:
│     argus --verify-consent http --domain example.com --token verify-a3f9b2c1d8e4f5a6
└─

┌─ METHOD 2: DNS TXT Record (Alternative)
│
│  1. Add a TXT record to your DNS:
│     Host: example.com
│     Value: argus-verify=verify-a3f9b2c1d8e4f5a6
│
│  2. Wait for DNS propagation (5-30 minutes)
│
│  3. Run verification:
│     argus --verify-consent dns --domain example.com --token verify-a3f9b2c1d8e4f5a6
└─

===========================================================================
NOTE: You must verify ownership before using --aggressive or --use-ai
===========================================================================
```

**What Happens:**

-   Token is stored in SQLite database (`~/.argos/argos.db`)
-   Token format: `verify-<16 hex characters>`
-   Token expires after 48 hours (configurable in `config/defaults.yaml`)

---

## 📁 Method 1: HTTP File Verification (Recommended)

### Why HTTP File?

✅ **Pros:**

-   Quick to set up (minutes)
-   No DNS propagation delay
-   Easy to verify manually
-   Works on localhost for testing

❌ **Cons:**

-   Requires web server file access
-   Less suitable for wildcard domains

### Implementation Steps

#### 1. Create Token File

Create a text file with **EXACTLY** the token string:

```bash
echo "verify-a3f9b2c1d8e4f5a6" > verify-a3f9b2c1d8e4f5a6.txt
```

**Important**: No extra spaces, newlines, or characters!

#### 2. Upload to .well-known Directory

**Standard Path:**

```
https://example.com/.well-known/verify-a3f9b2c1d8e4f5a6.txt
```

**Why .well-known?**

-   RFC 8615 standard location for site metadata
-   Used by Let's Encrypt, security.txt, and other security tools
-   Well-supported by web servers

**Server Configuration Examples:**

**Apache (.htaccess):**

```apache
# Allow .well-known directory access
<Directory "/var/www/html/.well-known">
    Options -Indexes
    AllowOverride None
    Require all granted
</Directory>
```

**Nginx:**

```nginx
location /.well-known/ {
    allow all;
}
```

**WordPress:**
Just create the directory and file in your WordPress root:

```bash
mkdir -p /var/www/html/.well-known
echo "verify-a3f9b2c1d8e4f5a6" > /var/www/html/.well-known/verify-a3f9b2c1d8e4f5a6.txt
chmod 644 /var/www/html/.well-known/verify-a3f9b2c1d8e4f5a6.txt
```

#### 3. Test Manually

Before running verification, test in your browser:

```
https://example.com/.well-known/verify-a3f9b2c1d8e4f5a6.txt
```

**Expected Response:**

```
verify-a3f9b2c1d8e4f5a6
```

**Troubleshooting:**

-   404 Not Found → File path incorrect
-   403 Forbidden → Permissions issue or .htaccess blocking
-   Different content → File content mismatch

#### 4. Run Verification

```bash
python -m argus --verify-consent http \
    --domain example.com \
    --token verify-a3f9b2c1d8e4f5a6
```

**Success Output:**

```
===========================================================================
✓ CONSENT VERIFICATION SUCCESSFUL
===========================================================================
Domain: example.com
Token: verify-a3f9b2c1d8e4f5a6
Method: HTTP
Proof: /home/user/.argus/consent-proofs/example.com_http_20251011_143022.txt

You can now use --aggressive and --use-ai modes for this domain.
===========================================================================
```

**Failure Output:**

```
===========================================================================
✗ CONSENT VERIFICATION FAILED
===========================================================================
Domain: example.com
Token: verify-a3f9b2c1d8e4f5a6
Method: HTTP
Error: Token file not accessible at https://example.com/.well-known/verify-a3f9b2c1d8e4f5a6.txt

Please check the token placement and try again.
===========================================================================
```

---

## 🌐 Method 2: DNS TXT Record Verification

### Why DNS TXT?

✅ **Pros:**

-   No web server file access needed
-   Works for domains without websites
-   Industry-standard (used by Google, AWS, etc.)
-   Covers wildcard subdomains

❌ **Cons:**

-   DNS propagation delay (5-30 minutes)
-   Requires DNS management access
-   More complex for beginners

### Implementation Steps

#### 1. Add DNS TXT Record

**Record Configuration:**

-   **Type**: TXT
-   **Host/Name**: `example.com` (or `@` for root)
-   **Value**: `argus-verify=verify-a3f9b2c1d8e4f5a6`
-   **TTL**: 300 (5 minutes) for quick testing

**Examples by Provider:**

**Cloudflare:**

1. Dashboard → DNS → Add Record
2. Type: TXT
3. Name: @
4. Content: `argus-verify=verify-a3f9b2c1d8e4f5a6`
5. TTL: Auto
6. Save

**GoDaddy:**

1. DNS Management
2. Add → TXT Record
3. Host: @
4. TXT Value: `argus-verify=verify-a3f9b2c1d8e4f5a6`
5. TTL: 600
6. Save

**Route53 (AWS):**

```bash
aws route53 change-resource-record-sets --hosted-zone-id Z1234567890ABC \
  --change-batch '{
    "Changes": [{
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "example.com",
        "Type": "TXT",
        "TTL": 300,
        "ResourceRecords": [{
          "Value": "\"argus-verify=verify-a3f9b2c1d8e4f5a6\""
        }]
      }
    }]
  }'
```

#### 2. Wait for Propagation

Check propagation status:

```bash
# Linux/Mac
dig TXT example.com +short

# Windows
nslookup -type=TXT example.com

# Online Tool
https://dnschecker.org/
```

**Expected Output:**

```
"argus-verify=verify-a3f9b2c1d8e4f5a6"
```

#### 3. Run Verification

```bash
python -m argus --verify-consent dns \
    --domain example.com \
    --token verify-a3f9b2c1d8e4f5a6
```

**Automatic Retries:**
Argus will retry 3 times with 2-second delays (configurable in `config/defaults.yaml`).

---

## 💾 Verification Storage

### Database Record

Upon successful verification:

```sql
INSERT INTO consent_tokens (
    domain,
    token,
    method,
    verified_at,
    proof_path,
    expires_at
) VALUES (
    'example.com',
    'verify-a3f9b2c1d8e4f5a6',
    'http',
    '2025-10-11T14:30:22Z',
    '/home/user/.argus/consent-proofs/example.com_http_20251011_143022.txt',
    '2025-10-13T14:30:22Z'
);
```

### Proof File

Stored at `~/.argus/consent-proofs/example.com_http_20251011_143022.txt`:

```
Domain: example.com
Token: verify-a3f9b2c1d8e4f5a6
Method: http
Verified: 2025-10-11T14:30:22Z
Proof: https://example.com/.well-known/verify-a3f9b2c1d8e4f5a6.txt
```

**Purpose**: Audit trail for compliance and accountability.

---

## ⏰ Token Expiration

### Default Expiration

**48 hours** from generation (configurable).

### Checking Expiration

```bash
# View verified domains
sqlite3 ~/.argos/argos.db "SELECT * FROM v_verified_domains"
```

**Output:**

```
domain       | token                     | method | verified_at           | expires_at            | status
example.com  | verify-a3f9b2c1d8e4f5a6   | http   | 2025-10-11T14:30:22Z  | 2025-10-13T14:30:22Z  | valid
test.com     | verify-deadbeef12345678   | dns    | 2025-10-09T10:00:00Z  | 2025-10-11T10:00:00Z  | expired
```

### Renewing Tokens

Simply generate a new token:

```bash
python -m argus --gen-consent example.com
```

Old tokens remain in database for audit purposes but are marked inactive.

---

## 🔒 Security Considerations

### Token Security

**Tokens are NOT secrets:**

-   They prove domain control, not identity
-   Safe to include in reports or logs
-   Expire automatically after 48 hours

**However:**

-   Don't reuse the same token format across tools
-   Rotate tokens regularly
-   Delete old tokens from web server after verification

### Attack Scenarios

**Scenario 1: Stolen Token**

-   Attacker steals your token string
-   **Impact**: None - They still need to place it on YOUR domain
-   **Mitigation**: Built-in - Token placement proves control

**Scenario 2: Token Guessing**

-   Attacker tries to guess token format
-   **Impact**: Minimal - 16 hex chars = 2^64 possibilities
-   **Mitigation**: Cryptographically random generation

**Scenario 3: Token Replay**

-   Attacker reuses old token
-   **Impact**: None - Tokens expire after 48h
-   **Mitigation**: Expiration timestamps

### Privacy

**What Argus Stores:**

-   Domain name
-   Token string
-   Verification method
-   Timestamps
-   Proof file path

**What Argus Does NOT Store:**

-   IP addresses
-   User credentials
-   Server details
-   Scan results (stored separately)

---

## 🛠️ Advanced Usage

### Custom Configuration

Edit `config/defaults.yaml`:

```yaml
consent:
    token_expiry_hours: 72 # Extend to 3 days
    token_hex_length: 32 # Longer tokens (16 hex chars = 8 bytes)
    http_verification_path: "/.well-known/"
    dns_txt_prefix: "argus-verify="
    verification_retries: 5 # More retries for DNS
    verification_retry_delay: 5 # Longer delays
```

### Environment Variables

Override config via env vars:

```bash
export ARGUS_CONSENT_TOKEN_EXPIRY_HOURS=96
export ARGUS_CONSENT_VERIFICATION_RETRIES=10
```

### Programmatic Usage

```python
from argus.core.consent import ConsentToken
from argus.core.config import Config

config = Config.load()
consent = ConsentToken(config)

# Generate token
token, expiration = consent.generate_token("example.com")
print(f"Token: {token}")

# Verify (HTTP)
success, result = consent.verify_http("example.com", token)
if success:
    consent.save_proof("example.com", token, "http", result)
```

---

## 📊 Verification Workflow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Argus Consent Flow                           │
└─────────────────────────────────────────────────────────────────┘

1. User runs: argus --gen-consent example.com
   ↓
2. Argus generates token: verify-abc123
   ↓
3. Token stored in SQLite (status: pending)
   ↓
4. User places token:
   → HTTP: .well-known/verify-abc123.txt
   → DNS: TXT record with argus-verify=verify-abc123
   ↓
5. User runs: argus --verify-consent [method] --domain example.com --token verify-abc123
   ↓
6. Argus attempts verification:
   → HTTP: GET https://example.com/.well-known/verify-abc123.txt
   → DNS: Query TXT example.com
   ↓
7. If successful:
   → Update SQLite (status: verified, verified_at: NOW)
   → Save proof file
   → Enable --aggressive and --use-ai
   ↓
8. User scans: argus --target https://example.com --aggressive
   ↓
9. Argus checks: is_domain_verified(example.com)?
   → YES: Proceed with scan
   → NO: Abort with error
```

---

## ❓ FAQ

### Q: Can I skip consent verification?

**A:** No for `--aggressive` and `--use-ai`. Yes for `--safe` mode (default).

### Q: Does consent verification replace legal authorization?

**A:** **NO!** Consent tokens prove technical control only. You still need proper legal permission to scan.

### Q: Can I use one token for multiple subdomains?

**A:** No. Generate separate tokens for each domain/subdomain.

### Q: What if I lose the token?

**A:** Generate a new token. Old tokens remain in the database but become inactive.

### Q: Can I verify via API?

**A:** Not currently. HTTP file and DNS TXT are the only supported methods.

### Q: How do I revoke a token?

**A:** Tokens automatically expire after 48 hours. To immediately revoke, delete from database:

```sql
DELETE FROM consent_tokens WHERE token = 'verify-abc123';
```

### Q: Is this system secure?

**A:** It's a safety mechanism, not a security boundary. It prevents accidental scans and proves domain control, but doesn't prevent determined attackers (who would need legal authorization anyway).

---

## 🎓 Best Practices

1. **Always verify before aggressive scans** - Even if you're the owner
2. **Document verification** - Keep proof files for audit trail
3. **Clean up after testing** - Remove token files from web server
4. **Rotate tokens regularly** - Generate fresh tokens every 48 hours
5. **Use secure channels** - Don't email tokens or store in public repos
6. **Test verification manually** - Check browser access before running `--verify-consent`

---

_Argus Version: 0.1.0_
