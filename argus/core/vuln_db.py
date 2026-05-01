"""
WPVulnerability.net API Client

Provides real-time CVE/CWE correlation for WordPress plugins, themes, and core.

API docs: https://www.wpvulnerability.net/api/
Endpoints:
  GET /plugin/{slug}/     → plugin vulnerabilities
  GET /theme/{slug}/      → theme vulnerabilities
  GET /core/{version}/    → WordPress core vulnerabilities

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import re
import time
import html as _html
import requests
from typing import Any, Dict, List, Optional, Tuple

from .logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Severity mapping constants
# ---------------------------------------------------------------------------

# CWE IDs that indicate critical severity
CRITICAL_CWES = {
    'CWE-434',   # Unrestricted Upload of File with Dangerous Type
    'CWE-94',    # Improper Control of Generation of Code (Code Injection)
    'CWE-89',    # SQL Injection
    'CWE-78',    # OS Command Injection
    'CWE-77',    # Command Injection
    'CWE-74',    # Injection
    'CWE-1321',  # Improperly Controlled Modification of Object Prototype
    'CWE-502',   # Deserialization of Untrusted Data
    'CWE-611',   # XML External Entity (XXE)
}

# CWE IDs that indicate high severity
HIGH_CWES = {
    'CWE-79',    # Cross-site Scripting (XSS)
    'CWE-352',   # Cross-Site Request Forgery (CSRF)
    'CWE-22',    # Path Traversal
    'CWE-918',   # Server-Side Request Forgery (SSRF)
    'CWE-287',   # Improper Authentication
    'CWE-863',   # Incorrect Authorization
    'CWE-862',   # Missing Authorization
    'CWE-732',   # Incorrect Permission Assignment
    'CWE-306',   # Missing Authentication for Critical Function
    'CWE-601',   # Open Redirect
    'CWE-367',   # TOCTOU Race Condition
    'CWE-285',   # Improper Authorization
    'CWE-269',   # Improper Privilege Management
}

# Keywords in title/description indicating critical severity
CRITICAL_KEYWORDS = {
    'remote code execution', 'rce', 'arbitrary code execution',
    'sql injection', 'sqli', 'arbitrary file upload',
    'command injection', 'object injection',
    'unauthenticated arbitrary file',
}

# Keywords indicating high severity
HIGH_KEYWORDS = {
    'cross-site scripting', 'xss', 'stored xss', 'reflected xss',
    'csrf', 'cross-site request forgery',
    'path traversal', 'directory traversal',
    'server-side request forgery', 'ssrf',
    'authentication bypass', 'auth bypass',
    'privilege escalation',
    'arbitrary file deletion', 'arbitrary file read',
    'local file inclusion', 'remote file inclusion',
    'open redirect',
}


class VulnDB:
    """
    Client for the WPVulnerability.net.

    No API key required. Includes in-memory cache to avoid duplicate
    requests during a scan session.
    """

    BASE_URL = "https://www.wpvulnerability.net"
    WP_PLUGINS_API = "https://api.wordpress.org/plugins/info/1.0/{slug}.json"
    WP_THEMES_API  = "https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]={slug}"
    NVD_CVE_API    = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

    REQUEST_TIMEOUT = 10  # seconds
    CACHE_TTL = 3600      # 1 hour

    def __init__(self, timeout: int = REQUEST_TIMEOUT):
        self._cache: Dict[str, Tuple[float, Any]] = {}  # key → (ts, data)
        self._session = requests.Session()
        self._session.headers.update({
            'User-Agent': 'Argus-WPScanner/0.2.0 (WordPress Security Scanner)',
            'Accept': 'application/json',
        })
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_plugin_vulns(
        self,
        slug: str,
        version: Optional[str] = None
    ) -> List[Dict]:
        """
        Return vulnerabilities for a plugin, optionally filtered by version.

        Args:
            slug: WordPress plugin directory name (e.g. 'contact-form-7')
            version: Detected plugin version (e.g. '5.5.3'). If provided,
                     only vulnerabilities affecting this version are returned.

        Returns:
            List of normalized vulnerability dicts, empty if none found.
        """
        all_vulns = self._get_all_plugin_vulns(slug)
        if version:
            return [v for v in all_vulns if self._is_version_affected(version, v)]
        return all_vulns

    def get_theme_vulns(
        self,
        slug: str,
        version: Optional[str] = None
    ) -> List[Dict]:
        """
        Return vulnerabilities for a theme, optionally filtered by version.
        """
        all_vulns = self._get_all_theme_vulns(slug)
        if version:
            return [v for v in all_vulns if self._is_version_affected(version, v)]
        return all_vulns

    def get_core_vulns(self, version: str) -> List[Dict]:
        """
        Return known vulnerabilities for a specific WordPress core version.
        """
        cache_key = f"core:{version}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        data = self._fetch(f"/core/{version}/")
        if data is None:
            return self._cache_set(cache_key, [])

        raw_vulns = data.get('vulnerability') or []
        vulns = [self._normalize(v) for v in raw_vulns if v]
        return self._cache_set(cache_key, vulns)

    def get_severity_for_vulns(self, vulns: List[Dict]) -> str:
        """
        Derive the highest severity from a list of normalized vulnerabilities.

        Returns: 'critical' | 'high' | 'medium'
        """
        if not vulns:
            return 'info'

        highest = 'medium'
        for vuln in vulns:
            sev = self._classify_severity(vuln)
            if sev == 'critical':
                return 'critical'
            if sev == 'high':
                highest = 'high'
        return highest

    def extract_cve_ids(self, vulns: List[Dict]) -> List[str]:
        """Extract unique CVE IDs from a list of normalized vulnerabilities."""
        cves = []
        for v in vulns:
            for src in v.get('sources', []):
                sid = src.get('id', '')
                if sid.startswith('CVE-'):
                    if sid not in cves:
                        cves.append(sid)
        return cves

    def get_plugin_latest_version(self, slug: str) -> Optional[str]:
        """
        Fetch the latest stable version of a plugin from the WordPress.org API.
        Returns None on any error or if plugin not found.
        """
        key = f"wp_latest_plugin:{slug}"
        cached = self._cache_get(key)
        if cached is not None:
            return cached[0] if cached else None
        try:
            resp = self._session.get(
                self.WP_PLUGINS_API.format(slug=slug), timeout=5
            )
            val = resp.json().get('version') if resp.status_code == 200 else None
        except Exception:
            val = None
        self._cache_set(key, [val] if val else [])
        return val

    def get_theme_latest_version(self, slug: str) -> Optional[str]:
        """
        Fetch the latest stable version of a theme from the WordPress.org API.
        Returns None on any error or if theme not found.
        """
        key = f"wp_latest_theme:{slug}"
        cached = self._cache_get(key)
        if cached is not None:
            return cached[0] if cached else None
        try:
            resp = self._session.get(
                self.WP_THEMES_API.format(slug=slug), timeout=5
            )
            val = resp.json().get('version') if resp.status_code == 200 else None
        except Exception:
            val = None
        self._cache_set(key, [val] if val else [])
        return val

    def get_cvss_score(self, cve_id: str) -> Optional[float]:
        """
        Fetch the CVSS base score for a CVE from the NVD API.
        Tries CVSSv3.1, then CVSSv3.0, then CVSSv2.
        Returns None if not found or on any error.
        """
        key = f"nvd_cvss:{cve_id}"
        cached = self._cache_get(key)
        if cached is not None:
            return cached[0] if cached else None
        score = None
        try:
            resp = self._session.get(
                self.NVD_CVE_API.format(cve_id=cve_id), timeout=8
            )
            if resp.status_code == 200:
                vulns = resp.json().get('vulnerabilities', [])
                if vulns:
                    metrics = vulns[0].get('cve', {}).get('metrics', {})
                    for mk in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                        ml = metrics.get(mk, [])
                        if ml:
                            raw = ml[0].get('cvssData', {}).get('baseScore')
                            if raw is not None:
                                score = float(raw)
                                break
        except Exception:
            score = None
        self._cache_set(key, [score] if score is not None else [])
        return score

    def _pick_best_title(self, v: Dict) -> str:
        """
        Pick the most human-readable title for a vulnerability.

        The API `name` field is constructed as "Plugin Name [slug] < X.Y.Z" — it is
        generic and repeats when multiple vulnerabilities share the same fix version.
        Source entries (especially WPScan advisory UUIDs) carry distinct, concise titles
        like "Elementor < 3.12.2 - Admin+ SQLi" that are unique per vulnerability.

        Priority:
          1. UUID-format source names with a space (WPScan advisories — short, clean, unique)
          2. Hex source names that are readable (not URLs, not just IDs)
          3. First CVE ID from sources (at least unique when nothing else is available)
          4. API name as last resort (may be shared across vulns with same fix version)
        """
        _UUID_RE = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        )
        sources = v.get('sources', [])

        def _is_readable(name: str, sid: str) -> bool:
            """True if name is a useful human-readable advisory title."""
            return (
                name
                and name != sid
                and not name.startswith('CVE-')
                and not name.startswith('http')
                and '.' not in name.split()[0]  # exclude "wpscan.com", "wpvulndb.com"
                and ' ' in name                  # must have at least one space
                and 10 < len(name) < 120
            )

        # 1. UUID-format source IDs → WPScan advisory titles (clean + unique)
        for src in sources:
            sid = src.get('id', '')
            name = src.get('name', '').strip()
            if _UUID_RE.match(sid) and _is_readable(name, sid):
                return name

        # 2. Hex source IDs with readable names
        for src in sources:
            name = src.get('name', '').strip()
            sid = src.get('id', '')
            if _is_readable(name, sid):
                return name

        # 3. First CVE ID from sources (at least unique per vulnerability)
        for src in sources:
            sid = src.get('id', '')
            if sid.startswith('CVE-'):
                return sid

        # 4. Fallback: API name (may be generic / shared across vulns)
        return v.get('title', 'Unknown vulnerability')

    def format_for_report(self, vulns: List[Dict], cvss_cache: Optional[Dict[str, Optional[float]]] = None) -> List[Dict]:
        """
        Convert internal vuln format to the report schema's vulnerabilities format.
        Only includes fields defined in the schema.

        Args:
            vulns: Normalized vulnerability list from get_plugin_vulns / get_theme_vulns.
            cvss_cache: Optional dict mapping CVE ID → CVSS base score. When provided,
                        the 'cvss' field is added to each entry that has a matching CVE.
        """
        result = []
        for v in vulns:
            entry = {
                'title': self._pick_best_title(v),
            }
            # Include primary CVE if available
            for src in v.get('sources', []):
                if src.get('id', '').startswith('CVE-'):
                    entry['cve_id'] = src['id']
                    if src.get('description'):
                        entry['description'] = src['description'][:500]
                    if src.get('link'):
                        entry['link'] = src['link']
                    if src.get('date'):
                        entry['date'] = src['date']
                    # Enrich with CVSS score if available in cache
                    if cvss_cache:
                        score = cvss_cache.get(src['id'])
                        if score is not None:
                            entry['cvss'] = score
                    break
            # Include CWE if available
            cwes = v.get('cwes', [])
            if cwes:
                entry['cwe_id'] = cwes[0].get('cwe', '')
                entry['cwe_name'] = cwes[0].get('name', '')
            result.append(entry)
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_all_plugin_vulns(self, slug: str) -> List[Dict]:
        """Fetch and cache all vulns for a plugin slug."""
        cache_key = f"plugin:{slug}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        data = self._fetch(f"/plugin/{slug}/")
        if data is None:
            return self._cache_set(cache_key, [])

        raw_vulns = data.get('vulnerability') or []
        vulns = [self._normalize_plugin_vuln(v) for v in raw_vulns if v]
        return self._cache_set(cache_key, vulns)

    def _get_all_theme_vulns(self, slug: str) -> List[Dict]:
        """Fetch and cache all vulns for a theme slug."""
        cache_key = f"theme:{slug}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        data = self._fetch(f"/theme/{slug}/")
        if data is None:
            return self._cache_set(cache_key, [])

        raw_vulns = data.get('vulnerability') or []
        vulns = [self._normalize_plugin_vuln(v) for v in raw_vulns if v]
        return self._cache_set(cache_key, vulns)

    def _normalize_plugin_vuln(self, raw: Dict) -> Dict:
        """
        Normalize a raw vulnerability from the plugin/theme API response.
        Preserves version range operator for later filtering.
        """
        sources = [
            {
                'id': s.get('id', ''),
                'name': _html.unescape(s.get('name', '')),
                'link': s.get('link', ''),
                'description': _html.unescape((s.get('description') or '').strip()),
                'date': s.get('date', ''),
            }
            for s in (raw.get('source') or [])
        ]

        operator = raw.get('operator') or {}
        cwes = []
        impact = raw.get('impact') or {}
        if isinstance(impact, dict):
            cwes = [
                {'cwe': c.get('cwe', ''), 'name': c.get('name', '')}
                for c in (impact.get('cwe') or [])
            ]

        return {
            'uuid': raw.get('uuid', ''),
            'title': _html.unescape(raw.get('name', '')),
            'operator': {
                'min_version': operator.get('min_version'),
                'min_operator': operator.get('min_operator'),
                'max_version': operator.get('max_version'),
                'max_operator': operator.get('max_operator'),
                'unfixed': operator.get('unfixed', '0') == '1',
            },
            'sources': sources,
            'cwes': cwes,
        }

    def _normalize(self, raw: Dict) -> Dict:
        """Normalize a raw core vulnerability (no operator, direct version match)."""
        sources = [
            {
                'id': s.get('id', ''),
                'name': _html.unescape(s.get('name', '')),
                'link': s.get('link', ''),
                'description': _html.unescape((s.get('description') or '').strip()),
                'date': s.get('date', ''),
            }
            for s in (raw.get('source') or [])
        ]
        cwes = []
        impact = raw.get('impact') or {}
        if isinstance(impact, dict):
            cwes = [
                {'cwe': c.get('cwe', ''), 'name': c.get('name', '')}
                for c in (impact.get('cwe') or [])
            ]

        # For core vulns the API sets 'name' to the WP version string (e.g. "6.0.3"),
        # not a useful vulnerability title. Fall back to the first source name instead.
        raw_name = raw.get('name', '')
        if re.match(r'^\d+\.\d+', raw_name.strip()) and sources:
            title = sources[0]['name'] or _html.unescape(raw_name)
        else:
            title = _html.unescape(raw_name)

        return {
            'uuid': raw.get('uuid', ''),
            'title': title,
            'operator': None,  # Core vulns are direct version matches
            'sources': sources,
            'cwes': cwes,
        }

    def _is_version_affected(self, version: str, vuln: Dict) -> bool:
        """
        Determine if a given version is affected by a vulnerability.

        Handles:
        - max_operator: "lt" (< max_version)
        - max_operator: "lte" (<= max_version)
        - Optional min bounds: "gt" (> min) or "gte" (>= min)
        - unfixed: True → all versions affected
        """
        op = vuln.get('operator')
        if op is None:
            # Core vuln or no operator info → consider affected
            return True

        if op.get('unfixed'):
            return True

        try:
            v = _parse_version(version)
        except (ValueError, AttributeError):
            return False

        # Check upper bound (required)
        max_ver = op.get('max_version')
        max_op = op.get('max_operator')

        if max_ver:
            try:
                mv = _parse_version(max_ver)
            except ValueError:
                return False

            if max_op == 'lt' and not (v < mv):
                return False
            elif max_op == 'lte' and not (v <= mv):
                return False
            # Unknown operator → skip (be conservative)

        # Check lower bound (optional)
        min_ver = op.get('min_version')
        min_op = op.get('min_operator')

        if min_ver:
            try:
                minv = _parse_version(min_ver)
            except ValueError:
                pass
            else:
                if min_op == 'gt' and not (v > minv):
                    return False
                elif min_op == 'gte' and not (v >= minv):
                    return False

        return True

    def _classify_severity(self, vuln: Dict) -> str:
        """
        Classify a vulnerability as critical/high/medium based on CWE and keywords.
        """
        # Check CWEs first (most reliable)
        for cwe_entry in vuln.get('cwes', []):
            cwe_id = cwe_entry.get('cwe', '')
            if cwe_id in CRITICAL_CWES:
                return 'critical'
            if cwe_id in HIGH_CWES:
                return 'high'

        # Fallback: keyword scan on title and source descriptions
        text = (vuln.get('title', '') + ' ').lower()
        for src in vuln.get('sources', []):
            text += (src.get('name', '') + ' ' + src.get('description', '') + ' ').lower()

        for kw in CRITICAL_KEYWORDS:
            if kw in text:
                return 'critical'

        for kw in HIGH_KEYWORDS:
            if kw in text:
                return 'high'

        return 'medium'

    def _fetch(self, path: str) -> Optional[Dict]:
        """
        HTTP GET to the WPVulnerability.net API.

        Returns parsed JSON data dict or None on any error.
        """
        url = f"{self.BASE_URL}{path}"
        try:
            resp = self._session.get(url, timeout=self.timeout)

            if resp.status_code == 404:
                logger.debug(f"VulnDB: not found → {url}")
                return None

            if resp.status_code != 200:
                logger.debug(f"VulnDB: HTTP {resp.status_code} for {url}")
                return None

            payload = resp.json()
            if payload.get('error', 1) != 0:
                logger.debug(f"VulnDB: API error for {url}: {payload.get('message')}")
                return None

            return payload.get('data')

        except requests.exceptions.Timeout:
            logger.debug(f"VulnDB: timeout for {url}")
            return None
        except requests.exceptions.RequestException as e:
            logger.debug(f"VulnDB: request error for {url}: {e}")
            return None
        except (ValueError, KeyError) as e:
            logger.debug(f"VulnDB: parse error for {url}: {e}")
            return None

    def _cache_get(self, key: str) -> Optional[List[Dict]]:
        """Return cached value if not expired, else None."""
        if key in self._cache:
            ts, data = self._cache[key]
            if time.time() - ts < self.CACHE_TTL:
                return data
        return None

    def _cache_set(self, key: str, data: List[Dict]) -> List[Dict]:
        """Store data in cache and return it."""
        self._cache[key] = (time.time(), data)
        return data


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_vuln_db: Optional[VulnDB] = None


def get_vuln_db() -> VulnDB:
    """Return the module-level VulnDB singleton."""
    global _vuln_db
    if _vuln_db is None:
        _vuln_db = VulnDB()
    return _vuln_db


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _parse_version(version_str: str) -> tuple:
    """
    Parse a version string into a comparable tuple of ints.

    Examples:
        '5.3.2'  → (5, 3, 2)
        '5.3'    → (5, 3, 0)
        '5'      → (5, 0, 0)
        '5.3.2-RC1' → (5, 3, 2)  (pre-release suffix stripped)
    """
    # Strip pre-release suffixes (e.g. '-RC1', '-beta', '-alpha')
    clean = re.split(r'[-+]', version_str.strip())[0]
    parts = clean.split('.')
    try:
        ints = [int(p) for p in parts[:4]]  # max 4 components
    except ValueError:
        raise ValueError(f"Cannot parse version: {version_str!r}")

    # Pad to at least 3 components
    while len(ints) < 3:
        ints.append(0)

    return tuple(ints)
