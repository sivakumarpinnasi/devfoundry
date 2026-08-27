/**
 * OsvAdvisoryProvider — queries the OSV.dev public vulnerability database.
 *
 * PRIVACY GUARANTEE:
 *   Only package name, version, and ecosystem are transmitted to OSV.
 *   Source files, secrets, environment variables, and repository contents
 *   are never sent.
 *
 * NETWORK SAFETY:
 *   On any network failure, HTTP error, or timeout:
 *   - An OsvProviderError is thrown.
 *   - scanWithAdvisories() catches it and returns status: 'unavailable'.
 *   - This is NEVER silently converted into "0 vulnerabilities".
 *
 * PERFORMANCE:
 *   - All dependencies are batched into a single POST /v1/querybatch request.
 *   - Duplicate package+version pairs are deduplicated before querying.
 *   - Results are cached in memory for the lifetime of the provider instance.
 *
 * OSV DATA LICENSE:
 *   OSV vulnerability data is provided under CC BY 4.0.
 *   DevFoundry queries OSV at runtime but does not store or redistribute
 *   advisory data. See docs/dependencies.md for details.
 */
import type { DependencyAdvisory, DependencyAdvisoryProvider } from '../model.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const OSV_API_BASE = 'https://api.osv.dev/v1';
/** OSV ecosystem identifier for Node.js / npm packages. */
const OSV_ECOSYSTEM = 'npm';
/** Network timeout in milliseconds for OSV API requests. */
const REQUEST_TIMEOUT_MS = 15_000;
/** Maximum queries per batch request (OSV supports up to 1000). */
const BATCH_CHUNK_SIZE = 1000;

// ---------------------------------------------------------------------------
// Error class
// ---------------------------------------------------------------------------

/** Thrown when the OSV provider encounters a network or API error. */
export class OsvProviderError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'OsvProviderError';
  }
}

// ---------------------------------------------------------------------------
// OSV API types (internal — not exposed to consumers)
// ---------------------------------------------------------------------------

interface OsvPackage {
  name: string;
  ecosystem: string;
}

interface OsvQuery {
  package: OsvPackage;
  version?: string;
}

interface OsvSeverity {
  type: string;   // e.g. "CVSS_V3", "CVSS_V4"
  score: string;  // e.g. "CVSS:3.1/AV:N/AC:L/..."
}

interface OsvRangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

interface OsvRange {
  type: string;  // "SEMVER", "ECOSYSTEM", "GIT"
  events: OsvRangeEvent[];
}

interface OsvAffected {
  package: OsvPackage;
  ranges?: OsvRange[];
  versions?: string[];
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  severity?: OsvSeverity[];
  affected?: OsvAffected[];
  references?: Array<{ type?: string; url: string }>;
  published?: string;
  modified?: string;
  aliases?: string[];
  database_specific?: {
    severity?: string;
    [key: string]: unknown;
  };
  ecosystem_specific?: {
    severity?: string;
    [key: string]: unknown;
  };
}

interface OsvBatchResult {
  vulns?: OsvVuln[];
}

interface OsvBatchResponse {
  results: OsvBatchResult[];
  next_page_token?: string;
}

// ---------------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------------

type Severity = 'low' | 'medium' | 'high' | 'critical';

/**
 * Map a string severity label from OSV database_specific / ecosystem_specific fields.
 *
 * GitHub Security Advisory database uses:
 *   "CRITICAL", "HIGH", "MODERATE", "LOW"
 */
function mapLabelSeverity(label: string): Severity | null {
  switch (label.toUpperCase()) {
    case 'CRITICAL': return 'critical';
    case 'HIGH':     return 'high';
    case 'MODERATE':
    case 'MEDIUM':   return 'medium';
    case 'LOW':      return 'low';
    default:         return null;
  }
}

/**
 * Heuristic CVSS v3/v4 vector → severity mapping.
 *
 * The CVSS base score is not directly encoded in the vector string.
 * This heuristic approximates the score from the Confidentiality (C),
 * Integrity (I), Availability (A), and Scope (S) metric values.
 *
 * Mapping rationale (approximates CVSS v3 base score ranges):
 *   9.0–10.0 → critical  (≥2 High CIA impacts, or Scope:Changed + 1 High)
 *   7.0–8.9  → high      (1 High CIA impact)
 *   4.0–6.9  → medium    (any Medium CIA impact)
 *   0.1–3.9  → low       (all Low/None CIA impacts)
 *
 * This is a documented approximation, NOT an exact CVSS base score calculation.
 */
function parseCvssVector(vector: string): Severity | null {
  const metrics: Record<string, string> = {};
  for (const part of vector.split('/')) {
    const colonIdx = part.indexOf(':');
    if (colonIdx > 0) {
      metrics[part.slice(0, colonIdx)] = part.slice(colonIdx + 1);
    }
  }

  const c = metrics['C'] ?? 'N';
  const i = metrics['I'] ?? 'N';
  const a = metrics['A'] ?? 'N';
  const s = metrics['S'] ?? 'U';

  const highCount = [c, i, a].filter(v => v === 'H').length;
  const medCount  = [c, i, a].filter(v => v === 'M').length;

  if (highCount >= 3) return 'critical';
  if (s === 'C' && highCount >= 1) return 'critical';
  if (highCount >= 2) return 'critical';
  if (highCount >= 1) return 'high';
  if (medCount  >= 1) return 'medium';
  return 'low';
}

/**
 * Resolve the DevFoundry severity for a given OSV vulnerability entry.
 *
 * Priority order:
 *   1. database_specific.severity  (string label — most reliable for GHSA/npm)
 *   2. ecosystem_specific.severity (string label)
 *   3. CVSS vector heuristic       (first CVSS_V3 or CVSS_V4 entry)
 *   4. 'medium'                    (documented safe fallback)
 */
function resolveSeverity(vuln: OsvVuln): Severity {
  const dbSev = vuln.database_specific?.severity;
  if (typeof dbSev === 'string') {
    const s = mapLabelSeverity(dbSev);
    if (s) return s;
  }

  const ecoSev = vuln.ecosystem_specific?.severity;
  if (typeof ecoSev === 'string') {
    const s = mapLabelSeverity(ecoSev);
    if (s) return s;
  }

  if (Array.isArray(vuln.severity)) {
    for (const sev of vuln.severity) {
      if (sev.type === 'CVSS_V3' || sev.type === 'CVSS_V4') {
        const s = parseCvssVector(sev.score);
        if (s) return s;
      }
    }
  }

  // Documented fallback: 'medium' (not critical/high) to avoid over-alerting
  return 'medium';
}

// ---------------------------------------------------------------------------
// Fixed version extraction
// ---------------------------------------------------------------------------

/**
 * Extract the first fixed version from OSV affected ranges for the given package.
 * Looks for SEMVER ranges with a 'fixed' event.
 */
function extractFixedVersion(vuln: OsvVuln, packageName: string): string | undefined {
  if (!Array.isArray(vuln.affected)) return undefined;

  for (const affected of vuln.affected) {
    if (affected.package?.name !== packageName) continue;
    if (!Array.isArray(affected.ranges)) continue;
    for (const range of affected.ranges) {
      if (range.type !== 'SEMVER') continue;
      for (const event of range.events) {
        if (event.fixed) return event.fixed;
      }
    }
  }

  return undefined;
}

/**
 * Extract a human-readable affected range string from OSV SEMVER ranges.
 * Returns the first "introduced → fixed" range for the given package.
 */
function extractAffectedRange(vuln: OsvVuln, packageName: string): string {
  if (!Array.isArray(vuln.affected)) return 'unknown';

  for (const affected of vuln.affected) {
    if (affected.package?.name !== packageName) continue;
    if (!Array.isArray(affected.ranges)) continue;
    for (const range of affected.ranges) {
      if (range.type !== 'SEMVER') continue;
      const parts: string[] = [];
      for (const event of range.events) {
        if (event.introduced && event.introduced !== '0') parts.push(`>=${event.introduced}`);
        if (event.fixed) parts.push(`<${event.fixed}`);
      }
      if (parts.length > 0) return parts.join(', ');
    }
  }

  return 'unknown';
}

// ---------------------------------------------------------------------------
// OSV response normalizer
// ---------------------------------------------------------------------------

/**
 * Normalize a raw OSV vulnerability into a DevFoundry DependencyAdvisory.
 */
function normalizeVuln(vuln: OsvVuln, packageName: string): DependencyAdvisory {
  const fixedVersion = extractFixedVersion(vuln, packageName);
  const vulnerableRange = extractAffectedRange(vuln, packageName);
  const severity = resolveSeverity(vuln);

  const remediation = fixedVersion
    ? `Upgrade "${packageName}" to ${fixedVersion} or higher.`
    : `Review advisory ${vuln.id} and update "${packageName}" to a patched version.`;

  return {
    id: vuln.id,
    dependencyName: packageName,
    vulnerableRange,
    fixedVersion,
    severity,
    summary: vuln.summary ?? `Vulnerability found in ${packageName} (${vuln.id})`,
    source: 'osv',
    remediation,
    published: vuln.published,
    modified: vuln.modified,
  };
}

// ---------------------------------------------------------------------------
// HTTP batch fetch
// ---------------------------------------------------------------------------

/**
 * Send one or more POST /v1/querybatch requests to OSV.
 * Handles chunking into BATCH_CHUNK_SIZE batches.
 * Returns results positionally aligned with the input queries array.
 *
 * @throws OsvProviderError on any network, timeout, HTTP, or parse failure.
 */
async function fetchOsvBatch(queries: OsvQuery[]): Promise<OsvBatchResult[]> {
  const allResults: OsvBatchResult[] = [];

  for (let offset = 0; offset < queries.length; offset += BATCH_CHUNK_SIZE) {
    const chunk = queries.slice(offset, offset + BATCH_CHUNK_SIZE);
    const chunkResults = await fetchOsvChunk(chunk);
    allResults.push(...chunkResults);
  }

  return allResults;
}

/**
 * Send a single POST /v1/querybatch request for one chunk of queries.
 * Handles pagination via next_page_token if the batch endpoint returns one.
 */
async function fetchOsvChunk(chunk: OsvQuery[]): Promise<OsvBatchResult[]> {
  // Start with empty results for each query
  const merged: OsvBatchResult[] = chunk.map(() => ({ vulns: [] }));
  let pageToken: string | undefined;

  do {
    const body: { queries: OsvQuery[]; page_token?: string } = { queries: chunk };
    if (pageToken) body.page_token = pageToken;

    let response: Response;
    try {
      response = await fetch(`${OSV_API_BASE}/querybatch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (err) {
      if (err instanceof Error && err.name === 'TimeoutError') {
        throw new OsvProviderError(`OSV API request timed out after ${REQUEST_TIMEOUT_MS}ms`, err);
      }
      throw new OsvProviderError(`OSV API network error: ${err instanceof Error ? err.message : String(err)}`, err);
    }

    if (!response.ok) {
      throw new OsvProviderError(`OSV API returned HTTP ${response.status} ${response.statusText}`);
    }

    let data: OsvBatchResponse;
    try {
      data = await response.json() as OsvBatchResponse;
    } catch (err) {
      throw new OsvProviderError('OSV API returned malformed JSON response', err);
    }

    if (!Array.isArray(data.results)) {
      throw new OsvProviderError('OSV API response missing results array');
    }

    // Merge vulns positionally
    for (let i = 0; i < Math.min(data.results.length, merged.length); i++) {
      const existing = merged[i].vulns ?? [];
      const incoming = data.results[i].vulns ?? [];
      merged[i] = { vulns: [...existing, ...incoming] };
    }

    pageToken = data.next_page_token;
  } while (pageToken);

  return merged;
}

// ---------------------------------------------------------------------------
// OsvAdvisoryProvider
// ---------------------------------------------------------------------------

/** Input shape for prefetchAll. */
interface DepInput {
  name: string;
  version?: string;
}

/**
 * Advisory provider backed by the OSV.dev public vulnerability database.
 *
 * Usage:
 *   const provider = new OsvAdvisoryProvider();
 *   // In scanWithAdvisories(), prefetchAll() is called automatically.
 */
export class OsvAdvisoryProvider implements DependencyAdvisoryProvider {
  readonly providerId = 'osv';

  /**
   * In-memory advisory cache for the lifetime of this provider instance.
   * Key: "name@version" (version may be empty string if unknown).
   */
  private readonly cache = new Map<string, DependencyAdvisory[]>();

  /**
   * Bulk-fetch advisories for all given dependencies in one OSV API round-trip.
   * Results are stored in the in-memory cache.
   * Deduplicates by name@version before querying.
   *
   * @throws OsvProviderError on network/API failure.
   */
  async prefetchAll(deps: DepInput[]): Promise<void> {
    // Deduplicate by "name@version"
    const uniqueMap = new Map<string, DepInput>();
    for (const dep of deps) {
      const key = this.cacheKey(dep.name, dep.version);
      if (!uniqueMap.has(key) && !this.cache.has(key)) {
        uniqueMap.set(key, dep);
      }
    }

    if (uniqueMap.size === 0) return;

    // Build OSV query list, preserving order for positional result mapping
    const orderedKeys: string[] = [];
    const queries: OsvQuery[] = [];

    for (const [key, dep] of uniqueMap) {
      orderedKeys.push(key);
      const q: OsvQuery = { package: { name: dep.name, ecosystem: OSV_ECOSYSTEM } };
      if (dep.version) q.version = dep.version;
      queries.push(q);
    }

    // Fetch (may throw OsvProviderError — propagated to scanWithAdvisories)
    const results = await fetchOsvBatch(queries);

    // Populate cache
    for (let i = 0; i < orderedKeys.length; i++) {
      const key = orderedKeys[i];
      const result = results[i] ?? { vulns: [] };
      const depInput = uniqueMap.get(key)!;
      const advisories = (result.vulns ?? []).map(v => normalizeVuln(v, depInput.name));
      this.cache.set(key, advisories);
    }
  }

  /**
   * Return cached advisories for a single package.
   * If not in cache (e.g. prefetchAll was not called), performs an individual query.
   *
   * @throws OsvProviderError on network/API failure.
   */
  async getAdvisories(packageName: string, installedVersion?: string): Promise<DependencyAdvisory[]> {
    const key = this.cacheKey(packageName, installedVersion);
    if (this.cache.has(key)) {
      return this.cache.get(key)!;
    }

    // Individual fallback query
    const q: OsvQuery = { package: { name: packageName, ecosystem: OSV_ECOSYSTEM } };
    if (installedVersion) q.version = installedVersion;

    const results = await fetchOsvBatch([q]);
    const advisories = (results[0]?.vulns ?? []).map(v => normalizeVuln(v, packageName));
    this.cache.set(key, advisories);
    return advisories;
  }

  private cacheKey(name: string, version?: string): string {
    return `${name}@${version ?? ''}`;
  }
}
