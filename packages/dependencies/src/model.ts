/**
 * Normalized dependency model and advisory interface for DevFoundry.
 * All other dependency sub-modules import types from here.
 */

export type DepType = 'production' | 'dev' | 'optional' | 'peer';
export type DepDirect = 'direct' | 'transitive';

/** A single resolved dependency entry. */
export interface Dependency {
  /** Package name as declared in package.json */
  name: string;
  /** Version range/specifier from package.json (e.g. "^4.17.21") */
  versionSpec: string;
  /** Exact version resolved by the lockfile */
  installedVersion?: string;
  /** Classification from package.json section */
  depType: DepType;
  /** Whether this dep is declared directly or pulled in transitively */
  direct: DepDirect;
  /** The file this entry was sourced from (e.g. "package.json", "pnpm-lock.yaml") */
  source: string;
}

/** Aggregated metrics over the full dependency graph. */
export interface DependencyMetrics {
  total: number;
  direct: number;
  transitive: number;
  /** Always 0 — requires registry lookup, not yet implemented */
  outdated: number;
  vulnerable: number;
}

/** Full result of dependency analysis for a project. */
export interface DependencyAnalysis {
  dependencies: Dependency[];
  packageManager?: string;
  metrics: DependencyMetrics;
}

/** A vulnerability advisory for a package. */
export interface DependencyAdvisory {
  id: string;
  dependencyName: string;
  /** Semver range that is affected, e.g. "<4.17.21" */
  vulnerableRange: string;
  /** First version where the vulnerability is fixed */
  fixedVersion?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  summary: string;
  /** Source identifier, e.g. "mock", "osv" */
  source: string;
  remediation?: string;
  /** OSV/GHSA published date, ISO8601 */
  published?: string;
  /** OSV/GHSA modified date, ISO8601 */
  modified?: string;
}

// ---------------------------------------------------------------------------
// Advisory status tracking
// ---------------------------------------------------------------------------

/**
 * The result of an advisory lookup round.
 *
 * - 'ok'          — The provider was contacted and responded successfully.
 * - 'unavailable' — The provider was unreachable or returned an error.
 *                   Findings MUST be treated as unknown, NOT as zero.
 * - 'not_checked' — The provider was intentionally skipped (e.g. --offline).
 *                   Vulnerability status is unknown, not zero.
 */
export type AdvisoryStatus = 'ok' | 'unavailable' | 'not_checked';

/** Metadata about the advisory lookup that produced findings. */
export interface AdvisoryInfo {
  /** Provider identifier: 'osv', 'none', 'mock', etc. */
  provider: string;
  status: AdvisoryStatus;
  /** Optional human-readable detail, e.g. an error message on failure. */
  detail?: string;
}

/**
 * Return type of scanWithAdvisories().
 * Callers MUST check advisoryInfo.status before interpreting findings.length === 0
 * as "no vulnerabilities" — it may mean the check failed or was skipped.
 */
export interface AdvisoryResult {
  findings: import('@devfoundry/core').Finding[];
  advisoryInfo: AdvisoryInfo;
}

/**
 * Interface for a source of dependency advisories.
 * Implementations may query OSV, GitHub Advisory DB, npm audit, etc.
 *
 * - MockAdvisoryProvider: deterministic in-memory provider for tests.
 * - NoOpAdvisoryProvider: returns nothing, reports status 'not_checked'.
 * - OsvAdvisoryProvider:  queries OSV.dev API, uses batch queries.
 */
export interface DependencyAdvisoryProvider {
  /**
   * Provider name used in output and reporting.
   * e.g. 'osv', 'none', 'mock'
   */
  readonly providerId: string;

  /**
   * Return advisories for a single package.
   * For batch-capable providers, call prefetchAll() first to avoid N serial requests.
   */
  getAdvisories(packageName: string, installedVersion?: string): Promise<DependencyAdvisory[]>;

  /**
   * Optional: bulk-fetch advisories for all dependencies in one or more HTTP requests.
   * If implemented, scanWithAdvisories() calls this before iterating per-package.
   * Implementations MUST cache results so subsequent getAdvisories() calls are instant.
   */
  prefetchAll?(deps: Array<{ name: string; version?: string }>): Promise<void>;
}
