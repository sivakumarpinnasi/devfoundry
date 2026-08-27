/**
 * Advisory scanning for dependency vulnerabilities.
 *
 * Exports:
 *   - DependencyAdvisoryProvider interface (re-exported from model)
 *   - AdvisoryResult — return type of scanWithAdvisories()
 *   - NoOpAdvisoryProvider — skips advisory check, reports 'not_checked'
 *   - MockAdvisoryProvider — deterministic in-memory provider for tests
 *   - scanWithAdvisories() — orchestrates prefetch + per-dep scan + status tracking
 */
import { Finding } from '@devfoundry/core';
import {
  AdvisoryInfo,
  AdvisoryResult,
  AdvisoryStatus,
  DependencyAdvisory,
  DependencyAdvisoryProvider,
  DependencyAnalysis,
} from './model.js';
import { OsvProviderError } from './providers/osv.js';

export { DependencyAdvisoryProvider, AdvisoryResult, AdvisoryInfo, AdvisoryStatus };

// ---------------------------------------------------------------------------
// No-op provider — offline mode / intentional skip
// ---------------------------------------------------------------------------

/**
 * Advisory provider that performs no network requests and returns no advisories.
 * Used when --offline is specified.
 *
 * Advisory status reported: 'not_checked'.
 * The vulnerable count in reports will show "Not checked", NOT "0 ✓".
 */
export class NoOpAdvisoryProvider implements DependencyAdvisoryProvider {
  readonly providerId = 'none';

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async getAdvisories(_pkg: string, _ver?: string): Promise<DependencyAdvisory[]> {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Mock provider — for unit and integration tests only
// ---------------------------------------------------------------------------

/**
 * A configurable in-memory advisory provider for tests.
 * Feed it a list of advisories; it returns matching ones for each package name.
 * Does NOT make any network requests.
 *
 * Advisory status reported: 'ok'.
 */
export class MockAdvisoryProvider implements DependencyAdvisoryProvider {
  readonly providerId = 'mock';

  constructor(private readonly advisories: DependencyAdvisory[]) {}

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async getAdvisories(packageName: string, _ver?: string): Promise<DependencyAdvisory[]> {
    return this.advisories.filter(a => a.dependencyName === packageName);
  }
}

// ---------------------------------------------------------------------------
// Type guard for batch-capable providers
// ---------------------------------------------------------------------------

interface BatchableProvider extends DependencyAdvisoryProvider {
  prefetchAll(deps: Array<{ name: string; version?: string }>): Promise<void>;
}

function isBatchable(p: DependencyAdvisoryProvider): p is BatchableProvider {
  return typeof (p as BatchableProvider).prefetchAll === 'function';
}

// ---------------------------------------------------------------------------
// Advisory scan — main function
// ---------------------------------------------------------------------------

/**
 * Scan a resolved DependencyAnalysis against an advisory provider.
 *
 * Returns an AdvisoryResult containing:
 *   - findings: deduplicated Finding[] entries (empty if status !== 'ok')
 *   - advisoryInfo: provider identity and status
 *
 * IMPORTANT: findings.length === 0 does NOT mean "no vulnerabilities" unless
 * advisoryInfo.status === 'ok'. Always check the status before interpreting results.
 *
 * Deduplication key: `${ruleId}:${dep.name}` — one finding per advisory per package.
 */
export async function scanWithAdvisories(
  analysis: DependencyAnalysis,
  provider: DependencyAdvisoryProvider,
): Promise<AdvisoryResult> {

  const makeResult = (
    findings: Finding[],
    status: AdvisoryStatus,
    detail?: string,
  ): AdvisoryResult => ({
    findings,
    advisoryInfo: { provider: provider.providerId, status, detail },
  });

  // NoOp provider → skip and report not_checked
  if (provider.providerId === 'none') {
    return makeResult([], 'not_checked');
  }

  // Bulk pre-fetch (e.g. OsvAdvisoryProvider) — one HTTP round-trip for all deps
  if (isBatchable(provider)) {
    try {
      await provider.prefetchAll(
        analysis.dependencies.map(d => ({ name: d.name, version: d.installedVersion })),
      );
    } catch (err) {
      if (err instanceof OsvProviderError) {
        return makeResult([], 'unavailable', err.message);
      }
      const msg = err instanceof Error ? err.message : String(err);
      return makeResult([], 'unavailable', msg);
    }
  }

  // Iterate per-dep, reading from provider cache or making individual queries
  const seen = new Set<string>();
  const findings: Finding[] = [];

  for (const dep of analysis.dependencies) {
    let advisories: DependencyAdvisory[];
    try {
      advisories = await provider.getAdvisories(dep.name, dep.installedVersion);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return makeResult(findings, 'unavailable', msg);
    }

    for (const advisory of advisories) {
      const ruleId = `vuln-${advisory.id}`;
      const dedupKey = `${ruleId}:${dep.name}`;
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);

      const rawFP = `${ruleId}:${dep.source}:${dep.name}:${dep.installedVersion ?? dep.versionSpec}`;
      const fingerprint = Buffer.from(rawFP).toString('base64');

      findings.push({
        ruleId,
        category: 'dependencies',
        severity: advisory.severity,
        confidence: 'high',
        message:
          `Dependency "${dep.name}" (${dep.installedVersion ?? dep.versionSpec}) is vulnerable: ` +
          `${advisory.summary} [${advisory.vulnerableRange}]`,
        file: dep.source,
        fingerprint,
        remediation: advisory.remediation ??
          (advisory.fixedVersion
            ? `Upgrade "${dep.name}" to ${advisory.fixedVersion} or higher.`
            : `Review advisory ${advisory.id} and update "${dep.name}".`),
      });
    }
  }

  return makeResult(findings, 'ok');
}
