/**
 * OsvAdvisoryProvider unit tests — all HTTP calls are mocked via vi.stubGlobal('fetch').
 * No live network requests are made.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { OsvAdvisoryProvider, OsvProviderError } from '../src/providers/osv.js';
import { scanWithAdvisories, NoOpAdvisoryProvider, MockAdvisoryProvider } from '../src/advisory.js';
import type { DependencyAnalysis } from '../src/model.js';

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

function mockFetch(response: unknown, status = 200, ok = true): void {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
    ok,
    status,
    statusText: ok ? 'OK' : 'Internal Server Error',
    json: async () => response,
  }));
}

function mockFetchError(err: Error): void {
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(err));
}

function makeAnalysis(deps: { name: string; version?: string }[]): DependencyAnalysis {
  return {
    dependencies: deps.map(d => ({
      name: d.name,
      versionSpec: d.version ? `^${d.version}` : 'unknown',
      installedVersion: d.version,
      depType: 'production' as const,
      direct: 'direct' as const,
      source: 'package.json',
    })),
    packageManager: 'npm',
    metrics: { total: deps.length, direct: deps.length, transitive: 0, outdated: 0, vulnerable: 0 },
  };
}

/** A realistic OSV vulnerability entry for lodash 4.17.20. */
const LODASH_VULN = {
  id: 'GHSA-p6mc-m468-83gw',
  summary: 'Prototype Pollution in lodash',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
  database_specific: { severity: 'HIGH' },
  affected: [{
    package: { name: 'lodash', ecosystem: 'npm' },
    ranges: [{
      type: 'SEMVER',
      events: [{ introduced: '0' }, { fixed: '4.17.21' }],
    }],
  }],
  references: [{ url: 'https://github.com/lodash/lodash/pull/5085' }],
  published: '2021-05-19T00:00:00Z',
  modified: '2023-03-06T00:00:00Z',
};

// ---------------------------------------------------------------------------
// afterEach cleanup
// ---------------------------------------------------------------------------

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

// ---------------------------------------------------------------------------
// Test: successful single vulnerability
// ---------------------------------------------------------------------------

describe('OsvAdvisoryProvider — single vulnerability found', () => {
  beforeEach(() => {
    mockFetch({ results: [{ vulns: [LODASH_VULN] }] });
  });

  it('returns one advisory for a vulnerable package', async () => {
    const provider = new OsvAdvisoryProvider();
    const advisories = await provider.getAdvisories('lodash', '4.17.20');
    expect(advisories).toHaveLength(1);
    expect(advisories[0].id).toBe('GHSA-p6mc-m468-83gw');
    expect(advisories[0].dependencyName).toBe('lodash');
    expect(advisories[0].source).toBe('osv');
    expect(advisories[0].fixedVersion).toBe('4.17.21');
    expect(advisories[0].vulnerableRange).toBe('<4.17.21');
    expect(advisories[0].severity).toBe('high');
    expect(advisories[0].summary).toContain('Prototype Pollution');
    expect(advisories[0].published).toBe('2021-05-19T00:00:00Z');
    expect(advisories[0].modified).toBe('2023-03-06T00:00:00Z');
    expect(advisories[0].remediation).toContain('4.17.21');
  });

  it('sends correct ecosystem and version in batch request', async () => {
    const provider = new OsvAdvisoryProvider();
    await provider.getAdvisories('lodash', '4.17.20');

    const fetchMock = vi.mocked(fetch);
    expect(fetchMock).toHaveBeenCalledOnce();
    const call = fetchMock.mock.calls[0];
    const body = JSON.parse(call[1]!.body as string);
    expect(body.queries[0].package.ecosystem).toBe('npm');
    expect(body.queries[0].package.name).toBe('lodash');
    expect(body.queries[0].version).toBe('4.17.20');
  });
});

// ---------------------------------------------------------------------------
// Test: no vulnerabilities
// ---------------------------------------------------------------------------

describe('OsvAdvisoryProvider — no vulnerabilities', () => {
  it('returns empty array when vulns is empty', async () => {
    mockFetch({ results: [{ vulns: [] }] });
    const provider = new OsvAdvisoryProvider();
    const advisories = await provider.getAdvisories('lodash', '4.17.21');
    expect(advisories).toHaveLength(0);
  });

  it('returns empty array when vulns key is absent', async () => {
    mockFetch({ results: [{}] });
    const provider = new OsvAdvisoryProvider();
    const advisories = await provider.getAdvisories('lodash', '4.17.21');
    expect(advisories).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Test: multiple vulnerabilities for one package
// ---------------------------------------------------------------------------

describe('OsvAdvisoryProvider — multiple vulnerabilities for one package', () => {
  it('returns all vulnerabilities', async () => {
    const vuln2 = { ...LODASH_VULN, id: 'GHSA-xxxx-yyyy-zzzz', summary: 'Another issue' };
    mockFetch({ results: [{ vulns: [LODASH_VULN, vuln2] }] });
    const provider = new OsvAdvisoryProvider();
    const advisories = await provider.getAdvisories('lodash', '4.17.20');
    expect(advisories).toHaveLength(2);
    expect(advisories.map(a => a.id)).toContain('GHSA-p6mc-m468-83gw');
    expect(advisories.map(a => a.id)).toContain('GHSA-xxxx-yyyy-zzzz');
  });
});

// ---------------------------------------------------------------------------
// Test: multiple packages in batch via prefetchAll
// ---------------------------------------------------------------------------

describe('OsvAdvisoryProvider — multiple packages in batch', () => {
  it('maps results positionally to packages', async () => {
    mockFetch({
      results: [
        { vulns: [LODASH_VULN] },
        { vulns: [] },
      ],
    });
    const provider = new OsvAdvisoryProvider();
    await provider.prefetchAll([
      { name: 'lodash', version: '4.17.20' },
      { name: 'express', version: '4.18.2' },
    ]);

    const lodashAdvisories = await provider.getAdvisories('lodash', '4.17.20');
    const expressAdvisories = await provider.getAdvisories('express', '4.18.2');
    expect(lodashAdvisories).toHaveLength(1);
    expect(expressAdvisories).toHaveLength(0);

    // Only one HTTP call should have been made
    expect(vi.mocked(fetch)).toHaveBeenCalledOnce();
  });

  it('sends all packages in one batch request body', async () => {
    mockFetch({ results: [{ vulns: [] }, { vulns: [] }] });
    const provider = new OsvAdvisoryProvider();
    await provider.prefetchAll([
      { name: 'lodash', version: '4.17.20' },
      { name: 'express', version: '4.18.2' },
    ]);

    const body = JSON.parse(vi.mocked(fetch).mock.calls[0][1]!.body as string);
    expect(body.queries).toHaveLength(2);
    expect(body.queries[0].package.name).toBe('lodash');
    expect(body.queries[1].package.name).toBe('express');
  });
});

// ---------------------------------------------------------------------------
// Test: duplicate package+version inputs are deduplicated
// ---------------------------------------------------------------------------

describe('OsvAdvisoryProvider — deduplication', () => {
  it('sends only one request for repeated package+version', async () => {
    mockFetch({ results: [{ vulns: [LODASH_VULN] }] });
    const provider = new OsvAdvisoryProvider();
    await provider.prefetchAll([
      { name: 'lodash', version: '4.17.20' },
      { name: 'lodash', version: '4.17.20' }, // duplicate
    ]);

    expect(vi.mocked(fetch)).toHaveBeenCalledOnce();
    const body = JSON.parse(vi.mocked(fetch).mock.calls[0][1]!.body as string);
    expect(body.queries).toHaveLength(1);
  });

  it('does not re-query already cached packages', async () => {
    mockFetch({ results: [{ vulns: [LODASH_VULN] }] });
    const provider = new OsvAdvisoryProvider();
    await provider.getAdvisories('lodash', '4.17.20'); // fills cache

    await provider.prefetchAll([{ name: 'lodash', version: '4.17.20' }]); // should hit cache

    expect(vi.mocked(fetch)).toHaveBeenCalledOnce(); // only first call
  });
});

// ---------------------------------------------------------------------------
// Test: malformed JSON response
// ---------------------------------------------------------------------------

describe('OsvAdvisoryProvider — malformed response', () => {
  it('throws OsvProviderError on malformed JSON', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => { throw new SyntaxError('Unexpected token'); },
    }));
    const provider = new OsvAdvisoryProvider();
    await expect(provider.getAdvisories('lodash', '4.17.20')).rejects.toBeInstanceOf(OsvProviderError);
  });

  it('throws OsvProviderError when results array is missing', async () => {
    mockFetch({ unexpected: 'shape' });
    const provider = new OsvAdvisoryProvider();
    await expect(provider.getAdvisories('lodash', '4.17.20')).rejects.toBeInstanceOf(OsvProviderError);
  });
});

// ---------------------------------------------------------------------------
// Test: HTTP 500
// ---------------------------------------------------------------------------

describe('OsvAdvisoryProvider — HTTP 500', () => {
  it('throws OsvProviderError on HTTP 5xx', async () => {
    mockFetch({}, 500, false);
    const provider = new OsvAdvisoryProvider();
    await expect(provider.getAdvisories('lodash', '4.17.20')).rejects.toBeInstanceOf(OsvProviderError);
  });

  it('OsvProviderError message contains HTTP status', async () => {
    mockFetch({}, 500, false);
    const provider = new OsvAdvisoryProvider();
    try {
      await provider.getAdvisories('lodash', '4.17.20');
    } catch (err) {
      expect((err as OsvProviderError).message).toContain('500');
    }
  });
});

// ---------------------------------------------------------------------------
// Test: timeout / network failure
// ---------------------------------------------------------------------------

describe('OsvAdvisoryProvider — network failure', () => {
  it('throws OsvProviderError on AbortError (timeout)', async () => {
    const timeoutErr = Object.assign(new Error('The operation was aborted'), { name: 'TimeoutError' });
    mockFetchError(timeoutErr);
    const provider = new OsvAdvisoryProvider();
    await expect(provider.getAdvisories('lodash', '4.17.20')).rejects.toBeInstanceOf(OsvProviderError);
  });

  it('throws OsvProviderError on generic network failure', async () => {
    mockFetchError(new Error('ECONNREFUSED'));
    const provider = new OsvAdvisoryProvider();
    await expect(provider.getAdvisories('lodash', '4.17.20')).rejects.toBeInstanceOf(OsvProviderError);
  });
});

// ---------------------------------------------------------------------------
// Test: pagination via next_page_token
// ---------------------------------------------------------------------------

describe('OsvAdvisoryProvider — pagination', () => {
  it('fetches next page when next_page_token is returned', async () => {
    const vuln2 = { ...LODASH_VULN, id: 'GHSA-page-2-vuln' };
    let callCount = 0;
    vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => {
      callCount++;
      return {
        ok: true,
        status: 200,
        json: async () => callCount === 1
          ? { results: [{ vulns: [LODASH_VULN] }], next_page_token: 'page2tok' }
          : { results: [{ vulns: [vuln2] }] },
      };
    }));

    const provider = new OsvAdvisoryProvider();
    const advisories = await provider.getAdvisories('lodash', '4.17.20');
    expect(advisories).toHaveLength(2);
    expect(advisories.map(a => a.id)).toContain('GHSA-p6mc-m468-83gw');
    expect(advisories.map(a => a.id)).toContain('GHSA-page-2-vuln');
    expect(callCount).toBe(2);

    // Second call includes page_token
    const page2Body = JSON.parse(vi.mocked(fetch).mock.calls[1][1]!.body as string);
    expect(page2Body.page_token).toBe('page2tok');
  });
});

// ---------------------------------------------------------------------------
// Test: missing severity field
// ---------------------------------------------------------------------------

describe('OsvAdvisoryProvider — severity mapping', () => {
  it('falls back to medium when severity is absent', async () => {
    const vulnNoSeverity = { id: 'GHSA-no-sev', summary: 'No severity info', affected: [] };
    mockFetch({ results: [{ vulns: [vulnNoSeverity] }] });
    const provider = new OsvAdvisoryProvider();
    const advisories = await provider.getAdvisories('some-package', '1.0.0');
    expect(advisories[0].severity).toBe('medium');
  });

  it('maps database_specific.severity CRITICAL correctly', async () => {
    const vuln = { ...LODASH_VULN, database_specific: { severity: 'CRITICAL' }, severity: undefined };
    mockFetch({ results: [{ vulns: [vuln] }] });
    const provider = new OsvAdvisoryProvider();
    const advisories = await provider.getAdvisories('lodash', '4.17.20');
    expect(advisories[0].severity).toBe('critical');
  });

  it('maps database_specific.severity MODERATE to medium', async () => {
    const vuln = { ...LODASH_VULN, database_specific: { severity: 'MODERATE' }, severity: undefined };
    mockFetch({ results: [{ vulns: [vuln] }] });
    const provider = new OsvAdvisoryProvider();
    const advisories = await provider.getAdvisories('lodash', '4.17.20');
    expect(advisories[0].severity).toBe('medium');
  });

  it('maps CVSS_V3 score with 2+ High impacts to critical', async () => {
    const vuln = { ...LODASH_VULN, database_specific: undefined, severity: [
      { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    ]};
    mockFetch({ results: [{ vulns: [vuln] }] });
    const provider = new OsvAdvisoryProvider();
    const advisories = await provider.getAdvisories('lodash', '4.17.20');
    expect(advisories[0].severity).toBe('critical');
  });

  it('maps CVSS_V3 score with 1 High impact to high', async () => {
    const vuln = { ...LODASH_VULN, database_specific: undefined, severity: [
      { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N' },
    ]};
    mockFetch({ results: [{ vulns: [vuln] }] });
    const provider = new OsvAdvisoryProvider();
    const advisories = await provider.getAdvisories('lodash', '4.17.20');
    expect(advisories[0].severity).toBe('high');
  });
});

// ---------------------------------------------------------------------------
// Test: fixed version extraction
// ---------------------------------------------------------------------------

describe('OsvAdvisoryProvider — fixed version extraction', () => {
  it('extracts fixed version from SEMVER range events', async () => {
    mockFetch({ results: [{ vulns: [LODASH_VULN] }] });
    const provider = new OsvAdvisoryProvider();
    const advisories = await provider.getAdvisories('lodash', '4.17.20');
    expect(advisories[0].fixedVersion).toBe('4.17.21');
  });

  it('sets remediation with fixed version when available', async () => {
    mockFetch({ results: [{ vulns: [LODASH_VULN] }] });
    const provider = new OsvAdvisoryProvider();
    const advisories = await provider.getAdvisories('lodash', '4.17.20');
    expect(advisories[0].remediation).toContain('4.17.21');
    expect(advisories[0].remediation).toContain('lodash');
  });

  it('sets remediation without fixed version when not available', async () => {
    const vulnNoFix = { ...LODASH_VULN, affected: [] };
    mockFetch({ results: [{ vulns: [vulnNoFix] }] });
    const provider = new OsvAdvisoryProvider();
    const advisories = await provider.getAdvisories('lodash', '4.17.20');
    expect(advisories[0].fixedVersion).toBeUndefined();
    expect(advisories[0].remediation).toContain(LODASH_VULN.id);
  });
});

// ---------------------------------------------------------------------------
// Test: scanWithAdvisories returns AdvisoryResult with correct status
// ---------------------------------------------------------------------------

describe('scanWithAdvisories — AdvisoryResult status', () => {
  const mockAnalysis = makeAnalysis([{ name: 'lodash', version: '4.17.20' }]);

  it('returns status:ok on successful OSV query', async () => {
    mockFetch({ results: [{ vulns: [LODASH_VULN] }] });
    const provider = new OsvAdvisoryProvider();
    const result = await scanWithAdvisories(mockAnalysis, provider);
    expect(result.advisoryInfo.status).toBe('ok');
    expect(result.advisoryInfo.provider).toBe('osv');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe('vuln-GHSA-p6mc-m468-83gw');
  });

  it('returns status:unavailable on HTTP 500 — never claims 0 vulns', async () => {
    mockFetch({}, 500, false);
    const provider = new OsvAdvisoryProvider();
    const result = await scanWithAdvisories(mockAnalysis, provider);
    expect(result.advisoryInfo.status).toBe('unavailable');
    expect(result.advisoryInfo.provider).toBe('osv');
    expect(result.advisoryInfo.detail).toBeDefined();
    // findings is empty but status signals this is NOT a clean result
    expect(result.findings).toHaveLength(0);
  });

  it('returns status:unavailable on network failure — never claims 0 vulns', async () => {
    mockFetchError(new Error('ECONNREFUSED'));
    const provider = new OsvAdvisoryProvider();
    const result = await scanWithAdvisories(mockAnalysis, provider);
    expect(result.advisoryInfo.status).toBe('unavailable');
    expect(result.findings).toHaveLength(0);
  });

  it('returns status:not_checked for NoOpAdvisoryProvider', async () => {
    const provider = new NoOpAdvisoryProvider();
    const result = await scanWithAdvisories(mockAnalysis, provider);
    expect(result.advisoryInfo.status).toBe('not_checked');
    expect(result.advisoryInfo.provider).toBe('none');
    expect(result.findings).toHaveLength(0);
  });

  it('returns status:ok for MockAdvisoryProvider', async () => {
    const provider = new MockAdvisoryProvider([]);
    const result = await scanWithAdvisories(mockAnalysis, provider);
    expect(result.advisoryInfo.status).toBe('ok');
    expect(result.advisoryInfo.provider).toBe('mock');
  });
});

// ---------------------------------------------------------------------------
// Test: advisory-to-finding normalization
// ---------------------------------------------------------------------------

describe('scanWithAdvisories — finding normalization', () => {
  it('populates all required Finding fields', async () => {
    mockFetch({ results: [{ vulns: [LODASH_VULN] }] });
    const provider = new OsvAdvisoryProvider();
    const analysis = makeAnalysis([{ name: 'lodash', version: '4.17.20' }]);
    const result = await scanWithAdvisories(analysis, provider);

    const finding = result.findings[0];
    expect(finding.ruleId).toBe('vuln-GHSA-p6mc-m468-83gw');
    expect(finding.category).toBe('dependencies');
    expect(finding.severity).toBe('high');
    expect(finding.confidence).toBe('high');
    expect(finding.message).toContain('lodash');
    expect(finding.message).toContain('4.17.20');
    expect(finding.message).toContain('Prototype Pollution');
    expect(finding.fingerprint).toBeDefined();
    expect(finding.fingerprint.length).toBeGreaterThan(0);
    expect(finding.remediation).toContain('4.17.21');
    expect(finding.file).toBe('package.json');
  });

  it('deduplicates the same advisory for direct and transitive entries of same package', async () => {
    mockFetch({ results: [{ vulns: [LODASH_VULN] }, { vulns: [LODASH_VULN] }] });
    const analysis: DependencyAnalysis = {
      dependencies: [
        { name: 'lodash', versionSpec: '^4.17.20', installedVersion: '4.17.20', depType: 'production', direct: 'direct', source: 'package.json' },
        { name: 'lodash', versionSpec: '^4.17.20', installedVersion: '4.17.20', depType: 'production', direct: 'transitive', source: 'lockfile' },
      ],
      packageManager: 'npm',
      metrics: { total: 2, direct: 1, transitive: 1, outdated: 0, vulnerable: 0 },
    };
    const provider = new OsvAdvisoryProvider();
    const result = await scanWithAdvisories(analysis, provider);
    expect(result.findings).toHaveLength(1); // deduplicated
  });
});
