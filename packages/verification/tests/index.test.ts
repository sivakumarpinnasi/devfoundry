/**
 * @devfoundry/verification unit tests.
 *
 * All tests are deterministic — no network calls, no file I/O.
 * Fingerprint is the sole identity criterion in all tests.
 */
import { describe, it, expect } from 'vitest';
import { verifyFindings } from '../src/compare.js';
import type { Finding, AdvisoryInfo } from '@devfoundry/core';

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

function makeFinding(id: string, overrides?: Partial<Finding>): Finding {
  return {
    ruleId: 'github-token',
    category: 'security',
    severity: 'critical',
    message: `Finding ${id}`,
    file: 'src/config.js',
    fingerprint: `fp-${id}`,
    confidence: 'high',
    ...overrides,
  };
}

function makeVulnFinding(id: string, overrides?: Partial<Finding>): Finding {
  return {
    ruleId: `vuln-GHSA-${id}`,
    category: 'dependencies',
    severity: 'high',
    message: `Dependency "lodash" (4.17.20) is vulnerable`,
    file: 'package.json',
    fingerprint: `vuln-fp-${id}`,
    confidence: 'high',
    ...overrides,
  };
}

const advisoryOk: AdvisoryInfo = { provider: 'osv', status: 'ok' };
const advisoryUnavailable: AdvisoryInfo = { provider: 'osv', status: 'unavailable', detail: 'ECONNREFUSED' };
const advisoryOffline: AdvisoryInfo = { provider: 'none', status: 'not_checked' };

// ---------------------------------------------------------------------------
// All findings resolved
// ---------------------------------------------------------------------------

describe('verifyFindings — all resolved', () => {
  it('returns status:passed when all previous findings are absent from current', () => {
    const prev = [makeFinding('A'), makeFinding('B')];
    const curr: Finding[] = [];
    const result = verifyFindings(prev, curr, advisoryOk);

    expect(result.status).toBe('passed');
    expect(result.resolved).toHaveLength(2);
    expect(result.remaining).toHaveLength(0);
    expect(result.newFindings).toHaveLength(0);
    expect(result.uncertain).toHaveLength(0);
    expect(result.summary.resolvedCount).toBe(2);
    expect(result.summary.remainingCount).toBe(0);
  });

  it('resolved bucket contains the original finding objects from previous', () => {
    const prev = [makeFinding('A')];
    const result = verifyFindings(prev, [], advisoryOk);
    expect(result.resolved[0].fingerprint).toBe('fp-A');
  });
});

// ---------------------------------------------------------------------------
// Some findings resolved, some remaining
// ---------------------------------------------------------------------------

describe('verifyFindings — partial resolution', () => {
  it('returns status:partial when some resolved and some remain', () => {
    const prev = [makeFinding('A'), makeFinding('B'), makeFinding('C')];
    const curr = [makeFinding('B')]; // A resolved, B remains, C resolved
    const result = verifyFindings(prev, curr, advisoryOk);

    expect(result.status).toBe('partial');
    expect(result.resolved.map(f => f.fingerprint)).toContain('fp-A');
    expect(result.resolved.map(f => f.fingerprint)).toContain('fp-C');
    expect(result.remaining.map(f => f.fingerprint)).toContain('fp-B');
    expect(result.newFindings).toHaveLength(0);
    expect(result.summary.resolvedCount).toBe(2);
    expect(result.summary.remainingCount).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Findings remain (nothing resolved)
// ---------------------------------------------------------------------------

describe('verifyFindings — all remaining (failed)', () => {
  it('returns status:failed when all previous findings still present', () => {
    const prev = [makeFinding('A'), makeFinding('B')];
    const curr = [makeFinding('A'), makeFinding('B')];
    const result = verifyFindings(prev, curr, advisoryOk);

    expect(result.status).toBe('failed');
    expect(result.remaining).toHaveLength(2);
    expect(result.resolved).toHaveLength(0);
    expect(result.newFindings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// New findings introduced
// ---------------------------------------------------------------------------

describe('verifyFindings — new findings introduced', () => {
  it('returns status:failed when new findings appear', () => {
    const prev = [makeFinding('A')];
    const curr = [makeFinding('B')]; // A resolved but B is new
    const result = verifyFindings(prev, curr, advisoryOk);

    expect(result.status).toBe('failed');
    expect(result.resolved.map(f => f.fingerprint)).toContain('fp-A');
    expect(result.newFindings.map(f => f.fingerprint)).toContain('fp-B');
    expect(result.summary.newCount).toBe(1);
    expect(result.summary.resolvedCount).toBe(1);
  });

  it('returns status:failed when new findings appear alongside remaining', () => {
    const prev = [makeFinding('A')];
    const curr = [makeFinding('A'), makeFinding('NEW')];
    const result = verifyFindings(prev, curr, advisoryOk);

    expect(result.status).toBe('failed');
    expect(result.remaining).toHaveLength(1);
    expect(result.newFindings).toHaveLength(1);
    expect(result.newFindings[0].fingerprint).toBe('fp-NEW');
  });
});

// ---------------------------------------------------------------------------
// No previous findings
// ---------------------------------------------------------------------------

describe('verifyFindings — no previous findings', () => {
  it('returns status:passed when no previous and no current findings', () => {
    const result = verifyFindings([], [], advisoryOk);
    expect(result.status).toBe('passed');
    expect(result.resolved).toHaveLength(0);
    expect(result.remaining).toHaveLength(0);
    expect(result.newFindings).toHaveLength(0);
    expect(result.summary.previousCount).toBe(0);
    expect(result.summary.currentCount).toBe(0);
  });

  it('returns status:failed when no previous but current has findings (all new)', () => {
    const curr = [makeFinding('A'), makeFinding('B')];
    const result = verifyFindings([], curr, advisoryOk);
    expect(result.status).toBe('failed');
    expect(result.newFindings).toHaveLength(2);
    expect(result.resolved).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Fingerprint identity stability
// ---------------------------------------------------------------------------

describe('verifyFindings — fingerprint is sole identity', () => {
  it('uses fingerprint not ruleId or message for comparison', () => {
    const prev = [makeFinding('A', { ruleId: 'old-rule', message: 'Old message' })];
    // Same fingerprint, different ruleId and message → still "remaining"
    const curr = [makeFinding('A', { ruleId: 'new-rule', message: 'New message' })];
    const result = verifyFindings(prev, curr, advisoryOk);

    expect(result.remaining).toHaveLength(1);
    expect(result.resolved).toHaveLength(0);
    expect(result.newFindings).toHaveLength(0);
    expect(result.status).toBe('failed');
  });

  it('same ruleId but different fingerprint = previous resolved, current is new', () => {
    const prev = [makeFinding('A', { ruleId: 'github-token', fingerprint: 'fp-old' })];
    const curr = [makeFinding('B', { ruleId: 'github-token', fingerprint: 'fp-new' })];
    const result = verifyFindings(prev, curr, advisoryOk);

    expect(result.resolved).toHaveLength(1); // fp-old gone
    expect(result.newFindings).toHaveLength(1); // fp-new is new
    expect(result.status).toBe('failed');
  });
});

// ---------------------------------------------------------------------------
// Advisory provider unavailable — uncertainty handling
// ---------------------------------------------------------------------------

describe('verifyFindings — advisory unavailable', () => {
  it('moves previous dep-vuln findings to uncertain when advisory check failed', () => {
    const prev = [makeVulnFinding('xxx')];
    const curr: Finding[] = []; // OSV returned no vulns but check failed
    const result = verifyFindings(prev, curr, advisoryUnavailable);

    expect(result.uncertain).toHaveLength(1);
    expect(result.resolved).toHaveLength(0);
    expect(result.uncertain[0].ruleId).toBe('vuln-GHSA-xxx');
    // Cannot claim passed since dep vuln status is unknown
    expect(result.status).toBe('partial');
  });

  it('does not move non-dep findings to uncertain', () => {
    const prev = [makeFinding('A'), makeVulnFinding('xxx')];
    const curr: Finding[] = [];
    const result = verifyFindings(prev, curr, advisoryUnavailable);

    // Security finding IS resolved (advisory availability doesn't affect it)
    expect(result.resolved.map(f => f.fingerprint)).toContain('fp-A');
    // Dep vuln goes to uncertain
    expect(result.uncertain.map(f => f.fingerprint)).toContain('vuln-fp-xxx');
    expect(result.summary.uncertainCount).toBe(1);
  });

  it('dep vuln that is still PRESENT (remaining) is not moved to uncertain', () => {
    const prev = [makeVulnFinding('xxx')];
    const curr = [makeVulnFinding('xxx')]; // still present
    const result = verifyFindings(prev, curr, advisoryUnavailable);

    expect(result.remaining).toHaveLength(1);
    expect(result.uncertain).toHaveLength(0);
    // Still present → remaining, status failed
    expect(result.status).toBe('failed');
  });

  it('passes through advisory info on the result', () => {
    const result = verifyFindings([], [], advisoryUnavailable);
    expect(result.advisoryInfo?.status).toBe('unavailable');
    expect(result.advisoryInfo?.provider).toBe('osv');
  });
});

// ---------------------------------------------------------------------------
// Offline verification
// ---------------------------------------------------------------------------

describe('verifyFindings — offline (not_checked)', () => {
  it('treats dep-vuln findings as uncertain when offline (not_checked)', () => {
    // offline (not_checked) means we cannot verify dep vulnerabilities
    const prev = [makeVulnFinding('xxx')];
    const curr: Finding[] = [];
    const result = verifyFindings(prev, curr, advisoryOffline);

    expect(result.resolved).toHaveLength(0);
    expect(result.uncertain).toHaveLength(1);
    expect(result.status).toBe('partial');
  });

  it('allows security-only findings to be resolved and PASSED offline', () => {
    const prev = [makeFinding('A')];
    const curr: Finding[] = [];
    const result = verifyFindings(prev, curr, advisoryOffline);

    expect(result.resolved).toHaveLength(1);
    expect(result.uncertain).toHaveLength(0);
    expect(result.status).toBe('passed');
  });

  it('still detects new non-dep findings in offline mode', () => {
    const prev: Finding[] = [];
    const curr = [makeFinding('NEW')];
    const result = verifyFindings(prev, curr, advisoryOffline);
    expect(result.newFindings).toHaveLength(1);
    expect(result.status).toBe('failed');
  });
});

// ---------------------------------------------------------------------------
// Summary fields
// ---------------------------------------------------------------------------

describe('verifyFindings — summary', () => {
  it('correctly populates all summary counts', () => {
    const prev = [makeFinding('A'), makeFinding('B'), makeFinding('C')];
    const curr = [makeFinding('B'), makeFinding('D')]; // A&C resolved, B remains, D new
    const result = verifyFindings(prev, curr, advisoryOk);

    expect(result.summary.previousCount).toBe(3);
    expect(result.summary.currentCount).toBe(2);
    expect(result.summary.resolvedCount).toBe(2);
    expect(result.summary.remainingCount).toBe(1);
    expect(result.summary.newCount).toBe(1);
    expect(result.summary.uncertainCount).toBe(0);
  });

  it('contains previousFindings and currentFindings verbatim', () => {
    const prev = [makeFinding('A')];
    const curr = [makeFinding('B')];
    const result = verifyFindings(prev, curr, advisoryOk);
    expect(result.previousFindings).toBe(prev);
    expect(result.currentFindings).toBe(curr);
  });
});

// ---------------------------------------------------------------------------
// Clean project (no findings ever)
// ---------------------------------------------------------------------------

describe('verifyFindings — clean project', () => {
  it('passed: no previous findings, no current findings', () => {
    const result = verifyFindings([], []);
    expect(result.status).toBe('passed');
    expect(result.summary.resolvedCount).toBe(0);
    expect(result.summary.newCount).toBe(0);
  });

  it('works without advisoryInfo argument', () => {
    const result = verifyFindings([], []);
    expect(result.advisoryInfo).toBeUndefined();
    expect(result.status).toBe('passed');
  });
});
