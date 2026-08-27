/**
 * @devfoundry/policy unit tests.
 */
import { describe, it, expect } from 'vitest';
import { evaluatePolicy, DEFAULT_CI_POLICY } from '../src/engine.js';
import type { Finding } from '@devfoundry/core';
import type { VerificationResult } from '@devfoundry/verification';

// ---------------------------------------------------------------------------
// Helpers
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
    remediation: 'Revoke token.',
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
    remediation: 'Upgrade lodash.',
    ...overrides,
  };
}

function makeVerificationResult(overrides?: Partial<VerificationResult>): VerificationResult {
  return {
    status: 'passed',
    resolved: [],
    remaining: [],
    newFindings: [],
    uncertain: [],
    previousFindings: [],
    currentFindings: [],
    advisoryInfo: { provider: 'osv', status: 'ok' },
    summary: {
      previousCount: 0,
      currentCount: 0,
      resolvedCount: 0,
      remainingCount: 0,
      newCount: 0,
      uncertainCount: 0,
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

describe('evaluatePolicy', () => {
  it('no findings -> pass', () => {
    const verification = makeVerificationResult();
    const result = evaluatePolicy(verification, DEFAULT_CI_POLICY);
    expect(result.passed).toBe(true);
    expect(result.failed).toBe(false);
    expect(result.matchedFindings).toHaveLength(0);
  });

  it('existing baseline finding -> pass', () => {
    // Only newFindings violate policies. Remaining baseline findings are whitelisted.
    const baselineFinding = makeFinding('A');
    const verification = makeVerificationResult({
      remaining: [baselineFinding],
      previousFindings: [baselineFinding],
      currentFindings: [baselineFinding],
      summary: {
        previousCount: 1,
        currentCount: 1,
        resolvedCount: 0,
        remainingCount: 1,
        newCount: 0,
        uncertainCount: 0,
      },
    });

    const result = evaluatePolicy(verification, DEFAULT_CI_POLICY);
    expect(result.passed).toBe(true);
    expect(result.failed).toBe(false);
  });

  it('new low finding -> fail (with default policy failOnNewFindings: true)', () => {
    const newLow = makeFinding('B', { severity: 'low' });
    const verification = makeVerificationResult({
      newFindings: [newLow],
      currentFindings: [newLow],
      summary: {
        previousCount: 0,
        currentCount: 1,
        resolvedCount: 0,
        remainingCount: 0,
        newCount: 1,
        uncertainCount: 0,
      },
    });

    const result = evaluatePolicy(verification, DEFAULT_CI_POLICY);
    expect(result.passed).toBe(false);
    expect(result.failed).toBe(true);
    expect(result.reasons[0]).toContain('NEW finding');
  });

  it('new low finding -> pass (when failOnNewFindings: false)', () => {
    const newLow = makeFinding('B', { severity: 'low' });
    const verification = makeVerificationResult({
      newFindings: [newLow],
      currentFindings: [newLow],
    });

    const customPolicy = {
      ...DEFAULT_CI_POLICY,
      failOnNewFindings: false,
    };

    const result = evaluatePolicy(verification, customPolicy);
    expect(result.passed).toBe(true);
    expect(result.failed).toBe(false);
  });

  it('new critical finding -> fail (with failOnNewFindings: false, failOnCritical: true)', () => {
    const newCritical = makeFinding('C', { severity: 'critical' });
    const verification = makeVerificationResult({
      newFindings: [newCritical],
      currentFindings: [newCritical],
    });

    const customPolicy = {
      ...DEFAULT_CI_POLICY,
      failOnNewFindings: false,
      failOnCritical: true,
    };

    const result = evaluatePolicy(verification, customPolicy);
    expect(result.passed).toBe(false);
    expect(result.failed).toBe(true);
    expect(result.reasons[0]).toContain('CRITICAL finding');
  });

  it('existing critical baseline finding -> pass (does not fail build)', () => {
    const criticalBaseline = makeFinding('C', { severity: 'critical' });
    const verification = makeVerificationResult({
      remaining: [criticalBaseline],
      previousFindings: [criticalBaseline],
      currentFindings: [criticalBaseline],
    });

    const result = evaluatePolicy(verification, DEFAULT_CI_POLICY);
    expect(result.passed).toBe(true);
    expect(result.failed).toBe(false);
  });

  it('new secret (high severity) -> fail', () => {
    const newSecret = makeFinding('S', { severity: 'high', category: 'security' });
    const verification = makeVerificationResult({
      newFindings: [newSecret],
      currentFindings: [newSecret],
    });

    const customPolicy = {
      ...DEFAULT_CI_POLICY,
      failOnNewFindings: false,
      failOnSecrets: true,
    };

    const result = evaluatePolicy(verification, customPolicy);
    expect(result.passed).toBe(false);
    expect(result.failed).toBe(true);
    expect(result.reasons[0]).toContain('HIGH/CRITICAL secret');
  });

  it('new vulnerable dependency (high severity) -> fail', () => {
    const newVuln = makeVulnFinding('V', { severity: 'high' });
    const verification = makeVerificationResult({
      newFindings: [newVuln],
      currentFindings: [newVuln],
    });

    const customPolicy = {
      ...DEFAULT_CI_POLICY,
      failOnNewFindings: false,
      failOnVulnerabilities: true,
    };

    const result = evaluatePolicy(verification, customPolicy);
    expect(result.passed).toBe(false);
    expect(result.failed).toBe(true);
    expect(result.reasons[0]).toContain('HIGH vulnerability');
  });

  it('advisory unavailable -> verification result is partial, but evaluation itself does not fail unless there are new violations', () => {
    const verification = makeVerificationResult({
      status: 'partial',
      advisoryInfo: { provider: 'osv', status: 'unavailable', detail: 'ECONNREFUSED' },
    });

    const result = evaluatePolicy(verification, DEFAULT_CI_POLICY);
    expect(result.passed).toBe(true); // Passes policy because no new findings/violations exist
    expect(result.failed).toBe(false);
  });
});
