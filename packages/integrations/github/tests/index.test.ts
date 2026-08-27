/**
 * @devfoundry/integrations-github unit tests.
 */
import { describe, it, expect } from 'vitest';
import { generateAnnotations } from '../src/annotations.js';
import { generateSummaryMarkdown } from '../src/summary.js';
import { SimpleChangedFileSet } from '../src/git.js';
import type { Finding } from '@devfoundry/core';
import type { VerificationResult } from '@devfoundry/verification';
import type { PolicyResult } from '@devfoundry/policy';

function makeFinding(id: string, overrides?: Partial<Finding>): Finding {
  return {
    ruleId: 'github-token',
    category: 'security',
    severity: 'critical',
    message: `Exposed token: ghp_${id}`,
    file: 'src/secret.js',
    line: 12,
    confidence: 'high',
    fingerprint: `fp-${id}`,
    remediation: 'Rotate token.',
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

describe('GitHub Annotations', () => {
  it('generates annotations for new critical/high findings, dependency vulns, and secrets', () => {
    const f1 = makeFinding('A', { severity: 'critical', ruleId: 'github-token' });
    const f2 = makeFinding('B', { severity: 'low', ruleId: 'github-token' }); // still annotated because it's a secret
    const f3 = makeFinding('C', { severity: 'medium', ruleId: 'normal-diagnostic', category: 'detector' }); // skipped (medium normal)

    const verification = makeVerificationResult({
      newFindings: [f1, f2, f3],
    });

    const anns = generateAnnotations(verification);
    expect(anns).toHaveLength(2); // f1 and f2

    const annFiles = anns.map(a => a.file);
    expect(annFiles).toContain('src/secret.js');
  });

  it('redacts raw secret values from annotation messages', () => {
    const sensitiveFinding = makeFinding('XYZ', {
      ruleId: 'github-token',
      category: 'security',
      message: 'Found active GitHub token: ghp_XYZabc123',
    });

    const verification = makeVerificationResult({
      newFindings: [sensitiveFinding],
    });

    const anns = generateAnnotations(verification);
    expect(anns).toHaveLength(1);
    expect(anns[0].message).not.toContain('ghp_XYZ');
    expect(anns[0].message).toContain('credential');
  });
});

describe('GitHub Job Summary', () => {
  const policy: PolicyResult = {
    passed: false,
    failed: true,
    reasons: ['NEW critical finding: src/secret.js:12'],
    matchedFindings: [],
    summary: { totalViolations: 1 },
  };

  it('formats Markdown summary counts and status correctly', () => {
    const f = makeFinding('A');
    const verification = makeVerificationResult({
      newFindings: [f],
      remaining: [f, f],
      resolved: [f],
      advisoryInfo: { provider: 'osv', status: 'ok' },
    });

    const md = generateSummaryMarkdown(policy, verification);
    expect(md).toContain('# DevFoundry');
    expect(md).toContain('❌ FAILED');
    expect(md).toContain('| Security | 1 | 2 | 1 |');
    expect(md).toContain('- NEW critical finding: src/secret.js:12');
    expect(md).toContain('- Provider: OSV');
    expect(md).toContain('- Status: Checked');
  });
});

describe('Changed Files Set', () => {
  it('determines changed vs unchanged status correctly', () => {
    const changedSet = new SimpleChangedFileSet(['src/index.ts', 'package.json']);

    expect(changedSet.status('src/index.ts')).toBe('changed');
    expect(changedSet.status('package.json')).toBe('changed');
    expect(changedSet.status('tests/index.test.ts')).toBe('unchanged');
  });
});
