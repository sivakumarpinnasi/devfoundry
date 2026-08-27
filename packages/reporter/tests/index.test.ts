import { describe, it, expect } from 'vitest';
import {
  formatDoctorReport,
  formatJsonReport,
  formatVerifyReport,
  formatVerifyJsonReport,
  formatCiReport,
  formatCiJsonReport,
  formatScanReport,
  formatScanJsonReport,
} from '../src/index.js';
import { AnalysisResult, AdvisoryInfo, PipelineResult } from '@devfoundry/core';
import { VerificationResult } from '@devfoundry/verification';
import { PolicyResult } from '@devfoundry/policy';

describe('reporter output formatting', () => {
  const advOk: AdvisoryInfo = { provider: 'osv', status: 'ok' };
  const advOffline: AdvisoryInfo = { provider: 'none', status: 'not_checked' };
  const advFailed: AdvisoryInfo = { provider: 'osv', status: 'unavailable', detail: 'ECONNREFUSED' };

  const cleanResult: AnalysisResult = {
    project: {
      type: 'Node.js / TypeScript',
      packageManager: 'pnpm',
      frameworks: ['React', 'Next.js']
    },
    findings: [],
    overallScore: 100,
    depMetrics: { total: 5, direct: 3, transitive: 2, outdated: 0, vulnerable: 0 },
    advisoryInfo: advOk,
  };

  const dirtyResult: AnalysisResult = {
    project: {
      type: 'Node.js / TypeScript',
      packageManager: 'pnpm',
      frameworks: ['React']
    },
    findings: [
      {
        ruleId: 'github-token',
        category: 'security',
        severity: 'critical',
        message: 'Potential GitHub Personal Access Token detected. (value: ghp_...3XYZ)',
        file: 'src/config.js',
        line: 5,
        confidence: 'high',
        fingerprint: 'fgp-123',
        remediation: 'Revoke token.'
      }
    ],
    overallScore: 60,
    depMetrics: { total: 10, direct: 6, transitive: 4, outdated: 0, vulnerable: 0 },
    advisoryInfo: advOk,
  };

  const vulnResult: AnalysisResult = {
    project: { type: 'Node.js', packageManager: 'npm', frameworks: [] },
    findings: [
      {
        ruleId: 'vuln-ADV-001',
        category: 'dependencies',
        severity: 'high',
        message: 'Dependency "lodash" (4.17.20) is vulnerable: Prototype Pollution [<4.17.21]',
        file: 'package.json',
        fingerprint: 'fp-vuln-001',
        remediation: 'Upgrade to 4.17.21+',
      }
    ],
    overallScore: 80,
    depMetrics: { total: 3, direct: 2, transitive: 1, outdated: 0, vulnerable: 1 },
    advisoryInfo: advOk,
  };

  const offlineResult: AnalysisResult = {
    project: { type: 'Node.js', packageManager: 'npm', frameworks: [] },
    findings: [],
    overallScore: 100,
    depMetrics: { total: 3, direct: 2, transitive: 1, outdated: 0, vulnerable: 0 },
    advisoryInfo: advOffline,
  };

  const failedResult: AnalysisResult = {
    project: { type: 'Node.js', packageManager: 'npm', frameworks: [] },
    findings: [],
    overallScore: 100,
    depMetrics: { total: 3, direct: 2, transitive: 1, outdated: 0, vulnerable: 0 },
    advisoryInfo: advFailed,
  };

  // -------------------------------------------------------------------------
  it('formats clean report with OSV advisory section', () => {
    const report = formatDoctorReport(cleanResult);
    expect(report).toContain('DEVFOUNDRY DOCTOR');
    expect(report).toContain('✓ No problems detected.');
    expect(report).toContain('100 / 100');
    expect(report).toContain('Total      5');
    expect(report).toContain('Direct     3');
    expect(report).toContain('Transitive 2');
    // Advisory section
    expect(report).toContain('Advisories');
    expect(report).toContain('Provider   OSV (osv.dev)');
    expect(report).toContain('Status     ✓ Checked');
    // Vulnerable shows count when status is ok
    expect(report).toContain('Vulnerable 0 ✓');
  });

  it('shows security findings correctly', () => {
    const report = formatDoctorReport(dirtyResult);
    expect(report).toContain('CRITICAL');
    expect(report).toContain('src/config.js:5');
    expect(report).toContain('github-token');
    expect(report).toContain('Fingerprint:  fgp-123');
    expect(report).toContain('Remediation:  Revoke token.');
    expect(report).toContain('⚠ Problems detected.');
    expect(report).toContain('60 / 100');
    expect(report).toContain('Total      10');
    expect(report).toContain('Transitive 4');
  });

  it('shows vulnerability findings correctly', () => {
    const report = formatDoctorReport(vulnResult);
    expect(report).toContain('HIGH');
    expect(report).toContain('vuln-ADV-001');
    expect(report).toContain('Prototype Pollution');
    expect(report).toContain('Vulnerable 1 ✗');
    expect(report).toContain('Status     ✓ Checked');
  });

  // -------------------------------------------------------------------------
  // Offline mode
  // -------------------------------------------------------------------------

  it('shows Not checked when offline (not_checked status)', () => {
    const report = formatDoctorReport(offlineResult);
    expect(report).toContain('Vulnerable Not checked');
    expect(report).toContain('Provider   None');
    expect(report).toContain('Status     — Not checked');
    // Should NOT show "0 ✓" for vulnerable
    expect(report).not.toContain('Vulnerable 0 ✓');
    // Should show clean message since no security findings
    expect(report).toContain('✓ No problems detected.');
  });

  // -------------------------------------------------------------------------
  // Advisory unavailable
  // -------------------------------------------------------------------------

  it('shows Unknown when advisory check failed (unavailable status)', () => {
    const report = formatDoctorReport(failedResult);
    expect(report).toContain('Vulnerable Unknown (advisory check failed)');
    expect(report).toContain('Provider   OSV (osv.dev)');
    expect(report).toContain('Status     ✗ Unavailable');
    // Should NOT show "0 ✓" for vulnerable
    expect(report).not.toContain('Vulnerable 0 ✓');
    // Warning message
    expect(report).toContain('⚠ Advisory check failed');
  });

  // -------------------------------------------------------------------------
  // Strict mode
  // -------------------------------------------------------------------------

  it('shows strict scan warning when enabled', () => {
    const report = formatDoctorReport(cleanResult, true);
    expect(report).toContain('STRICT SCANNING ENABLED');
  });

  // -------------------------------------------------------------------------
  // JSON output
  // -------------------------------------------------------------------------

  it('formats JSON report including depMetrics and advisoryInfo', () => {
    const report = formatJsonReport(cleanResult);
    const parsed = JSON.parse(report);
    expect(parsed.overallScore).toBe(100);
    expect(parsed.depMetrics.total).toBe(5);
    expect(parsed.depMetrics.direct).toBe(3);
    expect(parsed.advisoryInfo.provider).toBe('osv');
    expect(parsed.advisoryInfo.status).toBe('ok');
  });

  it('JSON report includes advisoryInfo status for offline mode', () => {
    const report = formatJsonReport(offlineResult);
    const parsed = JSON.parse(report);
    expect(parsed.advisoryInfo.provider).toBe('none');
    expect(parsed.advisoryInfo.status).toBe('not_checked');
  });

  it('JSON report includes advisoryInfo status for unavailable', () => {
    const report = formatJsonReport(failedResult);
    const parsed = JSON.parse(report);
    expect(parsed.advisoryInfo.provider).toBe('osv');
    expect(parsed.advisoryInfo.status).toBe('unavailable');
    expect(parsed.advisoryInfo.detail).toBe('ECONNREFUSED');
  });

  // -------------------------------------------------------------------------
  // Verify report formatting
  // -------------------------------------------------------------------------

  describe('verify report formatting', () => {
    const mockFinding = {
      ruleId: 'github-token',
      category: 'security' as const,
      severity: 'critical' as const,
      message: 'Dummy message',
      file: 'src/secret.js',
      line: 12,
      fingerprint: 'dummy-fp',
    };

    const passedResult: VerificationResult = {
      status: 'passed',
      resolved: [mockFinding],
      remaining: [],
      newFindings: [],
      uncertain: [],
      previousFindings: [mockFinding],
      currentFindings: [],
      advisoryInfo: { provider: 'osv', status: 'ok' },
      summary: {
        previousCount: 1,
        currentCount: 0,
        resolvedCount: 1,
        remainingCount: 0,
        newCount: 0,
        uncertainCount: 0,
      },
    };

    const failedResult: VerificationResult = {
      status: 'failed',
      resolved: [],
      remaining: [mockFinding],
      newFindings: [
        {
          ruleId: 'aws-access-key',
          category: 'security' as const,
          severity: 'high' as const,
          message: 'Dummy aws key',
          file: 'config.json',
          line: 2,
          fingerprint: 'new-fp',
        },
      ],
      uncertain: [],
      previousFindings: [mockFinding],
      currentFindings: [mockFinding, {
        ruleId: 'aws-access-key',
        category: 'security' as const,
        severity: 'high' as const,
        message: 'Dummy aws key',
        file: 'config.json',
        line: 2,
        fingerprint: 'new-fp',
      }],
      advisoryInfo: { provider: 'osv', status: 'ok' },
      summary: {
        previousCount: 1,
        currentCount: 2,
        resolvedCount: 0,
        remainingCount: 1,
        newCount: 1,
        uncertainCount: 0,
      },
    };

    it('formats passed verification report correctly', () => {
      const report = formatVerifyReport(passedResult);
      expect(report).toContain('DEVFOUNDRY VERIFY');
      expect(report).toContain('Previous findings    1');
      expect(report).toContain('Current findings     0');
      expect(report).toContain('Resolved');
      expect(report).toContain('  ✓ 1');
      expect(report).toContain('src/secret.js:12');
      expect(report).toContain('✓ PASSED');
    });

    it('formats failed verification report with remaining and new findings', () => {
      const report = formatVerifyReport(failedResult);
      expect(report).toContain('Previous findings    1');
      expect(report).toContain('Current findings     2');
      expect(report).toContain('Remaining');
      expect(report).toContain('  ⚠ 1');
      expect(report).toContain('New');
      expect(report).toContain('  ✗ 1');
      expect(report).toContain('config.json:2');
      expect(report).toContain('✗ FAILED');
    });

    it('formats JSON verification report correctly', () => {
      const report = formatVerifyJsonReport(passedResult);
      const parsed = JSON.parse(report);
      expect(parsed.status).toBe('passed');
      expect(parsed.previousCount).toBe(1);
      expect(parsed.resolvedCount).toBe(1);
      expect(parsed.newCount).toBe(0);
      expect(parsed.resolved).toHaveLength(1);
      expect(parsed.resolved[0].fingerprint).toBe('dummy-fp');
    });
  });

  // -------------------------------------------------------------------------
  // CI report formatting
  // -------------------------------------------------------------------------

  describe('ci report formatting', () => {
    const passedPolicy: PolicyResult = {
      passed: true,
      failed: false,
      reasons: [],
      matchedFindings: [],
      summary: { totalViolations: 0 },
    };

    const failedPolicy: PolicyResult = {
      passed: false,
      failed: true,
      reasons: ['NEW finding: [CRITICAL] src/secret.js:12 (github-token)'],
      matchedFindings: [
        {
          ruleId: 'github-token',
          category: 'security',
          severity: 'critical',
          message: 'Dummy msg',
          file: 'src/secret.js',
          line: 12,
          fingerprint: 'dummy-fp',
          confidence: 'high',
        },
      ],
      summary: { totalViolations: 1 },
    };

    const verification: VerificationResult = {
      status: 'passed',
      resolved: [],
      remaining: [],
      newFindings: [],
      uncertain: [],
      previousFindings: [],
      currentFindings: [],
      advisoryInfo: { provider: 'osv', status: 'ok' },
      summary: {
        previousCount: 8,
        currentCount: 8,
        resolvedCount: 0,
        remainingCount: 8,
        newCount: 0,
        uncertainCount: 0,
      },
    };

    it('formats passed CI report correctly', () => {
      const report = formatCiReport(passedPolicy, verification);
      expect(report).toContain('DEVFOUNDRY CI');
      expect(report).toContain('Baseline');
      expect(report).toContain('  Existing       8');
      expect(report).toContain('Current');
      expect(report).toContain('  Total          8');
      expect(report).toContain('New');
      expect(report).toContain('  0');
      expect(report).toContain('Policy');
      expect(report).toContain('  No policy violations detected.');
      expect(report).toContain('Result');
      expect(report).toContain('  ✓ PASSED');
    });

    it('formats failed CI report with policy violation details', () => {
      const failedVerification = {
        ...verification,
        summary: {
          previousCount: 8,
          currentCount: 9,
          resolvedCount: 0,
          remainingCount: 8,
          newCount: 1,
          uncertainCount: 0,
        },
      };

      const report = formatCiReport(failedPolicy, failedVerification);
      expect(report).toContain('Baseline');
      expect(report).toContain('  Existing       8');
      expect(report).toContain('Current');
      expect(report).toContain('  Total          9');
      expect(report).toContain('New');
      expect(report).toContain('  1 ✗');
      expect(report).toContain('Policy');
      expect(report).toContain('  NEW finding: [CRITICAL] src/secret.js:12 (github-token)');
      expect(report).toContain('Result');
      expect(report).toContain('  ✗ FAILED');
    });

    it('formats JSON CI report correctly', () => {
      const report = formatCiJsonReport(failedPolicy, verification, 1);
      const parsed = JSON.parse(report);
      expect(parsed.passed).toBe(false);
      expect(parsed.exitStatus).toBe(1);
      expect(parsed.policy.status).toBe('failed');
      expect(parsed.verification.status).toBe('passed');
      expect(parsed.advisories.provider).toBe('osv');
      expect(parsed.advisories.status).toBe('ok');
      expect(parsed.policyResult.matchedCount).toBe(1);
      expect(parsed.policyResult.reasons[0]).toContain('NEW finding');
      expect(parsed.verification.previousCount).toBe(8);
      expect(parsed.verification.newCount).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // Scan report formatting
  // -------------------------------------------------------------------------

  describe('scan report formatting', () => {
    const pipelineResult: PipelineResult = {
      schemaVersion: 1,
      toolVersion: '0.2.0',
      project: { type: 'Node.js', frameworks: ['Next.js'], packageManager: 'npm' },
      findings: [
        {
          ruleId: 'github-token',
          category: 'security',
          severity: 'critical',
          message: 'Found key',
          file: 'secrets.js',
          line: 2,
          fingerprint: 'fp-123',
          confidence: 'high',
        },
      ],
      dependencies: {
        metrics: { total: 10, direct: 5, transitive: 5, outdated: 1, vulnerable: 0 },
      },
      advisories: { provider: 'osv', status: 'ok' },
      baseline: {
        status: 'passed',
        summary: {
          previousCount: 1,
          currentCount: 1,
          resolvedCount: 0,
          remainingCount: 1,
          newCount: 0,
          uncertainCount: 0,
        },
      },
      score: { overallHealth: 60 },
      policy: { passed: true, reasons: [] },
    };

    it('formats human-readable scan report correctly', () => {
      const report = formatScanReport(pipelineResult);
      expect(report).toContain('DEVFOUNDRY SCAN');
      expect(report).toContain('Project');
      expect(report).toContain('Type:        Node.js');
      expect(report).toContain('Frameworks:  Next.js');
      expect(report).toContain('Security');
      expect(report).toContain('Findings:    1');
      expect(report).toContain('Dependencies');
      expect(report).toContain('Total:       10');
      expect(report).toContain('Advisories');
      expect(report).toContain('Provider:    OSV (osv.dev)');
      expect(report).toContain('Status:      ✓ Checked');
      expect(report).toContain('Baseline Comparison');
      expect(report).toContain('Status:      PASSED');
      expect(report).toContain('Score');
      expect(report).toContain('Overall Health: 60 / 100');
      expect(report).toContain('Detailed Findings:');
      expect(report).toContain('[CRITICAL] secrets.js:2 (github-token)');
    });

    it('formats JSON scan report correctly', () => {
      const report = formatScanJsonReport(pipelineResult);
      const parsed = JSON.parse(report);
      expect(parsed.schemaVersion).toBe(1);
      expect(parsed.toolVersion).toBe('0.2.0');
      expect(parsed.project.type).toBe('Node.js');
      expect(parsed.findings).toHaveLength(1);
      expect(parsed.dependencies.metrics.total).toBe(10);
      expect(parsed.score.overallHealth).toBe(60);
      expect(parsed.policy.passed).toBe(true);
    });
  });
});
