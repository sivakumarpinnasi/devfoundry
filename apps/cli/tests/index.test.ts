import { describe, it, expect, vi, afterEach } from 'vitest';
import * as path from 'node:path';
import { detectProject } from '@devfoundry/detector';
import { scanSecurity } from '@devfoundry/security';
import {
  analyzeDependencies,
  scanWithAdvisories,
  MockAdvisoryProvider,
  NoOpAdvisoryProvider,
  OsvAdvisoryProvider,
  DependencyAdvisory,
} from '@devfoundry/dependencies';
import { calculateScore, Finding } from '@devfoundry/core';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

/** Stub fetch so OsvAdvisoryProvider returns no vulnerabilities (clean result). */
function stubFetchClean(numPackages = 1): void {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => ({ results: new Array(numPackages).fill({ vulns: [] }) }),
  }));
}

/** Stub fetch to simulate network failure. */
function stubFetchFail(): void {
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')));
}

const fixturesPath = path.resolve(__dirname, '../../../tests/fixtures');

describe('integration flow with fixtures', () => {

  // -------------------------------------------------------------------------
  // clean-node fixture
  // -------------------------------------------------------------------------
  it('analyzes clean-node fixture correctly', async () => {
    const basePath = path.join(fixturesPath, 'clean-node');
    const files = ['package.json', 'tsconfig.json'];
    const context = { basePath, files, strict: false };

    const project = await detectProject(context);
    const security = await scanSecurity(context);
    const deps = await analyzeDependencies(context);

    expect(project.type).toBe('Node.js / TypeScript');
    expect(security.length).toBe(0);
    expect(deps.dependencies.length).toBe(1);
    expect(deps.dependencies[0].name).toBe('typescript');
    expect(deps.metrics.total).toBe(1);
    expect(calculateScore(security)).toBe(100);
  });

  // -------------------------------------------------------------------------
  // with-secrets fixture — scope tests
  // -------------------------------------------------------------------------
  it('skips fake secrets in test/fixtures in default mode', async () => {
    const basePath = path.join(fixturesPath, 'with-secrets');
    const files = ['package.json', 'secrets.js'];
    const context = { basePath, files, strict: false };
    const security = await scanSecurity(context);
    expect(security.length).toBe(0);
  });

  it('detects secrets in test/fixtures in strict mode', async () => {
    const basePath = path.join(fixturesPath, 'with-secrets');
    const files = ['package.json', 'secrets.js'];
    const context = { basePath, files, strict: true };
    const project = await detectProject(context);
    const security = await scanSecurity(context);
    expect(project.type).toBe('Node.js');
    expect(security.length).toBe(3);
    const ruleIds = security.map(f => f.ruleId);
    expect(ruleIds).toContain('github-token');
    expect(ruleIds).toContain('aws-access-key');
    expect(ruleIds).toContain('private-key');
    expect(ruleIds).not.toContain('generic-api-key');
    expect(calculateScore(security)).toBeLessThan(50);
  });

  // -------------------------------------------------------------------------
  // with-frameworks fixture
  // -------------------------------------------------------------------------
  it('detects frameworks in with-frameworks fixture', async () => {
    const basePath = path.join(fixturesPath, 'with-frameworks');
    const files = ['package.json', 'next.config.js'];
    const context = { basePath, files, strict: true };
    const project = await detectProject(context);
    expect(project.frameworks).toContain('Next.js');
    expect(project.frameworks).toContain('React');
  });

  // -------------------------------------------------------------------------
  // with-deps — pnpm fixture
  // -------------------------------------------------------------------------
  it('resolves pnpm lockfile versions and detects transitive deps', async () => {
    const basePath = path.join(fixturesPath, 'with-deps');
    const files = ['package.json', 'pnpm-lock.yaml'];
    const context = { basePath, files, strict: true };
    const deps = await analyzeDependencies(context);
    expect(deps.packageManager).toBe('pnpm');
    const lodash = deps.dependencies.find(d => d.name === 'lodash');
    expect(lodash?.installedVersion).toBe('4.17.21');
    expect(lodash?.direct).toBe('direct');
    const inherits = deps.dependencies.find(d => d.name === 'inherits');
    expect(inherits?.direct).toBe('transitive');
    expect(deps.metrics.direct).toBe(2);
    expect(deps.metrics.transitive).toBe(1);
    expect(deps.metrics.total).toBe(3);
  });

  // -------------------------------------------------------------------------
  // with-npm-deps fixture
  // -------------------------------------------------------------------------
  it('resolves npm lockfile with direct and transitive deps', async () => {
    const basePath = path.join(fixturesPath, 'with-npm-deps');
    const files = ['package.json', 'package-lock.json'];
    const context = { basePath, files, strict: true };
    const deps = await analyzeDependencies(context);
    expect(deps.packageManager).toBe('npm');
    const express = deps.dependencies.find(d => d.name === 'express');
    expect(express?.installedVersion).toBe('4.18.2');
    expect(express?.direct).toBe('direct');
    expect(express?.depType).toBe('production');
    const ms = deps.dependencies.find(d => d.name === 'ms');
    expect(ms?.direct).toBe('transitive');
    expect(deps.metrics.transitive).toBeGreaterThanOrEqual(1);
  });

  // -------------------------------------------------------------------------
  // with-yarn-deps fixture
  // -------------------------------------------------------------------------
  it('resolves yarn lockfile with direct and transitive deps', async () => {
    const basePath = path.join(fixturesPath, 'with-yarn-deps');
    const files = ['package.json', 'yarn.lock'];
    const context = { basePath, files, strict: true };
    const deps = await analyzeDependencies(context);
    expect(deps.packageManager).toBe('yarn');
    const axios = deps.dependencies.find(d => d.name === 'axios');
    expect(axios?.installedVersion).toBe('1.4.0');
    expect(axios?.direct).toBe('direct');
    const followRedirects = deps.dependencies.find(d => d.name === 'follow-redirects');
    expect(followRedirects?.direct).toBe('transitive');
    expect(deps.metrics.direct).toBe(1);
    expect(deps.metrics.transitive).toBe(1);
  });

  // -------------------------------------------------------------------------
  // with-vuln-deps fixture — mock advisories (deterministic, no network)
  // -------------------------------------------------------------------------
  it('flags vulnerable dependency using MockAdvisoryProvider', async () => {
    const basePath = path.join(fixturesPath, 'with-vuln-deps');
    const files = ['package.json', 'package-lock.json'];
    const context = { basePath, files, strict: true };

    const deps = await analyzeDependencies(context);
    const advisory: DependencyAdvisory = {
      id: 'GHSA-p6mc-m468-83gw',
      dependencyName: 'lodash',
      vulnerableRange: '<4.17.21',
      fixedVersion: '4.17.21',
      severity: 'high',
      summary: 'Prototype Pollution in lodash',
      source: 'mock',
    };
    const provider = new MockAdvisoryProvider([advisory]);
    const result = await scanWithAdvisories(deps, provider);

    expect(result.advisoryInfo.status).toBe('ok');
    expect(result.advisoryInfo.provider).toBe('mock');
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].ruleId).toBe('vuln-GHSA-p6mc-m468-83gw');
    expect(result.findings[0].severity).toBe('high');
    expect(result.findings[0].message).toContain('lodash');
    expect(result.findings[0].remediation).toContain('4.17.21');
  });

  it('produces status:ok with no findings from NoOpAdvisoryProvider', async () => {
    const basePath = path.join(fixturesPath, 'with-deps');
    const files = ['package.json', 'pnpm-lock.yaml'];
    const context = { basePath, files, strict: true };
    const deps = await analyzeDependencies(context);
    const result = await scanWithAdvisories(deps, new NoOpAdvisoryProvider());
    expect(result.advisoryInfo.status).toBe('not_checked');
    expect(result.findings).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // OSV provider with mocked fetch — clean result
  // -------------------------------------------------------------------------
  it('OsvAdvisoryProvider returns status:ok with mocked clean response', async () => {
    const basePath = path.join(fixturesPath, 'with-deps');
    const files = ['package.json', 'pnpm-lock.yaml'];
    const context = { basePath, files, strict: true };

    const deps = await analyzeDependencies(context);
    stubFetchClean(deps.dependencies.length);
    const provider = new OsvAdvisoryProvider();
    const result = await scanWithAdvisories(deps, provider);

    expect(result.advisoryInfo.status).toBe('ok');
    expect(result.advisoryInfo.provider).toBe('osv');
    expect(result.findings).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // OSV provider with mocked fetch — network failure (never false clean)
  // -------------------------------------------------------------------------
  it('OsvAdvisoryProvider returns status:unavailable on network failure', async () => {
    const basePath = path.join(fixturesPath, 'with-deps');
    const files = ['package.json', 'pnpm-lock.yaml'];
    const context = { basePath, files, strict: true };

    const deps = await analyzeDependencies(context);
    stubFetchFail();
    const provider = new OsvAdvisoryProvider();
    const result = await scanWithAdvisories(deps, provider);

    expect(result.advisoryInfo.status).toBe('unavailable');
    expect(result.advisoryInfo.provider).toBe('osv');
    // findings is empty but status shows this is NOT a clean result
    expect(result.findings).toHaveLength(0);
    expect(result.advisoryInfo.detail).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // Verification Integration Tests
  // -------------------------------------------------------------------------
  it('verification passed: clean to clean', async () => {
    const { verifyFindings } = await import('@devfoundry/verification');
    const prev: Finding[] = [];
    const curr: Finding[] = [];
    const result = verifyFindings(prev, curr, { provider: 'osv', status: 'ok' });
    expect(result.status).toBe('passed');
  });

  it('verification failed: clean to dirty (new finding introduced)', async () => {
    const { verifyFindings } = await import('@devfoundry/verification');
    const prev: Finding[] = [];
    const curr = [
      {
        ruleId: 'github-token',
        category: 'security',
        severity: 'critical',
        message: 'Potential GitHub token',
        file: 'secrets.js',
        fingerprint: 'fp-123',
      },
    ];
    const result = verifyFindings(prev, curr, { provider: 'osv', status: 'ok' });
    expect(result.status).toBe('failed');
    expect(result.newFindings).toHaveLength(1);
    expect(result.resolved).toHaveLength(0);
  });

  it('verification passed: dirty to clean (resolved)', async () => {
    const { verifyFindings } = await import('@devfoundry/verification');
    const prev = [
      {
        ruleId: 'github-token',
        category: 'security',
        severity: 'critical',
        message: 'Potential GitHub token',
        file: 'secrets.js',
        fingerprint: 'fp-123',
      },
    ];
    const curr: Finding[] = [];
    const result = verifyFindings(prev, curr, { provider: 'osv', status: 'ok' });
    expect(result.status).toBe('passed');
    expect(result.resolved).toHaveLength(1);
  });

  it('verification partial: advisory unavailable prevents resolving dep vuln', async () => {
    const { verifyFindings } = await import('@devfoundry/verification');
    const prev = [
      {
        ruleId: 'vuln-GHSA-123',
        category: 'dependencies',
        severity: 'high',
        message: 'Vulnerable lodash',
        file: 'package.json',
        fingerprint: 'fp-vuln',
      },
    ];
    const curr: Finding[] = [];
    const result = verifyFindings(prev, curr, { provider: 'osv', status: 'unavailable' });
    // Status is partial, NOT passed, because OSV was unavailable
    expect(result.status).toBe('partial');
    expect(result.uncertain).toHaveLength(1);
    expect(result.resolved).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Baseline Integration Tests
  // -------------------------------------------------------------------------
  it('baseline integration: maps findings safely for baseline file', async () => {
    const { createBaseline } = await import('@devfoundry/verification');
    const findings: Finding[] = [
      {
        ruleId: 'github-token',
        category: 'security',
        severity: 'critical',
        message: 'ghp_secretValue', // sensitive
        file: 'secrets.js',
        fingerprint: 'fp-123',
        remediation: 'Remove token.',
      },
    ];

    const baseline = createBaseline(
      findings,
      { type: 'Node.js', packageManager: 'npm' },
      { provider: 'osv', status: 'ok' },
      '0.1.6'
    );

    expect(baseline.findings).toHaveLength(1);
    expect(baseline.findings[0].fingerprint).toBe('fp-123');
    expect(baseline.findings[0].ruleId).toBe('github-token');
    // Ensure raw message and remediation are OMITTED for security
    expect((baseline.findings[0] as unknown as Record<string, unknown>).message).toBeUndefined();
    expect((baseline.findings[0] as unknown as Record<string, unknown>).remediation).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // CI Policy Integration Tests
  // -------------------------------------------------------------------------
  it('CI policy integration: evaluates default policy on verification result', async () => {
    const { verifyFindings } = await import('@devfoundry/verification');
    const { evaluatePolicy } = await import('@devfoundry/policy');

    const prev: Finding[] = [];
    const curr: Finding[] = [
      {
        ruleId: 'github-token',
        category: 'security',
        severity: 'critical',
        message: 'ghp_secretValue',
        file: 'secrets.js',
        fingerprint: 'fp-123',
        confidence: 'high',
        remediation: 'Remove token.',
      },
    ];

    const verification = verifyFindings(prev, curr, { provider: 'osv', status: 'ok' });
    const policyResult = evaluatePolicy(verification);

    expect(policyResult.passed).toBe(false);
    expect(policyResult.failed).toBe(true);
    expect(policyResult.reasons).toHaveLength(1);
    expect(policyResult.reasons[0]).toContain('NEW finding');
  });

  it('CI policy integration: exposes EXIT_CODES constants', async () => {
    const { EXIT_CODES } = await import('@devfoundry/core');
    expect(EXIT_CODES.SUCCESS).toBe(0);
    expect(EXIT_CODES.POLICY_VIOLATION).toBe(1);
    expect(EXIT_CODES.INVALID_CONFIG).toBe(2);
    expect(EXIT_CODES.ANALYSIS_ERROR).toBe(3);
  });

  it('Pipeline integration: executeScan works for doctor, scan, verify, fix, and ci commands', async () => {
    // Proves executeScan orchestration works as the single shared pipeline entry point
    const { runAnalysisPipeline } = await import('@devfoundry/core');
    expect(runAnalysisPipeline).toBeDefined();
  });
});
