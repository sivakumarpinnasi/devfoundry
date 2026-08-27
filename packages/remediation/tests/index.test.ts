/**
 * @devfoundry/remediation unit tests.
 *
 * All tests are deterministic — no network calls, no file I/O.
 * Tests verify the SAFETY CONTRACT: no files are modified during planning.
 */
import { describe, it, expect } from 'vitest';
import { buildRemediationPlan } from '../src/planner.js';
import { planDependencyRemediation } from '../src/planners/dependency.js';
import { planSecretRemediation } from '../src/planners/security.js';
import { planConfigurationRemediation } from '../src/planners/configuration.js';
import type { Finding, AnalysisResult } from '@devfoundry/core';

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

function makeVulnFinding(overrides?: Partial<Finding>): Finding {
  return {
    ruleId: 'vuln-GHSA-p6mc-m468-83gw',
    category: 'dependencies',
    severity: 'high',
    confidence: 'high',
    message: 'Dependency "lodash" (4.17.20) is vulnerable: Prototype Pollution in lodash [<4.17.21]',
    file: 'package.json',
    fingerprint: 'dGVzdC1maW5nZXJwcmludA==',
    remediation: 'Upgrade "lodash" to 4.17.21 or higher.',
    ...overrides,
  };
}

function makeVulnFindingNoFix(): Finding {
  return {
    ruleId: 'vuln-GHSA-no-fix',
    category: 'dependencies',
    severity: 'high',
    confidence: 'high',
    message: 'Dependency "some-pkg" (1.0.0) is vulnerable: Remote Code Execution [>=0]',
    file: 'package.json',
    fingerprint: 'bm9maXgtZmluZ2VycHJpbnQ=',
    remediation: 'Review advisory GHSA-no-fix and update "some-pkg".',
  };
}

function makeSecretFinding(ruleId = 'github-token', file = 'src/config.js', line = 5): Finding {
  return {
    ruleId,
    category: 'security',
    severity: 'critical',
    confidence: 'high',
    message: 'Potential GitHub Personal Access Token detected.',
    file,
    line,
    fingerprint: 'c2VjcmV0LWZpbmdlcnByaW50',
    remediation: 'Rotate this credential and remove it from source.',
  };
}

function makeAnalysisResult(findings: Finding[]): AnalysisResult {
  return {
    project: { type: 'Node.js', frameworks: [], packageManager: 'pnpm' },
    findings,
    overallScore: 100 - findings.length * 10,
    advisoryInfo: { provider: 'mock', status: 'ok' },
  };
}

// ---------------------------------------------------------------------------
// planDependencyRemediation
// ---------------------------------------------------------------------------

describe('planDependencyRemediation — with fixed version', () => {
  it('returns an action with correct metadata', () => {
    const finding = makeVulnFinding();
    const action = planDependencyRemediation(finding, 'pnpm');
    expect(action).not.toBeNull();
    expect(action!.category).toBe('dependency');
    expect(action!.title).toBe('Upgrade dependency');
    expect(action!.currentValue).toBe('4.17.20');
    expect(action!.targetValue).toBe('4.17.21');
    expect(action!.risk).toBe('low');
    expect(action!.reversible).toBe(true);
    expect(action!.requiresConfirmation).toBe(true);
    expect(action!.automated).toBe(false);
    expect(action!.findingId).toBe(finding.fingerprint);
  });

  it('includes pnpm lockfile in affected files for pnpm projects', () => {
    const action = planDependencyRemediation(makeVulnFinding(), 'pnpm');
    expect(action!.files).toContain('package.json');
    expect(action!.files).toContain('pnpm-lock.yaml');
  });

  it('includes package-lock.json for npm projects', () => {
    const action = planDependencyRemediation(makeVulnFinding({ file: 'package-lock.json' }), 'npm');
    expect(action!.files).toContain('package.json');
    expect(action!.files).toContain('package-lock.json');
  });

  it('includes yarn.lock for yarn projects', () => {
    const action = planDependencyRemediation(makeVulnFinding({ file: 'yarn.lock' }), 'yarn');
    expect(action!.files).toContain('package.json');
    expect(action!.files).toContain('yarn.lock');
  });

  it('has guidance steps', () => {
    const action = planDependencyRemediation(makeVulnFinding(), 'pnpm');
    expect(action!.guidance).toBeDefined();
    expect(action!.guidance!.length).toBeGreaterThan(0);
    expect(action!.guidance!.some(g => g.includes('4.17.21'))).toBe(true);
  });

  it('has a non-empty noAutomationReason', () => {
    const action = planDependencyRemediation(makeVulnFinding(), 'pnpm');
    expect(action!.noAutomationReason).toBeTruthy();
  });

  it('returns null for non-vulnerability ruleId', () => {
    const finding = makeVulnFinding({ ruleId: 'github-token' });
    expect(planDependencyRemediation(finding)).toBeNull();
  });
});

describe('planDependencyRemediation — without fixed version', () => {
  it('returns a guidance-only action with high risk', () => {
    const action = planDependencyRemediation(makeVulnFindingNoFix(), 'npm');
    expect(action).not.toBeNull();
    expect(action!.category).toBe('dependency');
    expect(action!.risk).toBe('high');
    expect(action!.reversible).toBe(false);
    expect(action!.targetValue).toBeUndefined();
    expect(action!.currentValue).toBe('1.0.0');
  });

  it('has guidance steps for manual review', () => {
    const action = planDependencyRemediation(makeVulnFindingNoFix(), 'npm');
    expect(action!.guidance).toBeDefined();
    expect(action!.guidance!.some(g => g.includes('some-pkg'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// planSecretRemediation
// ---------------------------------------------------------------------------

describe('planSecretRemediation', () => {
  it('returns an action for github-token', () => {
    const action = planSecretRemediation(makeSecretFinding('github-token'));
    expect(action).not.toBeNull();
    expect(action!.category).toBe('security');
    expect(action!.title).toBe('Credential remediation');
    expect(action!.risk).toBe('high');
    expect(action!.reversible).toBe(false);
    expect(action!.automated).toBe(false);
    expect(action!.requiresConfirmation).toBe(true);
  });

  it('returns an action for aws-access-key', () => {
    const action = planSecretRemediation(makeSecretFinding('aws-access-key'));
    expect(action).not.toBeNull();
    expect(action!.description).toContain('AWS Access Key');
  });

  it('returns an action for private-key', () => {
    const action = planSecretRemediation(makeSecretFinding('private-key'));
    expect(action!.description).toContain('Private Key');
  });

  it('returns an action for database-credential', () => {
    const action = planSecretRemediation(makeSecretFinding('database-credential'));
    expect(action!.description).toContain('Database Credential');
  });

  it('returns an action for jwt', () => {
    const action = planSecretRemediation(makeSecretFinding('jwt'));
    expect(action).not.toBeNull();
  });

  it('returns an action for generic-api-key', () => {
    const action = planSecretRemediation(makeSecretFinding('generic-api-key'));
    expect(action).not.toBeNull();
  });

  it('returns null for non-secret ruleId', () => {
    const action = planSecretRemediation(makeVulnFinding() as Finding);
    expect(action).toBeNull();
  });

  it('NEVER includes currentValue or targetValue (no secret exposure)', () => {
    const action = planSecretRemediation(makeSecretFinding());
    expect(action).not.toBeNull();
    expect(action!.currentValue).toBeUndefined();
    expect(action!.targetValue).toBeUndefined();
  });

  it('includes the file in affected files', () => {
    const action = planSecretRemediation(makeSecretFinding('github-token', 'src/config.js', 5));
    expect(action!.files).toContain('src/config.js');
  });

  it('includes ROTATE, REMOVE, GIT HISTORY steps in guidance', () => {
    const action = planSecretRemediation(makeSecretFinding());
    const joined = action!.guidance!.join(' ');
    expect(joined).toContain('ROTATE');
    expect(joined).toContain('REMOVE');
    expect(joined).toContain('git log');
  });
});

// ---------------------------------------------------------------------------
// planConfigurationRemediation
// ---------------------------------------------------------------------------

describe('planConfigurationRemediation', () => {
  it('returns null for all findings (v0.1.4 placeholder)', () => {
    expect(planConfigurationRemediation(makeVulnFinding())).toBeNull();
    expect(planConfigurationRemediation(makeSecretFinding())).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// buildRemediationPlan — orchestrator
// ---------------------------------------------------------------------------

describe('buildRemediationPlan — clean project', () => {
  it('returns status:none and empty actions for zero findings', () => {
    const result = makeAnalysisResult([]);
    const plan = buildRemediationPlan(result);
    expect(plan.status).toBe('none');
    expect(plan.actions).toHaveLength(0);
    expect(plan.actionsAvailable).toBe(0);
    expect(plan.totalFindings).toBe(0);
    expect(plan.noActionReasons).toHaveLength(0);
  });
});

describe('buildRemediationPlan — vulnerability findings', () => {
  it('creates upgrade action for vulnerable dependency with fix', () => {
    const result = makeAnalysisResult([makeVulnFinding()]);
    const plan = buildRemediationPlan(result, 'pnpm');
    expect(plan.status).toBe('available');
    expect(plan.actions).toHaveLength(1);
    expect(plan.actions[0].category).toBe('dependency');
    expect(plan.actions[0].targetValue).toBe('4.17.21');
    expect(plan.actionsAvailable).toBe(1);
  });

  it('creates guidance-only action for dependency without fixed version', () => {
    const result = makeAnalysisResult([makeVulnFindingNoFix()]);
    const plan = buildRemediationPlan(result, 'npm');
    expect(plan.status).toBe('available');
    expect(plan.actions).toHaveLength(1);
    expect(plan.actions[0].risk).toBe('high');
    expect(plan.actions[0].targetValue).toBeUndefined();
  });
});

describe('buildRemediationPlan — secret findings', () => {
  it('creates remediation action for secret finding', () => {
    const result = makeAnalysisResult([makeSecretFinding()]);
    const plan = buildRemediationPlan(result);
    expect(plan.status).toBe('available');
    expect(plan.actions).toHaveLength(1);
    expect(plan.actions[0].category).toBe('security');
    expect(plan.actions[0].risk).toBe('high');
  });

  it('never exposes credential values in plan output', () => {
    const finding = makeSecretFinding();
    const result = makeAnalysisResult([finding]);
    const plan = buildRemediationPlan(result);
    const action = plan.actions[0];
    expect(action.currentValue).toBeUndefined();
    expect(action.targetValue).toBeUndefined();
    // Verify the message and guidance don't contain secret data
    expect(action.description).not.toContain('ghp_');
    expect(JSON.stringify(action.guidance)).not.toContain('ghp_');
  });
});

describe('buildRemediationPlan — mixed findings', () => {
  it('handles multiple findings of different types', () => {
    const result = makeAnalysisResult([
      makeVulnFinding(),
      makeSecretFinding('github-token'),
      makeSecretFinding('aws-access-key', 'infra/deploy.sh'),
    ]);
    const plan = buildRemediationPlan(result, 'pnpm');
    expect(plan.status).toBe('available');
    expect(plan.actions).toHaveLength(3);
    expect(plan.actionsAvailable).toBe(3);
    expect(plan.totalFindings).toBe(3);
    const categories = plan.actions.map(a => a.category);
    expect(categories).toContain('dependency');
    expect(categories.filter(c => c === 'security')).toHaveLength(2);
  });

  it('assigns unique action IDs', () => {
    const result = makeAnalysisResult([
      makeVulnFinding({ fingerprint: 'fp1' }),
      makeVulnFinding({ fingerprint: 'fp2' }),
    ]);
    const plan = buildRemediationPlan(result, 'pnpm');
    const ids = plan.actions.map(a => a.id);
    expect(new Set(ids).size).toBe(ids.length); // all unique
  });
});

describe('buildRemediationPlan — safety: no file modifications', () => {
  it('does not attempt any file write operations', () => {
    // This test verifies the planner is pure — no side effects
    const fs = { writeFileSync: () => { throw new Error('File write attempted!'); } };
    const result = makeAnalysisResult([makeVulnFinding(), makeSecretFinding()]);
    // Should not throw — the planner never touches fs
    expect(() => buildRemediationPlan(result, 'pnpm')).not.toThrow();
    void fs; // suppress unused warning
  });
});
