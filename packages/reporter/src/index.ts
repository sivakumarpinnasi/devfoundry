import { AnalysisResult, AdvisoryInfo, PipelineResult } from '@devfoundry/core';

const SECURITY_RULE_IDS = new Set([
  'github-token', 'aws-access-key', 'private-key',
  'database-credential', 'jwt', 'generic-api-key',
]);

// ---------------------------------------------------------------------------
// Advisory info rendering helpers
// ---------------------------------------------------------------------------

function renderAdvisoryProvider(info: AdvisoryInfo | undefined): string {
  if (!info) return 'None';
  switch (info.provider) {
    case 'osv':  return 'OSV (osv.dev)';
    case 'none': return 'None';
    case 'mock': return 'Mock (test)';
    default:     return info.provider;
  }
}

function renderAdvisoryStatus(info: AdvisoryInfo | undefined): string {
  if (!info) return '— Not checked';
  switch (info.status) {
    case 'ok':          return '✓ Checked';
    case 'unavailable': return `✗ Unavailable${info.detail ? ` (${info.detail})` : ''}`;
    case 'not_checked': return '— Not checked';
    default:            return '— Unknown';
  }
}

/**
 * Render the "Vulnerable" line for the Dependencies section.
 * When advisory status is not 'ok', we MUST NOT claim "0 vulnerabilities".
 */
function renderVulnerableCount(
  count: number,
  info: AdvisoryInfo | undefined,
): string {
  if (!info || info.status === 'not_checked') return 'Not checked';
  if (info.status === 'unavailable') return 'Unknown (advisory check failed)';
  return `${count} ${count > 0 ? '✗' : '✓'}`;
}

// ---------------------------------------------------------------------------
// Public formatters
// ---------------------------------------------------------------------------

export function formatDoctorReport(result: AnalysisResult, strict = false): string {
  const secretFindings = result.findings.filter(f => SECURITY_RULE_IDS.has(f.ruleId));
  const vulnFindings = result.findings.filter(f => f.ruleId.startsWith('vuln-'));
  const otherSecurityFindings = result.findings.filter(
    f => !secretFindings.includes(f) && !vulnFindings.includes(f),
  );

  const secretsCount = secretFindings.length;
  const securityIssuesCount = otherSecurityFindings.length;

  const dm = result.depMetrics;
  const vulnerableCount = dm?.vulnerable ?? vulnFindings.length;
  const totalDeps = dm?.total ?? 0;
  const directDeps = dm?.direct ?? 0;
  const transitiveDeps = dm?.transitive ?? 0;

  const lines: string[] = [
    '╭──────────────────────────────────────╮',
    '│           DEVFOUNDRY DOCTOR          │',
    '╰──────────────────────────────────────╯',
  ];

  if (strict) {
    lines.push('ℹ STRICT SCANNING ENABLED (Scanning all test and fixture paths)');
  }

  lines.push(
    '',
    'Project',
    `  Type       ${result.project.type}`,
    `  Manager    ${result.project.packageManager || 'Not detected'}`,
    `  Frameworks ${result.project.frameworks.join(', ') || 'None'}`,
    '',
    'Security',
    `  Secrets    ${secretsCount} ${secretsCount > 0 ? '✗' : '✓'}`,
    `  Issues     ${securityIssuesCount} ${securityIssuesCount > 0 ? '✗' : '✓'}`,
    '',
    'Dependencies',
    `  Total      ${totalDeps}`,
    `  Direct     ${directDeps}`,
    `  Transitive ${transitiveDeps}`,
    `  Vulnerable ${renderVulnerableCount(vulnerableCount, result.advisoryInfo)}`,
    `  Outdated   Not checked`,
    '',
    'Advisories',
    `  Provider   ${renderAdvisoryProvider(result.advisoryInfo)}`,
    `  Status     ${renderAdvisoryStatus(result.advisoryInfo)}`,
    '',
    'Overall',
    `  ${result.overallScore} / 100`,
    '',
  );

  if (result.findings.length > 0) {
    lines.push('Findings:');

    const grouped = {
      critical: result.findings.filter(f => f.severity === 'critical'),
      high: result.findings.filter(f => f.severity === 'high'),
      medium: result.findings.filter(f => f.severity === 'medium'),
      low: result.findings.filter(f => f.severity === 'low'),
    };

    for (const [severity, list] of Object.entries(grouped)) {
      if (list.length > 0) {
        lines.push(`  [${severity.toUpperCase()}]`);
        for (const f of list) {
          const loc = f.line ? `:${f.line}` : '';
          lines.push(`    - ${f.file}${loc} [${f.category} / ${f.ruleId}]`);
          lines.push(`      Message:      ${f.message}`);
          lines.push(`      Fingerprint:  ${f.fingerprint}`);
          if (f.remediation) {
            lines.push(`      Remediation:  ${f.remediation}`);
          }
        }
      }
    }
    lines.push('');
    lines.push('⚠ Problems detected. Please resolve them.');
  } else if (result.advisoryInfo?.status === 'unavailable') {
    lines.push('⚠ Advisory check failed. Vulnerability status is unknown.');
  } else {
    lines.push('✓ No problems detected.');
  }

  return lines.join('\n');
}

export function formatJsonReport(result: AnalysisResult): string {
  return JSON.stringify(result, null, 2);
}

// ---------------------------------------------------------------------------
// foundry fix report formatters
// ---------------------------------------------------------------------------

import type { RemediationPlan, RemediationAction, RemediationRisk } from '@devfoundry/remediation';

function riskBadge(risk: RemediationRisk): string {
  switch (risk) {
    case 'critical': return '✗ critical';
    case 'high':     return '⚠ high';
    case 'medium':   return '~ medium';
    case 'low':      return '✓ low';
  }
}

function formatAction(index: number, action: RemediationAction, details: boolean): string[] {
  const lines: string[] = [];

  lines.push(`[${index}] ${action.title}`);

  if (action.category === 'dependency') {
    if (action.currentValue && action.targetValue) {
      lines.push(`    Package:  ${action.description.split('"')[1] ?? 'dependency'}`);
      lines.push(`    Version:  ${action.currentValue} → ${action.targetValue}`);
    } else if (action.currentValue) {
      lines.push(`    Package:  ${action.description.split('"')[1] ?? 'dependency'}`);
      lines.push(`    Version:  ${action.currentValue} (no fix available)`);
    }
  }

  if (action.category === 'security') {
    lines.push(`    ${action.description.split('.')[0]}.`);
  }

  lines.push(`    Risk:     ${riskBadge(action.risk)}`);

  if (action.files.length > 0) {
    lines.push('');
    lines.push('    Files affected (not modified):');
    for (const f of action.files) {
      lines.push(`      ${f}`);
    }
  }

  if (details) {
    if (action.guidance && action.guidance.length > 0) {
      lines.push('');
      lines.push('    Steps:');
      for (const step of action.guidance) {
        lines.push(`      ${step}`);
      }
    }
    if (action.noAutomationReason) {
      lines.push('');
      lines.push(`    Automation: ${action.noAutomationReason}`);
    }
  }

  return lines;
}

/**
 * Format a RemediationPlan for human-readable output.
 *
 * @param plan     The remediation plan to render.
 * @param details  If true, show expanded guidance and automation notes.
 */
export function formatFixReport(plan: RemediationPlan, details = false): string {
  const lines: string[] = [
    '╭──────────────────────────────────────╮',
    '│           DEVFOUNDRY FIX             │',
    '╰──────────────────────────────────────╯',
    '',
  ];

  if (plan.status === 'none') {
    lines.push('✓ No applicable fixes found.');
    if (plan.totalFindings === 0) {
      lines.push('  No findings were reported by the analysis.');
    } else {
      lines.push(`  ${plan.totalFindings} finding(s) detected but none have remediation actions in v0.1.4.`);
    }
    lines.push('');
    lines.push('No files have been modified.');
    return lines.join('\n');
  }

  const count = plan.actionsAvailable;
  lines.push(`${count} action${count === 1 ? '' : 's'} available`);
  lines.push('');

  for (let i = 0; i < plan.actions.length; i++) {
    const actionLines = formatAction(i + 1, plan.actions[i], details);
    lines.push(...actionLines);
    lines.push('');
  }

  if (plan.noActionReasons.length > 0) {
    lines.push('Findings with no applicable action:');
    for (const nr of plan.noActionReasons) {
      lines.push(`  [${nr.ruleId}] ${nr.reason}`);
    }
    lines.push('');
  }

  lines.push('No files have been modified.');
  return lines.join('\n');
}

/**
 * Format a RemediationPlan as stable machine-readable JSON.
 */
export function formatFixJsonReport(plan: RemediationPlan): string {
  return JSON.stringify(
    {
      status: plan.status,
      actionsAvailable: plan.actionsAvailable,
      totalFindings: plan.totalFindings,
      actions: plan.actions,
      noActionReasons: plan.noActionReasons,
    },
    null,
    2,
  );
}

// ---------------------------------------------------------------------------
// foundry verify report formatters
// ---------------------------------------------------------------------------

import type { VerificationResult, VerificationStatus } from '@devfoundry/verification';
import type { Finding } from '@devfoundry/core';

function statusIcon(status: VerificationStatus): string {
  switch (status) {
    case 'passed':  return '✓ PASSED';
    case 'partial': return '~ PARTIAL';
    case 'failed':  return '✗ FAILED';
  }
}

function renderFindingLine(f: Finding): string {
  const loc = f.line ? `:${f.line}` : '';
  return `    [${f.severity.toUpperCase()}] ${f.file}${loc} [${f.category} / ${f.ruleId}]`;
}

/**
 * Format a VerificationResult for human-readable output.
 * Secret values are NEVER printed — only file, line, ruleId, and severity.
 */
export function formatVerifyReport(result: VerificationResult): string {
  const s = result.summary;
  const lines: string[] = [
    '╭──────────────────────────────────────╮',
    '│         DEVFOUNDRY VERIFY            │',
    '╰──────────────────────────────────────╯',
    '',
    `Previous findings    ${s.previousCount}`,
    `Current findings     ${s.currentCount}`,
    '',
  ];

  // Resolved
  lines.push(`Resolved`);
  lines.push(`  ✓ ${s.resolvedCount}`);
  if (result.resolved.length > 0) {
    for (const f of result.resolved) lines.push(renderFindingLine(f));
  }
  lines.push('');

  // Remaining
  lines.push(`Remaining`);
  lines.push(`  ⚠ ${s.remainingCount}`);
  if (result.remaining.length > 0) {
    for (const f of result.remaining) lines.push(renderFindingLine(f));
  }
  lines.push('');

  // New
  lines.push(`New`);
  lines.push(`  ✗ ${s.newCount}`);
  if (result.newFindings.length > 0) {
    for (const f of result.newFindings) lines.push(renderFindingLine(f));
  }
  lines.push('');

  // Uncertain (advisory unavailable)
  if (s.uncertainCount > 0) {
    lines.push(`Uncertain (advisory check failed)`);
    lines.push(`  ? ${s.uncertainCount}`);
    for (const f of result.uncertain) lines.push(renderFindingLine(f));
    lines.push('');
    lines.push('  ⚠ Dependency vulnerability resolution cannot be confirmed.');
    lines.push('  ⚠ The advisory provider was unavailable during verification.');
    lines.push('');
  }

  // Advisory status
  if (result.advisoryInfo) {
    lines.push('Advisories');
    lines.push(`  Provider   ${renderAdvisoryProvider(result.advisoryInfo)}`);
    lines.push(`  Status     ${renderAdvisoryStatus(result.advisoryInfo)}`);
    lines.push('');
  }

  // Overall status
  lines.push('Status');
  lines.push(`  ${statusIcon(result.status)}`);

  return lines.join('\n');
}

/**
 * Format a VerificationResult as stable machine-readable JSON.
 */
export function formatVerifyJsonReport(result: VerificationResult): string {
  return JSON.stringify(
    {
      status: result.status,
      previousCount: result.summary.previousCount,
      currentCount: result.summary.currentCount,
      resolvedCount: result.summary.resolvedCount,
      remainingCount: result.summary.remainingCount,
      newCount: result.summary.newCount,
      uncertainCount: result.summary.uncertainCount,
      resolved: result.resolved,
      remaining: result.remaining,
      newFindings: result.newFindings,
      uncertain: result.uncertain,
      advisoryInfo: result.advisoryInfo,
    },
    null,
    2,
  );
}

// ---------------------------------------------------------------------------
// foundry ci report formatters
// ---------------------------------------------------------------------------

import type { PolicyResult } from '@devfoundry/policy';

/**
 * Format a PolicyResult and VerificationResult for CI console output.
 */
export function formatCiReport(policyResult: PolicyResult, verification: VerificationResult): string {
  const vSummary = verification.summary;
  const lines: string[] = [
    '╭──────────────────────────────────────╮',
    '│           DEVFOUNDRY CI              │',
    '╰──────────────────────────────────────╯',
    '',
    'Baseline',
    `  Existing       ${vSummary.previousCount}`,
    '',
    'Current',
    `  Total          ${vSummary.currentCount}`,
    '',
    'New',
    `  ${vSummary.newCount}${vSummary.newCount > 0 ? ' ✗' : ''}`,
    '',
    'Resolved',
    `  ${vSummary.resolvedCount}`,
    '',
    'Remaining',
    `  ${vSummary.remainingCount}`,
    '',
    'Policy',
  ];

  if (policyResult.reasons.length > 0) {
    for (const reason of policyResult.reasons) {
      lines.push(`  ${reason}`);
    }
  } else {
    lines.push('  No policy violations detected.');
  }

  lines.push('');
  lines.push('Result');

  if (policyResult.passed) {
    lines.push('  ✓ PASSED');
  } else {
    lines.push('  ✗ FAILED');
  }

  return lines.join('\n');
}

/**
 * Format a PolicyResult and VerificationResult as stable machine-readable JSON.
 */
export function formatCiJsonReport(
  policyResult: PolicyResult,
  verification: VerificationResult,
  exitCode: number,
): string {
  return JSON.stringify(
    {
      passed: policyResult.passed,
      exitStatus: exitCode,
      policy: {
        status: policyResult.passed ? 'passed' : 'failed',
      },
      verification: {
        status: verification.status,
        previousCount: verification.summary.previousCount,
        currentCount: verification.summary.currentCount,
        resolvedCount: verification.summary.resolvedCount,
        remainingCount: verification.summary.remainingCount,
        newCount: verification.summary.newCount,
        uncertainCount: verification.summary.uncertainCount,
      },
      advisories: {
        provider: verification.advisoryInfo?.provider ?? 'none',
        status: verification.advisoryInfo?.status ?? 'not_checked',
      },
      policyResult: {
        passed: policyResult.passed,
        failed: policyResult.failed,
        reasons: policyResult.reasons,
        matchedCount: policyResult.matchedFindings.length,
      },
      advisoryInfo: verification.advisoryInfo,
      findingsSummary: {
        total: verification.currentFindings.length,
        resolved: verification.resolved.map(f => f.fingerprint),
        remaining: verification.remaining.map(f => f.fingerprint),
        newFindings: verification.newFindings.map(f => f.fingerprint),
        uncertain: verification.uncertain.map(f => f.fingerprint),
      },
    },
    null,
    2,
  );
}

// ---------------------------------------------------------------------------
// foundry scan report formatters
// ---------------------------------------------------------------------------

/**
 * Format a PipelineResult for scan command console output.
 */
export function formatScanReport(result: PipelineResult): string {
  const lines: string[] = [
    '╭──────────────────────────────────────╮',
    '│           DEVFOUNDRY SCAN            │',
    '╰──────────────────────────────────────╯',
    '',
    'Project',
    `  Type:        ${result.project.type}`,
    `  Frameworks:  ${result.project.frameworks.length > 0 ? result.project.frameworks.join(', ') : 'None'}`,
    `  Pkg Manager: ${result.project.packageManager || 'Unknown'}`,
    '',
    'Security',
    `  Findings:    ${result.findings.filter(f => f.category === 'security').length}`,
  ];

  // Dependency metrics if present
  if (result.dependencies && result.dependencies.metrics) {
    const m = result.dependencies.metrics;
    lines.push(
      '',
      'Dependencies',
      `  Total:       ${m.total}`,
      `  Direct:      ${m.direct}`,
      `  Transitive:  ${m.transitive}`,
      `  Vulnerable:  ${m.vulnerable}`,
    );
  }

  lines.push(
    '',
    'Advisories',
    `  Provider:    ${renderAdvisoryProvider(result.advisories)}`,
    `  Status:      ${renderAdvisoryStatus(result.advisories)}`,
  );

  // Baseline integration summary if exists
  if (result.baseline) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const b = result.baseline as any;
    lines.push(
      '',
      'Baseline Comparison',
      `  Status:      ${b.status.toUpperCase()}`,
      `  Previous:    ${b.summary.previousCount}`,
      `  Remaining:   ${b.summary.remainingCount}`,
      `  Resolved:    ${b.summary.resolvedCount}`,
      `  New:         ${b.summary.newCount}`,
    );
  }

  lines.push(
    '',
    'Score',
    `  Overall Health: ${result.score.overallHealth} / 100`,
  );

  // Policy if evaluated
  if (result.policy) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const p = result.policy as any;
    lines.push(
      '',
      'Policy Evaluation',
      `  Status:      ${p.passed ? 'PASSED' : 'FAILED'}`,
    );
    if (p.reasons.length > 0) {
      for (const reason of p.reasons) {
        lines.push(`  - ${reason}`);
      }
    }
  }

  // List findings if any
  if (result.findings.length > 0) {
    lines.push('', 'Detailed Findings:');
    for (const f of result.findings) {
      const loc = f.line ? `:${f.line}` : '';
      const statusLabel = f.fileStatus ? ` [${f.fileStatus}]` : '';
      lines.push(`  [${f.severity.toUpperCase()}] ${f.file}${loc} (${f.ruleId})${statusLabel}`);
    }
  }

  return lines.join('\n');
}

/**
 * Format a PipelineResult as stable versioned machine-readable JSON.
 */
export function formatScanJsonReport(result: PipelineResult): string {
  return JSON.stringify(
    {
      schemaVersion: result.schemaVersion,
      toolVersion: result.toolVersion,
      project: result.project,
      findings: result.findings,
      dependencies: result.dependencies,
      advisories: result.advisories,
      baseline: result.baseline,
      score: result.score,
      policy: result.policy,
    },
    null,
    2,
  );
}
