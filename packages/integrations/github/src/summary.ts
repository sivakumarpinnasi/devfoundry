/**
 * GitHub Job Summary generator and writer.
 */
import * as fs from 'node:fs';
import type { PolicyResult } from '@devfoundry/policy';
import type { VerificationResult } from '@devfoundry/verification';

const SECRET_RULES = new Set([
  'github-token',
  'aws-access-key',
  'private-key',
  'database-credential',
  'jwt',
  'generic-api-key',
]);

function isSecurityFinding(f: { category: string; ruleId: string }): boolean {
  return f.category === 'security' || SECRET_RULES.has(f.ruleId);
}

function isDependencyFinding(f: { category: string; ruleId: string }): boolean {
  return f.category === 'dependencies' || f.ruleId.startsWith('vuln-');
}

/**
 * Generate Markdown summary for GitHub GITHUB_STEP_SUMMARY.
 */
export function generateSummaryMarkdown(policy: PolicyResult, verification: VerificationResult): string {
  const newSec = verification.newFindings.filter(isSecurityFinding).length;
  const remSec = verification.remaining.filter(isSecurityFinding).length;
  const resSec = verification.resolved.filter(isSecurityFinding).length;

  const newDep = verification.newFindings.filter(isDependencyFinding).length;
  const remDep = verification.remaining.filter(isDependencyFinding).length;
  const resDep = verification.resolved.filter(isDependencyFinding).length;

  const lines: string[] = [
    '# DevFoundry',
    '',
    '## Result',
    policy.passed ? '✓ PASSED' : '❌ FAILED',
    '',
    '## Findings',
    '',
    '| Category | New | Remaining | Resolved |',
    '| :--- | :---: | :---: | :---: |',
    `| Security | ${newSec} | ${remSec} | ${resSec} |`,
    `| Dependencies | ${newDep} | ${remDep} | ${resDep} |`,
    '',
  ];

  lines.push('## Policy');
  if (policy.reasons.length > 0) {
    for (const reason of policy.reasons) {
      lines.push(`- ${reason}`);
    }
  } else {
    lines.push('- No policy violations detected.');
  }
  lines.push('');

  lines.push('## Advisories');
  if (verification.advisoryInfo) {
    const provider =
      verification.advisoryInfo.provider === 'osv'
        ? 'OSV'
        : verification.advisoryInfo.provider === 'none'
        ? 'None'
        : verification.advisoryInfo.provider;
    const status =
      verification.advisoryInfo.status === 'ok'
        ? 'Checked'
        : verification.advisoryInfo.status === 'unavailable'
        ? 'Unavailable'
        : 'Not checked';

    lines.push(`- Provider: ${provider}`);
    lines.push(`- Status: ${status}`);
  } else {
    lines.push('- Provider: None');
    lines.push('- Status: Not checked');
  }

  return lines.join('\n');
}

/** Append the Markdown summary to the GitHub Actions step summary file. */
export function writeGitHubStepSummary(markdown: string): void {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile) {
    try {
      fs.appendFileSync(summaryFile, markdown + '\n', 'utf8');
    } catch {
      // Ignore write failures in case of bad environment permissions
    }
  }
}
