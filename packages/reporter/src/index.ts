import { DoctorResult } from '@devfoundry/core';

export function formatDoctorReport(result: DoctorResult): string {
  const statusChar = result.project.status === 'success' ? '✓' : '✗';
  const overallMessage = result.overallScore === 100 ? '✓ No problems detected.' : '⚠ Some issues found.';

  return [
    '╭──────────────────────────────────────╮',
    '│           DEVFOUNDRY DOCTOR          │',
    '╰──────────────────────────────────────╯',
    '',
    'Project',
    `  Type       ${result.project.type}`,
    `  Status     ${statusChar}`,
    '',
    'Security',
    `  Secrets    ${result.security.secrets}`,
    `  Issues     ${result.security.issues}`,
    '',
    'Dependencies',
    `  Vulnerable ${result.dependencies.vulnerable}`,
    `  Outdated   ${result.dependencies.outdated}`,
    '',
    'Overall',
    `  ${result.overallScore} / 100`,
    '',
    overallMessage
  ].join('\n');
}
