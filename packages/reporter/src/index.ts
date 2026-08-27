import { AnalysisResult } from '@devfoundry/core';

export function formatDoctorReport(result: AnalysisResult): string {
  const secretFindings = result.findings.filter(f => 
    ['github-token', 'aws-access-key', 'private-key', 'db-connection-string', 'jwt-token', 'generic-api-key'].includes(f.ruleId)
  );
  
  const vulnFindings = result.findings.filter(f => f.ruleId.startsWith('vuln-'));
  
  const otherSecurityFindings = result.findings.filter(f => 
    !secretFindings.includes(f) && !vulnFindings.includes(f)
  );

  const secretsCount = secretFindings.length;
  const securityIssuesCount = otherSecurityFindings.length;
  const vulnerableCount = vulnFindings.length;
  const outdatedCount = 0; // Stub for now

  const lines: string[] = [
    '╭──────────────────────────────────────╮',
    '│           DEVFOUNDRY DOCTOR          │',
    '╰──────────────────────────────────────╯',
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
    `  Vulnerable ${vulnerableCount} ${vulnerableCount > 0 ? '✗' : '✓'}`,
    `  Outdated   ${outdatedCount} ✓`,
    '',
    'Overall',
    `  ${result.overallScore} / 100`,
    ''
  ];

  if (result.findings.length > 0) {
    lines.push('Findings:');
    
    // Group findings by severity
    const grouped = {
      critical: result.findings.filter(f => f.severity === 'critical'),
      high: result.findings.filter(f => f.severity === 'high'),
      medium: result.findings.filter(f => f.severity === 'medium'),
      low: result.findings.filter(f => f.severity === 'low')
    };

    for (const [severity, list] of Object.entries(grouped)) {
      if (list.length > 0) {
        lines.push(`  [${severity.toUpperCase()}]`);
        for (const f of list) {
          const loc = f.line ? `:${f.line}` : '';
          lines.push(`    - ${f.file}${loc} [${f.ruleId}]: ${f.message}`);
        }
      }
    }
    lines.push('');
    lines.push('⚠ Problems detected. Please resolve them.');
  } else {
    lines.push('✓ No problems detected.');
  }

  return lines.join('\n');
}

export function formatJsonReport(result: AnalysisResult): string {
  return JSON.stringify(result, null, 2);
}
