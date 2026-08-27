/**
 * CI Policy evaluation engine.
 */
import type { Finding } from '@devfoundry/core';
import type { VerificationResult } from '@devfoundry/verification';
import type { Policy, PolicyResult } from './model.js';

export const DEFAULT_CI_POLICY: Policy = {
  failOnNewFindings: true,
  failOnCritical: true,
  failOnHigh: false, // Default is false so it doesn't fail on ALL high findings unless they match secrets/vulns
  failOnMedium: false,
  failOnLow: false,
  failOnSecrets: true,
  failOnVulnerabilities: true,
};

/**
 * Evaluate a VerificationResult against a Policy.
 *
 * SAFETY GUARANTEES:
 *   - Only NEW findings (fingerprint not in baseline) trigger policy violations.
 *   - Existing baseline findings NEVER trigger policy violations.
 *   - Advisory check failure (unavailable/not_checked) does not fail the build on its own,
 *     but it prevents claiming vulnerability findings are resolved.
 */
export function evaluatePolicy(
  verification: VerificationResult,
  policy: Policy = DEFAULT_CI_POLICY,
): PolicyResult {
  const reasons: string[] = [];
  const matchedFindings: Finding[] = [];

  // Security rule IDs for secrets category (mirroring reporter list)
  const SECRET_RULES = new Set([
    'github-token',
    'aws-access-key',
    'private-key',
    'database-credential',
    'jwt',
    'generic-api-key',
  ]);

  for (const finding of verification.newFindings) {
    let violated = false;
    const isSecret = SECRET_RULES.has(finding.ruleId) || finding.category === 'security';
    const isVuln = finding.ruleId.startsWith('vuln-') || finding.category === 'dependencies';

    // Rule 1: Any new finding
    if (policy.failOnNewFindings) {
      reasons.push(`NEW finding: [${finding.severity.toUpperCase()}] ${finding.file}${finding.line ? `:${finding.line}` : ''} (${finding.ruleId})`);
      violated = true;
    }

    // Rule 2: Critical severity
    if (!violated && policy.failOnCritical && finding.severity === 'critical') {
      reasons.push(`CRITICAL finding: ${finding.file}${finding.line ? `:${finding.line}` : ''} (${finding.ruleId})`);
      violated = true;
    }

    // Rule 3: High severity
    if (!violated && policy.failOnHigh && finding.severity === 'high') {
      reasons.push(`HIGH finding: ${finding.file}${finding.line ? `:${finding.line}` : ''} (${finding.ruleId})`);
      violated = true;
    }

    // Rule 4: Medium severity
    if (!violated && policy.failOnMedium && finding.severity === 'medium') {
      reasons.push(`MEDIUM finding: ${finding.file}${finding.line ? `:${finding.line}` : ''} (${finding.ruleId})`);
      violated = true;
    }

    // Rule 5: Low severity
    if (!violated && policy.failOnLow && finding.severity === 'low') {
      reasons.push(`LOW finding: ${finding.file}${finding.line ? `:${finding.line}` : ''} (${finding.ruleId})`);
      violated = true;
    }

    // Rule 6: Dependency vulnerability (specifically High severity vulnerability)
    if (!violated && policy.failOnVulnerabilities && isVuln && finding.severity === 'high') {
      reasons.push(`HIGH vulnerability: ${finding.file} (${finding.ruleId})`);
      violated = true;
    }

    // Rule 7: High/Critical secret finding
    if (
      !violated &&
      policy.failOnSecrets &&
      isSecret &&
      (finding.severity === 'high' || finding.severity === 'critical')
    ) {
      reasons.push(`HIGH/CRITICAL secret: ${finding.file}${finding.line ? `:${finding.line}` : ''} (${finding.ruleId})`);
      violated = true;
    }

    if (violated) {
      matchedFindings.push(finding);
    }
  }

  const failed = matchedFindings.length > 0;

  return {
    passed: !failed,
    failed,
    reasons,
    matchedFindings,
    summary: {
      totalViolations: matchedFindings.length,
    },
  };
}
