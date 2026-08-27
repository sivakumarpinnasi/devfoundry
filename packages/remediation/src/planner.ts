/**
 * Remediation plan orchestrator.
 *
 * Takes an AnalysisResult and routes each Finding through the appropriate
 * planner (dependency / security / configuration). Returns a complete
 * RemediationPlan without modifying any files.
 */
import { AnalysisResult, Finding } from '@devfoundry/core';
import { NoActionReason, RemediationAction, RemediationPlan } from './model.js';
import { planDependencyRemediation } from './planners/dependency.js';
import { planSecretRemediation } from './planners/security.js';
import { planConfigurationRemediation } from './planners/configuration.js';

/**
 * Route a single Finding to the appropriate planner.
 *
 * Returns { action } on success, { reason } when no automated action is possible.
 */
function planFinding(
  finding: Finding,
  packageManager?: string,
): { action: RemediationAction } | { reason: NoActionReason } {

  // 1. Vulnerability findings (ruleId starts with 'vuln-')
  if (finding.ruleId.startsWith('vuln-')) {
    const action = planDependencyRemediation(finding, packageManager);
    if (action) return { action };
    return {
      reason: {
        findingId: finding.fingerprint,
        ruleId: finding.ruleId,
        reason: 'Dependency finding could not be parsed for remediation.',
      },
    };
  }

  // 2. Secret / credential findings
  const secretAction = planSecretRemediation(finding);
  if (secretAction) return { action: secretAction };

  // 3. Configuration findings (future)
  const configAction = planConfigurationRemediation(finding);
  if (configAction) return { action: configAction };

  // 4. No applicable planner
  return {
    reason: {
      findingId: finding.fingerprint,
      ruleId: finding.ruleId,
      reason: `No automated or guidance remediation is available for rule "${finding.ruleId}" in v0.1.4.`,
    },
  };
}

/**
 * Build a complete RemediationPlan for an AnalysisResult.
 *
 * Does NOT modify any files. The returned plan is read-only.
 *
 * @param result       The analysis result from a `foundry doctor` run.
 * @param packageManager  Optional package manager hint for lockfile selection.
 */
export function buildRemediationPlan(
  result: AnalysisResult,
  packageManager?: string,
): RemediationPlan {
  const actions: RemediationAction[] = [];
  const noActionReasons: NoActionReason[] = [];

  for (const finding of result.findings) {
    const outcome = planFinding(finding, packageManager);
    if ('action' in outcome) {
      actions.push(outcome.action);
    } else {
      noActionReasons.push(outcome.reason);
    }
  }

  return {
    actions,
    status: actions.length > 0 ? 'available' : 'none',
    totalFindings: result.findings.length,
    actionsAvailable: actions.length,
    noActionReasons,
  };
}
