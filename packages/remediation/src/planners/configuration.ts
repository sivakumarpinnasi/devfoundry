/**
 * Configuration remediation planner — placeholder for future rules.
 *
 * v0.1.4 does not implement any automated configuration fixes.
 * This module is provided as an extension point for future rule implementations.
 */
import { Finding } from '@devfoundry/core';
import { RemediationAction } from '../model.js';

/**
 * Attempt to create a remediation action for a configuration finding.
 *
 * Currently returns null for all findings — no automated configuration
 * remediations are implemented in v0.1.4.
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function planConfigurationRemediation(_finding: Finding): RemediationAction | null {
  // Reserved for future configuration rule implementations.
  // When rules such as "insecure tsconfig settings" or "missing .gitignore entries"
  // are added, this planner will return RemediationActions for them.
  return null;
}
