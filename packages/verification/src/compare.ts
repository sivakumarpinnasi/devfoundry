/**
 * Core verification comparison logic.
 *
 * Uses stable Finding fingerprints as the sole identity criterion.
 * Human-readable messages are NEVER used for comparison.
 *
 * ADVISORY UNCERTAINTY:
 *   If the advisory provider returned status 'unavailable' during the current
 *   scan, dependency vulnerability findings (ruleId starts with 'vuln-') that
 *   are absent from the current scan are NOT classified as "resolved".
 *   They are placed in the `uncertain` bucket so callers can surface this to
 *   users rather than falsely claiming the vulnerability was fixed.
 *
 * STATUS LOGIC:
 *   passed   — remaining=0, newFindings=0, uncertain=0
 *   partial  — (some resolved AND some remaining AND newFindings=0)
 *              OR (uncertain.length > 0 AND newFindings=0 AND remaining=0)
 *   failed   — newFindings > 0
 *              OR (remaining > 0 AND resolved=0 AND uncertain=0)
 */
import type { Finding, AdvisoryInfo } from '@devfoundry/core';
import type { VerificationResult, VerificationStatus } from './model.js';

/**
 * Compare a previous finding set with a current finding set.
 *
 * @param previousFindings  Findings from the scan before a change was applied.
 * @param currentFindings   Findings from the fresh scan after the change.
 * @param advisoryInfo      Advisory metadata from the current scan.
 *                          Used to detect advisory-unavailable conditions.
 * @returns                 A VerificationResult describing what changed.
 */
export function verifyFindings(
  previousFindings: Finding[],
  currentFindings: Finding[],
  advisoryInfo?: AdvisoryInfo,
): VerificationResult {
  const cannotVerifyDeps = !advisoryInfo || advisoryInfo.status !== 'ok';

  const currByFP = new Map<string, Finding>(currentFindings.map(f => [f.fingerprint, f]));
  const prevByFP = new Map<string, Finding>(previousFindings.map(f => [f.fingerprint, f]));

  const resolved: Finding[] = [];
  const remaining: Finding[] = [];
  const uncertain: Finding[] = [];

  for (const pf of previousFindings) {
    if (currByFP.has(pf.fingerprint)) {
      // Same fingerprint still present in current scan → not resolved
      remaining.push(pf);
    } else if (cannotVerifyDeps && pf.ruleId.startsWith('vuln-')) {
      // Dependency advisory not ok: cannot confirm this dep vulnerability was fixed.
      // Moving to 'uncertain' instead of 'resolved' to avoid false clean result.
      uncertain.push(pf);
    } else {
      // Fingerprint gone from current scan AND either:
      //   - not a dep vuln, OR
      //   - advisory check succeeded (we can trust the absence)
      resolved.push(pf);
    }
  }

  // Findings in current scan with no matching previous fingerprint → introduced
  const newFindings = currentFindings.filter(f => !prevByFP.has(f.fingerprint));

  // Determine overall status
  let status: VerificationStatus;

  if (newFindings.length > 0) {
    // Regression: new issue introduced
    status = 'failed';
  } else if (remaining.length > 0 && resolved.length === 0 && uncertain.length === 0) {
    // Nothing improved
    status = 'failed';
  } else if (remaining.length === 0 && uncertain.length === 0) {
    // All previous findings gone, nothing new → clean pass
    status = 'passed';
  } else {
    // Some resolved but some remain or uncertain
    status = 'partial';
  }

  return {
    status,
    resolved,
    remaining,
    newFindings,
    uncertain,
    previousFindings,
    currentFindings,
    advisoryInfo,
    summary: {
      previousCount: previousFindings.length,
      currentCount: currentFindings.length,
      resolvedCount: resolved.length,
      remainingCount: remaining.length,
      newCount: newFindings.length,
      uncertainCount: uncertain.length,
    },
  };
}
