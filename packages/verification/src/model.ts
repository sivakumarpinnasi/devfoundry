/**
 * Verification models for DevFoundry.
 *
 * Verification compares a PREVIOUS set of findings with a CURRENT set
 * obtained from a fresh scan, using stable fingerprints as identity.
 *
 * KEY INVARIANTS:
 *   - Identity is ALWAYS the finding fingerprint, never the human-readable message.
 *   - A finding with the same fingerprint but a different message is still "remaining".
 *   - When the advisory provider was unavailable during the current scan,
 *     previous dependency vulnerability findings cannot be claimed as "resolved".
 *   - Verification NEVER writes to the repository.
 */
import type { Finding, AdvisoryInfo } from '@devfoundry/core';

// ---------------------------------------------------------------------------
// Status types
// ---------------------------------------------------------------------------

/**
 * Overall verification outcome.
 *
 * - 'passed'   All previous findings resolved, no new findings introduced.
 *              Advisory check must have succeeded if there were dep findings.
 * - 'partial'  Some findings resolved but some remain; OR advisory check
 *              failed so dep-vuln resolution cannot be confirmed.
 * - 'failed'   New findings were introduced, OR no previous findings resolved.
 */
export type VerificationStatus = 'passed' | 'failed' | 'partial';

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

/** Numeric summary of a verification run. */
export interface VerificationSummary {
  previousCount: number;
  currentCount: number;
  resolvedCount: number;
  remainingCount: number;
  newCount: number;
  /**
   * Number of previous findings whose resolution CANNOT be confirmed because
   * the advisory provider was unavailable during the current scan.
   * These are dependency vulnerability findings only.
   */
  uncertainCount: number;
}

// ---------------------------------------------------------------------------
// Verification result
// ---------------------------------------------------------------------------

/**
 * The complete result of a verification comparison run.
 *
 * Consumers MUST check `advisoryInfo.status` before interpreting
 * `uncertain.length === 0` as "all dep vulns resolved".
 */
export interface VerificationResult {
  /** Overall outcome of the verification. */
  status: VerificationStatus;

  /**
   * Previous findings confirmed as resolved (fingerprint absent from current scan).
   * ONLY populated when their resolution can be confirmed (i.e. dep findings
   * require a successful advisory check).
   */
  resolved: Finding[];

  /**
   * Previous findings still present in the current scan (fingerprint match). */
  remaining: Finding[];

  /**
   * Findings present in the current scan that were NOT in the previous scan.
   * Any new finding means something was INTRODUCED — regression or new issue.
   */
  newFindings: Finding[];

  /**
   * Previous dependency vulnerability findings that CANNOT be verified as
   * resolved because the advisory provider was unavailable in the current scan.
   * These are neither "resolved" nor "remaining" — their status is UNKNOWN.
   */
  uncertain: Finding[];

  /** Original previous findings passed to verifyFindings(). */
  previousFindings: Finding[];

  /** Current findings from the fresh scan. */
  currentFindings: Finding[];

  /** Numeric rollup of all the above. */
  summary: VerificationSummary;

  /** Advisory metadata from the current scan; undefined if dep analysis not run. */
  advisoryInfo?: AdvisoryInfo;
}

// ---------------------------------------------------------------------------
// Baseline models
// ---------------------------------------------------------------------------

/**
 * A finding saved in the baseline file.
 *
 * SAFETY CONTRACT:
 *   Contains only non-sensitive finding metadata needed for fingerprinting.
 *   Raw messages, remediation hints, and credential values are NEVER stored.
 */
export interface BaselineFinding {
  fingerprint: string;
  ruleId: string;
  category: string;
  severity: string;
  file: string;
  line?: number;
  metadata?: Record<string, unknown>;
}

/** Project info in baseline. */
export interface BaselineProject {
  type: string;
  packageManager?: string;
}

/** Advisories info in baseline. */
export interface BaselineAdvisories {
  provider: string;
  status: string;
}

/**
 * DevFoundry baseline JSON schema.
 * Saved as .devfoundry/baseline.json.
 */
export interface Baseline {
  version: number;
  createdAt: string;
  toolVersion: string;
  project: BaselineProject;
  findings: BaselineFinding[];
  advisories: BaselineAdvisories;
}
