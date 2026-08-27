/**
 * Policy models for DevFoundry CI Policy Engine.
 */
import type { Finding } from '@devfoundry/core';

export interface Policy {
  /** Fail on any new finding, regardless of severity/type. */
  failOnNewFindings: boolean;
  /** Fail when a critical finding exists. */
  failOnCritical: boolean;
  /** Fail when a high finding exists. */
  failOnHigh: boolean;
  /** Fail when a medium finding exists. */
  failOnMedium: boolean;
  /** Fail when a low finding exists. */
  failOnLow: boolean;
  /** Fail when a secret/credential finding is discovered. */
  failOnSecrets: boolean;
  /** Fail when a dependency vulnerability finding is discovered. */
  failOnVulnerabilities: boolean;
}

export interface PolicySummary {
  totalViolations: number;
}

export interface PolicyResult {
  /** True if the codebase complies with the CI policy. */
  passed: boolean;
  /** True if any policy violations were found. */
  failed: boolean;
  /** Human-readable explanations of all violations. */
  reasons: string[];
  /** The specific new findings that triggered the policy violations. */
  matchedFindings: Finding[];
  /** Summary counts of the evaluation. */
  summary: PolicySummary;
}
