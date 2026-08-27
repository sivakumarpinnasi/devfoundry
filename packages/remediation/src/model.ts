/**
 * Normalized remediation model for DevFoundry.
 *
 * SAFETY CONTRACT:
 *   No remediation action modifies files automatically.
 *   Every action carries a risk level and requires explicit user confirmation
 *   before any future mutation is applied.
 *   Secret values are NEVER included in remediation output.
 */

// ---------------------------------------------------------------------------
// Risk and status types
// ---------------------------------------------------------------------------

/**
 * Risk level of applying a remediation action.
 *
 * - low      Safe dependency version pin change; easily reversible.
 * - medium   Configuration change; requires testing.
 * - high     Irreversible action (credential rotation, secret deletion).
 * - critical High-blast-radius change; affects many files or core config.
 */
export type RemediationRisk = 'low' | 'medium' | 'high' | 'critical';

/**
 * Overall status of a RemediationPlan.
 *
 * - available  One or more actionable remediations exist.
 * - none       No applicable remediations were found for any finding.
 */
export type RemediationStatus = 'available' | 'none';

// ---------------------------------------------------------------------------
// Remediation action
// ---------------------------------------------------------------------------

/**
 * A single proposed remediation for one finding.
 *
 * IMPORTANT: This action NEVER modifies files. It is a proposal only.
 * Future CLI support for --apply will require explicit user confirmation.
 */
export interface RemediationAction {
  /** Unique action identifier (deterministic, based on findingId + category). */
  id: string;
  /** Fingerprint of the Finding this action addresses. */
  findingId: string;
  /** Category of remediation action. */
  category: 'dependency' | 'security' | 'configuration';
  /** Short human-readable title shown in the fix report header. */
  title: string;
  /** Extended description of what this action does. */
  description: string;
  /** Risk level of applying this action. */
  risk: RemediationRisk;
  /** Files that would be affected. Listed for transparency; NOT modified. */
  files: string[];
  /**
   * Current value being replaced (e.g. package version "4.17.20").
   * MUST NEVER contain secret values.
   */
  currentValue?: string;
  /**
   * Target value after remediation (e.g. fixed version "4.17.21").
   * MUST NEVER contain secret values.
   */
  targetValue?: string;
  /** Whether this action can be reversed after applying. */
  reversible: boolean;
  /** Whether this action must prompt for user confirmation before applying. */
  requiresConfirmation: boolean;
  /**
   * Whether an automated fix implementation is available.
   * false = guidance only (v0.1.4); true = future automated apply support.
   */
  automated: boolean;
  /**
   * Step-by-step manual guidance for actions that cannot be automated safely.
   * Used for credential remediation and other high-risk actions.
   */
  guidance?: string[];
  /** Short note explaining why automation is not available. */
  noAutomationReason?: string;
}

// ---------------------------------------------------------------------------
// Finding with no remediation
// ---------------------------------------------------------------------------

/** Describes why a finding has no applicable remediation action. */
export interface NoActionReason {
  findingId: string;
  ruleId: string;
  reason: string;
}

// ---------------------------------------------------------------------------
// Remediation plan
// ---------------------------------------------------------------------------

/**
 * The complete remediation plan for a full analysis run.
 * Contains zero or more RemediationActions and summary metadata.
 *
 * GUARANTEE: Consuming this plan does not modify any files.
 */
export interface RemediationPlan {
  actions: RemediationAction[];
  status: RemediationStatus;
  totalFindings: number;
  actionsAvailable: number;
  /** Findings for which no automated or guidance action could be generated. */
  noActionReasons: NoActionReason[];
}
