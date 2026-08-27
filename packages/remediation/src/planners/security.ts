/**
 * Security (secret) remediation planner.
 *
 * SAFETY CONTRACT:
 *   - Credentials are NEVER rotated automatically.
 *   - Credential values are NEVER exposed in output.
 *   - Actions are guidance-only with high risk rating.
 *   - Users must manually follow each guidance step.
 *
 * Supported finding categories:
 *   - github-token
 *   - aws-access-key
 *   - private-key
 *   - database-credential
 *   - jwt
 *   - generic-api-key
 */
import { Finding } from '@devfoundry/core';
import { RemediationAction } from '../model.js';

/** Human-readable label for a secret type by ruleId. */
const SECRET_LABELS: Record<string, string> = {
  'github-token':          'GitHub Personal Access Token',
  'aws-access-key':        'AWS Access Key',
  'private-key':           'Private Key (RSA/EC/PGP)',
  'database-credential':   'Database Credential',
  'jwt':                   'JSON Web Token (JWT)',
  'generic-api-key':       'Generic API Key / Secret',
};

const KNOWN_SECRET_RULE_IDS = new Set(Object.keys(SECRET_LABELS));

/**
 * Build step-by-step guidance for secret remediation.
 * Guidance is generic enough to apply to any credential type.
 */
function buildSecretGuidance(label: string, file: string, line?: number): string[] {
  const loc = line ? `${file}:${line}` : file;
  return [
    `1. ROTATE: Immediately revoke and regenerate the ${label} through the issuing service (GitHub, AWS console, etc.).`,
    `2. REMOVE: Delete the credential from "${loc}". Replace with an environment variable or secret manager reference.`,
    `3. INSPECT GIT HISTORY: The credential may already be in version control history. Run:`,
    `   git log --all --full-history -- "${file}"`,
    `   If found in history, consider using git-filter-repo or BFG Repo Cleaner.`,
    `4. SCAN ENVIRONMENT: Ensure the credential is not also present in .env files, CI/CD configs, or deployment scripts.`,
    `5. ADD SECRET MANAGEMENT: Use a secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager, GitHub Actions secrets) to inject credentials at runtime.`,
    `6. PREVENT RECURRENCE: Add a pre-commit hook (e.g. detect-secrets, gitleaks) to block future accidental commits.`,
  ];
}

/**
 * Create a RemediationAction for a secret/credential finding.
 *
 * Returns null if the finding is not a recognized secret rule.
 * Never includes secret values in the action output.
 */
export function planSecretRemediation(finding: Finding): RemediationAction | null {
  if (!KNOWN_SECRET_RULE_IDS.has(finding.ruleId)) return null;

  const label = SECRET_LABELS[finding.ruleId] ?? 'Secret / Credential';
  const id = Buffer.from(`sec:${finding.fingerprint}`).toString('base64').slice(0, 16);
  const loc = finding.line ? `${finding.file}:${finding.line}` : finding.file;

  return {
    id,
    findingId: finding.fingerprint,
    category: 'security',
    title: 'Credential remediation',
    description:
      `A ${label} was detected at ${loc}. ` +
      `This credential must be rotated immediately and removed from the codebase. ` +
      `Automated credential management is not safe — follow the manual steps below.`,
    risk: 'high',
    files: [finding.file],
    // currentValue and targetValue are intentionally omitted — never expose secret values
    reversible: false,
    requiresConfirmation: true,
    automated: false,
    noAutomationReason:
      'Automatic credential rotation is unsafe. Credentials must be manually revoked ' +
      'through the issuing service before removing them from source.',
    guidance: buildSecretGuidance(label, finding.file, finding.line),
  };
}
