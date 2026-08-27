/**
 * GitHub Annotation generator and CLI formatter.
 */
import type { VerificationResult } from '@devfoundry/verification';
import type { GitHubAnnotation } from './model.js';

const SECRET_RULES = new Set([
  'github-token',
  'aws-access-key',
  'private-key',
  'database-credential',
  'jwt',
  'generic-api-key',
]);

/**
 * Generate GitHubAnnotations from new findings in a VerificationResult.
 *
 * SAFETY CONTRACT:
 *   - Never includes raw secret values in titles or messages.
 *   - Only annotates new findings matching criteria.
 */
export function generateAnnotations(verification: VerificationResult): GitHubAnnotation[] {
  const annotations: GitHubAnnotation[] = [];

  for (const f of verification.newFindings) {
    const isSecret = SECRET_RULES.has(f.ruleId) || f.category === 'security';
    const isVuln = f.ruleId.startsWith('vuln-') || f.category === 'dependencies';

    const shouldAnnotate = f.severity === 'critical' || f.severity === 'high' || isSecret || isVuln;

    if (!shouldAnnotate) {
      continue;
    }

    const title = isSecret
      ? `DevFoundry Security Alert: ${f.ruleId}`
      : isVuln
      ? `DevFoundry Dependency Alert: ${f.ruleId}`
      : `DevFoundry Alert: ${f.ruleId}`;

    // REDACT sensitive credentials from annotation message
    let message = f.message;
    if (isSecret) {
      message = `A potential credential pattern was detected. Revoke and remove the credential immediately.`;
    }

    annotations.push({
      file: f.file,
      line: f.line ?? 1,
      title,
      message,
      level: f.severity === 'critical' ? 'error' : 'warning',
    });
  }

  return annotations;
}

/** Print workflow command annotations to stdout. */
export function printGitHubAnnotations(annotations: GitHubAnnotation[]): void {
  for (const ann of annotations) {
    const level = ann.level === 'error' ? 'error' : ann.level === 'warning' ? 'warning' : 'notice';
    console.log(`::${level} file=${ann.file},line=${ann.line},title=${ann.title}::${ann.message}`);
  }
}
