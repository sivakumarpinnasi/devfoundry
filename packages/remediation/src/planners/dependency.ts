/**
 * Dependency remediation planner.
 *
 * Given a vulnerability finding for a dependency, generates a RemediationAction
 * describing the version upgrade. Does NOT modify package.json or lockfiles.
 *
 * Parsing strategy:
 *   Finding message format: `Dependency "PKGNAME" (VERSION) is vulnerable: SUMMARY [RANGE]`
 *   Finding remediation:    `Upgrade "PKGNAME" to FIXED or higher.`
 *                       or: `Review advisory ADVISORY_ID and update "PKGNAME".`
 */
import { Finding } from '@devfoundry/core';
import { RemediationAction } from '../model.js';

/** Extract package name and installed version from a vulnerability finding message. */
function parseDependencyFinding(message: string): { name: string; version: string } | null {
  const match = message.match(/^Dependency "([^"]+)" \(([^)]+)\) is vulnerable/);
  if (!match) return null;
  return { name: match[1], version: match[2] };
}

/** Extract the fixed version from the remediation hint string. */
function parseFixedVersion(remediation: string | undefined): string | undefined {
  if (!remediation) return undefined;
  const match = remediation.match(/Upgrade "[^"]+" to ([^\s]+) or higher/);
  return match?.[1];
}

/** Determine which lockfile to list based on the finding source file. */
function resolveLockfiles(sourceFile: string, packageManager?: string): string[] {
  // Prefer the package manager hint embedded in source if available
  if (sourceFile.endsWith('pnpm-lock.yaml')) return ['package.json', 'pnpm-lock.yaml'];
  if (sourceFile.endsWith('yarn.lock'))       return ['package.json', 'yarn.lock'];
  if (sourceFile.endsWith('package-lock.json')) return ['package.json', 'package-lock.json'];

  // Fall back to a reasonable default
  switch (packageManager) {
    case 'pnpm': return ['package.json', 'pnpm-lock.yaml'];
    case 'yarn': return ['package.json', 'yarn.lock'];
    default:     return ['package.json', 'package-lock.json'];
  }
}

/**
 * Create a RemediationAction for a dependency vulnerability finding.
 *
 * Returns null if the finding cannot be parsed as a dependency finding
 * (e.g. wrong ruleId format or unparseable message).
 */
export function planDependencyRemediation(
  finding: Finding,
  packageManager?: string,
): RemediationAction | null {
  if (!finding.ruleId.startsWith('vuln-')) return null;

  const parsed = parseDependencyFinding(finding.message);
  if (!parsed) return null;

  const { name, version } = parsed;
  const fixedVersion = parseFixedVersion(finding.remediation);
  const hasFixedVersion = !!fixedVersion;

  const files = resolveLockfiles(finding.file, packageManager);
  const id = Buffer.from(`dep:${finding.fingerprint}`).toString('base64').slice(0, 16);

  if (hasFixedVersion) {
    return {
      id,
      findingId: finding.fingerprint,
      category: 'dependency',
      title: `Upgrade dependency`,
      description:
        `"${name}" version ${version} is vulnerable. ` +
        `Upgrading to ${fixedVersion} or higher resolves this advisory. ` +
        `After changing package.json, run your package manager to regenerate the lockfile.`,
      risk: 'low',
      files,
      currentValue: version,
      targetValue: fixedVersion,
      reversible: true,
      requiresConfirmation: true,
      automated: false,
      noAutomationReason: 'Automated version pinning is not yet implemented (planned for v0.2.0).',
      guidance: [
        `Update "${name}" in package.json to "${fixedVersion}" or higher.`,
        `Run your package manager to regenerate the lockfile (e.g. pnpm install, npm install, yarn).`,
        `Run your test suite to verify nothing broke.`,
      ],
    };
  }

  // No fixed version available — guidance only
  return {
    id,
    findingId: finding.fingerprint,
    category: 'dependency',
    title: `Review vulnerable dependency`,
    description:
      `"${name}" version ${version} is vulnerable and no fixed version is currently available. ` +
      `Review the advisory and monitor for a patch release.`,
    risk: 'high',
    files,
    currentValue: version,
    reversible: false,
    requiresConfirmation: true,
    automated: false,
    noAutomationReason: 'No fixed version is available yet. Manual review required.',
    guidance: [
      `Check the advisory for "${name}" (${finding.ruleId.replace('vuln-', '')}) for workarounds.`,
      `Consider replacing "${name}" with an alternative library if no patch is expected.`,
      `Monitor the package releases and upgrade as soon as a fixed version is published.`,
      `Evaluate whether this dependency is reachable in your application's code paths.`,
    ],
  };
}
