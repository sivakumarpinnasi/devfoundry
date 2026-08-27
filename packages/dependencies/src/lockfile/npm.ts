/**
 * Parses package-lock.json (npm v1/v2/v3) to resolve installed versions.
 *
 * Returns:
 *   - resolvedVersions: Map<name, version> for all packages (direct + transitive)
 *   - transitiveNames: Set<name> for packages not declared directly in the manifest
 */
import * as fs from 'node:fs';

export interface NpmLockfileResult {
  resolvedVersions: Map<string, string>;
  /** Names of packages found in the lockfile but not in the manifest (transitive) */
  allLockfileNames: Set<string>;
}

interface PackageLockPackages {
  [key: string]: { version?: string; dev?: boolean };
}
interface PackageLockDeps {
  [name: string]: { version?: string };
}
interface PackageLockJson {
  lockfileVersion?: number;
  packages?: PackageLockPackages;
  dependencies?: PackageLockDeps;
}

/**
 * Parse a package-lock.json file.
 * Returns an empty result on any error.
 */
export function parseNpmLockfile(lockfilePath: string): NpmLockfileResult {
  const empty: NpmLockfileResult = {
    resolvedVersions: new Map(),
    allLockfileNames: new Set(),
  };

  if (!fs.existsSync(lockfilePath)) return empty;

  let lock: PackageLockJson;
  try {
    lock = JSON.parse(fs.readFileSync(lockfilePath, 'utf8'));
  } catch {
    // Malformed JSON — graceful fallback
    return empty;
  }

  const resolvedVersions = new Map<string, string>();
  const allLockfileNames = new Set<string>();

  if (lock.packages) {
    // v2/v3 format: keys are "node_modules/<name>" or "node_modules/<scope>/<name>"
    for (const [key, entry] of Object.entries(lock.packages)) {
      if (key === '') continue; // root package entry
      if (!key.startsWith('node_modules/')) continue;
      const name = key.slice('node_modules/'.length);
      if (entry.version) {
        resolvedVersions.set(name, entry.version);
        allLockfileNames.add(name);
      }
    }
  } else if (lock.dependencies) {
    // v1 format
    for (const [name, entry] of Object.entries(lock.dependencies)) {
      if (entry.version) {
        resolvedVersions.set(name, entry.version);
        allLockfileNames.add(name);
      }
    }
  }

  return { resolvedVersions, allLockfileNames };
}
