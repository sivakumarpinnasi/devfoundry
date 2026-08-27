/**
 * Parses yarn.lock (classic Yarn v1 and Yarn Berry v2+) to resolve installed versions.
 *
 * Returns:
 *   - resolvedVersions: Map<name, version>
 *   - allLockfileNames: Set<name>
 */
import * as fs from 'node:fs';

export interface YarnLockfileResult {
  resolvedVersions: Map<string, string>;
  allLockfileNames: Set<string>;
}

/**
 * Extract package name from a yarn.lock entry header like:
 *   "lodash@^4.17.0, lodash@^4.17.21":
 *   axios@^1.4.0:
 *
 * Returns the bare package name.
 */
function extractNameFromHeader(header: string): string | null {
  // Strip quotes if present
  const clean = header.replace(/^"/, '').replace(/":\s*$/, '').replace(/:\s*$/, '');
  // Take the first specifier (comma-separated list)
  const first = clean.split(',')[0].trim();
  // Remove the version range after the last @ (but not for scoped packages like @scope/name)
  const atIdx = first.lastIndexOf('@');
  if (atIdx > 0) {
    return first.slice(0, atIdx);
  }
  // Scoped package with no version (edge case)
  return first || null;
}

/**
 * Parse a yarn.lock file.
 * Handles both classic (v1) and berry (v2+) formats.
 * Returns an empty result on any error or missing file.
 */
export function parseYarnLockfile(lockfilePath: string): YarnLockfileResult {
  const empty: YarnLockfileResult = {
    resolvedVersions: new Map(),
    allLockfileNames: new Set(),
  };

  if (!fs.existsSync(lockfilePath)) return empty;

  let content: string;
  try {
    content = fs.readFileSync(lockfilePath, 'utf8').replace(/\r\n/g, '\n');
  } catch {
    return empty;
  }

  const resolvedVersions = new Map<string, string>();
  const allLockfileNames = new Set<string>();

  const lines = content.split('\n');
  let currentName: string | null = null;

  for (const line of lines) {
    // Skip comments and blank lines
    if (line.startsWith('#') || line.trim() === '') {
      if (line.trim() === '') currentName = null;
      continue;
    }

    // Detect an entry header: starts with a non-space char, ends with ":"
    // Classic: `"lodash@^4.0.0":` or `lodash@^4.0.0:`
    // Berry: `"lodash@npm:^4.0.0":` etc.
    if (!line.startsWith(' ') && !line.startsWith('\t')) {
      currentName = extractNameFromHeader(line);
      continue;
    }

    // Detect version line inside an entry block
    if (currentName) {
      const versionMatch = line.match(/^\s+version\s+"?([^\s"]+)"?\s*$/);
      if (versionMatch) {
        const version = versionMatch[1];
        if (!resolvedVersions.has(currentName)) {
          resolvedVersions.set(currentName, version);
        }
        allLockfileNames.add(currentName);
      }
    }
  }

  return { resolvedVersions, allLockfileNames };
}
