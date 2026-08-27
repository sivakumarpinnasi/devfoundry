/**
 * Parses pnpm-lock.yaml (lockfile version 5.x and 6.x) without a YAML library.
 *
 * Returns:
 *   - resolvedVersions: Map<name, version> for all packages resolved
 *   - allLockfileNames: Set<name> for all packages found in lockfile
 */
import * as fs from 'node:fs';

export interface PnpmLockfileResult {
  resolvedVersions: Map<string, string>;
  allLockfileNames: Set<string>;
}

/**
 * Extract the content of a named top-level YAML section (e.g. "packages").
 * Returns all lines that are indented (belong to that section).
 */
function extractSection(content: string, sectionName: string): string {
  const marker = `\n${sectionName}:\n`;
  let startIdx = content.indexOf(marker);
  // Also handle if section is at the very start of the file
  if (startIdx === -1) {
    if (content.startsWith(`${sectionName}:\n`)) {
      startIdx = -marker.length; // offset so sectionStart below = 0
    } else {
      return '';
    }
  }

  const sectionStart = startIdx + marker.length;
  const remaining = content.slice(sectionStart);
  const lines = remaining.split('\n');
  const sectionLines: string[] = [];

  for (const line of lines) {
    // Stop at the next top-level key (non-empty line that doesn't start with whitespace)
    if (line.length > 0 && !/^\s/.test(line)) break;
    sectionLines.push(line);
  }

  return sectionLines.join('\n');
}

/**
 * Parse the packages: section to extract name→version entries.
 *
 * Handles:
 *   v5:  /lodash/4.17.21:
 *   v6:  /lodash@4.17.21:
 *   v9:  lodash@4.17.21:
 *   scoped: /@babel/core@7.22.0:
 */
function parsePackagesSection(section: string): Map<string, string> {
  const result = new Map<string, string>();

  const lines = section.split('\n');
  for (const line of lines) {
    // Entry header: 2 spaces of indent, optional leading slash
    // Patterns: "  /name@ver:", "  /name/ver:", "  name@ver:", "  /@scope/name@ver:"
    const trimmed = line.trim();
    if (!trimmed.endsWith(':')) continue;

    // Strip leading slash(es)
    const entry = trimmed.replace(/^\/+/, '').replace(/:$/, '');

    // Try "@" separator for v6/v9 (e.g. "lodash@4.17.21" or "@babel/core@7.22.0")
    // The version always starts with a digit
    const atIdx = entry.lastIndexOf('@');
    if (atIdx > 0) {
      const name = entry.slice(0, atIdx);
      const version = entry.slice(atIdx + 1);
      // version must start with a digit
      if (/^\d/.test(version) && name.length > 0) {
        if (!result.has(name)) result.set(name, version);
        continue;
      }
    }

    // Try "/" separator for v5 (e.g. "lodash/4.17.21" or "@babel/core/7.22.0")
    // Find the last "/" that precedes a digit-starting token
    const slashIdx = entry.lastIndexOf('/');
    if (slashIdx > 0) {
      const name = entry.slice(0, slashIdx);
      const version = entry.slice(slashIdx + 1);
      if (/^\d/.test(version) && name.length > 0) {
        if (!result.has(name)) result.set(name, version);
      }
    }
  }

  return result;
}

/**
 * Parse the importers section for direct dep specifier→version mappings.
 * More precise than the packages section for direct dependencies.
 *
 * Format (v6):
 *   importers:
 *     .:
 *       dependencies:
 *         lodash:
 *           specifier: ^4.17.21
 *           version: 4.17.21
 */
function parseImportersSection(section: string): Map<string, string> {
  const result = new Map<string, string>();
  const lines = section.split('\n');

  let currentName: string | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Detect a dependency name entry (indented 6+ spaces, ends with ":")
    // e.g. "      lodash:"
    const nameMatch = line.match(/^\s{6,}(\S[^:]*):$/);
    if (nameMatch) {
      currentName = nameMatch[1].trim();
      continue;
    }

    // Detect version line after a name line
    if (currentName) {
      const versionMatch = line.match(/^\s+version:\s*(\S+)/);
      if (versionMatch) {
        // Strip any build metadata suffix pnpm may append (e.g. "4.17.21(patch_hash=abc)")
        const rawVersion = versionMatch[1].split('(')[0];
        if (!result.has(currentName)) {
          result.set(currentName, rawVersion);
        }
        currentName = null;
        continue;
      }
      // If we see a non-version, non-specifier indented key, clear currentName
      if (line.match(/^\s+\w+:/) && !line.match(/^\s+specifier:/)) {
        currentName = null;
      }
    }
  }

  return result;
}

/**
 * Parse a pnpm-lock.yaml file.
 * Returns an empty result on any error or missing file.
 */
export function parsePnpmLockfile(lockfilePath: string): PnpmLockfileResult {
  const empty: PnpmLockfileResult = {
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

  // Parse the packages section (all locked packages, direct + transitive)
  const packagesSection = extractSection(content, 'packages');
  const resolvedVersions = parsePackagesSection(packagesSection);
  const allLockfileNames = new Set(resolvedVersions.keys());

  // Parse the importers section (direct deps with precise resolved versions)
  const importersSection = extractSection(content, 'importers');
  const importerVersions = parseImportersSection(importersSection);

  // Importer versions override packages section versions for direct deps
  for (const [name, version] of importerVersions) {
    resolvedVersions.set(name, version);
    allLockfileNames.add(name);
  }

  return { resolvedVersions, allLockfileNames };
}
