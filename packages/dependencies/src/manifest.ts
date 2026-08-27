/**
 * Parses package.json to extract declared dependencies.
 * Returns a flat list of Dependency entries (all marked as 'direct').
 * Installed versions are not resolved here — see resolver.ts.
 */
import * as fs from 'node:fs';
import { Dependency, DepType } from './model.js';

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

/**
 * Parse package.json at the given absolute path.
 * Returns an empty array on any error (missing file, invalid JSON, etc.).
 */
export function parseManifest(packageJsonPath: string): Dependency[] {
  if (!fs.existsSync(packageJsonPath)) {
    return [];
  }

  let pkg: PackageJson;
  try {
    pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  } catch {
    return [];
  }

  const deps: Dependency[] = [];

  const sections: Array<{ field: keyof PackageJson; depType: DepType }> = [
    { field: 'dependencies', depType: 'production' },
    { field: 'devDependencies', depType: 'dev' },
    { field: 'optionalDependencies', depType: 'optional' },
    { field: 'peerDependencies', depType: 'peer' },
  ];

  for (const { field, depType } of sections) {
    const section = pkg[field];
    if (!section) continue;
    for (const [name, versionSpec] of Object.entries(section)) {
      // Avoid duplicates: if already added from a higher-priority section, skip
      if (deps.some(d => d.name === name)) continue;
      deps.push({
        name,
        versionSpec,
        installedVersion: undefined,
        depType,
        direct: 'direct',
        source: 'package.json',
      });
    }
  }

  return deps;
}
