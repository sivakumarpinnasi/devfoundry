/**
 * Merges manifest dependency declarations with lockfile resolved versions.
 * Appends transitive dependencies (found in lockfile but not in package.json).
 * Computes DependencyMetrics.
 */
import { Dependency, DependencyAnalysis, DependencyMetrics } from './model.js';

export interface ResolverInput {
  manifestDeps: Dependency[];
  resolvedVersions: Map<string, string>;
  /** All package names found in the lockfile (direct + transitive) */
  allLockfileNames: Set<string>;
  packageManager?: string;
}

/**
 * Produce a fully resolved DependencyAnalysis from manifest + lockfile data.
 */
export function resolveDependencies(input: ResolverInput): DependencyAnalysis {
  const { manifestDeps, resolvedVersions, allLockfileNames, packageManager } = input;

  // Start with manifest deps; fill in installed versions from lockfile
  const resolved: Dependency[] = manifestDeps.map(dep => ({
    ...dep,
    installedVersion: resolvedVersions.get(dep.name) ?? dep.installedVersion,
  }));

  // Determine which names are already in the manifest
  const manifestNames = new Set(manifestDeps.map(d => d.name));

  // Append transitive deps from lockfile that are not in the manifest
  for (const name of allLockfileNames) {
    if (manifestNames.has(name)) continue;
    const version = resolvedVersions.get(name);
    resolved.push({
      name,
      versionSpec: version ?? 'unknown',
      installedVersion: version,
      depType: 'production', // lockfile does not reliably expose type for transitives
      direct: 'transitive',
      source: 'lockfile',
    });
  }

  const directCount = resolved.filter(d => d.direct === 'direct').length;
  const transitiveCount = resolved.filter(d => d.direct === 'transitive').length;

  const metrics: DependencyMetrics = {
    total: resolved.length,
    direct: directCount,
    transitive: transitiveCount,
    outdated: 0, // TODO: requires registry lookup — not implemented in v0.1.2
    vulnerable: 0, // Will be updated after advisory scan
  };

  return { dependencies: resolved, packageManager, metrics };
}
