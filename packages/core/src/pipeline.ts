/**
 * Unified codebase analysis orchestrator.
 */
import type { AnalysisContext, Finding, ProjectInfo } from './index.js';
import { PluginRegistry } from './plugin.js';

export interface PipelineInput {
  basePath: string;
  files: string[];
  strict?: boolean;
  offline?: boolean;
  previousFindings?: Finding[];
  // Pluggable hooks to prevent package circular dependencies
  verifyFindings?: (prev: Finding[], curr: Finding[], advisoryInfo: unknown) => unknown;
  evaluatePolicy?: (verification: unknown) => unknown;
  advisoryInfo?: unknown;
}

export interface PipelineResult {
  schemaVersion: number;
  toolVersion: string;
  project: ProjectInfo;
  findings: Finding[];
  dependencies: {
    metrics?: Record<string, unknown>;
  };
  advisories: {
    provider: string;
    status: 'ok' | 'unavailable' | 'not_checked';
    detail?: string;
  };
  baseline?: unknown;
  score: {
    overallHealth: number;
  };
  policy?: unknown;
}

/**
 * Orchestrate analysis steps across registered plugin analyzers.
 */
export async function runAnalysisPipeline(input: PipelineInput): Promise<PipelineResult> {
  const context: AnalysisContext = {
    basePath: input.basePath,
    files: input.files,
    strict: input.strict,
  };

  const registry = PluginRegistry.getInstance();

  // 1. Run detectors
  let project: ProjectInfo = { type: 'unknown', frameworks: [] };
  for (const detector of registry.getDetectors()) {
    try {
      const info = await detector.detect(context);
      if (info.type !== 'unknown') {
        project = info;
      }
    } catch {
      // Ignore detector failure
    }
  }

  // 2. Run security and dependency analyzers
  let findings: Finding[] = [];
  for (const analyzer of registry.getAnalyzers()) {
    try {
      const results = await analyzer.analyze(context);
      findings = [...findings, ...results];
    } catch (err) {
      console.error(`Analyzer ${analyzer.name} execution failed:`, err);
    }
  }

  // Deduplicate findings by fingerprint
  const uniqueFindings: Finding[] = [];
  const seenFp = new Set<string>();
  for (const f of findings) {
    if (!seenFp.has(f.fingerprint)) {
      uniqueFindings.push(f);
      seenFp.add(f.fingerprint);
    }
  }

  // Calculate overall score
  let penalty = 0;
  for (const f of uniqueFindings) {
    switch (f.severity) {
      case 'critical':
        penalty += 40;
        break;
      case 'high':
        penalty += 20;
        break;
      case 'medium':
        penalty += 10;
        break;
      case 'low':
        penalty += 2;
        break;
    }
  }
  const score = Math.max(0, 100 - penalty);

  // 3. Optional baseline comparison & verification
  let baselineResult: unknown = undefined;
  let policyResult: unknown = undefined;

  if (input.verifyFindings && input.previousFindings) {
    const advisoryInfo = input.advisoryInfo || { provider: 'none', status: 'not_checked' };
    const verification = input.verifyFindings(input.previousFindings, uniqueFindings, advisoryInfo);
    baselineResult = verification;

    if (input.evaluatePolicy) {
      policyResult = input.evaluatePolicy(verification);
    }
  }

  return {
    schemaVersion: 1,
    toolVersion: '0.2.0',
    project,
    findings: uniqueFindings,
    dependencies: {}, // Resolved externally or updated by caller
    advisories: (input.advisoryInfo as PipelineResult['advisories']) || { provider: 'none', status: 'not_checked' },
    baseline: baselineResult,
    score: {
      overallHealth: score,
    },
    policy: policyResult,
  };
}
