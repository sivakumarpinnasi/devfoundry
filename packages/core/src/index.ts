export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type FileChangeStatus = 'changed' | 'unchanged' | 'unknown';

export interface ChangedFileSet {
  status(file: string): FileChangeStatus;
}

export interface Finding {
  ruleId: string;
  category: 'security' | 'dependencies' | 'detector';
  severity: Severity;
  message: string;
  file: string;
  line?: number;
  column?: number;
  confidence?: 'low' | 'medium' | 'high';
  fingerprint: string;
  remediation?: string;
  fileStatus?: FileChangeStatus;
}

export interface AnalysisContext {
  basePath: string;
  files: string[];
  strict?: boolean;
}

export interface ProjectInfo {
  type: string;
  frameworks: string[];
  packageManager?: string;
}

/** Minimal dependency metrics shape — mirrors DependencyMetrics in @devfoundry/dependencies */
export interface DepMetrics {
  total: number;
  direct: number;
  transitive: number;
  outdated: number;
  vulnerable: number;
}

/**
 * Advisory lookup status for a completed analysis run.
 *
 * - 'ok'          — provider was contacted and responded successfully
 * - 'unavailable' — provider was unreachable or returned an error;
 *                   vulnerability count is UNKNOWN, not zero
 * - 'not_checked' — provider was intentionally skipped (e.g. --offline);
 *                   vulnerability count is NOT checked, not zero
 */
export interface AdvisoryInfo {
  /** Provider identifier: 'osv', 'none', 'mock' */
  provider: string;
  status: 'ok' | 'unavailable' | 'not_checked';
  detail?: string;
}

export interface AnalysisResult {
  project: ProjectInfo;
  findings: Finding[];
  overallScore: number;
  /** Populated by CLI after advisory scan; undefined when dep analysis not run */
  depMetrics?: DepMetrics;
  /** Advisory lookup metadata; undefined when dependency analysis was not run */
  advisoryInfo?: AdvisoryInfo;
}

export interface Analyzer {
  name: string;
  analyze(context: AnalysisContext): Promise<Finding[]>;
}

export function calculateScore(findings: Finding[]): number {
  let penalty = 0;
  for (const finding of findings) {
    switch (finding.severity) {
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
  return Math.max(0, 100 - penalty);
}

export const EXIT_CODES = {
  SUCCESS: 0,
  POLICY_VIOLATION: 1,
  INVALID_CONFIG: 2,
  ANALYSIS_ERROR: 3,
} as const;

export type ExitCode = typeof EXIT_CODES[keyof typeof EXIT_CODES];

export * from './rule.js';
export * from './plugin.js';
export * from './pipeline.js';
