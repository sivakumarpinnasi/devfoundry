export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface Finding {
  ruleId: string;
  severity: Severity;
  message: string;
  file: string;
  line?: number;
  column?: number;
  confidence?: 'low' | 'medium' | 'high';
}

export interface AnalysisContext {
  basePath: string;
  files: string[];
}

export interface ProjectInfo {
  type: string;
  frameworks: string[];
  packageManager?: string;
}

export interface AnalysisResult {
  project: ProjectInfo;
  findings: Finding[];
  overallScore: number;
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
