/**
 * GitHub integration models.
 */

export interface GitHubAnnotation {
  file: string;
  line: number;
  endLine?: number;
  title: string;
  message: string;
  level: 'notice' | 'warning' | 'error';
}

export interface GitHubSummary {
  markdown: string;
}

export interface GitHubCheckResult {
  conclusion: 'success' | 'failure' | 'neutral' | 'skipped' | 'timed_out' | 'action_required';
  summary: string;
  annotations: GitHubAnnotation[];
}
