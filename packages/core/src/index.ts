export interface DoctorResult {
  project: {
    type: string;
    status: 'success' | 'warning' | 'error';
  };
  security: {
    secrets: number;
    issues: number;
  };
  dependencies: {
    vulnerable: number;
    outdated: number;
  };
  overallScore: number;
}

export function evaluateProject(): DoctorResult {
  return {
    project: {
      type: 'Node.js / TypeScript',
      status: 'success',
    },
    security: {
      secrets: 0,
      issues: 0,
    },
    dependencies: {
      vulnerable: 0,
      outdated: 0,
    },
    overallScore: 100,
  };
}
