import { describe, it, expect } from 'vitest';
import { formatDoctorReport, formatJsonReport } from '../src/index.js';
import { AnalysisResult } from '@devfoundry/core';

describe('reporter output formatting', () => {
  const cleanResult: AnalysisResult = {
    project: {
      type: 'Node.js / TypeScript',
      packageManager: 'pnpm',
      frameworks: ['React', 'Next.js']
    },
    findings: [],
    overallScore: 100
  };

  const dirtyResult: AnalysisResult = {
    project: {
      type: 'Node.js / TypeScript',
      packageManager: 'pnpm',
      frameworks: ['React']
    },
    findings: [
      {
        ruleId: 'github-token',
        severity: 'critical',
        message: 'Potential GitHub Personal Access Token detected. (value: ghp_...3XYZ)',
        file: 'src/config.js',
        line: 5,
        confidence: 'high'
      }
    ],
    overallScore: 60
  };

  it('should format clean doctor report', () => {
    const report = formatDoctorReport(cleanResult);
    expect(report).toContain('DEVFOUNDRY DOCTOR');
    expect(report).toContain('✓ No problems detected.');
    expect(report).toContain('100 / 100');
  });

  it('should format doctor report with findings', () => {
    const report = formatDoctorReport(dirtyResult);
    expect(report).toContain('CRITICAL');
    expect(report).toContain('src/config.js:5');
    expect(report).toContain('github-token');
    expect(report).toContain('⚠ Problems detected.');
    expect(report).toContain('60 / 100');
  });

  it('should format JSON report', () => {
    const report = formatJsonReport(dirtyResult);
    const parsed = JSON.parse(report);
    expect(parsed.overallScore).toBe(60);
    expect(parsed.findings.length).toBe(1);
  });
});
