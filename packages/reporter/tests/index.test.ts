import { describe, it, expect } from 'vitest';
import { formatDoctorReport } from '../src/index.js';
import { evaluateProject } from '@devfoundry/core';

describe('reporter', () => {
  it('should format doctor report correctly', () => {
    const evaluation = evaluateProject();
    const formatted = formatDoctorReport(evaluation);
    expect(formatted).toContain('DEVFOUNDRY DOCTOR');
    expect(formatted).toContain('Node.js / TypeScript');
    expect(formatted).toContain('✓ No problems detected.');
  });
});
