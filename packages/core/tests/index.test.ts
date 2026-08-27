import { describe, it, expect } from 'vitest';
import { evaluateProject } from '../src/index.js';

describe('core', () => {
  it('should return a default perfect health evaluation', () => {
    const result = evaluateProject();
    expect(result.overallScore).toBe(100);
    expect(result.project.status).toBe('success');
  });
});
