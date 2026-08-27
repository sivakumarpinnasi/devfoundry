import { describe, it, expect } from 'vitest';
import { calculateScore, Finding } from '../src/index.js';

describe('core calculateScore', () => {
  it('should return 100 for no findings', () => {
    expect(calculateScore([])).toBe(100);
  });

  it('should deduct scores correctly based on severity', () => {
    const findings: Finding[] = [
      { ruleId: 'rule1', severity: 'low', message: 'test', file: 'file.js' },
      { ruleId: 'rule2', severity: 'medium', message: 'test', file: 'file.js' },
      { ruleId: 'rule3', severity: 'high', message: 'test', file: 'file.js' },
      { ruleId: 'rule4', severity: 'critical', message: 'test', file: 'file.js' },
    ];
    // penalty: 2 + 10 + 20 + 40 = 72. Score: 100 - 72 = 28
    expect(calculateScore(findings)).toBe(28);
  });

  it('should not go below 0', () => {
    const findings: Finding[] = [
      { ruleId: 'rule1', severity: 'critical', message: 'test', file: 'file.js' },
      { ruleId: 'rule2', severity: 'critical', message: 'test', file: 'file.js' },
      { ruleId: 'rule3', severity: 'critical', message: 'test', file: 'file.js' },
    ];
    // penalty: 120. Score: 0
    expect(calculateScore(findings)).toBe(0);
  });
});
