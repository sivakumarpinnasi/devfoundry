import { describe, it, expect } from 'vitest';
import { detectProject } from '../src/index.js';

describe('detector', () => {
  it('should detect a Node.js / TypeScript project', () => {
    const result = detectProject();
    expect(result.type).toBe('Node.js / TypeScript');
    expect(result.status).toBe('success');
  });
});
