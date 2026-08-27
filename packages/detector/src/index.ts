export function detectProject(): { type: string; status: 'success' | 'warning' | 'error' } {
  return {
    type: 'Node.js / TypeScript',
    status: 'success',
  };
}
