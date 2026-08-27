/**
 * ChangedFileSet implementation using Git diffs.
 */
import { execSync } from 'node:child_process';
import type { ChangedFileSet, FileChangeStatus } from '@devfoundry/core';

/**
 * Parses git diff output to determine which files have changed.
 */
export class GitChangedFileSet implements ChangedFileSet {
  private changedFiles = new Set<string>();
  private isGit = false;

  constructor(basePath: string) {
    try {
      // Gather unstaged and staged changes
      const diffUnstaged = execSync('git diff --name-only', { cwd: basePath, encoding: 'utf8' });
      const diffStaged = execSync('git diff --cached --name-only', { cwd: basePath, encoding: 'utf8' });

      const files = [...diffUnstaged.split('\n'), ...diffStaged.split('\n')]
        .map(f => f.trim().replace(/\\/g, '/'))
        .filter(f => f.length > 0);

      this.changedFiles = new Set(files);
      this.isGit = true;
    } catch {
      // Git is either not installed, or this is not a git repository
    }
  }

  status(file: string): FileChangeStatus {
    if (!this.isGit) {
      return 'unknown';
    }
    const normalized = file.trim().replace(/\\/g, '/');
    return this.changedFiles.has(normalized) ? 'changed' : 'unchanged';
  }
}

/** Simple manual/mock change list checker. */
export class SimpleChangedFileSet implements ChangedFileSet {
  private files: Set<string>;

  constructor(changedFiles: string[]) {
    this.files = new Set(changedFiles.map(f => f.trim().replace(/\\/g, '/')));
  }

  status(file: string): FileChangeStatus {
    const normalized = file.trim().replace(/\\/g, '/');
    return this.files.has(normalized) ? 'changed' : 'unchanged';
  }
}
