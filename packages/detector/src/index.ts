import * as fs from 'node:fs';
import * as path from 'node:path';
import { AnalysisContext, ProjectInfo } from '@devfoundry/core';

export interface LanguageDetector {
  name: string;
  detect(context: AnalysisContext): Promise<ProjectInfo | null>;
}

export class NodeDetector implements LanguageDetector {
  name = 'Node.js/TypeScript';

  async detect(context: AnalysisContext): Promise<ProjectInfo | null> {
    const files = context.files;
    
    // Check if it's a Node.js project (typically has package.json)
    const hasPackageJson = files.some(f => f === 'package.json' || f.endsWith('/package.json') || f.endsWith('\\package.json'));
    if (!hasPackageJson) {
      return null;
    }

    let type = 'Node.js';
    const hasTsConfig = files.some(f => f === 'tsconfig.json' || f.endsWith('/tsconfig.json') || f.endsWith('\\tsconfig.json'));
    if (hasTsConfig) {
      type = 'Node.js / TypeScript';
    }

    // Determine package manager
    let packageManager = 'npm'; // Default fallback
    if (files.some(f => f === 'pnpm-lock.yaml' || f.endsWith('pnpm-lock.yaml'))) {
      packageManager = 'pnpm';
    } else if (files.some(f => f === 'yarn.lock' || f.endsWith('yarn.lock'))) {
      packageManager = 'yarn';
    } else if (files.some(f => f === 'bun.lockb' || f.endsWith('bun.lockb') || f.endsWith('bun.lock'))) {
      packageManager = 'bun';
    } else if (files.some(f => f === 'package-lock.json' || f.endsWith('package-lock.json'))) {
      packageManager = 'npm';
    }

    // Detect frameworks
    const frameworks = new Set<string>();
    
    // Check config files
    if (files.some(f => f.includes('next.config'))) frameworks.add('Next.js');
    if (files.some(f => f.includes('vite.config'))) frameworks.add('Vite');
    if (files.some(f => f.includes('astro.config'))) frameworks.add('Astro');

    // Parse package.json for frameworks
    const packageJsonFile = files.find(f => f === 'package.json' || f.endsWith('/package.json') || f.endsWith('\\package.json'));
    if (packageJsonFile) {
      try {
        const fullPath = path.isAbsolute(packageJsonFile) ? packageJsonFile : path.join(context.basePath, packageJsonFile);
        if (fs.existsSync(fullPath)) {
          const content = fs.readFileSync(fullPath, 'utf8');
          const pkg = JSON.parse(content);
          const deps = { ...pkg.dependencies, ...pkg.devDependencies };

          if (deps['next']) frameworks.add('Next.js');
          if (deps['vite']) frameworks.add('Vite');
          if (deps['astro']) frameworks.add('Astro');
          if (deps['@angular/core']) frameworks.add('Angular');
          if (deps['react']) frameworks.add('React');
          if (deps['vue']) frameworks.add('Vue');
        }
      } catch {
        // Ignore read/parse errors
      }
    }

    return {
      type,
      frameworks: Array.from(frameworks),
      packageManager,
    };
  }
}

// Registry for extension/future language support (Python, Go, Rust, Java, etc.)
const detectors: LanguageDetector[] = [new NodeDetector()];

export async function detectProject(context: AnalysisContext): Promise<ProjectInfo> {
  for (const detector of detectors) {
    const result = await detector.detect(context);
    if (result) {
      return result;
    }
  }

  // Fallback if nothing detected
  return {
    type: 'Unknown',
    frameworks: [],
  };
}
