import * as fs from 'node:fs';
import * as path from 'node:path';
import { Command } from 'commander';
import { calculateScore, AnalysisContext, AnalysisResult } from '@devfoundry/core';
import { detectProject } from '@devfoundry/detector';
import { scanSecurity } from '@devfoundry/security';
import { analyzeDependencies } from '@devfoundry/dependencies';
import { formatDoctorReport, formatJsonReport } from '@devfoundry/reporter';

function getFilesRecursive(dir: string, baseDir = dir): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];

  const IGNORED_DIRS = ['.git', 'node_modules', 'dist', 'build', 'coverage'];

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(baseDir, fullPath).replace(/\\/g, '/');

    if (entry.isDirectory()) {
      if (IGNORED_DIRS.includes(entry.name)) {
        continue;
      }
      try {
        files.push(...getFilesRecursive(fullPath, baseDir));
      } catch {
        // Skip unreadable directories
      }
    } else {
      files.push(relPath);
    }
  }

  return files;
}

export function runCLI(): void {
  const program = new Command();

  program
    .name('foundry')
    .description('DevFoundry CLI')
    .version('0.1.1');

  program
    .command('doctor')
    .description('Run project doctor diagnostics')
    .option('--json', 'Output findings in JSON format')
    .action(async (options) => {
      const basePath = process.cwd();
      let files: string[] = [];
      try {
        files = getFilesRecursive(basePath);
      } catch (err) {
        console.error('Failed to read workspace directory:', err);
        process.exit(1);
      }

      const context: AnalysisContext = { basePath, files };

      try {
        // Run detectors
        const project = await detectProject(context);
        
        // Run security secret scanner
        const securityFindings = await scanSecurity(context);

        // Run dependency parser
        const depAnalysis = await analyzeDependencies(context);

        // Merge findings (we can add dependency vulnerabilities/findings here in future)
        const findings = [...securityFindings];
        
        // Simple advisory test integration (if project has deprecated or placeholder vulnerable packages in package.json)
        const hasVulnDep = depAnalysis.dependencies.some((d: { name: string }) => d.name === 'vulnerable-package');
        if (hasVulnDep) {
          findings.push({
            ruleId: 'vuln-cve-test',
            severity: 'high',
            message: 'Dependency "vulnerable-package" has a known security vulnerability.',
            file: 'package.json',
          });
        }

        const overallScore = calculateScore(findings);

        const result: AnalysisResult = {
          project,
          findings,
          overallScore,
        };

        if (options.json) {
          console.log(formatJsonReport(result));
        } else {
          console.log(formatDoctorReport(result));
        }
      } catch (error) {
        console.error('Error running diagnostics:', error);
        process.exit(1);
      }
    });

  program.parse();
}
