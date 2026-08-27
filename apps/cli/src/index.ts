import * as fs from 'node:fs';
import * as path from 'node:path';
import { Command } from 'commander';
import { AnalysisContext, AnalysisResult, Finding, EXIT_CODES, PipelineResult, PluginRegistry, runAnalysisPipeline, DepMetrics, AdvisoryInfo } from '@devfoundry/core';
import { detectProject } from '@devfoundry/detector';
import { scanSecurity } from '@devfoundry/security';
import {
  analyzeDependencies,
  scanWithAdvisories,
  NoOpAdvisoryProvider,
  OsvAdvisoryProvider,
  DependencyAdvisoryProvider,
} from '@devfoundry/dependencies';
import { buildRemediationPlan } from '@devfoundry/remediation';
import {
  verifyFindings,
  readBaseline,
  createBaseline,
  writeBaseline,
  clearBaseline,
  mapBaselineToFinding,
} from '@devfoundry/verification';
import {
  formatDoctorReport,
  formatJsonReport,
  formatFixReport,
  formatFixJsonReport,
  formatVerifyReport,
  formatVerifyJsonReport,
  formatCiReport,
  formatCiJsonReport,
  formatScanReport,
  formatScanJsonReport,
} from '@devfoundry/reporter';
import { evaluatePolicy } from '@devfoundry/policy';
import {
  GitChangedFileSet,
  generateAnnotations,
  printGitHubAnnotations,
  generateSummaryMarkdown,
  writeGitHubStepSummary,
} from '@devfoundry/integrations-github';


const IGNORED_DIRS = ['.git', 'node_modules', 'dist', 'build', 'coverage'];
const TEST_DIRS = ['tests', 'test', '__tests__', 'fixtures', '__fixtures__'];

function getFilesRecursive(dir: string, baseDir = dir, strict = false): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(baseDir, fullPath).replace(/\\/g, '/');

    if (entry.isDirectory()) {
      if (IGNORED_DIRS.includes(entry.name)) continue;
      if (!strict && TEST_DIRS.includes(entry.name)) continue;
      try {
        files.push(...getFilesRecursive(fullPath, baseDir, strict));
      } catch {
        // Skip unreadable directories
      }
    } else {
      files.push(relPath);
    }
  }

  return files;
}

/**
 * Shared analysis orchestrator using the core AnalysisPipeline.
 */
async function executeScan(
  basePath: string,
  strict: boolean,
  offline: boolean,
  previousFindings?: Finding[],
  depsOnly = false,
): Promise<PipelineResult> {
  const provider: DependencyAdvisoryProvider = offline
    ? new NoOpAdvisoryProvider()
    : new OsvAdvisoryProvider();

  // Initialize and setup the plugin registry
  const registry = PluginRegistry.getInstance();
  registry.clear();

  if (!depsOnly) {
    registry.registerDetector({
      name: 'detector',
      detect: (ctx: AnalysisContext) => detectProject(ctx),
    });

    registry.registerAnalyzer({
      name: 'security',
      analyze: (ctx: AnalysisContext) => scanSecurity(ctx),
    });
  }

  let depMetrics: DepMetrics | undefined = undefined;
  let advisoryInfo: AdvisoryInfo = { provider: 'none', status: 'not_checked' };

  registry.registerAnalyzer({
    name: 'dependencies',
    analyze: async (ctx: AnalysisContext) => {
      const depAnalysis = await analyzeDependencies(ctx);
      depMetrics = depAnalysis.metrics;
      const { findings, advisoryInfo: adv } = await scanWithAdvisories(depAnalysis, provider);
      advisoryInfo = adv;
      if (depMetrics) {
        depMetrics.vulnerable = findings.length;
      }
      return findings;
    },
  });

  // Collect files
  let files: string[] = [];
  try {
    files = getFilesRecursive(basePath, basePath, strict);
  } catch (err) {
    console.error('Failed to read workspace directory:', err);
    process.exit(EXIT_CODES.ANALYSIS_ERROR);
  }

  // Execute pipeline
  const result = await runAnalysisPipeline({
    basePath,
    files,
    strict,
    offline,
    previousFindings,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    verifyFindings: (prev, curr, adv) => verifyFindings(prev, curr, adv as any),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    evaluatePolicy: (v) => evaluatePolicy(v as any),
    advisoryInfo,
  });

  if (depMetrics) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    result.dependencies = { metrics: depMetrics as any };
  }
  result.advisories = advisoryInfo;

  return result;
}

export function runCLI(): void {
  const program = new Command();

  program
    .name('foundry')
    .description('DevFoundry CLI')
    .version('0.1.7');

  program
    .command('doctor')
    .description('Run project doctor diagnostics')
    .option('--strict', 'Scan all files including test and fixture folders')
    .option('--json', 'Output findings in stable machine-readable JSON format')
    .option('--dependencies', 'Run dependency analysis only (skip security and project detection)')
    .option('--offline', 'Skip network advisory checks. Vulnerability status will be reported as Not checked.')
    .addHelpText('after', `
Examples:
  foundry doctor                       # Full scan (security + OSV dependency advisories)
  foundry doctor --offline             # Full scan, skip advisory network check
  foundry doctor --strict              # Scan test and fixture files too
  foundry doctor --dependencies        # Dependency analysis + OSV advisories
  foundry doctor --dependencies --offline # Dependency analysis, skip advisories
  foundry doctor --json                # Output findings in JSON format (includes advisoryInfo)
  foundry doctor --strict --json       # Scan all files and output JSON format

Advisory Providers:
  Default:  OSV (osv.dev) — public vulnerability database, no API key required
  Offline:  None — use --offline to skip network checks

Privacy:
  Only package name, version, and ecosystem are sent to OSV.
  Source files, secrets, and environment variables are never transmitted.
`)
    .action(async (options) => {
      const basePath = process.cwd();
      const strict = !!options.strict;
      const depsOnly = !!options.dependencies;
      const offline = !!options.offline;

      try {
        const result = await executeScan(basePath, strict, offline, undefined, depsOnly);

        const analysisResult: AnalysisResult = {
          project: depsOnly
            ? { type: 'Unknown', frameworks: [], packageManager: result.dependencies?.metrics?.packageManager as string | undefined }
            : result.project,
          findings: result.findings,
          overallScore: result.score.overallHealth,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          depMetrics: result.dependencies?.metrics as any,
          advisoryInfo: result.advisories,
        };

        if (options.json) {
          console.log(formatJsonReport(analysisResult));
        } else {
          console.log(formatDoctorReport(analysisResult, strict));
        }
        process.exit(EXIT_CODES.SUCCESS);
      } catch (error) {
        console.error('Error running diagnostics:', error);
        process.exit(EXIT_CODES.ANALYSIS_ERROR);
      }
    });

  // ---------------------------------------------------------------------------
  // foundry scan
  // ---------------------------------------------------------------------------

  program
    .command('scan')
    .description('Run complete codebase analysis pipeline')
    .option('--strict', 'Scan all files including test and fixture folders')
    .option('--offline', 'Skip network advisory checks when analyzing dependencies')
    .option('--json', 'Output scan result as stable versioned JSON')
    .action(async (options) => {
      const basePath = process.cwd();
      const strict = !!options.strict;
      const offline = !!options.offline;

      // Automatically check for baseline.json
      let previousFindings: Finding[] = [];
      const baseline = readBaseline(basePath);
      if (baseline) {
        previousFindings = baseline.findings.map(mapBaselineToFinding);
      }

      try {
        const result = await executeScan(basePath, strict, offline, previousFindings);

        if (options.json) {
          console.log(formatScanJsonReport(result));
        } else {
          console.log(formatScanReport(result));
        }
        process.exit(EXIT_CODES.SUCCESS);
      } catch (error) {
        console.error('Error running scan:', error);
        process.exit(EXIT_CODES.ANALYSIS_ERROR);
      }
    });

  // ---------------------------------------------------------------------------
  // foundry fix
  // ---------------------------------------------------------------------------

  program
    .command('fix')
    .description('Build a remediation plan for detected findings (does not modify files)')
    .option('--strict', 'Scan all files including test and fixture folders')
    .option('--offline', 'Skip network advisory checks when analyzing dependencies')
    .option('--json', 'Output remediation plan as stable machine-readable JSON')
    .option('--details', 'Show expanded guidance, steps, and automation notes')
    .addHelpText('after', `
Examples:
  foundry fix                  # Show available remediation actions
  foundry fix --details        # Show full guidance steps for each action
  foundry fix --json           # Machine-readable remediation plan
  foundry fix --offline        # Analyze without OSV network call
  foundry fix --strict         # Include test/fixture files in analysis

Safety:
  foundry fix NEVER modifies files automatically.
  Every action requires explicit user confirmation before any future apply.
  Credentials are never rotated or exposed automatically.
`)
    .action(async (options) => {
      const basePath = process.cwd();
      const strict = !!options.strict;
      const offline = !!options.offline;
      const details = !!options.details;

      try {
        const result = await executeScan(basePath, strict, offline);

        const analysisResult: AnalysisResult = {
          project: result.project,
          findings: result.findings,
          overallScore: result.score.overallHealth,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          depMetrics: result.dependencies?.metrics as any,
          advisoryInfo: result.advisories,
        };

        // Build remediation plan (no file modifications)
        const plan = buildRemediationPlan(analysisResult, result.project.packageManager);

        if (options.json) {
          console.log(formatFixJsonReport(plan));
        } else {
          console.log(formatFixReport(plan, details));
        }
        process.exit(EXIT_CODES.SUCCESS);
      } catch (error) {
        console.error('Error building remediation plan:', error);
        process.exit(EXIT_CODES.ANALYSIS_ERROR);
      }
    });

  // ---------------------------------------------------------------------------
  // foundry verify
  // ---------------------------------------------------------------------------

  program
    .command('verify')
    .description('Verify whether previously detected findings have been resolved')
    .option('--previous <path>', 'Path to a JSON file containing previous findings or AnalysisResult')
    .option('--strict', 'Scan all files including test and fixture folders')
    .option('--offline', 'Skip network advisory checks when analyzing dependencies')
    .option('--json', 'Output verification result as stable machine-readable JSON')
    .action(async (options) => {
      const basePath = process.cwd();
      const strict = !!options.strict;
      const offline = !!options.offline;

      // 1. Read previous findings
      let previousFindings: Finding[] = [];
      if (options.previous) {
        const fullPath = path.resolve(basePath, options.previous);
        if (!fs.existsSync(fullPath)) {
          console.error(`Error: Previous findings file not found at ${fullPath}`);
          process.exit(EXIT_CODES.INVALID_CONFIG);
        }
        try {
          const content = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
          if (Array.isArray(content)) {
            previousFindings = content;
          } else if (content && Array.isArray(content.findings)) {
            previousFindings = content.findings;
          } else {
            console.error('Error: Previous findings JSON must be a findings array or an AnalysisResult object.');
            process.exit(EXIT_CODES.INVALID_CONFIG);
          }
        } catch (err) {
          console.error(`Error parsing previous findings file: ${err instanceof Error ? err.message : err}`);
          process.exit(EXIT_CODES.INVALID_CONFIG);
        }
      } else {
        // Automatically check for baseline.json
        const baseline = readBaseline(basePath);
        if (baseline) {
          previousFindings = baseline.findings.map(mapBaselineToFinding);
        }
      }

      try {
        const result = await executeScan(basePath, strict, offline, previousFindings);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const verificationResult = result.baseline as any;

        if (options.json) {
          console.log(formatVerifyJsonReport(verificationResult));
        } else {
          console.log(formatVerifyReport(verificationResult));
        }

        // Exit with 1 if verification did not pass completely (failed or partial)
        if (verificationResult.status !== 'passed') {
          process.exit(EXIT_CODES.POLICY_VIOLATION);
        }
        process.exit(EXIT_CODES.SUCCESS);
      } catch (error) {
        console.error('Error running verification:', error);
        process.exit(EXIT_CODES.ANALYSIS_ERROR);
      }
    });

  // ---------------------------------------------------------------------------
  // foundry baseline
  // ---------------------------------------------------------------------------

  const baselineCmd = program
    .command('baseline')
    .description('Manage codebase baseline/snapshot');

  baselineCmd
    .command('create')
    .description('Run analysis and save codebase baseline to .devfoundry/baseline.json')
    .option('--strict', 'Scan all files including test and fixture folders')
    .option('--offline', 'Skip network advisory checks when analyzing dependencies')
    .action(async (options) => {
      const basePath = process.cwd();
      const strict = !!options.strict;
      const offline = !!options.offline;

      try {
        const result = await executeScan(basePath, strict, offline);

        const baseline = createBaseline(
          result.findings,
          result.project,
          result.advisories,
          '0.2.0' // Tool version
        );

        writeBaseline(basePath, baseline);
        console.log(`✓ Baseline created at .devfoundry/baseline.json (${result.findings.length} finding(s) saved)`);
        process.exit(EXIT_CODES.SUCCESS);
      } catch (error) {
        console.error('Error creating baseline:', error);
        process.exit(EXIT_CODES.ANALYSIS_ERROR);
      }
    });

  baselineCmd
    .command('show')
    .description('Display information about the currently saved baseline')
    .action(async () => {
      const basePath = process.cwd();
      const baseline = readBaseline(basePath);

      if (!baseline) {
        console.log('No baseline found. Run "foundry baseline create" to create one.');
        process.exit(0);
      }

      const createdDate = baseline.createdAt ? baseline.createdAt.split('T')[0] : 'Unknown';
      const securityCount = baseline.findings.filter(f => f.category === 'security').length;
      const dependencyCount = baseline.findings.filter(
        f => f.category === 'dependencies' || f.ruleId.startsWith('vuln-')
      ).length;

      console.log('╭──────────────────────────────────────╮');
      console.log('│          DEVFOUNDRY BASELINE         │');
      console.log('╰──────────────────────────────────────╯');
      console.log('');
      console.log(`Created       ${createdDate}`);
      console.log(`Tool version  ${baseline.toolVersion}`);
      console.log('');
      console.log(`Findings      ${baseline.findings.length}`);
      console.log(`  Security    ${securityCount}`);
      console.log(`  Dependencies ${dependencyCount}`);
      console.log('');
      console.log('Advisories');
      console.log(`  ${baseline.advisories.provider === 'osv' ? 'OSV' : baseline.advisories.provider === 'none' ? 'None' : baseline.advisories.provider}`);
      console.log(`  ${baseline.advisories.status === 'ok' ? '✓ Checked' : baseline.advisories.status === 'unavailable' ? '✗ Unavailable' : '— Not checked'}`);

      process.exit(0);
    });

  baselineCmd
    .command('clear')
    .description('Remove the saved baseline file')
    .action(async () => {
      const basePath = process.cwd();
      const cleared = clearBaseline(basePath);
      if (cleared) {
        console.log('Baseline cleared.');
      } else {
        console.log('No baseline file found to clear.');
      }
      process.exit(0);
    });

  // ---------------------------------------------------------------------------
  // foundry ci
  // ---------------------------------------------------------------------------

  program
    .command('ci')
    .description('Run codebase analysis and evaluate CI policies against baseline')
    .option('--strict', 'Scan all files including test and fixture folders')
    .option('--offline', 'Skip network advisory checks when analyzing dependencies')
    .option('--json', 'Output stable machine-readable CI result JSON')
    .option('--github', 'Enable GitHub Actions annotations and job summary output')
    .action(async (options) => {
      const basePath = process.cwd();
      const strict = !!options.strict;
      const offline = !!options.offline;
      const github = !!options.github;

      // 1. Automatically load baseline.json if available
      let previousFindings: Finding[] = [];
      const baseline = readBaseline(basePath);
      if (baseline) {
        previousFindings = baseline.findings.map(mapBaselineToFinding);
      }

      try {
        const result = await executeScan(basePath, strict, offline, previousFindings);

        // 3. Changed File Awareness: Expose status on each finding
        const changedFiles = new GitChangedFileSet(basePath);
        for (const f of result.findings) {
          f.fileStatus = changedFiles.status(f.file);
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const verificationResult = result.baseline as any;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const policyResult = result.policy as any;

        // Determine exit status: SUCCESS (0) or POLICY_VIOLATION (1)
        const exitCode = policyResult.passed ? EXIT_CODES.SUCCESS : EXIT_CODES.POLICY_VIOLATION;

        if (options.json) {
          console.log(formatCiJsonReport(policyResult, verificationResult, exitCode));
        } else {
          console.log(formatCiReport(policyResult, verificationResult));
        }

        // 4. GitHub integration mode
        if (github) {
          if (process.env.GITHUB_ACTIONS === 'true') {
            const annotations = generateAnnotations(verificationResult);
            printGitHubAnnotations(annotations);

            const summaryMarkdown = generateSummaryMarkdown(policyResult, verificationResult);
            writeGitHubStepSummary(summaryMarkdown);
          } else {
            console.log('GitHub Actions integration is enabled, but GITHUB_ACTIONS environment variable is not true.');
            console.log('Annotations and job summary generation skipped.');
          }
        }

        process.exit(exitCode);
      } catch (error) {
        console.error('Error running CI policy evaluation:', error);
        process.exit(EXIT_CODES.ANALYSIS_ERROR);
      }
    });

  program.parse();
}
