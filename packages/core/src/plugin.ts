/**
 * Pluggable contract for detectors, analyzers, and remediation planners.
 */
import type { AnalysisContext, Finding, ProjectInfo } from './index.js';

export interface DetectorPlugin {
  name: string;
  detect(context: AnalysisContext): Promise<ProjectInfo>;
}

export interface AnalyzerPlugin {
  name: string;
  analyze(context: AnalysisContext): Promise<Finding[]>;
}

export interface RemediationPlugin {
  name: string;
  canPlan(finding: Finding): boolean;
  plan(finding: Finding, context: AnalysisContext): Promise<unknown>;
}

export class PluginRegistry {
  private static instance: PluginRegistry;
  private detectors: DetectorPlugin[] = [];
  private analyzers: AnalyzerPlugin[] = [];
  private remediationPlugins: RemediationPlugin[] = [];

  private constructor() {}

  public static getInstance(): PluginRegistry {
    if (!PluginRegistry.instance) {
      PluginRegistry.instance = new PluginRegistry();
    }
    return PluginRegistry.instance;
  }

  public registerDetector(detector: DetectorPlugin): void {
    this.detectors.push(detector);
  }

  public registerAnalyzer(analyzer: AnalyzerPlugin): void {
    this.analyzers.push(analyzer);
  }

  public registerRemediation(plugin: RemediationPlugin): void {
    this.remediationPlugins.push(plugin);
  }

  public getDetectors(): DetectorPlugin[] {
    return this.detectors;
  }

  public getAnalyzers(): AnalyzerPlugin[] {
    return this.analyzers;
  }

  public getRemediationPlugins(): RemediationPlugin[] {
    return this.remediationPlugins;
  }

  public clear(): void {
    this.detectors = [];
    this.analyzers = [];
    this.remediationPlugins = [];
  }
}
