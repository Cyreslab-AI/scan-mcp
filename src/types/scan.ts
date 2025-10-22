// Scan configuration and result types for MCP Security Scanner
import { AnalysisType, LanguageType, ScanStatus, SeverityLevel } from './index';
import { Vulnerability } from './vulnerability';
import { ASTNode, LanguageAST, SourceLocation } from './language';

// Re-export types that are used by other modules
export { ASTNode, LanguageAST, SourceLocation };

export interface ScanOptions {
  analysisType: AnalysisType;
  targetLanguages: LanguageType[];
  includePaths: string[];
  excludePaths: string[];
  maxDepth: number;
  timeout: number; // in milliseconds
  concurrent: boolean;
  maxConcurrency: number;
  enableDynamicAnalysis: boolean;
  enableStaticAnalysis: boolean;
  severityThreshold: SeverityLevel;
  customRules?: string[];
  sandboxConfig?: SandboxScanConfig;
  reportConfig?: ReportConfig;
}

export interface SandboxScanConfig {
  enabled: boolean;
  timeout: number;
  memoryLimit: string; // e.g., '512m'
  cpuLimit: string; // e.g., '0.5'
  networkAccess: boolean;
  fileSystemAccess: 'none' | 'read' | 'readwrite';
  allowedDomains?: string[];
  blockedDomains?: string[];
}

export interface ReportConfig {
  includeExploitProofs: boolean;
  includeRemediation: boolean;
  includeCVEReferences: boolean;
  includeCodeSnippets: boolean;
  confidenceThreshold: number;
  outputPath?: string;
  templatePath?: string;
}

export interface ScanTarget {
  type: 'file' | 'directory' | 'url' | 'repository';
  path: string;
  language?: LanguageType;
  metadata?: Record<string, unknown>;
}

export interface ScanProgress {
  scanId: string;
  status: ScanStatus;
  startTime: Date;
  endTime?: Date;
  progress: number; // 0-100
  currentPhase: string;
  totalFiles: number;
  processedFiles: number;
  vulnerabilitiesFound: number;
  errors: ScanError[];
}

export interface ScanError {
  type: 'parse' | 'analysis' | 'sandbox' | 'io' | 'timeout';
  message: string;
  file?: string;
  line?: number;
  severity: 'warning' | 'error' | 'fatal';
  timestamp: Date;
  stack?: string;
}

export interface ScanResult {
  scanId: string;
  targetInfo: ScanTargetInfo;
  scanOptions: ScanOptions;
  progress: ScanProgress;
  vulnerabilities: Vulnerability[];
  summary: ScanSummary;
  metadata: ScanMetadata;
  generatedAt: Date;
}

export interface ScanTargetInfo {
  targets: ScanTarget[];
  totalFiles: number;
  totalLines: number;
  languageBreakdown: Record<LanguageType, number>;
  dependencies: DependencyInfo[];
  mcpConfig?: McpServerInfo;
}

export interface DependencyInfo {
  name: string;
  version: string;
  source: 'npm' | 'pip' | 'cargo' | 'go.mod' | 'unknown';
  vulnerabilities?: string[]; // CVE IDs
  outdated: boolean;
  license?: string;
}

export interface McpServerInfo {
  name?: string;
  version?: string;
  transport: 'stdio' | 'http';
  capabilities: string[];
  tools: McpToolInfo[];
  resources: McpResourceInfo[];
}

export interface McpToolInfo {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
  dangerous: boolean;
  securityRisk: SeverityLevel;
}

export interface McpResourceInfo {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
  securityRisk: SeverityLevel;
}

export interface ScanSummary {
  totalVulnerabilities: number;
  vulnerabilityBreakdown: Record<SeverityLevel, number>;
  typeBreakdown: Record<string, number>;
  riskScore: number; // 0-100
  confidence: number; // 0-1
  falsePositiveEstimate: number; // 0-1
  recommendedActions: string[];
}

export interface ScanMetadata {
  scannerVersion: string;
  scanDuration: number; // milliseconds
  rulesVersion: string;
  environment: {
    nodeVersion: string;
    platform: string;
    architecture: string;
  };
  performance: {
    memoryUsage: number;
    cpuUsage: number;
    filesPerSecond: number;
  };
}

export interface StaticAnalysisResult {
  ast: Record<string, unknown>;
  symbols: SymbolTable;
  dependencies: DependencyInfo[];
  vulnerabilities: Vulnerability[];
  metrics: CodeMetrics;
}

export interface SymbolTable {
  functions: FunctionSymbol[];
  classes: ClassSymbol[];
  variables: VariableSymbol[];
  imports: ImportSymbol[];
  exports: ExportSymbol[];
}

export interface SymbolExtraction {
  functions: FunctionSymbol[];
  classes: ClassSymbol[];
  variables: VariableSymbol[];
  imports: ImportSymbol[];
  exports: ExportSymbol[];
}

export interface FunctionSymbol {
  name: string;
  parameters: Parameter[];
  returnType?: string;
  location: { line: number; column: number };
  visibility: 'public' | 'private' | 'protected';
  async: boolean;
  generator: boolean;
}

export interface Parameter {
  name: string;
  type?: string;
  optional: boolean;
  defaultValue?: unknown;
}

export interface ClassSymbol {
  name: string;
  superClass?: string;
  interfaces: string[];
  methods: FunctionSymbol[];
  properties: PropertySymbol[];
  location: { line: number; column: number };
}

export interface PropertySymbol {
  name: string;
  type?: string;
  visibility: 'public' | 'private' | 'protected';
  static: boolean;
  readonly: boolean;
}

export interface VariableSymbol {
  name: string;
  type?: string;
  scope: 'global' | 'local' | 'parameter';
  mutable: boolean;
  location: { line: number; column: number };
}

export interface ImportSymbol {
  module: string;
  imports: string[];
  namespace?: string;
  location: { line: number; column: number };
}

export interface ExportSymbol {
  name: string;
  type: 'function' | 'class' | 'variable' | 'default';
  location: { line: number; column: number };
}

export interface CodeMetrics {
  linesOfCode: number;
  complexity: number;
  maintainabilityIndex: number;
  testCoverage?: number;
  technicalDebt: number;
}

export interface DynamicAnalysisResult {
  executionTraces: ExecutionTrace[];
  networkCalls: NetworkCall[];
  fileSystemAccess: FileSystemAccess[];
  vulnerabilities: Vulnerability[];
  performance: PerformanceMetrics;
}

export interface ExecutionTrace {
  function: string;
  arguments: unknown[];
  returnValue: unknown;
  executionTime: number;
  memoryUsage: number;
  errors: Error[];
}

export interface NetworkCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
  response: {
    status: number;
    headers: Record<string, string>;
    body?: string;
  };
  timestamp: Date;
}

export interface FileSystemAccess {
  operation: 'read' | 'write' | 'delete' | 'execute';
  path: string;
  success: boolean;
  timestamp: Date;
  details?: string;
}

export interface PerformanceMetrics {
  executionTime: number;
  memoryPeak: number;
  cpuUsage: number;
  ioOperations: number;
  networkRequests: number;
}
