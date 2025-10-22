// Core type definitions for MCP Security Scanner
// Security-focused type system with comprehensive vulnerability detection

export * from './vulnerability';
export * from './scan';
export * from './report';
export * from './mcp';
// Note: sandbox, database, and language types excluded to resolve import conflicts

// Core enums and constants
export enum SeverityLevel {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info',
}

export enum VulnerabilityType {
  COMMAND_INJECTION = 'command_injection',
  PATH_TRAVERSAL = 'path_traversal',
  PROMPT_INJECTION = 'prompt_injection',
  TOOL_POISONING = 'tool_poisoning',
  OAUTH_VULNERABILITY = 'oauth_vulnerability',
  DATA_EXFILTRATION = 'data_exfiltration',
  RESOURCE_EXHAUSTION = 'resource_exhaustion',
  CONFIGURATION_ERROR = 'configuration_error',
  INSECURE_TRANSPORT = 'insecure_transport',
  AUTHENTICATION_BYPASS = 'authentication_bypass',
}

export enum AnalysisType {
  STATIC = 'static',
  DYNAMIC = 'dynamic',
  HYBRID = 'hybrid',
}

export enum ScanStatus {
  PENDING = 'pending',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled',
}

export enum ReportFormat {
  JSON = 'json',
  SARIF = 'sarif',
  HTML = 'html',
  XML = 'xml',
  CSV = 'csv',
  MARKDOWN = 'markdown',
}

export enum LanguageType {
  TYPESCRIPT = 'typescript',
  JAVASCRIPT = 'javascript',
  PYTHON = 'python',
  GO = 'go',
  RUST = 'rust',
  DOCKERFILE = 'dockerfile',
  YAML = 'yaml',
  JSON = 'json',
}

// Severity scoring based on CVSS v3.1
export const SEVERITY_SCORES = {
  [SeverityLevel.CRITICAL]: { min: 9.0, max: 10.0 },
  [SeverityLevel.HIGH]: { min: 7.0, max: 8.9 },
  [SeverityLevel.MEDIUM]: { min: 4.0, max: 6.9 },
  [SeverityLevel.LOW]: { min: 0.1, max: 3.9 },
  [SeverityLevel.INFO]: { min: 0.0, max: 0.0 },
} as const;

// Common utility types
export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;
export type RequiredFields<T, K extends keyof T> = T & Required<Pick<T, K>>;
export type DeepReadonly<T> = {
  readonly [P in keyof T]: T[P] extends object ? DeepReadonly<T[P]> : T[P];
};

// Error handling types
export interface SecurityError extends Error {
  code: string;
  severity: SeverityLevel;
  context?: Record<string, unknown>;
}

export interface ValidationError extends SecurityError {
  field: string;
  value: unknown;
  constraint: string;
}
