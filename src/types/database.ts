// Database types for vulnerability patterns and CVE data
import { SeverityLevel, VulnerabilityType } from './index';
import { VulnerabilityPattern, VulnerabilityRule } from './vulnerability';

export interface VulnerabilityDatabase {
  version: string;
  lastUpdated: Date;
  patterns: VulnerabilityPattern[];
  rules: VulnerabilityRule[];
  cveReferences: CVEDatabase;
  metadata: DatabaseMetadata;
}

export interface CVEDatabase {
  version: string;
  lastUpdated: Date;
  entries: CVEEntry[];
  sources: CVESource[];
  statistics: CVEStatistics;
}

export interface CVEEntry {
  id: string; // CVE-YYYY-NNNN format
  description: string;
  severity: SeverityLevel;
  score: number; // CVSS score
  vector?: string; // CVSS vector string
  published: Date;
  modified: Date;
  references: string[];
  affectedProducts: AffectedProduct[];
  weaknesses: CWEReference[];
  exploitability: ExploitabilityInfo;
  impact: ImpactInfo;
}

export interface CVESource {
  name: string;
  url: string;
  lastSync: Date;
  status: 'active' | 'inactive' | 'error';
  errorMessage?: string;
}

export interface CVEStatistics {
  totalEntries: number;
  severityBreakdown: Record<SeverityLevel, number>;
  recentEntries: number; // entries from last 30 days
  averageScore: number;
  topAffectedProducts: ProductStatistic[];
}

export interface AffectedProduct {
  vendor: string;
  product: string;
  versions: VersionRange[];
  platforms?: string[];
}

export interface VersionRange {
  startIncluding?: string;
  startExcluding?: string;
  endIncluding?: string;
  endExcluding?: string;
  versionType?: string;
}

export interface CWEReference {
  id: string; // CWE-NNN format
  name: string;
  description: string;
  category: string;
}

export interface ExploitabilityInfo {
  attackVector: 'network' | 'adjacent' | 'local' | 'physical';
  attackComplexity: 'low' | 'high';
  privilegesRequired: 'none' | 'low' | 'high';
  userInteraction: 'none' | 'required';
  scope: 'unchanged' | 'changed';
}

export interface ImpactInfo {
  confidentialityImpact: 'none' | 'low' | 'high';
  integrityImpact: 'none' | 'low' | 'high';
  availabilityImpact: 'none' | 'low' | 'high';
}

export interface ProductStatistic {
  vendor: string;
  product: string;
  vulnerabilityCount: number;
  averageSeverity: number;
}

export interface DatabaseMetadata {
  createdAt: Date;
  updatedAt: Date;
  version: string;
  sources: DataSource[];
  statistics: DatabaseStatistics;
  integrity: IntegrityInfo;
}

export interface DataSource {
  name: string;
  type: 'cve' | 'pattern' | 'rule' | 'custom';
  url?: string;
  version?: string;
  lastSync: Date;
  entryCount: number;
}

export interface DatabaseStatistics {
  totalPatterns: number;
  totalRules: number;
  totalCVEs: number;
  patternsByLanguage: Record<string, number>;
  patternsBySeverity: Record<SeverityLevel, number>;
  patternsByType: Record<VulnerabilityType, number>;
  rulesByStatus: Record<string, number>;
}

export interface IntegrityInfo {
  checksum: string;
  algorithm: 'sha256' | 'sha512' | 'md5';
  verified: boolean;
  lastVerification: Date;
}

// Pattern database operations
export interface PatternDatabase {
  addPattern(pattern: VulnerabilityPattern): Promise<void>;
  updatePattern(id: string, updates: Partial<VulnerabilityPattern>): Promise<void>;
  removePattern(id: string): Promise<void>;
  getPattern(id: string): Promise<VulnerabilityPattern | null>;
  getPatternsByLanguage(language: string): Promise<VulnerabilityPattern[]>;
  getPatternsBySeverity(severity: SeverityLevel): Promise<VulnerabilityPattern[]>;
  getPatternsByType(type: VulnerabilityType): Promise<VulnerabilityPattern[]>;
  searchPatterns(query: PatternQuery): Promise<VulnerabilityPattern[]>;
  validatePattern(pattern: VulnerabilityPattern): Promise<ValidationResult>;
}

export interface PatternQuery {
  language?: string;
  severity?: SeverityLevel;
  type?: VulnerabilityType;
  tags?: string[];
  keywords?: string[];
  limit?: number;
  offset?: number;
  sortBy?: 'name' | 'severity' | 'type' | 'created' | 'updated';
  sortOrder?: 'asc' | 'desc';
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
}

export interface ValidationError {
  field: string;
  message: string;
  code: string;
}

export interface ValidationWarning {
  field: string;
  message: string;
  code: string;
}

// Rule database operations
export interface RuleDatabase {
  addRule(rule: VulnerabilityRule): Promise<void>;
  updateRule(id: string, updates: Partial<VulnerabilityRule>): Promise<void>;
  removeRule(id: string): Promise<void>;
  getRule(id: string): Promise<VulnerabilityRule | null>;
  getEnabledRules(): Promise<VulnerabilityRule[]>;
  getDisabledRules(): Promise<VulnerabilityRule[]>;
  enableRule(id: string): Promise<void>;
  disableRule(id: string): Promise<void>;
  searchRules(query: RuleQuery): Promise<VulnerabilityRule[]>;
}

export interface RuleQuery {
  enabled?: boolean;
  patternId?: string;
  confidence?: number;
  limit?: number;
  offset?: number;
}

// CVE database operations
export interface CVEDatabaseOperations {
  addCVE(cve: CVEEntry): Promise<void>;
  updateCVE(id: string, updates: Partial<CVEEntry>): Promise<void>;
  getCVE(id: string): Promise<CVEEntry | null>;
  searchCVEs(query: CVEQuery): Promise<CVEEntry[]>;
  getCVEsBySeverity(severity: SeverityLevel): Promise<CVEEntry[]>;
  getCVEsByProduct(vendor: string, product: string): Promise<CVEEntry[]>;
  getRecentCVEs(days?: number): Promise<CVEEntry[]>;
  syncCVEDatabase(sources: CVESource[]): Promise<SyncResult>;
}

export interface CVEQuery {
  keywords?: string[];
  severity?: SeverityLevel;
  scoreRange?: { min: number; max: number };
  dateRange?: { start: Date; end: Date };
  vendor?: string;
  product?: string;
  cweIds?: string[];
  limit?: number;
  offset?: number;
}

export interface SyncResult {
  success: boolean;
  added: number;
  updated: number;
  errors: SyncError[];
  duration: number; // in milliseconds
}

export interface SyncError {
  source: string;
  message: string;
  cveId?: string;
  timestamp: Date;
}

// Database configuration
export interface DatabaseConfig {
  type: 'sqlite' | 'postgresql' | 'mysql' | 'memory';
  connectionString?: string;
  host?: string;
  port?: number;
  database?: string;
  username?: string;
  password?: string;
  ssl?: boolean;
  poolSize?: number;
  timeout?: number;
  backupConfig?: BackupConfig;
  syncConfig?: SyncConfig;
}

export interface BackupConfig {
  enabled: boolean;
  schedule: string; // cron expression
  location: string;
  retention: number; // days
  compression: boolean;
  encryption?: EncryptionConfig;
}

export interface EncryptionConfig {
  enabled: boolean;
  algorithm: 'aes-256-gcm' | 'aes-256-cbc';
  keyPath: string;
  rotationSchedule?: string; // cron expression
}

export interface SyncConfig {
  enabled: boolean;
  schedule: string; // cron expression
  sources: CVESource[];
  retryAttempts: number;
  retryDelay: number; // in milliseconds
  timeout: number; // in milliseconds
}

// Cache configuration
export interface CacheConfig {
  enabled: boolean;
  type: 'memory' | 'redis' | 'memcached';
  host?: string;
  port?: number;
  ttl: number; // time to live in seconds
  maxSize?: number;
  evictionPolicy?: 'lru' | 'fifo' | 'random';
}

// Database factory and manager
export interface DatabaseManager {
  initialize(config: DatabaseConfig): Promise<void>;
  getPatternDatabase(): PatternDatabase;
  getRuleDatabase(): RuleDatabase;
  getCVEDatabase(): CVEDatabaseOperations;
  backup(): Promise<void>;
  restore(backupPath: string): Promise<void>;
  vacuum(): Promise<void>;
  getStatistics(): Promise<DatabaseStatistics>;
  healthCheck(): Promise<HealthCheckResult>;
  close(): Promise<void>;
}

export interface HealthCheckResult {
  healthy: boolean;
  checks: {
    database: boolean;
    patterns: boolean;
    rules: boolean;
    cves: boolean;
    cache?: boolean;
  };
  responseTime: number;
  lastUpdated: Date;
  errors?: string[];
}

// Migration system
export interface DatabaseMigration {
  version: string;
  description: string;
  up: () => Promise<void>;
  down: () => Promise<void>;
  checksum?: string;
}

export interface MigrationManager {
  getCurrentVersion(): Promise<string>;
  getPendingMigrations(): Promise<DatabaseMigration[]>;
  runMigrations(): Promise<MigrationResult[]>;
  rollbackMigration(version: string): Promise<void>;
  addMigration(migration: DatabaseMigration): void;
}

export interface MigrationResult {
  version: string;
  success: boolean;
  duration: number;
  error?: string;
}
