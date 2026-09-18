// Core security analyzer with static analysis engine
import * as esprima from 'esprima';
import { promises as fs } from 'fs';
import * as path from 'path';

import { 
  ScanOptions, 
  ScanResult, 
  ScanProgress,
  StaticAnalysisResult,
  ScanTargetInfo,
  ScanSummary,
  ScanMetadata,
  LanguageAST,
  ASTNode,
  SymbolExtraction 
} from '@/types/scan';
import { 
  Vulnerability,
  VulnerabilityPattern
} from '@/types/vulnerability';
import { 
  LanguageType, 
  SeverityLevel, 
  VulnerabilityType,
  AnalysisType,
  ScanStatus as ScanStatusEnum
} from '@/types';
import { vulnerabilityPatternDatabase } from '@/database/vulnerability-patterns';
import { cveMappingDatabase } from '@/database/cve-mappings';
import { VulnerabilityDetector } from '@/vulnerabilities/base';
import { commandInjectionDetector } from '@/vulnerabilities/command-injection';
import { pathTraversalDetector } from '@/vulnerabilities/path-traversal';
import { promptInjectionDetector } from '@/vulnerabilities/prompt-injection';
import { toolPoisoningDetector } from '@/vulnerabilities/tool-poisoning';
import { analyzeToolDescriptions } from '@/vulnerabilities/tool-description-poisoning';
import { detectSecrets } from '@/vulnerabilities/secrets';
import { dockerfileLinter } from '@/vulnerabilities/dockerfile-lint';
import { dependencyScanner } from '@/scanners/dependency-scanner';
import { scannerRegistry } from '@/scanners/base';
import { typeScriptScanner } from '@/scanners/typescript';
import { pythonScanner } from '@/scanners/python';
import { LanguageVulnerabilityPattern } from '@/types/language';

// Importing the scanners above registers them into `scannerRegistry` as a side effect; reference
// them so bundlers/linters don't consider the import "unused" if tree-shaken oddly.
void typeScriptScanner;
void pythonScanner;

export class SecurityAnalyzer {
  private patterns: Map<LanguageType, VulnerabilityPattern[]> = new Map();
  private scanProgress: Map<string, ScanProgress> = new Map();
  // Context-aware detectors (previously implemented but never invoked by the scan pipeline -
  // core.ts used only the flat regex pattern database below). These bring confidence scoring,
  // severity escalation, and false-positive-risk assessment based on surrounding code context.
  private readonly dedicatedDetectors: VulnerabilityDetector[] = [
    commandInjectionDetector,
    pathTraversalDetector,
    promptInjectionDetector,
    toolPoisoningDetector,
  ];
  // Vulnerability types fully handled by a dedicated detector/module above; the generic
  // pattern-database fallback below skips these to avoid duplicate/lower-quality findings for the
  // same issue. (A few entries - dockerfile/secrets/dependency ones - exist in the pattern
  // database purely so `get_vulnerability_patterns` can document them; actual detection for those
  // always goes through the dedicated modules, never this generic regex path.)
  private readonly typesWithDedicatedDetectors = new Set<VulnerabilityType>([
    VulnerabilityType.COMMAND_INJECTION,
    VulnerabilityType.PATH_TRAVERSAL,
    VulnerabilityType.PROMPT_INJECTION,
    VulnerabilityType.TOOL_POISONING,
    VulnerabilityType.DOCKERFILE_MISCONFIGURATION,
    VulnerabilityType.HARDCODED_SECRET,
    VulnerabilityType.DEPENDENCY_VULNERABILITY,
  ]);

  constructor() {
    this.initializePatterns();
  }

  private initializePatterns(): void {
    // Load patterns by language
    const allPatterns = vulnerabilityPatternDatabase.getAllPatterns();
    
    for (const pattern of allPatterns) {
      if (!this.patterns.has(pattern.language)) {
        this.patterns.set(pattern.language, []);
      }
      this.patterns.get(pattern.language)!.push(pattern);
    }
  }

  async scanServer(source: string, options: ScanOptions): Promise<ScanResult> {
    const scanId = this.generateScanId();
    const startTime = new Date();

    // Initialize scan progress
    const progress: ScanProgress = {
      scanId,
      status: ScanStatusEnum.RUNNING,
      startTime,
      progress: 0,
      currentPhase: 'Initialization',
      totalFiles: 0,
      processedFiles: 0,
      vulnerabilitiesFound: 0,
      errors: [],
    };

    this.scanProgress.set(scanId, progress);

    try {
      // Analyze target and collect file information
      progress.currentPhase = 'Target Analysis';
      const targetInfo = await this.analyzeTarget(source, options);
      progress.totalFiles = targetInfo.totalFiles;
      progress.progress = 10;

      // Perform static analysis if enabled
      let staticResults: StaticAnalysisResult[] = [];
      if (options.enableStaticAnalysis || options.analysisType !== AnalysisType.DYNAMIC) {
        progress.currentPhase = 'Static Analysis';
        staticResults = await this.performStaticAnalysis(targetInfo, options, progress);
        progress.progress = 70;
      }

      // Dependency vulnerability scanning (OSV.dev) - reads package.json/requirements.txt under
      // the scan target and checks every dependency against OSV's free, public database.
      progress.currentPhase = 'Dependency Scanning';
      const depScan = await dependencyScanner
        .scan(source, options.excludePaths, options.maxDepth)
        .catch((error): { dependencies: never[]; vulnerabilities: never[]; warnings: string[] } => ({
          dependencies: [],
          vulnerabilities: [],
          warnings: [`Dependency scan failed: ${error instanceof Error ? error.message : String(error)}`],
        }));
      targetInfo.dependencies = depScan.dependencies;
      for (const warning of depScan.warnings) {
        progress.errors.push({
          type: 'analysis',
          message: warning,
          severity: 'warning',
          timestamp: new Date(),
        });
      }
      progress.progress = 85;

      // Aggregate vulnerabilities
      progress.currentPhase = 'Aggregating Results';
      const allVulnerabilities = [
        ...staticResults.flatMap(result => result.vulnerabilities),
        ...depScan.vulnerabilities,
      ];
      progress.vulnerabilitiesFound = allVulnerabilities.length;
      progress.progress = 90;

      // Generate summary
      progress.currentPhase = 'Generating Summary';
      const summary = this.generateSummary(allVulnerabilities, targetInfo);
      const metadata = this.generateMetadata(startTime, targetInfo);
      
      // Complete scan
      progress.status = ScanStatusEnum.COMPLETED;
      progress.endTime = new Date();
      progress.progress = 100;
      progress.currentPhase = 'Completed';

      const result: ScanResult = {
        scanId,
        targetInfo,
        scanOptions: options,
        progress,
        vulnerabilities: allVulnerabilities,
        summary,
        metadata,
        generatedAt: new Date(),
      };

      return result;

    } catch (error) {
      progress.status = ScanStatusEnum.FAILED;
      progress.endTime = new Date();
      progress.errors.push({
        type: 'analysis',
        message: error instanceof Error ? error.message : 'Unknown error',
        severity: 'fatal',
        timestamp: new Date(),
        ...(error instanceof Error && error.stack ? { stack: error.stack } : {}),
      });

      throw error;
    }
  }

  private async analyzeTarget(source: string, options: ScanOptions): Promise<ScanTargetInfo> {
    const stats = await fs.stat(source);
    let targets: Array<{ path: string; language: LanguageType }> = [];

    if (stats.isDirectory()) {
      targets = await this.scanDirectory(source, options);
    } else {
      const language = this.detectLanguage(source);
      targets = [{ path: source, language }];
    }

    // Filter by included/excluded paths
    targets = targets.filter(target => {
      const relativePath = path.relative(process.cwd(), target.path);
      
      if (options.includePaths.length > 0) {
        if (!options.includePaths.some(pattern => relativePath.includes(pattern))) {
          return false;
        }
      }

      if (options.excludePaths.length > 0) {
        if (options.excludePaths.some(pattern => relativePath.includes(pattern))) {
          return false;
        }
      }

      return options.targetLanguages.length === 0 || 
             options.targetLanguages.includes(target.language);
    });

    // Calculate metrics
    let totalLines = 0;
    const languageBreakdown: Record<LanguageType, number> = {} as Record<LanguageType, number>;
    
    for (const target of targets) {
      try {
        const content = await fs.readFile(target.path, 'utf-8');
        const lines = content.split('\n').length;
        totalLines += lines;
        
        if (!languageBreakdown[target.language]) {
          languageBreakdown[target.language] = 0;
        }
        languageBreakdown[target.language]++;
      } catch (error) {
        // Skip files that can't be read
      }
    }

    return {
      targets: targets.map(t => ({ 
        type: 'file' as const, 
        path: t.path, 
        language: t.language 
      })),
      totalFiles: targets.length,
      totalLines,
      languageBreakdown,
      dependencies: [], // TODO: Extract from package files
    };
  }

  private async scanDirectory(dirPath: string, options: ScanOptions): Promise<Array<{ path: string; language: LanguageType }>> {
    const results: Array<{ path: string; language: LanguageType }> = [];
    
    const scan = async (currentPath: string, depth = 0): Promise<void> => {
      if (depth > options.maxDepth) return;

      const entries = await fs.readdir(currentPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(currentPath, entry.name);
        
        if (entry.isDirectory()) {
          // Skip common directories
          if (['node_modules', '.git', 'dist', 'build', '.next'].includes(entry.name)) {
            continue;
          }
          await scan(fullPath, depth + 1);
        } else if (entry.isFile()) {
          const language = this.detectLanguage(fullPath);
          if (language !== LanguageType.JSON) { // Skip JSON for now
            results.push({ path: fullPath, language });
          }
        }
      }
    };

    await scan(dirPath);
    return results;
  }

  private detectLanguage(filePath: string): LanguageType {
    const ext = path.extname(filePath).toLowerCase();
    
    switch (ext) {
      case '.ts':
        return LanguageType.TYPESCRIPT;
      case '.js':
      case '.mjs':
      case '.cjs':
        return LanguageType.JAVASCRIPT;
      case '.py':
        return LanguageType.PYTHON;
      case '.go':
        return LanguageType.GO;
      case '.rs':
        return LanguageType.RUST;
      case '.yml':
      case '.yaml':
        return LanguageType.YAML;
      case '.json':
        return LanguageType.JSON;
      default:
        // Check for Dockerfile
        if (path.basename(filePath).toLowerCase().startsWith('dockerfile')) {
          return LanguageType.DOCKERFILE;
        }
        return LanguageType.JAVASCRIPT; // Default fallback
    }
  }

  private async performStaticAnalysis(
    targetInfo: ScanTargetInfo, 
    _options: ScanOptions, 
    progress: ScanProgress
  ): Promise<StaticAnalysisResult[]> {
    const results: StaticAnalysisResult[] = [];

    for (let i = 0; i < targetInfo.targets.length; i++) {
      const target = targetInfo.targets[i];
      
      if (!target || !target.language) {
        continue;
      }
      
      try {
        const content = await fs.readFile(target.path, 'utf-8');

        // Dockerfiles get real hadolint-equivalent linting instead of the AST-based JS/TS/Python
        // pipeline below (dockerfile-ast, not esprima, understands FROM/RUN/USER/ENV semantics).
        if (target.language === LanguageType.DOCKERFILE) {
          const vulnerabilities = [
            ...dockerfileLinter.lint(target.path, content),
            ...detectSecrets(content, target.path),
          ];

          results.push({
            ast: {},
            symbols: { functions: [], classes: [], variables: [], imports: [], exports: [] },
            dependencies: [],
            vulnerabilities,
            metrics: {
              linesOfCode: content.split('\n').length,
              complexity: 1,
              maintainabilityIndex: 100,
              technicalDebt: 0,
            },
          });

          progress.processedFiles++;
          progress.progress = 10 + Math.floor((progress.processedFiles / progress.totalFiles) * 60);
          continue;
        }

        const ast = await this.parseFile(target.path, content, target.language);
        const symbols = this.extractSymbols(ast);
        const vulnerabilities = await this.detectVulnerabilities(ast, content, target.language);

        results.push({
          ast: ast.ast as unknown as Record<string, unknown>,
          symbols,
          dependencies: [], // TODO: Extract dependencies
          vulnerabilities,
          metrics: {
            linesOfCode: content.split('\n').length,
            complexity: this.calculateComplexity(ast),
            maintainabilityIndex: 100, // TODO: Implement
            technicalDebt: 0, // TODO: Implement
          },
        });

        progress.processedFiles++;
        progress.progress = 10 + Math.floor((progress.processedFiles / progress.totalFiles) * 60);

      } catch (error) {
        progress.errors.push({
          type: 'parse',
          message: `Failed to parse ${target.path}: ${error instanceof Error ? error.message : 'Unknown error'}`,
          file: target.path,
          severity: 'error',
          timestamp: new Date(),
        });
      }
    }

    return results;
  }

  private async parseFile(filePath: string, content: string, language: LanguageType): Promise<LanguageAST> {
    let ast: ASTNode;
    const parseErrors: any[] = [];

    try {
      switch (language) {
        case LanguageType.TYPESCRIPT:
        case LanguageType.JAVASCRIPT:
          // Use esprima for JavaScript
          const jsResult = esprima.parseScript(content, {
            loc: true,
            range: true,
            tolerant: true,
          });
          ast = this.convertEsprimaASTToStandard(jsResult, content);
          break;

        default:
          // For other languages, create a simple AST structure
          ast = {
            type: 'Program',
            start: 0,
            end: content.length,
            loc: {
              start: { line: 1, column: 0 },
              end: { line: content.split('\n').length, column: 0 },
            },
            children: [],
            properties: { content },
          };
      }

      return {
        language,
        filePath,
        ast,
        parseErrors,
        metadata: {
          parseTime: Date.now(),
          nodeCount: this.countASTNodes(ast),
          complexity: this.calculateComplexity({ language, filePath, ast, parseErrors, metadata: {} as any }),
          dependencies: [],
          imports: [],
          exports: [],
        },
      };

    } catch (error) {
      parseErrors.push({
        message: error instanceof Error ? error.message : 'Parse error',
        line: 0,
        column: 0,
        severity: 'error' as const,
      });

      // Return minimal AST on parse failure
      return {
        language,
        filePath,
        ast: {
          type: 'Program',
          start: 0,
          end: content.length,
          children: [],
          properties: { content },
        },
        parseErrors,
        metadata: {
          parseTime: Date.now(),
          nodeCount: 1,
          complexity: 1,
          dependencies: [],
          imports: [],
          exports: [],
        },
      };
    }
  }

  private convertTSASTToStandard(tsAst: any): ASTNode {
    return {
      type: tsAst.type || 'Unknown',
      start: tsAst.range?.[0] || 0,
      end: tsAst.range?.[1] || 0,
      loc: tsAst.loc,
      children: Array.isArray(tsAst.body) ? tsAst.body.map((child: any) => this.convertTSASTToStandard(child)) : [],
      properties: { ...tsAst },
    };
  }

  private convertEsprimaASTToStandard(esprimaAst: any, content?: string): ASTNode {
    return {
      type: esprimaAst.type || 'Unknown',
      start: esprimaAst.range?.[0] || 0,
      end: esprimaAst.range?.[1] || 0,
      loc: esprimaAst.loc,
      children: Array.isArray(esprimaAst.body) ? esprimaAst.body.map((child: any) => this.convertEsprimaASTToStandard(child)) : [],
      // NOTE: esprima's own Program node has no `content` field. Previously this spread left
      // `properties.content` undefined for every successfully-parsed file, which silently broke
      // all AST-content-based pattern matching below (it only ever "worked" by accident, when a
      // file failed to parse and fell back to the minimal AST that does set `content`). Passing
      // `content` through explicitly fixes that for real.
      properties: { ...esprimaAst, ...(content !== undefined ? { content } : {}) },
    };
  }

  private extractSymbols(_ast: LanguageAST): SymbolExtraction {
    // TODO: Implement comprehensive symbol extraction
    return {
      functions: [],
      classes: [],
      variables: [],
      imports: [],
      exports: [],
    };
  }

  private async detectVulnerabilities(ast: LanguageAST, content: string, language: LanguageType): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    // Context-aware detectors (command injection, path traversal, prompt injection, and
    // tool-poisoning-via-handler-code). These were previously fully implemented but never
    // called from anywhere in the scan pipeline.
    for (const detector of this.dedicatedDetectors) {
      if (detector.supportsLanguage(language)) {
        vulnerabilities.push(...await detector.detect(ast, content));
      }
    }

    // Tool-description-based poisoning detection: the actual, documented MCP "tool poisoning" /
    // "rug pull" attack surface (hidden Unicode, LLM-directed instructions, description/behavior
    // mismatches in tool metadata) rather than handler code.
    if (
      language === LanguageType.TYPESCRIPT ||
      language === LanguageType.JAVASCRIPT ||
      language === LanguageType.PYTHON
    ) {
      vulnerabilities.push(...analyzeToolDescriptions(content, ast.filePath));
    }

    // Extra language-specific regex patterns contributed by the language scanners (unsafe `any`,
    // insecure Math.random(), Python pickle/SQL-injection/subprocess checks, etc.). These pattern
    // lists existed in src/scanners/*.ts but were only reachable through methods nothing called.
    const scanner = scannerRegistry.getScannerForFile(ast.filePath);
    if (scanner) {
      // Skip patterns that substantially duplicate a dedicated detector's coverage above (e.g.
      // Python's subprocess shell=True / eval-exec / path-traversal patterns) so the same issue
      // isn't reported twice under two different vulnerability types; keep the genuinely
      // additional checks (unsafe `any`, insecure randomness, pickle deserialization, SQL
      // injection via string formatting) that nothing else in the pipeline covers.
      const excludedScannerPatterns = new Set([
        // Substantially duplicate a dedicated detector's coverage above.
        'py_subprocess_shell_injection',
        'py_eval_exec_injection',
        'py_path_traversal',
        'ts_exec_template_literal',
        'ts_path_traversal_template',
        // Match every `any` annotation / `as X` assertion in a file with no security-relevant
        // context at all. On this very codebase they accounted for ~80% of all findings (298 of
        // 369) with essentially no signal - idiomatic, safe TypeScript triggers them constantly.
        // A general type-safety linter is a legitimate tool, but flagging every occurrence as a
        // "vulnerability" would wreck this scanner's precision, so they're deliberately excluded.
        'ts_unsafe_any',
        'ts_unsafe_type_assertion',
      ]);
      const extraPatterns = scanner.getVulnerabilityPatterns().filter(p => !excludedScannerPatterns.has(p.id));
      vulnerabilities.push(...this.matchScannerPatterns(content, ast.filePath, extraPatterns));
    }

    // Secrets scanning applies to every text file regardless of language.
    vulnerabilities.push(...detectSecrets(content, ast.filePath));

    // Remaining generic patterns from the regex pattern database (currently just OAuth) that
    // aren't already covered by one of the dedicated detectors above.
    const genericPatterns = (this.patterns.get(language) || [])
      .filter(pattern => !this.typesWithDedicatedDetectors.has(pattern.type));

    for (const pattern of genericPatterns) {
      const matches = await this.matchPattern(ast, pattern);
      vulnerabilities.push(...matches);
    }

    return vulnerabilities;
  }

  /**
   * Apply a language scanner's own `LanguageVulnerabilityPattern` regex rules directly against
   * raw file content. (Deliberately does not call the scanners' own `analyzeCode`/`matchPattern`,
   * which read `ast.ast.properties.content` - a field their `parseFile()` never actually
   * populates for successfully-parsed TypeScript, the same latent bug fixed above for core.ts's
   * own AST conversion.)
   */
  private matchScannerPatterns(
    content: string,
    filePath: string,
    patterns: LanguageVulnerabilityPattern[]
  ): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const pattern of patterns) {
      if (pattern.pattern.type !== 'regex') continue;
      const matcher = pattern.pattern.matcher as { pattern: RegExp };
      if (!(matcher.pattern instanceof RegExp)) continue;

      const regex = new RegExp(matcher.pattern.source, matcher.pattern.flags.includes('g') ? matcher.pattern.flags : `${matcher.pattern.flags}g`);
      const severity = this.mapLanguagePatternSeverity(pattern.severity);

      for (const match of content.matchAll(regex)) {
        if (match.index === undefined) continue;
        const lines = content.substring(0, match.index).split('\n');
        const line = lines.length;
        const column = lines[lines.length - 1]?.length || 0;

        vulnerabilities.push({
          id: this.generateVulnerabilityId(),
          type: VulnerabilityType.CONFIGURATION_ERROR,
          severity,
          score: this.severityToScore(severity),
          title: pattern.name,
          description: pattern.description,
          location: { file: filePath, line, column },
          remediation: {
            title: `Fix ${pattern.name}`,
            description: pattern.description,
            steps: pattern.remediation,
            references: pattern.references,
            effort: severity === SeverityLevel.CRITICAL ? 'high' : 'medium',
            priority: severity === SeverityLevel.CRITICAL ? 1 : 2,
          },
          cveReferences: pattern.cweId ? this.getCVEReferences(pattern.cweId) : [],
          context: {
            pattern: pattern.id,
            match: match[0],
            detectionMethod: 'language-scanner-pattern',
          },
          detectedAt: new Date(),
          confidence: 0.75,
          falsePositiveRisk: 'medium',
          tags: [pattern.language, severity, ...pattern.tags],
        });
      }
    }

    return vulnerabilities;
  }

  private mapLanguagePatternSeverity(severity: 'critical' | 'high' | 'medium' | 'low'): SeverityLevel {
    switch (severity) {
      case 'critical': return SeverityLevel.CRITICAL;
      case 'high': return SeverityLevel.HIGH;
      case 'medium': return SeverityLevel.MEDIUM;
      case 'low': return SeverityLevel.LOW;
      default: return SeverityLevel.LOW;
    }
  }

  private async matchPattern(ast: LanguageAST, pattern: VulnerabilityPattern): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const content = (ast.ast.properties?.['content'] as string) || '';

    if (typeof pattern.pattern === 'string') {
      const regex = new RegExp(pattern.pattern, 'gi');
      const matches = content.matchAll(regex);
      
      for (const match of matches) {
        if (match.index !== undefined) {
          const lines = content.substring(0, match.index).split('\n');
          const line = lines.length;
          const column = lines[lines.length - 1]?.length || 0;

          vulnerabilities.push({
            id: this.generateVulnerabilityId(),
            type: pattern.type,
            severity: pattern.severity,
            score: this.severityToScore(pattern.severity),
            title: pattern.name,
            description: pattern.description,
            location: {
              file: ast.filePath,
              line,
              column,
            },
            remediation: {
              title: `Fix ${pattern.name}`,
              description: pattern.description,
              steps: ['Review the code', 'Apply security best practices', 'Test the fix'],
              references: pattern.references,
              effort: 'medium',
              priority: pattern.severity === SeverityLevel.CRITICAL ? 1 : 2,
            },
            cveReferences: pattern.cweId ? this.getCVEReferences(pattern.cweId) : [],
            context: {
              pattern: pattern.id,
              match: match[0],
              language: ast.language,
            },
            detectedAt: new Date(),
            confidence: pattern.severity === SeverityLevel.CRITICAL ? 0.9 : 0.7,
            falsePositiveRisk: 'medium',
            tags: [pattern.type, pattern.severity, ast.language],
          });
        }
      }
    } else if (pattern.pattern instanceof RegExp) {
      const matches = content.matchAll(pattern.pattern);
      
      for (const match of matches) {
        if (match.index !== undefined) {
          const lines = content.substring(0, match.index).split('\n');
          const line = lines.length;
          const column = lines[lines.length - 1]?.length || 0;

          vulnerabilities.push({
            id: this.generateVulnerabilityId(),
            type: pattern.type,
            severity: pattern.severity,
            score: this.severityToScore(pattern.severity),
            title: pattern.name,
            description: pattern.description,
            location: {
              file: ast.filePath,
              line,
              column,
            },
            remediation: {
              title: `Fix ${pattern.name}`,
              description: pattern.description,
              steps: ['Review the code', 'Apply security best practices', 'Test the fix'],
              references: pattern.references,
              effort: 'medium',
              priority: pattern.severity === SeverityLevel.CRITICAL ? 1 : 2,
            },
            cveReferences: pattern.cweId ? this.getCVEReferences(pattern.cweId) : [],
            context: {
              pattern: pattern.id,
              match: match[0],
              language: ast.language,
            },
            detectedAt: new Date(),
            confidence: pattern.severity === SeverityLevel.CRITICAL ? 0.9 : 0.7,
            falsePositiveRisk: 'medium',
            tags: [pattern.type, pattern.severity, ast.language],
          });
        }
      }
    }

    return vulnerabilities;
  }

  private getCVEReferences(cweId: string): any[] {
    const cveDatabase = cveMappingDatabase.getDatabase();
    return cveDatabase.entries
      .filter(entry => entry.weaknesses.some(w => w.id === cweId))
      .map(entry => ({
        id: entry.id,
        url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${entry.id}`,
        description: entry.description,
        score: entry.score,
        vector: entry.vector,
      }));
  }

  private countASTNodes(ast: ASTNode): number {
    let count = 1; // Count current node
    if (ast.children) {
      for (const child of ast.children) {
        count += this.countASTNodes(child);
      }
    }
    return count;
  }

  private calculateComplexity(ast: LanguageAST): number {
    // Simple complexity calculation based on AST structure
    return Math.max(1, Math.floor(this.countASTNodes(ast.ast) / 10));
  }

  private severityToScore(severity: SeverityLevel): number {
    switch (severity) {
      case SeverityLevel.CRITICAL: return 9.5;
      case SeverityLevel.HIGH: return 8.0;
      case SeverityLevel.MEDIUM: return 5.5;
      case SeverityLevel.LOW: return 2.0;
      case SeverityLevel.INFO: return 0.0;
      default: return 0.0;
    }
  }

  private generateScanId(): string {
    return `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateVulnerabilityId(): string {
    return `vuln_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateSummary(vulnerabilities: Vulnerability[], _targetInfo: ScanTargetInfo): ScanSummary {
    const severityBreakdown: Record<SeverityLevel, number> = {
      [SeverityLevel.CRITICAL]: 0,
      [SeverityLevel.HIGH]: 0,
      [SeverityLevel.MEDIUM]: 0,
      [SeverityLevel.LOW]: 0,
      [SeverityLevel.INFO]: 0,
    };

    const typeBreakdown: Record<string, number> = {};

    for (const vuln of vulnerabilities) {
      severityBreakdown[vuln.severity]++;
      typeBreakdown[vuln.type] = (typeBreakdown[vuln.type] || 0) + 1;
    }

    const riskScore = this.calculateRiskScore(vulnerabilities);

    return {
      totalVulnerabilities: vulnerabilities.length,
      vulnerabilityBreakdown: severityBreakdown,
      typeBreakdown,
      riskScore,
      confidence: vulnerabilities.length > 0 ? 
        vulnerabilities.reduce((sum, v) => sum + v.confidence, 0) / vulnerabilities.length : 1.0,
      falsePositiveEstimate: 0.1, // TODO: Implement better estimation
      recommendedActions: this.generateRecommendations(vulnerabilities),
    };
  }

  private calculateRiskScore(vulnerabilities: Vulnerability[]): number {
    if (vulnerabilities.length === 0) return 0;
    
    const scores = vulnerabilities.map(v => v.score);
    const maxScore = Math.max(...scores);
    const avgScore = scores.reduce((sum, score) => sum + score, 0) / scores.length;
    
    // Weight max score higher than average
    return Math.min(100, Math.round((maxScore * 0.7 + avgScore * 0.3) * 10));
  }

  private generateRecommendations(vulnerabilities: Vulnerability[]): string[] {
    const recommendations: string[] = [];

    if (vulnerabilities.some(v => v.type === VulnerabilityType.COMMAND_INJECTION)) {
      recommendations.push('Implement input sanitization for all shell commands');
    }

    if (vulnerabilities.some(v => v.type === VulnerabilityType.PATH_TRAVERSAL)) {
      recommendations.push('Validate and sanitize all file paths');
    }

    if (vulnerabilities.some(v => v.type === VulnerabilityType.PROMPT_INJECTION)) {
      recommendations.push('Implement prompt injection defenses');
    }

    if (vulnerabilities.some(v => v.type === VulnerabilityType.TOOL_POISONING && v.context?.['detectionMethod'] === 'tool-description-analysis')) {
      recommendations.push('Audit every tool name/description/parameter for hidden Unicode or LLM-directed instructions, and diff them against previous releases before publishing');
    }

    if (vulnerabilities.some(v => v.type === VulnerabilityType.DOCKERFILE_MISCONFIGURATION)) {
      recommendations.push('Fix Dockerfile best-practice violations (pin base images, run as a non-root user, avoid baking secrets into layers)');
    }

    if (vulnerabilities.some(v => v.type === VulnerabilityType.HARDCODED_SECRET)) {
      recommendations.push('Rotate and remove all hardcoded credentials; move secrets to environment variables or a secrets manager');
    }

    if (vulnerabilities.some(v => v.type === VulnerabilityType.DEPENDENCY_VULNERABILITY)) {
      recommendations.push('Upgrade dependencies with known vulnerabilities reported by OSV.dev');
    }

    if (vulnerabilities.some(v => v.severity === SeverityLevel.CRITICAL)) {
      recommendations.push('Address critical vulnerabilities immediately');
    }

    return recommendations;
  }

  private generateMetadata(startTime: Date, targetInfo: ScanTargetInfo): ScanMetadata {
    const endTime = new Date();
    const duration = endTime.getTime() - startTime.getTime();

    return {
      scannerVersion: '1.0.0',
      scanDuration: duration,
      rulesVersion: '2024.1',
      environment: {
        nodeVersion: process.version,
        platform: process.platform,
        architecture: process.arch,
      },
      performance: {
        memoryUsage: process.memoryUsage().heapUsed,
        cpuUsage: 0, // TODO: Implement CPU usage tracking
        filesPerSecond: targetInfo.totalFiles / (duration / 1000),
      },
    };
  }

  getScanProgress(scanId: string): ScanProgress | undefined {
    return this.scanProgress.get(scanId);
  }

  getAllScans(): ScanProgress[] {
    return Array.from(this.scanProgress.values());
  }
}

export const securityAnalyzer = new SecurityAnalyzer();
