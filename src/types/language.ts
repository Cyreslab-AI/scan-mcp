// Language-specific types for multi-language security scanning
import { LanguageType } from './index';

export interface LanguageScanner {
  language: LanguageType;
  extensions: string[];
  parseFile(filePath: string, content: string): Promise<LanguageAST>;
  extractSymbols(ast: LanguageAST): SymbolExtraction;
  getVulnerabilityPatterns(): LanguageVulnerabilityPattern[];
  analyzeCode(ast: LanguageAST, patterns: LanguageVulnerabilityPattern[]): LanguageVulnerability[];
}

export interface LanguageAST {
  language: LanguageType;
  filePath: string;
  ast: ASTNode;
  sourceMap?: SourceMap;
  parseErrors: ParseError[];
  metadata: ASTMetadata;
}

export interface ASTNode {
  type: string;
  start: number;
  end: number;
  loc?: SourceLocation;
  children?: ASTNode[];
  properties?: Record<string, unknown>;
  parent?: ASTNode;
}

export interface SourceLocation {
  start: Position;
  end: Position;
}

export interface Position {
  line: number;
  column: number;
}

export interface SourceMap {
  version: number;
  sources: string[];
  names: string[];
  mappings: string;
  sourcesContent?: string[];
}

export interface ParseError {
  message: string;
  line: number;
  column: number;
  severity: 'error' | 'warning';
  code?: string;
}

export interface ASTMetadata {
  parseTime: number;
  nodeCount: number;
  complexity: number;
  dependencies: string[];
  imports: ImportDeclaration[];
  exports: ExportDeclaration[];
}

export interface ImportDeclaration {
  source: string;
  imports: ImportSpecifier[];
  location: SourceLocation;
  dynamic: boolean;
}

export interface ImportSpecifier {
  name: string;
  alias?: string;
  type: 'default' | 'namespace' | 'named';
}

export interface ExportDeclaration {
  name: string;
  type: 'default' | 'named' | 'namespace';
  location: SourceLocation;
  source?: string;
}

export interface SymbolExtraction {
  functions: FunctionDeclaration[];
  classes: ClassDeclaration[];
  variables: VariableDeclaration[];
  types: TypeDeclaration[];
  interfaces: InterfaceDeclaration[];
  modules: ModuleDeclaration[];
}

export interface FunctionDeclaration {
  name: string;
  parameters: FunctionParameter[];
  returnType?: TypeAnnotation;
  body: ASTNode[];
  location: SourceLocation;
  modifiers: FunctionModifier[];
  isAsync: boolean;
  isGenerator: boolean;
}

export interface FunctionParameter {
  name: string;
  type?: TypeAnnotation;
  optional: boolean;
  defaultValue?: ASTNode;
  rest: boolean;
}

export interface FunctionModifier {
  type: 'public' | 'private' | 'protected' | 'static' | 'abstract' | 'readonly';
}

export interface ClassDeclaration {
  name: string;
  superClass?: string;
  interfaces: string[];
  members: ClassMember[];
  location: SourceLocation;
  modifiers: ClassModifier[];
  typeParameters?: TypeParameter[];
}

export interface ClassMember {
  type: 'method' | 'property' | 'constructor' | 'getter' | 'setter';
  name: string;
  signature?: TypeSignature;
  modifiers: FunctionModifier[];
  location: SourceLocation;
}

export interface ClassModifier {
  type: 'public' | 'private' | 'protected' | 'abstract' | 'final' | 'static';
}

export interface VariableDeclaration {
  name: string;
  type?: TypeAnnotation;
  initializer?: ASTNode;
  location: SourceLocation;
  scope: 'global' | 'function' | 'block' | 'class';
  mutable: boolean;
  kind: 'var' | 'let' | 'const';
}

export interface TypeDeclaration {
  name: string;
  definition: TypeDefinition;
  location: SourceLocation;
  typeParameters?: TypeParameter[];
}

export interface InterfaceDeclaration {
  name: string;
  members: InterfaceMember[];
  extends: string[];
  location: SourceLocation;
  typeParameters?: TypeParameter[];
}

export interface InterfaceMember {
  name: string;
  type: TypeAnnotation;
  optional: boolean;
  readonly: boolean;
}

export interface ModuleDeclaration {
  name: string;
  exports: ExportDeclaration[];
  imports: ImportDeclaration[];
  location: SourceLocation;
}

export interface TypeAnnotation {
  type: string;
  parameters?: TypeAnnotation[];
  properties?: Record<string, TypeAnnotation>;
  nullable: boolean;
  optional: boolean;
}

export interface TypeDefinition {
  kind: 'primitive' | 'object' | 'array' | 'union' | 'intersection' | 'function';
  definition: unknown;
}

export interface TypeParameter {
  name: string;
  constraint?: TypeAnnotation;
  default?: TypeAnnotation;
}

export interface TypeSignature {
  parameters: FunctionParameter[];
  returnType?: TypeAnnotation;
}

// Language-specific vulnerability patterns
export interface LanguageVulnerabilityPattern {
  id: string;
  language: LanguageType;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  pattern: PatternMatcher;
  examples: PatternExample[];
  remediation: string[];
  references: string[];
  cweId?: string;
  tags: string[];
}

export interface PatternMatcher {
  type: 'ast' | 'regex' | 'semantic' | 'dataflow';
  matcher: ASTMatcher | RegexMatcher | SemanticMatcher | DataFlowMatcher;
}

export interface ASTMatcher {
  nodeType: string;
  properties?: Record<string, unknown>;
  children?: ASTMatcher[];
  ancestors?: ASTMatcher[];
  descendants?: ASTMatcher[];
}

export interface RegexMatcher {
  pattern: RegExp;
  flags?: string;
  context?: 'line' | 'function' | 'class' | 'file';
}

export interface SemanticMatcher {
  symbolType: 'function' | 'variable' | 'class' | 'import';
  symbolName?: string;
  symbolPattern?: RegExp;
  usage: 'declaration' | 'call' | 'assignment' | 'access';
  context?: SemanticContext;
}

export interface SemanticContext {
  inFunction?: string;
  inClass?: string;
  withParameters?: string[];
  withTypes?: string[];
}

export interface DataFlowMatcher {
  source: DataFlowNode;
  sink: DataFlowNode;
  path?: DataFlowPath;
}

export interface DataFlowNode {
  type: 'parameter' | 'variable' | 'property' | 'return' | 'call';
  identifier?: string;
  pattern?: RegExp;
  tainted: boolean;
}

export interface DataFlowPath {
  maxLength?: number;
  excludeNodes?: DataFlowNode[];
  requiredNodes?: DataFlowNode[];
}

export interface PatternExample {
  code: string;
  vulnerable: boolean;
  description: string;
  line?: number;
}

export interface LanguageVulnerability {
  patternId: string;
  location: SourceLocation;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  context: VulnerabilityContext;
  confidence: number;
  suggestions: string[];
}

export interface VulnerabilityContext {
  codeSnippet: string;
  functionName?: string;
  className?: string;
  symbolsInvolved: string[];
  dataFlow?: DataFlowTrace;
}

export interface DataFlowTrace {
  source: DataFlowNode;
  sink: DataFlowNode;
  path: DataFlowNode[];
  taintedVariables: string[];
}

// Language-specific configurations
export interface TypeScriptConfig {
  compilerOptions?: TypeScriptCompilerOptions;
  include?: string[];
  exclude?: string[];
  extends?: string;
}

export interface TypeScriptCompilerOptions {
  target?: string;
  module?: string;
  strict?: boolean;
  skipLibCheck?: boolean;
  forceConsistentCasingInFileNames?: boolean;
  [key: string]: unknown;
}

export interface PythonConfig {
  version: string;
  virtualEnv?: string;
  requirements?: string[];
  pylintConfig?: string;
  mypyConfig?: string;
}

export interface JavaScriptConfig {
  ecmaVersion?: number;
  sourceType?: 'module' | 'script';
  parserOptions?: Record<string, unknown>;
  env?: Record<string, boolean>;
}

export interface GoConfig {
  goVersion?: string;
  goMod?: string;
  buildTags?: string[];
  cgoEnabled?: boolean;
}

export interface RustConfig {
  edition?: string;
  cargoToml?: string;
  features?: string[];
  target?: string;
}

export interface LanguageConfig {
  language: LanguageType;
  config: TypeScriptConfig | PythonConfig | JavaScriptConfig | GoConfig | RustConfig;
  scannerOptions: LanguageScannerOptions;
}

export interface LanguageScannerOptions {
  enableTypeChecking: boolean;
  enableDataFlowAnalysis: boolean;
  enableSemanticAnalysis: boolean;
  maxComplexity?: number;
  timeout?: number;
  memoryLimit?: number;
}
