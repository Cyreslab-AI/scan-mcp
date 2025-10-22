// TypeScript language scanner with advanced security analysis
import * as esprima from 'esprima';
import { LanguageScanner } from './base';
import { 
  LanguageAST,
  SymbolExtraction,
  LanguageVulnerabilityPattern,
  LanguageVulnerability,
  ASTNode,
  FunctionDeclaration,
  ClassDeclaration,
  VariableDeclaration
} from '@/types/language';
import { LanguageType } from '@/types';

export class TypeScriptScanner extends LanguageScanner {
  readonly language = LanguageType.TYPESCRIPT;
  readonly extensions = ['.ts', '.tsx'];

  async parseFile(filePath: string, content: string): Promise<LanguageAST> {
    const startTime = Date.now();
    const parseErrors: any[] = [];

    try {
      // Use esprima for parsing (can handle most TypeScript syntax)
      const ast = esprima.parseScript(content, {
        loc: true,
        range: true,
        tolerant: true,
        tokens: false,
        comment: false,
      });

      if (!this.validateAST(ast)) {
        throw new Error('Invalid AST structure');
      }

      const nodeCount = this.countNodes(ast);
      const imports = this.extractImports(ast);
      const exports = this.extractExports(ast);
      const dependencies = this.extractDependencies(imports);

      return {
        language: this.language,
        filePath,
        ast: this.convertToStandardAST(ast),
        parseErrors,
        metadata: this.createMetadata(Date.now() - startTime, nodeCount, dependencies, imports, exports),
      };

    } catch (error) {
      parseErrors.push(this.createParseError(
        error instanceof Error ? error.message : 'Parse error',
        0,
        0,
        'error'
      ));

      // Return minimal AST on parse failure
      return {
        language: this.language,
        filePath,
        ast: {
          type: 'Program',
          start: 0,
          end: content.length,
          children: [],
          properties: { content },
        },
        parseErrors,
        metadata: this.createMetadata(Date.now() - startTime, 1, [], [], []),
      };
    }
  }

  extractSymbols(ast: LanguageAST): SymbolExtraction {
    const functions = this.extractFunctions(ast.ast);
    const classes = this.extractClasses(ast.ast);
    const variables = this.extractVariables(ast.ast);
    // Note: imports and exports are available in ast.metadata if needed for future enhancements

    return {
      functions,
      classes,
      variables,
      types: [], // TODO: Extract TypeScript type declarations
      interfaces: [], // TODO: Extract interface declarations
      modules: [], // TODO: Extract module declarations
    };
  }

  getVulnerabilityPatterns(): LanguageVulnerabilityPattern[] {
    return TYPESCRIPT_VULNERABILITY_PATTERNS;
  }

  analyzeCode(ast: LanguageAST, patterns: LanguageVulnerabilityPattern[]): LanguageVulnerability[] {
    const vulnerabilities: LanguageVulnerability[] = [];

    for (const pattern of patterns) {
      if (pattern.language === this.language) {
        const matches = this.matchPattern(ast, pattern);
        vulnerabilities.push(...matches);
      }
    }

    return vulnerabilities;
  }

  private convertToStandardAST(esprimaAst: any): ASTNode {
    return {
      type: esprimaAst.type || 'Program',
      start: esprimaAst.range?.[0] || 0,
      end: esprimaAst.range?.[1] || 0,
      loc: esprimaAst.loc,
      children: Array.isArray(esprimaAst.body) ? esprimaAst.body.map((child: any) => this.convertToStandardAST(child)) : [],
      properties: { ...esprimaAst },
    };
  }

  private extractFunctions(ast: ASTNode): FunctionDeclaration[] {
    const functions: FunctionDeclaration[] = [];
    
    this.traverseAST(ast, (node: any) => {
      if (node.type === 'FunctionDeclaration' || node.type === 'ArrowFunctionExpression') {
        functions.push({
          name: node.id?.name || 'anonymous',
          parameters: node.params?.map((param: any) => ({
            name: param.name || param.id?.name || 'unknown',
            optional: param.optional || false,
            defaultValue: param.defaultValue,
            rest: param.rest || false,
          })) || [],
          body: Array.isArray(node.body?.body) ? node.body.body : [],
          location: {
            start: { line: node.loc?.start?.line || 0, column: node.loc?.start?.column || 0 },
            end: { line: node.loc?.end?.line || 0, column: node.loc?.end?.column || 0 },
          },
          modifiers: [], // TODO: Extract modifiers
          isAsync: node.async || false,
          isGenerator: node.generator || false,
        });
      }
    });

    return functions;
  }

  private extractClasses(ast: ASTNode): ClassDeclaration[] {
    const classes: ClassDeclaration[] = [];
    
    this.traverseAST(ast, (node: any) => {
      if (node.type === 'ClassDeclaration') {
        classes.push({
          name: node.id?.name || 'anonymous',
          superClass: node.superClass?.name || undefined,
          interfaces: [], // TODO: Extract implemented interfaces
          members: [], // TODO: Extract class members
          location: {
            start: { line: node.loc?.start?.line || 0, column: node.loc?.start?.column || 0 },
            end: { line: node.loc?.end?.line || 0, column: node.loc?.end?.column || 0 },
          },
          modifiers: [], // TODO: Extract modifiers
        });
      }
    });

    return classes;
  }

  private extractVariables(ast: ASTNode): VariableDeclaration[] {
    const variables: VariableDeclaration[] = [];
    
    this.traverseAST(ast, (node: any) => {
      if (node.type === 'VariableDeclaration') {
        for (const declarator of node.declarations || []) {
          variables.push({
            name: declarator.id?.name || 'unknown',
            initializer: declarator.init,
            location: {
              start: { line: declarator.loc?.start?.line || 0, column: declarator.loc?.start?.column || 0 },
              end: { line: declarator.loc?.end?.line || 0, column: declarator.loc?.end?.column || 0 },
            },
            scope: 'global', // TODO: Determine proper scope
            mutable: node.kind !== 'const',
            kind: node.kind as 'var' | 'let' | 'const',
          });
        }
      }
    });

    return variables;
  }

  private extractDependencies(imports: Array<{ source: string; imports: string[] }>): string[] {
    return imports.map(imp => imp.source).filter(source => 
      !source.startsWith('.') && !source.startsWith('/')
    );
  }

  private traverseAST(node: any, callback: (node: any) => void): void {
    callback(node);

    if (node.body && Array.isArray(node.body)) {
      for (const child of node.body) {
        this.traverseAST(child, callback);
      }
    }

    if (node.children && Array.isArray(node.children)) {
      for (const child of node.children) {
        this.traverseAST(child, callback);
      }
    }

    // Traverse other common AST node collections
    if (node.declarations && Array.isArray(node.declarations)) {
      for (const child of node.declarations) {
        this.traverseAST(child, callback);
      }
    }
  }

  private matchPattern(ast: LanguageAST, pattern: LanguageVulnerabilityPattern): LanguageVulnerability[] {
    const vulnerabilities: LanguageVulnerability[] = [];
    const content = ast.ast.properties?.['content'] as string || '';

    if (pattern.pattern.type === 'regex') {
      const regexMatcher = pattern.pattern.matcher as any;
      if (regexMatcher.pattern instanceof RegExp) {
        const regex = regexMatcher.pattern;
        const matches = Array.from(content.matchAll(regex));

        for (const match of matches) {
          if (match.index !== undefined) {
            const lines = content.substring(0, match.index).split('\n');
            const line = lines.length;
            const column = lines[lines.length - 1]?.length || 0;

            vulnerabilities.push({
              patternId: pattern.id,
              location: {
                start: { line, column },
                end: { line, column: column + match[0].length },
              },
              severity: pattern.severity,
              message: pattern.description,
              context: {
                codeSnippet: this.extractSnippet(content, match.index, match.index + match[0].length),
                symbolsInvolved: [],
              },
              confidence: 0.8,
              suggestions: [`Fix ${pattern.name}`],
            });
          }
        }
      }
    }

    return vulnerabilities;
  }

  private extractSnippet(content: string, start: number, end: number): string {
    const lines = content.split('\n');
    const startPos = this.findLineColumn(content, start);
    const endPos = this.findLineColumn(content, end);
    
    const startLine = Math.max(0, startPos.line - 2);
    const endLine = Math.min(lines.length - 1, endPos.line + 2);
    
    return lines.slice(startLine, endLine + 1).join('\n');
  }

  private findLineColumn(content: string, index: number): { line: number; column: number } {
    const lines = content.substring(0, index).split('\n');
    return {
      line: lines.length - 1,
      column: lines[lines.length - 1]?.length || 0,
    };
  }

  protected override getCapabilities(): string[] {
    return [
      ...super.getCapabilities(),
      'type_analysis',
      'interface_extraction',
      'generic_support',
      'decorator_analysis',
    ];
  }
}

// TypeScript-specific vulnerability patterns
const TYPESCRIPT_VULNERABILITY_PATTERNS: LanguageVulnerabilityPattern[] = [
  {
    id: 'ts_unsafe_any',
    language: LanguageType.TYPESCRIPT,
    name: 'Unsafe Any Type Usage',
    description: 'Usage of "any" type that bypasses TypeScript type checking',
    severity: 'medium',
    pattern: {
      type: 'regex',
      matcher: {
        pattern: /:\s*any\s*[;,\)=]/g,
        flags: 'g',
      },
    },
    examples: [
      {
        code: 'let userInput: any = req.body;',
        vulnerable: true,
        description: 'Any type allows unsafe operations',
      },
      {
        code: 'let userInput: string = req.body as string;',
        vulnerable: false,
        description: 'Proper type annotation with validation',
      },
    ],
    remediation: [
      'Replace any types with specific type annotations',
      'Use type guards for runtime type checking',
      'Implement proper input validation',
    ],
    references: [
      'https://www.typescriptlang.org/docs/handbook/2/everyday-types.html#any',
    ],
    tags: ['typescript', 'type-safety', 'input-validation'],
  },

  {
    id: 'ts_unsafe_type_assertion',
    language: LanguageType.TYPESCRIPT,
    name: 'Unsafe Type Assertion',
    description: 'Type assertions that may hide runtime type mismatches',
    severity: 'medium',
    pattern: {
      type: 'regex',
      matcher: {
        pattern: /as\s+\w+|<\w+>/g,
        flags: 'g',
      },
    },
    examples: [
      {
        code: 'const data = userInput as SecretData;',
        vulnerable: true,
        description: 'Unsafe type assertion without validation',
      },
      {
        code: 'const data = validateSecretData(userInput);',
        vulnerable: false,
        description: 'Proper validation function',
      },
    ],
    remediation: [
      'Replace type assertions with type guards',
      'Implement runtime validation',
      'Use discriminated unions where appropriate',
    ],
    references: [
      'https://www.typescriptlang.org/docs/handbook/2/everyday-types.html#type-assertions',
    ],
    tags: ['typescript', 'type-assertions', 'validation'],
  },

  {
    id: 'ts_exec_template_literal',
    language: LanguageType.TYPESCRIPT,
    name: 'Command Execution with Template Literals',
    description: 'Shell command execution using template literals with user input',
    severity: 'critical',
    pattern: {
      type: 'regex',
      matcher: {
        pattern: /exec\s*\(\s*`[^`]*\$\{[^}]*\}[^`]*`\s*\)/g,
        flags: 'g',
      },
    },
    examples: [
      {
        code: 'exec(`rm -rf ${userDir}`);',
        vulnerable: true,
        description: 'Direct command injection via template literal',
      },
      {
        code: 'execFile("rm", ["-rf", userDir]);',
        vulnerable: false,
        description: 'Safe command execution with argument array',
      },
    ],
    remediation: [
      'Use execFile() or spawn() with argument arrays',
      'Validate and sanitize all user inputs',
      'Implement allowlist for permitted commands',
    ],
    references: [
      'https://owasp.org/www-community/attacks/Command_Injection',
    ],
    cweId: 'CWE-78',
    tags: ['command-injection', 'template-literals', 'user-input'],
  },

  {
    id: 'ts_path_traversal_template',
    language: LanguageType.TYPESCRIPT,
    name: 'Path Traversal via Template Literals',
    description: 'File path construction with template literals allowing directory traversal',
    severity: 'high',
    pattern: {
      type: 'regex',
      matcher: {
        pattern: /fs\.\w+\s*\(\s*`[^`]*\$\{[^}]*\}[^`]*`/g,
        flags: 'g',
      },
    },
    examples: [
      {
        code: 'fs.readFile(`./uploads/${userFile}`);',
        vulnerable: true,
        description: 'Path traversal via template literal',
      },
      {
        code: 'fs.readFile(path.join("./uploads", path.basename(userFile)));',
        vulnerable: false,
        description: 'Safe path construction with validation',
      },
    ],
    remediation: [
      'Use path.join() and path.basename() for safe path construction',
      'Validate file paths against allowlists',
      'Implement path traversal protection',
    ],
    references: [
      'https://owasp.org/www-community/attacks/Path_Traversal',
    ],
    cweId: 'CWE-22',
    tags: ['path-traversal', 'template-literals', 'file-access'],
  },

  {
    id: 'ts_insecure_random',
    language: LanguageType.TYPESCRIPT,
    name: 'Cryptographically Insecure Random Number Generation',
    description: 'Usage of Math.random() for security-sensitive operations',
    severity: 'medium',
    pattern: {
      type: 'regex',
      matcher: {
        pattern: /Math\.random\(\)/g,
        flags: 'g',
      },
    },
    examples: [
      {
        code: 'const sessionId = Math.random().toString();',
        vulnerable: true,
        description: 'Predictable random number for security token',
      },
      {
        code: 'const sessionId = crypto.randomUUID();',
        vulnerable: false,
        description: 'Cryptographically secure random generation',
      },
    ],
    remediation: [
      'Use crypto.randomBytes() or crypto.randomUUID()',
      'Implement proper entropy for security tokens',
      'Review all random number usage in security contexts',
    ],
    references: [
      'https://nodejs.org/api/crypto.html#cryptorandombytessize-callback',
    ],
    cweId: 'CWE-330',
    tags: ['cryptography', 'random', 'predictability'],
  },
];

export const typeScriptScanner = new TypeScriptScanner();

// Register the scanner
import { scannerRegistry } from './base';
scannerRegistry.register(typeScriptScanner);
