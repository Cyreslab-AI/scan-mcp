// Python language scanner for MCP security analysis
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

export class PythonScanner extends LanguageScanner {
  readonly language = LanguageType.PYTHON;
  readonly extensions = ['.py', '.pyw'];

  async parseFile(filePath: string, content: string): Promise<LanguageAST> {
    const startTime = Date.now();
    const parseErrors: any[] = [];

    try {
      // For Python, we'll create a simple AST structure since we don't have a Python parser
      // In production, you'd use a Python AST parser like @babel/parser with Python plugin
      const ast = this.createSimplePythonAST(content);

      const nodeCount = this.countNodes(ast);
      const imports = this.extractPythonImports(content);
      const exports = this.extractPythonExports(content);
      const dependencies = this.extractDependencies(imports);

      return {
        language: this.language,
        filePath,
        ast,
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

      return {
        language: this.language,
        filePath,
        ast: {
          type: 'Module',
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
    const content = ast.ast.properties?.['content'] as string || '';
    const functions = this.extractPythonFunctions(content);
    const classes = this.extractPythonClasses(content);
    const variables = this.extractPythonVariables(content);

    return {
      functions,
      classes,
      variables,
      types: [], // Python doesn't have explicit type declarations like TypeScript
      interfaces: [], // Python uses duck typing
      modules: [], // TODO: Extract module information
    };
  }

  getVulnerabilityPatterns(): LanguageVulnerabilityPattern[] {
    return PYTHON_VULNERABILITY_PATTERNS;
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

  private createSimplePythonAST(content: string): ASTNode {
    // Simple Python AST representation
    // In production, would use proper Python parser
    const lines = content.split('\n');
    
    return {
      type: 'Module',
      start: 0,
      end: content.length,
      loc: {
        start: { line: 1, column: 0 },
        end: { line: lines.length, column: 0 },
      },
      children: [],
      properties: { content, lines },
    };
  }

  private extractPythonImports(content: string): Array<{ source: string; imports: string[] }> {
    const imports: Array<{ source: string; imports: string[] }> = [];
    const importPatterns = [
      /^import\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)/gm,
      /^from\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\s+import\s+([^#\n]+)/gm,
    ];

    // Simple import statements
    if (importPatterns[0]) {
      for (const match of content.matchAll(importPatterns[0])) {
        if (match[1]) {
          imports.push({
            source: match[1],
            imports: [match[1]],
          });
        }
      }
    }

    // From...import statements
    if (importPatterns[1]) {
      for (const match of content.matchAll(importPatterns[1])) {
        if (match[1] && match[2]) {
          const importNames = match[2].split(',').map(name => name.trim());
          imports.push({
            source: match[1],
            imports: importNames,
          });
        }
      }
    }

    return imports;
  }

  private extractPythonExports(content: string): Array<{ name: string; type: string }> {
    const exports: Array<{ name: string; type: string }> = [];
    
    // In Python, exports are typically functions/classes defined at module level
    // Extract from __all__ if present
    const allPattern = /__all__\s*=\s*\[(.*?)\]/s;
    const allMatch = content.match(allPattern);
    
    if (allMatch && allMatch[1]) {
      const exportNames = allMatch[1].match(/['"`]([^'"`]+)['"`]/g);
      if (exportNames) {
        for (const name of exportNames) {
          const cleanName = name.replace(/['"`]/g, '');
          exports.push({
            name: cleanName,
            type: 'named',
          });
        }
      }
    }

    return exports;
  }

  private extractPythonFunctions(content: string): FunctionDeclaration[] {
    const functions: FunctionDeclaration[] = [];
    const functionPattern = /^(\s*)def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*:/gm;
    const matches = content.matchAll(functionPattern);

    for (const match of matches) {
      if (match[2]) {
        const parameters = this.parsePythonParameters(match[3] || '');
        const lineNumber = content.substring(0, match.index).split('\n').length;
        
        functions.push({
          name: match[2],
          parameters,
          body: [], // TODO: Extract function body
          location: {
            start: { line: lineNumber, column: 0 },
            end: { line: lineNumber, column: match[0].length },
          },
          modifiers: [], // TODO: Extract decorators as modifiers
          isAsync: false, // TODO: Detect async def
          isGenerator: false, // TODO: Detect generators
        });
      }
    }

    return functions;
  }

  private extractPythonClasses(content: string): ClassDeclaration[] {
    const classes: ClassDeclaration[] = [];
    const classPattern = /^(\s*)class\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\(([^)]*)\))?\s*:/gm;
    const matches = content.matchAll(classPattern);

    for (const match of matches) {
      if (match[2]) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        
        classes.push({
          name: match[2],
          ...(match[3] && { superClass: match[3] }),
          interfaces: [], // Python doesn't have explicit interfaces
          members: [], // TODO: Extract methods and attributes
          location: {
            start: { line: lineNumber, column: 0 },
            end: { line: lineNumber, column: match[0].length },
          },
          modifiers: [], // TODO: Extract decorators
        });
      }
    }

    return classes;
  }

  private extractPythonVariables(content: string): VariableDeclaration[] {
    const variables: VariableDeclaration[] = [];
    // Simple variable assignment pattern (module level)
    const varPattern = /^([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)$/gm;
    const matches = content.matchAll(varPattern);

    for (const match of matches) {
      if (match[1]) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        
        variables.push({
          name: match[1],
          location: {
            start: { line: lineNumber, column: 0 },
            end: { line: lineNumber, column: match[0].length },
          },
          scope: 'global',
          mutable: true, // Python variables are mutable by default
          kind: 'var', // Python doesn't distinguish var/let/const
        });
      }
    }

    return variables;
  }

  private parsePythonParameters(paramString: string): any[] {
    if (!paramString.trim()) return [];
    
    const params = paramString.split(',').map(p => p.trim());
    return params.map(param => {
      const parts = param.split('=');
      const firstPart = parts[0];
      const secondPart = parts[1];
      return {
        name: firstPart ? firstPart.trim() : '',
        optional: parts.length > 1,
        defaultValue: parts.length > 1 && secondPart ? secondPart.trim() : undefined,
        rest: param.startsWith('*'),
      };
    });
  }

  private extractDependencies(imports: Array<{ source: string; imports: string[] }>): string[] {
    return imports
      .map(imp => imp.source)
      .filter(source => !source.startsWith('.') && !source.startsWith('/'));
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
    const lastLine = lines[lines.length - 1];
    return {
      line: lines.length - 1,
      column: lastLine ? lastLine.length : 0,
    };
  }

  protected override getCapabilities(): string[] {
    return [
      ...super.getCapabilities(),
      'import_analysis',
      'decorator_detection',
      'async_analysis',
      'type_hint_support',
    ];
  }
}

// Python-specific vulnerability patterns
const PYTHON_VULNERABILITY_PATTERNS: LanguageVulnerabilityPattern[] = [
  {
    id: 'py_subprocess_shell_injection',
    language: LanguageType.PYTHON,
    name: 'Subprocess Shell Injection',
    description: 'Use of subprocess with shell=True and user input',
    severity: 'critical',
    pattern: {
      type: 'regex',
      matcher: {
        pattern: /subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True[^)]*\)/g,
        flags: 'g',
      },
    },
    examples: [
      {
        code: 'subprocess.call(user_command, shell=True)',
        vulnerable: true,
        description: 'Shell injection via subprocess with shell=True',
      },
      {
        code: 'subprocess.run(["ls", user_dir])',
        vulnerable: false,
        description: 'Safe subprocess with argument list',
      },
    ],
    remediation: [
      'Use subprocess with argument lists instead of shell=True',
      'Validate and sanitize all user inputs',
      'Use shlex.quote() for shell escaping if shell=True is necessary',
    ],
    references: [
      'https://docs.python.org/3/library/subprocess.html#security-considerations',
    ],
    cweId: 'CWE-78',
    tags: ['subprocess', 'shell-injection', 'command-execution'],
  },

  {
    id: 'py_eval_exec_injection',
    language: LanguageType.PYTHON,
    name: 'Code Injection via eval/exec',
    description: 'Direct execution of user input through eval() or exec()',
    severity: 'critical',
    pattern: {
      type: 'regex',
      matcher: {
        pattern: /(eval|exec)\s*\([^)]*user[^)]*\)|(eval|exec)\s*\([^)]*input[^)]*\)/gi,
        flags: 'gi',
      },
    },
    examples: [
      {
        code: 'eval(user_input)',
        vulnerable: true,
        description: 'Direct code execution from user input',
      },
      {
        code: 'ast.literal_eval(user_input)',
        vulnerable: false,
        description: 'Safe evaluation of literals only',
      },
    ],
    remediation: [
      'Use ast.literal_eval() for safe literal evaluation',
      'Implement proper input validation and sanitization',
      'Use allowlist-based validation for dynamic code',
    ],
    references: [
      'https://docs.python.org/3/library/ast.html#ast.literal_eval',
    ],
    cweId: 'CWE-94',
    tags: ['code-injection', 'eval', 'exec'],
  },

  {
    id: 'py_path_traversal',
    language: LanguageType.PYTHON,
    name: 'Path Traversal in File Operations',
    description: 'File operations with unsanitized user input allowing path traversal',
    severity: 'high',
    pattern: {
      type: 'regex',
      matcher: {
        pattern: /open\s*\([^)]*\+[^)]*\)|os\.path\.join\s*\([^)]*user[^)]*\)/gi,
        flags: 'gi',
      },
    },
    examples: [
      {
        code: 'open(base_path + user_file, "r")',
        vulnerable: true,
        description: 'Path concatenation allowing traversal',
      },
      {
        code: 'open(os.path.join(base_path, os.path.basename(user_file)), "r")',
        vulnerable: false,
        description: 'Safe path construction with basename',
      },
    ],
    remediation: [
      'Use os.path.basename() to extract filename only',
      'Validate file paths against allowlists',
      'Use os.path.abspath() and check path prefix',
    ],
    references: [
      'https://docs.python.org/3/library/os.path.html#os.path.basename',
    ],
    cweId: 'CWE-22',
    tags: ['path-traversal', 'file-operations'],
  },

  {
    id: 'py_pickle_deserialization',
    language: LanguageType.PYTHON,
    name: 'Unsafe Pickle Deserialization',
    description: 'Deserialization of untrusted data using pickle module',
    severity: 'critical',
    pattern: {
      type: 'regex',
      matcher: {
        pattern: /pickle\.loads?\s*\([^)]*\)|pickle\.load\s*\([^)]*user[^)]*\)/gi,
        flags: 'gi',
      },
    },
    examples: [
      {
        code: 'pickle.loads(user_data)',
        vulnerable: true,
        description: 'Unsafe deserialization of user data',
      },
      {
        code: 'json.loads(user_data)',
        vulnerable: false,
        description: 'Safe JSON deserialization',
      },
    ],
    remediation: [
      'Use JSON or other safe serialization formats',
      'Implement cryptographic signatures for pickle data',
      'Validate data source before deserialization',
    ],
    references: [
      'https://docs.python.org/3/library/pickle.html#what-can-be-pickled-and-unpickled',
    ],
    cweId: 'CWE-502',
    tags: ['deserialization', 'pickle', 'untrusted-data'],
  },

  {
    id: 'py_sql_injection',
    language: LanguageType.PYTHON,
    name: 'SQL Injection in Database Queries',
    description: 'SQL queries constructed with string formatting and user input',
    severity: 'high',
    pattern: {
      type: 'regex',
      matcher: {
        pattern: /execute\s*\(\s*f?['"`][^'"`]*\{[^}]*user[^}]*\}[^'"`]*['"`]/gi,
        flags: 'gi',
      },
    },
    examples: [
      {
        code: 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        vulnerable: true,
        description: 'SQL injection via f-string formatting',
      },
      {
        code: 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        vulnerable: false,
        description: 'Safe parameterized query',
      },
    ],
    remediation: [
      'Use parameterized queries with placeholders',
      'Validate and sanitize all user inputs',
      'Use ORM with built-in protection',
    ],
    references: [
      'https://owasp.org/www-community/attacks/SQL_Injection',
    ],
    cweId: 'CWE-89',
    tags: ['sql-injection', 'database', 'user-input'],
  },
];

export const pythonScanner = new PythonScanner();

// Register the scanner
import { scannerRegistry } from './base';
scannerRegistry.register(pythonScanner);
