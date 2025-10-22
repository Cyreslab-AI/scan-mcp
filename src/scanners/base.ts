// Base language scanner for extensible multi-language security analysis
import { 
  LanguageAST, 
  LanguageScanner as ILanguageScanner,
  SymbolExtraction,
  LanguageVulnerabilityPattern,
  LanguageVulnerability,
  ParseError,
  ASTMetadata
} from '@/types/language';
import { LanguageType } from '@/types';

export abstract class LanguageScanner implements ILanguageScanner {
  abstract readonly language: LanguageType;
  abstract readonly extensions: string[];

  /**
   * Parse a file and return its AST representation
   */
  abstract parseFile(filePath: string, content: string): Promise<LanguageAST>;

  /**
   * Extract symbols from the AST
   */
  abstract extractSymbols(ast: LanguageAST): SymbolExtraction;

  /**
   * Get language-specific vulnerability patterns
   */
  abstract getVulnerabilityPatterns(): LanguageVulnerabilityPattern[];

  /**
   * Analyze code for vulnerabilities using patterns
   */
  abstract analyzeCode(ast: LanguageAST, patterns: LanguageVulnerabilityPattern[]): LanguageVulnerability[];

  /**
   * Check if this scanner supports the given file extension
   */
  supportsExtension(extension: string): boolean {
    return this.extensions.includes(extension.toLowerCase());
  }

  /**
   * Check if this scanner supports the given file path
   */
  supportsFile(filePath: string): boolean {
    const extension = this.extractExtension(filePath);
    return this.supportsExtension(extension);
  }

  /**
   * Extract file extension from path
   */
  protected extractExtension(filePath: string): string {
    const lastDot = filePath.lastIndexOf('.');
    return lastDot !== -1 ? filePath.substring(lastDot) : '';
  }

  /**
   * Calculate code complexity metrics
   */
  protected calculateComplexity(ast: LanguageAST): number {
    return this.countNodes(ast.ast) / 10; // Simple complexity metric
  }

  /**
   * Count AST nodes recursively
   */
  protected countNodes(node: any): number {
    let count = 1;
    
    if (node.body && Array.isArray(node.body)) {
      for (const child of node.body) {
        count += this.countNodes(child);
      }
    }

    if (node.children && Array.isArray(node.children)) {
      for (const child of node.children) {
        count += this.countNodes(child);
      }
    }

    return count;
  }

  /**
   * Extract imports from AST
   */
  protected extractImports(ast: any): Array<{ source: string; imports: string[] }> {
    const imports: Array<{ source: string; imports: string[] }> = [];
    
    // This is a simplified implementation - would need proper AST traversal
    if (ast.body) {
      for (const node of ast.body) {
        if (node.type === 'ImportDeclaration') {
          imports.push({
            source: node.source?.value || 'unknown',
            imports: node.specifiers?.map((spec: any) => spec.local?.name || 'unknown') || [],
          });
        }
      }
    }

    return imports;
  }

  /**
   * Extract exports from AST
   */
  protected extractExports(ast: any): Array<{ name: string; type: string }> {
    const exports: Array<{ name: string; type: string }> = [];
    
    // This is a simplified implementation - would need proper AST traversal
    if (ast.body) {
      for (const node of ast.body) {
        if (node.type === 'ExportNamedDeclaration') {
          if (node.declaration) {
            if (node.declaration.type === 'FunctionDeclaration') {
              exports.push({
                name: node.declaration.id?.name || 'anonymous',
                type: 'function',
              });
            } else if (node.declaration.type === 'VariableDeclaration') {
              for (const declarator of node.declaration.declarations) {
                exports.push({
                  name: declarator.id?.name || 'unknown',
                  type: 'variable',
                });
              }
            }
          }
        } else if (node.type === 'ExportDefaultDeclaration') {
          exports.push({
            name: 'default',
            type: 'default',
          });
        }
      }
    }

    return exports;
  }

  /**
   * Create parse error object
   */
  protected createParseError(
    message: string, 
    line: number = 0, 
    column: number = 0, 
    severity: 'error' | 'warning' = 'error'
  ): ParseError {
    return {
      message,
      line,
      column,
      severity,
    };
  }

  /**
   * Create AST metadata
   */
  protected createMetadata(
    parseTime: number,
    nodeCount: number,
    dependencies: string[],
    imports: any[],
    exports: any[]
  ): ASTMetadata {
    return {
      parseTime,
      nodeCount,
      complexity: Math.max(1, Math.floor(nodeCount / 10)),
      dependencies,
      imports: imports.map(imp => ({
        source: imp.source,
        imports: imp.imports.map((name: string) => ({ name, alias: undefined, type: 'named' as const })),
        location: { start: { line: 1, column: 0 }, end: { line: 1, column: 0 } },
        dynamic: false,
      })),
      exports: exports.map(exp => ({
        name: exp.name,
        type: exp.type === 'default' ? 'default' as const : 'named' as const,
        location: { start: { line: 1, column: 0 }, end: { line: 1, column: 0 } },
      })),
    };
  }

  /**
   * Validate AST structure
   */
  protected validateAST(ast: any): boolean {
    return ast && typeof ast === 'object' && ast.type;
  }

  /**
   * Get scanner metadata
   */
  getMetadata(): ScannerMetadata {
    return {
      language: this.language,
      extensions: this.extensions,
      version: '1.0.0',
      capabilities: this.getCapabilities(),
    };
  }

  /**
   * Get scanner capabilities
   */
  protected getCapabilities(): string[] {
    return [
      'ast_parsing',
      'symbol_extraction',
      'vulnerability_detection',
      'static_analysis',
    ];
  }
}

export interface ScannerMetadata {
  language: LanguageType;
  extensions: string[];
  version: string;
  capabilities: string[];
}

// Scanner registry for managing multiple language scanners
export class ScannerRegistry {
  private scanners: Map<LanguageType, LanguageScanner> = new Map();

  /**
   * Register a language scanner
   */
  register(scanner: LanguageScanner): void {
    this.scanners.set(scanner.language, scanner);
  }

  /**
   * Get scanner for language
   */
  getScanner(language: LanguageType): LanguageScanner | undefined {
    return this.scanners.get(language);
  }

  /**
   * Get scanner for file path
   */
  getScannerForFile(filePath: string): LanguageScanner | undefined {
    for (const scanner of this.scanners.values()) {
      if (scanner.supportsFile(filePath)) {
        return scanner;
      }
    }
    return undefined;
  }

  /**
   * Get all registered scanners
   */
  getAllScanners(): LanguageScanner[] {
    return Array.from(this.scanners.values());
  }

  /**
   * Get supported languages
   */
  getSupportedLanguages(): LanguageType[] {
    return Array.from(this.scanners.keys());
  }

  /**
   * Get supported file extensions
   */
  getSupportedExtensions(): string[] {
    const extensions: string[] = [];
    for (const scanner of this.scanners.values()) {
      extensions.push(...scanner.extensions);
    }
    return [...new Set(extensions)]; // Remove duplicates
  }
}

export const scannerRegistry = new ScannerRegistry();
