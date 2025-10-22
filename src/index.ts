#!/usr/bin/env node
// MCP Security Scanner - CLI tool for scanning MCP servers
import { program } from 'commander';
import { promises as fs } from 'fs';
import * as path from 'path';

import { securityAnalyzer } from './analyzer/core';
import { reportGenerator } from './reports/generator';
import { selfValidationFramework } from './analyzer/self-validation';
import { AnalysisType, LanguageType, SeverityLevel, ReportFormat } from './types';
import { ScanOptions } from './types/scan';

// Configure CLI
program
  .name('mcp-scan')
  .description('Security scanner for Model Context Protocol (MCP) servers')
  .version('1.0.0');

// Main scan command
program
  .argument('<target>', 'MCP server directory or file to scan')
  .option('-t, --type <type>', 'Analysis type (static, dynamic, hybrid)', 'hybrid')
  .option('-l, --languages <languages>', 'Target languages (comma-separated)', 'typescript,javascript,python')
  .option('-s, --severity <level>', 'Minimum severity level', 'medium')
  .option('-o, --output <path>', 'Output directory for reports')
  .option('-f, --format <formats>', 'Report formats (comma-separated)', 'json,html,markdown')
  .option('--include <paths>', 'Include paths (comma-separated)')
  .option('--exclude <paths>', 'Exclude paths (comma-separated)', 'node_modules,.git,dist')
  .option('--max-depth <depth>', 'Maximum scan depth', '10')
  .option('--timeout <ms>', 'Scan timeout in milliseconds', '60000')
  .option('--self-scan', 'Perform self-validation scan')
  .option('--verbose', 'Enable verbose output')
  .action(async (target: string, options: any) => {
    try {
      console.log('🔍 MCP Security Scanner v1.0.0');
      console.log('=====================================');

      if (options.selfScan) {
        await performSelfScan(options);
        return;
      }

      // Validate target exists
      await validateTarget(target);

      // Configure scan options
      const scanOptions = buildScanOptions(target, options);
      
      console.log(`📁 Scanning: ${target}`);
      console.log(`🔧 Analysis: ${scanOptions.analysisType}`);
      console.log(`🌐 Languages: ${scanOptions.targetLanguages.join(', ')}`);
      
      // Perform security scan
      const scanResult = await securityAnalyzer.scanServer(target, scanOptions);
      
      // Display results
      console.log('\n📊 Scan Results:');
      console.log(`   Total vulnerabilities: ${scanResult.vulnerabilities.length}`);
      console.log(`   Risk score: ${scanResult.summary.riskScore}/100`);
      console.log(`   Files scanned: ${scanResult.targetInfo.totalFiles}`);
      console.log(`   Scan duration: ${scanResult.metadata.scanDuration}ms`);

      // Show vulnerability breakdown
      const breakdown = scanResult.summary.vulnerabilityBreakdown;
      console.log('\n🚨 Vulnerability Breakdown:');
      Object.entries(breakdown).forEach(([severity, count]) => {
        if (count > 0) {
          const icon = getSeverityIcon(severity as SeverityLevel);
          console.log(`   ${icon} ${severity.toUpperCase()}: ${count}`);
        }
      });

      // Show top vulnerabilities
      if (scanResult.vulnerabilities.length > 0) {
        console.log('\n🔍 Top Vulnerabilities:');
        scanResult.vulnerabilities
          .slice(0, 5)
          .forEach((vuln, index) => {
            const icon = getSeverityIcon(vuln.severity);
            console.log(`   ${index + 1}. ${icon} ${vuln.title}`);
            console.log(`      📂 ${path.basename(vuln.location.file)}:${vuln.location.line}`);
          });
      }

      // Generate reports if requested
      if (options.output) {
        console.log('\n📄 Generating Reports...');
        const formats = options.format.split(',').map((f: string) => f.trim() as ReportFormat);
        const reportFiles = await reportGenerator.generateMultipleReports(
          scanResult,
          options.output,
          formats
        );
        
        console.log('   Generated reports:');
        reportFiles.forEach(file => {
          console.log(`   📄 ${path.basename(file)}`);
        });
      }

      // Show recommendations
      if (scanResult.summary.recommendedActions.length > 0) {
        console.log('\n💡 Recommendations:');
        scanResult.summary.recommendedActions.forEach(action => {
          console.log(`   • ${action}`);
        });
      }

      console.log('\n✅ Scan completed successfully!');
      
      // Exit with appropriate code
      const criticalCount = scanResult.vulnerabilities.filter(v => v.severity === SeverityLevel.CRITICAL).length;
      process.exit(criticalCount > 0 ? 1 : 0);

    } catch (error) {
      console.error('❌ Scan failed:', error instanceof Error ? error.message : 'Unknown error');
      if (options.verbose) {
        console.error(error);
      }
      process.exit(1);
    }
  });

async function validateTarget(target: string): Promise<void> {
  try {
    await fs.access(target);
  } catch {
    throw new Error(`Target not found: ${target}`);
  }
}

function buildScanOptions(target: string, options: any): ScanOptions {
  return {
    analysisType: options.type as AnalysisType,
    targetLanguages: options.languages.split(',').map((l: string) => l.trim() as LanguageType),
    includePaths: options.include ? options.include.split(',').map((p: string) => p.trim()) : [],
    excludePaths: options.exclude.split(',').map((p: string) => p.trim()),
    maxDepth: parseInt(options.maxDepth),
    timeout: parseInt(options.timeout),
    concurrent: false,
    maxConcurrency: 1,
    enableDynamicAnalysis: options.type !== 'static',
    enableStaticAnalysis: options.type !== 'dynamic',
    severityThreshold: options.severity as SeverityLevel,
  };
}

async function performSelfScan(options: any): Promise<void> {
  console.log('🔄 Performing self-validation scan...');
  
  const projectRoot = process.cwd();
  const selfScanResult = await selfValidationFramework.performSelfScan(projectRoot);
  
  console.log('\n📊 Self-Scan Results:');
  console.log(`   Security Score: ${selfScanResult.analysis.securityScore}/100`);
  console.log(`   Status: ${selfScanResult.passed ? '✅ PASSED' : '❌ FAILED'}`);
  console.log(`   Total Issues: ${selfScanResult.analysis.totalVulnerabilities}`);
  console.log(`   Critical Issues: ${selfScanResult.analysis.criticalVulnerabilities}`);
  
  if (selfScanResult.analysis.scannerSpecificIssues.length > 0) {
    console.log('\n⚠️  Scanner-Specific Issues:');
    selfScanResult.analysis.scannerSpecificIssues.forEach(issue => {
      console.log(`   • ${issue.description}`);
    });
  }
  
  if (options.output) {
    const reportPath = path.join(options.output, 'self-scan-report.md');
    await fs.writeFile(reportPath, selfScanResult.report);
    console.log(`\n📄 Self-scan report saved: ${reportPath}`);
  }
  
  process.exit(selfScanResult.passed ? 0 : 1);
}

function getSeverityIcon(severity: SeverityLevel): string {
  switch (severity) {
    case SeverityLevel.CRITICAL: return '🔴';
    case SeverityLevel.HIGH: return '🟠';
    case SeverityLevel.MEDIUM: return '🟡';
    case SeverityLevel.LOW: return '🔵';
    case SeverityLevel.INFO: return '⚪';
    default: return '⚪';
  }
}

// Parse command line arguments
if (require.main === module) {
  program.parse();
}

export * from './analyzer/core';
export * from './database/vulnerability-patterns';
export * from './database/cve-mappings';
export * from './vulnerabilities/command-injection';
export * from './vulnerabilities/path-traversal';
export * from './vulnerabilities/prompt-injection';
export * from './vulnerabilities/tool-poisoning';
export * from './scanners/typescript';
export * from './scanners/python';
export * from './sandbox/environment';
export * from './analyzer/dynamic';
