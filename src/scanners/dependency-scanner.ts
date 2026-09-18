// Dependency vulnerability scanning via OSV.dev (https://osv.dev) - a free, public, no-auth-key
// API. Previously the scanner had no dependency-vulnerability checking at all: `targetInfo.dependencies`
// was hardcoded to `[]` with a `// TODO: Extract from package files` comment in analyzer/core.ts.
import { promises as fs } from 'fs';
import * as path from 'path';

import { DependencyInfo } from '@/types/scan';
import { Vulnerability, RemediationGuidance, CVEReference } from '@/types/vulnerability';
import { SeverityLevel, VulnerabilityType } from '@/types';

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns';
const REQUEST_TIMEOUT_MS = 15000;
const MAX_VULN_DETAIL_LOOKUPS = 50;
const DETAIL_LOOKUP_CONCURRENCY = 8;

interface ParsedDependency {
  name: string;
  version?: string; // Concrete version, if one could be determined.
  rawVersion: string; // As written in the manifest.
  ecosystem: 'npm' | 'PyPI';
  source: 'npm' | 'pip';
  manifestFile: string;
}

interface OsvSeverityEntry {
  type: string;
  score: string;
}

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: OsvSeverityEntry[];
  database_specific?: { severity?: string };
  references?: Array<{ url: string }>;
}

interface OsvBatchResultEntry {
  vulns?: Array<{ id: string; modified?: string }>;
}

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Best-effort extraction of a concrete `major.minor.patch` version out of an npm-style semver
 * range string (e.g. "^1.2.3", "~1.2", ">=1.2.3 <2.0.0"). This is intentionally simple (no
 * `semver` package type declarations are installed) - it is only used as a fallback when a
 * package-lock.json isn't available to give the exact resolved version.
 */
function stripSemverRange(range: string): string | undefined {
  const match = range.match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!match) return undefined;
  const [, major, minor, patch] = match;
  return `${major}.${minor}.${patch ?? '0'}`;
}

async function findManifestFiles(rootPath: string, excludePaths: string[], maxDepth: number): Promise<string[]> {
  const stats = await fs.stat(rootPath).catch(() => null);
  if (!stats) return [];

  if (!stats.isDirectory()) {
    // A single-file scan target - just check the containing directory.
    rootPath = path.dirname(rootPath);
  }

  const found: string[] = [];
  const skipDirs = new Set(['node_modules', '.git', 'dist', 'build', '.next', ...excludePaths]);

  const walk = async (dir: string, depth: number): Promise<void> => {
    if (depth > maxDepth) return;
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) continue;
        await walk(path.join(dir, entry.name), depth + 1);
      } else if (entry.isFile()) {
        if (entry.name === 'package.json' || entry.name.toLowerCase() === 'requirements.txt') {
          found.push(path.join(dir, entry.name));
        }
      }
    }
  };

  await walk(rootPath, 0);
  return found;
}

async function parseNpmManifest(manifestPath: string): Promise<ParsedDependency[]> {
  const raw = await fs.readFile(manifestPath, 'utf-8');
  let pkg: any;
  try {
    pkg = JSON.parse(raw);
  } catch {
    return [];
  }

  const lockVersions = await readNpmLockVersions(path.dirname(manifestPath));
  const deps: ParsedDependency[] = [];
  const sections = [pkg.dependencies, pkg.devDependencies, pkg.optionalDependencies];

  for (const section of sections) {
    if (!section || typeof section !== 'object') continue;
    for (const [name, rangeRaw] of Object.entries(section)) {
      const range = String(rangeRaw);
      if (range.startsWith('file:') || range.startsWith('link:') || range.startsWith('git')) continue; // Not resolvable via OSV by version.

      const resolved = lockVersions.get(name) || stripSemverRange(range);
      deps.push({
        name,
        version: resolved,
        rawVersion: range,
        ecosystem: 'npm',
        source: 'npm',
        manifestFile: manifestPath,
      });
    }
  }

  return deps;
}

async function readNpmLockVersions(dir: string): Promise<Map<string, string>> {
  const versions = new Map<string, string>();
  const lockPath = path.join(dir, 'package-lock.json');
  const raw = await fs.readFile(lockPath, 'utf-8').catch(() => null);
  if (!raw) return versions;

  try {
    const lock = JSON.parse(raw);
    if (lock.packages && typeof lock.packages === 'object') {
      // npm v7+ lockfile format: keys are paths like "node_modules/lodash" or scoped equivalents.
      for (const [key, value] of Object.entries<any>(lock.packages)) {
        if (!key || !key.startsWith('node_modules/')) continue;
        const name = key.replace(/^.*node_modules\//, '');
        if (value?.version && !versions.has(name)) {
          versions.set(name, value.version);
        }
      }
    } else if (lock.dependencies && typeof lock.dependencies === 'object') {
      // Legacy lockfile v1 format.
      for (const [name, value] of Object.entries<any>(lock.dependencies)) {
        if (value?.version) versions.set(name, value.version);
      }
    }
  } catch {
    // Ignore malformed lockfiles - fall back to manifest range coercion.
  }

  return versions;
}

function parsePythonRequirement(line: string): { name: string; version?: string } | null {
  const stripped = line.split('#')[0]?.trim();
  if (!stripped || stripped.startsWith('-')) return null;

  const match = stripped.match(/^([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9.\-*+!]*)/);
  if (!match || !match[1]) return null;

  const name = match[1];
  const operator = match[2];
  const version = match[3];

  // Only a pinned "==" version can be trusted as "the" installed version for a static scan.
  if (operator === '==' && version) {
    return { name, version };
  }
  return { name };
}

async function parsePythonManifest(manifestPath: string): Promise<ParsedDependency[]> {
  const raw = await fs.readFile(manifestPath, 'utf-8').catch(() => null);
  if (!raw) return [];

  const deps: ParsedDependency[] = [];
  for (const line of raw.split('\n')) {
    const parsed = parsePythonRequirement(line);
    if (!parsed) continue;
    deps.push({
      name: parsed.name,
      version: parsed.version,
      rawVersion: line.trim(),
      ecosystem: 'PyPI',
      source: 'pip',
      manifestFile: manifestPath,
    });
  }

  return deps;
}

function mapOsvSeverity(vuln: OsvVulnerability): SeverityLevel {
  const dbSeverity = vuln.database_specific?.severity?.toUpperCase();
  if (dbSeverity === 'CRITICAL') return SeverityLevel.CRITICAL;
  if (dbSeverity === 'HIGH') return SeverityLevel.HIGH;
  if (dbSeverity === 'MODERATE' || dbSeverity === 'MEDIUM') return SeverityLevel.MEDIUM;
  if (dbSeverity === 'LOW') return SeverityLevel.LOW;

  if (vuln.severity && vuln.severity.length > 0) {
    // Has CVSS data but we didn't classify it above - treat as at least HIGH rather than
    // silently under-reporting a scored vulnerability.
    return SeverityLevel.HIGH;
  }

  return SeverityLevel.MEDIUM;
}

function severityToScore(severity: SeverityLevel): number {
  switch (severity) {
    case SeverityLevel.CRITICAL: return 9.5;
    case SeverityLevel.HIGH: return 8.0;
    case SeverityLevel.MEDIUM: return 5.5;
    case SeverityLevel.LOW: return 2.0;
    case SeverityLevel.INFO: return 0.0;
    default: return 0.0;
  }
}

function buildRemediation(dep: ParsedDependency, fixedVersions: string[]): RemediationGuidance {
  const steps = [`Upgrade "${dep.name}" from ${dep.version ?? dep.rawVersion} to a patched version.`];
  if (fixedVersions.length > 0) {
    steps.push(`Known fixed version(s): ${fixedVersions.join(', ')}`);
  }
  steps.push(dep.source === 'npm' ? 'Run `npm audit fix` or update the version in package.json and reinstall.' : 'Update the pinned version in requirements.txt and reinstall.');

  return {
    title: `Upgrade vulnerable dependency ${dep.name}`,
    description: `${dep.name}@${dep.version ?? dep.rawVersion} has a known, publicly disclosed vulnerability.`,
    steps,
    references: ['https://osv.dev'],
    effort: 'low',
    priority: 1,
  };
}

async function fetchVulnDetails(ids: string[]): Promise<Map<string, OsvVulnerability>> {
  const details = new Map<string, OsvVulnerability>();
  const capped = ids.slice(0, MAX_VULN_DETAIL_LOOKUPS);

  for (let i = 0; i < capped.length; i += DETAIL_LOOKUP_CONCURRENCY) {
    const chunk = capped.slice(i, i + DETAIL_LOOKUP_CONCURRENCY);
    const results = await Promise.allSettled(chunk.map(async id => {
      const res = await fetchWithTimeout(`${OSV_VULN_URL}/${encodeURIComponent(id)}`, {}, REQUEST_TIMEOUT_MS);
      if (!res.ok) throw new Error(`OSV vuln lookup failed for ${id}: ${res.status}`);
      return (await res.json()) as OsvVulnerability;
    }));

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value?.id) {
        details.set(result.value.id, result.value);
      }
    }
  }

  return details;
}

export interface DependencyScanResult {
  dependencies: DependencyInfo[];
  vulnerabilities: Vulnerability[];
  warnings: string[];
}

export class DependencyScanner {
  /**
   * Discover package.json/requirements.txt manifests under `rootPath`, then check every
   * dependency against OSV.dev's free vulnerability database.
   */
  async scan(rootPath: string, excludePaths: string[] = [], maxDepth = 10): Promise<DependencyScanResult> {
    const warnings: string[] = [];
    const manifests = await findManifestFiles(rootPath, excludePaths, maxDepth);

    const allDeps: ParsedDependency[] = [];
    for (const manifest of manifests) {
      try {
        if (path.basename(manifest) === 'package.json') {
          allDeps.push(...await parseNpmManifest(manifest));
        } else {
          allDeps.push(...await parsePythonManifest(manifest));
        }
      } catch (error) {
        warnings.push(`Failed to parse manifest ${manifest}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    if (allDeps.length === 0) {
      return { dependencies: [], vulnerabilities: [], warnings };
    }

    const queryable = allDeps.filter(d => !!d.version);
    let batchResults: OsvBatchResultEntry[] = [];

    if (queryable.length > 0) {
      try {
        const body = JSON.stringify({
          queries: queryable.map(d => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })),
        });
        const res = await fetchWithTimeout(OSV_BATCH_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body,
        }, REQUEST_TIMEOUT_MS);

        if (!res.ok) {
          warnings.push(`OSV.dev querybatch returned HTTP ${res.status}`);
        } else {
          const json = await res.json() as { results?: OsvBatchResultEntry[] };
          batchResults = json.results || [];
        }
      } catch (error) {
        warnings.push(`OSV.dev lookup failed (network error): ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    const idsByDepIndex = new Map<number, string[]>();
    const allIds = new Set<string>();
    queryable.forEach((_dep, i) => {
      const ids = (batchResults[i]?.vulns || []).map(v => v.id);
      if (ids.length > 0) {
        idsByDepIndex.set(i, ids);
        ids.forEach(id => allIds.add(id));
      }
    });

    const details = allIds.size > 0
      ? await fetchVulnDetails([...allIds]).catch(() => new Map<string, OsvVulnerability>())
      : new Map<string, OsvVulnerability>();

    const vulnerabilities: Vulnerability[] = [];
    const dependencies: DependencyInfo[] = allDeps.map(dep => ({
      name: dep.name,
      version: dep.version ?? dep.rawVersion,
      source: dep.source,
      vulnerabilities: [] as string[],
      outdated: false,
    }));

    queryable.forEach((dep, i) => {
      const ids = idsByDepIndex.get(i);
      if (!ids) return;

      const depInfo = dependencies.find(d => d.name === dep.name && d.version === (dep.version ?? dep.rawVersion));
      if (depInfo) depInfo.vulnerabilities = ids;

      for (const id of ids) {
        const detail = details.get(id);
        const severity = detail ? mapOsvSeverity(detail) : SeverityLevel.MEDIUM;
        const cveAliases = (detail?.aliases || []).filter(a => a.startsWith('CVE-'));
        const cveReferences: CVEReference[] = [
          {
            id,
            url: `https://osv.dev/vulnerability/${id}`,
            description: detail?.summary || detail?.details || `OSV advisory ${id}`,
            score: severityToScore(severity),
          },
          ...cveAliases.map(cve => ({
            id: cve,
            url: `https://nvd.nist.gov/vuln/detail/${cve}`,
            description: detail?.summary || `Aliased CVE for OSV advisory ${id}`,
            score: severityToScore(severity),
          })),
        ];

        vulnerabilities.push({
          id: `osv_${id}_${Math.random().toString(36).substr(2, 6)}`,
          type: VulnerabilityType.DEPENDENCY_VULNERABILITY,
          severity,
          score: severityToScore(severity),
          title: `Known vulnerability in ${dep.name}@${dep.version}: ${id}`,
          description: detail?.summary || detail?.details || `${dep.name}@${dep.version} is affected by ${id}. See https://osv.dev/vulnerability/${id} for details.`,
          location: { file: dep.manifestFile, line: 0, column: 0 },
          remediation: buildRemediation(dep, []),
          cveReferences,
          context: { osvId: id, dependency: dep.name, version: dep.version, ecosystem: dep.ecosystem, detectionMethod: 'osv.dev' },
          detectedAt: new Date(),
          confidence: 0.9,
          falsePositiveRisk: 'low',
          tags: [VulnerabilityType.DEPENDENCY_VULNERABILITY, severity, dep.ecosystem],
        });
      }
    });

    return { dependencies, vulnerabilities, warnings };
  }
}

export const dependencyScanner = new DependencyScanner();
