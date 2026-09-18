// Dockerfile linter - real hadolint-equivalent checks using dockerfile-ast
//
// Previously `dockerfile-ast` was listed as a dependency but never imported anywhere in the
// codebase, so "Docker linting" was a complete no-op. This module actually parses a Dockerfile
// and checks a handful of well known best-practice rules (the same ones hadolint flags):
//   - unpinned FROM (no tag or digest, or ":latest")
//   - `apt-get update` / `apt-get install` split across layers (cache-busting / stale index)
//   - missing non-root USER
//   - ADD used where COPY would be safer/clearer
//   - secrets hardcoded in ENV/ARG
import { DockerfileParser, Dockerfile, From, Property } from 'dockerfile-ast';
import { Vulnerability, RemediationGuidance } from '@/types/vulnerability';
import { SeverityLevel, VulnerabilityType } from '@/types';

interface RuleHit {
  id: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  line: number; // 1-based
  column: number; // 0-based
  remediation: RemediationGuidance;
  references: string[];
  tags: string[];
}

const SECRET_NAME_RE = /pass(word)?|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential/i;
const ARCHIVE_EXT_RE = /\.(tar(\.(gz|bz2|xz))?|tgz|taz|tbz2?|txz)$/i;

export class DockerfileLinter {
  /**
   * Parse and lint a single Dockerfile, returning one Vulnerability per finding.
   */
  lint(filePath: string, content: string): Vulnerability[] {
    let dockerfile: Dockerfile;
    try {
      dockerfile = DockerfileParser.parse(content);
    } catch (_error) {
      // Malformed Dockerfile - nothing we can safely lint.
      return [];
    }

    const hits: RuleHit[] = [
      ...this.checkUnpinnedBaseImages(dockerfile),
      ...this.checkAptGetLayering(dockerfile),
      ...this.checkMissingNonRootUser(dockerfile),
      ...this.checkAddVsCopy(dockerfile),
      ...this.checkSecretsInEnvArg(dockerfile),
    ];

    return hits.map(hit => this.toVulnerability(hit, filePath));
  }

  private checkUnpinnedBaseImages(dockerfile: Dockerfile): RuleHit[] {
    const hits: RuleHit[] = [];
    const froms = dockerfile.getFROMs();
    const stageNames = new Set(
      froms.map(f => f.getBuildStage()).filter((name): name is string => !!name)
    );

    for (const from of froms) {
      const imageName = from.getImageName();
      if (!imageName) continue;
      if (imageName.toLowerCase() === 'scratch') continue;
      // Referencing an earlier build stage by name (multi-stage builds) - not a registry image.
      if (stageNames.has(imageName)) continue;

      const tag = from.getImageTag();
      const digest = from.getImageDigest();
      const range = from.getImageRange() || from.getRange();

      if (digest) continue; // Pinned by digest - as strict as it gets.
      if (tag && tag !== 'latest') continue; // Pinned to a concrete tag.

      hits.push({
        id: 'dockerfile_unpinned_base_image',
        title: 'Unpinned Docker base image',
        description: `FROM ${imageName}${tag ? `:${tag}` : ''} does not pin a specific version via a digest, and ` +
          `${tag === 'latest' ? 'explicitly uses the "latest" tag' : 'has no tag at all (defaults to "latest")'}. ` +
          `Builds are not reproducible and can silently pull in breaking or vulnerable changes.`,
        severity: SeverityLevel.HIGH,
        line: (range?.start.line ?? 0) + 1,
        column: range?.start.character ?? 0,
        remediation: {
          title: 'Pin the base image to an immutable version',
          description: 'Pin FROM instructions to a specific version tag, and preferably a content digest.',
          steps: [
            `Replace "FROM ${imageName}${tag ? `:${tag}` : ''}" with a specific version, e.g. "FROM ${imageName}:1.2.3"`,
            'For maximum reproducibility, pin by digest: FROM image@sha256:<digest>',
            'Use automated tooling (Dependabot/Renovate) to keep pinned versions up to date',
          ],
          references: ['https://docs.docker.com/build/building/best-practices/#pin-base-image-versions'],
          effort: 'low',
          priority: 2,
        },
        references: [
          'https://docs.docker.com/build/building/best-practices/#pin-base-image-versions',
          'https://github.com/hadolint/hadolint/wiki/DL3006',
        ],
        tags: ['dockerfile', 'supply-chain', 'reproducibility'],
      });
    }

    return hits;
  }

  private checkAptGetLayering(dockerfile: Dockerfile): RuleHit[] {
    const hits: RuleHit[] = [];
    const runInstructions = dockerfile.getInstructions().filter(i => i.getKeyword() === 'RUN');

    for (const run of runInstructions) {
      const raw = run.getArgumentsContent() || '';
      const hasUpdate = /apt(-get)?\s+update\b/i.test(raw);
      const hasInstall = /apt(-get)?\s+(install|upgrade|dist-upgrade)\b/i.test(raw);
      const range = run.getRange();
      const line = (range?.start.line ?? 0) + 1;
      const column = range?.start.character ?? 0;

      if (hasUpdate && !hasInstall) {
        hits.push({
          id: 'dockerfile_apt_update_without_install',
          title: 'apt-get update run in its own layer',
          description: '"apt-get update" is run without a corresponding "apt-get install" in the same RUN ' +
            'instruction. Because Docker caches each layer independently, a later layer that installs ' +
            'packages can silently reuse a stale package index from this layer.',
          severity: SeverityLevel.MEDIUM,
          line,
          column,
          remediation: {
            title: 'Combine apt-get update and install in a single RUN',
            description: 'Chain update and install together so the package index is always fresh when packages are installed.',
            steps: [
              'RUN apt-get update && apt-get install -y --no-install-recommends <packages> && rm -rf /var/lib/apt/lists/*',
            ],
            references: ['https://github.com/hadolint/hadolint/wiki/DL3009'],
            effort: 'low',
            priority: 3,
          },
          references: ['https://github.com/hadolint/hadolint/wiki/DL3009'],
          tags: ['dockerfile', 'caching', 'best-practice'],
        });
      }

      if (hasInstall && !hasUpdate && /apt(-get)?\s+install\b/i.test(raw)) {
        hits.push({
          id: 'dockerfile_apt_install_without_update',
          title: 'apt-get install without a preceding apt-get update',
          description: '"apt-get install" is run in this layer without "apt-get update" first, which risks ' +
            'installing from a missing or outdated package index (and can fail outright on a fresh base image).',
          severity: SeverityLevel.MEDIUM,
          line,
          column,
          remediation: {
            title: 'Always update before installing, in the same layer',
            description: 'Chain update and install together in a single RUN instruction.',
            steps: [
              'RUN apt-get update && apt-get install -y --no-install-recommends <packages> && rm -rf /var/lib/apt/lists/*',
            ],
            references: ['https://github.com/hadolint/hadolint/wiki/DL3009'],
            effort: 'low',
            priority: 3,
          },
          references: ['https://github.com/hadolint/hadolint/wiki/DL3009'],
          tags: ['dockerfile', 'caching', 'best-practice'],
        });
      }
    }

    return hits;
  }

  private checkMissingNonRootUser(dockerfile: Dockerfile): RuleHit[] {
    const userInstructions = dockerfile.getInstructions().filter(i => i.getKeyword() === 'USER');
    const froms = dockerfile.getFROMs();
    const anchor = froms[froms.length - 1]?.getRange() ?? dockerfile.getRange();
    const line = (anchor?.start.line ?? 0) + 1;
    const column = anchor?.start.character ?? 0;

    if (userInstructions.length === 0) {
      return [{
        id: 'dockerfile_missing_user',
        title: 'Container runs as root (no USER instruction)',
        description: 'This Dockerfile never switches to a non-root user, so the resulting container runs its ' +
          'process as root by default. A container escape or RCE in the application then grants root inside ' +
          '(and potentially outside, depending on the runtime) the container.',
        severity: SeverityLevel.HIGH,
        line,
        column,
        remediation: {
          title: 'Add a non-root USER',
          description: 'Create a dedicated user/group and switch to it before running the application.',
          steps: [
            'RUN addgroup --system app && adduser --system --ingroup app app',
            'USER app',
          ],
          references: ['https://docs.docker.com/build/building/best-practices/#user'],
          effort: 'low',
          priority: 2,
        },
        references: [
          'https://docs.docker.com/build/building/best-practices/#user',
          'https://github.com/hadolint/hadolint/wiki/DL3002',
        ],
        tags: ['dockerfile', 'least-privilege', 'container-security'],
      }];
    }

    const last = userInstructions[userInstructions.length - 1];
    const lastArg = last?.getArguments()[0]?.getValue();
    if (lastArg && (lastArg === 'root' || lastArg === '0' || lastArg === '0:0')) {
      const range = last!.getRange();
      return [{
        id: 'dockerfile_explicit_root_user',
        title: 'Container explicitly runs as root',
        description: `The final USER instruction sets the container's user to "${lastArg}" (root).`,
        severity: SeverityLevel.HIGH,
        line: (range?.start.line ?? 0) + 1,
        column: range?.start.character ?? 0,
        remediation: {
          title: 'Switch to a non-root user',
          description: 'Use a dedicated, unprivileged user for the final USER instruction.',
          steps: ['USER app  # instead of USER root / USER 0'],
          references: ['https://docs.docker.com/build/building/best-practices/#user'],
          effort: 'low',
          priority: 2,
        },
        references: ['https://docs.docker.com/build/building/best-practices/#user'],
        tags: ['dockerfile', 'least-privilege', 'container-security'],
      }];
    }

    return [];
  }

  private checkAddVsCopy(dockerfile: Dockerfile): RuleHit[] {
    const hits: RuleHit[] = [];
    const adds = dockerfile.getInstructions().filter(i => i.getKeyword() === 'ADD');

    for (const add of adds) {
      const args = add.getArguments().map(a => a.getValue()).filter(v => !v.startsWith('--'));
      const source = args[0];
      if (!source) continue;

      const isRemoteUrl = /^https?:\/\//i.test(source);
      const isLocalArchive = ARCHIVE_EXT_RE.test(source);

      if (!isRemoteUrl && !isLocalArchive) {
        const range = add.getRange();
        hits.push({
          id: 'dockerfile_add_instead_of_copy',
          title: 'ADD used for a plain file/directory copy',
          description: `ADD is used to copy "${source}", which is neither a remote URL nor a local archive that ` +
            'needs automatic extraction. ADD has implicit, easy-to-miss behavior (remote fetch, tar ' +
            'auto-extraction) that has led to real supply-chain and unpacking issues; COPY is the explicit, ' +
            'predictable choice for plain copies.',
          severity: SeverityLevel.LOW,
          line: (range?.start.line ?? 0) + 1,
          column: range?.start.character ?? 0,
          remediation: {
            title: 'Prefer COPY over ADD',
            description: 'Use COPY for plain local file/directory copies; reserve ADD for remote URLs or archives that must be auto-extracted.',
            steps: [`Replace "ADD ${source} ..." with "COPY ${source} ..."`],
            references: ['https://docs.docker.com/build/building/best-practices/#add-or-copy'],
            effort: 'low',
            priority: 4,
          },
          references: [
            'https://docs.docker.com/build/building/best-practices/#add-or-copy',
            'https://github.com/hadolint/hadolint/wiki/DL3020',
          ],
          tags: ['dockerfile', 'best-practice'],
        });
      }
    }

    return hits;
  }

  private checkSecretsInEnvArg(dockerfile: Dockerfile): RuleHit[] {
    const hits: RuleHit[] = [];
    const propertySources: Array<{ keyword: string; properties: Property[]; range: ReturnType<From['getRange']> }> = [
      ...dockerfile.getENVs().map(env => ({ keyword: 'ENV', properties: env.getProperties(), range: env.getRange() })),
      ...dockerfile.getARGs().map(arg => ({
        keyword: 'ARG',
        properties: arg.getProperty() ? [arg.getProperty()!] : [],
        range: arg.getRange(),
      })),
    ];

    for (const { keyword, properties, range } of propertySources) {
      for (const prop of properties) {
        const name = prop.getName();
        const value = prop.getUnescapedValue();
        if (!name || !value) continue;
        if (!SECRET_NAME_RE.test(name)) continue;
        if (value.startsWith('$')) continue; // References another variable rather than a literal secret.
        if (value.length < 4) continue;

        hits.push({
          id: 'dockerfile_hardcoded_secret',
          title: `Hardcoded secret in Dockerfile ${keyword}`,
          description: `${keyword} ${name} is assigned a literal value that looks like a credential. Secrets ` +
            'baked into image layers are readable by anyone with access to the image (including via `docker history`), ' +
            'even if removed in a later layer.',
          severity: SeverityLevel.CRITICAL,
          line: (range?.start.line ?? 0) + 1,
          column: range?.start.character ?? 0,
          remediation: {
            title: 'Never bake secrets into image layers',
            description: 'Pass secrets at runtime or via BuildKit secret mounts instead of ENV/ARG literals.',
            steps: [
              'Use `docker build --secret` / BuildKit RUN --mount=type=secret for build-time secrets',
              'Inject runtime secrets via environment variables or a secrets manager at container start, not at build time',
              'Rotate the exposed credential immediately',
            ],
            references: ['https://docs.docker.com/build/building/secrets/'],
            effort: 'medium',
            priority: 1,
          },
          references: [
            'https://docs.docker.com/build/building/secrets/',
            'https://github.com/hadolint/hadolint/wiki/DL3007',
          ],
          tags: ['dockerfile', 'secrets', 'supply-chain'],
        });
      }
    }

    return hits;
  }

  private toVulnerability(hit: RuleHit, filePath: string): Vulnerability {
    return {
      id: `dockerfile_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      type: VulnerabilityType.DOCKERFILE_MISCONFIGURATION,
      severity: hit.severity,
      score: this.severityToScore(hit.severity),
      title: hit.title,
      description: hit.description,
      location: {
        file: filePath,
        line: hit.line,
        column: hit.column,
      },
      remediation: hit.remediation,
      cveReferences: [],
      context: {
        rule: hit.id,
        detectionMethod: 'dockerfile-ast',
      },
      detectedAt: new Date(),
      confidence: 0.85,
      falsePositiveRisk: 'low',
      tags: [VulnerabilityType.DOCKERFILE_MISCONFIGURATION, hit.severity, ...hit.tags],
    };
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
}

export const dockerfileLinter = new DockerfileLinter();
