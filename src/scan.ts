import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { repositoryConfigFor } from "./config.js";
import { reconcileFindingsForScope } from "./findings.js";
import { issueBody, issueTitle, planPublications } from "./policy.js";
import type {
  DependencyAlert,
  Finding,
  HubConfig,
  PublicationPlan,
  PullRequest,
  RadarCve,
  RepositoryIssue,
  ScanReport,
} from "./types.js";

export interface FixtureScanInput {
  readonly cves: readonly RadarCve[];
  readonly alerts: readonly DependencyAlert[];
  readonly issues?: Readonly<Record<string, readonly RepositoryIssue[]>>;
  readonly pullRequests?: Readonly<Record<string, readonly PullRequest[]>>;
}

export async function loadFixtureScanInput(directory: string): Promise<FixtureScanInput> {
  const [cves, alerts, issues, pullRequests] = await Promise.all([
    readJson(join(directory, "radar.json")),
    readJson(join(directory, "alerts.json")),
    readOptionalJson(join(directory, "issues.json"), {}),
    readOptionalJson(join(directory, "pull-requests.json"), {}),
  ]);
  if (!Array.isArray(cves) || !Array.isArray(alerts)) {
    throw new Error("radar.json and alerts.json must contain arrays");
  }
  return {
    cves: cves as RadarCve[],
    alerts: alerts as DependencyAlert[],
    issues: issues as Record<string, RepositoryIssue[]>,
    pullRequests: pullRequests as Record<string, PullRequest[]>,
  };
}

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8")) as unknown;
}

async function readOptionalJson(path: string, fallback: unknown): Promise<unknown> {
  try {
    return await readJson(path);
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      (error as { code?: unknown }).code === "ENOENT"
    ) {
      return fallback;
    }
    throw error;
  }
}

export function buildPlans(
  config: HubConfig,
  input: FixtureScanInput,
): { readonly findings: readonly Finding[]; readonly plans: readonly PublicationPlan[] } {
  const repositoryDefaults = {
    owner: "*",
    name: "*",
    enabled: true,
    ...config.repositoryDefaults,
  };
  const alerts = input.alerts.filter((alert) => {
    const [owner, name] = alert.repositoryFullName.split("/");
    return Boolean(owner && name && repositoryConfigFor(config, owner, name));
  });
  const findings = reconcileFindingsForScope(
    {
      repositories: config.repositories,
      appInstalls: config.inventory === "app-installations",
      repositoryDefaults,
    },
    alerts,
    input.cves,
  ).filter((finding) => finding.severity === "critical" || finding.severity === "high");
  const plans = findings.map((finding) => {
    const [owner, name] = finding.repositoryFullName.split("/");
    if (!owner || !name) throw new Error("Finding has an invalid repository full name");
    const configured = config.repositories.find(
      (repository) =>
        repository.owner.toLowerCase() === owner.toLowerCase() &&
        repository.name.toLowerCase() === name.toLowerCase(),
    );
    const repository =
      configured ??
      (config.inventory === "app-installations" ? repositoryDefaults : undefined);
    if (!repository) {
      throw new Error(
        `Finding references unconfigured repository ${finding.repositoryFullName}`,
      );
    }
    return planPublications(finding, repository, {
      issues: input.issues?.[finding.repositoryFullName] ?? [],
      pullRequests: input.pullRequests?.[finding.repositoryFullName] ?? [],
      trustedIssueAuthor: config.trustedIssueAuthor,
    });
  });
  return { findings, plans };
}

export function buildFixtureReport(options: {
  readonly config: HubConfig;
  readonly input: FixtureScanInput;
  readonly dryRun: boolean;
  readonly feedUrl: string;
  readonly now?: Date;
}): ScanReport {
  const { findings, plans } = buildPlans(options.config, options.input);
  const newest =
    options.input.cves
      .map((cve) => cve.publishedAt)
      .sort((left, right) => right.localeCompare(left))[0] ?? null;
  const enabled = options.config.repositories.filter((repository) => repository.enabled);
  const observedRepositories = new Set(
    options.input.alerts.map((alert) => alert.repositoryFullName.toLowerCase()),
  ).size;
  return {
    schemaVersion: 1,
    generatedAt: (options.now ?? new Date()).toISOString(),
    dryRun: options.dryRun,
    feed: {
      url: options.feedUrl,
      cves: options.input.cves.length,
      newestPublishedAt: newest,
    },
    inventory: {
      repositories:
        options.config.inventory === "app-installations"
          ? observedRepositories
          : options.config.repositories.length,
      configured: options.config.repositories.length,
      eligible:
        options.config.inventory === "app-installations"
          ? observedRepositories
          : enabled.length,
      skipped: options.config.repositories
        .filter((repository) => !repository.enabled)
        .map((repository) => `${repository.owner}/${repository.name}`),
    },
    alerts: {
      queried: options.input.alerts.length,
      unavailable: [],
      open: options.input.alerts.filter((alert) => alert.state === "open").length,
    },
    findings,
    plans,
    potentialExposures: [],
    coverageGaps: coverageGaps(options.config, options.input.alerts),
  };
}

export function coverageGaps(
  config: HubConfig,
  alerts: readonly DependencyAlert[],
): readonly string[] {
  const unsupported = alerts
    .filter((alert) => alert.state === "open")
    .map((alert) => alert.package.ecosystem)
    .filter(
      (ecosystem) => !["npm", "pip", "go", "rust", "cargo", "composer"].includes(ecosystem),
    );
  const gaps = new Set<string>();
  if (unsupported.length > 0) {
    gaps.add(
      `Dependency ecosystems present without deterministic remediation planning: ${[
        ...new Set(unsupported),
      ]
        .sort()
        .join(", ")}`,
    );
  }
  const noPatched = alerts.filter(
    (alert) => alert.state === "open" && !alert.package.firstPatchedVersion,
  );
  if (noPatched.length > 0) {
    gaps.add(`${noPatched.length} open alerts do not publish a first patched version.`);
  }
  if (config.inventory === "configured") {
    gaps.add(
      "Repository inventory is configured; new App-visible repositories are not auto-enabled.",
    );
  } else if (!config.repositoryDefaults.publishIssues) {
    gaps.add(
      "New App-visible repositories are audited automatically and require explicit publishIssues=true before issue publication.",
    );
  }
  return [...gaps];
}

export function issueForFinding(
  finding: Finding,
  advice?: { readonly summary: string },
): { readonly title: string; readonly body: string } {
  return {
    title: issueTitle(finding),
    body: issueBody(finding, advice?.summary),
  };
}
