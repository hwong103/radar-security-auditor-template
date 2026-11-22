#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import {
  CommandCodeClient,
  enrichReportWithAdvice,
  installedEvidenceForFinding,
  needsComplexAdvice,
} from "./commandcode.js";
import { buildCampaignPreview } from "./campaigns.js";
import { publishCampaign } from "./campaign-publisher.js";
import {
  assertCampaignArtifact,
  campaignArtifactDigest,
  campaignSelectedDigest,
  selectCampaignByKey,
} from "./campaigns.js";
import { loadHubConfig, repositoryConfigFor, repositoryKey } from "./config.js";
import { potentialExposures } from "./exposure.js";
import { fetchRadarFeed } from "./feed.js";
import { GitHubAppTokenMinter, createAppJwt } from "./github-app.js";
import {
  GitHubClient,
  splitRepository,
  type GitHubRepository,
  type GlobalAdvisory,
} from "./github.js";
import { HttpTransportImpl } from "./http.js";
import { parseManifestFiles, type InstalledPackage } from "./manifests.js";
import { selectedInstallations } from "./inventory.js";
import { planPublications } from "./policy.js";
import {
  isConfirmedFinding,
  readReportFindings,
  scopePlans,
  validateReport,
} from "./report.js";
import { findingFromAlert } from "./findings.js";
import { loadState, saveState } from "./state.js";
import {
  buildFixtureReport,
  buildPlans,
  issueForFinding,
  loadFixtureScanInput,
} from "./scan.js";
import type {
  CampaignPreview,
  DependencyAlert,
  PullRequest,
  RadarCve,
  RepositoryIssue,
  ScanReport,
} from "./types.js";

interface ParsedArguments {
  readonly command: string;
  readonly options: Readonly<Record<string, string>>;
}

function parseArguments(argv: readonly string[]): ParsedArguments {
  const [command, ...rest] = argv;
  if (!command) throw new Error("A command is required");
  const options: Record<string, string> = {};
  for (let index = 0; index < rest.length; index += 2) {
    const key = rest[index];
    const value = rest[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error(`Invalid argument near ${key ?? "end of command"}`);
    }
    options[key.slice(2)] = value;
  }
  return { command, options };
}

function required(options: Readonly<Record<string, string>>, key: string): string {
  const value = options[key];
  if (!value) throw new Error(`--${key} is required`);
  return value;
}

function booleanOption(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`Boolean option must be true or false, received ${value}`);
}

async function writeJson(path: string, value: unknown): Promise<void> {
  const absolute = resolve(path);
  await mkdir(dirname(absolute), { recursive: true });
  await writeFile(absolute, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(resolve(path), "utf8")) as unknown;
}

function monthRange(options: Readonly<Record<string, string>>): string {
  const start = options.since ? Date.parse(options.since) : Date.now() - 90 * 86_400_000;
  const end = options.until ? Date.parse(options.until) : Date.now();
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) {
    throw new Error("Invalid --since or --until date");
  }
  return `${new Date(start).toISOString()}...${new Date(end).toISOString()}`;
}

async function scanFixture(options: Readonly<Record<string, string>>): Promise<ScanReport> {
  const config = await loadHubConfig(required(options, "config"));
  const input = await loadFixtureScanInput(required(options, "fixtures"));
  const report = buildFixtureReport({
    config,
    input,
    dryRun: booleanOption(options["dry-run"], true),
    feedUrl: config.feedUrl,
  });
  await writeJson(required(options, "output"), report);
  console.log(
    JSON.stringify({
      findings: report.findings.length,
      plans: report.plans.length,
      coverageGaps: report.coverageGaps.length,
    }),
  );
  return report;
}

async function latestCve(options: Readonly<Record<string, string>>): Promise<void> {
  const config = await loadHubConfig(required(options, "config"));
  const radar = await fetchRadarFeed(
    new HttpTransportImpl(),
    options["feed-url"] ?? config.feedUrl,
    config.severities,
  );
  const latest = [...radar.cves].sort((left, right) =>
    right.publishedAt.localeCompare(left.publishedAt),
  )[0];
  if (!latest) throw new Error("Radar feed contained no matching CVEs");
  console.log(latest.id);
}

async function scanGitHub(options: Readonly<Record<string, string>>): Promise<ScanReport> {
  const config = await loadHubConfig(required(options, "config"));
  const appId = requiredEnvironment("RADAR_GITHUB_APP_ID");
  const privateKey = requiredEnvironment("RADAR_GITHUB_PRIVATE_KEY").replaceAll(
    "\\n",
    "\n",
  );
  const transport = new HttpTransportImpl();
  const token = new GitHubAppTokenMinter({ appId, privateKey }, { transport });
  const github = new GitHubClient({ transport, token });
  const installations = selectedInstallations(
    config,
    await github.listInstallations(createAppJwt({ appId, privateKey })),
  );
  const installationByOwner = new Map(
    installations.map((installation) => [installation.owner.toLowerCase(), installation]),
  );
  const configuredEntries = new Map(
    config.repositories.map((repository) => [
      repositoryKey(repository.owner, repository.name),
      repository,
    ]),
  );
  const found = new Set<string>();
  const skipped: string[] = [];
  const unavailable: string[] = [];
  const scopeGaps: string[] = [];
  const issuesByRepository: Record<string, readonly RepositoryIssue[]> = {};
  const pullRequestsByRepository: Record<string, readonly PullRequest[]> = {};
  const manifestSamples: Record<string, readonly InstalledPackage[]> = {};
  const alerts: DependencyAlert[] = [];
  let eligible = 0;

  for (const installation of installations) {
    const repositories = await github.listRepositories(installation.id);
    for (const repository of repositories) {
      const key = repository.fullName.toLowerCase();
      const configured = configuredEntries.get(key);
      if (config.inventory === "configured") {
        if (!configured?.enabled) continue;
      } else if (configured && !configured.enabled) {
        skipped.push(`${repository.fullName} (disabled in config)`);
        continue;
      }
      found.add(key);
      if (repository.archived || repository.disabled) {
        skipped.push(
          `${repository.fullName} (${repository.archived ? "archived" : "disabled"})`,
        );
        continue;
      }
      eligible += 1;
      const currentIssues = await github.listIssues(installation.id, repository.fullName);
      const currentPullRequests = await github.listPullRequests(
        installation.id,
        repository.fullName,
      );
      issuesByRepository[repository.fullName] = currentIssues;
      pullRequestsByRepository[repository.fullName] = currentPullRequests;
      const alertsResult = await github.listDependabotAlerts(
        installation.id,
        repository.fullName,
        repository.owner,
        repository.name,
      );
      if (alertsResult.available) {
        alerts.push(
          ...alertsResult.alerts.map((alert) => ({
            ...alert,
            repositoryId: repository.id,
          })),
        );
      } else {
        unavailable.push(repository.fullName);
      }
      if (process.env.RADAR_SCAN_MANIFESTS === "true") {
        manifestSamples[repository.fullName] = await collectManifests(
          github,
          installation.id,
          repository,
          unavailable,
        );
      }
    }
  }

  for (const repository of config.repositories.filter((entry) => entry.enabled)) {
    const key = repositoryKey(repository.owner, repository.name);
    if (!found.has(key)) {
      scopeGaps.push(
        `${repository.owner}/${repository.name} was not visible to the GitHub App`,
      );
    }
    if (!installationByOwner.has(repository.owner.toLowerCase())) {
      scopeGaps.push(`No GitHub App installation for ${repository.owner}`);
    }
  }

  const radar = await fetchRadarFeed(transport, config.feedUrl, config.severities);
  const report = buildFixtureReport({
    config,
    input: {
      cves: radar.cves,
      alerts,
      issues: issuesByRepository,
      pullRequests: pullRequestsByRepository,
    },
    dryRun: booleanOption(options["dry-run"], true),
    feedUrl: radar.url,
  });
  const advisoryLookups = await lookupAdvisories(
    github,
    radar.cves,
    installations.map((installation) => installation.id),
  );
  const potential = advisoryLookups.advisories.flatMap((advisory) =>
    Object.entries(manifestSamples).flatMap(([repositoryFullName, manifests]) =>
      potentialExposures({
        radar: radar.cves,
        advisories: advisory.vulnerabilities.map((vulnerability) => ({
          cveId: advisory.cve,
          ecosystem: vulnerability.ecosystem,
          packageName: vulnerability.packageName,
          vulnerableVersionRange: vulnerability.vulnerableVersionRange,
          firstPatchedVersion: vulnerability.firstPatchedVersion,
        })),
        manifests: { manifest: manifests },
      }).map((exposure) => ({
        repositoryFullName,
        advisory: advisory.ghsaId,
        radarUrl: radar.cves.find((cve) => cve.id === advisory.cve)?.url ?? "",
        ecosystem: exposure.package.ecosystem,
        packageName: exposure.package.name,
        installedVersion: exposure.package.version,
        manifestPath: exposure.package.manifestPath,
        firstPatchedVersion: exposure.advisory.firstPatchedVersion,
      })),
    ),
  );
  const withScope: ScanReport = {
    ...report,
    inventory: {
      ...report.inventory,
      repositories: found.size,
      eligible,
      skipped: [...report.inventory.skipped, ...skipped],
    },
    alerts: {
      ...report.alerts,
      queried: alerts.length,
      unavailable,
    },
    potentialExposures: potential,
    coverageGaps: [
      ...report.coverageGaps,
      ...scopeGaps,
      ...unavailable.map((repo) => `Dependabot alerts unavailable for ${repo}`),
      ...advisoryLookups.unavailable,
    ],
  };
  await writeJson(required(options, "output"), withScope);
  await writeJson(required(options, "manifest-output"), manifestSamples);
  console.log(
    JSON.stringify({
      findings: withScope.findings.length,
      plans: withScope.plans.length,
      potential: potential.length,
    }),
  );
  return withScope;
}

async function collectManifests(
  github: GitHubClient,
  installationId: number,
  repository: GitHubRepository,
  unavailable: string[],
): Promise<readonly InstalledPackage[]> {
  const packages: InstalledPackage[] = [];
  try {
    const tree = await github.listManifestPaths(
      installationId,
      repository.owner,
      repository.name,
    );
    if (tree.truncated) unavailable.push(`${repository.fullName} manifest tree truncated`);
    for (const path of tree.paths) {
      try {
        const text = await github.fetchBlob(
          installationId,
          repository.owner,
          repository.name,
          path.sha,
        );
        packages.push(...parseManifestFiles(path.path, text));
      } catch {
        unavailable.push(`${repository.fullName}:${path.path}`);
      }
    }
  } catch {
    unavailable.push(`${repository.fullName} manifests`);
  }
  return packages;
}

async function lookupAdvisories(
  github: GitHubClient,
  cves: readonly RadarCve[],
  installationIds: readonly number[],
): Promise<{
  advisories: readonly {
    cve: string;
    ghsaId: string;
    vulnerabilities: GlobalAdvisory["vulnerabilities"];
  }[];
  unavailable: string[];
}> {
  const advisories: Array<{
    cve: string;
    ghsaId: string;
    vulnerabilities: GlobalAdvisory["vulnerabilities"];
  }> = [];
  const unavailable: string[] = [];
  for (const cve of cves) {
    try {
      const installationId = installationIds[0];
      if (!installationId) throw new Error("No GitHub App installation for advisories");
      const result = await github.listGlobalAdvisories(installationId, cve.id);
      if (result.unavailable.length) unavailable.push(`GHSA unavailable for ${cve.id}`);
      for (const advisory of result.advisories) {
        advisories.push({
          cve: cve.id,
          ghsaId: advisory.ghsaId,
          vulnerabilities: advisory.vulnerabilities,
        });
      }
    } catch {
      unavailable.push(`GHSA unavailable for ${cve.id}`);
    }
  }
  return { advisories, unavailable };
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

interface PublicationResult {
  readonly action: ScanReport["plans"][number]["action"];
  readonly repository: string;
  readonly issueNumber: number | null;
  readonly pullRequestNumber: number | null;
  readonly url: string | null;
  readonly skipped: boolean;
  readonly failed: boolean;
  readonly reason: string;
}

async function publish(options: Readonly<Record<string, string>>): Promise<void> {
  const config = await loadHubConfig(required(options, "config"));
  const report = validateReport(await readJson(required(options, "report")), config);
  const dryRun = booleanOption(options["dry-run"], true);
  if (report.dryRun && !dryRun) {
    throw new Error("Refusing to publish from a report produced in dry-run mode");
  }
  if (!dryRun && !/^\d+:\d+$/.test(required(options, "approval"))) {
    throw new Error("--approval must contain an Actions run ID and attempt");
  }
  for (const plan of scopePlans(report, config)) {
    const [owner, name] = splitRepository(plan.finding.repositoryFullName);
    const repository = repositoryConfigFor(config, owner, name);
    if (!repository?.enabled || !isConfirmedFinding(plan.finding)) {
      throw new Error(`Refusing unconfirmed plan for ${plan.finding.repositoryFullName}`);
    }
    if (!repository.publishIssues) {
      throw new Error(`Refusing issue publication for ${plan.finding.repositoryFullName}`);
    }
  }
  const appId = requiredEnvironment("RADAR_GITHUB_APP_ID");
  const privateKey = requiredEnvironment("RADAR_GITHUB_PRIVATE_KEY").replaceAll(
    "\\n",
    "\n",
  );
  const transport = new HttpTransportImpl();
  const token = new GitHubAppTokenMinter({ appId, privateKey }, { transport });
  const github = new GitHubClient({ transport, token });
  const installations = selectedInstallations(
    config,
    await github.listInstallations(createAppJwt({ appId, privateKey })),
  );
  const installationByOwner = new Map(
    installations.map((installation) => [
      installation.owner.toLowerCase(),
      installation.id,
    ]),
  );
  const repositoryMetadata = new Map<
    string,
    Awaited<ReturnType<GitHubClient["listRepositories"]>>[number]
  >();
  for (const installation of installations) {
    for (const repository of await github.listRepositories(installation.id)) {
      repositoryMetadata.set(repository.fullName.toLowerCase(), repository);
    }
  }
  const trustedIssueAuthor = config.trustedIssueAuthor;
  const results: PublicationResult[] = [];
  for (const approved of scopePlans(report, config)) {
    const [owner, name] = splitRepository(approved.finding.repositoryFullName);
    const repository = repositoryConfigFor(config, owner, name);
    const installationId = repository
      ? installationByOwner.get(repository.owner.toLowerCase())
      : undefined;
    if (!repository || !installationId) {
      results.push(skipped(approved, "repository scope changed"));
      continue;
    }
    const liveRepository = repositoryMetadata.get(
      approved.finding.repositoryFullName.toLowerCase(),
    );
    if (
      !liveRepository ||
      liveRepository.id !== approved.finding.repositoryId ||
      liveRepository.archived ||
      liveRepository.disabled
    ) {
      results.push(skipped(approved, "repository identity or activity changed"));
      continue;
    }
    let currentAlerts;
    try {
      currentAlerts = await github.listDependabotAlerts(
        installationId,
        approved.finding.repositoryFullName,
        repository.owner,
        repository.name,
      );
    } catch (error) {
      results.push(failed(approved, error));
      continue;
    }
    const currentAlert = currentAlerts.available
      ? currentAlerts.alerts.find(
          (alert) =>
            alert.alertNumber === approved.finding.alertNumber &&
            alert.state === "open" &&
            alert.package.ecosystem === approved.finding.package.ecosystem &&
            alert.package.name === approved.finding.package.name &&
            alert.package.manifestPath === approved.finding.package.manifestPath,
        )
      : undefined;
    if (!currentAlert) {
      results.push(skipped(approved, "Dependabot alert changed or became unavailable"));
      continue;
    }
    const finding = {
      ...findingFromAlert(currentAlert, null),
      modelAdvice: approved.finding.modelAdvice,
    };
    if (
      finding.key !== approved.finding.key ||
      finding.repositoryId !== approved.finding.repositoryId ||
      finding.alertNumber !== approved.finding.alertNumber ||
      finding.package.manifestPath !== approved.finding.package.manifestPath
    ) {
      results.push(skipped(approved, "live advisory identity changed"));
      continue;
    }
    let issues;
    let pullRequests;
    try {
      issues = await github.listIssues(installationId, finding.repositoryFullName);
      pullRequests = await github.listPullRequests(
        installationId,
        finding.repositoryFullName,
      );
    } catch (error) {
      results.push(failed(approved, error));
      continue;
    }
    const current = planPublications(finding, repository, {
      issues,
      pullRequests,
      trustedIssueAuthor,
    });
    if (current.action === "reuse-pr") {
      results.push({
        ...skipped(approved, current.reason),
        pullRequestNumber: current.pullRequestNumber,
      });
      continue;
    }
    if (current.action === "update-issue" && trustedIssueAuthor === null) {
      results.push(
        skipped(
          approved,
          "Trusted issue author is not configured; refusing to update an issue",
        ),
      );
      continue;
    }
    if (approved.action === "reuse-pr") {
      results.push(skipped(approved, "The approved pull request reuse is no longer open"));
      continue;
    }
    if (!isSafeTransition(approved.action, current.action)) {
      results.push(
        skipped(approved, `approved ${approved.action} is no longer executable`),
      );
      continue;
    }
    if (
      approved.action === "update-issue" &&
      approved.issueNumber !== current.issueNumber
    ) {
      results.push(skipped(approved, "the approved issue identity changed"));
      continue;
    }
    if (current.action !== "create-issue" && current.action !== "update-issue") {
      results.push(skipped(approved, current.reason));
      continue;
    }
    const issue = issueForFinding(finding);
    const { publishIssuePlan } = await import("./publish.js");
    try {
      const result = await publishIssuePlan({
        client: github,
        installationId,
        plan: current,
        title: issue.title,
        body: issue.body,
        dryRun,
      });
      results.push({ ...result, pullRequestNumber: null, failed: false });
    } catch (error) {
      results.push(failed(approved, error));
    }
  }
  await writeJson(required(options, "output"), {
    publishedAt: new Date().toISOString(),
    approval: dryRun ? null : required(options, "approval"),
    results,
    published: results.filter((result) => !result.skipped && !result.failed).length,
    failed: results.filter((result) => result.failed).length,
  });
}

function isSafeTransition(
  approved: PublicationResult["action"],
  current: PublicationResult["action"],
): boolean {
  if (approved === current) return true;
  return approved === "create-issue" && current === "update-issue";
}

function skipped(plan: ScanReport["plans"][number], reason: string): PublicationResult {
  return {
    action: plan.action,
    repository: plan.finding.repositoryFullName,
    issueNumber: plan.issueNumber,
    pullRequestNumber: null,
    url: null,
    skipped: true,
    failed: false,
    reason,
  };
}

function failed(plan: ScanReport["plans"][number], error: unknown): PublicationResult {
  const message = error instanceof Error ? error.message : String(error);
  return {
    ...skipped(plan, message.slice(0, 1_000)),
    skipped: false,
    failed: true,
  };
}

async function inventory(options: Readonly<Record<string, string>>): Promise<void> {
  const config = await loadHubConfig(required(options, "config"));
  const appId = required(options, "app-id");
  const privateKey = await readFile(required(options, "private-key"), "utf8");
  const transport = new HttpTransportImpl();
  const token = new GitHubAppTokenMinter({ appId, privateKey }, { transport });
  const github = new GitHubClient({ transport, token });
  const jwt = createAppJwt({ appId, privateKey });
  const installations = selectedInstallations(config, await github.listInstallations(jwt));
  const result: Array<{
    id: number;
    owner: string;
    repositories: Array<{
      id: number;
      fullName: string;
      archived: boolean;
      disabled: boolean;
    }>;
  }> = [];
  for (const installation of installations) {
    const repositories = await github.listRepositories(installation.id);
    result.push({
      id: installation.id,
      owner: installation.owner,
      repositories: repositories.map((repository) => ({
        id: repository.id,
        fullName: repository.fullName,
        archived: repository.archived,
        disabled: repository.disabled,
      })),
    });
  }
  await writeJson(required(options, "output"), {
    generatedAt: new Date().toISOString(),
    installations: result,
  });
}

async function advice(options: Readonly<Record<string, string>>): Promise<void> {
  const config = await loadHubConfig(required(options, "config"));
  const report = validateReport(await readJson(required(options, "report")), config);
  const manifestSamples = (await readJson(required(options, "manifests"))) as Record<
    string,
    readonly InstalledPackage[]
  >;
  const finding = report.findings.find((item) =>
    item.aliases.includes(required(options, "advisory").toUpperCase()),
  );
  if (!finding) throw new Error("Finding not present in report");
  const apiKey = process.env.RADAR_COMMANDCODE_API_KEY;
  if (!apiKey) {
    throw new Error("RADAR_COMMANDCODE_API_KEY is required for advice");
  }
  const model = new CommandCodeClient({
    transport: new HttpTransportImpl(),
    apiKey,
    ...(process.env.RADAR_COMMANDCODE_BASE_URL
      ? { baseUrl: process.env.RADAR_COMMANDCODE_BASE_URL }
      : {}),
    zeroDataRetention: process.env.RADAR_COMMANDCODE_ZDR !== "false",
  });
  const manifestEvidence = installedEvidenceForFinding(
    finding,
    manifestSamples[finding.repositoryFullName] ?? [],
  );
  const evidenceFinding =
    manifestEvidence.length > 0
      ? {
          ...finding,
          summary: `${finding.summary} Observed installed version: ${manifestEvidence.join(", ")}.`,
        }
      : finding;
  const adviceResult = await model.advise(
    evidenceFinding,
    booleanOption(options["complex"], needsComplexAdvice(finding)),
    {
      installedVersions: manifestEvidence,
    },
  );
  const issue = issueForFinding(evidenceFinding, adviceResult);
  await writeJson(required(options, "output"), { advice: adviceResult, issue });
}

async function adviseReport(options: Readonly<Record<string, string>>): Promise<void> {
  const config = await loadHubConfig(required(options, "config"));
  const report = validateReport(await readJson(required(options, "report")), config);
  const manifestSamples = (await readJson(required(options, "manifests"))) as Record<
    string,
    readonly InstalledPackage[]
  >;
  const apiKey = requiredEnvironment("RADAR_COMMANDCODE_API_KEY");
  const client = new CommandCodeClient({
    transport: new HttpTransportImpl(),
    apiKey,
    ...(process.env.RADAR_COMMANDCODE_BASE_URL
      ? { baseUrl: process.env.RADAR_COMMANDCODE_BASE_URL }
      : {}),
    zeroDataRetention: process.env.RADAR_COMMANDCODE_ZDR !== "false",
  });
  const advised = await enrichReportWithAdvice(
    {
      advise: async (finding, complex) => {
        const installedVersions = installedEvidenceForFinding(
          finding,
          manifestSamples[finding.repositoryFullName] ?? [],
        );
        return client.advise(finding, complex, { installedVersions });
      },
    },
    report,
  );
  await writeJson(required(options, "output"), advised);
}

async function campaignPreview(options: Readonly<Record<string, string>>): Promise<void> {
  const config = await loadHubConfig(required(options, "config"));
  const report = readReportFindings(await readJson(required(options, "report")), config);
  const maximum = options["max-findings"] ? Number(options["max-findings"]) : undefined;
  const preview = buildCampaignPreview(report.findings, {
    sourceReportGeneratedAt: report.generatedAt,
    ...(maximum === undefined ? {} : { maxFindingsPerCampaign: maximum }),
  });
  await writeJson(required(options, "output"), preview);
  console.log(
    JSON.stringify({
      ...preview.summary,
      artifactDigest: campaignArtifactDigest(preview),
      campaignDigests: Object.fromEntries(
        preview.campaigns.map((campaign) => [
          campaign.key,
          campaignSelectedDigest(preview, campaign.key),
        ]),
      ),
    }),
  );
}

async function campaignPublish(options: Readonly<Record<string, string>>): Promise<void> {
  if (required(options, "confirm") !== "CREATE_APPROVED_CAMPAIGN_ISSUE") {
    throw new Error("Campaign issue creation requires CREATE_APPROVED_CAMPAIGN_ISSUE");
  }
  const campaignKey = required(options, "campaign-key");
  const approvedDigest = required(options, "campaign-digest");
  const approvedArtifactDigest = required(options, "artifact-digest");
  const config = await loadHubConfig(required(options, "config"));
  const previewValue = await readJson(required(options, "campaigns"));
  if (!isCampaignPreview(previewValue)) throw new Error("Invalid campaign artifact");
  assertCampaignArtifact(previewValue);
  if (campaignArtifactDigest(previewValue) !== approvedArtifactDigest) {
    throw new Error("Campaign artifact digest does not match approval");
  }
  const selected = selectCampaignByKey(previewValue, {
    campaignKey,
    digest: approvedDigest,
  });
  const campaign = selected.campaign;
  const [owner, name] = splitRepository(campaign.repositoryFullName);
  const configured = repositoryConfigFor(config, owner, name);
  if (!configured) {
    throw new Error("Approved campaign repository is outside the audit scope");
  }
  if (!configured.publishIssues) {
    throw new Error(
      "Issue publication is not enabled for the approved campaign repository",
    );
  }
  if (campaign.repositoryIds.length !== 1 || (campaign.repositoryIds[0] ?? 0) <= 0) {
    throw new Error("Approved campaign must have exactly one positive repository ID");
  }
  const repositoryId = campaign.repositoryIds[0];
  if (repositoryId === undefined) {
    throw new Error("Approved campaign has no repository ID");
  }
  const readerAppId = requiredEnvironment("RADAR_GITHUB_APP_ID");
  const readerPrivateKey = requiredEnvironment("RADAR_GITHUB_PRIVATE_KEY").replaceAll(
    "\\n",
    "\n",
  );
  const writerAppId = requiredEnvironment("RADAR_GITHUB_WRITE_APP_ID");
  const writerPrivateKey = requiredEnvironment("RADAR_GITHUB_WRITE_PRIVATE_KEY").replaceAll(
    "\\n",
    "\n",
  );
  const transport = new HttpTransportImpl();
  const readerToken = new GitHubAppTokenMinter(
    { appId: readerAppId, privateKey: readerPrivateKey },
    { transport },
  );
  const readerGithub = new GitHubClient({
    transport,
    token: readerToken,
    tokenForRepositoryIds: (installationId, ids) =>
      readerToken.scopedToken(installationId, ids),
  });
  const writerToken = new GitHubAppTokenMinter(
    { appId: writerAppId, privateKey: writerPrivateKey },
    { transport },
  );
  const writerGithub = new GitHubClient({
    transport,
    token: writerToken,
    tokenForRepositoryIds: (installationId, ids) =>
      writerToken.scopedTokenWithPermissions(installationId, ids, {
        issues: "write",
      }),
  });
  const readerJwt = createAppJwt({
    appId: readerAppId,
    privateKey: readerPrivateKey,
  });
  const writerJwt = createAppJwt({
    appId: writerAppId,
    privateKey: writerPrivateKey,
  });
  const readerInstallation = selectedInstallations(
    config,
    await readerGithub.listInstallations(readerJwt),
  ).find((item) => item.owner.toLowerCase() === owner.toLowerCase());
  if (!readerInstallation) {
    throw new Error(`Reader App is not installed for ${owner}`);
  }
  const writerInstallation = selectedInstallations(
    config,
    await writerGithub.listInstallations(writerJwt),
  ).find((item) => item.owner.toLowerCase() === owner.toLowerCase());
  if (!writerInstallation) {
    throw new Error(`Writer App is not installed for ${owner}`);
  }
  const writerApp = await writerGithub.getAuthenticatedApp(writerJwt);
  if (String(writerApp.id) !== writerAppId) {
    throw new Error("Writer App identity did not match the configured App ID");
  }
  const trustedIssueAuthor = `${writerApp.slug}[bot]`;
  const value = await readerGithub.getRepository(readerInstallation.id, owner, name, [
    repositoryId,
  ]);
  if (value.id !== repositoryId || value.archived || value.disabled) {
    throw new Error("Target repository identity or activity changed");
  }
  const live = await readerGithub.listDependabotAlerts(
    readerInstallation.id,
    value.fullName,
    owner,
    name,
    [repositoryId],
  );
  if (!live.available) throw new Error("Live Dependabot alerts are unavailable");
  const result = await publishCampaign({
    campaign: selected.campaign,
    sourceReportGeneratedAt: previewValue.sourceReportGeneratedAt,
    maximumFindings: previewValue.limits.maxFindingsPerCampaign,
    liveAlerts: live.alerts,
    trustedIssueAuthor,
    client: {
      listIssues: async (fullName) =>
        writerGithub.listIssuesScoped(writerInstallation.id, [repositoryId], fullName),
      createIssue: async (fullName, title, body) =>
        writerGithub.createIssueScoped(
          writerInstallation.id,
          [repositoryId],
          fullName,
          title,
          body,
        ),
      updateIssue: async (fullName, issueNumber, title, body) =>
        writerGithub.updateIssueScoped(
          writerInstallation.id,
          [repositoryId],
          fullName,
          issueNumber,
          title,
          body,
        ),
    },
  });
  await writeJson(required(options, "output"), {
    approvedAt: new Date().toISOString(),
    repositoryFullName: campaign.repositoryFullName,
    repositoryId,
    campaignKey,
    campaignDigest: approvedDigest,
    artifactDigest: approvedArtifactDigest,
    result,
  });
  if (result.action === "stale" || result.action === "untrusted") {
    throw new Error(result.reason);
  }
}

function isCampaignPreview(value: unknown): value is CampaignPreview {
  return (
    typeof value === "object" &&
    value !== null &&
    "schemaVersion" in value &&
    value.schemaVersion === 1 &&
    "campaigns" in value &&
    Array.isArray(value.campaigns) &&
    "limits" in value &&
    typeof value.limits === "object" &&
    value.limits !== null &&
    "maxFindingsPerCampaign" in value.limits &&
    typeof value.limits.maxFindingsPerCampaign === "number"
  );
}

async function scanHttp(options: Readonly<Record<string, string>>): Promise<void> {
  const config = await loadHubConfig(required(options, "config"));
  const radar = await fetchRadarFeed(
    new HttpTransportImpl(),
    config.feedUrl,
    config.severities,
  );
  const alerts = (await readJson(required(options, "alerts"))) as DependencyAlert[];
  const report = buildFixtureReport({
    config,
    input: { cves: radar.cves, alerts },
    dryRun: booleanOption(options["dry-run"], true),
    feedUrl: radar.url,
  });
  await writeJson(required(options, "output"), report);
}

async function validateConfig(options: Readonly<Record<string, string>>): Promise<void> {
  const config = await loadHubConfig(required(options, "config"));
  const duplicates = new Set<string>();
  for (const repository of config.repositories) {
    const key = `${repository.owner}/${repository.name}`.toLowerCase();
    if (duplicates.has(key)) throw new Error(`Duplicate repository ${key}`);
    duplicates.add(key);
  }
  await writeJson(required(options, "output"), {
    ok: true,
    repositories: config.repositories.length,
    severities: config.severities,
  });
}

async function plan(options: Readonly<Record<string, string>>): Promise<void> {
  const config = await loadHubConfig(required(options, "config"));
  const input = await loadFixtureScanInput(required(options, "fixtures"));
  const { findings, plans } = buildPlans(config, input);
  await writeJson(required(options, "output"), { findings, plans });
}

async function state(options: Readonly<Record<string, string>>): Promise<void> {
  const current = await loadState(required(options, "input"));
  current.lastSuccessfulRun = new Date().toISOString();
  await saveState(required(options, "output"), current);
}

async function main(): Promise<void> {
  const { command, options } = parseArguments(process.argv.slice(2));
  switch (command) {
    case "scan-fixture":
      await scanFixture(options);
      break;
    case "scan":
      await scanGitHub(options);
      break;
    case "publish":
      await publish(options);
      break;
    case "latest-cve":
      await latestCve(options);
      break;
    case "scan-http":
      await scanHttp(options);
      break;
    case "inventory":
      await inventory(options);
      break;
    case "advice":
      await advice(options);
      break;
    case "advise-report":
      await adviseReport(options);
      break;
    case "campaign-preview":
      await campaignPreview(options);
      break;
    case "campaign-publish":
      await campaignPublish(options);
      break;
    case "plan":
      await plan(options);
      break;
    case "validate-config":
      await validateConfig(options);
      break;
    case "state":
      await state(options);
      break;
    case "month-range": {
      const value = monthRange(options);
      await writeJson(required(options, "output"), { range: value });
      break;
    }
    default:
      throw new Error(`Unknown command: ${command}`);
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
