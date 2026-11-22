import { createHash } from "node:crypto";
import * as pep440 from "@renovatebot/pep440";
import semver from "semver";

import { stableFindingKey } from "./findings.js";
import { isVersionInRange, packageKey } from "./manifests.js";
import type {
  CampaignPreview,
  CampaignReviewReason,
  CampaignUpgrade,
  Finding,
  GitHubEcosystem,
  RemediationCampaign,
} from "./types.js";

export interface CampaignPlanningOptions {
  readonly now?: Date;
  readonly sourceReportGeneratedAt: string;
  readonly maxFindingsPerCampaign?: number;
}

interface CampaignGroup {
  readonly repositoryFullName: string;
  readonly ecosystem: GitHubEcosystem;
  readonly manifestPath: string | null;
  readonly normalizedManifest: string;
  readonly findings: Finding[];
}

const DEFAULT_MAX_FINDINGS_PER_CAMPAIGN = 50;

export function buildCampaignPreview(
  findings: readonly Finding[],
  options: CampaignPlanningOptions,
): CampaignPreview {
  const maximum = options.maxFindingsPerCampaign ?? DEFAULT_MAX_FINDINGS_PER_CAMPAIGN;
  if (!Number.isInteger(maximum) || maximum < 1) {
    throw new Error("maxFindingsPerCampaign must be a positive integer");
  }
  const confirmed = findings.filter(
    (finding) =>
      (finding.severity === "critical" || finding.severity === "high") &&
      finding.createdFrom === "dependabot" &&
      finding.alertNumber !== null &&
      finding.alertNumber > 0,
  );
  const groups = new Map<string, CampaignGroup>();
  for (const finding of confirmed) {
    const manifestPath = normalizeCampaignManifest(finding.package.manifestPath);
    const normalizedManifest = manifestPath ?? "";
    const groupKey = [
      finding.repositoryFullName.toLowerCase(),
      finding.package.ecosystem,
      normalizedManifest,
    ].join("\0");
    const group = groups.get(groupKey) ?? {
      repositoryFullName: finding.repositoryFullName,
      ecosystem: finding.package.ecosystem,
      manifestPath,
      normalizedManifest,
      findings: [],
    };
    group.findings.push(finding);
    groups.set(groupKey, group);
  }

  const campaigns = [...groups.values()]
    .map((group) => campaignForGroup(group, maximum))
    .sort(compareCampaigns);
  return {
    schemaVersion: 1,
    generatedAt: (options.now ?? new Date()).toISOString(),
    sourceReportGeneratedAt: options.sourceReportGeneratedAt,
    limits: { maxFindingsPerCampaign: maximum },
    campaigns,
    summary: {
      highCriticalFindings: confirmed.length,
      campaigns: campaigns.length,
      eligibleForPilot: campaigns.filter((campaign) => campaign.eligibleForPilot).length,
      manualReview: campaigns.filter((campaign) => campaign.reviewReasons.length > 0)
        .length,
      deferredByCap: campaigns.filter(
        (campaign) =>
          campaign.reviewReasons.length === 0 && campaign.findingCount > maximum,
      ).length,
    },
  };
}

function campaignForGroup(group: CampaignGroup, maximum: number): RemediationCampaign {
  const findings = [...group.findings].sort((left, right) =>
    left.key.localeCompare(right.key),
  );
  const criticalCount = findings.filter(
    (finding) => finding.severity === "critical",
  ).length;
  const highCount = findings.length - criticalCount;
  const reviewReasons = reviewReasonsFor(group);
  const key = stableFindingKey([
    "campaign",
    group.repositoryFullName.toLowerCase(),
    group.ecosystem,
    group.normalizedManifest,
  ]);
  return {
    key,
    marker: `<!-- radar-remediator:campaign=${key} -->`,
    repositoryFullName: group.repositoryFullName,
    repositoryIds: uniqueNumbers(
      findings.flatMap((finding) =>
        finding.repositoryId === null ? [] : [finding.repositoryId],
      ),
    ),
    ecosystem: group.ecosystem,
    manifestPath: group.manifestPath,
    severity: criticalCount > 0 ? "critical" : "high",
    findingCount: findings.length,
    criticalCount,
    highCount,
    alertNumbers: uniqueNumbers(
      findings.flatMap((finding) =>
        finding.alertNumber === null ? [] : [finding.alertNumber],
      ),
    ),
    findingKeys: findings.map((finding) => finding.key),
    findings: findings.map(campaignFinding),
    upgrades: upgradesFor(findings),
    remediationMode: reviewReasons.length === 0 ? "upgrade" : "review",
    reviewReasons,
    eligibleForPilot: reviewReasons.length === 0 && findings.length <= maximum,
  };
}

function campaignFinding(finding: Finding): RemediationCampaign["findings"][number] {
  if (finding.alertNumber === null) {
    throw new Error("Confirmed campaign finding has no alert number");
  }
  return {
    alertNumber: finding.alertNumber,
    findingKey: finding.key,
    advisory: finding.identity,
    aliases: finding.aliases,
    packageName: finding.package.name,
    severity: finding.severity === "critical" ? "critical" : "high",
    summary: finding.summary,
    vulnerableVersionRange: finding.package.vulnerableVersionRange,
    firstPatchedVersion: finding.package.firstPatchedVersion,
  };
}

export function campaignDigest(campaign: RemediationCampaign): string {
  return createHash("sha256")
    .update(JSON.stringify(campaignDigestInput(campaign)))
    .digest("hex");
}

export function selectCampaign(
  preview: CampaignPreview,
  options: {
    readonly repositoryFullName: string;
    readonly campaignKey: string;
    readonly digest: string;
  },
): { readonly campaign: RemediationCampaign; readonly digest: string } {
  const campaign = preview.campaigns.find(
    (item) =>
      item.key === options.campaignKey &&
      item.repositoryFullName.toLowerCase() === options.repositoryFullName.toLowerCase(),
  );
  if (!campaign)
    throw new Error("Approved campaign is not present in the campaign artifact");
  const digest = campaignDigest(campaign);
  if (digest !== options.digest) {
    throw new Error("Approved campaign digest does not match the campaign artifact");
  }
  return { campaign, digest };
}

export function selectCampaignByKey(
  preview: CampaignPreview,
  options: {
    readonly campaignKey: string;
    readonly digest: string;
  },
): { readonly campaign: RemediationCampaign; readonly digest: string } {
  const campaign = preview.campaigns.find((item) => item.key === options.campaignKey);
  if (!campaign) {
    throw new Error("Approved campaign is not present in the campaign artifact");
  }
  return selectCampaign(preview, {
    repositoryFullName: campaign.repositoryFullName,
    campaignKey: options.campaignKey,
    digest: options.digest,
  });
}

export function campaignArtifactDigest(preview: CampaignPreview): string {
  return createHash("sha256")
    .update(
      JSON.stringify({
        schemaVersion: preview.schemaVersion,
        sourceReportGeneratedAt: preview.sourceReportGeneratedAt,
        limits: preview.limits,
        campaigns: preview.campaigns.map(campaignDigestInput),
      }),
    )
    .digest("hex");
}

export function assertCampaignArtifact(preview: CampaignPreview): void {
  for (const campaign of preview.campaigns) {
    if (
      !Array.isArray(campaign.findings) ||
      campaign.findings.length !== campaign.findingCount ||
      campaign.findings.some(
        (finding) =>
          !Number.isInteger(finding.alertNumber) || typeof finding.advisory !== "string",
      )
    ) {
      throw new Error("Campaign artifact lacks approval evidence; rerun campaign-preview");
    }
  }
}

function campaignDigestInput(campaign: RemediationCampaign): unknown {
  if (!Array.isArray(campaign.findings)) {
    return {
      key: campaign.key,
      repositoryFullName: campaign.repositoryFullName.toLowerCase(),
      repositoryIds: campaign.repositoryIds,
      ecosystem: campaign.ecosystem,
      manifestPath: campaign.manifestPath,
    };
  }
  return {
    key: campaign.key,
    repositoryFullName: campaign.repositoryFullName.toLowerCase(),
    repositoryIds: campaign.repositoryIds,
    ecosystem: campaign.ecosystem,
    manifestPath: campaign.manifestPath,
    severity: campaign.severity,
    remediationMode: campaign.remediationMode,
    reviewReasons: campaign.reviewReasons,
    upgrades: campaign.upgrades,
    findings: campaign.findings.map((finding) => ({
      alertNumber: finding.alertNumber,
      advisory: finding.advisory.toUpperCase(),
      aliases: [...finding.aliases].map((alias) => alias.toUpperCase()).sort(),
      packageName: finding.packageName.toLowerCase(),
      severity: finding.severity,
      summary: finding.summary,
      vulnerableVersionRange: finding.vulnerableVersionRange,
      firstPatchedVersion: finding.firstPatchedVersion,
    })),
  };
}

export function campaignSelectedDigest(
  preview: CampaignPreview,
  campaignKey: string,
): string {
  const campaign = preview.campaigns.find((item) => item.key === campaignKey);
  return campaign ? campaignDigest(campaign) : "not-found";
}

function reviewReasonsFor(group: CampaignGroup): readonly CampaignReviewReason[] {
  const reasons = new Set<CampaignReviewReason>();
  if (group.ecosystem !== "npm") reasons.add("review-required");
  if (group.manifestPath === null) reasons.add("ambiguous-manifest");
  if (!isSupportedManifest(group.ecosystem, group.manifestPath)) {
    reasons.add("unsupported-manifest");
  }
  if (group.findings.some((finding) => finding.package.firstPatchedVersion === null)) {
    reasons.add("missing-patched-version");
  } else if (
    (group.ecosystem === "npm" || group.ecosystem === "pip") &&
    group.findings.some(
      (finding) =>
        finding.package.firstPatchedVersion !== null &&
        !isValidVersion(finding.package.firstPatchedVersion),
    )
  ) {
    reasons.add("invalid-patched-version");
  }
  if (
    (group.ecosystem === "npm" || group.ecosystem === "pip") &&
    unknownVulnerableRange(group.findings)
  ) {
    reasons.add("unknown-vulnerable-range");
  }
  if (
    (group.ecosystem === "npm" || group.ecosystem === "pip") &&
    hasIncompatibleUpgradeEvidence(group.findings)
  ) {
    reasons.add("incompatible-patched-version");
  }
  return [...reasons].sort();
}

function unknownVulnerableRange(findings: readonly Finding[]): boolean {
  return findings.some(
    (finding) =>
      finding.package.firstPatchedVersion !== null &&
      normalizeVulnerableRange(finding.package.vulnerableVersionRange) === null,
  );
}

function hasIncompatibleUpgradeEvidence(findings: readonly Finding[]): boolean {
  const byPackage = new Map<string, Finding[]>();
  for (const finding of findings) {
    const key = packageKey(finding.package.ecosystem, finding.package.name);
    const packageFindings = byPackage.get(key) ?? [];
    packageFindings.push(finding);
    byPackage.set(key, packageFindings);
  }

  for (const packageFindings of byPackage.values()) {
    const candidate = highestPatchedVersion(packageFindings);
    if (candidate === null) continue;
    for (const finding of packageFindings) {
      const range = normalizeVulnerableRange(finding.package.vulnerableVersionRange);
      if (range === null) continue;
      if (
        isVersionInRange(
          candidate,
          range,
          packageFindings[0]?.package.ecosystem === "pip" ? "pip" : "npm",
        )
      ) {
        return true;
      }
    }
  }
  return false;
}

function highestPatchedVersion(findings: readonly Finding[]): string | null {
  const versions = findings
    .flatMap((finding) =>
      finding.package.firstPatchedVersion === null
        ? []
        : [finding.package.firstPatchedVersion],
    )
    .filter((version) => isValidVersion(version));
  return versions.sort(compareVersions).at(-1) ?? null;
}

function normalizeVulnerableRange(value: string | null): string | null {
  if (value === null) return null;
  const normalized = value.trim().replace(/,\s*(?=[<>=])/g, " ");
  return semver.validRange(normalized) !== null || pep440.validRange(normalized)
    ? normalized
    : null;
}

function upgradesFor(findings: readonly Finding[]): readonly CampaignUpgrade[] {
  const byPackage = new Map<
    string,
    { packageName: string; count: number; highestFirstPatchedVersion: string }
  >();
  for (const finding of findings) {
    const highestFirstPatchedVersion = finding.package.firstPatchedVersion;
    if (!highestFirstPatchedVersion) continue;
    const key = packageKey(finding.package.ecosystem, finding.package.name);
    const current = byPackage.get(key);
    if (!current) {
      byPackage.set(key, {
        packageName: finding.package.name,
        count: 1,
        highestFirstPatchedVersion,
      });
      continue;
    }
    current.count += 1;
    if (
      compareVersions(highestFirstPatchedVersion, current.highestFirstPatchedVersion) > 0
    ) {
      current.highestFirstPatchedVersion = highestFirstPatchedVersion;
    }
  }
  return [...byPackage.values()]
    .map(({ packageName, count, highestFirstPatchedVersion }) => ({
      packageName,
      affectedFindings: count,
      highestFirstPatchedVersion,
    }))
    .sort((left, right) => left.packageName.localeCompare(right.packageName));
}

function compareVersions(left: string, right: string): number {
  const pythonComparison = comparePythonVersions(left, right);
  if (pythonComparison !== null) return pythonComparison;
  const leftValid = semver.valid(left);
  const rightValid = semver.valid(right);
  if (leftValid && rightValid) return semver.compare(leftValid, rightValid);
  if (leftValid) return 1;
  if (rightValid) return -1;
  return left.localeCompare(right);
}

function isValidVersion(version: string): boolean {
  return semver.valid(version) !== null || pep440.valid(version) !== null;
}

function comparePythonVersions(left: string, right: string): number | null {
  if (!isValidVersion(left) || !isValidVersion(right)) return null;
  if (semver.valid(left) !== null && semver.valid(right) !== null) return null;
  return pep440.compare(left, right);
}

function compareCampaigns(left: RemediationCampaign, right: RemediationCampaign): number {
  if (left.severity !== right.severity) return left.severity === "critical" ? -1 : 1;
  if (left.findingCount !== right.findingCount) {
    return right.findingCount - left.findingCount;
  }
  return (
    left.repositoryFullName.localeCompare(right.repositoryFullName) ||
    left.ecosystem.localeCompare(right.ecosystem) ||
    (left.manifestPath ?? "").localeCompare(right.manifestPath ?? "") ||
    left.key.localeCompare(right.key)
  );
}

function normalizeCampaignManifest(value: string | null): string | null {
  if (value === null) return null;
  const normalized = value
    .trim()
    .replaceAll("\\", "/")
    .replace(/^\.?\//, "");
  return normalized || null;
}

function isSupportedManifest(
  ecosystem: GitHubEcosystem,
  manifestPath: string | null,
): boolean {
  if (manifestPath === null) return false;
  const lower = manifestPath.toLowerCase();
  if (ecosystem === "npm") {
    return (
      lower === "package-lock.json" ||
      lower.endsWith("/package-lock.json") ||
      lower === "npm-shrinkwrap.json" ||
      lower.endsWith("/npm-shrinkwrap.json")
    );
  }
  if (ecosystem === "pip") {
    const basename = lower.split("/").at(-1) ?? lower;
    return (
      /^requirements(?:[-_.][a-z0-9_.-]+)?\.txt$/.test(basename) ||
      basename === "poetry.lock" ||
      basename === "pipfile.lock" ||
      basename === "uv.lock"
    );
  }
  return false;
}

function uniqueNumbers(values: readonly number[]): readonly number[] {
  return [...new Set(values)].sort((left, right) => left - right);
}
