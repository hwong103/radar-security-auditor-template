import { z } from "zod";

import { repositoryConfigFor } from "./config.js";
import { githubEcosystemToEcosystem } from "./github.js";
import type {
  Finding,
  GitHubEcosystem,
  HubConfig,
  PublicationPlan,
  ScanReport,
} from "./types.js";

const affectedPackageSchema = z
  .object({
    ecosystem: z.string(),
    name: z.string().min(1),
    manifestPath: z.string().nullable(),
    vulnerableVersionRange: z.string().nullable(),
    firstPatchedVersion: z.string().nullable(),
  })
  .passthrough();

const modelAdviceSchema = z
  .object({
    model: z.string().min(1),
    tier: z.enum(["fast", "complex"]),
    summary: z.string().min(1).max(2_000),
    steps: z.array(z.string().max(500)).max(10),
    risks: z.array(z.string().max(500)).max(10),
    fallback: z.boolean(),
  })
  .strict();

const findingSchema = z
  .object({
    key: z.string().regex(/^[a-f0-9]{24}$/),
    repositoryFullName: z.string().regex(/^[^/\s]+\/[^/\s]+$/),
    repositoryId: z.number().int().positive().nullable(),
    alertNumber: z.number().int().positive().nullable(),
    identity: z.string().min(1),
    aliases: z.array(z.string().min(1)),
    severity: z.enum(["critical", "high", "medium", "low", "unknown"]),
    summary: z.string(),
    description: z.string(),
    htmlUrl: z.string().url(),
    package: affectedPackageSchema,
    radarUrl: z.string().nullable(),
    createdFrom: z.enum(["dependabot", "radar"]),
    modelAdvice: modelAdviceSchema.optional(),
  })
  .passthrough();

const planSchema = z
  .object({
    action: z.enum(["create-issue", "update-issue", "reuse-pr", "report-only"]),
    reason: z.string(),
    finding: findingSchema,
    issueNumber: z.number().int().positive().nullable(),
    pullRequestNumber: z.number().int().positive().nullable(),
    branch: z.string().nullable(),
  })
  .passthrough();

const reportSchema = z
  .object({
    schemaVersion: z.literal(1),
    generatedAt: z.string().datetime({ offset: true }),
    dryRun: z.boolean(),
    feed: z
      .object({
        url: z.string().url(),
        cves: z.number().int().nonnegative(),
        newestPublishedAt: z.string().datetime({ offset: true }).nullable(),
      })
      .passthrough(),
    inventory: z
      .object({
        repositories: z.number().int().nonnegative(),
        configured: z.number().int().nonnegative(),
        eligible: z.number().int().nonnegative(),
        skipped: z.array(z.string()),
      })
      .passthrough(),
    alerts: z
      .object({
        queried: z.number().int().nonnegative(),
        unavailable: z.array(z.string()),
        open: z.number().int().nonnegative(),
      })
      .passthrough(),
    findings: z.array(findingSchema),
    plans: z.array(planSchema),
    potentialExposures: z.array(z.unknown()),
    coverageGaps: z.array(z.string()),
  })
  .passthrough();

const findingsOnlyReportSchema = z
  .object({
    generatedAt: z.string().datetime({ offset: true }),
    findings: z.array(findingSchema),
  })
  .passthrough();

export function validateReport(value: unknown, config: HubConfig): ScanReport {
  const report = reportSchema.parse(value) as ScanReport;
  const findings = new Map(report.findings.map((finding) => [finding.key, finding]));
  for (const plan of report.plans) {
    const [owner, name] = splitFullName(plan.finding.repositoryFullName);
    const repository = repositoryConfigFor(config, owner, name);
    if (!repository) {
      throw new Error(
        `Report repository is outside the audit scope: ${plan.finding.repositoryFullName}`,
      );
    }
    if (plan.action !== "report-only" && !repository.publishIssues) {
      throw new Error(
        `Report repository does not permit issue publication: ${plan.finding.repositoryFullName}`,
      );
    }
    const ecosystem = githubEcosystemToEcosystem(plan.finding.package.ecosystem);
    if (ecosystem === null || !repository.allowedEcosystems.includes(ecosystem)) {
      throw new Error("Plan ecosystem is not allowed by current repository config");
    }
    if (
      plan.action === "update-issue" &&
      (plan.issueNumber === null || plan.finding.alertNumber === null)
    ) {
      throw new Error("Update issue plan is missing its issue or alert identity");
    }
    const stored = findings.get(plan.finding.key);
    if (!stored) throw new Error("Plan references a missing finding");
    if (
      stored.repositoryFullName.toLowerCase() !==
      plan.finding.repositoryFullName.toLowerCase()
    ) {
      throw new Error("Finding and plan repository disagree");
    }
    if (
      stored.repositoryId !== plan.finding.repositoryId ||
      stored.alertNumber !== plan.finding.alertNumber ||
      JSON.stringify(stored.package) !== JSON.stringify(plan.finding.package)
    ) {
      throw new Error("Finding and plan identity disagree");
    }
  }
  return report;
}

export function readReportFindings(
  value: unknown,
  config: HubConfig,
): Pick<ScanReport, "generatedAt" | "findings"> {
  const report = findingsOnlyReportSchema.parse(value);
  for (const finding of report.findings) {
    const [owner, name] = splitFullName(finding.repositoryFullName);
    const repository = repositoryConfigFor(config, owner, name);
    if (!repository) {
      throw new Error(
        `Report repository is outside the audit scope: ${finding.repositoryFullName}`,
      );
    }
    const ecosystem = githubEcosystemToEcosystem(
      finding.package.ecosystem as GitHubEcosystem,
    );
    if (ecosystem === null || !repository.allowedEcosystems.includes(ecosystem)) {
      throw new Error("Finding ecosystem is not allowed by current repository config");
    }
  }
  return report as unknown as Pick<ScanReport, "generatedAt" | "findings">;
}

export function scopePlans(
  report: ScanReport,
  config: HubConfig,
): readonly PublicationPlan[] {
  return report.plans.filter((plan) => {
    const [owner, name] = splitFullName(plan.finding.repositoryFullName);
    const repository = repositoryConfigFor(config, owner, name);
    return repository?.publishIssues === true;
  });
}

function splitFullName(repository: string): readonly [string, string] {
  const parts = repository.split("/");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error(`Expected owner/name repository, received ${repository}`);
  }
  return [parts[0], parts[1]];
}

export function isConfirmedFinding(finding: Finding): boolean {
  return (
    finding.createdFrom === "dependabot" &&
    finding.alertNumber !== null &&
    finding.alertNumber > 0
  );
}
