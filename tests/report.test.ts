import { describe, expect, it } from "vitest";

import { needsComplexAdvice } from "../src/commandcode.js";
import { loadHubConfig } from "../src/config.js";
import { readReportFindings, validateReport } from "../src/report.js";
import type { Finding } from "../src/types.js";

const baseFinding: Finding = {
  key: "b".repeat(24),
  repositoryFullName: "example-org/sample-repo",
  repositoryId: 1,
  alertNumber: 1,
  identity: "GHSA-test",
  aliases: ["GHSA-test"],
  severity: "high",
  summary: "test",
  description: "",
  htmlUrl: "https://github.com/advisories/GHSA-test",
  package: {
    ecosystem: "npm",
    name: "example",
    manifestPath: "package-lock.json#node_modules/example",
    vulnerableVersionRange: ">=1.0.0 <1.1.0",
    firstPatchedVersion: "1.1.0",
  },
  radarUrl: null,
  createdFrom: "dependabot",
};

describe("report validation", () => {
  it("rejects a plan for a repository outside the exact enabled allowlist", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const report = {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      dryRun: false,
      feed: { url: config.feedUrl, cves: 1, newestPublishedAt: null },
      inventory: { repositories: 1, configured: 2, eligible: 1, skipped: [] },
      alerts: { queried: 1, unavailable: [], open: 1 },
      findings: [{ ...baseFinding, repositoryFullName: "example-org/disabled-sample" }],
      plans: [
        {
          action: "create-issue" as const,
          reason: "test",
          issueNumber: null,
          pullRequestNumber: null,
          branch: null,
          finding: { ...baseFinding, repositoryFullName: "example-org/disabled-sample" },
        },
      ],
      potentialExposures: [],
      coverageGaps: [],
    };
    expect(() => validateReport(report, config)).toThrow(/outside the audit scope/);
  });

  it("rejects a publication plan whose finding identity disagrees with the report", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const mismatched = { ...baseFinding, alertNumber: 2 };
    const report = {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      dryRun: false,
      feed: { url: config.feedUrl, cves: 1, newestPublishedAt: null },
      inventory: { repositories: 1, configured: 2, eligible: 1, skipped: [] },
      alerts: { queried: 1, unavailable: [], open: 1 },
      findings: [baseFinding],
      plans: [
        {
          action: "create-issue" as const,
          reason: "test",
          issueNumber: null,
          pullRequestNumber: null,
          branch: null,
          finding: mismatched,
        },
      ],
      potentialExposures: [],
      coverageGaps: [],
    };
    expect(() => validateReport(report, config)).toThrow(/identity disagree/);
  });

  it("reads findings for campaign preview without trusting legacy plans", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const duplicated = {
      ...baseFinding,
      alertNumber: 2,
      package: { ...baseFinding.package, vulnerableVersionRange: "< 2.0.0" },
    };
    const report = {
      generatedAt: new Date().toISOString(),
      findings: [baseFinding, duplicated],
      plans: "legacy and intentionally unreadable",
    };
    expect(readReportFindings(report, config).findings).toEqual([baseFinding, duplicated]);
  });

  it("uses the complex tier for a nested manifest path", () => {
    expect(
      needsComplexAdvice({
        ...baseFinding,
        package: {
          ...baseFinding.package,
          manifestPath: "package-lock.json#node_modules/a/node_modules/b",
        },
      }),
    ).toBe(true);
  });

  it("allows a report-only plan for an App-discovered repository without publication opt-in", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const dynamicConfig = {
      ...config,
      inventory: "app-installations" as const,
    };
    const finding = { ...baseFinding, repositoryFullName: "example-org/new-sample" };
    const report = {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      dryRun: true,
      feed: { url: config.feedUrl, cves: 1, newestPublishedAt: null },
      inventory: { repositories: 1, configured: 0, eligible: 1, skipped: [] },
      alerts: { queried: 1, unavailable: [], open: 1 },
      findings: [finding],
      plans: [
        {
          action: "report-only" as const,
          reason: "Issue publication is not enabled for this repository.",
          issueNumber: null,
          pullRequestNumber: null,
          branch: null,
          finding,
        },
      ],
      potentialExposures: [],
      coverageGaps: [],
    };
    expect(validateReport(report, dynamicConfig).plans).toHaveLength(1);
  });

  it("rejects an issue-writing plan for an App-discovered repository without publication opt-in", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const dynamicConfig = {
      ...config,
      inventory: "app-installations" as const,
    };
    const finding = { ...baseFinding, repositoryFullName: "example-org/new-sample" };
    const report = {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      dryRun: false,
      feed: { url: config.feedUrl, cves: 1, newestPublishedAt: null },
      inventory: { repositories: 1, configured: 0, eligible: 1, skipped: [] },
      alerts: { queried: 1, unavailable: [], open: 1 },
      findings: [finding],
      plans: [
        {
          action: "create-issue" as const,
          reason: "test",
          issueNumber: null,
          pullRequestNumber: null,
          branch: null,
          finding,
        },
      ],
      potentialExposures: [],
      coverageGaps: [],
    };
    expect(() => validateReport(report, dynamicConfig)).toThrow(
      /does not permit issue publication/,
    );
  });

  it("rejects a report for an owner outside configured App installations", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const dynamicConfig = {
      ...config,
      inventory: "app-installations" as const,
      repositoryDefaults: {
        ...config.repositoryDefaults,
        publishIssues: true,
      },
    };
    const finding = { ...baseFinding, repositoryFullName: "another-owner/outside-scope" };
    const report = {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      dryRun: false,
      feed: { url: config.feedUrl, cves: 1, newestPublishedAt: null },
      inventory: { repositories: 1, configured: 0, eligible: 1, skipped: [] },
      alerts: { queried: 1, unavailable: [], open: 1 },
      findings: [finding],
      plans: [
        {
          action: "create-issue" as const,
          reason: "test",
          issueNumber: null,
          pullRequestNumber: null,
          branch: null,
          finding,
        },
      ],
      potentialExposures: [],
      coverageGaps: [],
    };
    expect(() => validateReport(report, dynamicConfig)).toThrow(/outside the audit scope/);
  });
});
