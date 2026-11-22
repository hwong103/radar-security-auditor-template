import { describe, expect, it } from "vitest";

import {
  buildCampaignPreview,
  campaignArtifactDigest,
  campaignDigest,
  selectCampaign,
  selectCampaignByKey,
} from "../src/campaigns.js";
import type { Finding, GitHubEcosystem } from "../src/types.js";

function finding(
  suffix: string,
  options: {
    severity?: "critical" | "high" | "medium";
    repository?: string;
    ecosystem?: GitHubEcosystem;
    manifestPath?: string | null;
    packageName?: string;
    patchedVersion?: string | null;
    vulnerableRange?: string | null;
  } = {},
): Finding {
  return {
    key: suffix.repeat(24).slice(0, 24),
    repositoryFullName: options.repository ?? "example-org/example",
    repositoryId: 42,
    alertNumber: Number(suffix.replace(/\D/g, "") || 1),
    identity: `GHSA-${suffix}`,
    aliases: [`GHSA-${suffix}`],
    severity: options.severity ?? "high",
    summary: "test",
    description: "",
    htmlUrl: `https://github.com/advisories/GHSA-${suffix}`,
    package: {
      ecosystem: options.ecosystem ?? "npm",
      name: options.packageName ?? "example",
      manifestPath:
        "manifestPath" in options ? (options.manifestPath ?? null) : "package-lock.json",
      vulnerableVersionRange:
        "vulnerableRange" in options ? (options.vulnerableRange ?? null) : "<2.0.0",
      firstPatchedVersion:
        "patchedVersion" in options ? (options.patchedVersion ?? null) : "2.0.0",
    },
    radarUrl: null,
    createdFrom: "dependabot",
  };
}

function preview(findings: readonly Finding[], maxFindingsPerCampaign = 50) {
  return buildCampaignPreview(findings, {
    sourceReportGeneratedAt: "2026-11-22T00:00:00.000Z",
    now: new Date("2026-11-22T01:00:00.000Z"),
    maxFindingsPerCampaign,
  });
}

describe("remediation campaigns", () => {
  it("keeps high and critical findings and omits lower severities", () => {
    const result = preview([
      finding("1", { severity: "critical" }),
      finding("2", { severity: "high" }),
      finding("3", { severity: "medium" }),
    ]);
    expect(result.summary.highCriticalFindings).toBe(2);
    expect(result.campaigns).toHaveLength(1);
    expect(result.campaigns[0]).toMatchObject({
      severity: "critical",
      criticalCount: 1,
      highCount: 1,
      findingCount: 2,
    });
  });

  it("produces the same campaigns and ordering under shuffled input", () => {
    const findings = [
      finding("1", { repository: "example-org/a" }),
      finding("2", { repository: "example-org/b", severity: "critical" }),
      finding("3", { repository: "example-org/a", packageName: "other" }),
    ];
    expect(JSON.stringify(preview(findings))).toBe(
      JSON.stringify(preview([findings[2]!, findings[0]!, findings[1]!])),
    );
  });

  it("keeps lockfiles in different monorepo packages in separate campaigns", () => {
    const result = preview([
      finding("1", { manifestPath: "apps/web/package-lock.json" }),
      finding("2", { manifestPath: "workers/api/package-lock.json" }),
    ]);
    expect(result.campaigns).toHaveLength(2);
    expect(result.campaigns.map((campaign) => campaign.manifestPath).sort()).toEqual([
      "apps/web/package-lock.json",
      "workers/api/package-lock.json",
    ]);
  });

  it("uses the highest patched version required for a repeated package", () => {
    const result = preview([
      finding("1", { patchedVersion: "2.1.0" }),
      finding("2", { patchedVersion: "2.3.0" }),
    ]);
    expect(result.campaigns[0]?.upgrades).toEqual([
      {
        packageName: "example",
        affectedFindings: 2,
        highestFirstPatchedVersion: "2.3.0",
      },
    ]);
  });

  it("rejects a patched version that remains vulnerable to another alert range", () => {
    const result = preview([
      finding("1", {
        packageName: "brace-expansion",
        vulnerableRange: "< 2.0.0 || >= 3.0.0, < 4.0.0",
        patchedVersion: "2.0.0",
      }),
      finding("2", {
        packageName: "brace-expansion",
        vulnerableRange: "< 3.2.0",
        patchedVersion: "3.2.0",
      }),
    ]);
    expect(result.campaigns[0]).toMatchObject({
      remediationMode: "review",
      eligibleForPilot: false,
      reviewReasons: expect.arrayContaining(["incompatible-patched-version"]),
    });
  });

  it("sends unknown vulnerable ranges to manual review", () => {
    const result = preview([
      finding("1", { vulnerableRange: "the affected versions", patchedVersion: "2.0.0" }),
    ]);
    expect(result.campaigns[0]).toMatchObject({
      remediationMode: "review",
      eligibleForPilot: false,
      reviewReasons: expect.arrayContaining(["unknown-vulnerable-range"]),
    });
  });

  it("marks unsupported or incomplete campaigns for review and excludes them from the pilot", () => {
    const result = preview([
      finding("1", { manifestPath: "pnpm-lock.yaml" }),
      finding("2", {
        repository: "example-org/other",
        patchedVersion: null,
      }),
      finding("3", {
        repository: "example-org/missing",
        manifestPath: null,
      }),
    ]);
    expect(result.campaigns.every((campaign) => !campaign.eligibleForPilot)).toBe(true);
    expect(result.campaigns.map((campaign) => campaign.reviewReasons)).toEqual(
      expect.arrayContaining([
        expect.arrayContaining(["unsupported-manifest"]),
        expect.arrayContaining(["ambiguous-manifest"]),
        expect.arrayContaining(["missing-patched-version"]),
      ]),
    );
    expect(
      result.campaigns.every((campaign) => campaign.remediationMode === "review"),
    ).toBe(true);
  });

  it("preserves Git path casing and separates case-sensitive lockfile paths", () => {
    const result = preview([
      finding("1", { manifestPath: "Apps/Web/package-lock.json" }),
      finding("2", { manifestPath: "apps/web/package-lock.json" }),
    ]);
    expect(result.campaigns.map((campaign) => campaign.manifestPath).sort()).toEqual([
      "Apps/Web/package-lock.json",
      "apps/web/package-lock.json",
    ]);
    expect(result.campaigns[0]?.key).not.toBe(result.campaigns[1]?.key);
  });

  it("sends invalid npm patch versions to manual review", () => {
    const result = preview([finding("1", { patchedVersion: "latest" })]);
    expect(result.campaigns[0]).toMatchObject({
      remediationMode: "review",
      eligibleForPilot: false,
      reviewReasons: expect.arrayContaining(["invalid-patched-version"]),
    });
  });

  it("plans Python campaigns for manual review while preserving deterministic evidence", () => {
    const result = preview([
      finding("1", {
        ecosystem: "pip",
        manifestPath: "services/api/requirements.txt",
        packageName: "Requests",
        vulnerableRange: ">=2.0.0, <2.32.0",
        patchedVersion: "2.32.0",
      }),
    ]);
    expect(result.campaigns[0]).toMatchObject({
      ecosystem: "pip",
      manifestPath: "services/api/requirements.txt",
      remediationMode: "review",
      eligibleForPilot: false,
      reviewReasons: ["review-required"],
      upgrades: [
        {
          packageName: "Requests",
          affectedFindings: 1,
          highestFirstPatchedVersion: "2.32.0",
        },
      ],
    });
  });

  it("validates Python patch versions and ranges with PEP 440", () => {
    const result = preview([
      finding("1", {
        ecosystem: "pip",
        manifestPath: "pyproject-lock/uv.lock",
        packageName: "zope.interface",
        vulnerableRange: "<6.2",
        patchedVersion: "6.2rc1",
      }),
    ]);
    expect(result.campaigns[0]?.reviewReasons).toEqual(
      expect.arrayContaining(["incompatible-patched-version", "review-required"]),
    );
  });

  it("sends unknown Python ranges to manual review", () => {
    const result = preview([
      finding("1", {
        ecosystem: "pip",
        manifestPath: "requirements.txt",
        vulnerableRange: "the affected releases",
        patchedVersion: "2.0.0",
      }),
    ]);
    expect(result.campaigns[0]?.reviewReasons).toContain("unknown-vulnerable-range");
  });

  it("defers campaigns above the pilot cap", () => {
    const result = preview([finding("1"), finding("2"), finding("3")], 2);
    expect(result.summary.deferredByCap).toBe(1);
    expect(result.campaigns[0]?.eligibleForPilot).toBe(false);
  });
  it("binds an approved campaign to its exact alert evidence digest", () => {
    const result = preview([finding("1")]);
    const campaign = result.campaigns[0];
    if (!campaign) throw new Error("expected campaign");
    const digest = campaignDigest(campaign);
    expect(
      selectCampaign(result, {
        repositoryFullName: "example-org/example",
        campaignKey: campaign.key,
        digest,
      }).campaign,
    ).toBe(campaign);
    expect(() =>
      selectCampaign(result, {
        repositoryFullName: "example-org/example",
        campaignKey: campaign.key,
        digest: "0".repeat(64),
      }),
    ).toThrow(/digest/);
    expect(digest).toMatch(/^[a-f0-9]{64}$/);
    expect(campaignArtifactDigest(result)).toMatch(/^[a-f0-9]{64}$/);
  });

  it("selects a campaign by its approved key without client-supplied repository scope", () => {
    const result = preview([
      finding("1", { repository: "example-org/one" }),
      finding("2", { repository: "example-org/two" }),
    ]);
    const campaign = result.campaigns[1];
    if (!campaign) throw new Error("expected campaign");
    expect(
      selectCampaignByKey(result, {
        campaignKey: campaign.key,
        digest: campaignDigest(campaign),
      }).campaign.repositoryFullName,
    ).toBe(campaign.repositoryFullName);
  });
});
