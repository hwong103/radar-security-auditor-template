import { describe, expect, it } from "vitest";

import { campaignIssueBody, planCampaignIssue } from "../src/campaign-issue.js";
import { publishCampaign } from "../src/campaign-publisher.js";
import { buildCampaignPreview } from "../src/campaigns.js";
import type { DependencyAlert, Finding, RepositoryIssue } from "../src/types.js";

function finding(alertNumber = 7): Finding {
  return {
    key: "a".repeat(24),
    repositoryFullName: "example-org/example-repo",
    repositoryId: 1170364244,
    alertNumber,
    identity: "GHSA-test",
    aliases: ["GHSA-test", "CVE-test"],
    severity: "high",
    summary: "test",
    description: "test",
    htmlUrl: "https://github.com/advisories/GHSA-test",
    package: {
      ecosystem: "npm",
      name: "example",
      manifestPath: "package-lock.json",
      vulnerableVersionRange: "< 2.0.0",
      firstPatchedVersion: "2.0.0",
    },
    radarUrl: null,
    createdFrom: "dependabot",
  };
}

function campaign() {
  const preview = buildCampaignPreview([finding()], {
    sourceReportGeneratedAt: "2026-11-22T00:00:00.000Z",
    now: new Date("2026-11-22T01:00:00.000Z"),
  });
  const value = preview.campaigns[0];
  if (!value) throw new Error("expected campaign");
  return value;
}

function alert(): DependencyAlert {
  const value = finding();
  return {
    repositoryId: 1170364244,
    repositoryFullName: value.repositoryFullName,
    alertNumber: 7,
    state: "open",
    severity: "high",
    ghsaId: value.aliases[0] ?? null,
    cveIds: value.aliases.slice(1),
    summary: value.summary,
    description: value.description,
    htmlUrl: value.htmlUrl,
    package: value.package,
    createdAt: "2026-11-22T00:00:00.000Z",
    updatedAt: "2026-11-22T00:00:00.000Z",
    dismissedReason: null,
    fixedAt: null,
  };
}

function issue(
  state: "open" | "closed",
  body: string,
  authorLogin = "hw-radar-remediation-writer[bot]",
): RepositoryIssue {
  return {
    number: 9,
    title: "tracking",
    state,
    htmlUrl: "https://github.com/example-org/example-repo/issues/9",
    body,
    authorLogin,
    authorType: "Bot",
  };
}

describe("campaign issue publisher", () => {
  it("creates one campaign issue with evidence and no fix claim", () => {
    const value = campaign();
    const plan = planCampaignIssue(value, {
      issues: [],
      trustedIssueAuthor: "hw-radar-remediation-writer[bot]",
    });
    expect(plan.action).toBe("create");
    expect(plan.body).toContain(value.marker);
    expect(plan.body).toContain("No automated dependency fix is claimed");
    expect(plan.body).toContain("| 7 | high |");
  });

  it("updates only an open trusted campaign issue", () => {
    const value = campaign();
    const plan = planCampaignIssue(value, {
      issues: [issue("open", campaignIssueBody(value))],
      trustedIssueAuthor: "hw-radar-remediation-writer[bot]",
    });
    expect(plan).toMatchObject({ action: "update", issueNumber: 9 });
  });

  it("skips an identical trusted campaign issue", () => {
    const value = campaign();
    expect(
      planCampaignIssue(value, {
        issues: [
          {
            ...issue("open", value.marker),
            title: `[security] Review ${value.ecosystem} dependencies in ${value.manifestPath}`,
            body: campaignIssueBody(value),
          },
        ],
        trustedIssueAuthor: "hw-radar-remediation-writer[bot]",
      }),
    ).toMatchObject({ action: "same", issueNumber: 9 });
  });

  it("does not reopen a closed trusted issue", () => {
    const value = campaign();
    expect(
      planCampaignIssue(value, {
        issues: [issue("closed", campaignIssueBody(value))],
        trustedIssueAuthor: "hw-radar-remediation-writer[bot]",
      }),
    ).toMatchObject({ action: "closed", issueNumber: 9 });
  });

  it("refuses a forged marker from an unrelated author", () => {
    const value = campaign();
    expect(
      planCampaignIssue(value, {
        issues: [issue("open", value.marker, "attacker")],
        trustedIssueAuthor: "hw-radar-remediation-writer[bot]",
      }),
    ).toMatchObject({ action: "untrusted" });
  });

  it("refuses duplicate markers and mixed campaign markers", () => {
    const value = campaign();
    expect(
      planCampaignIssue(value, {
        issues: [issue("open", `${value.marker}\n${value.marker}`)],
        trustedIssueAuthor: "hw-radar-remediation-writer[bot]",
      }),
    ).toMatchObject({ action: "untrusted" });
    expect(
      planCampaignIssue(value, {
        issues: [
          issue(
            "open",
            `${value.marker}\n<!-- radar-remediator:campaign=${"b".repeat(24)} -->`,
          ),
        ],
        trustedIssueAuthor: "hw-radar-remediation-writer[bot]",
      }),
    ).toMatchObject({ action: "untrusted" });
  });

  it("lets publisher reject a non-leading quoted marker before planning", async () => {
    const value = campaign();
    let writes = 0;
    const result = await publishCampaign({
      campaign: value,
      sourceReportGeneratedAt: "2026-11-22T00:00:00.000Z",
      maximumFindings: 50,
      liveAlerts: [alert()],
      trustedIssueAuthor: "hw-radar-remediation-writer[bot]",
      client: {
        listIssues: async () => [issue("open", `Example:\n${value.marker}`)],
        createIssue: async () => {
          writes += 1;
          throw new Error("must not create");
        },
        updateIssue: async () => {
          writes += 1;
          throw new Error("must not update");
        },
      },
    });
    expect(result).toMatchObject({ action: "untrusted", attempted: false });
    expect(writes).toBe(0);
  });

  it("keeps an alert identity in the body and does not print markdown injection", () => {
    const value = campaign();
    const body = campaignIssueBody({
      ...value,
      findings: [{ ...value.findings[0]!, packageName: "**example**|bad" }],
    });
    expect(body).toContain("`**example**|bad`");
  });

  it("recomputes live state and refuses a stale approved campaign", async () => {
    const value = campaign();
    let mutations = 0;
    const result = await publishCampaign({
      campaign: value,
      sourceReportGeneratedAt: "2026-11-22T00:00:00.000Z",
      maximumFindings: 50,
      liveAlerts: [{ ...alert(), state: "fixed" }],
      trustedIssueAuthor: "hw-radar-remediation-writer[bot]",
      client: {
        listIssues: async () => [],
        createIssue: async () => {
          mutations += 1;
          throw new Error("must not write");
        },
        updateIssue: async () => {
          throw new Error("must not write");
        },
      },
    });
    expect(result).toMatchObject({ action: "stale", attempted: false });
    expect(mutations).toBe(0);
  });

  it("creates at most one issue when live evidence matches", async () => {
    const value = campaign();
    let creates = 0;
    const result = await publishCampaign({
      campaign: value,
      sourceReportGeneratedAt: "2026-11-22T00:00:00.000Z",
      maximumFindings: 50,
      liveAlerts: [alert()],
      trustedIssueAuthor: "hw-radar-remediation-writer[bot]",
      client: {
        listIssues: async () => [],
        createIssue: async (_repository, _title, body) => {
          creates += 1;
          expect(body).toContain(value.marker);
          return issue("open", body, "hw-radar-remediation-writer[bot]");
        },
        updateIssue: async () => {
          throw new Error("must not update");
        },
      },
    });
    expect(result).toMatchObject({ action: "create", attempted: true, issueNumber: 9 });
    expect(creates).toBe(1);
  });

  it("reconciles a successful create when the client loses the response", async () => {
    const value = campaign();
    let listCalls = 0;
    let created: RepositoryIssue | null = null;
    const result = await publishCampaign({
      campaign: value,
      sourceReportGeneratedAt: "2026-11-22T00:00:00.000Z",
      maximumFindings: 50,
      liveAlerts: [alert()],
      trustedIssueAuthor: "hw-radar-remediation-writer[bot]",
      client: {
        listIssues: async () => {
          listCalls += 1;
          return listCalls === 1 || created === null ? [] : [created];
        },
        createIssue: async (_repository, title, body) => {
          const base = issue("open", body, "hw-radar-remediation-writer[bot]");
          created = { ...base, title };
          throw new Error("response lost");
        },
        updateIssue: async () => {
          throw new Error("must not update");
        },
      },
    });
    expect(result).toMatchObject({ action: "same", attempted: true, issueNumber: 9 });
    expect(result.reason).toContain("Reconciled");
  });

  it("does not reconcile a create when the issue differs from approved evidence", async () => {
    const value = campaign();
    let listCalls = 0;
    const created = {
      ...issue("open", campaignIssueBody(value)),
      title: "different title",
    };
    await expect(
      publishCampaign({
        campaign: value,
        sourceReportGeneratedAt: "2026-11-22T00:00:00.000Z",
        maximumFindings: 50,
        liveAlerts: [alert()],
        trustedIssueAuthor: "hw-radar-remediation-writer[bot]",
        client: {
          listIssues: async () => {
            listCalls += 1;
            return listCalls === 1 ? [] : [created];
          },
          createIssue: async () => {
            throw new Error("response lost");
          },
          updateIssue: async () => {
            throw new Error("must not update");
          },
        },
      }),
    ).rejects.toThrow("response lost");
  });

  it("reports an exact closed issue as a successful no-op", async () => {
    const value = campaign();
    const result = await publishCampaign({
      campaign: value,
      sourceReportGeneratedAt: "2026-11-22T00:00:00.000Z",
      maximumFindings: 50,
      liveAlerts: [alert()],
      trustedIssueAuthor: "hw-radar-remediation-writer[bot]",
      client: {
        listIssues: async () => [issue("closed", campaignIssueBody(value))],
        createIssue: async () => {
          throw new Error("must not create");
        },
        updateIssue: async () => {
          throw new Error("must not update");
        },
      },
    });
    expect(result).toMatchObject({ action: "closed", attempted: false, issueNumber: 9 });
  });

  it("creates the selected campaign when another valid campaign already exists", async () => {
    const value = campaign();
    let creates = 0;
    const result = await publishCampaign({
      campaign: value,
      sourceReportGeneratedAt: "2026-11-22T00:00:00.000Z",
      maximumFindings: 50,
      liveAlerts: [alert()],
      trustedIssueAuthor: "hw-radar-remediation-writer[bot]",
      client: {
        listIssues: async () => [
          issue(
            "open",
            `<!-- radar-remediator:campaign=${"b".repeat(24)} -->\n## Remediation campaign`,
            "hw-radar-remediation-writer[bot]",
          ),
        ],
        createIssue: async (_repository, title, body) => {
          creates += 1;
          return { ...issue("open", body), title };
        },
        updateIssue: async () => {
          throw new Error("must not write");
        },
      },
    });
    expect(result).toMatchObject({ action: "create", attempted: true, issueNumber: 9 });
    expect(creates).toBe(1);
  });
});
