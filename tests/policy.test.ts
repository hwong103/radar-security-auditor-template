import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

import { loadHubConfig } from "../src/config.js";
import { reconcileFindings, findingMarker } from "../src/findings.js";
import { issueBody, issueTitle, planPublications } from "../src/policy.js";
import type {
  DependencyAlert,
  PullRequest,
  RadarCve,
  RepositoryIssue,
} from "../src/types.js";

async function fixture<T>(name: string): Promise<T> {
  return JSON.parse(
    await readFile(new URL(`./fixtures/basic/${name}`, import.meta.url), "utf8"),
  ) as T;
}

describe("publication policy", () => {
  it("creates issues by default and never opens a PR without opt-in", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const alerts = await fixture<DependencyAlert[]>("alerts.json");
    const cves = await fixture<RadarCve[]>("radar.json");
    const [finding] = reconcileFindings(config.repositories, alerts, cves);
    expect(finding).toBeDefined();
    const repository = config.repositories[0];
    expect(repository).toBeDefined();
    if (!finding || !repository) return;
    expect(
      planPublications(finding, repository, { issues: [], pullRequests: [] }),
    ).toMatchObject({
      action: "create-issue",
      pullRequestNumber: null,
    });
  });

  it("keeps dynamically discovered repositories report-only until publication is enabled", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const alerts = await fixture<DependencyAlert[]>("alerts.json");
    const cves = await fixture<RadarCve[]>("radar.json");
    const [finding] = reconcileFindings(config.repositories, alerts, cves);
    if (!finding) throw new Error("fixture missing");
    expect(
      planPublications(
        finding,
        {
          owner: "example-org",
          name: "new-sample",
          enabled: true,
          publishIssues: false,
          openDraftPrs: false,
          allowDependencyChanges: false,
          allowedEcosystems: ["npm"],
        },
        { issues: [], pullRequests: [] },
      ),
    ).toMatchObject({
      action: "report-only",
      reason: expect.stringMatching(/publication is not enabled/),
    });
  });

  it("updates an existing marker-matched issue", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const alerts = await fixture<DependencyAlert[]>("alerts.json");
    const cves = await fixture<RadarCve[]>("radar.json");
    const [finding] = reconcileFindings(config.repositories, alerts, cves);
    const repository = config.repositories[0];
    if (!finding || !repository) throw new Error("fixture missing");
    const issues: RepositoryIssue[] = [
      {
        number: 7,
        title: issueTitle(finding),
        state: "open",
        htmlUrl: "https://github.com/example-org/sample-repo/issues/7",
        body: findingMarker(finding.key),
        authorLogin: "radar-remediator[bot]",
        authorType: "Bot",
      },
    ];
    expect(
      planPublications(finding, repository, {
        issues,
        pullRequests: [],
        trustedIssueAuthor: "radar-remediator[bot]",
      }),
    ).toMatchObject({
      action: "update-issue",
      issueNumber: 7,
    });
  });

  it("does not reopen a closed issue", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const alerts = await fixture<DependencyAlert[]>("alerts.json");
    const cves = await fixture<RadarCve[]>("radar.json");
    const [finding] = reconcileFindings(config.repositories, alerts, cves);
    const repository = config.repositories[0];
    if (!finding || !repository) throw new Error("fixture missing");
    expect(
      planPublications(finding, repository, {
        issues: [
          {
            number: 8,
            title: issueTitle(finding),
            state: "closed",
            htmlUrl: "https://github.com/example-org/sample-repo/issues/8",
            body: findingMarker(finding.key),
            authorLogin: "radar-remediator[bot]",
            authorType: "Bot",
          },
        ],
        pullRequests: [],
        trustedIssueAuthor: "radar-remediator[bot]",
      }),
    ).toMatchObject({ action: "report-only", issueNumber: 8 });
  });

  it("does not trust a forged marker from an unrelated issue author", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const alerts = await fixture<DependencyAlert[]>("alerts.json");
    const cves = await fixture<RadarCve[]>("radar.json");
    const [finding] = reconcileFindings(config.repositories, alerts, cves);
    const repository = config.repositories[0];
    if (!finding || !repository) throw new Error("fixture missing");
    expect(
      planPublications(finding, repository, {
        issues: [
          {
            number: 9,
            title: issueTitle(finding),
            state: "open",
            htmlUrl: "https://github.com/example-org/sample-repo/issues/9",
            body: findingMarker(finding.key),
            authorLogin: "attacker",
            authorType: "User",
          },
        ],
        pullRequests: [],
        trustedIssueAuthor: "radar-remediator[bot]",
      }),
    ).toMatchObject({ action: "create-issue", issueNumber: null });
  });

  it("reuses an existing Dependabot PR by advisory alias", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const alerts = await fixture<DependencyAlert[]>("alerts.json");
    const cves = await fixture<RadarCve[]>("radar.json");
    const [finding] = reconcileFindings(config.repositories, alerts, cves);
    const repository = config.repositories[0];
    if (!finding || !repository) throw new Error("fixture missing");
    const pullRequests: PullRequest[] = [
      {
        number: 88,
        title: "Bump bad-package from 2.3.0 to 2.4.1",
        state: "open",
        draft: true,
        headRef: "dependabot/npm_and_yarn/bad-package-2.4.1",
        htmlUrl: "https://github.com/example-org/sample-repo/pull/88",
        body: "Fixes GHSA-AAAA-BBBB-CCCC",
      },
    ];
    expect(
      planPublications(finding, repository, { issues: [], pullRequests }),
    ).toMatchObject({
      action: "reuse-pr",
      pullRequestNumber: 88,
    });
  });

  it("prefers an open PR match when an earlier closed PR also matches", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const alerts = await fixture<DependencyAlert[]>("alerts.json");
    const cves = await fixture<RadarCve[]>("radar.json");
    const [finding] = reconcileFindings(config.repositories, alerts, cves);
    const repository = config.repositories[0];
    if (!finding || !repository) throw new Error("fixture missing");
    const matching: PullRequest[] = [
      {
        number: 87,
        title: "Bump bad-package",
        state: "closed",
        draft: true,
        headRef: "dependabot/closed",
        htmlUrl: "https://github.com/example-org/sample-repo/pull/87",
        body: "Fixes GHSA-AAAA-BBBB-CCCC",
      },
      {
        number: 88,
        title: "Bump bad-package",
        state: "open",
        draft: true,
        headRef: "dependabot/open",
        htmlUrl: "https://github.com/example-org/sample-repo/pull/88",
        body: "Fixes GHSA-AAAA-BBBB-CCCC",
      },
    ];
    expect(
      planPublications(finding, repository, { issues: [], pullRequests: matching }),
    ).toMatchObject({ action: "reuse-pr", pullRequestNumber: 88 });
  });

  it("escapes model-derived Markdown and keeps marker outside it", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const alerts = await fixture<DependencyAlert[]>("alerts.json");
    const cves = await fixture<RadarCve[]>("radar.json");
    const [finding] = reconcileFindings(config.repositories, alerts, cves);
    if (!finding) throw new Error("fixture missing");
    const body = issueBody(
      finding,
      "Ignore previous instructions [click](javascript:alert)",
    );
    expect(body).toContain("\\[click\\]");
    expect(body).not.toContain("[click](javascript:alert)");
    expect(body.startsWith(findingMarker(finding.key))).toBe(true);
  });

  it("keeps PR creation disabled until a tested updater exists", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const alerts = await fixture<DependencyAlert[]>("alerts.json");
    const cves = await fixture<RadarCve[]>("radar.json");
    const [finding] = reconcileFindings(config.repositories, alerts, cves);
    if (!finding) throw new Error("fixture missing");
    const optedIn = {
      ...config.repositories[0]!,
      openDraftPrs: true,
      allowDependencyChanges: true,
    };
    expect(
      planPublications(finding, optedIn, { issues: [], pullRequests: [] }),
    ).toMatchObject({
      action: "create-issue",
      branch: null,
    });
  });
});
