import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

import { loadHubConfig } from "../src/config.js";
import { reconcileFindings, reconcileFindingsForScope } from "../src/findings.js";
import type { DependencyAlert, RadarCve } from "../src/types.js";

async function fixture<T>(name: string): Promise<T> {
  return JSON.parse(
    await readFile(new URL(`./fixtures/basic/${name}`, import.meta.url), "utf8"),
  ) as T;
}

describe("finding reconciliation", () => {
  it("uses Dependabot alerts as evidence and ignores disabled repositories", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const alerts = await fixture<DependencyAlert[]>("alerts.json");
    const cves = await fixture<RadarCve[]>("radar.json");
    const findings = reconcileFindings(config.repositories, alerts, cves);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      repositoryFullName: "example-org/sample-repo",
      identity: "GHSA-AAAA-BBBB-CCCC",
      severity: "critical",
      radarUrl: "https://radar.cloudflare.com/zero-wire/cves/CVE-2026-100001",
      package: { firstPatchedVersion: "2.4.1" },
    });
  });

  it("returns no finding merely because a Radar CVE exists", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const cves = await fixture<RadarCve[]>("radar.json");
    expect(reconcileFindings(config.repositories, [], cves)).toEqual([]);
  });

  it("does not collapse separate alerts for the same advisory and package", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const alerts = await fixture<DependencyAlert[]>("alerts.json");
    const cves = await fixture<RadarCve[]>("radar.json");
    const alert = alerts.find((item) => item.state === "open");
    if (!alert) throw new Error("fixture missing");
    const duplicate = {
      ...alert,
      alertNumber: alert.alertNumber + 100,
      package: {
        ...alert.package,
        vulnerableVersionRange: ">= 1.0.0, < 2.4.1",
      },
    };
    const findings = reconcileFindings(config.repositories, [alert, duplicate], cves);
    expect(findings).toHaveLength(2);
    expect(new Set(findings.map((finding) => finding.key)).size).toBe(2);
  });

  it("audits newly App-visible repositories without an allowlist entry", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const alerts = await fixture<DependencyAlert[]>("alerts.json");
    const cves = await fixture<RadarCve[]>("radar.json");
    const newRepositoryAlert: DependencyAlert = {
      ...alerts[0]!,
      repositoryId: 999,
      repositoryFullName: "example-org/new-sample",
      alertNumber: 31,
      htmlUrl: "https://github.com/example-org/new-sample/security/dependabot/31",
    };
    const findings = reconcileFindingsForScope(
      {
        repositories: config.repositories,
        appInstalls: true,
        repositoryDefaults: {
          owner: "*",
          name: "*",
          enabled: true,
          ...config.repositoryDefaults,
        },
      },
      [newRepositoryAlert],
      cves,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.repositoryFullName).toBe("example-org/new-sample");
  });

  it("honors explicit App-wide exclusions", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const alerts = await fixture<DependencyAlert[]>("alerts.json");
    const cves = await fixture<RadarCve[]>("radar.json");
    const findings = reconcileFindingsForScope(
      {
        repositories: config.repositories,
        appInstalls: true,
        repositoryDefaults: {
          owner: "*",
          name: "*",
          enabled: true,
          ...config.repositoryDefaults,
        },
      },
      alerts.filter((alert) => alert.repositoryFullName === "example-org/disabled-sample"),
      cves,
    );
    expect(findings).toEqual([]);
  });

  it("rejects App-visible repositories from unconfigured installation owners", async () => {
    const config = await loadHubConfig(
      new URL("./fixtures/basic/config.json", import.meta.url).pathname,
    );
    const alerts = await fixture<DependencyAlert[]>("alerts.json");
    const cves = await fixture<RadarCve[]>("radar.json");
    const outsideScope: DependencyAlert = {
      ...alerts[0]!,
      repositoryId: 1000,
      repositoryFullName: "another-owner/outside-scope",
      alertNumber: 40,
      htmlUrl: "https://github.com/another-owner/outside-scope/security/dependabot/40",
    };
    const findings = reconcileFindingsForScope(
      {
        repositories: [],
        appInstalls: false,
        repositoryDefaults: {
          owner: "*",
          name: "*",
          enabled: true,
          ...config.repositoryDefaults,
        },
      },
      [outsideScope],
      cves,
    );
    expect(findings).toEqual([]);
  });
});
