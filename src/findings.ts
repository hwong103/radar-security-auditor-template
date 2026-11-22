import { createHash } from "node:crypto";

import { githubEcosystemToEcosystem } from "./github.js";
import type { DependencyAlert, Finding, RadarCve, RepositoryConfig } from "./types.js";

export function stableFindingKey(parts: readonly (string | number | null)[]): string {
  return createHash("sha256")
    .update(parts.map(String).join("\0"))
    .digest("hex")
    .slice(0, 24);
}

export function findingMarker(key: string): string {
  return `<!-- radar-remediator:finding=${key} -->`;
}

export function findingKeyForAlert(
  repositoryFullName: string,
  alert: DependencyAlert,
): string {
  const identity =
    alert.ghsaId ??
    alert.cveIds[0] ??
    stableFindingKey([alert.package.ecosystem, alert.package.name, alert.summary]);
  return stableFindingKey([
    repositoryFullName.toLowerCase(),
    alert.alertNumber,
    identity,
    alert.package.ecosystem,
    alert.package.name.toLowerCase(),
    normalizeManifest(alert.package.manifestPath),
  ]);
}

export function normalizeManifest(value: string | null): string {
  return (value ?? "")
    .replaceAll("\\", "/")
    .replace(/^\.?\//, "")
    .toLowerCase();
}

function aliasesForAlert(alert: DependencyAlert): readonly string[] {
  const aliases = [alert.ghsaId, ...alert.cveIds].filter(
    (value): value is string => typeof value === "string" && value.length > 0,
  );
  return [...new Set(aliases.map((value) => value.toUpperCase()))];
}

export function findingFromAlert(alert: DependencyAlert, radar: RadarCve | null): Finding {
  const key = findingKeyForAlert(alert.repositoryFullName, alert);
  const aliases = aliasesForAlert(alert);
  const identity = aliases[0] ?? key;
  return {
    key,
    repositoryFullName: alert.repositoryFullName,
    repositoryId: alert.repositoryId,
    alertNumber: alert.alertNumber,
    identity,
    aliases,
    severity: alert.severity,
    summary: alert.summary || `Dependency vulnerability in ${alert.package.name}`,
    description: alert.description,
    htmlUrl: alert.htmlUrl,
    package: alert.package,
    radarUrl: radar?.url ?? null,
    createdFrom: "dependabot",
  };
}

export function radarIndex(cves: readonly RadarCve[]): ReadonlyMap<string, RadarCve> {
  return new Map(cves.map((cve) => [cve.id.toUpperCase(), cve]));
}

export function radarForAlert(
  alert: DependencyAlert,
  radar: ReadonlyMap<string, RadarCve>,
): RadarCve | null {
  for (const cve of alert.cveIds) {
    const match = radar.get(cve.toUpperCase());
    if (match) return match;
  }
  return null;
}

export function reconcileFindings(
  repositories: readonly RepositoryConfig[],
  alerts: readonly DependencyAlert[],
  cves: readonly RadarCve[],
): readonly Finding[] {
  return reconcileFindingsForScope({ repositories, appInstalls: false }, alerts, cves);
}

export interface FindingScope {
  readonly repositories: readonly RepositoryConfig[];
  readonly appInstalls: boolean;
  readonly repositoryDefaults?: RepositoryConfig;
}

export function reconcileFindingsForScope(
  scope: FindingScope,
  alerts: readonly DependencyAlert[],
  cves: readonly RadarCve[],
): readonly Finding[] {
  const byRadar = radarIndex(cves);
  return alerts
    .filter((alert) => alert.state === "open")
    .filter((alert) => {
      const [owner, name] = splitName(alert.repositoryFullName);
      const repository = scope.appInstalls
        ? (scope.repositories.find(
            (item) =>
              item.owner.toLowerCase() === owner.toLowerCase() &&
              item.name.toLowerCase() === name.toLowerCase(),
          ) ??
          scope.repositoryDefaults ??
          null)
        : (scope.repositories.find(
            (item) =>
              item.owner.toLowerCase() === owner.toLowerCase() &&
              item.name.toLowerCase() === name.toLowerCase(),
          ) ?? null);
      if (!repository || !repository.enabled) return false;
      const ecosystem = githubEcosystemToEcosystem(alert.package.ecosystem);
      return ecosystem !== null && repository.allowedEcosystems.includes(ecosystem);
    })
    .map((alert) => findingFromAlert(alert, radarForAlert(alert, byRadar)))
    .sort((left, right) => severityRank(left.severity) - severityRank(right.severity));
}

function splitName(repository: string): [string, string] {
  const parts = repository.split("/");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error(`Expected owner/name, received ${repository}`);
  }
  return [parts[0], parts[1]];
}

export function severityRank(value: Finding["severity"]): number {
  return ["critical", "high", "medium", "low", "unknown"].indexOf(value);
}

export function findingByIdentity(
  findings: readonly Finding[],
  identity: string,
): Finding | null {
  const normalized = identity.toUpperCase();
  return (
    findings.find((finding) => finding.aliases.some((alias) => alias === normalized)) ??
    null
  );
}
