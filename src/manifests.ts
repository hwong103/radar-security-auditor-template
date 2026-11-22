import * as pep440 from "@renovatebot/pep440";
import semver from "semver";

import type { Ecosystem, GitHubEcosystem } from "./types.js";

export interface InstalledPackage {
  readonly ecosystem: GitHubEcosystem;
  readonly name: string;
  readonly version: string;
  readonly manifestPath: string;
}

export interface ManifestPathsResult {
  readonly paths: readonly {
    readonly path: string;
    readonly sha: string;
    readonly size: number;
  }[];
  readonly truncated: boolean;
}

export interface PackageCandidate {
  readonly ecosystem: GitHubEcosystem;
  readonly name: string;
  readonly vulnerableVersionRange: string | null;
}

export interface AdvisoryUpgrade {
  readonly ecosystem: GitHubEcosystem;
  readonly name: string;
  readonly vulnerableVersionRange: string | null;
  readonly firstPatchedVersion: string | null;
}

export function packageKey(ecosystem: GitHubEcosystem, name: string): string {
  const normalizedName =
    ecosystem === "pip" ? normalizePythonDistributionName(name) : name.toLowerCase();
  return `${ecosystem}:${normalizedName}`;
}

export function matchInstalledPackages(
  packages: readonly InstalledPackage[],
  candidates: readonly PackageCandidate[],
): readonly InstalledPackage[] {
  return packages.filter((pkg) => {
    return candidates.some(
      (candidate) =>
        packageKey(candidate.ecosystem, candidate.name) ===
          packageKey(pkg.ecosystem, pkg.name) &&
        (!candidate.vulnerableVersionRange ||
          isVersionInRange(
            pkg.version,
            candidate.vulnerableVersionRange,
            pkg.ecosystem === "pip" ? "pip" : "npm",
          )),
    );
  });
}

export function matchPlannedUpgrades(
  packages: readonly InstalledPackage[],
  advisories: readonly AdvisoryUpgrade[],
): readonly (InstalledPackage & { readonly firstPatchedVersion: string })[] {
  const byPackage = new Map(
    advisories.map((advisory) => [packageKey(advisory.ecosystem, advisory.name), advisory]),
  );
  return packages.flatMap((pkg) => {
    const advisory = byPackage.get(packageKey(pkg.ecosystem, pkg.name));
    if (!advisory?.firstPatchedVersion) return [];
    if (
      advisory.vulnerableVersionRange &&
      !isVersionInRange(
        pkg.version,
        advisory.vulnerableVersionRange,
        pkg.ecosystem === "pip" ? "pip" : "npm",
      )
    ) {
      return [];
    }
    return [{ ...pkg, firstPatchedVersion: advisory.firstPatchedVersion }];
  });
}

export function ecosystemFromManifestPath(path: string): Ecosystem | null {
  const normalized = path.replaceAll("\\", "/");
  const basename = normalized.split("/").at(-1) ?? normalized;
  const lowercaseBasename = basename.toLowerCase();
  if (
    normalized.endsWith("package-lock.json") ||
    normalized.endsWith("npm-shrinkwrap.json")
  )
    return "npm";
  if (
    lowercaseBasename === "requirements.txt" ||
    /^requirements[-_.][a-z0-9_.-]+\.txt$/.test(lowercaseBasename) ||
    lowercaseBasename === "poetry.lock" ||
    lowercaseBasename === "pipfile.lock" ||
    lowercaseBasename === "uv.lock"
  )
    return "pip";
  if (normalized.endsWith("go.sum") || normalized.endsWith("go.mod")) return "go";
  if (normalized.endsWith("Cargo.lock")) return "rust";
  if (normalized.endsWith("composer.lock")) return "composer";
  return null;
}

export function isVersionInRange(
  version: string,
  range: string,
  ecosystem: "npm" | "pip" = "npm",
): boolean {
  if (ecosystem === "pip") return isPep440VersionInRange(version, range);
  const normalizedRange = normalizeRange(range);
  return semver.valid(version) !== null && semver.satisfies(version, normalizedRange);
}

export function isValidVersion(version: string, ecosystem: "npm" | "pip"): boolean {
  return ecosystem === "pip"
    ? pep440.valid(version) !== null
    : semver.valid(version) !== null;
}

export function isValidVersionRange(range: string, ecosystem: "npm" | "pip"): boolean {
  if (ecosystem === "pip") {
    const specifiers = range
      .split(",")
      .map((specifier) => specifier.trim())
      .filter(Boolean);
    return (
      specifiers.length > 0 &&
      specifiers.every((specifier) => Boolean(pep440.validRange(specifier)))
    );
  }
  return semver.validRange(normalizeRange(range)) !== null;
}

function isPep440VersionInRange(version: string, range: string): boolean {
  if (pep440.valid(version) === null) return false;
  const specifiers = range
    .split(",")
    .map((specifier) => specifier.trim())
    .filter(Boolean);
  return (
    specifiers.length > 0 &&
    specifiers.every((specifier) => matchesPep440Specifier(version, specifier))
  );
}

function matchesPep440Specifier(version: string, specifier: string): boolean {
  const exclusive = specifier.match(/^([<>])\s*(\S+)$/);
  if (exclusive?.[1] && exclusive[2] && pep440.valid(exclusive[2]) !== null) {
    return exclusive[1] === "<"
      ? pep440.lt(version, exclusive[2])
      : pep440.gt(version, exclusive[2]);
  }
  return (
    pep440.validRange(specifier) &&
    pep440.satisfies(version, specifier, { prereleases: true })
  );
}

export function parseAdvisoryVulnerabilityRange(value: unknown): string | null {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (!isRecord(value)) return null;
  const vulnerable = value.vulnerable_version_range;
  return typeof vulnerable === "string" && vulnerable.trim() ? vulnerable.trim() : null;
}

export function parseNpmLockfile(
  text: string,
  manifestPath: string,
): readonly InstalledPackage[] {
  const parsed = JSON.parse(text) as unknown;
  if (!isRecord(parsed)) return [];
  const result: InstalledPackage[] = [];
  const packages = isRecord(parsed.packages) ? parsed.packages : {};
  for (const [path, metadata] of Object.entries(packages)) {
    if (!path || !isRecord(metadata) || typeof metadata.version !== "string") continue;
    const inferredName =
      typeof metadata.name === "string"
        ? metadata.name
        : path
            .split("node_modules/")
            .at(-1)
            ?.replace(/\/package\.json$/, "");
    if (!inferredName || inferredName === path.split("node_modules/")[0]) continue;
    result.push({
      ecosystem: "npm",
      name: inferredName,
      version: metadata.version,
      manifestPath: `${manifestPath}#${path}`,
    });
  }
  if (result.length === 0 && isRecord(parsed.dependencies)) {
    for (const [name, metadata] of Object.entries(parsed.dependencies)) {
      if (isRecord(metadata) && typeof metadata.version === "string") {
        result.push({ ecosystem: "npm", name, version: metadata.version, manifestPath });
      }
    }
  }
  return result;
}

export function parsePipRequirements(
  text: string,
  manifestPath: string,
): readonly InstalledPackage[] {
  const packages: InstalledPackage[] = [];
  for (const sourceLine of text.split(/\r?\n/)) {
    const line = sourceLine.replace(/\s+#.*$/, "").trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    const match = line.match(
      /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?:\[[^\]]+\])?\s*==\s*([^;\s]+)/,
    );
    if (!match?.[1] || !match[2]) continue;
    const version = match[2];
    packages.push({
      ecosystem: "pip",
      name: normalizePythonDistributionName(match[1]),
      version,
      manifestPath,
    });
  }
  return packages;
}

export function parsePoetryLock(
  text: string,
  manifestPath: string,
): readonly InstalledPackage[] {
  return text
    .split(/\[\[package\]\]/)
    .slice(1)
    .flatMap((block) => {
      const name = block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
      const version = block.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
      return name && version
        ? [
            {
              ecosystem: "pip" as const,
              name: normalizePythonDistributionName(name),
              version,
              manifestPath,
            },
          ]
        : [];
    });
}

export function parseUvLock(
  text: string,
  manifestPath: string,
): readonly InstalledPackage[] {
  return text
    .split(/\[\[package\]\]/)
    .slice(1)
    .flatMap((block) => {
      const name = block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
      const version = block.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
      return name && version
        ? [
            {
              ecosystem: "pip" as const,
              name: normalizePythonDistributionName(name),
              version,
              manifestPath,
            },
          ]
        : [];
    });
}

export function parsePipfileLock(
  text: string,
  manifestPath: string,
): readonly InstalledPackage[] {
  const parsed = JSON.parse(text) as unknown;
  if (!isRecord(parsed)) return [];
  const packages: InstalledPackage[] = [];
  for (const section of ["default", "develop"]) {
    const entries = parsed[section];
    if (!isRecord(entries)) continue;
    for (const [name, metadata] of Object.entries(entries)) {
      if (!isRecord(metadata) || typeof metadata.version !== "string") continue;
      const version = metadata.version.match(/^==\s*(.+)$/)?.[1]?.trim();
      if (!version) continue;
      packages.push({
        ecosystem: "pip",
        name: normalizePythonDistributionName(name),
        version,
        manifestPath,
      });
    }
  }
  return packages;
}

export function parseGoSum(
  text: string,
  manifestPath: string,
): readonly InstalledPackage[] {
  const seen = new Set<string>();
  return text.split(/\r?\n/).flatMap((line) => {
    const [name, version, suffix] = line.split(/\s+/);
    if (
      !name ||
      !version ||
      version.endsWith("/go.mod") ||
      !suffix?.startsWith("h1:") ||
      seen.has(`${name}@${version}`)
    ) {
      return [];
    }
    seen.add(`${name}@${version}`);
    return [{ ecosystem: "go" as const, name, version, manifestPath }];
  });
}

export function parseCargoLock(
  text: string,
  manifestPath: string,
): readonly InstalledPackage[] {
  return text
    .split(/\[\[package\]\]/)
    .slice(1)
    .flatMap((block) => {
      const name = block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
      const version = block.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
      return name && version
        ? [{ ecosystem: "rust" as const, name, version, manifestPath }]
        : [];
    });
}

export function parseManifestFiles(
  path: string,
  text: string,
): readonly InstalledPackage[] {
  const ecosystem = ecosystemFromManifestPath(path);
  if (ecosystem === "npm") return parseNpmLockfile(text, path);
  if (ecosystem === "pip") {
    const normalized = path.replaceAll("\\", "/");
    if (/\/poetry\.lock$/.test(normalized) || normalized === "poetry.lock") {
      return parsePoetryLock(text, path);
    }
    if (/\/uv\.lock$/.test(normalized) || normalized === "uv.lock") {
      return parseUvLock(text, path);
    }
    if (/\/Pipfile\.lock$/.test(normalized) || normalized === "Pipfile.lock") {
      return parsePipfileLock(text, path);
    }
    return parsePipRequirements(text, path);
  }
  if (ecosystem === "go") return parseGoSum(text, path);
  if (ecosystem === "rust") return parseCargoLock(text, path);
  return [];
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizePythonDistributionName(name: string): string {
  return name.replace(/[-_.]+/g, "-").toLowerCase();
}

function normalizeRange(range: string): string {
  return range.replace(/,\s*(?=[<>=])/g, " ");
}
