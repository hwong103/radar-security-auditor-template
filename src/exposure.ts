import type { InstalledPackage, PackageCandidate } from "./manifests.js";
import { isVersionInRange, matchInstalledPackages, packageKey } from "./manifests.js";
import type { Ecosystem, Finding, RadarCve } from "./types.js";

export interface ExposureAdvisory {
  readonly cveId: string;
  readonly ecosystem: string;
  readonly packageName: string;
  readonly vulnerableVersionRange: string | null;
  readonly firstPatchedVersion: string | null;
}

export interface ExposureInput {
  readonly radar: readonly RadarCve[];
  readonly advisories: readonly ExposureAdvisory[];
  readonly manifests: Readonly<Record<string, readonly InstalledPackage[]>>;
}

export function potentialExposureCandidates(
  input: ExposureInput,
): readonly PackageCandidate[] {
  const radarIds = new Set(input.radar.map((item) => item.id.toUpperCase()));
  return input.advisories
    .filter((advisory) => radarIds.has(advisory.cveId.toUpperCase()))
    .map((advisory) => ({
      ecosystem: advisory.ecosystem as PackageCandidate["ecosystem"],
      name: advisory.packageName,
      vulnerableVersionRange: advisory.vulnerableVersionRange,
    }));
}

export function potentialExposures(input: ExposureInput): readonly {
  readonly package: InstalledPackage;
  readonly advisory: ExposureAdvisory;
}[] {
  const candidates = potentialExposureCandidates(input);
  const exposed = matchInstalledPackages(Object.values(input.manifests).flat(), candidates);
  return exposed.flatMap((pkg) => {
    return input.advisories
      .filter(
        (item) =>
          item.ecosystem === pkg.ecosystem &&
          packageKey(pkg.ecosystem, item.packageName) ===
            packageKey(pkg.ecosystem, pkg.name) &&
          (!item.vulnerableVersionRange ||
            isVersionInRange(
              pkg.version,
              item.vulnerableVersionRange,
              pkg.ecosystem === "pip" ? "pip" : "npm",
            )),
      )
      .map((advisory) => ({ package: pkg, advisory }));
  });
}

export function exposureUnavailable(ecosystem: Ecosystem | null): boolean {
  return ecosystem === null || ecosystem === "composer";
}

export function isFindingConfirmed(finding: Finding): boolean {
  return finding.createdFrom === "dependabot" && finding.alertNumber !== null;
}
