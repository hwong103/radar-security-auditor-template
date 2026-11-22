import { describe, expect, it } from "vitest";

import { potentialExposures } from "../src/exposure.js";

const radar = [
  {
    id: "CVE-2026-100001",
    url: "https://radar.cloudflare.com/zero-wire/cves/CVE-2026-100001",
    title: "test",
    summary: "test",
    publishedAt: "2026-11-20T00:00:00.000Z",
    severity: "critical" as const,
    score: 9.8,
    cvssVersion: "3.1",
  },
];

describe("potential exposure without Dependabot", () => {
  it("reports an installed manifest package that matches the GHSA range", () => {
    const exposures = potentialExposures({
      radar,
      advisories: [
        {
          cveId: "CVE-2026-100001",
          ecosystem: "npm",
          packageName: "bad-package",
          vulnerableVersionRange: "<2.4.1",
          firstPatchedVersion: "2.4.1",
        },
      ],
      manifests: {
        "package-lock.json": [
          {
            ecosystem: "npm",
            name: "bad-package",
            version: "2.3.0",
            manifestPath: "package-lock.json",
          },
        ],
      },
    });
    expect(exposures[0]?.package.name).toBe("bad-package");
  });

  it("does not report a package outside the affected range", () => {
    expect(
      potentialExposures({
        radar,
        advisories: [
          {
            cveId: "CVE-2026-100001",
            ecosystem: "npm",
            packageName: "bad-package",
            vulnerableVersionRange: "<2.4.1",
            firstPatchedVersion: "2.4.1",
          },
        ],
        manifests: {
          "package-lock.json": [
            {
              ecosystem: "npm",
              name: "bad-package",
              version: "2.4.1",
              manifestPath: "package-lock.json",
            },
          ],
        },
      }),
    ).toEqual([]);
  });

  it("checks every affected range when the same package appears more than once", () => {
    const exposures = potentialExposures({
      radar,
      advisories: [
        {
          cveId: "CVE-2026-100001",
          ecosystem: "npm",
          packageName: "bad-package",
          vulnerableVersionRange: "<2.0.0",
          firstPatchedVersion: "2.0.0",
        },
        {
          cveId: "CVE-2026-100001",
          ecosystem: "npm",
          packageName: "bad-package",
          vulnerableVersionRange: ">=3.0.0 <4.0.0",
          firstPatchedVersion: "4.0.0",
        },
      ],
      manifests: {
        "package-lock.json": [
          {
            ecosystem: "npm",
            name: "bad-package",
            version: "1.0.0",
            manifestPath: "package-lock.json",
          },
        ],
      },
    });
    expect(exposures.map((entry) => entry.advisory.firstPatchedVersion)).toEqual(["2.0.0"]);
  });

  it("uses canonical rust identity for Cargo advisories", () => {
    const exposures = potentialExposures({
      radar,
      advisories: [
        {
          cveId: "CVE-2026-100001",
          ecosystem: "rust",
          packageName: "bad-crate",
          vulnerableVersionRange: "<2.0.0",
          firstPatchedVersion: "2.0.0",
        },
      ],
      manifests: {
        "Cargo.lock": [
          {
            ecosystem: "rust",
            name: "bad-crate",
            version: "1.0.0",
            manifestPath: "Cargo.lock",
          },
        ],
      },
    });
    expect(exposures).toHaveLength(1);
  });
});
