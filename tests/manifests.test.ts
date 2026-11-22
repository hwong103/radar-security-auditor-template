import { describe, expect, it } from "vitest";

import {
  ecosystemFromManifestPath,
  isValidVersion,
  isValidVersionRange,
  isVersionInRange,
  matchInstalledPackages,
  parseCargoLock,
  parseGoSum,
  parseManifestFiles,
  parseNpmLockfile,
  parsePipfileLock,
  parsePipRequirements,
  parsePoetryLock,
  parseUvLock,
} from "../src/manifests.js";

describe("manifest exposure matching", () => {
  it("matches an installed npm package in a vulnerable range", () => {
    const lockfile = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "node_modules/bad-package": { name: "bad-package", version: "2.3.0" },
      },
    });
    const installed = parseNpmLockfile(lockfile, "package-lock.json");
    expect(
      matchInstalledPackages(installed, [
        { ecosystem: "npm", name: "bad-package", vulnerableVersionRange: ">=2.0.0 <2.4.1" },
      ]),
    ).toEqual(installed);
  });

  it("does not match a patched npm package", () => {
    const lockfile = JSON.stringify({
      packages: {
        "node_modules/bad-package": { name: "bad-package", version: "2.4.1" },
      },
    });
    expect(
      matchInstalledPackages(parseNpmLockfile(lockfile, "package-lock.json"), [
        { ecosystem: "npm", name: "bad-package", vulnerableVersionRange: "<2.4.1" },
      ]),
    ).toEqual([]);
  });

  it("parses pinned pip requirements", () => {
    expect(
      parsePipRequirements(
        [
          "# pinned production dependencies",
          "Requests==2.31.0  # comment",
          "zope.interface==6.1",
          "Backport-Zoneinfo==0.2.13; python_version < '3.9'",
          "urllib3>=2",
          "-r requirements-dev.txt",
        ].join("\n"),
        "requirements.txt",
      ),
    ).toEqual([
      {
        ecosystem: "pip",
        name: "requests",
        version: "2.31.0",
        manifestPath: "requirements.txt",
      },
      {
        ecosystem: "pip",
        name: "zope-interface",
        version: "6.1",
        manifestPath: "requirements.txt",
      },
      {
        ecosystem: "pip",
        name: "backport-zoneinfo",
        version: "0.2.13",
        manifestPath: "requirements.txt",
      },
    ]);
  });

  it("recognizes nested Python manifest conventions", () => {
    expect(ecosystemFromManifestPath("requirements-dev.txt")).toBe("pip");
    expect(ecosystemFromManifestPath("services/api/requirements-prod.txt")).toBe("pip");
    expect(ecosystemFromManifestPath("Pipfile.lock")).toBe("pip");
    expect(ecosystemFromManifestPath("service/poetry.lock")).toBe("pip");
    expect(ecosystemFromManifestPath("service/uv.lock")).toBe("pip");
  });

  it("matches Python names after PEP 503 normalization", () => {
    expect(
      matchInstalledPackages(
        [
          {
            ecosystem: "pip",
            name: "zope.interface",
            version: "6.1",
            manifestPath: "requirements.txt",
          },
        ],
        [
          {
            ecosystem: "pip",
            name: "Zope-Interface",
            vulnerableVersionRange: "<6.2",
          },
        ],
      ),
    ).toHaveLength(1);
  });

  it("collapses repeated separators only for Python package identity", () => {
    expect(
      matchInstalledPackages(
        [
          {
            ecosystem: "pip",
            name: "zope.interface",
            version: "6.1",
            manifestPath: "requirements.txt",
          },
        ],
        [
          {
            ecosystem: "pip",
            name: "zope__interface",
            vulnerableVersionRange: "<6.2",
          },
        ],
      ),
    ).toHaveLength(1);
    expect(
      matchInstalledPackages(
        [
          {
            ecosystem: "npm",
            name: "zope.interface",
            version: "6.1.0",
            manifestPath: "package-lock.json",
          },
        ],
        [
          {
            ecosystem: "npm",
            name: "zope-interface",
            vulnerableVersionRange: "<7.0.0",
          },
        ],
      ),
    ).toEqual([]);
  });

  it("uses PEP 440 semantics, including epochs and prereleases", () => {
    expect(isVersionInRange("1.0rc1", ">=1.0rc1, <1.0", "pip")).toBe(true);
    expect(isVersionInRange("1.0", ">=1.0rc1, <1.0", "pip")).toBe(false);
    expect(isVersionInRange("1!2.0", ">=1!1.0, <1!3.0", "pip")).toBe(true);
    expect(isVersionInRange("2026.7.22", ">= 2019.03.09, < 2026.10.18", "pip")).toBe(true);
  });

  it("parses Poetry lock packages", () => {
    const text = `[[package]]
name = "Requests"
version = "2.31.0"

[[package]]
name = "zope.interface"
version = "6.1"
`;
    expect(parsePoetryLock(text, "poetry.lock")).toEqual([
      {
        ecosystem: "pip",
        name: "requests",
        version: "2.31.0",
        manifestPath: "poetry.lock",
      },
      {
        ecosystem: "pip",
        name: "zope-interface",
        version: "6.1",
        manifestPath: "poetry.lock",
      },
    ]);
  });

  it("parses uv lock packages", () => {
    const text = `[[package]]
name = "Requests"
version = "2.31.0"

[[package]]
name = "zope.interface"
version = "6.1"
`;
    expect(parseUvLock(text, "uv.lock")).toHaveLength(2);
    expect(parseManifestFiles("uv.lock", text)[0]?.name).toBe("requests");
  });

  it("parses Pipfile lock default and develop packages", () => {
    const text = JSON.stringify({
      default: {
        Requests: { version: "==2.31.0" },
        "zope.interface": { version: "==6.1" },
      },
      develop: {
        pytest: { version: "==8.3.0" },
      },
    });
    expect(parsePipfileLock(text, "Pipfile.lock")).toEqual([
      {
        ecosystem: "pip",
        name: "requests",
        version: "2.31.0",
        manifestPath: "Pipfile.lock",
      },
      {
        ecosystem: "pip",
        name: "zope-interface",
        version: "6.1",
        manifestPath: "Pipfile.lock",
      },
      {
        ecosystem: "pip",
        name: "pytest",
        version: "8.3.0",
        manifestPath: "Pipfile.lock",
      },
    ]);
    expect(parseManifestFiles("Pipfile.lock", text)).toHaveLength(3);
  });

  it("parses Go checksum modules without duplicates", () => {
    expect(
      parseGoSum(
        "golang.org/x/net v0.10.0 h1:abc\ngolang.org/x/net v0.10.0/go.mod h1:def\n",
        "go.sum",
      ),
    ).toEqual([
      {
        ecosystem: "go",
        name: "golang.org/x/net",
        version: "v0.10.0",
        manifestPath: "go.sum",
      },
    ]);
  });

  it("parses Cargo lockfile package blocks", () => {
    expect(
      parseCargoLock('[[package]]\nname = "example"\nversion = "1.2.3"\n', "Cargo.lock"),
    ).toEqual([
      { ecosystem: "rust", name: "example", version: "1.2.3", manifestPath: "Cargo.lock" },
    ]);
  });

  it("supports comma-separated and space-separated range conjunctions", () => {
    expect(isVersionInRange("1.2.3", ">=1.0.0, <2.0.0")).toBe(true);
    expect(isVersionInRange("1.2.3", ">=1.0.0 <2.0.0")).toBe(true);
    expect(isVersionInRange("2.0.1", ">=1.0.0, <2.0.0")).toBe(false);
  });

  it("matches GitHub ranges that use commas between comparators", () => {
    expect(isVersionInRange("7.0.4", ">= 7.0.0, < 7.0.5")).toBe(true);
    expect(isVersionInRange("7.0.5", ">= 7.0.0, < 7.0.5")).toBe(false);
  });

  it("uses npm SemVer semantics for caret and prerelease ranges", () => {
    expect(isVersionInRange("0.9.0", "^0.2.3")).toBe(false);
    expect(isVersionInRange("1.2.3-beta.1", ">=1.2.3-beta.1 <1.2.3")).toBe(true);
  });

  it("validates versions and ranges for the selected ecosystem", () => {
    expect(isValidVersion("1.2.3", "npm")).toBe(true);
    expect(isValidVersion("latest", "npm")).toBe(false);
    expect(isValidVersion("1.0rc1", "pip")).toBe(true);
    expect(isValidVersionRange(">=1.0.0, <2.0.0", "npm")).toBe(true);
    expect(isValidVersionRange("affected versions", "npm")).toBe(false);
    expect(isValidVersionRange(">=1.0rc1, <2", "pip")).toBe(true);
    expect(isValidVersionRange("affected versions", "pip")).toBe(false);
  });

  it("infers npm package names from lockfile paths", () => {
    expect(
      parseNpmLockfile(
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            "node_modules/a": { version: "1.0.0" },
            "node_modules/a/node_modules/b": { version: "2.0.0" },
          },
        }),
        "package-lock.json",
      ).map(({ name }) => name),
    ).toEqual(["a", "b"]);
  });
});
