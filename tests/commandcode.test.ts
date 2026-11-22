import { describe, expect, it } from "vitest";

import {
  CommandCodeClient,
  COMMAND_CODE_MODELS,
  fallbackAdvice,
  installedEvidenceForFinding,
  needsComplexAdvice,
} from "../src/commandcode.js";
import { HttpTransportImpl } from "../src/http.js";
import type { Finding } from "../src/types.js";

const finding: Finding = {
  key: "c".repeat(24),
  repositoryFullName: "example-org/example",
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

describe("Command Code routing", () => {
  it.each([
    [false, COMMAND_CODE_MODELS.fast],
    [true, COMMAND_CODE_MODELS.complex],
  ])("selects the expected model tier for complex=%s", async (complex, expected) => {
    let requestBody: string | undefined;
    const transport = new HttpTransportImpl({
      fetcher: async (_url, init) => {
        requestBody = String(init?.body ?? "");
        return new Response(
          JSON.stringify({
            choices: [
              {
                message: {
                  content:
                    '{"summary":"Update the dependency.","steps":["Run tests."],"risks":[],"evidenceStatus":"sufficient"}',
                },
              },
            ],
          }),
          { status: 200 },
        );
      },
    });
    const client = new CommandCodeClient({
      transport,
      apiKey: "test",
      zeroDataRetention: true,
    });
    const advice = await client.advise(finding, complex, {
      installedVersions: ["1.0.0"],
    });
    expect(advice.model).toBe(expected);
    expect(advice.tier).toBe(complex ? "complex" : "fast");
    expect(advice.evidenceStatus).toBe("sufficient");
    expect(JSON.parse(requestBody ?? "{}")).toMatchObject({ model: expected });
  });

  it("forces abstention when the installed version is missing", async () => {
    const client = new CommandCodeClient({
      transport: new HttpTransportImpl({
        fetcher: async () =>
          new Response(
            JSON.stringify({
              choices: [
                {
                  message: {
                    content:
                      '{"summary":"Upgrade to 9.9.9.","steps":["Upgrade."],"risks":[],"evidenceStatus":"sufficient"}',
                  },
                },
              ],
            }),
            { status: 200 },
          ),
      }),
      apiKey: "test",
      zeroDataRetention: true,
    });
    const advice = await client.advise(finding);
    expect(advice).toMatchObject({
      evidenceStatus: "insufficient",
      fallback: true,
    });
    expect(advice.summary).toMatch(/insufficient/);
    expect(advice.steps.join(" ")).toMatch(/installed versions/);
    expect(advice.summary).not.toContain("9.9.9");
  });

  it("honors model abstention even when deterministic fields are present", async () => {
    const client = new CommandCodeClient({
      transport: new HttpTransportImpl({
        fetcher: async () =>
          new Response(
            JSON.stringify({
              choices: [
                {
                  message: {
                    content:
                      '{"summary":"Parent constraints are unresolved.","steps":["Inspect the resolver."],"risks":["Compatibility is unproven."],"evidenceStatus":"insufficient"}',
                  },
                },
              ],
            }),
            { status: 200 },
          ),
      }),
      apiKey: "test",
      zeroDataRetention: true,
    });
    const advice = await client.advise(finding, false, {
      installedVersions: ["1.0.0"],
    });
    expect(advice).toMatchObject({ evidenceStatus: "insufficient", fallback: true });
    expect(advice.summary).not.toContain("Parent constraints");
  });

  it("routes ambiguous evidence to the complex tier without treating nesting as complexity", () => {
    expect(needsComplexAdvice(finding)).toBe(false);
    expect(
      needsComplexAdvice({
        ...finding,
        package: { ...finding.package, firstPatchedVersion: null },
      }),
    ).toBe(true);
    expect(
      needsComplexAdvice({
        ...finding,
        package: { ...finding.package, vulnerableVersionRange: null },
      }),
    ).toBe(true);
  });

  it("makes the deterministic fallback abstain when installed evidence is missing", () => {
    expect(fallbackAdvice(finding)).toMatchObject({
      evidenceStatus: "insufficient",
      fallback: true,
    });
    expect(
      fallbackAdvice(finding, COMMAND_CODE_MODELS.fast, "fast", {
        installedVersions: ["1.0.0"],
      }),
    ).toMatchObject({ evidenceStatus: "sufficient" });
  });

  it("requires an installed version from the affected manifest and range", () => {
    const packages = [
      {
        ecosystem: "npm" as const,
        name: "example",
        version: "1.0.0",
        manifestPath: "package-lock.json#apps/web/node_modules/example",
      },
      {
        ecosystem: "npm" as const,
        name: "example",
        version: "9.0.0",
        manifestPath: "package-lock.json#apps/mobile/node_modules/example",
      },
    ];
    const locatedFinding = {
      ...finding,
      package: {
        ...finding.package,
        manifestPath: "package-lock.json#apps/web/node_modules/example",
      },
    };
    expect(installedEvidenceForFinding(locatedFinding, packages)).toEqual(["1.0.0"]);
    expect(installedEvidenceForFinding(locatedFinding, packages.slice(1))).toEqual([]);
  });

  it("does not match another workspace under the same root lockfile", () => {
    const findingForWeb = {
      ...finding,
      package: {
        ...finding.package,
        manifestPath: "package-lock.json#apps/web/node_modules/example",
      },
    };
    expect(
      installedEvidenceForFinding(findingForWeb, [
        {
          ecosystem: "npm",
          name: "example",
          version: "1.0.0",
          manifestPath: "package-lock.json#apps/mobile/node_modules/example",
        },
      ]),
    ).toEqual([]);
  });

  it("does not treat malformed advisory evidence as sufficient", async () => {
    let requested = false;
    const client = new CommandCodeClient({
      transport: new HttpTransportImpl({
        fetcher: async () => {
          requested = true;
          return new Response("{}", { status: 200 });
        },
      }),
      apiKey: "test",
      zeroDataRetention: true,
    });
    const advice = await client.advise(
      {
        ...finding,
        package: { ...finding.package, vulnerableVersionRange: "affected versions" },
      },
      true,
      { installedVersions: ["1.0.0"] },
    );
    expect(requested).toBe(false);
    expect(advice.evidenceStatus).toBe("insufficient");
  });

  it("sends bounded advisory identifiers and matching versions without local manifest paths", async () => {
    let requestBody = "";
    const client = new CommandCodeClient({
      transport: new HttpTransportImpl({
        fetcher: async (_url, init) => {
          requestBody = String(init?.body ?? "");
          return new Response(
            JSON.stringify({
              choices: [
                {
                  message: {
                    content:
                      '{"summary":"Upgrade the dependency.","steps":["Run tests."],"risks":[],"evidenceStatus":"sufficient"}',
                  },
                },
              ],
            }),
            { status: 200 },
          );
        },
      }),
      apiKey: "test",
      zeroDataRetention: true,
    });
    await client.advise({ ...finding, description: "private advisory body" }, false, {
      installedVersions: ["1.0.0"],
    });
    const request = JSON.parse(requestBody) as {
      messages: Array<{ content: string }>;
    };
    expect(request.messages[1]?.content).not.toContain("private advisory body");
    expect(request.messages[1]?.content).not.toContain("manifestPath");
    expect(request.messages[1]?.content).toContain('"installedVersions":["1.0.0"]');
  });
});
