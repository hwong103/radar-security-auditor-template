import { describe, expect, it } from "vitest";

import { CommandCodeClient, COMMAND_CODE_MODELS } from "../src/commandcode.js";
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
                    '{"summary":"Update the dependency.","steps":["Run tests."],"risks":[]}',
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
    const advice = await client.advise(finding, complex);
    expect(advice.model).toBe(expected);
    expect(advice.tier).toBe(complex ? "complex" : "fast");
    expect(JSON.parse(requestBody ?? "{}")).toMatchObject({ model: expected });
  });
});
