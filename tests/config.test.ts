import { describe, expect, it } from "vitest";

import { hubConfigSchema, repositoryConfigFor } from "../src/config.js";

describe("repository policy", () => {
  it("does not grant publication to an override that omits publishIssues", () => {
    const config = hubConfigSchema.parse({
      version: 1,
      inventory: "configured",
      repositories: [{ owner: "example", name: "repo" }],
    });
    expect(repositoryConfigFor(config, "example", "repo")?.publishIssues).toBe(false);
  });

  it("keeps unlisted repositories within the configured installation boundary", () => {
    const config = hubConfigSchema.parse({
      version: 1,
      inventory: "app-installations",
      installations: [{ owner: "example" }],
      repositoryDefaults: { publishIssues: true },
      repositories: [{ owner: "another-owner", name: "repo", publishIssues: true }],
    });
    expect(repositoryConfigFor(config, "another-owner", "repo")).toBeNull();
    expect(repositoryConfigFor(config, "example", "new-repo")).toMatchObject({
      owner: "example",
      name: "new-repo",
      publishIssues: true,
    });
  });
});
