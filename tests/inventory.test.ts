import { describe, expect, it } from "vitest";

import { hubConfigSchema } from "../src/config.js";
import { discoverRepositories, selectedInstallations } from "../src/inventory.js";

describe("installation selection", () => {
  it("fails when a configured installation owner is missing", () => {
    const config = hubConfigSchema.parse({
      version: 1,
      inventory: "app-installations",
      installations: [{ owner: "expected-owner" }],
    });
    expect(() => selectedInstallations(config, [])).toThrow(
      /not installed for configured owner expected-owner/,
    );
  });

  it("fails when a pinned installation ID does not match", () => {
    const config = hubConfigSchema.parse({
      version: 1,
      inventory: "app-installations",
      installations: [{ owner: "example", installationId: 10 }],
    });
    expect(() => selectedInstallations(config, [{ id: 11, owner: "example" }])).toThrow(
      /Installation ID mismatch for example/,
    );
  });

  it("returns only installations selected by the configured owners", async () => {
    const config = hubConfigSchema.parse({
      version: 1,
      inventory: "app-installations",
      installations: [{ owner: "example" }],
    });
    const installations = selectedInstallations(config, [
      { id: 10, owner: "example" },
      { id: 11, owner: "other" },
    ]);
    expect(installations).toEqual([{ id: 10, owner: "example" }]);
    await expect(
      discoverRepositories(
        config,
        {
          installations: async () => [
            { id: 10, owner: "example" },
            { id: 11, owner: "other" },
          ],
          repositories: async (installationId) => [
            {
              id: installationId,
              fullName: "example/repo",
              owner: "example",
              name: "repo",
              archived: false,
              disabled: false,
            },
          ],
        },
        "jwt",
      ),
    ).resolves.toMatchObject([{ installationId: 10 }]);
  });
});
