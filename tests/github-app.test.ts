import { describe, expect, it } from "vitest";

import { GitHubAppTokenMinter } from "../src/github-app.js";

describe("GitHub App scoped token exchange", () => {
  it("requests repository_ids and rejects a mismatched returned scope", async () => {
    let requestBody = "";
    const minter = new GitHubAppTokenMinter(
      {
        appId: "1",
        privateKey: "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----",
      },
      {
        transport: {
          request: async (_url, init) => {
            requestBody = String(init.body ?? "");
            return {
              status: 201,
              headers: new Headers(),
              body: JSON.stringify({
                token: "test",
                repositories: [{ id: 1170364244 }],
              }),
            };
          },
        },
      },
    );
    // Signing happens before the fake request; replace the JWT only for this transport test.
    minter.appJwt = () => "test-jwt";
    await expect(minter.scopedToken(1, [1170364244])).resolves.toBe("test");
    expect(JSON.parse(requestBody)).toEqual({ repository_ids: [1170364244] });
  });

  it("allows only Issues write when requesting scoped permissions", async () => {
    let body = "";
    const minter = new GitHubAppTokenMinter(
      { appId: "1", privateKey: "unused" },
      {
        transport: {
          request: async (_url, init) => {
            body = String(init.body ?? "");
            return {
              status: 201,
              headers: new Headers(),
              body: JSON.stringify({
                token: "test",
                repositories: [{ id: 1170364244 }],
                permissions: { issues: "write" },
              }),
            };
          },
        },
      },
    );
    minter.appJwt = () => "test-jwt";
    await expect(
      minter.scopedTokenWithPermissions(1, [1170364244], { issues: "write" }),
    ).resolves.toBe("test");
    expect(JSON.parse(body)).toMatchObject({
      repository_ids: [1170364244],
      permissions: { issues: "write" },
    });
    await expect(
      minter.scopedTokenWithPermissions(1, [1170364244], { contents: "write" }),
    ).rejects.toThrow(/Issues write/);
  });

  it("accepts implicit metadata read and rejects any extra write permission", async () => {
    let responsePermissions: Record<string, string> = {
      metadata: "read",
      issues: "write",
    };
    const minter = new GitHubAppTokenMinter(
      { appId: "1", privateKey: "unused" },
      {
        transport: {
          request: async () => ({
            status: 201,
            headers: new Headers(),
            body: JSON.stringify({
              token: "test",
              repositories: [{ id: 1170364244 }],
              permissions: responsePermissions,
            }),
          }),
        },
      },
    );
    minter.appJwt = () => "test-jwt";
    await expect(
      minter.scopedTokenWithPermissions(1, [1170364244], { issues: "write" }),
    ).resolves.toBe("test");
    responsePermissions = {
      metadata: "read",
      issues: "write",
      contents: "write",
    };
    await expect(
      minter.scopedTokenWithPermissions(1, [1170364244], { issues: "write" }),
    ).rejects.toThrow(/did not match the requested scope/);
  });

  it("requests and validates a metadata-only token for installation inventory", async () => {
    let body = "";
    let responsePermissions: Record<string, string> = { metadata: "read" };
    const minter = new GitHubAppTokenMinter(
      { appId: "1", privateKey: "unused" },
      {
        transport: {
          request: async (_url, init) => {
            body = String(init.body ?? "");
            return {
              status: 201,
              headers: new Headers(),
              body: JSON.stringify({
                token: "test",
                permissions: responsePermissions,
              }),
            };
          },
        },
      },
    );
    minter.appJwt = () => "test-jwt";
    await expect(minter.metadataReadToken(1)).resolves.toBe("test");
    expect(JSON.parse(body)).toEqual({ permissions: { metadata: "read" } });
    responsePermissions = { issues: "write" };
    await expect(minter.metadataReadToken(1)).rejects.toThrow(
      /did not match the requested scope/,
    );
  });
});
