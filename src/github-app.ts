import { createSign } from "node:crypto";
import { z } from "zod";

import type { GitHubTokenMinter } from "./github.js";
import type { HttpTransport } from "./types.js";

export interface GitHubAppCredentials {
  readonly appId: string;
  readonly privateKey: string;
}

export function base64Url(value: string | Buffer): string {
  return Buffer.from(value).toString("base64url");
}

export function createAppJwt(credentials: GitHubAppCredentials, now = Date.now()): string {
  const header = base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const issuedAt = Math.floor(now / 1_000) - 60;
  const payload = base64Url(
    JSON.stringify({ iat: issuedAt, exp: issuedAt + 9 * 60, iss: credentials.appId }),
  );
  const signer = createSign("RSA-SHA256");
  signer.update(`${header}.${payload}`);
  signer.end();
  const signature = signer.sign(credentials.privateKey);
  return `${header}.${payload}.${base64Url(signature)}`;
}

export interface InstallationTokenClient {
  readonly transport: HttpTransport;
  readonly apiBase?: string;
  readonly userAgent?: string;
}

export class GitHubAppTokenMinter implements GitHubTokenMinter {
  constructor(
    private readonly credentials: GitHubAppCredentials,
    private readonly options: InstallationTokenClient,
  ) {}

  async token(installationId: number): Promise<string> {
    return this.mint(installationId, {});
  }

  async scopedToken(
    installationId: number,
    repositoryIds: readonly number[],
  ): Promise<string> {
    if (repositoryIds.length === 0 || repositoryIds.some((id) => !Number.isInteger(id))) {
      throw new Error("Repository-scoped token needs positive repository IDs");
    }
    return this.mint(installationId, { repository_ids: repositoryIds });
  }

  async scopedTokenWithPermissions(
    installationId: number,
    repositoryIds: readonly number[],
    permissions: Readonly<Record<string, "read" | "write">>,
  ): Promise<string> {
    if (repositoryIds.length === 0) {
      throw new Error("Repository-scoped token needs repository IDs");
    }
    const keys = Object.keys(permissions);
    if (keys.length !== 1 || permissions["issues"] !== "write") {
      throw new Error("Campaign publisher only permits Issues write");
    }
    return this.mint(installationId, {
      repository_ids: repositoryIds,
      permissions,
    });
  }

  async metadataReadToken(installationId: number): Promise<string> {
    return this.mint(installationId, {
      permissions: { metadata: "read" },
    });
  }

  private async mint(
    installationId: number,
    scope: {
      readonly repository_ids?: readonly number[];
      readonly permissions?: Readonly<Record<string, "read" | "write">>;
    },
  ): Promise<string> {
    const jwt = this.appJwt();
    const base = this.options.apiBase ?? "https://api.github.com";
    const response = await this.options.transport.request(
      `${base}/app/installations/${installationId}/access_tokens`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${jwt}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
          "User-Agent": this.options.userAgent ?? "radar-security-auditor/0.1",
          ...(scope.repository_ids || scope.permissions
            ? { "Content-Type": "application/json" }
            : {}),
        },
        ...(scope.repository_ids || scope.permissions
          ? { body: JSON.stringify(scope) }
          : {}),
      },
    );
    if (response.status !== 201) {
      throw new Error(`GitHub App token exchange returned HTTP ${response.status}`);
    }
    const parsed = tokenResponseSchema.parse(JSON.parse(response.body) as unknown);
    if (typeof parsed.token !== "string" || !parsed.token) {
      throw new Error("GitHub App token exchange returned no token");
    }
    if (scope.repository_ids) {
      const returned = new Set(
        parsed.repositories?.map((repository) => repository.id) ?? [],
      );
      if (
        returned.size !== scope.repository_ids.length ||
        scope.repository_ids.some((id) => !returned.has(id))
      ) {
        throw new Error("GitHub App token repository scope did not match the request");
      }
    }
    if (scope.permissions) {
      const permissions = parsed.permissions ?? {};
      const metadataRequested =
        Object.keys(scope.permissions).length === 1 &&
        scope.permissions.metadata === "read";
      const issuesRequested =
        Object.keys(scope.permissions).length === 1 && scope.permissions.issues === "write";
      const valid =
        (metadataRequested &&
          Object.keys(permissions).length === 1 &&
          permissions.metadata === "read") ||
        (issuesRequested &&
          permissions.issues === "write" &&
          Object.entries(permissions).every(([permission, access]) =>
            permission === "metadata"
              ? access === "read"
              : permission === "issues" && access === "write",
          ));
      if (!valid) {
        throw new Error("GitHub App token permissions did not match the requested scope");
      }
    }
    return parsed.token;
  }

  appJwt(): string {
    return createAppJwt(this.credentials);
  }
}

const tokenResponseSchema = z
  .object({
    token: z.string().min(1),
    repositories: z
      .array(z.object({ id: z.number().int().positive() }).passthrough())
      .optional(),
    permissions: z.record(z.string(), z.string()).optional(),
  })
  .passthrough();
