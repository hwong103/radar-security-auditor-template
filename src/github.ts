import { z } from "zod";

import { repositoryKey } from "./config.js";
import { ecosystemFromManifestPath, type ManifestPathsResult } from "./manifests.js";
import type {
  ApiResponse,
  DependencyAlert,
  Ecosystem,
  GitHubEcosystem,
  HttpTransport,
  PullRequest,
  RepositoryConfig,
  RepositoryIssue,
  Severity,
} from "./types.js";

const MAX_GITHUB_PAGES = 100;

const repositorySchema = z
  .object({
    id: z.number().int().positive(),
    full_name: z.string().min(3),
    owner: z.object({ login: z.string().min(1) }),
    name: z.string().min(1),
    private: z.boolean().optional(),
    archived: z.boolean().default(false),
    disabled: z.boolean().default(false),
    default_branch: z.string().min(1),
    permissions: z
      .object({
        admin: z.boolean().optional(),
        maintain: z.boolean().optional(),
        push: z.boolean().optional(),
        triage: z.boolean().optional(),
        pull: z.boolean().optional(),
      })
      .optional(),
  })
  .passthrough();

const alertSchema = z
  .object({
    number: z.number().int().positive(),
    state: z.string().min(1),
    dependency: z
      .object({
        package: z
          .object({
            ecosystem: z.string().min(1),
            name: z.string().min(1),
          })
          .passthrough(),
        manifest_path: z.string().nullable().optional(),
      })
      .passthrough(),
    security_advisory: z
      .object({
        ghsa_id: z.string().nullable().optional(),
        cve_id: z.string().nullable().optional(),
        summary: z.string().default(""),
        description: z.string().default(""),
        severity: z.string().default("unknown"),
        html_url: z.string().url().optional(),
      })
      .passthrough(),
    security_vulnerability: z
      .object({
        vulnerable_version_range: z.string().nullable().optional(),
        first_patched_version: z
          .object({ identifier: z.string().min(1) })
          .nullable()
          .optional(),
      })
      .passthrough()
      .nullable(),
    created_at: z.string().min(1),
    updated_at: z.string().min(1),
    dismissed_reason: z.string().nullable().optional(),
    fixed_at: z.string().nullable().optional(),
  })
  .passthrough();

const issueSchema = z
  .object({
    number: z.number().int().positive(),
    title: z.string(),
    state: z.enum(["open", "closed"]),
    html_url: z.string().url(),
    body: z.string().nullable().optional(),
    pull_request: z.unknown().optional(),
    user: z
      .object({ login: z.string().min(1), type: z.string().optional() })
      .nullable()
      .optional(),
  })
  .passthrough();

const pullRequestSchema = z
  .object({
    number: z.number().int().positive(),
    title: z.string(),
    state: z.enum(["open", "closed"]),
    draft: z.boolean().default(false),
    html_url: z.string().url(),
    body: z.string().nullable().optional(),
    head: z.object({ ref: z.string().min(1) }),
  })
  .passthrough();

const installationSchema = z
  .object({
    id: z.number().int().positive(),
    repository_selection: z.string().optional(),
    account: z.object({
      login: z.string().min(1),
      type: z.string().optional(),
    }),
  })
  .passthrough();

function normalizeSeverity(value: string): Severity {
  const lower = value.toLowerCase();
  return ["critical", "high", "medium", "low"].includes(lower)
    ? (lower as Severity)
    : "unknown";
}

function normalizeEcosystem(value: string): GitHubEcosystem {
  const normalized = value.toLowerCase();
  if (normalized === "npm") return "npm";
  if (normalized === "pip") return "pip";
  if (normalized === "go" || normalized === "gomod") return "go";
  if (normalized === "rust" || normalized === "cargo") return "rust";
  if (normalized === "composer") return "composer";
  if (normalized === "maven") return "maven";
  if (normalized === "gradle") return "gradle";
  if (normalized === "nuget") return "nuget";
  if (normalized === "rubygems") return "rubygems";
  if (normalized === "pub") return "pub";
  if (normalized === "swift") return "swift";
  if (normalized === "actions") return "actions";
  if (normalized === "docker") return "docker";
  if (normalized === "erlang") return "erlang";
  if (normalized === "github-actions") return "github-actions";
  return "other";
}

export function githubEcosystemToEcosystem(ecosystem: GitHubEcosystem): Ecosystem | null {
  if (ecosystem === "npm") return "npm";
  if (ecosystem === "pip") return "pip";
  if (ecosystem === "go") return "go";
  if (ecosystem === "rust" || ecosystem === "cargo") return "rust";
  if (ecosystem === "composer") return "composer";
  return null;
}

export interface GitHubRepository {
  readonly id: number;
  readonly fullName: string;
  readonly owner: string;
  readonly name: string;
  readonly private: boolean;
  readonly archived: boolean;
  readonly disabled: boolean;
  readonly defaultBranch: string;
}

export interface GitHubInstallation {
  readonly id: number;
  readonly owner: string;
  readonly type: string;
  readonly repositorySelection: string;
}

export interface AuthenticatedResponse {
  readonly api: ApiResponse;
  readonly token: string;
}

export interface GitHubTokenMinter {
  readonly token: (installationId: number) => Promise<string>;
  readonly appJwt?: () => string;
}

export interface GitHubClientOptions {
  readonly transport: HttpTransport;
  readonly token: GitHubTokenMinter;
  readonly tokenForRepositoryIds?: (
    installationId: number,
    repositoryIds: readonly number[],
  ) => Promise<string>;
  readonly apiBase?: string;
  readonly userAgent?: string;
}

export interface GlobalAdvisory {
  readonly ghsaId: string;
  readonly cveId: string | null;
  readonly summary: string;
  readonly description: string;
  readonly severity: Severity;
  readonly htmlUrl: string;
  readonly publishedAt: string;
  readonly updatedAt: string;
  readonly vulnerabilities: readonly {
    readonly ecosystem: GitHubEcosystem;
    readonly packageName: string;
    readonly vulnerableVersionRange: string | null;
    readonly firstPatchedVersion: string | null;
  }[];
}

export class GitHubApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "GitHubApiError";
  }
}

export class GitHubClient {
  private readonly apiBase: string;
  private readonly userAgent: string;
  private readonly tokens = new Map<number, Promise<string>>();

  constructor(private readonly options: GitHubClientOptions) {
    this.apiBase = options.apiBase ?? "https://api.github.com";
    this.userAgent = options.userAgent ?? "radar-security-auditor/0.1";
  }

  private headers(token: string): Record<string, string> {
    return {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": this.userAgent,
    };
  }

  private async request(
    path: string,
    token: string,
    init: RequestInit = {},
    allowNotFound = false,
  ): Promise<ApiResponse> {
    const response = await this.options.transport.request(
      `${this.apiBase}${path}`,
      {
        ...init,
        headers: { ...this.headers(token), ...(init.headers ?? {}) },
      },
      { allowNotFound },
    );
    if (response.status === 404 && allowNotFound) return response;
    if (response.status < 200 || response.status >= 300) {
      const error = new GitHubApiError(
        response.status,
        `GitHub ${path} returned HTTP ${response.status}`,
      );
      Object.defineProperty(error, "body", {
        value: response.body,
        enumerable: true,
      });
      throw error;
    }
    return response;
  }

  async installationToken(installationId: number): Promise<string> {
    let pending = this.tokens.get(installationId);
    if (!pending) {
      pending = this.options.token.token(installationId).catch((error: unknown) => {
        this.tokens.delete(installationId);
        throw error;
      });
      this.tokens.set(installationId, pending);
    }
    const token = await pending;
    if (!token)
      throw new Error(`GitHub App token was empty for installation ${installationId}`);
    return token;
  }

  async repositoryScopedToken(
    installationId: number,
    repositoryIds: readonly number[],
  ): Promise<string> {
    if (!this.options.tokenForRepositoryIds) {
      throw new Error("Repository-scoped installation tokens are not configured");
    }
    return this.options.tokenForRepositoryIds(installationId, repositoryIds);
  }

  async getRepository(
    installationId: number,
    owner: string,
    name: string,
    repositoryIds?: readonly number[],
  ): Promise<GitHubRepository> {
    const token = repositoryIds
      ? await this.repositoryScopedToken(installationId, repositoryIds)
      : await this.installationToken(installationId);
    const response = await this.request(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`,
      token,
    );
    const repository = repositorySchema.parse(JSON.parse(response.body) as unknown);
    return {
      id: repository.id,
      fullName: repository.full_name,
      owner: repository.owner.login,
      name: repository.name,
      private: repository.private ?? false,
      archived: repository.archived,
      disabled: repository.disabled,
      defaultBranch: repository.default_branch,
    };
  }

  async listInstallations(appJwt: string): Promise<readonly GitHubInstallation[]> {
    const response = await this.request("/app/installations?per_page=100", appJwt);
    return z
      .array(installationSchema.passthrough())
      .parse(JSON.parse(response.body) as unknown)
      .map((installation) => ({
        id: installation.id,
        owner: installation.account.login,
        type: installation.account.type ?? "unknown",
        repositorySelection: installation.repository_selection ?? "unknown",
      }));
  }

  async getAuthenticatedApp(appJwt: string): Promise<{
    readonly id: number;
    readonly slug: string;
    readonly name: string;
  }> {
    const response = await this.request("/app", appJwt);
    return z
      .object({
        id: z.number().int().positive(),
        slug: z.string().regex(/^[a-z0-9-]+$/),
        name: z.string().min(1),
      })
      .passthrough()
      .parse(JSON.parse(response.body) as unknown);
  }

  async listRepositories(installationId: number): Promise<readonly GitHubRepository[]> {
    const token = await this.installationToken(installationId);
    const repositories: GitHubRepository[] = [];
    for (let page = 1; page <= MAX_GITHUB_PAGES; page += 1) {
      const response = await this.request(
        `/installation/repositories?per_page=100&page=${page}`,
        token,
      );
      const body = z
        .object({
          total_count: z.number().int().nonnegative(),
          repositories: z.array(repositorySchema),
        })
        .passthrough()
        .parse(JSON.parse(response.body) as unknown);
      for (const repository of body.repositories) {
        repositories.push({
          id: repository.id,
          fullName: repository.full_name,
          owner: repository.owner.login,
          name: repository.name,
          private: repository.private ?? false,
          archived: repository.archived,
          disabled: repository.disabled,
          defaultBranch: repository.default_branch,
        });
      }
      if (repositories.length >= body.total_count || body.repositories.length < 100) break;
    }
    return repositories;
  }

  async listInstallationRepositories(token: string): Promise<readonly GitHubRepository[]> {
    const repositories: GitHubRepository[] = [];
    let fetched = 0;
    for (let page = 1; page <= MAX_GITHUB_PAGES; page += 1) {
      const response = await this.request(
        `/installation/repositories?per_page=100&page=${page}`,
        token,
      );
      const body = z
        .object({
          total_count: z.number().int().nonnegative(),
          repositories: z.array(repositorySchema),
        })
        .passthrough()
        .parse(JSON.parse(response.body) as unknown);
      fetched += body.repositories.length;
      repositories.push(
        ...body.repositories.map((repository) => ({
          id: repository.id,
          fullName: repository.full_name,
          owner: repository.owner.login,
          name: repository.name,
          private: repository.private ?? false,
          archived: repository.archived,
          disabled: repository.disabled,
          defaultBranch: repository.default_branch,
        })),
      );
      if (fetched >= body.total_count) return repositories;
      if (body.repositories.length === 0) break;
    }
    throw new Error("GitHub installation repository inventory exceeded pagination limit");
  }

  async listDependabotAlerts(
    installationId: number,
    repository: string,
    owner: string,
    name: string,
    repositoryIds?: readonly number[],
  ): Promise<{ readonly alerts: readonly DependencyAlert[]; readonly available: boolean }> {
    const token = repositoryIds
      ? await this.repositoryScopedToken(installationId, repositoryIds)
      : await this.installationToken(installationId);
    const repositoryId = repositoryIds?.length === 1 ? (repositoryIds[0] ?? null) : null;
    const alerts: DependencyAlert[] = [];
    let nextUrl: string | null =
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/dependabot/alerts?state=open&per_page=100`;
    for (let page = 1; page <= MAX_GITHUB_PAGES && nextUrl; page += 1) {
      let response: ApiResponse;
      try {
        response = await this.request(nextUrl, token, {}, true);
      } catch (error) {
        if (error instanceof Error && /\bHTTP (403|404)\b/.test(error.message)) {
          return { alerts: [], available: false };
        }
        throw error;
      }
      if (response.status === 404 || response.status === 403) {
        return { alerts: [], available: false };
      }
      const parsed = z.array(alertSchema).parse(JSON.parse(response.body) as unknown);
      for (const alert of parsed) {
        const cveId = alert.security_advisory.cve_id?.toUpperCase() ?? null;
        alerts.push({
          repositoryId,
          repositoryFullName: repository,
          alertNumber: alert.number,
          state:
            alert.state === "open" ||
            alert.state === "dismissed" ||
            alert.state === "fixed" ||
            alert.state === "auto_dismissed"
              ? alert.state
              : "unknown",
          severity: normalizeSeverity(alert.security_advisory.severity),
          ghsaId: alert.security_advisory.ghsa_id?.toUpperCase() ?? null,
          cveIds: cveId ? [cveId] : [],
          summary: alert.security_advisory.summary,
          description: alert.security_advisory.description,
          htmlUrl:
            alert.security_advisory.html_url ??
            `https://github.com/${repository}/security/dependabot/${alert.number}`,
          package: {
            ecosystem: normalizeEcosystem(alert.dependency.package.ecosystem),
            name: alert.dependency.package.name,
            manifestPath: alert.dependency.manifest_path ?? null,
            vulnerableVersionRange:
              alert.security_vulnerability?.vulnerable_version_range ?? null,
            firstPatchedVersion:
              alert.security_vulnerability?.first_patched_version?.identifier ?? null,
          },
          createdAt: alert.created_at,
          updatedAt: alert.updated_at,
          dismissedReason: alert.dismissed_reason ?? null,
          fixedAt: alert.fixed_at ?? null,
        });
      }
      if (parsed.length < 100) break;
      nextUrl = nextPagePath(response.headers.get("link"), this.apiBase);
      if (!nextUrl && page === MAX_GITHUB_PAGES) {
        throw new Error("GitHub Dependabot alert pagination did not terminate");
      }
    }
    return { alerts, available: true };
  }

  async listGlobalAdvisories(
    installationId: number,
    cveId: string,
  ): Promise<{
    readonly advisories: readonly GlobalAdvisory[];
    readonly unavailable: readonly string[];
  }> {
    if (!/^CVE-\d{4}-\d{4,}$/.test(cveId.toUpperCase())) {
      throw new Error("Global advisory lookup requires a canonical CVE ID");
    }
    const token = await this.installationToken(installationId);
    const response = await this.request(
      `/advisories?cve_id=${encodeURIComponent(cveId.toUpperCase())}&per_page=100`,
      token,
      {},
      true,
    );
    if (response.status === 404 || response.status === 403) {
      return { advisories: [], unavailable: [cveId.toUpperCase()] };
    }
    const parsed = z
      .array(
        z
          .object({
            ghsa_id: z.string().min(1),
            cve_id: z.string().nullable().optional(),
            summary: z.string().default(""),
            description: z.string().default(""),
            severity: z.string().default("unknown"),
            html_url: z.string().url(),
            published_at: z.string().min(1),
            updated_at: z.string().min(1),
            vulnerabilities: z.array(
              z
                .object({
                  package: z.object({ ecosystem: z.string(), name: z.string() }),
                  vulnerable_version_range: z.string().nullable().optional(),
                  first_patched_version: z
                    .union([
                      z.string().min(1),
                      z.object({ identifier: z.string().min(1) }),
                      z.null(),
                    ])
                    .optional(),
                })
                .passthrough(),
            ),
          })
          .passthrough(),
      )
      .parse(JSON.parse(response.body) as unknown);
    const advisories = parsed.flatMap((advisory) => {
      const vulnerabilities = advisory.vulnerabilities.map((vulnerability) => ({
        ecosystem: normalizeEcosystem(vulnerability.package.ecosystem),
        packageName: vulnerability.package.name,
        vulnerableVersionRange: vulnerability.vulnerable_version_range ?? null,
        firstPatchedVersion:
          typeof vulnerability.first_patched_version === "string"
            ? vulnerability.first_patched_version
            : (vulnerability.first_patched_version?.identifier ?? null),
      }));
      return [
        {
          ghsaId: advisory.ghsa_id.toUpperCase(),
          cveId: advisory.cve_id?.toUpperCase() ?? null,
          summary: advisory.summary,
          description: advisory.description,
          severity: normalizeSeverity(advisory.severity),
          htmlUrl: advisory.html_url,
          publishedAt: advisory.published_at,
          updatedAt: advisory.updated_at,
          vulnerabilities,
        },
      ];
    });
    return { advisories, unavailable: [] };
  }

  async listManifestPaths(
    installationId: number,
    owner: string,
    name: string,
  ): Promise<ManifestPathsResult> {
    const token = await this.installationToken(installationId);
    const repositoryResponse = await this.request(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`,
      token,
    );
    const repository = z
      .object({ default_branch: z.string().min(1) })
      .passthrough()
      .parse(JSON.parse(repositoryResponse.body) as unknown);
    const response = await this.request(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/git/trees/${encodeURIComponent(repository.default_branch)}?recursive=1`,
      token,
    );
    const parsed = z
      .object({
        truncated: z.boolean().default(false),
        tree: z.array(
          z
            .object({
              path: z.string(),
              sha: z.string(),
              type: z.string(),
              size: z.number().int().nonnegative().optional(),
            })
            .passthrough(),
        ),
      })
      .parse(JSON.parse(response.body) as unknown);
    const manifests = parsed.tree
      .filter(
        (entry) =>
          entry.type === "blob" &&
          ecosystemFromManifestPath(entry.path) !== null &&
          (entry.size ?? 0) <= 2_000_000,
      )
      .map((entry) => ({ path: entry.path, sha: entry.sha, size: entry.size ?? 0 }));
    return { paths: manifests, truncated: parsed.truncated };
  }

  async fetchBlob(
    installationId: number,
    owner: string,
    name: string,
    sha: string,
  ): Promise<string> {
    const token = await this.installationToken(installationId);
    const response = await this.request(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/git/blobs/${encodeURIComponent(sha)}`,
      token,
    );
    const parsed = z
      .object({
        encoding: z.string(),
        content: z.string(),
        size: z.number().int().nonnegative().optional(),
      })
      .parse(JSON.parse(response.body) as unknown);
    if (parsed.size !== undefined && parsed.size > 2_000_000) {
      throw new Error("Manifest exceeds 2 MB");
    }
    if (parsed.encoding !== "base64") throw new Error("Unexpected GitHub blob encoding");
    return Buffer.from(parsed.content.replaceAll("\n", ""), "base64").toString("utf8");
  }

  async listIssues(
    installationId: number,
    repository: string,
  ): Promise<readonly RepositoryIssue[]> {
    const [owner, name] = splitRepository(repository);
    const token = await this.installationToken(installationId);
    const issues: RepositoryIssue[] = [];
    for (let page = 1; page <= MAX_GITHUB_PAGES; page += 1) {
      const response = await this.request(
        `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/issues?state=all&per_page=100&page=${page}`,
        token,
      );
      const parsed = z
        .array(issueSchema.passthrough())
        .parse(JSON.parse(response.body) as unknown);
      for (const issue of parsed) {
        if (issue.pull_request !== undefined) continue;
        issues.push({
          number: issue.number,
          title: issue.title,
          state: issue.state,
          htmlUrl: issue.html_url,
          body: issue.body ?? "",
          authorLogin: issue.user?.login ?? null,
          authorType: issue.user?.type ?? null,
        });
      }
      if (parsed.length < 100) break;
    }
    return issues;
  }

  async listPullRequests(
    installationId: number,
    repository: string,
  ): Promise<readonly PullRequest[]> {
    const [owner, name] = splitRepository(repository);
    const token = await this.installationToken(installationId);
    const pullRequests: PullRequest[] = [];
    for (let page = 1; page <= MAX_GITHUB_PAGES; page += 1) {
      const response = await this.request(
        `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/pulls?state=all&per_page=100&page=${page}`,
        token,
      );
      const parsed = z.array(pullRequestSchema).parse(JSON.parse(response.body) as unknown);
      for (const pullRequest of parsed) {
        pullRequests.push({
          number: pullRequest.number,
          title: pullRequest.title,
          state: pullRequest.state,
          draft: pullRequest.draft,
          headRef: pullRequest.head.ref,
          htmlUrl: pullRequest.html_url,
          body: pullRequest.body ?? "",
        });
      }
      if (parsed.length < 100) break;
    }
    return pullRequests;
  }

  async createIssue(
    installationId: number,
    repository: string,
    title: string,
    body: string,
  ): Promise<RepositoryIssue> {
    const [owner, name] = splitRepository(repository);
    const token = await this.installationToken(installationId);
    const response = await this.request(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/issues`,
      token,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title,
          body,
          labels: ["security", "dependencies", "radar-remediator"],
        }),
      },
    );
    const issue = issueSchema.parse(JSON.parse(response.body) as unknown);
    return {
      number: issue.number,
      title: issue.title,
      state: issue.state,
      htmlUrl: issue.html_url,
      body: issue.body ?? "",
      authorLogin: issue.user?.login ?? null,
      authorType: issue.user?.type ?? null,
    };
  }

  async createIssueScoped(
    installationId: number,
    repositoryIds: readonly number[],
    repository: string,
    title: string,
    body: string,
  ): Promise<RepositoryIssue> {
    const [owner, name] = splitRepository(repository);
    const token = await this.repositoryScopedToken(installationId, repositoryIds);
    const response = await this.request(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/issues`,
      token,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title,
          body,
          labels: ["security", "dependencies", "radar-remediator"],
        }),
      },
    );
    return parseIssue(response.body);
  }

  async updateIssueScoped(
    installationId: number,
    repositoryIds: readonly number[],
    repository: string,
    issueNumber: number,
    title: string,
    body: string,
  ): Promise<RepositoryIssue> {
    const [owner, name] = splitRepository(repository);
    const token = await this.repositoryScopedToken(installationId, repositoryIds);
    const response = await this.request(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/issues/${issueNumber}`,
      token,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title, body }),
      },
    );
    return parseIssue(response.body);
  }

  async listIssuesScoped(
    installationId: number,
    repositoryIds: readonly number[],
    repository: string,
  ): Promise<readonly RepositoryIssue[]> {
    const [owner, name] = splitRepository(repository);
    const token = await this.repositoryScopedToken(installationId, repositoryIds);
    const issues: RepositoryIssue[] = [];
    for (let page = 1; page <= MAX_GITHUB_PAGES; page += 1) {
      const response = await this.request(
        `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/issues?state=all&per_page=100&page=${page}`,
        token,
      );
      const parsed = z
        .array(issueSchema.passthrough())
        .parse(JSON.parse(response.body) as unknown);
      for (const issue of parsed) {
        if (issue.pull_request !== undefined) continue;
        issues.push(parseIssue(JSON.stringify(issue)));
      }
      if (parsed.length < 100) break;
      if (page === MAX_GITHUB_PAGES) {
        throw new Error("GitHub issue pagination did not terminate");
      }
    }
    return issues;
  }

  async updateIssue(
    installationId: number,
    repository: string,
    issueNumber: number,
    title: string,
    body: string,
  ): Promise<RepositoryIssue> {
    const [owner, name] = splitRepository(repository);
    const token = await this.installationToken(installationId);
    const response = await this.request(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/issues/${issueNumber}`,
      token,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title, body }),
      },
    );
    const issue = issueSchema.parse(JSON.parse(response.body) as unknown);
    return {
      number: issue.number,
      title: issue.title,
      state: issue.state,
      htmlUrl: issue.html_url,
      body: issue.body ?? "",
      authorLogin: issue.user?.login ?? null,
      authorType: issue.user?.type ?? null,
    };
  }
}

function parseIssue(value: string): RepositoryIssue {
  const issue = issueSchema.parse(JSON.parse(value) as unknown);
  return {
    number: issue.number,
    title: issue.title,
    state: issue.state,
    htmlUrl: issue.html_url,
    body: issue.body ?? "",
    authorLogin: issue.user?.login ?? null,
    authorType: issue.user?.type ?? null,
  };
}

export function splitRepository(repository: string): readonly [string, string] {
  const parts = repository.split("/");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error(`Expected owner/name repository, received ${repository}`);
  }
  return [parts[0], parts[1]];
}

export function configuredRepositorySet(
  repositories: readonly RepositoryConfig[],
): ReadonlyMap<string, RepositoryConfig> {
  return new Map(
    repositories.map((repository) => [
      repositoryKey(repository.owner, repository.name),
      repository,
    ]),
  );
}

export function nextPagePath(link: string | null, apiBase: string): string | null {
  if (!link) return null;
  const next = link.split(",").find((entry) => /rel="next"/.test(entry));
  const target = next?.match(/<([^>]+)>/)?.[1];
  if (!target) return null;
  const url = new URL(target);
  const base = new URL(apiBase);
  if (url.origin !== base.origin) throw new Error("GitHub pagination left the API origin");
  return `${url.pathname}${url.search}`;
}
