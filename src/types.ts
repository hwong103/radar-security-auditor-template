export const SEVERITIES = ["critical", "high", "medium", "low", "unknown"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const ECOSYSTEMS = ["npm", "pip", "go", "rust", "composer"] as const;
export type Ecosystem = (typeof ECOSYSTEMS)[number];

export interface RadarCve {
  readonly id: string;
  readonly url: string;
  readonly title: string;
  readonly summary: string;
  readonly publishedAt: string;
  readonly severity: Severity;
  readonly score: number | null;
  readonly cvssVersion: string | null;
}

export interface RepositoryConfig {
  readonly owner: string;
  readonly name: string;
  readonly publishIssues: boolean;
  readonly enabled: boolean;
  readonly openDraftPrs: boolean;
  readonly allowDependencyChanges: boolean;
  readonly allowedEcosystems: readonly Ecosystem[];
}

export interface HubConfig {
  readonly version: 1;
  readonly feedUrl: string;
  readonly trustedIssueAuthor: string | null;
  readonly severities: readonly Severity[];
  readonly inventory: "configured" | "app-installations";
  readonly repositoryDefaults: RepositoryDefaults;
  readonly installations: readonly {
    readonly owner: string;
    readonly installationId?: number | undefined;
  }[];
  readonly repositories: readonly RepositoryConfig[];
}

export interface RepositoryDefaults {
  readonly publishIssues: boolean;
  readonly openDraftPrs: boolean;
  readonly allowDependencyChanges: boolean;
  readonly allowedEcosystems: readonly Ecosystem[];
}

export const GH_ECOSYSTEMS = [
  "npm",
  "pip",
  "go",
  "rust",
  "composer",
  "maven",
  "gradle",
  "nuget",
  "rubygems",
  "pub",
  "swift",
  "cargo",
  "actions",
  "docker",
  "erlang",
  "github-actions",
  "other",
] as const;

export type GitHubEcosystem = (typeof GH_ECOSYSTEMS)[number];

export interface AffectedPackage {
  readonly ecosystem: GitHubEcosystem;
  readonly name: string;
  readonly manifestPath: string | null;
  readonly vulnerableVersionRange: string | null;
  readonly firstPatchedVersion: string | null;
}

export interface DependencyAlert {
  readonly repositoryId: number | null;
  readonly repositoryFullName: string;
  readonly alertNumber: number;
  readonly state: "open" | "dismissed" | "fixed" | "auto_dismissed" | "unknown";
  readonly severity: Severity;
  readonly ghsaId: string | null;
  readonly cveIds: readonly string[];
  readonly summary: string;
  readonly description: string;
  readonly htmlUrl: string;
  readonly package: AffectedPackage;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly dismissedReason: string | null;
  readonly fixedAt: string | null;
}

export interface Finding {
  readonly key: string;
  readonly repositoryFullName: string;
  readonly repositoryId: number | null;
  readonly alertNumber: number | null;
  readonly identity: string;
  readonly aliases: readonly string[];
  readonly severity: Severity;
  readonly summary: string;
  readonly description: string;
  readonly htmlUrl: string;
  readonly package: AffectedPackage;
  readonly radarUrl: string | null;
  readonly createdFrom: "dependabot" | "radar";
  readonly modelAdvice?: ModelAdvice | undefined;
}

export interface RepositoryIssue {
  readonly number: number;
  readonly title: string;
  readonly state: "open" | "closed";
  readonly htmlUrl: string;
  readonly body: string;
  readonly authorLogin?: string | null;
  readonly authorType?: string | null;
}

export interface PullRequest {
  readonly number: number;
  readonly title: string;
  readonly state: "open" | "closed";
  readonly draft: boolean;
  readonly headRef: string;
  readonly htmlUrl: string;
  readonly body: string;
}

export interface PublicationPlan {
  readonly action: "create-issue" | "update-issue" | "reuse-pr" | "report-only";
  readonly reason: string;
  readonly finding: Finding;
  readonly issueNumber: number | null;
  readonly pullRequestNumber: number | null;
  readonly branch: string | null;
}

export interface ModelAdvice {
  readonly model: string;
  readonly tier: "fast" | "complex";
  readonly summary: string;
  readonly steps: readonly string[];
  readonly risks: readonly string[];
  readonly fallback: boolean;
}

export interface ScanReport {
  readonly schemaVersion: 1;
  readonly generatedAt: string;
  readonly dryRun: boolean;
  readonly feed: {
    readonly url: string;
    readonly cves: number;
    readonly newestPublishedAt: string | null;
  };
  readonly inventory: {
    readonly repositories: number;
    readonly configured: number;
    readonly eligible: number;
    readonly skipped: readonly string[];
  };
  readonly alerts: {
    readonly queried: number;
    readonly unavailable: readonly string[];
    readonly open: number;
  };
  readonly findings: readonly Finding[];
  readonly plans: readonly PublicationPlan[];
  readonly potentialExposures: readonly {
    readonly repositoryFullName: string;
    readonly advisory: string;
    readonly radarUrl: string;
    readonly ecosystem: GitHubEcosystem;
    readonly packageName: string;
    readonly installedVersion: string;
    readonly manifestPath: string;
    readonly firstPatchedVersion: string | null;
  }[];
  readonly coverageGaps: readonly string[];
}

export type CampaignReviewReason =
  | "ambiguous-manifest"
  | "incompatible-patched-version"
  | "invalid-patched-version"
  | "missing-patched-version"
  | "review-required"
  | "unsupported-manifest"
  | "unknown-vulnerable-range";

export interface CampaignUpgrade {
  readonly packageName: string;
  readonly affectedFindings: number;
  readonly highestFirstPatchedVersion: string;
}

export interface RemediationCampaign {
  readonly key: string;
  readonly marker: string;
  readonly repositoryFullName: string;
  readonly repositoryIds: readonly number[];
  readonly ecosystem: GitHubEcosystem;
  readonly manifestPath: string | null;
  readonly severity: "critical" | "high";
  readonly findingCount: number;
  readonly criticalCount: number;
  readonly highCount: number;
  readonly alertNumbers: readonly number[];
  readonly findingKeys: readonly string[];
  readonly findings: readonly CampaignFinding[];
  readonly upgrades: readonly CampaignUpgrade[];
  readonly reviewReasons: readonly CampaignReviewReason[];
  readonly remediationMode: "upgrade" | "review";
  readonly eligibleForPilot: boolean;
}

export interface CampaignFinding {
  readonly alertNumber: number;
  readonly findingKey: string;
  readonly advisory: string;
  readonly aliases: readonly string[];
  readonly packageName: string;
  readonly severity: "critical" | "high";
  readonly summary: string;
  readonly vulnerableVersionRange: string | null;
  readonly firstPatchedVersion: string | null;
}

export interface CampaignPreview {
  readonly schemaVersion: 1;
  readonly generatedAt: string;
  readonly sourceReportGeneratedAt: string;
  readonly limits: {
    readonly maxFindingsPerCampaign: number;
  };
  readonly campaigns: readonly RemediationCampaign[];
  readonly summary: {
    readonly highCriticalFindings: number;
    readonly campaigns: number;
    readonly eligibleForPilot: number;
    readonly manualReview: number;
    readonly deferredByCap: number;
  };
}

export interface CampaignPublicationScope {
  readonly campaignKey: string;
  readonly campaignDigest: string;
}

export interface ApiResponse {
  readonly status: number;
  readonly headers: Headers;
  readonly body: string;
}

export interface HttpResponse {
  readonly status: number;
  readonly headers: Headers;
  readonly body: string;
}

export interface HttpTransport {
  request(
    url: string,
    init: RequestInit,
    options?: { readonly allowNotFound?: boolean; readonly timeoutMs?: number },
  ): Promise<ApiResponse>;
}
