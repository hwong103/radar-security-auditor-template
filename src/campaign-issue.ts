import type { RemediationCampaign, RepositoryIssue } from "./types.js";

export type CampaignIssueAction = "create" | "update" | "same" | "closed" | "untrusted";

export interface CampaignIssuePlan {
  readonly action: CampaignIssueAction;
  readonly title: string;
  readonly body: string;
  readonly issueNumber: number | null;
  readonly reason: string;
}

export interface CampaignIssueState {
  readonly issues: readonly RepositoryIssue[];
  readonly trustedIssueAuthor: string;
}

export function planCampaignIssue(
  campaign: RemediationCampaign,
  state: CampaignIssueState,
): CampaignIssuePlan {
  const issuesWithMarkers = state.issues
    .map((issue) => ({ issue, markers: campaignMarkers(issue.body) }))
    .filter(({ markers }) => markers.length > 0);
  const matching = issuesWithMarkers.filter(({ markers }) =>
    markers.includes(campaign.key),
  );
  if (matching.length > 1) {
    return untrustedPlan(campaign, "More than one issue contains this campaign marker.");
  }
  if (matching.some(({ markers }) => markers.length > 1)) {
    return untrustedPlan(campaign, "The campaign issue contains duplicate markers.");
  }
  const matchingIssue = matching[0]?.issue;
  if (!matchingIssue) {
    return {
      action: "create",
      title: campaignIssueTitle(campaign),
      body: campaignIssueBody(campaign),
      issueNumber: null,
      reason: "No trusted issue tracks this campaign.",
    };
  }
  if (!`${matchingIssue.body}\n`.startsWith(`${campaign.marker}\n`)) {
    return untrustedPlan(campaign, "The campaign marker is not the first line.");
  }
  const trusted =
    matchingIssue.authorLogin === state.trustedIssueAuthor &&
    matchingIssue.authorType?.toLowerCase() === "bot";
  if (!trusted) {
    return untrustedPlan(
      campaign,
      "The campaign issue is not authored by the authenticated writer bot.",
    );
  }
  if (matchingIssue.state === "closed") {
    return {
      action: "closed",
      title: campaignIssueTitle(campaign),
      body: campaignIssueBody(campaign),
      issueNumber: matchingIssue.number,
      reason: "A trusted closed campaign issue exists; do not reopen it.",
    };
  }
  const title = campaignIssueTitle(campaign);
  const body = campaignIssueBody(campaign);
  if (matchingIssue.title === title && matchingIssue.body === body) {
    return {
      action: "same",
      title,
      body,
      issueNumber: matchingIssue.number,
      reason: "The trusted campaign issue already matches the approved evidence.",
    };
  }
  return {
    action: "update",
    title,
    body,
    issueNumber: matchingIssue.number,
    reason: "Update the trusted open campaign issue.",
  };
}

function untrustedPlan(campaign: RemediationCampaign, reason: string): CampaignIssuePlan {
  return {
    action: "untrusted",
    title: campaignIssueTitle(campaign),
    body: campaignIssueBody(campaign),
    issueNumber: null,
    reason,
  };
}

function campaignMarkers(body: string): readonly string[] {
  return [...body.matchAll(/<!-- radar-remediator:campaign=([a-f0-9]{24}) -->/g)].flatMap(
    (match) => (match[1] ? [match[1]] : []),
  );
}

export function campaignMarkerKeys(body: string): readonly string[] {
  return campaignMarkers(body);
}

export function campaignIssueTitle(campaign: RemediationCampaign): string {
  return `[security] Review ${campaign.ecosystem} dependencies in ${campaign.manifestPath ?? "unknown manifest"}`;
}

export function campaignIssueBody(campaign: RemediationCampaign): string {
  const rows = campaign.findings
    .slice()
    .sort((left, right) => left.alertNumber - right.alertNumber)
    .map(
      (finding) =>
        `| ${finding.alertNumber} | ${finding.severity} | ${inlineCode(finding.packageName)} | ${escapeInline(finding.summary)} | ${inlineCode(finding.vulnerableVersionRange ?? "unknown")} | ${finding.firstPatchedVersion ? inlineCode(finding.firstPatchedVersion) : "Not published"} | ${finding.aliases.map(escapeInline).join(", ")} |`,
    );
  return [
    campaign.marker,
    "## Remediation campaign",
    "",
    `| Field | Value |`,
    `| --- | --- |`,
    `| Repository | ${inlineCode(campaign.repositoryFullName)} |`,
    `| Repository IDs | ${campaign.repositoryIds.join(", ") || "unknown"} |`,
    `| Ecosystem | ${inlineCode(campaign.ecosystem)} |`,
    `| Manifest | ${inlineCode(campaign.manifestPath ?? "unknown")} |`,
    `| Campaign key | ${inlineCode(campaign.key)} |`,
    `| Findings | ${campaign.findingCount} |`,
    `| Critical | ${campaign.criticalCount} |`,
    `| High | ${campaign.highCount} |`,
    `| Remediation mode | ${inlineCode(campaign.remediationMode)} |`,
    "",
    "## Alert evidence",
    "",
    "| Alert | Severity | Package | Summary | Vulnerable range | First patched version | Advisory |",
    "| ---: | --- | --- | --- | --- | --- | --- |",
    ...rows,
    "",
    "## Remediation brief",
    "",
    "- Inspect the direct and transitive dependency graph before editing.",
    "- Prefer upgrading the owning direct dependency when a transitive package is affected.",
    "- Do not assume the highest first-patched version is compatible across dependency trains.",
    "- Change only the approved manifest and its lockfile.",
    "- Run dependency installation without publication credentials.",
    "- Run the repository's tests, lint, build, and audit.",
    "- Verify every resolved affected package is outside all applicable vulnerable ranges.",
    "- Open a draft PR for human review. Do not merge.",
    "",
    "## Manual review evidence",
    "",
    campaign.reviewReasons.length > 0
      ? campaign.reviewReasons.map((reason) => `- ${inlineCode(reason)}`).join("\n")
      : "- None identified by the campaign planner.",
    "",
    "This issue is evidence and coordination only. No automated dependency fix is claimed.",
    "",
    "_Generated by Radar Security Auditor._",
  ].join("\n");
}

function table(value: string): string {
  return value.replace(/[\r\n]+/g, " ").replaceAll("|", "\\|");
}

function inlineCode(value: string): string {
  return `\`${value.replaceAll("`", "'").replace(/[\r\n]+/g, " ")}\``;
}

function escapeInline(value: string): string {
  return table(value.replaceAll("|", "").replaceAll("`", "'"))
    .replaceAll("`", "'")
    .replace(/([\\`*_[\]()<>#+.!@-])/g, "\\$1");
}
