import type { CampaignIssuePlan, CampaignIssueState } from "./campaign-issue.js";
import {
  campaignIssueBody,
  campaignIssueTitle,
  planCampaignIssue,
} from "./campaign-issue.js";
import { findingFromAlert } from "./findings.js";
import { buildCampaignPreview, campaignDigest } from "./campaigns.js";
import type { DependencyAlert, RemediationCampaign, RepositoryIssue } from "./types.js";

export interface CampaignPublisherClient {
  listIssues(repository: string): Promise<readonly RepositoryIssue[]>;
  createIssue(repository: string, title: string, body: string): Promise<RepositoryIssue>;
  updateIssue(
    repository: string,
    issueNumber: number,
    title: string,
    body: string,
  ): Promise<RepositoryIssue>;
}

export interface CampaignPublisherResult {
  readonly action: CampaignIssuePlan["action"] | "stale";
  readonly issueNumber: number | null;
  readonly url: string | null;
  readonly attempted: boolean;
  readonly reason: string;
}

export async function publishCampaign(options: {
  readonly client: CampaignPublisherClient;
  readonly campaign: RemediationCampaign;
  readonly sourceReportGeneratedAt: string;
  readonly maximumFindings: number;
  readonly liveAlerts: readonly DependencyAlert[];
  readonly trustedIssueAuthor: string;
}): Promise<CampaignPublisherResult> {
  const currentPreview = buildCampaignPreview(
    options.liveAlerts
      .filter((alert) => alert.state === "open")
      .map((alert) => findingFromAlert(alert, null)),
    {
      sourceReportGeneratedAt: options.sourceReportGeneratedAt,
      maxFindingsPerCampaign: options.maximumFindings,
    },
  );
  const current = currentPreview.campaigns.find(
    (campaign) =>
      campaign.key === options.campaign.key &&
      campaign.repositoryFullName.toLowerCase() ===
        options.campaign.repositoryFullName.toLowerCase(),
  );
  if (!current || campaignDigest(current) !== campaignDigest(options.campaign)) {
    return {
      action: "stale",
      issueNumber: null,
      url: null,
      attempted: false,
      reason: "Campaign alerts changed or are no longer open.",
    };
  }
  const issues = await options.client.listIssues(options.campaign.repositoryFullName);
  const plan = planCampaignIssue(current, {
    issues,
    trustedIssueAuthor: options.trustedIssueAuthor,
  });
  if (plan.action === "closed" || plan.action === "untrusted") {
    return resultForPlan(issues, plan);
  }
  if (plan.action === "same") {
    return resultForPlan(issues, plan);
  }
  if (plan.action === "update") {
    if (plan.issueNumber === null) throw new Error("Campaign update has no issue number");
    try {
      const issue = await options.client.updateIssue(
        current.repositoryFullName,
        plan.issueNumber,
        plan.title,
        plan.body,
      );
      return {
        action: "update",
        issueNumber: issue.number,
        url: issue.htmlUrl,
        attempted: true,
        reason: plan.reason,
      };
    } catch (error) {
      const reconciled = await reconcileAmbiguousWrite(options, current, plan, error);
      if (reconciled) return reconciled;
      throw error;
    }
  }
  try {
    const issue = await options.client.createIssue(
      current.repositoryFullName,
      plan.title,
      plan.body,
    );
    return {
      action: "create",
      issueNumber: issue.number,
      url: issue.htmlUrl,
      attempted: true,
      reason: plan.reason,
    };
  } catch (error) {
    const reconciled = await reconcileAmbiguousWrite(options, current, plan, error);
    if (reconciled) return reconciled;
    throw error;
  }
}

function resultForPlan(
  issues: readonly RepositoryIssue[],
  plan: CampaignIssuePlan,
): CampaignPublisherResult {
  const issue =
    plan.issueNumber === null
      ? null
      : (issues.find((candidate) => candidate.number === plan.issueNumber) ?? null);
  return {
    action: plan.action,
    issueNumber: plan.issueNumber,
    url: issue?.htmlUrl ?? null,
    attempted: false,
    reason: plan.reason,
  };
}

async function reconcileAmbiguousWrite(
  options: {
    readonly client: CampaignPublisherClient;
    readonly trustedIssueAuthor: string;
  },
  campaign: RemediationCampaign,
  originalPlan: CampaignIssuePlan,
  writeError: unknown,
): Promise<CampaignPublisherResult | null> {
  const issues = await options.client.listIssues(campaign.repositoryFullName);
  const currentPlan = planCampaignIssue(campaign, {
    issues,
    trustedIssueAuthor: options.trustedIssueAuthor,
  });
  const matchingIssue = issues.find(
    (issue) =>
      issue.number === currentPlan.issueNumber &&
      issue.title === campaignIssueTitle(campaign) &&
      issue.body === campaignIssueBody(campaign),
  );
  if (
    matchingIssue !== undefined &&
    ((originalPlan.action === "update" && currentPlan.action === "same") ||
      (originalPlan.action === "create" && currentPlan.action === "same"))
  ) {
    const result = resultForPlan(issues, currentPlan);
    if (result.issueNumber !== null) {
      return {
        ...result,
        attempted: true,
        reason: `Reconciled a successful issue write after the client reported: ${
          writeError instanceof Error
            ? writeError.message.slice(0, 300)
            : String(writeError)
        }`,
      };
    }
  }
  return null;
}

export type { CampaignIssueState };
