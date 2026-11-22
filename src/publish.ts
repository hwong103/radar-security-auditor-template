import type { PublicationPlan } from "./types.js";

export interface PublisherClient {
  createIssue(
    installationId: number,
    repository: string,
    title: string,
    body: string,
  ): Promise<{ readonly number: number; readonly htmlUrl: string }>;
  updateIssue(
    installationId: number,
    repository: string,
    issueNumber: number,
    title: string,
    body: string,
  ): Promise<{ readonly number: number; readonly htmlUrl: string }>;
}

export interface PublicationResult {
  readonly action: PublicationPlan["action"];
  readonly repository: string;
  readonly issueNumber: number | null;
  readonly url: string | null;
  readonly skipped: boolean;
  readonly failed: boolean;
  readonly reason: string;
}

export async function publishIssuePlan(options: {
  readonly client: PublisherClient;
  readonly installationId: number;
  readonly plan: PublicationPlan;
  readonly title: string;
  readonly body: string;
  readonly dryRun: boolean;
}): Promise<PublicationResult> {
  const { client, installationId, plan, title, body, dryRun } = options;
  if (plan.action !== "create-issue" && plan.action !== "update-issue") {
    return {
      action: plan.action,
      repository: plan.finding.repositoryFullName,
      issueNumber: plan.issueNumber,
      url: null,
      skipped: true,
      failed: false,
      reason: plan.reason,
    };
  }
  if (dryRun) {
    return {
      action: plan.action,
      repository: plan.finding.repositoryFullName,
      issueNumber: plan.issueNumber,
      url: null,
      skipped: true,
      failed: false,
      reason: "Dry run; no issue was changed.",
    };
  }
  if (plan.action === "update-issue") {
    if (!plan.issueNumber) throw new Error("Update issue plan has no issue number");
    const issue = await client.updateIssue(
      installationId,
      plan.finding.repositoryFullName,
      plan.issueNumber,
      title,
      body,
    );
    return {
      action: plan.action,
      repository: plan.finding.repositoryFullName,
      issueNumber: issue.number,
      url: issue.htmlUrl,
      skipped: false,
      failed: false,
      reason: "Updated the marker-matched issue.",
    };
  }
  const issue = await client.createIssue(
    installationId,
    plan.finding.repositoryFullName,
    title,
    body,
  );
  return {
    action: plan.action,
    repository: plan.finding.repositoryFullName,
    issueNumber: issue.number,
    url: issue.htmlUrl,
    skipped: false,
    failed: false,
    reason: "Created a marker-matched issue.",
  };
}
