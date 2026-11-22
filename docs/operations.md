# Operations

## First run

1. Run **Radar security audit** with `dry_run=true`. With installation-wide discovery, the scan reconciles every open Dependabot alert in every active repository visible to the configured App installation. Repository entries are only exclusions or policy overrides.
2. Download the `radar-plan` artifact. Review confirmed findings, potential manifest exposures, unavailable repositories, skipped scope, and coverage gaps.
3. Compare confirmed findings with each repository's Dependabot page.
4. Configure and verify protection for the protected write environment. Required reviewers are not available for private environments on every GitHub plan.
5. Run an issue-only canary in a disposable repository with a real alert.
6. Scheduled runs are read-only. The template does not wire legacy per-alert publication. Any opted-in publisher should require a successful canary and a separately protected environment.
7. Set `trustedIssueAuthor` to the publishing App bot login before enabling issue updates. Markers from other authors are ignored.
8. Optional model advice runs only in a dry manual run, in a job with no GitHub App credentials. It enriches a separate `radar-advised` artifact and does not participate in the write job.

## What a clean result means

A clean report means there is no matching open Dependabot alert among covered repositories. It does not prove the repositories are vulnerability-free.

Read these coverage indicators:

| Indicator                          | Meaning                                                                          |
| ---------------------------------- | -------------------------------------------------------------------------------- |
| Dependabot alerts unavailable      | The App lacks permissions, Dependabot is disabled, or the API is unavailable.    |
| Repository inventory is configured | The scan uses the locked-down allowlist instead of all App-visible repositories. |
| Publication needs opt-in           | A discovered repository is audited, but its findings are report-only.            |
| No matching Radar item             | Feed discovery did not contain the CVE. Reconcile alerts directly.               |
| Unsupported ecosystem              | No deterministic version-range or remediation path is configured.                |
| No first patched version           | A human must identify vendor guidance or a mitigated deployment.                 |

## Python campaigns

The scanner discovers `requirements*.txt`, `poetry.lock`, `uv.lock`, and `Pipfile.lock` recursively and reads exact installed versions only. Python package identity is normalized according to PEP 503, and vulnerable ranges are evaluated with PEP 440 semantics.

Every Python campaign is marked `review-required`, even when its evidence contains a valid first patched version. Do not run an unreviewed generic package-manager command or hand-edit only the manifest. A resolving agent must identify the owning dependency and lock operation, apply the correct updater for that repository, verify the resolved graph no longer contains the vulnerable version, and run the repository’s validation commands before proposing a Draft PR.

## Repository inventory

Run the inventory command with the read-only App credential and compare it with `config/repos.json`:

```bash
node dist/cli.js inventory \
  --config config/repos.json \
  --app-id "$RADAR_GITHUB_APP_ID" \
  --private-key /run/secrets/github-app.pem \
  --output artifacts/inventory.json
```

Configure each installation owner explicitly. A token valid for one owner cannot inventory another owner.

For day-to-day operation, `inventory: "app-installations"` discovers new repositories automatically. Use the inventory command to inspect App visibility or to troubleshoot a repository that did not appear in a scan. Set `enabled: false` in `config/repos.json` for an App-visible repository that must not be audited.

## Credential rotation

Use separate App credentials for reads and writes. Store private keys in GitHub environment secrets. Never print them, cache them, or add them to artifacts. Revoke the old key only after a token exchange succeeds with the new one. The scheduler does not persist installation tokens.

## Ambiguous writes

After a timeout on issue creation, rerun the scan before retrying. The closed watch and marker search turn an already-created issue into an `update-issue` plan. Do not blindly retry a mutation from a stale report.

Close an issue when the alert is fixed, dismissed, or accepted as a risk. A closed marker is not reopened by the same finding key. If an advisory is later reassessed as a new exposure with a new package, manifest, or advisory identity, its new key can open a new item.

## Model provider

Model advice is optional and limited to dry manual runs. Before enabling it, verify:

- the current Provider API entitlement and exact model IDs;
- zero-data-retention support for the chosen account and model;
- the provider accepts `x-cmd-zdr: 1` without changing authorization behavior;
- sanitized evidence does not contain repository secrets or issue bodies.

The tool falls back to deterministic text on provider failure. A provider outage must not change exposure facts or block a dry run.

Model advice requires the advisory range, first patched version, and an exact installed version. When any of those are missing, the advice is marked `insufficient` and gives evidence-gathering steps. Treat a model summary as an advisory note, never as proof that an upgrade is compatible.

Before changing model tiers, compare the deterministic fallback, DeepSeek Flash, GLM Flash, and any proposed larger model on previously resolved findings. Measure unsupported claims, correct abstention, maintainer usefulness, latency, and cost. The routing tests establish selection and parsing only.

## Adding a repository

In installation-wide mode, normally no entry is needed. Confirm the GitHub App is installed on the owner, the repository is visible to that installation, and Dependabot alerts are enabled. The next audit includes it as report-only. Add an override with `publishIssues: true`, `openDraftPrs: false`, and `allowDependencyChanges: false` only after inspecting its alert state. Missing and unavailable repositories are reported as coverage gaps rather than treated as clean.

## Incidents

For a critical finding with no Dependabot alert:

1. Fetch the canonical CVE from Radar and resolve GHSA/OSV records.
2. Compare the advisory ranges with lockfiles and deployed runtime versions.
3. Treat the model's explanation as advisory only.
4. Open a manual issue in the affected private or public repository with evidence and the exact installed version.
5. Do not auto-merge or deploy a fix from this hub.
