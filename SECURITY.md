# Security

Report vulnerabilities privately through GitHub's security advisory feature for this repository.

## Trust boundaries

- Radar feed text, advisory bodies, repository files, model output, and GitHub web responses are untrusted data.
- A read-only GitHub App installation token is used for inventory, alerts, existing issues, and CI validation.
- A separate write-capable App token exists only in the approved publisher job.
- Command Code receives sanitized advisory metadata and has no GitHub token, shell, repository checkout, or write tool.
- The publisher never executes target repository code and never merges.

## Non-negotiables

- Do not infer exposure from feed prose alone.
- Do not accept model-provided repository lists, paths, package versions, issue actions, or patches.
- Do not expose a write token to an artifact, command output, or environment used by the model.
- Do not create non-Draft PRs.
- Do not bypass protected environment approval for writes.
- Keep third-party Actions pinned to full commit SHAs.
- Recheck base SHA, paths, candidate version, and tests before any future patch publication.

## Known limitation

This release does not open replacement PRs. A safe update must run the real package manager, verify lockfile integrity and dependency graph, and pass target-repository checks without write credentials. Generic model-authored or scalar-only lockfile edits are intentionally out of scope.
