# Architecture decisions

## ADR 0001: Scheduled Actions hub

**Decision:** Start with a private repository using Actions schedule and manual dispatch. A Worker remains optional.

**Reason:** Matching, lockfile inspection, package-manager commands, and target-repository tests need source checkouts and installed toolchains. Actions supplies those without adding a control-plane database or queue. Concurrency prevents overlapping publication.

**Tradeoffs:** Polling can lag publication. The feed retains only its most recent bounded window. Full open-alert reconciliation makes alert discovery durable despite feed truncation. A Worker or repository webhook can replace polling later without changing the evidence model.

## ADR 0002: Alerts and manifests establish exposure

**Decision:** Use GitHub Dependabot alerts as confirmed evidence. Use package identity and version-range matching against repository manifests only for a potential-exposure lane.

**Reason:** CVE prose often names a product but not the installed package or version. It can be incomplete, ambiguous, stale, or adversarially worded. A CVE alone cannot authorize a repository-specific write.

**Tradeoffs:** Dependabot is not exhaustive. Coverage gaps are explicit, and potential-exposure matching gives a safety net without pretending that every package ecosystem supports deterministic matching.

## ADR 0003: Credential-separated publication

**Decision:** Plan and model jobs receive read-only GitHub access. A separate write job consumes a validated artifact under an approval environment.

**Reason:** Advisory descriptions and CVE text are untrusted input. A model with repository write access or a shell would turn prompt injection into a supply-chain risk.

**Tradeoffs:** The workflow has more jobs and artifacts. Those boundaries keep retries auditable.

## ADR 0004: Stable finding identity and resource checks

**Decision:** Key a finding by repository, canonical advisory aliases, ecosystem, normalized package name, and manifest. Before a write, search marker-matched issues and matching/Dependabot PRs. Check state again after ambiguous responses.

**Reason:** Repeated runs, overlapping aliases, and partial network failures must not create duplicate issues or PRs. A closed issue records a human decision and is not reopened by the same finding.

## ADR 0005: Advisory-only models

**Decision:** Route routine work to `deepseek/deepseek-v4.1-flash` and complex remediation explanations to `z-ai/glm-5.3-flash`. Use deterministic templates on failure.

**Reason:** Model output adds value in explaining compatibility and package-manager effects. Facts, candidate payloads, and mutation authority remain deterministic.

## ADR 0006: No PR builder in the initial release

**Decision:** Do not ship a model-generated patch publisher initially.

**Reason:** Creating a safe dependency PR needs ecosystem-specific package-manager semantics, lockfile correctness, conflict handling, required commands, and CI. A generic text diff can appear to fix a package while leaving the vulnerable resolved version installed.

**Next step:** Implement npm as a narrow service with a tested package-manager update, lockfile integrity and dependency-graph proof, protected-path policy, Draft PR creation, and credential-free target-repository validation. Add other ecosystems only after their equivalent proof path exists.

## ADR 0007: Python inventory is evidence, not an automatic updater

**Decision:** Parse exact Python lock entries from `requirements*.txt`, `poetry.lock`, `uv.lock`, and `Pipfile.lock`, normalize distribution names with PEP 503, and compare version constraints with PEP 440. Python campaigns require manual review and are excluded from the npm pilot.

**Reason:** A Python update depends on the selected package manager, constraints, platform-specific markers, transitive resolution, and repository tests. A textual version replacement or generic `pip install` command can appear to fix a report while leaving the vulnerable version installed or breaking another dependency.

**Tradeoffs:** Python alerts and potential exposures can be deterministically grouped and issues can be created for agents, but the hub does not claim to produce or verify Python patches. An ecosystem-specific updater and credential-free validation are required before Python PR creation is enabled.
