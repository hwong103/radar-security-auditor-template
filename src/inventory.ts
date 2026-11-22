import type { HubConfig } from "./types.js";

export interface AppInstallation {
  readonly id: number;
  readonly owner: string;
}

export interface InstallationRepository {
  readonly id: number;
  readonly fullName: string;
  readonly owner: string;
  readonly name: string;
  readonly archived: boolean;
  readonly disabled: boolean;
}

export interface RepositoryInstallation {
  readonly repository: InstallationRepository;
  readonly installationId: number;
}

export interface InventoryDiscovery {
  readonly installations: (appJwt: string) => Promise<readonly AppInstallation[]>;
  readonly repositories: (
    installationId: number,
  ) => Promise<readonly InstallationRepository[]>;
}

export function selectedInstallations(
  config: HubConfig,
  installations: readonly AppInstallation[],
): readonly AppInstallation[] {
  const available = new Map(
    installations.map((installation) => [installation.owner.toLowerCase(), installation]),
  );
  if (config.inventory === "configured") return installations;
  const allowed = new Set(
    config.installations.map((installation) => installation.owner.toLowerCase()),
  );
  if (allowed.size === 0) {
    throw new Error(
      "app-installations inventory requires at least one configured installation owner",
    );
  }
  const selected: AppInstallation[] = [];
  for (const configured of config.installations) {
    const installation = available.get(configured.owner.toLowerCase());
    if (!installation) {
      throw new Error(
        `GitHub App is not installed for configured owner ${configured.owner}`,
      );
    }
    if (
      configured.installationId !== undefined &&
      configured.installationId !== installation.id
    ) {
      throw new Error(`Installation ID mismatch for ${configured.owner}`);
    }
    selected.push(installation);
  }
  return selected;
}

export async function discoverRepositories(
  config: HubConfig,
  discovery: InventoryDiscovery,
  appJwt: string,
): Promise<readonly RepositoryInstallation[]> {
  if (!appJwt) throw new Error("A GitHub App JWT is required");
  const installations = selectedInstallations(
    config,
    await discovery.installations(appJwt),
  );
  const result: RepositoryInstallation[] = [];
  for (const installation of installations) {
    const repositories = await discovery.repositories(installation.id);
    for (const repository of repositories) {
      if (repository.archived || repository.disabled) continue;
      result.push({ repository, installationId: installation.id });
    }
  }
  return result;
}
