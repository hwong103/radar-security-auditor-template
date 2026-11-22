import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { z } from "zod";

import { ECOSYSTEMS, SEVERITIES, type HubConfig, type RepositoryConfig } from "./types.js";

const ecosystemSchema = z.enum(ECOSYSTEMS);
const severitySchema = z.enum(SEVERITIES);

const defaultEcosystems = ["npm", "pip", "go", "rust", "composer"] as const;

const repositorySchema = z
  .object({
    owner: z.string().trim().min(1).max(100),
    name: z.string().trim().min(1).max(100),
    publishIssues: z.boolean().default(false),
    enabled: z.boolean().default(true),
    openDraftPrs: z.boolean().default(false),
    allowDependencyChanges: z.boolean().default(false),
    allowedEcosystems: z.array(ecosystemSchema).default([...defaultEcosystems]),
  })
  .strict();

const repositoryDefaultsSchema = z
  .object({
    publishIssues: z.boolean().default(false),
    openDraftPrs: z.boolean().default(false),
    allowDependencyChanges: z.boolean().default(false),
    allowedEcosystems: z.array(ecosystemSchema).default([...defaultEcosystems]),
  })
  .strict();

export const hubConfigSchema = z
  .object({
    version: z.literal(1),
    feedUrl: z.string().url().default("https://radar.cloudflare.com/zero-wire/cves/feed"),
    trustedIssueAuthor: z.string().trim().min(1).nullable().default(null),
    severities: z.array(severitySchema).min(1).default(["critical", "high"]),
    inventory: z.enum(["configured", "app-installations"]).default("configured"),
    repositoryDefaults: repositoryDefaultsSchema.default({
      publishIssues: false,
      openDraftPrs: false,
      allowDependencyChanges: false,
      allowedEcosystems: [...defaultEcosystems],
    }),
    installations: z
      .array(
        z
          .object({
            owner: z.string().trim().min(1),
            installationId: z.number().int().positive().optional(),
          })
          .strict(),
      )
      .default([]),
    repositories: z.array(repositorySchema).default([]),
  })
  .strict();

export async function loadHubConfig(
  path: string,
  environment: Readonly<Record<string, string | undefined>> = process.env,
): Promise<HubConfig> {
  const absolute = resolve(path);
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(absolute, "utf8")) as unknown;
  } catch (error) {
    throw new Error(`Could not read hub config at ${absolute}`, { cause: error });
  }
  const parsed = hubConfigSchema.parse(raw);
  const severities = environment.RADAR_SEVERITIES
    ? environment.RADAR_SEVERITIES.split(",")
        .map((item) => item.trim())
        .filter(Boolean)
        .map((item) => severitySchema.parse(item))
    : parsed.severities;
  return { ...parsed, severities };
}

export function repositoryKey(owner: string, name: string): string {
  return `${owner}/${name}`.toLowerCase();
}

export function repositoryConfigFor(
  config: HubConfig,
  owner: string,
  name: string,
): RepositoryConfig | null {
  if (
    config.inventory === "app-installations" &&
    !config.installations.some(
      (installation) => installation.owner.toLowerCase() === owner.toLowerCase(),
    )
  ) {
    return null;
  }
  const key = repositoryKey(owner, name);
  const override = config.repositories.find(
    (repository) => repositoryKey(repository.owner, repository.name) === key,
  );
  if (override) return override.enabled ? override : null;
  if (config.inventory === "configured") return null;
  return {
    owner,
    name,
    enabled: true,
    ...config.repositoryDefaults,
    allowedEcosystems: [...config.repositoryDefaults.allowedEcosystems],
  };
}
