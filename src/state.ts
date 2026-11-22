import { createHash } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { z } from "zod";

const stateSchema = z
  .object({
    version: z.literal(1),
    lastSuccessfulRun: z.string().datetime({ offset: true }),
    lastRadarPublishedAt: z.string().datetime({ offset: true }).nullable(),
    seenFindings: z.record(z.string(), z.string().datetime({ offset: true })),
  })
  .strict();

export type HubState = z.infer<typeof stateSchema>;

export function emptyState(): HubState {
  return {
    version: 1,
    lastSuccessfulRun: new Date(0).toISOString(),
    lastRadarPublishedAt: null,
    seenFindings: {},
  };
}

export async function loadState(path: string): Promise<HubState> {
  try {
    return stateSchema.parse(JSON.parse(await readFile(path, "utf8")) as unknown);
  } catch (error) {
    if (isMissingFile(error)) return emptyState();
    throw new Error(`Could not read state at ${path}`, { cause: error });
  }
}

export async function saveState(path: string, state: HubState): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(stateSchema.parse(state), null, 2)}\n`, {
    mode: 0o600,
  });
  await rename(temporary, path);
}

export function stateDigest(state: HubState): string {
  return createHash("sha256").update(JSON.stringify(state)).digest("hex");
}

export function isMissingFile(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: unknown }).code === "ENOENT"
  );
}
