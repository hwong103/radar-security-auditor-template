import { z } from "zod";

import type { ApiResponse, HttpResponse, RadarCve, Severity } from "./types.js";

const dateSchema = z
  .string()
  .datetime({ offset: true })
  .transform((value) => new Date(value).toISOString());

const jsonFeedSchema = z
  .object({
    version: z.string(),
    title: z.string(),
    feed_url: z.string().url(),
    items: z
      .array(
        z
          .object({
            id: z.string().min(1),
            url: z.string().url(),
            title: z.string().min(1),
            summary: z.string().default(""),
            content_text: z.string().default(""),
            date_published: dateSchema,
            _cve: z
              .object({
                id: z.string().regex(/^CVE-\d{4}-\d{4,}$/),
                severity: z.string(),
                score: z.number().finite().nullable().optional(),
                cvss_version: z.string().nullable().optional(),
              })
              .passthrough()
              .optional(),
          })
          .passthrough(),
      )
      .default([]),
  })
  .passthrough();

function parseSeverity(value: string): Severity {
  const lower = value.toLowerCase();
  return ["critical", "high", "medium", "low"].includes(lower)
    ? (lower as Severity)
    : "unknown";
}

function stripMarkup(value: string): string {
  return value
    .replace(/<[^>]*>/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 12_000);
}

function escapeXml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

export function parseRadarFeed(body: string): readonly RadarCve[] {
  const trimmed = body.trim();
  if (!trimmed) throw new Error("Radar feed was empty");
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    const parsed = jsonFeedSchema.parse(JSON.parse(trimmed) as unknown);
    return parsed.items.flatMap((item) => {
      const cve = item._cve;
      if (!cve) return [];
      return [
        {
          id: cve.id,
          url: item.url,
          title: stripMarkup(item.title),
          summary: stripMarkup(item.content_text || item.summary),
          publishedAt: item.date_published,
          severity: parseSeverity(cve.severity),
          score: cve.score ?? null,
          cvssVersion: cve.cvss_version ?? null,
        },
      ];
    });
  }
  return parseRss(trimmed);
}

function unescapeXml(value: string): string {
  return value
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"')
    .replaceAll("&apos;", "'")
    .replaceAll("&amp;", "&");
}

function xmlText(item: string, name: string): string {
  const match = item.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, "i"));
  return match?.[1] ? unescapeXml(match[1].replace(/^<!\[CDATA\[|\]\]>$/g, "")).trim() : "";
}

export function parseRss(body: string): readonly RadarCve[] {
  const cves: RadarCve[] = [];
  for (const match of body.matchAll(/<item(?:\s[^>]*)?>([\s\S]*?)<\/item>/gi)) {
    const item = match[1] ?? "";
    const title = xmlText(item, "title");
    const link = xmlText(item, "link");
    const guid = xmlText(item, "guid");
    const id = (
      title.match(/CVE-\d{4}-\d{4,}/)?.[0] ?? guid.match(/CVE-\d{4}-\d{4,}/)?.[0]
    )?.toUpperCase();
    if (!id) continue;
    const summary = stripMarkup(xmlText(item, "description"));
    const severityMatch =
      summary.match(/CVSS\s+[\d.]+\s+score\s*:\s*[\d.]+\s*\(([^)]+)\)/i) ??
      summary.match(/\b(Critical|High|Medium|Low)\b/i);
    const scoreMatch = summary.match(/CVSS\s+([\d.]+)\s+score\s*:\s*([\d.]+)/i);
    const publishedRaw = xmlText(item, "pubDate");
    const publishedAt = publishedRaw
      ? new Date(publishedRaw).toISOString()
      : new Date(0).toISOString();
    cves.push({
      id,
      url: link || `https://radar.cloudflare.com/zero-wire/cves/${id}`,
      title: stripMarkup(title),
      summary,
      publishedAt,
      severity: severityMatch?.[1] ? parseSeverity(severityMatch[1]) : "unknown",
      score: scoreMatch?.[2] ? Number(scoreMatch[2]) : null,
      cvssVersion: scoreMatch?.[1] ?? null,
    });
  }
  return cves;
}

export function feedUrlForSeverities(
  baseUrl: string,
  severities: readonly Severity[],
): string {
  const url = new URL(baseUrl);
  url.searchParams.set("format", "json");
  const first = severities.find((severity) => severity !== "unknown");
  if (first) url.searchParams.set("severity", first);
  return url.toString();
}

export function feedUrlsForSeverities(
  baseUrl: string,
  severities: readonly Severity[],
): readonly string[] {
  const ranked = [...new Set(severities)].sort(
    (left, right) =>
      ["critical", "high", "medium", "low"].indexOf(left) -
      ["critical", "high", "medium", "low"].indexOf(right),
  );
  return (ranked.length > 0 ? ranked : ["unknown" as const]).map((severity) => {
    const url = new URL(baseUrl);
    url.searchParams.set("format", "json");
    if (severity !== "unknown") url.searchParams.set("severity", severity);
    return url.toString();
  });
}

export function filterRadarCves(
  cves: readonly RadarCve[],
  severities: readonly Severity[],
): readonly RadarCve[] {
  const allowed = new Set(severities);
  return cves.filter((cve) => allowed.has(cve.severity));
}

interface FeedTransport {
  readonly request: (
    url: string,
    init: RequestInit,
    options?: { readonly allowNotFound?: boolean; readonly timeoutMs?: number },
  ) => Promise<ApiResponse>;
}

export async function fetchRadarFeed(
  client: FeedTransport,
  baseUrl: string,
  severities: readonly Severity[],
): Promise<{ readonly cves: readonly RadarCve[]; readonly url: string }> {
  const urls = feedUrlsForSeverities(baseUrl, severities);
  const byId = new Map<string, RadarCve>();
  for (const url of urls) {
    const response: HttpResponse = await client.request(url, {
      method: "GET",
      headers: {
        Accept: "application/feed+json, application/json, application/rss+xml, text/xml",
        "User-Agent": "radar-security-auditor/0.1",
      },
      redirect: "error",
    });
    if (response.status !== 200) {
      throw new Error(`Radar feed returned HTTP ${response.status}`);
    }
    for (const cve of filterRadarCves(parseRadarFeed(response.body), severities)) {
      byId.set(cve.id, cve);
    }
  }
  return { cves: [...byId.values()], url: new URL(baseUrl).toString() };
}

export function escapeForFeed(value: string): string {
  return escapeXml(value);
}
