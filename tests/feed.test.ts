import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

import {
  feedUrlForSeverities,
  feedUrlsForSeverities,
  fetchRadarFeed,
  filterRadarCves,
  parseRadarFeed,
  parseRss,
} from "../src/feed.js";
import { HttpTransportImpl } from "../src/http.js";

describe("Cloudflare Radar feed", () => {
  it("parses Radar JSON feed items", async () => {
    const body = await readFile(new URL("./fixtures/feed.json", import.meta.url), "utf8");
    expect(parseRadarFeed(body)).toEqual([
      {
        id: "CVE-2026-100001",
        url: "https://radar.cloudflare.com/zero-wire/cves/CVE-2026-100001",
        title: "CVE-2026-100001: Test package",
        summary: "A short summary. CVSS 3.1 score: 9.8 (Critical)",
        publishedAt: "2026-11-20T00:00:00.000Z",
        severity: "critical",
        score: 9.8,
        cvssVersion: "3.1",
      },
    ]);
  });

  it("parses RSS without treating markup as structure", async () => {
    const body = await readFile(new URL("./fixtures/feed.rss", import.meta.url), "utf8");
    expect(parseRss(body)).toMatchObject([
      {
        id: "CVE-2026-100001",
        severity: "critical",
        score: 9.8,
        publishedAt: "2026-11-20T00:00:00.000Z",
      },
    ]);
  });

  it("rejects unknown JSON shapes instead of silently accepting them", () => {
    expect(() => parseRadarFeed('{"items":"not-an-array"}')).toThrow();
  });

  it("builds a supported severity URL", () => {
    expect(
      feedUrlForSeverities("https://radar.cloudflare.com/zero-wire/cves/feed", [
        "high",
        "critical",
      ]),
    ).toBe("https://radar.cloudflare.com/zero-wire/cves/feed?format=json&severity=high");
  });

  it("builds one documented feed request for each configured severity", () => {
    expect(
      feedUrlsForSeverities("https://radar.cloudflare.com/zero-wire/cves/feed", [
        "high",
        "critical",
      ]),
    ).toEqual([
      "https://radar.cloudflare.com/zero-wire/cves/feed?format=json&severity=critical",
      "https://radar.cloudflare.com/zero-wire/cves/feed?format=json&severity=high",
    ]);
  });

  it("still requests the unfiltered JSON feed for unknown-only configuration", () => {
    expect(
      feedUrlsForSeverities("https://radar.cloudflare.com/zero-wire/cves/feed", [
        "unknown",
      ]),
    ).toEqual(["https://radar.cloudflare.com/zero-wire/cves/feed?format=json"]);
  });

  it("filters unsafe severity tags", () => {
    const cves = [
      {
        id: "CVE-2026-100001",
        url: "https://example.test/cve",
        title: "test",
        summary: "test",
        publishedAt: "2026-11-20T00:00:00.000Z",
        severity: "critical" as const,
        score: 9.8,
        cvssVersion: "3.1",
      },
      {
        id: "CVE-2026-100002",
        url: "https://example.test/cve",
        title: "test",
        summary: "test",
        publishedAt: "2026-11-20T00:00:00.000Z",
        severity: "high" as const,
        score: 8.8,
        cvssVersion: "3.1",
      },
    ];
    expect(filterRadarCves(cves, ["critical"])).toHaveLength(1);
  });

  it("fetches with redirects disabled", async () => {
    const body = await readFile(new URL("./fixtures/feed.json", import.meta.url), "utf8");
    let redirect: "error" | "follow" | "manual" | undefined;
    const transport = new HttpTransportImpl({
      fetcher: async (_url, init) => {
        redirect = init?.redirect;
        return new Response(body, {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    });
    const result = await fetchRadarFeed(
      transport,
      "https://radar.cloudflare.com/zero-wire/cves/feed",
      ["critical"],
    );
    expect(result.cves).toHaveLength(1);
    expect(redirect).toBe("error");
  });
});
