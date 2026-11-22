import { describe, expect, it } from "vitest";

import { HttpTransportImpl } from "../src/http.js";

describe("HTTP transport retry policy", () => {
  it("does not retry a mutating request after a transient failure", async () => {
    let calls = 0;
    const transport = new HttpTransportImpl({
      fetcher: async () => {
        calls += 1;
        return new Response("temporary", { status: 503 });
      },
      sleep: async () => undefined,
    });
    await expect(
      transport.request("https://api.github.com/repos/a/b/issues", {
        method: "POST",
        body: "{}",
      }),
    ).rejects.toThrow(/HTTP 503/);
    expect(calls).toBe(1);
  });

  it("retries a read after a transient failure", async () => {
    let calls = 0;
    const transport = new HttpTransportImpl({
      fetcher: async () => {
        calls += 1;
        return calls === 1
          ? new Response("temporary", { status: 503 })
          : new Response("{}", { status: 200 });
      },
      sleep: async () => undefined,
    });
    await expect(
      transport.request("https://api.github.com/repos", {}),
    ).resolves.toMatchObject({
      status: 200,
    });
    expect(calls).toBe(2);
  });
});
