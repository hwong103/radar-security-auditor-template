import type { ApiResponse, HttpTransport } from "./types.js";

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 5_000_000;

export interface HttpOptions {
  readonly fetcher?: typeof fetch;
  readonly sleep?: (milliseconds: number) => Promise<void>;
}

export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly retryAfterMs: number | null,
    readonly body = "",
  ) {
    super(message);
    this.name = "HttpError";
  }
}

function retryDelay(headers: Headers): number | null {
  const retryAfter = headers.get("retry-after");
  if (!retryAfter) return null;
  const seconds = Number(retryAfter);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1_000);
  const date = new Date(retryAfter);
  return Number.isNaN(date.valueOf()) ? null : Math.max(0, date.valueOf() - Date.now());
}

export class HttpTransportImpl implements HttpTransport {
  private readonly fetcher: typeof fetch;
  private readonly sleep: (milliseconds: number) => Promise<void>;

  constructor(options: HttpOptions = {}) {
    this.fetcher = options.fetcher ?? fetch;
    this.sleep =
      options.sleep ??
      (async (milliseconds) => {
        await new Promise((resolve) => setTimeout(resolve, milliseconds));
      });
  }

  async request(
    url: string,
    init: RequestInit,
    options: { readonly allowNotFound?: boolean; readonly timeoutMs?: number } = {},
  ): Promise<ApiResponse> {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const response = await this.fetcher(url, {
        ...init,
        redirect: "error",
        signal: AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS),
      });
      const chunks: Uint8Array[] = [];
      let bytes = 0;
      const reader = response.body?.getReader();
      if (reader) {
        try {
          while (true) {
            const chunk = await reader.read();
            if (chunk.done) break;
            bytes += chunk.value.byteLength;
            if (bytes > MAX_RESPONSE_BYTES) {
              await reader.cancel();
              throw new Error(`${url} response exceeded 5 MB`);
            }
            chunks.push(chunk.value);
          }
        } finally {
          reader.releaseLock();
        }
      }
      const body = new TextDecoder().decode(Buffer.concat(chunks));
      if ((response.status === 404 && options.allowNotFound) || response.ok) {
        return { status: response.status, headers: response.headers, body };
      }
      const transient = response.status === 429 || response.status >= 500;
      const wait = retryDelay(response.headers) ?? 500 * 2 ** attempt + Math.random() * 200;
      const method = (init.method ?? "GET").toUpperCase();
      const safeToRetry = method === "GET" || method === "HEAD";
      if (!transient || !safeToRetry || attempt === 2) {
        throw new HttpError(
          response.status,
          `${init.method ?? "GET"} ${url} returned HTTP ${response.status}: ${body.slice(0, 500)}`,
          retryDelay(response.headers),
          body,
        );
      }
      await this.sleep(wait);
    }
    throw new Error("HTTP retry loop exhausted");
  }
}
