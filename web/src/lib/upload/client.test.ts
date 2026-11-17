// @vitest-environment node
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { uploadFile } from "./client";

const AGENT = "http://agent.test/v1/upload/u1";

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** A 10-byte file split into 4-byte chunks: offsets 0, 4 and 8. */
function makeFile() {
  return new File(["0123456789"], "a.bin", { type: "application/octet-stream" });
}

/**
 * Routes init, grant and complete. PATCH replies come from `patches`, one per
 * call, so each test controls the Agent's responses in order.
 */
function setup(patches: Array<() => Response>) {
  const queue = [...patches];
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    if (method === "POST" && url === "/api/files/uploads") {
      return json({ uploadId: "u1", fileId: "f1", chunkSize: 4 });
    }
    if (method === "POST" && url === "/api/files/uploads/u1/grant") {
      return json({ agentUrl: AGENT, grant: "g=abc", fileId: "f1" });
    }
    if (method === "POST" && url === "/api/files/uploads/u1/complete") {
      return json({ ok: true });
    }
    if (method === "PATCH" && url.startsWith(AGENT)) {
      const next = queue.shift();
      if (!next) throw new Error(`Unexpected PATCH: ${url}`);
      return next();
    }
    throw new Error(`Unexpected fetch: ${method} ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  const patchCalls = () =>
    fetchMock.mock.calls.filter(([, init]) => init?.method === "PATCH");
  return {
    patchUrls: () => patchCalls().map(([url]) => String(url)),
    patchBodies: () => patchCalls().map(([, init]) => init?.body as Blob),
  };
}

const ok = () => new Response(null, { status: 200 });
const conflict = (size: number) => () => json({ size }, 409);
const serverError = () => new Response("boom", { status: 500 });

/**
 * Runs the upload while advancing fake time. The client awaits real crypto
 * between steps, so timers are scheduled after a single advance would run;
 * we keep advancing until the promise settles.
 */
async function drive<T>(promise: Promise<T>): Promise<T> {
  let settled = false;
  promise.then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    },
  );
  while (!settled) {
    await vi.advanceTimersByTimeAsync(10_000);
    await new Promise((resolve) => setImmediate(resolve));
  }
  return promise;
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout"] });
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("uploadFile 409 resume", () => {
  it("resumes from the offset the Agent reports and sends the remaining bytes", async () => {
    // The Agent already holds 4 bytes: the first attempt at offset 0 gets a 409,
    // so the client re-slices from offset 4 and carries on with the remaining bytes.
    const { patchUrls, patchBodies } = setup([conflict(4), ok, ok]);

    await drive(uploadFile(makeFile()));

    expect(patchUrls()).toEqual([
      `${AGENT}?g=abc&offset=0`,
      `${AGENT}?g=abc&offset=4`,
      `${AGENT}?g=abc&offset=8`,
    ]);
    expect(await patchBodies()[1].text()).toBe("4567");
    expect(await patchBodies()[2].text()).toBe("89");
  });

  it("gives up after repeated 409 replies", async () => {
    // Every 409 reports offset 0, so the client never advances.
    const { patchUrls } = setup(Array.from({ length: 6 }, () => conflict(0)));

    await expect(drive(uploadFile(makeFile()))).rejects.toThrow("Upload conflict");
    expect(patchUrls()).toHaveLength(6);
  });
});

describe("uploadFile chunk retry", () => {
  it("retries a failed chunk after backoff and then completes", async () => {
    const { patchUrls } = setup([serverError, ok, ok, ok]);

    await drive(uploadFile(makeFile()));

    // The first chunk is attempted twice; the rest go once each.
    expect(patchUrls()).toEqual([
      `${AGENT}?g=abc&offset=0`,
      `${AGENT}?g=abc&offset=0`,
      `${AGENT}?g=abc&offset=4`,
      `${AGENT}?g=abc&offset=8`,
    ]);
  });

  it("fails after MAX_RETRIES consecutive chunk failures", async () => {
    // One initial attempt plus 5 retries is 6 PATCH calls before giving up.
    const { patchUrls } = setup(Array.from({ length: 6 }, () => serverError));

    await expect(drive(uploadFile(makeFile()))).rejects.toThrow("500");
    expect(patchUrls()).toHaveLength(6);
  });
});
