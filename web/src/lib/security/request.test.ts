import { describe, expect, it } from "vitest";
import { buildCsp, clientIp, isSameOrigin } from "./request";

const APP = "https://mycloud.example.com";

describe("isSameOrigin", () => {
  it("accepts the exact app origin", () => {
    const req = new Request("https://x/api", { headers: { origin: APP } });
    expect(isSameOrigin(req, APP)).toBe(true);
  });

  it("rejects foreign origins, missing origins and lookalike subdomains", () => {
    expect(isSameOrigin(new Request("https://x", { headers: { origin: "https://evil.com" } }), APP)).toBe(false);
    expect(isSameOrigin(new Request("https://x"), APP)).toBe(false);
    expect(isSameOrigin(new Request("https://x", { headers: { origin: "https://mycloud.example.com.evil.io" } }), APP)).toBe(false);
    expect(isSameOrigin(new Request("https://x", { headers: { origin: "null" } }), APP)).toBe(false);
  });

  it("fails closed when no app origin is configured", () => {
    expect(isSameOrigin(new Request("https://x", { headers: { origin: APP } }), "")).toBe(false);
  });
});

describe("clientIp", () => {
  it("uses the first x-forwarded-for entry", () => {
    const req = new Request("https://x", { headers: { "x-forwarded-for": "203.0.113.5, 10.0.0.1" } });
    expect(clientIp(req)).toBe("203.0.113.5");
  });

  it("falls back to unknown", () => {
    expect(clientIp(new Request("https://x"))).toBe("unknown");
  });
});

describe("buildCsp", () => {
  it("uses a nonce and never allows unsafe-inline scripts in production", () => {
    const csp = buildCsp("abc123", false);
    expect(csp).toContain("script-src 'self' 'nonce-abc123' 'strict-dynamic'");
    expect(csp).not.toMatch(/script-src[^;]*unsafe-inline/);
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
  });
});
