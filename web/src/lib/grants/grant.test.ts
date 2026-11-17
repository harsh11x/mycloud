import { describe, expect, it } from "vitest";
import { generateKeyPairSync, verify, createPublicKey } from "node:crypto";
import { canonicalGrant, grantQuery, issueGrant, MAX_GRANT_TTL_SECONDS } from "./grant";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const privPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

describe("grant signing", () => {
  it("produces the canonical v1 layout the Agent verifies", () => {
    const c = canonicalGrant({ op: "upload", fileId: "f1", userId: "u1", nonce: "n", exp: 100 });
    expect(c).toBe("v1\nupload\nf1\nu1\nn\n100");
  });

  it("signature verifies with the public key and fails when a field changes", () => {
    const { grant, sig } = issueGrant("download", "file-1", "user-1", privPem, new Date(0), 60);
    const sigBuf = Buffer.from(sig, "base64");
    const pub = createPublicKey(publicKey.export({ type: "spki", format: "pem" }).toString());
    expect(verify(null, Buffer.from(canonicalGrant(grant)), pub, sigBuf)).toBe(true);
    const tampered = canonicalGrant({ ...grant, fileId: "file-2" });
    expect(verify(null, Buffer.from(tampered), pub, sigBuf)).toBe(false);
  });

  it("caps lifetime at the Agent maximum", () => {
    const now = new Date(0);
    const { grant } = issueGrant("upload", "f", "u", privPem, now, 99999);
    expect(grant.exp - 0).toBe(MAX_GRANT_TTL_SECONDS);
  });

  it("gives each grant a fresh nonce", () => {
    const a = issueGrant("upload", "f", "u", privPem).grant.nonce;
    const b = issueGrant("upload", "f", "u", privPem).grant.nonce;
    expect(a).not.toBe(b);
  });

  it("builds the query string with the names the Agent reads", () => {
    const { grant, sig } = issueGrant("delete", "f", "u", privPem, new Date(0), 30);
    const q = new URLSearchParams(grantQuery(grant, sig));
    expect([...q.keys()].sort()).toEqual(["exp", "nonce", "op", "sig", "uid"]);
    expect(q.get("op")).toBe("delete");
    expect(q.get("uid")).toBe("u");
  });
});
