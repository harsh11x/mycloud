import { createPrivateKey, sign, randomBytes } from "node:crypto";

/**
 * Signs short-lived, single-use grants for the Storage Agent.
 *
 * The canonical string MUST match agent/internal/signing/signing.go exactly:
 * "v1\n<op>\n<fileId>\n<userId>\n<nonce>\n<exp>". The private key lives only
 * on the web server; the Agent holds the matching public key.
 */
export type GrantOp = "upload" | "download" | "delete" | "finalize";

export const MAX_GRANT_TTL_SECONDS = 300;

export type Grant = {
  op: GrantOp;
  fileId: string;
  userId: string;
  nonce: string;
  exp: number;
};

export function canonicalGrant(g: Grant): string {
  return ["v1", g.op, g.fileId, g.userId, g.nonce, String(g.exp)].join("\n");
}

export function signGrant(
  g: Grant,
  privateKeyPem: string,
): string {
  const key = createPrivateKey(privateKeyPem);
  return sign(null, Buffer.from(canonicalGrant(g)), key).toString("base64");
}

/** Builds and signs a grant that expires in ttlSeconds (capped at the Agent's maximum). */
export function issueGrant(
  op: GrantOp,
  fileId: string,
  userId: string,
  privateKeyPem: string,
  now: Date = new Date(),
  ttlSeconds = 120,
): { grant: Grant; sig: string } {
  const ttl = Math.min(Math.max(ttlSeconds, 1), MAX_GRANT_TTL_SECONDS);
  const grant: Grant = {
    op,
    fileId,
    userId,
    nonce: randomBytes(16).toString("base64url"),
    exp: Math.floor(now.getTime() / 1000) + ttl,
  };
  return { grant, sig: signGrant(grant, privateKeyPem) };
}

/**
 * Loads server configuration for grants. Fails closed: a missing key or Agent URL
 * stops the request rather than issuing anything unsigned.
 */
export function grantConfig(env: NodeJS.ProcessEnv = process.env): { privateKeyPem: string; agentUrl: string } {
  const privateKeyPem = env.GRANT_SIGNING_KEY?.replace(/\\n/g, "\n");
  const agentUrl = env.AGENT_URL;
  if (!privateKeyPem || !agentUrl) throw new Error("Storage grant configuration is missing");
  return { privateKeyPem, agentUrl };
}

/** Builds the query string the Agent parses: op, uid, nonce, exp, sig. */
export function grantQuery(g: Grant, sig: string): string {
  const p = new URLSearchParams({
    op: g.op,
    uid: g.userId,
    nonce: g.nonce,
    exp: String(g.exp),
    sig,
  });
  return p.toString();
}
