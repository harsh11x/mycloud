import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * RFC 6238 TOTP (SHA-1, 6 digits, 30 s step), implemented with node:crypto.
 * Secrets are stored base32-encoded. Verification accepts one step either side
 * for clock drift and rejects reuse of an already-accepted counter.
 */
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEP = 30;
const DIGITS = 6;

export function generateTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

export function totpCode(secretB32: string, counter: number): string {
  const key = base32Decode(secretB32);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", key).update(buf).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const bin =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);
  return String(bin % 10 ** DIGITS).padStart(DIGITS, "0");
}

/**
 * Returns the matched counter, or null. Callers must reject counters at or below
 * the last accepted one (lastCounter) to block replay within the window.
 */
export function verifyTotp(
  secretB32: string,
  code: string,
  nowMs: number = Date.now(),
  lastCounter = -1,
): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const current = Math.floor(nowMs / 1000 / STEP);
  for (let c = current - 1; c <= current + 1; c++) {
    if (c <= lastCounter) continue;
    const expected = totpCode(secretB32, c);
    if (
      expected.length === code.length &&
      timingSafeEqual(Buffer.from(expected), Buffer.from(code))
    ) {
      return c;
    }
  }
  return null;
}

export function totpUri(secretB32: string, accountEmail: string, issuer = "MyCloud"): string {
  const label = encodeURIComponent(`${issuer}:${accountEmail}`);
  return `otpauth://totp/${label}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

function base32Encode(bytes: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(s: string): Buffer {
  const clean = s.replace(/=+$/, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error("invalid base32");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}
