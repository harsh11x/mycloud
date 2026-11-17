/**
 * Returns true only when the request's Origin matches the app origin.
 * Mutating routes require this in addition to the SameSite=Lax session cookie (CSRF defence).
 */
export function isSameOrigin(req: Request, appOrigin = process.env.APP_ORIGIN): boolean {
  if (!appOrigin) return false;
  const origin = req.headers.get("origin");
  if (!origin) return false;
  try {
    return new URL(origin).origin === new URL(appOrigin).origin;
  } catch {
    return false;
  }
}

/**
 * Client IP for rate limiting. On Vercel the platform sets x-forwarded-for; the
 * first entry is the original client. Falls back to "unknown" so limits still apply.
 */
export function clientIp(req: Request): string {
  const fwd = req.headers.get("x-forwarded-for");
  if (fwd) return fwd.split(",")[0].trim().slice(0, 64);
  return req.headers.get("x-real-ip")?.slice(0, 64) ?? "unknown";
}

export const SECURITY_HEADERS: Record<string, string> = {
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "Cross-Origin-Opener-Policy": "same-origin",
};

/** Strict CSP: no inline scripts, no eval, frames denied. Next.js needs a per-request nonce for inline bootstrap. */
export function buildCsp(nonce: string, isDev: boolean): string {
  const scriptSrc = isDev
    ? `'self' 'nonce-${nonce}' 'unsafe-eval'`
    : `'self' 'nonce-${nonce}' 'strict-dynamic'`;
  return [
    "default-src 'self'",
    `script-src ${scriptSrc}`,
    `style-src 'self' 'unsafe-inline'`,
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-src https://challenges.cloudflare.com",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "upgrade-insecure-requests",
  ].join("; ");
}
