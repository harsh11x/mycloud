# MyCloud Threat Model

## Assets
- User files (bytes on the Storage Agent's drives).
- User accounts, password hashes, TOTP secrets, session tokens.
- Admin capabilities (user management, storage pools, kill switch).
- Audit log integrity.
- Agent signing key (Ed25519 private key lives only on the Vercel side; Agent holds the public key).

## Trust boundaries
1. Browser <-> Web app (Vercel). Untrusted input.
2. Web app <-> Postgres (hosted). Trusted for data, credentials via env vars.
3. Web app <-> Storage Agent (user's PC via Cloudflare Tunnel). Only signed, short-lived, single-use URLs cross this boundary. The Agent never trusts a path from the network.
4. Storage Agent <-> local disk. Agent runs as an unprivileged user and only touches configured roots.

## Adversaries and mitigations
| Threat | Mitigation |
|---|---|
| Credential stuffing / brute force | Argon2id hashing, per-IP and per-account rate limiting, progressive lockout, Turnstile on login/signup. |
| Session theft | Server-side sessions (hashed token in DB), HttpOnly/Secure/SameSite=Lax cookies, short idle and absolute expiry, rotation on login and privilege change. |
| CSRF | SameSite cookies, Origin/Referer check on mutations, CSRF token on forms. |
| XSS | Strict CSP (nonce-based script-src), no inline handlers, React escaping, HSTS. |
| SQL injection | Drizzle parameterized queries only; Zod validation on every input. |
| IDOR | Every query scoped by owner user ID from session; file access by opaque file ID; IDOR tests. |
| Path traversal on Agent | No path ever accepted from the network. Files are addressed by UUID; Agent maps ID -> path from a signed record; roots enforced with canonical-path checks. |
| URL forgery / replay | Ed25519 signatures over method, file ID, user, action, expiry, nonce; single-use nonce store on Agent; clock-skew tolerance of +/-60s; TTL <= 5 minutes. |
| Malicious uploads (content-type sniffing, stored XSS) | X-Content-Type-Options: nosniff, Content-Disposition attachment for non-safe types, server-computed MIME, optional ClamAV scan. |
| Admin abuse / stolen admin session | TOTP mandatory, optional passkeys, IP allowlist, short admin sessions, re-auth for dangerous actions, hash-chained audit log. |
| Agent compromise | Low-privilege OS user, no shell, no arbitrary endpoints, only allowlisted operations, outbound-only tunnel. |
| Data loss | Verify-then-delete drain, SHA-256 verification, scrubbing, tested backups and restore. |
| Dependency vulnerabilities | npm audit / govulncheck in CI, Dependabot. |

## Out of scope / residual risk
- A fully compromised user PC can read the drive contents; encryption at rest is not in scope for v1.
- The hosted Postgres provider and Vercel are trusted parties.
- Denial of service through the Cloudflare Tunnel is limited to Cloudflare's protections and rate limits.
- Browser-side malware is out of scope.
