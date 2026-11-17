# Deploying MyCloud

Two pieces: the Next.js app on Vercel, and the Go storage agent somewhere with a disk.
Vercel serves the app only; the agent is reached directly by the browser over its tunnel.

## Vercel project settings

- **Root Directory: `web`.** The repo root has no `package.json`, so leaving it at the root
  fails with `NEXT_NO_VERSION`. `web/vercel.json` holds the framework and header config.
- Install and Build commands stay on the preset defaults (`npm ci`, `npm run build`) —
  they run from `web/`. Do not prefix them with `--prefix web`.
- Node.js Version: 20 or newer (`web/package.json` requires `>=20.9.0`).

## Environment variables

Set all four for Production *and* Preview:

| Variable | Value |
| --- | --- |
| `DATABASE_URL` | Hosted Postgres connection string, including `sslmode=require`. Use the pooled string. `localhost` will not work. |
| `APP_ORIGIN` | Public origin of the deployment, e.g. `https://your-app.vercel.app`, no trailing slash. Mutating requests are rejected when this is missing or wrong. |
| `GRANT_SIGNING_KEY` | Ed25519 private key (PEM) used to sign upload and download grants. Server-side only. Store it as a single line with literal `\n` for newlines. |
| `AGENT_URL` | Public HTTPS URL of the storage agent's Cloudflare Tunnel. A `127.0.0.1` value only works on your own machine. |

Never commit these. Local values live in `web/.env`, which is gitignored.

## One-time database migration

The hosted database starts empty, so apply the schema once from your machine:

```bash
cd web
DATABASE_URL='<hosted connection string>' npm run db:migrate
```

Re-run it after any change under `web/drizzle/`. Skip it and the app returns 500s on
every route that touches the database.
