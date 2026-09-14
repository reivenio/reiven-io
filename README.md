# Reiven.io

Zero-knowledge encrypted notes and files. No accounts, no logs.

Reiven is a browser-first encrypted sharing service. The active production deployment is a standalone Node.js server behind a normal HTTPS reverse proxy, not a Cloudflare Worker deployment.

## Current Production Path

- Public site: `https://reiven.io/`
- App directory: `/opt/reiven`
- Data directory: `/srv/reiven`
- Service: `reiven-direct`
- Runtime entrypoint: `direct-server/server.mjs`
- Reverse proxy: Caddy or any HTTPS-capable proxy to `127.0.0.1:8080`

Cloudflare Worker, D1, R2, Wrangler, and mem-server files remain in the repository for reference and migration history, but they are not the current production architecture.

## What Reiven Does

- Encrypts files in the browser or CLI before upload.
- Encrypts text notes as downloadable `note.txt` payloads.
- Generates 8-digit access codes such as `12-34-56-78`.
- Provides download links and optional receiver-side delete links.
- Expires uploaded ciphertext automatically based on server TTL.
- Supports QR Mode, where a random browser-generated key is embedded in a QR/link fragment for direct recipient download.
- Serves an indexable public landing page while marking private download pages as `noindex`.

## Security Model

Reiven protects payload contents client-side. The server should be treated as untrusted storage for encrypted blobs.

- Passwords and QR Mode random keys are generated or entered client-side and are not submitted to the server.
- File and note payloads are encrypted client-side before upload.
- Payload encryption uses AES-256-GCM with random 256-bit data encryption keys.
- Password-derived wrapping uses Argon2id and deterministic ML-KEM-768 key wrapping.
- Standard profile uses Argon2id `time=4`, `memory=64MB`, `parallelism=1`, `PIM=100`.
- Paranoid profile uses Argon2id `time=6`, `memory=128MB`, `parallelism=1`, `PIM=100`.
- Chunk payload encryption uses unique per-chunk AES-GCM nonces.
- The server stores ciphertext plus operational metadata: file ID, encrypted size, expiry, delete token, receiver-delete flag, note flag, access-code hash, download count, and upload filename.
- If filenames are sensitive, rename files before sharing.
- Password strength remains critical; weak passwords can be brute-forced offline from ciphertext.

QR Mode creates a random key in the browser and appends it to the download URL fragment. URL fragments are not sent in normal HTTP requests, but the full QR/link is the secret and can be exposed through browser history, screenshots, chat previews, or recipient devices.

## Architecture

```text
Browser / CLI
    |
    | HTTPS
    v
Reverse proxy
    |
    | http://127.0.0.1:8080
    v
direct-server/server.mjs
    |
    +-- public/ static web app
    +-- public/vendor/ vendored crypto and QR browser bundles
    +-- shared/encryption-config.mjs shared crypto constants
    +-- /srv/reiven/files encrypted payload blobs
    +-- /srv/reiven/metadata.json metadata, hashes, tokens, expiry
```

### Direct Server Responsibilities

- Serves the static web app from `public/`.
- Exposes the `/api/*` upload, download, metadata, and delete endpoints.
- Receives encrypted upload parts and assembles final encrypted blobs.
- Maintains upload sessions in memory.
- Stores metadata in a local JSON database.
- Deletes expired records and orphaned upload parts during cleanup.
- Sends security headers including CSP, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- Redirects `/index.html` to `/` and `/download.html` to `/download`.

The app still encrypts in chunks even without Cloudflare limits. Chunking keeps browser memory lower, supports progress updates, and allows range-based download/decryption for large files.

## Repository Layout

- `public/` — browser UI, download page, styles, crypto worker, SEO files.
- `public/vendor/` — committed browser bundles for Argon2, ML-KEM, and QR generation.
- `direct-server/` — standalone production Node.js server.
- `shared/encryption-config.mjs` — shared encryption parameters used by web and CLI.
- `reiven-cli/` — terminal client for uploads and downloads.
- `src/worker.js` — legacy Cloudflare Worker implementation.
- `mem-server/` — legacy volatile storage backend used by the Worker path.
- `migrations/` — legacy Cloudflare D1 schema migrations.
- `wrangler.toml` — legacy Cloudflare configuration.

## Prerequisites

### Local Development

- Node.js 18 or newer.
- `npm`.
- A modern browser with WebCrypto and Web Worker support.

### Production Server

- Linux server with SSH access.
- Node.js 18 or newer at `/usr/bin/node`.
- Caddy, nginx, or another HTTPS reverse proxy.
- Persistent writable data directory, normally `/srv/reiven`.
- A locked-down service user, normally `reiven`.

The direct server has no production npm package dependency at runtime. Browser vendor bundles are committed under `public/vendor/`; rebuild them locally or in CI when dependency versions change.

## Local Development

Install dependencies:

```bash
npm install
```

Build vendored browser assets:

```bash
npm run vendor
```

Run the direct server locally:

```bash
npm run direct:dev
```

Open:

```text
http://127.0.0.1:8080
```

Useful checks:

```bash
node --check direct-server/server.mjs
node --check public/upload.js
node --check public/download.js
npm audit --omit=dev
```

## Production Deployment

### 1. Create User And Directories

```bash
sudo useradd --system --home /opt/reiven --shell /usr/sbin/nologin reiven || true
sudo mkdir -p /opt/reiven /srv/reiven
sudo chown -R root:root /opt/reiven
sudo chown -R reiven:reiven /srv/reiven
sudo chmod 755 /opt/reiven
sudo chmod 700 /srv/reiven
```

### 2. Install Source

Clone or sync this repository to `/opt/reiven`:

```bash
cd /opt
sudo git clone https://github.com/reivenio/reiven-io.git reiven
sudo chown -R root:root /opt/reiven
```

If deploying from a local checkout instead of cloning on the server:

```bash
rsync -az --delete \
  --exclude .git \
  --exclude node_modules \
  ./ root@SERVER:/opt/reiven/
```

### 3. Run Manually For A Smoke Test

```bash
cd /opt/reiven
sudo -u reiven \
  HOST=127.0.0.1 \
  PORT=8080 \
  PUBLIC_BASE_URL=https://reiven.io \
  REIVEN_DATA_DIR=/srv/reiven \
  /usr/bin/node /opt/reiven/direct-server/server.mjs
```

In another shell:

```bash
curl -sSI http://127.0.0.1:8080/
curl -fsSL http://127.0.0.1:8080/api/encryption-config
```

### 4. Install systemd Service

Create `/etc/systemd/system/reiven-direct.service`:

```ini
[Unit]
Description=Reiven direct file-transfer server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=reiven
Group=reiven
WorkingDirectory=/opt/reiven
Environment=NODE_ENV=production
Environment=HOST=127.0.0.1
Environment=PORT=8080
Environment=PUBLIC_BASE_URL=https://reiven.io
Environment=REIVEN_DATA_DIR=/srv/reiven
Environment=FILE_TTL_HOURS=24
Environment=MAX_FILE_SIZE_MB=10240
Environment=PART_SIZE_BYTES=52428800
ExecStart=/usr/bin/node /opt/reiven/direct-server/server.mjs
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/srv/reiven
CapabilityBoundingSet=
LockPersonality=true
RestrictRealtime=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now reiven-direct
sudo systemctl status reiven-direct --no-pager
```

### 5. Configure HTTPS Reverse Proxy

Caddy example for the apex domain:

```caddyfile
reiven.io {
  reverse_proxy 127.0.0.1:8080
}
```

If `www.reiven.io` is used, point DNS at the same server and redirect it to the apex domain:

```caddyfile
www.reiven.io {
  redir https://reiven.io{uri} permanent
}
```

Reload Caddy:

```bash
sudo caddy reload --config /etc/caddy/Caddyfile
```

### 6. DNS

- `reiven.io` should resolve to the server IPv4 address using an `A` record.
- `www.reiven.io` can be either a `CNAME` to `reiven.io` or an `A` record to the same server.
- The canonical URL is `https://reiven.io/`; `www` should redirect there.

### 7. Verify Production

```bash
curl -sSI https://reiven.io/
curl -fsSL https://reiven.io/api/encryption-config
curl -fsSL https://reiven.io/robots.txt
curl -fsSL https://reiven.io/sitemap.xml
curl -sSI https://reiven.io/download | grep -i x-robots-tag
```

## Updating Production

From a server clone:

```bash
cd /opt/reiven
sudo git fetch origin
sudo git reset --hard origin/main
sudo chown -R root:root /opt/reiven
sudo systemctl restart reiven-direct
sudo systemctl status reiven-direct --no-pager
```

From a local checkout:

```bash
rsync -az --delete \
  --exclude .git \
  --exclude node_modules \
  ./ root@SERVER:/opt/reiven/
ssh root@SERVER 'chown -R root:root /opt/reiven && systemctl restart reiven-direct'
```

Do not overwrite `/srv/reiven` during application deploys unless intentionally restoring or deleting stored encrypted payloads.

## Environment Variables

- `HOST` — bind host, default `127.0.0.1`.
- `PORT` — bind port, default `8080`.
- `PUBLIC_BASE_URL` — external origin used for generated links, for example `https://reiven.io`.
- `PUBLIC_DIR` — static asset directory override, default `public/`.
- `REIVEN_DATA_DIR` — storage directory, default `/srv/reiven`.
- `FILE_TTL_HOURS` — upload lifetime, default `24`.
- `MAX_FILE_SIZE_MB` — encrypted upload size limit, default `10240`.
- `PART_SIZE_BYTES` — server upload part size, default `52428800`.
- `UPLOAD_MAX_AGE_MS` — abandoned upload session lifetime, default `7200000`.

## API

### Upload

- `POST /api/upload/init`
  - JSON: `originalName`, `size`, `allowReceiverDelete`, `isNote`.
  - Returns: `uploadId`, `partSizeBytes`.
- `POST /api/upload/part?uploadId=<id>&partNumber=<n>`
  - Body: encrypted binary part.
  - Returns: `partNumber`, `etag`.
- `POST /api/upload/complete`
  - JSON: `uploadId`, `size`, `parts[]`.
  - Returns: `id`, `size`, `expiresAt`, `downloadUrl`, `deleteUrl`, `allowReceiverDelete`, `isNote`, `accessCode`.
- `POST /api/upload/abort`
  - JSON: `uploadId`.
  - Returns: `204 No Content`.

### Download And Metadata

- `GET /api/encryption-config` — returns shared crypto parameters.
- `GET /api/file/:id/info` — returns metadata needed by the download page.
- `GET /api/file/code/:code/info` — resolves an 8-digit access code.
- `GET /api/file/:id/download` — streams encrypted payload bytes, with range support.
- `DELETE /api/file/:id?token=<deleteToken>` — deletes an upload when the token matches.
- `GET /delete/:id/:token` — browser confirmation page for deletion.

## CLI

The CLI lives in `reiven-cli/`.

Install locally:

```bash
cd reiven-cli
npm install
npm link
```

Upload:

```bash
reiven put ./secret.pdf --base https://reiven.io
```

Download by code or file ID:

```bash
reiven get 12-34-56-78 --base https://reiven.io --out ./downloads
reiven get f8a91c2de --base https://reiven.io
```

The CLI uses the same shared encryption config as the web app.

## SEO

- `public/index.html` contains the title, description, canonical URL, Open Graph, Twitter, and `index, follow` metadata.
- `public/robots.txt` allows the homepage and advertises `https://reiven.io/sitemap.xml`.
- `public/sitemap.xml` lists the canonical homepage.
- `/download` sends both `noindex` page metadata and `X-Robots-Tag` because share URLs can contain sensitive identifiers.
- `/index.html` redirects to `/`; `/download.html` redirects to `/download`.

After DNS and HTTPS are live, add the domain in Google Search Console and submit:

```text
https://reiven.io/sitemap.xml
```

## Operational Runbook

Check service:

```bash
systemctl status reiven-direct --no-pager
```

View logs:

```bash
journalctl -u reiven-direct -n 200 --no-pager
journalctl -u reiven-direct -f
```

Restart:

```bash
systemctl restart reiven-direct
```

Inspect data directory:

```bash
find /srv/reiven -maxdepth 2 -type f -ls
```

Back up encrypted payloads and metadata only when retention is intended:

```bash
tar -C /srv -czf reiven-data-backup.tgz reiven
```

## Release Checklist

- Run JavaScript syntax checks.
- Run `npm audit --omit=dev`.
- Rebuild `public/vendor/` if dependency versions changed.
- Verify upload, download, access-code download, receiver delete, and QR Mode in a browser.
- Verify `robots.txt`, `sitemap.xml`, and `/download` `noindex`.
- Push `main`.
- Deploy to `/opt/reiven`.
- Restart `reiven-direct`.
- Check HTTPS headers and service logs.

## Legacy Cloudflare Path

The following files are legacy/reference material:

- `src/worker.js`
- `mem-server/`
- `migrations/`
- `wrangler.toml`
- `npm run dev`
- `npm run deploy`
- `npm run db:migrate`
- `npm run db:migrate:remote`

Do not use the Cloudflare path for current production deploys unless intentionally reviving that infrastructure.

## Safety Notes

- Do not log passwords, URL fragments, plaintext payloads, ciphertext contents, or delete tokens.
- Treat QR links as secrets because they include the decryption key in the fragment.
- Keep `/srv/reiven` writable only by the `reiven` service user.
- Keep `/opt/reiven` owned by `root` in production.
- Keep TLS termination, firewalling, OS patching, and host monitoring managed at the server layer.
- Never commit production data from `/srv/reiven`.
