# Reiven.io

Zero-knowledge encrypted notes and files. No accounts, no logs.

Reiven is a browser-first encrypted sharing service. Payloads are encrypted before upload, held by the server in process memory only, and lost on server restart, deploy, crash, or expiry.

## What Reiven Does

- Encrypts files in the browser or CLI before upload.
- Encrypts text notes as downloadable `note.txt` payloads.
- Generates 8-digit access codes such as `12-34-56-78`.
- Provides download links and optional receiver-side delete links.
- Expires uploaded ciphertext automatically based on server TTL.
- Supports QR Mode with a random browser-generated key embedded in the URL fragment.
- Serves an indexable public landing page while marking private download pages as `noindex`.

## Security Model

Reiven protects payload contents client-side. The server should be treated as untrusted, ephemeral transport memory.

- Passwords and QR Mode random keys are generated or entered client-side and are not submitted to the server.
- File and note payloads are encrypted client-side before upload.
- Payload encryption uses AES-256-GCM with random 256-bit data encryption keys.
- Password-derived wrapping uses Argon2id and deterministic ML-KEM-768 key wrapping.
- Standard profile uses Argon2id `time=4`, `memory=64MB`, `parallelism=1`, `PIM=100`.
- Paranoid profile uses Argon2id `time=6`, `memory=128MB`, `parallelism=1`, `PIM=100`.
- Chunk payload encryption uses unique per-chunk AES-GCM nonces.
- The server stores ciphertext only in process memory, never in application-managed files.
- The server also keeps operational metadata in process memory: file ID, encrypted size, expiry, delete token, receiver-delete flag, note flag, access-code hash, download count, and upload filename.
- If filenames are sensitive, rename files before sharing.
- Password strength remains critical; weak passwords can still be brute-forced offline from ciphertext.

For a strict “never touches disk” deployment, disable swap and core dumps on the host. The app does not intentionally write ciphertext or metadata to disk, but operating systems can otherwise page memory or persist process dumps outside the app’s control.

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
    +-- process memory: encrypted payloads
    +-- process memory: metadata, code hashes, delete tokens, upload sessions
```

## Server Responsibilities

- Serves the static web app from `public/`.
- Exposes upload, download, metadata, and delete endpoints.
- Receives encrypted upload parts and keeps them in process memory.
- Assembles completed uploads into memory-backed encrypted payload records.
- Cleans expired files and abandoned upload sessions from memory.
- Sends security headers including CSP, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- Redirects `/index.html` to `/` and `/download.html` to `/download`.

The app still encrypts in chunks. Chunking keeps browser memory lower, supports progress updates, and allows range-based download/decryption for large files.

## Repository Layout

- `public/` — browser UI, download page, styles, crypto worker, SEO files.
- `public/vendor/` — committed browser bundles for Argon2, ML-KEM, and QR generation.
- `direct-server/` — standalone production Node.js server.
- `shared/encryption-config.mjs` — shared encryption parameters used by web and CLI.
- `reiven-cli/` — terminal client for uploads and downloads.
- `reiven-ps/` — helper documentation and scripts for desktop integration work.

## Prerequisites

### Local Development

- Node.js 18 or newer.
- `npm`.
- A modern browser with WebCrypto and Web Worker support.

### Production Server

- Linux server with SSH access.
- Node.js 18 or newer at `/usr/bin/node`.
- Caddy, nginx, or another HTTPS reverse proxy.
- A locked-down service user, normally `reiven`.
- Swap disabled if the deployment promise is that ciphertext never touches disk.
- Core dumps disabled for the service.

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

### 1. Create User And Install Source

```bash
sudo useradd --system --home /opt/reiven --shell /usr/sbin/nologin reiven || true
sudo mkdir -p /opt/reiven
sudo chown -R root:root /opt/reiven
sudo chmod 755 /opt/reiven
```

Clone the repository:

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
ssh root@SERVER 'chown -R root:root /opt/reiven'
```

### 2. Disable Swap For Strict Memory-Only Operation

Check swap:

```bash
swapon --show
```

Disable active swap:

```bash
sudo swapoff -a
```

Remove or comment swap entries from `/etc/fstab` so swap stays disabled after reboot.

### 3. Run Manually For A Smoke Test

```bash
cd /opt/reiven
sudo -u reiven \
  HOST=127.0.0.1 \
  PORT=8080 \
  PUBLIC_BASE_URL=https://reiven.io \
  MAX_FILE_SIZE_MB=512 \
  MAX_MEMORY_STORAGE_MB=2048 \
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
Description=Reiven memory-only encrypted sharing server
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
Environment=FILE_TTL_HOURS=24
Environment=MAX_FILE_SIZE_MB=512
Environment=MAX_MEMORY_STORAGE_MB=2048
Environment=PART_SIZE_BYTES=52428800
ExecStart=/usr/bin/node /opt/reiven/direct-server/server.mjs
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
CapabilityBoundingSet=
LockPersonality=true
RestrictRealtime=true
SystemCallArchitectures=native
LimitCORE=0
MemorySwapMax=0
MemoryMax=3G

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

Because storage is memory-only, every restart, deploy, crash, or host reboot removes all pending uploads.

## Environment Variables

- `HOST` — bind host, default `127.0.0.1`.
- `PORT` — bind port, default `8080`.
- `PUBLIC_BASE_URL` — external origin used for generated links, for example `https://reiven.io`.
- `PUBLIC_DIR` — static asset directory override, default `public/`.
- `FILE_TTL_HOURS` — upload lifetime, default `24`.
- `MAX_FILE_SIZE_MB` — per-upload encrypted size limit, default `512`.
- `MAX_MEMORY_STORAGE_MB` — total in-memory storage reservation limit, default `2048`.
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

Check memory settings:

```bash
systemctl show reiven-direct -p MemoryMax -p MemorySwapMax -p LimitCORE
```

Check active uploads:

```bash
curl -fsSL http://127.0.0.1:8080/health
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

## Safety Notes

- Do not log passwords, URL fragments, plaintext payloads, ciphertext contents, or delete tokens.
- Treat QR links as secrets because they include the decryption key in the fragment.
- Keep `/opt/reiven` owned by `root` in production.
- Keep swap disabled and core dumps blocked for strict memory-only operation.
- Keep TLS termination, firewalling, OS patching, and host monitoring managed at the server layer.
