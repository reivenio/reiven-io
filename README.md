# Reiven.io

[Reiven.io](https://reiven.io/) — encrypted notes and files, with no accounts.

Reiven is a browser-first encrypted sharing service. Payloads are encrypted before upload, held by the server in process memory only, and lost on server restart, deploy, crash, or expiry.

## What Reiven Does

- Encrypts files in the browser or CLI before upload.
- Encrypts text notes as downloadable `note.txt` payloads.
- Generates 8-digit access codes such as `12-34-56-78`.
- Provides download links and optional receiver-side delete links.
- Expires uploaded ciphertext automatically based on server TTL.
- Supports QR Mode with a random browser-generated key embedded in the URL fragment.
- Serves static public information pages while excluding sharing tools and private/API routes from indexing.

## Security Model

Reiven protects payload contents client-side. The server should be treated as untrusted, ephemeral transport memory.

- Passwords and QR Mode random keys are generated or entered client-side and are not submitted to the server.
- File and note payloads are encrypted client-side before upload.
- Payload encryption uses AES-256-GCM with random 256-bit data encryption keys.
- Version 6 uses Argon2id, deterministic ML-KEM-768, HKDF-SHA-256 and AES-256-GCM key wrapping. Header parameters, metadata, record roles, total length and chunk positions are authenticated. See `CRYPTO-FORMAT.md` for the wire specification. Legacy v4/v5 files are rejected; re-encrypt originals with updated clients.
- Standard profile uses Argon2id `time=4`, `memory=64MB`, `parallelism=1`, `PIM=100`.
- Paranoid profile uses Argon2id `time=6`, `memory=128MB`, `parallelism=1`, `PIM=100`.
- Chunk payload encryption uses unique per-chunk AES-GCM nonces and requires authenticated stream completeness, including for empty files.
- The server stores ciphertext only in process memory, never in application-managed files.
- The server also keeps operational metadata in process memory: file ID, encrypted size, expiry, delete token, receiver-delete flag, note flag, access-code hash, download count, and upload filename.
- Bundled browser/CLI clients upload the placeholder `encrypted.bin`; actual filenames are authenticated inside the encrypted header. Custom API clients can expose their chosen upload name.
- Password strength remains critical; weak passwords can still be brute-forced offline from ciphertext.

For a strict memory-only deployment, disable swap and crash collection on the host. `LimitCORE=0` alone is insufficient when Linux pipes dumps to Apport or another collector. The app does not intentionally write ciphertext or metadata to disk, but operating systems can otherwise page memory or persist process dumps outside the app’s control.

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
    +-- public/ generated public pages and separate sharing tools
    +-- public/vendor/ vendored crypto and QR browser bundles
    +-- shared/encryption-config.mjs shared crypto constants
    +-- shared/site-pages.mjs public route allowlist and website schema
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
- Permanently redirects known `.html` aliases and trailing-slash page URLs to canonical routes.

Public pages are plain HTML and load without encryption initialization or JavaScript. `/share` opens file sharing; `/share#note` opens the note editor; `/receive` resolves an access code. `/download?id=...` and existing share URLs remain compatible. Legacy homepage fragments (`/#share`, `/#note`, `/#download`, `/#cli`) redirect to their corresponding routes.

The sharing workspace starts its crypto worker only when sharing is opened, and loads the QR bundle only when generating a QR result. Public pages, including the homepage, do not load either bundle. Private tools have a same-origin-only script/connect CSP; public pages additionally allow Google Analytics. Homepage JSON-LD is permitted using a CSP hash rather than unrestricted inline scripts.

The app still encrypts in chunks. Chunking keeps browser memory lower, supports progress updates, and allows range-based download/decryption for large files.

## Repository Layout

- `public/` — browser UI, download page, styles, crypto worker, SEO files.
- `public/vendor/` — committed browser bundles for Argon2, ML-KEM, and QR generation.
- `direct-server/` — standalone production Node.js server.
- `shared/encryption-config.mjs` — shared encryption parameters used by web and CLI.
- `shared/site-pages.mjs` — public routes and `WebSite` structured data.
- `scripts/build-pages.mjs` — dependency-free public-page content, templates, and sitemap generator.
- `direct-server/Caddyfile` — HTTPS apex configuration and permanent `www` redirect.
- `appliance/` — reproducible Ubuntu RAM-boot appliance build and release framework.
- `reiven-cli/` — terminal client for uploads and downloads.
- `reiven-ps/` — helper documentation and scripts for desktop integration work.

## Prerequisites

### Local Development

- Node.js 24 LTS (also used for production); use `npm ci` for reproducible dependency installation.
- `npm`.
- A modern browser with WebCrypto and Web Worker support.

### Production Server

- Linux server with SSH access.
- Node.js 24 LTS. The supplied service pins `/opt/node-v24.21.0-linux-x64/bin/node`; adapt this verified path for your host architecture/release.
- Caddy, nginx, or another HTTPS reverse proxy.
- A locked-down service user, normally `reiven`.
- Swap disabled if the deployment promise is that ciphertext never touches disk.
- Core dumps disabled for the service.

The direct server has no production npm package dependency at runtime. Browser vendor bundles are committed under `public/vendor/`; rebuild them locally or in CI when dependency versions change.

## RAM-Boot Appliance

The `appliance/` framework builds an Ubuntu 24.04 LTS hybrid ISO that loads its live filesystem into RAM. The image contains the reviewed Reiven source, Node runtime, Caddy, SSH, firewall policy and fail-closed runtime checks. It deliberately contains no private keys. HTTPS certificates, ACME state, SSH host keys, machine identity, logs, uploads and all writable system state are recreated in RAM after each cold boot.

The appliance refuses to start Caddy or Reiven unless the kernel command line includes `toram` and `nopersistence`, the root filesystem is an overlay, swap is absent, the crash handler is disabled and no writable block-backed filesystem is mounted. See `appliance/README.md` for build requirements, signed release artifacts, test procedure and deployment constraints.

Application/static changes can be copied into a running RAM instance, but every change must also be included in a newly tested image or it will disappear at reboot. Kernel and base-image security updates require building and booting a new image. The scheduled workflow detects this need by producing a fresh candidate and exact package manifest; it does not reboot production automatically.

## Local Development

Install dependencies:

```bash
npm install
```

Build vendored browser assets:

```bash
npm run vendor
```

After editing public-page content or routes, regenerate the committed HTML and sitemap:

```bash
npm run build:pages
```

Edit `scripts/build-pages.mjs` rather than generated public HTML. Update the generator's `updated` date when publishing substantive content changes. Tool pages (`public/share.html` and `public/download.html`) remain hand-authored. The social preview PNG is committed alongside its editable SVG source. No page build or dependency install is needed on a server deploying the committed assets.

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
rsync -az --delete public shared direct-server root@SERVER:/opt/reiven/
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
  /opt/node-v24.21.0-linux-x64/bin/node /opt/reiven/direct-server/server.mjs
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
Environment=TRUST_PROXY=1
Environment=FILE_TTL_HOURS=24
Environment=MAX_FILE_SIZE_MB=512
Environment=MAX_MEMORY_STORAGE_MB=2048
Environment=PART_SIZE_BYTES=52428800
ExecStart=/opt/node-v24.21.0-linux-x64/bin/node --max-old-space-size=256 /opt/reiven/direct-server/server.mjs
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
RestrictSUIDSGID=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LimitCORE=0
CoredumpFilter=0
MemorySwapMax=0
MemoryMax=3G
TasksMax=128
LimitNOFILE=4096
UMask=0077

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

Caddy configuration (also tracked in `direct-server/Caddyfile`):

```caddyfile
{
	log default {
		format filter {
			wrap json
			fields {
				request delete
				uri delete
			}
		}
	}
}

reiven.io {
	header Strict-Transport-Security "max-age=86400"
	encode zstd gzip
	reverse_proxy 127.0.0.1:8080
}

www.reiven.io {
	header Strict-Transport-Security "max-age=86400"
	redir https://reiven.io{uri} permanent
}
```

Point both hostnames at this server first. Install, validate, and reload Caddy:

```bash
sudo cp direct-server/Caddyfile /etc/caddy/Caddyfile
sudo caddy validate --config /etc/caddy/Caddyfile
sudo caddy reload --config /etc/caddy/Caddyfile
```

### 6. DNS

- `reiven.io` should resolve to the server IPv4 address using an `A` record.
- `www.reiven.io` can be either a `CNAME` to `reiven.io` or an `A` record to the same server.
- The canonical URL is `https://reiven.io/`; `www` should redirect there.

### 7. Verify Production

```bash
curl -sSI https://reiven.io/
curl -sSI https://www.reiven.io/security
curl -fsSL https://reiven.io/api/encryption-config
curl -fsSL https://reiven.io/robots.txt
curl -fsSL https://reiven.io/sitemap.xml
curl -sSI https://reiven.io/download | grep -i x-robots-tag
curl -sSI https://reiven.io/share | grep -i x-robots-tag
```

## Updating Production

Check `GET /health` before restarting. If `files` or `uploads` is nonzero, postpone the restart until those shares expire or arrange a maintenance window with explicit acceptance of their loss. Back up deployed source and proxy configuration for rollback; this does not back up RAM-held shares. Close the release window to new uploads operationally if an uninterrupted guarantee is required.

From a server clone:

```bash
cd /opt/reiven
sudo git pull --ff-only origin main
sudo chown -R root:root /opt/reiven
sudo systemctl restart reiven-direct
sudo systemctl status reiven-direct --no-pager
```

From a local checkout:

```bash
rsync -az --delete public shared direct-server root@SERVER:/opt/reiven/
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
- `UPLOAD_MAX_AGE_MS` — abandoned upload session lifetime, default `1800000` (30 minutes), with an additional fixed five-minute inactivity timeout.

## API

### Upload

- `POST /api/upload/init`
  - JSON: `formatVersion: 6`, `originalName`, positive integer `size`, `allowReceiverDelete`, `isNote`.
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

- Eleven static public pages cover the homepage, encrypted file sharing, notes, security, privacy, About, CLI, a guide index, and three practical guides.
- Every public page has a unique title/description, self-canonical HTTPS URL, social preview metadata, and crawlable internal links. The homepage adds `WebSite` JSON-LD.
- `public/sitemap.xml` includes only the public route allowlist in `shared/site-pages.mjs`.
- `public/robots.txt` permits crawling so crawlers can read exclusion headers; it advertises the sitemap. A robots policy is not an access-control mechanism.
- `/share`, `/receive`, `/download`, `/delete/*`, `/api/*`, and `/health` send `X-Robots-Tag: noindex, nofollow, noarchive`. Tool and delete HTML also include robots metadata. Private URLs never enter the sitemap or public navigation.
- Known `.html` page aliases and trailing slashes redirect with HTTP 308. Caddy redirects HTTPS `www` to the apex with HTTP 301, preserving path and query.

The domain is already verified in Google Search Console. Submit or refresh this sitemap and inspect the canonical homepage and key public pages after deployment:

```text
https://reiven.io/sitemap.xml
```

Track branded queries (`reiven`, `reiven.io`, `reiven encryption`) separately from product queries. Record impressions, clicks, CTR, average position, indexed pages, and mobile performance before comparing subsequent weeks. Indexing and ranking are Google's decisions, not guarantees provided by this implementation.

## Privacy And Analytics

Google Analytics (`G-MY4DKRSGEJ`) loads after page load/idle on public information pages only. Its initializer skips URLs with queries or fragments, sets a canonical page URL and empty referrer, and disables Google Signals and advertising-personalization signals. No custom upload-completion event is sent. Remote Google code remains third-party code where it loads.

Sharing, receiving, download, and delete pages do not load analytics or third-party scripts. QR passwords stay in URL fragments, not query strings. The app does not enable a routine successful-request/upload access log, but application, reverse-proxy, and operating-system errors may be logged to disk, with application errors limited to method/status and the supplied Caddy filter removing request/URI fields. Other system and hosting logs may still contain metadata. There is no application-enforced fixed retention period. RAM-only upload storage does not mean “no logs”; see the live [privacy information](https://reiven.io/privacy).

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
- Run `npm run build:pages` after content/template changes and commit generated outputs.
- Verify upload, download, access-code download, receiver delete, and QR Mode in a browser.
- Verify all sitemap URLs, internal links, canonicals, permanent redirects, `www` HTTPS, and private/API `noindex` headers.
- Check that public pages display immediately and private tools load no analytics.
- Push `main`.
- Deploy to `/opt/reiven`.
- Recheck `/health`; do not silently discard active shares.
- Restart `reiven-direct`.
- Check HTTPS headers and service logs.

## Safety Notes

- Do not log passwords, URL fragments, plaintext payloads, ciphertext contents, or delete tokens.
- Treat QR links as secrets because they include the decryption key in the fragment.
- Keep `/opt/reiven` owned by `root` in production.
- Keep swap disabled and core dumps blocked for strict memory-only operation.
- Keep TLS termination, firewalling, OS patching, and host monitoring managed at the server layer.

## Security Hardening And v6 Rollout

- New envelopes use the single implementation in `public/envelope.mjs`; see `CRYPTO-FORMAT.md`. Both clients require 32-character minimum passwords for new uploads; prefer generated secrets or QR Mode. Crack-time guesses are no longer shown. PIM is a password-input parameter, not a KDF cost multiplier.
- Receiver deletion remains enabled by default in the browser. Anyone with the link/code can obtain its delete capability without the password; this is stated in the UI.
- Upload admission: one active upload and 64 stored files per client network, at most min(per-file limit, one quarter of global storage) stored/reserved bytes per client, 32 sessions/1024 total records globally, and half of the global pool reserved for active uploads at most. Init limits are 10/minute per client and 120/minute globally. These are abuse mitigations, not DDoS immunity; shared NATs share quotas.
- Part readers are serialized per upload, bounded globally at eight, capped at 50 MiB per part and 120 seconds. Completion validates unique ordered parts, exact counts/sizes and the v6 envelope layout. The server does not possess keys to authenticate payloads.
- Client quota keys are process-salted IP hashes (IPv6 /64 groups), stored only in RAM with bounded/expired rate buckets. Set `TRUST_PROXY=1` only for a loopback reverse proxy that overwrites untrusted forwarded headers. The backend must not be publicly reachable.
- Install `direct-server/99-reiven-no-core.conf` under `/etc/sysctl.d/`, disable and mask Apport, and apply `sysctl --system`. The dedicated host must use `kernel.core_pattern=|/bin/false`; retain `LimitCORE=0` and `CoredumpFilter=0`. Verify with a disposable staging crash and again after reboot. Check hosting snapshot/diagnostic policy separately; no app can guarantee a provider never captures RAM.
- Install `direct-server/00-reiven-ssh.conf` under `/etc/ssh/sshd_config.d/` only after checking key-based administrative access. Run `sshd -t`, reload SSH, and verify a fresh key-based connection before closing the existing session.
- For manually coordinated maintenance, install `direct-server/99-reiven-no-reboot` under `/etc/apt/apt.conf.d/` to disable unattended automatic reboots. This does not prevent crashes, power loss, or operator reboots. Confirm encrypted-disk recovery access before any planned reboot; schedule kernel activation separately rather than leaving security updates deferred indefinitely.
- HSTS starts at one day without includeSubDomains/preload. Review all hostnames before increasing coverage. Caddy filters request/URI fields out of default error logging; successful-request access logging remains disabled.
- Before rollout, block new init requests at the proxy and check `/health`. Drain active shares/uploads or obtain explicit acceptance of their loss. Stage an allowlisted artifact directory, validate configuration, then switch while the service is stopped. A restart/reboot destroys all RAM shares. Never deploy private audit/SEO reports or local dependency trees.
- Do not silently restore the old vulnerable reader as a rollback. Keep a reviewed v6 release available; an unavailable service is safer than accepting unauthenticated legacy completeness.
- Independent cryptographic review and a broader penetration test are still outstanding. This remediation is not a security certification.
