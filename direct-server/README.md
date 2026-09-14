# Reiven Direct Server

`server.mjs` is the current production Reiven runtime. It serves the web app from `../public`, implements the API contract, and keeps encrypted payloads plus operational metadata in process memory only.

Read the root `README.md` for the full project architecture, deployment guide, systemd unit, Caddy config, API documentation, SEO notes, and operational runbook.

## Quick Run

```bash
HOST=127.0.0.1 \
PORT=8080 \
PUBLIC_BASE_URL=https://reiven.io \
MAX_FILE_SIZE_MB=512 \
MAX_MEMORY_STORAGE_MB=2048 \
node direct-server/server.mjs
```

## Runtime Environment

- `HOST` default `127.0.0.1`
- `PORT` default `8080`
- `PUBLIC_BASE_URL` optional external origin, for example `https://reiven.io`
- `PUBLIC_DIR` optional static asset directory override
- `FILE_TTL_HOURS` default `24`
- `MAX_FILE_SIZE_MB` default `512`
- `MAX_MEMORY_STORAGE_MB` default `2048`
- `PART_SIZE_BYTES` default `52428800`
- `UPLOAD_MAX_AGE_MS` default `7200000`
