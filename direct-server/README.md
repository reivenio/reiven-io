# Reiven Direct Server

Standalone Reiven server with no Cloudflare Worker, R2, or D1 runtime dependency.

## Runtime

- Serves `../public`
- Implements the same `/api/*` contract as the Worker
- Stores encrypted blobs in `REIVEN_DATA_DIR/files`
- Stores metadata in `REIVEN_DATA_DIR/metadata.json`
- Keeps upload sessions in memory and cleans abandoned part files

The server stores ciphertext only. Browser/CLI crypto remains Argon2id + ML-KEM-768 wrapping + AES-256-GCM chunked v5.

## Environment

- `HOST` default `127.0.0.1`
- `PORT` default `8080`
- `PUBLIC_BASE_URL` optional external origin, e.g. `https://reiven.io`
- `REIVEN_DATA_DIR` default `/srv/reiven`
- `FILE_TTL_HOURS` default `24`
- `MAX_FILE_SIZE_MB` default `10240`
- `PART_SIZE_BYTES` default `52428800`
- `UPLOAD_MAX_AGE_MS` default `7200000`

## Local Run

```bash
npm run direct:dev
```

## Server Run

```bash
cd /opt/reiven
npm ci
HOST=127.0.0.1 PORT=8080 PUBLIC_BASE_URL=https://reiven.io REIVEN_DATA_DIR=/srv/reiven npm run direct:start
```
