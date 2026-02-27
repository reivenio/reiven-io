# Reiven Memory Server

RAM-only encrypted blob backend for Reiven.

## Endpoints

- `GET /health`
- `POST /api/upload/init`
- `POST /api/upload/part?uploadId=<id>&partNumber=<n>`
- `POST /api/upload/complete`
- `POST /api/upload/abort`
- `GET /api/file/:id/download`
- `DELETE /api/file/:id`

All `/api/*` routes require bearer auth when `MEM_BEARER_TOKEN` is set.

## Environment

- `PORT` (default `8788`)
- `MEM_ROOT` (default `/srv/reiven-mem`)
- `MEM_PART_SIZE_BYTES` (default `5242880`)
- `MEM_UPLOAD_MAX_AGE_MS` (default `7200000`)
- `MEM_CLEANUP_INTERVAL_MS` (default `60000`)
- `MEM_BEARER_TOKEN` (recommended)

## Run Locally

```bash
cd mem-server
npm install
MEM_ROOT=/tmp/reiven-mem MEM_BEARER_TOKEN=test-token npm start
```

## Hetzner Setup (systemd)

```bash
# on server
cd /opt/reiven-mem-api
npm ci --omit=dev --prefix mem-server

sudo mkdir -p /srv/reiven-mem
sudo chown deploy:deploy /srv/reiven-mem
sudo chmod 700 /srv/reiven-mem

sudo mkdir -p /etc/reiven-mem
sudo chmod 700 /etc/reiven-mem
sudo tee /etc/reiven-mem/env >/dev/null <<'ENV'
PORT=8788
MEM_ROOT=/srv/reiven-mem
MEM_BEARER_TOKEN=REPLACE_WITH_SAME_TOKEN_AS_CLOUDFLARE_SECRET
ENV
sudo chmod 600 /etc/reiven-mem/env
```

Create service:

```bash
sudo tee /etc/systemd/system/reiven-mem-api.service >/dev/null <<'UNIT'
[Unit]
Description=Reiven Memory Storage API
After=network.target

[Service]
User=deploy
Group=deploy
WorkingDirectory=/opt/reiven-mem-api/mem-server
EnvironmentFile=/etc/reiven-mem/env
ExecStart=/usr/bin/node /opt/reiven-mem-api/mem-server/server.mjs
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/srv/reiven-mem /opt/reiven-mem-api/mem-server

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now reiven-mem-api
sudo systemctl status reiven-mem-api --no-pager
```

## Update on Server

```bash
cd /opt/reiven-mem-api
git pull origin main
npm ci --omit=dev --prefix mem-server
sudo systemctl restart reiven-mem-api
sudo systemctl status reiven-mem-api --no-pager
```
