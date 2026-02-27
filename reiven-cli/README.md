# reiven-cli

Command-line downloader/decrypter for the reiven.io ecosystem.

Encryption constants are shared with the web app from:
- `../shared/encryption-config.mjs`

## Install

```bash
cd reiven-cli
npm install
npm link
```

## Usage

```bash
reiven get 23287345
reiven put ./report.pdf
```

The command will:
- Prompt for password
- Show `*` while typing password
- Fetch encrypted header first (`Range: bytes=0-4095`) to validate password
- Show download progress in terminal
- Download full payload only after password validation
- Decrypt locally and save file in current directory

Upload command will:
- Prompt for password and confirmation
- Encrypt locally using the shared encryption profile
- Show upload progress in terminal
- Upload with multipart API (`/api/upload/init`, `/api/upload/part`, `/api/upload/complete`)
- Print access code, download URL, delete URL, and expiry

## Options

```bash
reiven get <code-or-id> --base https://reiven.io --out ./downloads --pim 100
reiven put <file-path> --base https://reiven.io --pim 100
reiven upload <file-path> --base https://reiven.io --pim 100
reiven put <file-path> --storage mem
reiven put <file-path> --mem
reiven put <file-path> --debug
```

Environment variable:
- `REIVEN_BASE_URL` (default: `https://reiven.io`)
