# reiven-cli

Command-line downloader/decrypter for the reiven.io ecosystem.

Encryption constants are shared with the web app from:
- `../shared/encryption-config.mjs`
- `../public/envelope.mjs` (shared authenticated v6 implementation)

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
reiven put <file-path> --debug
```

Environment variable:
- `REIVEN_BASE_URL` (default: `https://reiven.io`)

## Security And Compatibility

Use Node.js 24 LTS and install locked dependencies with `npm ci`. Keep the full repository layout when installing the CLI. New uploads require at least 32 password characters; use generated secrets. PIM is an input parameter, not an iteration multiplier. Browser PIM is fixed at 100.

Only v6 envelopes are accepted. Legacy v4/v5 ciphertext must be re-created from originals; there is no automatic downgrade. Recipients validate authenticated total length and every chunk before saving. Output creation is exclusive, with mode 0600 (subject to platform support), rather than overwriting an existing file. See the root `CRYPTO-FORMAT.md` for the protocol and its limitations.
