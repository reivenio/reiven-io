# reiven.exe Contract

Expected CLI invocation:

```text
reiven.exe <get|put> <target> --base <url> --pim <int> [--out <dir>] [--debug]
```

Required behavior:

- `get <code-or-id>`
  - On success print only: `Saved: <absolute-path>` (unless `--debug`)
  - On error print `Error: ...` and exit non-zero
- `put <file-path>`
  - On success print:
    - `Access code: *** XX-XX-XX-XX ***`
    - `Download URL: ...`
    - `Delete URL: ...`
    - `Expires at: ...`
  - On error print `Error: ...` and exit non-zero

Compatibility requirements:
- Same envelope format as web app (`shared/encryption-config.mjs`)
- Header-first password verification on `get`
- Multipart upload API flow (`/api/upload/init`, `/api/upload/part`, `/api/upload/complete`, `/api/upload/abort`)

Current implementation approach:
- Build helper from `reiven-cli/bin/reiven.mjs` into a Windows `.exe` (`reiven.exe`).
- End users run only `reiven.exe` + context-menu `.reg` installer (no Node.js installation required).
