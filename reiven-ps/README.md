# Reiven Windows CLI (EXE)

Windows packaging for the Reiven CLI with no Node.js requirement on the end-user machine.

Main executable:
- `reiven-ps/reiven.exe`

## Prerequisites

- Windows 10/11 (x64)
- `reiven.exe` placed in `reiven-ps/`

### Building `reiven.exe` (for maintainers)

If you are preparing a Windows package from source:

```powershell
.\build-helper.ps1
```

This compiles `reiven-cli/bin/reiven.mjs` into a Windows executable at:
- `reiven-ps/reiven.exe`

## Usage

```bat
# Download by code/id
reiven.exe get 23-28-73-45
reiven.exe get cafed50947953609cf --out .\downloads

# Upload
reiven.exe put .\report.pdf
reiven.exe upload .\report.pdf --debug
```

Options:

- `--base https://reiven.io`
- `--pim 100`
- `--out <folder>` (get only)
- `--debug`

## Context Menu Installer (`.reg`)

Generate install/uninstall `.reg` files with absolute paths:

```powershell
.\generate-reg-installers.ps1
```

This creates:
- `install-context-menu.reg`
- `uninstall-context-menu.reg`

Import install file:

```powershell
reg import .\install-context-menu.reg
```

This adds:
- `Share by Reiven` on file right-click (`reiven.exe put "%1"`)
- `Get Reiven file here` on folder background right-click (`reiven.exe get` in that folder)

Remove entries:

```powershell
reg import .\uninstall-context-menu.reg
```
