[CmdletBinding()]
param(
  [string]$Target = 'node20-win-x64'
)

$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$cliDir = Join-Path $repoRoot 'reiven-cli'
if (-not (Test-Path -LiteralPath $cliDir)) {
  throw "reiven-cli directory not found: $cliDir"
}

Push-Location $cliDir
try {
  npm install --save-dev pkg
  npx pkg .\bin\reiven.mjs --targets $Target --output ..\reiven-ps\reiven.exe
} finally {
  Pop-Location
}

Write-Host 'Built helper at reiven-ps/reiven.exe'
