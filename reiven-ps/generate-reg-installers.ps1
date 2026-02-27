[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$exePath = Join-Path $PSScriptRoot 'reiven.exe'
$exePath = [System.IO.Path]::GetFullPath($exePath)
if (-not (Test-Path -LiteralPath $exePath)) {
  throw "reiven.exe not found at: $exePath"
}

$exeEscaped = $exePath.Replace('\', '\\')

$installReg = @"
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Classes\*\shell\ReivenShare]
@="Share by Reiven"
"Icon"="$exeEscaped"

[HKEY_CURRENT_USER\Software\Classes\*\shell\ReivenShare\command]
@="\"$exeEscaped\" put \"%1\""

[HKEY_CURRENT_USER\Software\Classes\Directory\Background\shell\ReivenGet]
@="Get Reiven file here"
"Icon"="$exeEscaped"

[HKEY_CURRENT_USER\Software\Classes\Directory\Background\shell\ReivenGet\command]
@="cmd.exe /k cd /d \"%V\" && \"$exeEscaped\" get"
"@

$uninstallReg = @"
Windows Registry Editor Version 5.00

[-HKEY_CURRENT_USER\Software\Classes\*\shell\ReivenShare]

[-HKEY_CURRENT_USER\Software\Classes\Directory\Background\shell\ReivenGet]
"@

$installPath = Join-Path $PSScriptRoot 'install-context-menu.reg'
$uninstallPath = Join-Path $PSScriptRoot 'uninstall-context-menu.reg'

$installReg | Set-Content -LiteralPath $installPath -Encoding Unicode
$uninstallReg | Set-Content -LiteralPath $uninstallPath -Encoding Unicode

Write-Host "Generated: $installPath"
Write-Host "Generated: $uninstallPath"
