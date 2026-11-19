<#
.SYNOPSIS
  Install (or upgrade) the openmail-mcp binary from a GitHub release on Windows.
.DESCRIPTION
  Env: OPENMAIL_REPO (owner/name), OPENMAIL_VERSION (tag, default latest),
       OPENMAIL_BASE_URL (override download dir), OPENMAIL_INSTALL_DIR
       (default %LOCALAPPDATA%\Programs\openmail).
  The SHA-256 of the archive is verified BEFORE extraction. Refuses to run elevated.
  -Upgrade keeps openmail-mcp.exe.bak; -Rollback restores it; -Uninstall removes the
  binary (config kept unless -Purge).
#>
[CmdletBinding()]
param(
  [switch]$Upgrade,
  [switch]$Rollback,
  [switch]$Uninstall,
  [switch]$Purge
)
$ErrorActionPreference = 'Stop'
$BinName = 'openmail-mcp.exe'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Refusing to run elevated; use a normal (non-Administrator) PowerShell.'
}

$installDir = if ($env:OPENMAIL_INSTALL_DIR) { $env:OPENMAIL_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\openmail' }
$dest = Join-Path $installDir $BinName

if ($Uninstall) {
  Remove-Item -Force -ErrorAction SilentlyContinue $dest, "$dest.bak", "$dest.new"
  $configDir = if ($env:OPENMAIL_CONFIG_DIR) { $env:OPENMAIL_CONFIG_DIR } else { Join-Path $env:APPDATA 'openmail' }
  if ($Purge) { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $configDir; Write-Host "Purged $configDir" }
  else { Write-Host "Kept configuration in $configDir (use -Purge to delete it)" }
  return
}

if ($Rollback) {
  if (-not (Test-Path "$dest.bak")) { throw "No backup at $dest.bak" }
  Move-Item -Force "$dest.bak" $dest
  Write-Host 'Rolled back to previous binary'
  return
}

if ($env:OPENMAIL_BASE_URL) {
  $base = $env:OPENMAIL_BASE_URL.TrimEnd('/')
} else {
  if (-not $env:OPENMAIL_REPO -or $env:OPENMAIL_REPO -notmatch '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$') {
    throw 'Set OPENMAIL_REPO=<owner>/<repo> (or OPENMAIL_BASE_URL)'
  }
  $version = if ($env:OPENMAIL_VERSION) { $env:OPENMAIL_VERSION } else { 'latest' }
  $base = if ($version -eq 'latest') { "https://github.com/$($env:OPENMAIL_REPO)/releases/latest/download" }
          else { "https://github.com/$($env:OPENMAIL_REPO)/releases/download/$version" }
}

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { 'x86_64' }
  'ARM64' { 'aarch64' }
  default { throw "Unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
}
$asset = "openmail-mcp-$arch-pc-windows-msvc.zip"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("openmail-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Invoke-WebRequest -Uri "$base/$asset" -OutFile (Join-Path $tmp $asset)
  Invoke-WebRequest -Uri "$base/SHA-256SUMS" -OutFile (Join-Path $tmp 'SHA-256SUMS')

  $line = Get-Content (Join-Path $tmp 'SHA-256SUMS') |
    Where-Object { ($_ -split '\s+', 2)[1] -replace '^\*', '' -eq $asset } | Select-Object -First 1
  if (-not $line) { throw "No checksum entry for $asset" }
  $expected = ($line -split '\s+')[0].ToLowerInvariant()
  $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $asset)).Hash.ToLowerInvariant()
  if ($expected -ne $actual) { throw "Checksum mismatch for $asset (expected $expected, got $actual); nothing was installed" }
  Write-Host 'Checksum OK'

  Expand-Archive -Path (Join-Path $tmp $asset) -DestinationPath (Join-Path $tmp 'x')
  $src = Get-ChildItem -Recurse -File (Join-Path $tmp 'x') -Filter $BinName | Select-Object -First 1
  if (-not $src) { throw "Archive does not contain $BinName" }

  New-Item -ItemType Directory -Force -Path $installDir | Out-Null
  if ($Upgrade -and (Test-Path $dest)) { Copy-Item -Force $dest "$dest.bak"; Write-Host "Backed up previous binary to $dest.bak" }
  Copy-Item -Force $src.FullName "$dest.new"
  Move-Item -Force "$dest.new" $dest
  Write-Host "Installed $dest"
} finally {
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $tmp
}
