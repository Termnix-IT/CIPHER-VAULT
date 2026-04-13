$ErrorActionPreference = "Stop"

$root = (Get-Location).Path
$releaseDir = Join-Path $root "release"

if (Test-Path $releaseDir) {
  Remove-Item -LiteralPath $releaseDir -Recurse -Force
}

New-Item -ItemType Directory -Path $releaseDir | Out-Null
New-Item -ItemType Directory -Path (Join-Path $releaseDir "data") | Out-Null

Copy-Item -LiteralPath (Join-Path $root "apps/api/dist") -Destination (Join-Path $releaseDir "dist") -Recurse
Copy-Item -LiteralPath (Join-Path $root "apps/web/dist") -Destination (Join-Path $releaseDir "web") -Recurse

$databasePath = Join-Path $root "apps/api/data/password-manager.db"
if (Test-Path $databasePath) {
  Copy-Item -LiteralPath $databasePath -Destination (Join-Path $releaseDir "data/password-manager.db")
}

$releasePackageJson = @'
{
  "name": "password-manager-release",
  "private": true,
  "type": "module",
  "scripts": {
    "start": "node dist/apps/api/src/server.js"
  },
  "dependencies": {
    "better-sqlite3": "^11.7.0"
  }
}
'@

Set-Content -LiteralPath (Join-Path $releaseDir "package.json") -Value $releasePackageJson -Encoding UTF8

$startBat = @'
@echo off
cd /d %~dp0
if not exist node_modules (
  echo Installing runtime dependencies...
  call npm install --omit=dev
  if errorlevel 1 exit /b 1
)
node dist/apps/api/src/server.js
'@

Set-Content -LiteralPath (Join-Path $releaseDir "start.bat") -Value $startBat -Encoding ASCII

$startPs1 = @'
Set-Location $PSScriptRoot
if (-not (Test-Path node_modules)) {
  Write-Host "Installing runtime dependencies..."
  npm install --omit=dev
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
node dist/apps/api/src/server.js
'@

Set-Content -LiteralPath (Join-Path $releaseDir "start.ps1") -Value $startPs1 -Encoding UTF8

$readme = @'
Password Manager Release

1. Node.js 20 以上をインストールしてください。
2. このフォルダで start.bat を実行してください。
3. 初回起動時は better-sqlite3 を自動インストールします。
4. ブラウザで http://localhost:3001 を開いてください。

data/password-manager.db に保管庫データが保存されます。
'@

Set-Content -LiteralPath (Join-Path $releaseDir "README.txt") -Value $readme -Encoding UTF8

Write-Host "Release package created at $releaseDir"
