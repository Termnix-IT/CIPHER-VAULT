$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$releaseDir = Join-Path $root "release"

foreach ($source in @("apps/api/dist", "apps/web/dist")) {
  if (-not (Test-Path -LiteralPath (Join-Path $root $source) -PathType Container)) {
    throw "Build output missing: $source. Run npm run build first."
  }
}
if (Test-Path $releaseDir) {
  $resolvedRelease = (Resolve-Path -LiteralPath $releaseDir).Path
  if ($resolvedRelease -ne [IO.Path]::GetFullPath((Join-Path $root "release")) -or
      ((Get-Item -LiteralPath $releaseDir).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw "Unsafe release output path: $releaseDir"
  }
  $existingData = Join-Path $releaseDir "data"
  if (Test-Path -LiteralPath $existingData) {
    if (((Get-Item -LiteralPath $existingData).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        @(Get-ChildItem -LiteralPath $existingData -Force).Count -gt 0) {
      throw "Release data exists. Move the existing release folder to a safe location before packaging."
    }
  }
  Remove-Item -LiteralPath $releaseDir -Recurse -Force
}

New-Item -ItemType Directory -Path $releaseDir | Out-Null
New-Item -ItemType Directory -Path (Join-Path $releaseDir "data") | Out-Null

Copy-Item -LiteralPath (Join-Path $root "apps/api/dist") -Destination (Join-Path $releaseDir "dist") -Recurse
Copy-Item -LiteralPath (Join-Path $root "apps/web/dist") -Destination (Join-Path $releaseDir "web") -Recurse

$releasePackageJson = @'
{
  "name": "password-manager-release",
  "private": true,
  "type": "module",
  "scripts": {
    "start": "node dist/apps/api/src/server.js"
  },
  "dependencies": {
    "better-sqlite3": "^12.9.0"
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
