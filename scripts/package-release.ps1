$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$releaseDir = [IO.Path]::GetFullPath((Join-Path $root "release"))

foreach ($source in @("apps/api/dist", "apps/web/dist", "packages/shared/dist")) {
  if (-not (Test-Path -LiteralPath (Join-Path $root $source) -PathType Container)) {
    throw "Build output missing: $source. Run npm run build first."
  }
}

function Assert-ReleaseDataIsEmpty {
  if (Test-Path -LiteralPath $releaseDir) {
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
  }
}

Assert-ReleaseDataIsEmpty
$stagingParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar)
$stagingName = "cipher-vault-web-release-" + [Guid]::NewGuid().ToString("N")
$staging = Join-Path $stagingParent $stagingName
New-Item -ItemType Directory -Path $staging | Out-Null
try {
  $manifestScript = Join-Path $PSScriptRoot "web-release-manifest.mjs"
  node $manifestScript prepare $root $staging
  if ($LASTEXITCODE -ne 0) { throw "Failed to prepare release manifests." }
  Push-Location -LiteralPath $staging
  try {
    # Reuse audited resolutions without downloading metadata or executing install scripts.
    npm install --package-lock-only --ignore-scripts --offline --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) { throw "Failed to generate the locked runtime package." }
  } finally { Pop-Location }
  node $manifestScript verify $root $staging
  if ($LASTEXITCODE -ne 0) { throw "Release dependencies differ from the source lockfile." }

  New-Item -ItemType Directory -Path (Join-Path $staging "data") | Out-Null
  Copy-Item -LiteralPath (Join-Path $root "apps/api/dist") -Destination (Join-Path $staging "dist") -Recurse
  Copy-Item -LiteralPath (Join-Path $root "apps/web/dist") -Destination (Join-Path $staging "web") -Recurse
  Copy-Item -LiteralPath (Join-Path $root "packages/shared/dist") -Destination (Join-Path $staging "packages/shared/dist") -Recurse
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot "start-web-release.mjs") -Destination (Join-Path $staging "start.mjs")

  $startBat = @'
@echo off
cd /d "%~dp0"
node start.mjs
'@
  Set-Content -LiteralPath (Join-Path $staging "start.bat") -Value $startBat -Encoding ASCII

  $startPs1 = @'
Set-Location -LiteralPath $PSScriptRoot
node (Join-Path $PSScriptRoot "start.mjs")
exit $LASTEXITCODE
'@
  Set-Content -LiteralPath (Join-Path $staging "start.ps1") -Value $startPs1 -Encoding UTF8

  $readme = @'
Password Manager Release

1. Node.js 22 以上とnpmをインストールしてください。
2. このフォルダ全体を展開し、start.bat または start.ps1 を実行してください。
3. 初回起動時は同梱lockfileからランタイム依存を導入します。通信が必要です。
4. ブラウザで http://localhost:3001 を開いてください。

data/password-manager.db に保管庫データが保存されます。
導入失敗時は起動せず、次の実行で導入を再試行します。
package.json・package-lock.json・packages/shared は一緒に保持してください。
'@
  Set-Content -LiteralPath (Join-Path $staging "README.txt") -Value $readme -Encoding UTF8

  $resolvedStaging = (Resolve-Path -LiteralPath $staging).Path
  if ([IO.Path]::GetDirectoryName($resolvedStaging) -ne $stagingParent -or
      [IO.Path]::GetFileName($resolvedStaging) -ne $stagingName -or
      ((Get-Item -LiteralPath $staging).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw "Unsafe staging output path."
  }
  # Check again immediately before replacement, in case data appeared during preparation.
  Assert-ReleaseDataIsEmpty
  if (Test-Path -LiteralPath $releaseDir) { Remove-Item -LiteralPath $releaseDir -Recurse -Force }
  Move-Item -LiteralPath $resolvedStaging -Destination $releaseDir
  Write-Host "Release package created at $releaseDir"
} finally {
  if (Test-Path -LiteralPath $staging) {
    $resolvedStaging = (Resolve-Path -LiteralPath $staging).Path
    if ([IO.Path]::GetDirectoryName($resolvedStaging) -ne $stagingParent -or
        [IO.Path]::GetFileName($resolvedStaging) -ne $stagingName -or
        ((Get-Item -LiteralPath $staging).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw "Unsafe staging cleanup path."
    }
    Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
  }
}
