param(
    [Parameter(Mandatory)][ValidateSet('inspect', 'serve')][string]$Mode,
    [Parameter(Mandatory)][ValidatePattern('^cipher-vault-probe-[a-f0-9-]{36}$')][string]$PipeName,
    [Parameter(Mandatory)][ValidateRange(1, 2147483647)][int]$ExpectedPeer,
    [ValidateRange(1, 8)][int]$Count = 3
)
$ErrorActionPreference = 'Stop'
try {
    if (-not $IsWindows) { throw 'Windows required' }
    Add-Type -Path (Join-Path $PSScriptRoot 'local-endpoint-windows.cs')
    if ($Mode -eq 'inspect') { [LocalEndpointProbe]::Inspect($PipeName, $ExpectedPeer) | ConvertTo-Json -Depth 3 -Compress }
    else { [LocalEndpointProbe]::Serve($PipeName, $ExpectedPeer, $Count) }
} catch {
    $cause = $_.Exception.InnerException ?? $_.Exception
    [Console]::Error.WriteLine('LOCAL_ENDPOINT_PROBE_FAILED: ' + $cause.GetType().Name)
    exit 1
}
