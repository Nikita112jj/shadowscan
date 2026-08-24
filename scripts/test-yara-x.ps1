[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\")).Path
$yr = Join-Path $repoRoot "yr.exe"
$rules = Join-Path $repoRoot "rules\modern_stealers.yar"
$fixtures = Join-Path $repoRoot "tests\fixtures"
$tempRules = Join-Path ([System.IO.Path]::GetTempPath()) ("shadowscan-modern-" + [guid]::NewGuid().ToString("N") + ".yarx")
$tempList = Join-Path ([System.IO.Path]::GetTempPath()) ("shadowscan-fixtures-" + [guid]::NewGuid().ToString("N") + ".txt")

if (-not (Test-Path $yr)) { throw "yr.exe not found. Run .\scripts\build-yara-x.ps1 first." }
if (-not (Test-Path $rules)) { throw "Source rules not found: $rules" }

$fixtureNames = @(
    "rust_generic.bin",
    "rust_benign.bin",
    "myth_rust.bin",
    "eddie_rust.bin",
    "acr_chain.bin"
)
$fixtureNames | ForEach-Object { Join-Path $fixtures $_ } | Set-Content -LiteralPath $tempList -Encoding utf8

try {
    & $yr compile --output $tempRules $rules
    if ($LASTEXITCODE -ne 0) { throw "YARA-X rule compilation failed with exit code $LASTEXITCODE" }

    $lines = & $yr scan -o ndjson --scan-list $rules $tempList
    if ($LASTEXITCODE -ne 0) { throw "YARA-X fixture scan failed with exit code $LASTEXITCODE" }
    $results = @($lines | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })

    $expected = @{
        "rust_generic.bin" = "ShadowScan_Rust_Infostealer_Generic"
        "rust_benign.bin" = $null
        "myth_rust.bin" = "ShadowScan_Myth_Rust_Infostealer"
        "eddie_rust.bin" = "ShadowScan_Eddie_Rust_Infostealer"
        "acr_chain.bin" = "ShadowScan_ACR_Browser_Stealer_Chain"
    }

    foreach ($result in $results) {
        $name = Split-Path $result.path -Leaf
        $rulesFound = @($result.rules | ForEach-Object { $_.identifier })
        $wanted = $expected[$name]
        if ($null -eq $wanted) {
            if ($rulesFound.Count -ne 0) { throw "False positive in $name: $($rulesFound -join ', ')" }
        } elseif ($rulesFound -notcontains $wanted) {
            throw "Expected $wanted in $name, found: $($rulesFound -join ', ')"
        }
    }

    Write-Host "YARA-X modern stealer regression tests passed."
} finally {
    Remove-Item -LiteralPath $tempRules, $tempList -Force -ErrorAction SilentlyContinue
}
