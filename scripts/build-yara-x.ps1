[CmdletBinding()]
param(
    [switch]$SkipRules
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\")).Path
$yaraRoot = Join-Path $repoRoot "third_party\yara-x"
$targetDir = Join-Path $yaraRoot "target\release"
$yrPath = Join-Path $targetDir "yr.exe"

if (-not (Test-Path (Join-Path $yaraRoot "Cargo.toml"))) {
    throw "Vendored YARA-X source is missing: $yaraRoot"
}

$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if ($null -eq $cargo) {
    throw "Rust toolchain is required. Install Rust stable with rustup and retry."
}

Push-Location $yaraRoot
try {
    cargo build --release --locked --package yara-x-cli
    if ($LASTEXITCODE -ne 0) {
        throw "YARA-X CLI build failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

if (-not (Test-Path $yrPath)) {
    throw "YARA-X CLI was not produced: $yrPath"
}

Copy-Item -LiteralPath $yrPath -Destination (Join-Path $repoRoot "yr.exe") -Force

$rustManifest = Join-Path $repoRoot "rust_engine\Cargo.toml"
$rustEnginePath = Join-Path $repoRoot "rust_engine\target\release\shadow_engine.exe"
if (-not (Test-Path $rustManifest)) {
    throw "Rust engine manifest is missing: $rustManifest"
}

Push-Location $repoRoot
try {
    cargo build --release --locked --manifest-path $rustManifest
    if ($LASTEXITCODE -ne 0) {
        throw "Shadow engine build failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

if (-not (Test-Path $rustEnginePath)) {
    throw "Shadow engine was not produced: $rustEnginePath"
}
Copy-Item -LiteralPath $rustEnginePath -Destination (Join-Path $repoRoot "shadow_engine.exe") -Force

if (-not $SkipRules) {
    $sourceRules = Join-Path $repoRoot "rules\modern_stealers.yar"
    $compiledRules = Join-Path $repoRoot "modern_stealers.yarx"
    if (-not (Test-Path $sourceRules)) {
        throw "Source rules are missing: $sourceRules"
    }

    Push-Location $repoRoot
    try {
        & (Join-Path $repoRoot "yr.exe") compile --output $compiledRules $sourceRules
        if ($LASTEXITCODE -ne 0) {
            throw "Modern YARA-X rule compilation failed with exit code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }

    Write-Host "Built and compiled: $compiledRules"
}

Write-Host "Built YARA-X CLI: $(Join-Path $repoRoot 'yr.exe')"
Write-Host "Built Shadow engine: $(Join-Path $repoRoot 'shadow_engine.exe')"
