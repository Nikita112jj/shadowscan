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
    throw "Rust toolchain is required. Install Rust stable and retry."
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

# The Rust helper remains an auditable source/test component. It is deliberately
# not copied into the Windows release: endpoint AV can mistake an unsigned
# standalone binary containing scanner logic for malware. The GUI has its own
# C# heuristic layer and treats the Rust helper as optional when present.
$rustManifest = Join-Path $repoRoot "rust_engine\Cargo.toml"
if (Test-Path $rustManifest) {
    Push-Location $repoRoot
    try {
        cargo check --release --locked --manifest-path $rustManifest
        if ($LASTEXITCODE -ne 0) {
            throw "Rust engine tests failed with exit code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }
    Write-Host "Rust engine source type-checked; standalone helper is not bundled."
}

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
Write-Host "No standalone Rust helper is bundled in the release artifact."
