# Vendored YARA-X

This directory contains the runtime and CLI source of **YARA-X v1.19.0** from the official VirusTotal repository.

- Upstream repository: https://github.com/VirusTotal/yara-x
- Release: `v1.19.0`
- Pinned source commit: `fe40349ea12c5ccb89aae9f304b979c4fb410f66`
- License: BSD-3-Clause; see [`LICENSE`](LICENSE)
- Upstream documentation: https://virustotal.github.io/yara-x/

The vendored tree intentionally keeps the crates required to build the `yara-x-cli` binary (`yr`) and omits upstream web assets, editor integrations, bindings, and test corpora. The source remains auditable and reproducible from the pinned upstream release.

Build the CLI and compile ShadowScan’s modern rules from the repository root with:

```powershell
.\scripts\build-yara-x.ps1
```

The generated `yr.exe` and `modern_stealers.yarx` are build artifacts and remain ignored by Git. ShadowScan can run the tracked source rule `rules/modern_stealers.yar` directly, so a generated compiled rules file is optional at runtime.

When updating YARA-X, fetch a tagged official release, verify its commit and license, replace this directory while preserving the vendor note, and run the full build and rule-validation checks before committing.

## Defensive rule references

The modern rules use documented behavior patterns rather than live samples or stolen data:

- YARA-X project and release provenance: https://github.com/VirusTotal/yara-x and https://virustotal.github.io/yara-x/
- YARA-X BSD-3-Clause license: https://github.com/VirusTotal/yara-x/blob/main/LICENSE
- Myth Stealer Rust loader, browser credential collection, clipboard/screenshot activity, and persistence: https://www.trellix.com/blogs/research/demystifying-myth-stealer-a-rust-based-infostealer/
- EDDIESTEALER Rust tasking, browser credential collection, dynamic API resolution, and self-delete behavior: https://www.elastic.co/security-labs/eddiestealer
- ACR/Amatera-style browser theft delivery chains, MSHTA/PowerShell/WebDAV, scheduled tasks, and in-memory execution: https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/
