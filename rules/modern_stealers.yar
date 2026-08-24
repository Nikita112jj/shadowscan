// ShadowScan defensive detections for current infostealer tradecraft.
//
// These rules intentionally use composite signals instead of single strings:
// Rust runtime artifacts alone are common in legitimate software, and browser
// paths alone are not malicious. Keep the rules static-only and test them with
// synthetic fixtures; never place live malware samples in this repository.

rule ShadowScan_Rust_Infostealer_Generic : stealer rust {
    meta:
        description = "Rust PE with browser credential collection and exfiltration signals"
        family = "generic-rust-infostealer"
        confidence = "medium"
        source = "ShadowScan defensive rule; Rust stealer tradecraft reported by Trellix and Elastic"
        mitre = "T1555.003,T1555.004,T1041"

    strings:
        $mz = "MZ"

        // Rust artifacts. One is insufficient because ordinary Rust binaries
        // frequently contain panic metadata and runtime strings.
        $rust_runtime_1 = "rust_eh_personality" ascii wide nocase
        $rust_runtime_2 = "core::panicking" ascii wide nocase
        $rust_runtime_3 = "panicking.rs" ascii wide nocase
        $rust_runtime_4 = "rustc_demangle" ascii wide nocase
        $rust_runtime_5 = ".rs:" ascii wide

        // Browser and password-store targets.
        $browser_1 = "Login Data" ascii wide nocase
        $browser_2 = "Local State" ascii wide nocase
        $browser_3 = "Cookies" ascii wide nocase
        $browser_4 = "key4.db" ascii wide nocase
        $browser_5 = "logins.json" ascii wide nocase
        $browser_6 = "Local Storage\\leveldb" ascii wide nocase
        $browser_7 = "password-store" ascii wide nocase

        // Collection, decryption, or exfiltration signals.
        $collection_1 = "CryptUnprotectData" ascii wide nocase
        $collection_2 = "--remote-debugging-port" ascii wide nocase
        $collection_3 = "webSocketDebuggerUrl" ascii wide nocase
        $collection_4 = "api.telegram.org" ascii wide nocase
        $collection_5 = "discord.com/api/webhooks" ascii wide nocase
        $collection_6 = "http://" ascii wide nocase
        $collection_7 = "Base64" ascii wide nocase

    condition:
        $mz at 0 and
        2 of ($rust_runtime_*) and
        2 of ($browser_*) and
        1 of ($collection_*)
}

rule ShadowScan_Myth_Rust_Infostealer : stealer rust myth {
    meta:
        description = "Rust Myth Stealer loader and browser-data collection profile"
        family = "Myth Stealer"
        confidence = "high"
        source = "Trellix Advanced Research Center, 2025"
        mitre = "T1555.003,T1555.004,T1113,T1027"

    strings:
        $mz = "MZ"
        $loader_1 = "native-windows-gui" ascii wide nocase
        $loader_2 = "native-dialog" ascii wide nocase
        $loader_3 = "include-crypt" ascii wide nocase
        $loader_4 = "memexec" ascii wide nocase
        $loader_5 = "obfstr" ascii wide nocase
        $loader_6 = "myth-key" ascii wide nocase
        $loader_7 = "/api/send" ascii wide nocase
        $loader_8 = "winlnk.exe" ascii wide nocase
        $loader_9 = ".lnkk" ascii wide nocase
        $browser_1 = "Login Data" ascii wide nocase
        $browser_2 = "Web Data" ascii wide nocase
        $browser_3 = "WalletWasabi" ascii wide nocase
        $browser_4 = "Telegram Desktop\\tdata" ascii wide nocase
        $browser_5 = "Discord" ascii wide nocase
        $capture_1 = "CryptUnprotectData" ascii wide nocase
        $capture_2 = "--remote-debugging-port" ascii wide nocase
        $capture_3 = "clipboard" ascii wide nocase
        $capture_4 = "screenshot" ascii wide nocase

    condition:
        $mz at 0 and
        3 of ($loader_*) and
        1 of ($browser_*) and
        1 of ($capture_*)
}

rule ShadowScan_Eddie_Rust_Infostealer : stealer rust eddie {
    meta:
        description = "EDDIESTEALER-style Rust browser collection and tasking profile"
        family = "EDDIESTEALER"
        confidence = "high"
        source = "Elastic Security Labs, 2025"
        mitre = "T1555.003,T1555.004,T1071.001,T1027"

    strings:
        $mz = "MZ"
        $source_1 = "chromium_hound.rs" ascii wide nocase
        $source_2 = "search_pattern.rs" ascii wide nocase
        $source_3 = "search_entry.rs" ascii wide nocase
        $source_4 = "additional_task.rs" ascii wide nocase
        $tasking_1 = "api/handler" ascii wide nocase
        $tasking_2 = "webSocketDebuggerUrl" ascii wide nocase
        $tasking_3 = "Target.createTarget" ascii wide nocase
        $tasking_4 = "self_delete" ascii wide nocase
        $tasking_5 = "WaitOnAddress" ascii wide nocase
        $browser_1 = "Login Data" ascii wide nocase
        $browser_2 = "Local State" ascii wide nocase
        $browser_3 = "CryptUnprotectData" ascii wide nocase
        $browser_4 = "--remote-debugging-port" ascii wide nocase
        $browser_5 = "key4.db" ascii wide nocase

    condition:
        $mz at 0 and
        2 of ($source_*) and
        2 of ($tasking_*) and
        2 of ($browser_*)
}

rule ShadowScan_ACR_Browser_Stealer_Chain : stealer delivery {
    meta:
        description = "Browser credential theft combined with ClickFix-style script delivery signals"
        family = "ACR Stealer / Amatera-style chain"
        confidence = "medium"
        source = "Microsoft Security Research, 2026"
        mitre = "T1059.001,T1218.005,T1555.003,T1105"

    strings:
        $script_1 = "mshta" ascii wide nocase
        $script_2 = "rundll32" ascii wide nocase
        $script_3 = "powershell" ascii wide nocase
        $script_4 = "Invoke-WebRequest" ascii wide nocase
        $script_5 = "WebDAV" ascii wide nocase
        $script_6 = "@ssl" ascii wide nocase
        $script_7 = "schtasks" ascii wide nocase
        $script_8 = "ConvertThreadToFiber" ascii wide nocase
        $script_9 = "VirtualAlloc" ascii wide nocase
        $credential_1 = "Login Data" ascii wide nocase
        $credential_2 = "Web Data" ascii wide nocase
        $credential_3 = "CryptUnprotectData" ascii wide nocase
        $credential_4 = "Local State" ascii wide nocase

    condition:
        3 of ($script_*) and 2 of ($credential_*)
}

rule ShadowScan_Rust_Credential_Collection : stealer rust {
    meta:
        description = "Rust PE combining credential-store access, staging, and outbound transport"
        family = "generic-rust-credential-collector"
        confidence = "low"
        source = "ShadowScan composite heuristic"
        mitre = "T1555,T1005,T1071.001"

    strings:
        $mz = "MZ"
        $rust_1 = "rust_eh_personality" ascii wide nocase
        $rust_2 = "core::result::unwrap_failed" ascii wide nocase
        $rust_3 = "alloc::" ascii wide nocase
        $store_1 = "Login Data" ascii wide nocase
        $store_2 = "Cookies" ascii wide nocase
        $store_3 = "key4.db" ascii wide nocase
        $store_4 = "wallet.dat" ascii wide nocase
        $store_5 = "Local Storage" ascii wide nocase
        $stage_1 = ".zip" ascii wide nocase
        $stage_2 = "Base64" ascii wide nocase
        $stage_3 = "webhook" ascii wide nocase
        $stage_4 = "api/send" ascii wide nocase
        $stage_5 = "POST" ascii wide nocase

    condition:
        $mz at 0 and
        2 of ($rust_*) and
        2 of ($store_*) and
        1 of ($stage_*)
}
