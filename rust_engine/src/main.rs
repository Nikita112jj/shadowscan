// ShadowEngine — лёгкий эвристический движок на Rust для ShadowScan.
// Дружит с yara-x: берёт те же файлы, делает независимый быстрый анализ
// (энтропия, подозрительные строки, упаковка) и выводит JSON-скор 0..100.
// C#-обёртка использует скор, чтобы ПОДТВЕРЖДАТЬ или ОТКЛОНЯТЬ совпадения
// yara — слабые одиночные yara-хиты на чистом по эвристикам файле
// отклоняются (меньше ложных срабатываний).
//
// Сборка:  cargo build --release
// Использование:  shadow_engine.exe file1 file2 ...  ->  JSON в stdout

use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::process;

/// Опасные строки-маркеры (быстрый поиск по первым 4 МБ файла).
const MARKERS: &[&str] = &[
    "powershell -enc",
    "-WindowStyle Hidden",
    "DownloadString",
    "Invoke-Expression",
    "IEX(",
    "CreateRemoteThread",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "stratum+tcp",
    "mimikatz",
    "api.telegram.org",
    "discord.com/api/webhooks",
    "Login Data",
    "vssadmin delete shadows",
    "meterpreter",
    "msfvenom",
    "webhook",
    "shellcode",
    "CurrentVersion\\Run",
    "taskkill /f /im",
    "DisableAntiSpyware",
    "ConsentPromptBehaviorAdmin",
    "Winlogon",
    "wscript.exe",
    "LogonUI.exe",
    "takeown",
    "icacls",
];

// Rust runtime strings are not malicious by themselves. They become useful
// only when combined with credential-store and transport indicators.
const RUST_RUNTIME_MARKERS: &[&str] = &[
    "rust_eh_personality",
    "core::panicking",
    "core::result::unwrap_failed",
    "rustc_demangle",
    "panicking.rs",
    "panic_fmt",
    "alloc::",
];

const BROWSER_STORE_MARKERS: &[&str] = &[
    "Login Data",
    "Local State",
    "Cookies",
    "Web Data",
    "key4.db",
    "logins.json",
    "Local Storage\\leveldb",
    "password-store",
    "wallet.dat",
    "Telegram Desktop\\tdata",
];

const COLLECTION_TRANSPORT_MARKERS: &[&str] = &[
    "CryptUnprotectData",
    "webSocketDebuggerUrl",
    "Target.createTarget",
    "api.telegram.org",
    "discord.com/api/webhooks",
    "webhook",
    "api/handler",
    "Base64",
    "HTTP/1.1",
    "POST",
];

const MYTH_MARKERS: &[&str] = &[
    "native-windows-gui",
    "native-dialog",
    "include-crypt",
    "memexec",
    "obfstr",
    "myth-key",
    "winlnk.exe",
    ".lnkk",
];

const EDDIE_MARKERS: &[&str] = &[
    "chromium_hound.rs",
    "search_pattern.rs",
    "search_entry.rs",
    "additional_task.rs",
    "WaitOnAddress",
    "self_delete",
];

fn contains_marker(data: &[u8], marker: &str) -> bool {
    !marker.is_empty()
        && data
            .windows(marker.len())
            .any(|window| window.eq_ignore_ascii_case(marker.as_bytes()))
}

fn count_markers(data: &[u8], markers: &[&str]) -> usize {
    markers
        .iter()
        .filter(|marker| contains_marker(data, marker))
        .count()
}

// Composite profiles deliberately require multiple independent signal groups.
// This keeps ordinary Rust applications and browser utilities below the threat
// threshold while still catching stripped Rust infostealer builds.
fn rust_infostealer_profile(data: &[u8]) -> bool {
    count_markers(data, RUST_RUNTIME_MARKERS) >= 2
        && count_markers(data, BROWSER_STORE_MARKERS) >= 2
        && count_markers(data, COLLECTION_TRANSPORT_MARKERS) >= 1
}

fn myth_profile(data: &[u8]) -> bool {
    count_markers(data, MYTH_MARKERS) >= 3
        && count_markers(data, BROWSER_STORE_MARKERS) >= 1
        && (contains_marker(data, "CryptUnprotectData")
            || contains_marker(data, "clipboard")
            || contains_marker(data, "screenshot"))
}

fn eddie_profile(data: &[u8]) -> bool {
    count_markers(data, EDDIE_MARKERS) >= 2
        && count_markers(data, BROWSER_STORE_MARKERS) >= 2
        && count_markers(data, COLLECTION_TRANSPORT_MARKERS) >= 1
}

/// Энтропия Шеннона по байтам (первые 1 МБ).
fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data.iter().take(1 << 20) {
        counts[b as usize] += 1;
    }
    let total = data.len().min(1 << 20) as f64;
    let mut e = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / total;
            e -= p * p.log2();
        }
    }
    e
}

/// Читает файл (первые 4 МБ достаточно для строк/энтропии).
fn read_head(path: &str) -> io::Result<Vec<u8>> {
    let f = File::open(path)?;
    let mut buf = Vec::with_capacity(4 << 20);
    f.take(4 << 20).read_to_end(&mut buf)?;
    Ok(buf)
}

fn analyze(path: &str) -> String {
    let mut out = String::from("{\"file\":");
    out.push_str(&json_escape(path));
    out.push(',');

    let mut score: i32 = 0;
    let mut hits: Vec<&str> = Vec::new();

    match read_head(path) {
        Ok(data) => {
            // Энтропия: > 7.4 — вероятно упаковка/шифрование (+6)
            let e = entropy(&data);
            out.push_str(&format!("\"entropy\":{:.2},", e));
            if e > 7.4 {
                score += 6;
            }

            // Опасные строки: 2+ маркера — сильный сигнал
            for m in MARKERS {
                if data
                    .windows(m.len())
                    .any(|w| w.eq_ignore_ascii_case(m.as_bytes()))
                {
                    hits.push(m);
                    score += 8;
                    if hits.len() >= 4 {
                        break;
                    }
                }
            }

            // NOP-слайд (shellcode-маркер) в первых 4 МБ
            if data.windows(32).any(|w| w.iter().all(|&b| b == 0x90)) {
                hits.push("nop_slide");
                score += 6;
            }

            if rust_infostealer_profile(&data) {
                hits.push("rust_infostealer_profile");
                score += 18;
            }
            if myth_profile(&data) {
                hits.push("myth_rust_profile");
                score += 14;
            }
            if eddie_profile(&data) {
                hits.push("eddie_rust_profile");
                score += 14;
            }
        }
        Err(_) => {
            out.push_str("\"entropy\":0.0,");
        }
    }

    // Имя файла: двойное расширение (document.pdf.exe) — маскировка
    let lower = path.to_lowercase();
    let double_ext = [
        ".exe", ".scr", ".pif", ".bat", ".cmd", ".vbs", ".js", ".jar", ".ps1", ".hta", ".msi",
    ]
    .iter()
    .any(|e| {
        let stem = lower.trim_end_matches(e);
        stem.rsplit_once('.').is_some()
    });
    if double_ext {
        score += 5;
    }

    // Скор 0..100
    let score = score.min(100).max(0);

    out.push_str("\"score\":");
    out.push_str(&score.to_string());
    out.push_str(",\"hits\":[");
    for (i, h) in hits.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(h);
        out.push('"');
    }
    out.push_str("]}");
    out
}

/// Экранирование строки для JSON.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(parts: &[&str]) -> Vec<u8> {
        parts.join("\\n").into_bytes()
    }

    #[test]
    fn rust_profile_requires_composite_signals() {
        let data = fixture(&[
            "rust_eh_personality",
            "core::panicking",
            "Login Data",
            "Cookies",
            "CryptUnprotectData",
        ]);
        assert!(rust_infostealer_profile(&data));
        assert!(!rust_infostealer_profile(&fixture(&[
            "rust_eh_personality",
            "core::panicking",
        ])));
    }

    #[test]
    fn myth_profile_requires_loader_and_collection_signals() {
        let data = fixture(&[
            "native-windows-gui",
            "include-crypt",
            "memexec",
            "Login Data",
            "clipboard",
        ]);
        assert!(myth_profile(&data));
    }

    #[test]
    fn eddie_profile_accepts_tasking_and_browser_signals() {
        let data = fixture(&[
            "chromium_hound.rs",
            "search_pattern.rs",
            "Login Data",
            "Local State",
            "api/handler",
        ]);
        assert!(eddie_profile(&data));
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("shadow_engine: файлы не указаны");
        process::exit(1);
    }
    let mut out = String::from("[");
    for (i, path) in args.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&analyze(path));
    }
    out.push(']');
    println!("{}", out);
}
