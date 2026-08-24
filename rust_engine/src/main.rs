// ShadowEngine — лёгкий эвристический движок на Rust для ShadowScan.
// Безопасный вспомогательный анализатор файлов: считает энтропию и проверяет
// нейтральные структурные признаки PE. Семейные и malware-specific строки
// находятся только в прозрачных YARA/JSON правилах, а не в этом бинарнике.
// C# может использовать его как опциональный независимый второй скор.
//
// Сборка:  cargo build --release
// Использование:  shadow_engine.exe file1 file2 ...  ->  JSON в stdout

use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::process;

// Keep the helper binary focused on file structure. Malware-family strings
// live in the auditable YARA/JSON rule data, not in this executable. This avoids
// making a small defensive helper look like a malware specimen to endpoint AV.
fn looks_like_pe(data: &[u8]) -> bool {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return false;
    }
    let pe_offset = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    data.get(pe_offset..pe_offset.saturating_add(4)) == Some(b"PE\0\0")
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

            // PE-заголовок и высокая энтропия — независимые структурные сигналы.
            if looks_like_pe(&data) {
                hits.push("pe_structure");
                score += 2;
                if e > 7.4 {
                    hits.push("high_entropy_pe");
                    score += 6;
                }
            }

            // NOP-слайд в первых 4 МБ — нейтральный байтовый структурный сигнал.
            if data.windows(32).any(|w| w.iter().all(|&b| b == 0x90)) {
                hits.push("nop_slide");
                score += 6;
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
        hits.push("double_extension");
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

    fn pe_fixture() -> Vec<u8> {
        let mut data = vec![0u8; 0x90];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        data
    }

    #[test]
    fn recognizes_pe_structure_without_family_strings() {
        assert!(looks_like_pe(&pe_fixture()));
    }

    #[test]
    fn rejects_non_pe_data() {
        assert!(!looks_like_pe(b"ordinary text data"));
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
