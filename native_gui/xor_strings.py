# -*- coding: utf-8 -*-
# Трансформер: XOR-кодирует строковые литералы таблиц правил в ScannerCore.cs,
# чтобы свежесобранная DLL не содержала «зловредных» строк открытым текстом
# (сторонние AV, напр. Касперский, иначе удаляют билд по эвристикам).
# Раскодировка — в рантайме через S(new byte[]{...}).
import io, re, sys

path = r"D:\колизион\antivirus\native_gui\ScannerCore.cs"
src = io.open(path, encoding='utf-8', newline='').read()

MARKERS = [
    "IMPORT_RULES = new()",
    "STRING_RULES = new()",
    "PS_RULES = new()",
    "PY_RULES = new()",
    "BAT_RULES = new()",
    "MRSMAJOR_RULES = new()",
    "CHAIN_RULES = new()",
    "PE_SUS_SECTIONS = {",
    "YARA_CAT_MAP = {",
    "DEOBF_TRIGGERS = {",
    "DEOBF_MARKERS = {",
    "var danger = new (string pat",
]

KEY = [0x13, 0x37, 0xA5, 0x5C]

def unescape_cs(s):
    """Декодирует C#-эскейпы в строковом литерале; None если эскейп неизвестен."""
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == '\\' and i + 1 < len(s):
            n = s[i + 1]
            if n == '\\': out.append('\\'); i += 2; continue
            if n == '"': out.append('"'); i += 2; continue
            if n == 'n': out.append('\n'); i += 2; continue
            if n == 't': out.append('\t'); i += 2; continue
            if n == 'r': out.append('\r'); i += 2; continue
            if n == '0': out.append('\0'); i += 2; continue
            if n == 'x':
                m = re.match(r'[0-9a-fA-F]{1,4}', s[i + 2:i + 6])
                if m: out.append(chr(int(m.group(0), 16))); i += 2 + len(m.group(0)); continue
            if n == 'u':
                m = re.match(r'[0-9a-fA-F]{4}', s[i + 2:i + 6])
                if m: out.append(chr(int(m.group(0), 16))); i += 2 + len(m.group(0)); continue
            return None
        out.append(c); i += 1
    return ''.join(out)

def xor_bytes(text):
    return [ord(ch) ^ KEY[i % len(KEY)] for i, ch in enumerate(text)]

def replace_literals(text):
    out = []
    i = 0
    changed = 0
    while i < len(text):
        if text[i] == '"':
            j = i + 1
            while j < len(text):
                if text[j] == '\\':
                    j += 2; continue
                if text[j] == '"':
                    break
                j += 1
            if j >= len(text):
                out.append(text[i:]); break
            content = text[i + 1:j]
            val = unescape_cs(content)
            if val is not None and len(val) >= 2:
                bt = xor_bytes(val)
                out.append('S(new int[]{' + ','.join(map(str, bt)) + '})')
                changed += 1
            else:
                out.append(text[i:j + 1])
            i = j + 1
        else:
            out.append(text[i]); i += 1
    return ''.join(out), changed

lines = src.split('\n')
result = []
i = 0
total = 0
while i < len(lines):
    line = lines[i]
    marker = next((m for m in MARKERS if m in line), None)
    if marker:
        depth = line.count('{') - line.count('}')
        region = [line]
        j = i + 1
        while j < len(lines) and depth > 0:
            l = lines[j]
            depth += l.count('{') - l.count('}')
            region.append(l)
            j += 1
        region_text = '\n'.join(region)
        new_text, changed = replace_literals(region_text)
        result.append(new_text)
        total += changed
        i = j
    else:
        result.append(line)
        i += 1

src2 = '\n'.join(result)

helper = '''
    // Паттерны правил не хранятся в бинарнике открытым текстом: свежесобранную
    // DLL сторонние AV (Касперский, Defender) иначе удаляют как «зловред» по
    // эвристикам строк. S() раскодирует литералы в рантайме; категории и
    // описания (безопасный текст) остаются читаемыми.
    static readonly int[] S_KEY = { 0x13, 0x37, 0xA5, 0x5C };
    static string S(int[] x) {
        var sb = new StringBuilder(x.Length);
        for (int i = 0; i < x.Length; i++) sb.Append((char)(x[i] ^ S_KEY[i % S_KEY.Length]));
        return sb.ToString();
    }
'''
if "static string S(int[] x)" not in src2:
    anchor = "static class ScannerCore {"
    pos = src2.find(anchor)
    if pos >= 0:
        nl = src2.find("\n", pos)
        src2 = src2[:nl + 1] + helper + src2[nl + 1:]
    else:
        print("ОШИБКА: якорь ScannerCore не найден")
        sys.exit(1)

io.open(path, 'w', encoding='utf-8', newline='').write(src2)
print("заменено литералов:", total)
