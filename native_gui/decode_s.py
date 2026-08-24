# -*- coding: utf-8 -*-
# Декодирует S(new int[]{...}) обратно в строки, чтобы отредактировать правила,
# затем xor_strings.py закодирует их заново.
import io, re, sys

path = r"D:\колизион\antivirus\native_gui\ScannerCore.cs"
src = io.open(path, encoding='utf-8', newline='').read()

KEY = [0x13, 0x37, 0xA5, 0x5C]

def dec(m):
    try:
        vals = [int(x) for x in m.group(1).split(',')]
        s = ''.join(chr(v ^ KEY[i % 4]) for i, v in enumerate(vals))
        # re-escape для C#-исходника: \\ → \\\\, " → \", \n → \\n, \r → \\r, \t → \\t
        s = s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
        return '"' + s + '"'
    except Exception:
        return m.group(0)

# заменяем S(new int[]{...}) на "строка" (с кавычками)
new_src, n = re.subn(r'S\(new int\[\]\{([^}]*)\}\)', dec, src)
io.open(path, 'w', encoding='utf-8', newline='').write(new_src)
print("декодировано вызовов:", n)
