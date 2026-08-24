# -*- coding: utf-8 -*-
# Чинит декодированный ScannerCore.cs: приводит ВСЕ строковые литералы к валидному C#.
# - одиночный бэкслеш (из XOR-значения) -> \\
# - готовая пара \\ или \" (MRSMAJOR_RULES от кодера) -> как есть
# - кавычка внутри строки -> \"
# Закрывающая кавычка определяется по следующему символу: , ) } ] ; пробел/новая строка.
import io

path = r"D:\колизион\antivirus\native_gui\ScannerCore.cs"
src = io.open(path, encoding='utf-8', newline='').read()

CLOSERS = set(',)}];: \t\r\n')
out = []
i = 0
n = len(src)
fixed = 0
while i < n:
    c = src[i]
    if c == '"' and i > 0 and src[i - 1] == '@':
        # verbatim-строка @"...": бэкслеши литеральны, "" = экранированная кавычка — не трогаем
        j = i + 1
        while j < n:
            if src[j] == '"':
                if j + 1 < n and src[j + 1] == '"':
                    j += 2
                    continue
                break
            j += 1
        out.append(src[i:j + 1])  # @ уже добавлен отдельной веткой
        i = j + 1
        continue
    if c == '"':
        j = i + 1
        parts = []
        closed = False
        while j < n:
            if src[j] == '\\':
                nxt = src[j + 1] if j + 1 < n else ''
                if nxt == '\\':
                    parts.append('\\\\')
                    j += 2
                    continue
                if nxt == '"':
                    # пара \" — только если строка продолжается (не закрывающая кавычка)
                    nxt2 = src[j + 2] if j + 2 < n else ''
                    if nxt2 in CLOSERS or nxt2 == '':
                        parts.append('\\\\')  # литеральный бэкслеш + закрывающая кавычка дальше
                        fixed += 1
                        j += 1
                        continue
                    parts.append('\\"')
                    j += 2
                    continue
                parts.append('\\\\')
                fixed += 1
                j += 1
                continue
            if src[j] == '"':
                nxt2 = src[j + 1] if j + 1 < n else ''
                if nxt2 in CLOSERS or nxt2 == '':
                    closed = True
                    break
                parts.append('\\"')  # кавычка внутри строки
                fixed += 1
                j += 1
                continue
            parts.append(src[j])
            j += 1
        if not closed:
            out.append(src[i:])
            break
        out.append('"' + ''.join(parts) + '"')
        i = j + 1
    else:
        out.append(c)
        i += 1

io.open(path, 'w', encoding='utf-8', newline='').write(''.join(out))
print("исправлено литералов:", fixed)
