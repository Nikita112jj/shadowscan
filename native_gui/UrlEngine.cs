// ShadowScan UrlEngine — движок анти-фишинга и веб-защиты: статический анализ
// URL-строк в файле (репутация доменов). Детектит: подделку брендов (paypa1.com,
// paypal-login.xyz, paypal.com.evil.ru), IP-адреса вместо домена, punycode (xn--),
// сокращатели ссылок, не-http схемы (file://, javascript:, data:), обфускацию
// символов (%00, %2e, user@host, обратный слэш), подозрительные TLD, длинные URL.
// Реализация — в partial-классе ScannerCore (нужны приватные Add/Truncate);
// класс UrlEngine — тонкая обёртка под вызов из ScanFile (ScannerCore.cs):
//     try { UrlEngine.ScanUrls(res, allText); } catch { }
// Техника: без regex по всему тексту — сначала IndexOf-циклы по префиксам схем
// (до 50 вхождений на схему), токен вырезается до пробела/кавычки/скобки (макс.
// 512), затем разбирается по частям (scheme/authority/path). Потокобезопасно:
// состояние — только static readonly, всё остальное — локальное.
using System;
using System.Collections.Generic;
using System.Text;

static partial class ScannerCore {

    // ---------- Базы (readonly — ничего мутабельного) ----------

    // Префиксы схем, по которым ищем кандидатов-URL.
    static readonly string[] URL_SCHEMES = { "http://", "https://", "file://", "ftp://", "javascript:", "data:" };

    // Бренды, на которые маскируются фишеры (якорь + мусор вокруг).
    static readonly string[] URL_BRANDS = {
        "paypal","ebay","amazon","google","facebook","microsoft","apple","instagram",
        "whatsapp","telegram","binance","coinbase","roblox","steam","netflix",
        "bank","vk","sber","alfa","tinkoff"
    };

    // Легальные TLD: хост, оканчивающийся на brand.<tld> (или brand.co/com.<tld> —
    // co.uk, com.cn), считается настоящим доменом бренда: paypal.com, sber.ru,
    // google.co.uk, apple.com.cn. Любой другой хвост за брендом — подделка.
    static readonly string[] LEGIT_TLDS = {
        "com","org","net","ru","de","fr","it","es","nl","pl","se","no","fi","dk",
        "ch","at","be","pt","gr","ie","is","lu","cz","sk","hu","ro","bg","hr","si",
        "rs","lt","lv","ee","ua","kz","by","ge","am","az","md","us","ca","mx","br",
        "ar","cl","jp","cn","kr","in","sg","my","th","vn","ph","id","tw","hk","au",
        "nz","tr","il","sa","ae","za","uk","me","cc","io"
    };

    // TLD, массово используемые фишерами/мошенниками.
    static readonly string[] SUS_TLDS = { "xyz","top","club","online","site","icu","buzz","click","zip","mov" };

    // Сервисы сокращения ссылок.
    static readonly string[] URL_SHORTENERS = { "bit.ly","goo.gl","t.co","tinyurl.com","cutt.ly","is.gd","rb.gy" };

    // Leet-варианты брендов (1-2 подмены символа): paypa1, r0blox, t1nk0ff,
    // faceb00k, b4nk. Вариант с подменой в хосте = гарантированная подделка
    // (в легитимном домене бренда цифр нет), проверка «настоящего домена» не нужна.
    static readonly (string Variant, string Brand, bool Leet)[] URL_BRAND_VARIANTS = BuildBrandVariants();

    static (string, string, bool)[] BuildBrandVariants() {
        var list = new List<(string, string, bool)>();
        foreach (var b in URL_BRANDS) {
            list.Add((b, b, false)); // канонический вариант — для проверки якоря
            var pos = new List<(int Idx, char Digit)>();
            for (int i = 0; i < b.Length; i++) {
                char d = LeetDigit(b[i]);
                if (d != 0) pos.Add((i, d));
            }
            for (int a = 0; a < pos.Count; a++) {
                var sb = new StringBuilder(b);
                sb[pos[a].Idx] = pos[a].Digit;
                list.Add((sb.ToString(), b, true));
                for (int c = a + 1; c < pos.Count; c++) {
                    var sb2 = new StringBuilder(b);
                    sb2[pos[a].Idx] = pos[a].Digit;
                    sb2[pos[c].Idx] = pos[c].Digit;
                    list.Add((sb2.ToString(), b, true));
                }
            }
        }
        return list.ToArray();
    }

    // Цифра-подмена для буквы (l/i→1, o→0, e→3, a→4, s→5, t→7, g→9, b→8, z→2).
    static char LeetDigit(char c) {
        switch (c) {
            case 'l': case 'i': return '1';
            case 'o': return '0';
            case 'e': return '3';
            case 'a': return '4';
            case 's': return '5';
            case 't': return '7';
            case 'g': return '9';
            case 'b': return '8';
            case 'z': return '2';
            default: return '\0';
        }
    }

    // ---------- Точка входа (вызывается из ScanFile для allText) ----------

    public static void ScanUrls(ScanResult res, string allText) {
        if (string.IsNullOrEmpty(allText) || allText.Length < 12) return;
        var seen = new HashSet<string>();   // обработанные токены
        var added = new HashSet<string>();  // дедупликация «правило|хост»
        int total = 0;
        foreach (var sch in URL_SCHEMES) {
            int pos = 0, hits = 0;
            while (hits < 50 && total < 200) {
                int i = allText.IndexOf(sch, pos, StringComparison.OrdinalIgnoreCase);
                if (i < 0) break;
                pos = i + sch.Length;
                hits++;
                if (!IsUrlStart(allText, i)) continue; // схема внутри слова/пути
                string tok = CutUrlToken(allText, i);
                if (tok.Length < 9) continue;          // голый "http://x" — мимо
                if (seen.Add(tok.ToLowerInvariant())) { total++; AnalyzeUrl(res, tok, added); }
            }
        }
    }

    // Схема должна начинаться на границе токена, а не внутри слова/пути
    // ("profile://", "metadata:" — не URL).
    static bool IsUrlStart(string text, int i) {
        if (i == 0) return true;
        char c = text[i - 1];
        return !(char.IsLetterOrDigit(c) || c == '_' || c == '.' || c == '/' || c == '\\' || c == '-');
    }

    // Вырезает URL-токен до пробела/кавычки/скобки (макс. 512) и убирает
    // хвостовую пунктуацию текста (запятая, точка в конце предложения и т.п.).
    static string CutUrlToken(string text, int start) {
        int n = Math.Min(start + 512, text.Length);
        int e = start;
        while (e < n) {
            char c = text[e];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '"' || c == '\'' || c == '`'
                || c == '<' || c == '>' || c == '(' || c == ')' || c == '[' || c == ']' || c == '{' || c == '}')
                break;
            e++;
        }
        string t = text.Substring(start, e - start);
        int end = t.Length;
        while (end > 0) {
            char c = t[end - 1];
            if (c == ',' || c == '.' || c == ';' || c == '!' || c == '?' || c == ':') end--;
            else break;
        }
        return end < t.Length ? t.Substring(0, end) : t;
    }

    // ---------- Разбор и проверки одного токена ----------

    static void AnalyzeUrl(ScanResult res, string url, HashSet<string> added) {
        string scheme = GetScheme(url);
        bool isWeb = scheme == "http" || scheme == "https";
        bool isFileFtp = scheme == "file" || scheme == "ftp";

        // 5. Не-http схемы (вес 5): file://, ftp://, javascript:, data:
        // data:image/* — ЛЕГИТИМНО (встроенные картинки, капчи) — не флагаем
        if (isFileFtp) {
            TryAdd(res, added, "url_scheme_" + scheme + "|", "network",
                "URL со схемой " + scheme + ":// — небезопасный протокол", 5, url);
        } else if (scheme == "javascript" || (scheme == "data" && !url.StartsWith("data:image/", System.StringComparison.OrdinalIgnoreCase))) {
            TryAdd(res, added, "url_scheme_" + scheme + "|", "network",
                "URL со схемой " + scheme + ": — инлайн-код/контент (фишинг)", 5, url);
            return; // код схем javascript/data дальше не разбираем
        }
        if (!isWeb && !isFileFtp) return;

        // authority: после scheme:// до первого '/', '?', '#'
        int p = scheme.Length + 3;
        int e = url.Length;
        for (int k = p; k < url.Length; k++) {
            char c = url[k];
            if (c == '/' || c == '?' || c == '#') { e = k; break; }
        }
        string auth = url.Substring(p, e - p);
        string rest = url.Substring(e); // путь + query (+ якорь)

        // 6. @ в authority — маскировка хоста (user@host, вес 6)
        int at = auth.IndexOf('@');
        string host = at >= 0 ? auth.Substring(at + 1) : auth;

        // порт (host:8080) — срезаем
        int pc = host.LastIndexOf(':');
        if (pc > 0) {
            bool digits = true;
            for (int k = pc + 1; k < host.Length; k++) if (!char.IsDigit(host[k])) { digits = false; break; }
            if (digits && pc + 1 < host.Length) host = host.Substring(0, pc);
        }

        host = host.ToLowerInvariant();
        if (host.Length == 0 || host[0] == '[') return; // пустой authority / IPv6

        if (at >= 0)
            TryAdd(res, added, "url_userinfo|" + host, "phishing",
                "маскировка хоста user@host в URL (" + host + ")", 6, url);

        string lrest = rest.ToLowerInvariant();
        string lurl = url.ToLowerInvariant();

        // 6. Обфускация символов (вес 6): %00, %2e, обратный слэш
        if (lurl.Contains("%00"))
            TryAdd(res, added, "url_nul|" + host, "network", "null-байт %00 в URL", 6, url);
        if (lurl.Contains("%2e"))
            TryAdd(res, added, "url_pctdot|" + host, "network", "обфускация точки %2e в URL", 6, url);
        if (isWeb && url.Contains('\\'))
        {
            // "\." — экранированная точка из regex легального кода (huggingface\.co) — не маскировка.
            // Маскировка — слэш в других позициях (http:\\evil.com)
            if (url.Replace("\\.", "").Contains('\\'))
                TryAdd(res, added, "url_backslash|" + host, "network", "обратный слэш в URL (маскировка)", 6, url);
        }

        // 2. Публичный IPv4 вместо домена (вес 7) — обычно C2/фишинг
        if (TryParseIPv4(host, out long ip) && IsPublicIPv4(ip))
            TryAdd(res, added, "url_ip|" + host, "network", "URL на IP-адрес " + host + " вместо домена", 7, url);

        // 3. Punycode/IDN (вес 6) — обход фильтров
        if (host.Contains("xn--"))
            TryAdd(res, added, "url_puny|" + host, "phishing", "Punycode-домен (xn--) — обход фильтров", 6, url);

        // 4. Сокращатели ссылок (вес 6 с login-путём, иначе 3)
        if (IsShortenerHost(host)) {
            bool login = lrest.Contains("/login") || lrest.Contains("/auth");
            TryAdd(res, added, "url_short|" + host, "network",
                "сокращатель ссылок " + host + (login ? " с login-путём (фишинг)" : ""),
                login ? 6 : 3, url);
        }

        // 1. Подделка бренда; если не сработало — 7. подозрительный TLD
        if (!CheckBrandSpoof(res, url, host, added))
            CheckSuspTld(res, url, host, added);

        // 8. Очень длинный URL (>300) с query-параметрами и login-путём (вес 4)
        if (url.Length > 300) {
            int q = lrest.IndexOf('?');
            if (q > 0 && (lrest.Substring(0, q).Contains("/login") || lrest.Substring(0, q).Contains("/auth")))
                TryAdd(res, added, "url_long|" + host, "network",
                    "очень длинный URL (>300 симв.) с параметрами и login-путём", 4, url);
        }
    }

    // Схема — всё до первого ':' при условии, что до него нет '/', '\\', '?', '#'.
    static string GetScheme(string url) {
        int c = url.IndexOf(':');
        if (c <= 0) return "";
        for (int i = 0; i < c; i++) {
            char ch = url[i];
            if (ch == '/' || ch == '\\' || ch == '?' || ch == '#') return "";
        }
        return url.Substring(0, c).ToLowerInvariant();
    }

    // Add с дедупликацией «правило|хост» — не спамим findings на десятках
    // одинаковых URL в файле (одно срабатывание на правило и хост).
    static void TryAdd(ScanResult res, HashSet<string> added, string key, string category, string detail, int weight, string src) {
        if (!added.Add(key)) return;
        Add(res, category, detail, weight, key.Substring(0, key.IndexOf('|')), Truncate(src, 120));
    }

    // ---------- Правило 1: подделка брендов ----------

    // Бренд-якорь + «мусор» вокруг (не родной домен бренда). Не срабатывает на:
    // paypal.com, www.paypal.com, sber.ru, google.co.uk, apple.com.cn (родной домен),
    // bankofamerica.com, steampowered.com, googleapis.com (буква сразу после бренда —
    // составное легитимное имя; компромисс: пропускает редкие подделки вида
    // evilpaypal.com / paypalcom.com — цена нулевых ложных срабатываний).
    static bool CheckBrandSpoof(ScanResult res, string url, string host, HashSet<string> added) {
        bool suspTld = IsSuspTld(host);
        foreach (var (v, b, leet) in URL_BRAND_VARIANTS) {
            if (!BrandAnchorHit(host, v)) continue;
            if (!leet && IsLegitBrandDomain(host, b)) continue; // настоящий домен бренда
            if (leet)
                TryAdd(res, added, "url_brand_leet|" + host, "phishing",
                    "фишинг: бренд «" + b + "» с подменой символов (l→1, o→0) в домене " + host, 10, url);
            else
                TryAdd(res, added, "url_brand|" + host, "phishing",
                    "фишинг: подделка бренда «" + b + "» в домене " + host, suspTld ? 10 : 8, url);
            return true;
        }
        return false;
    }

    // Бренд в начале DNS-лейбла (после точки/дефиса/начала хоста), после бренда
    // не буква, рядом «мусор» (дефис/цифра) либо в хосте есть точка
    // (paypal.com.evil.ru — якорь и мусор за брендом).
    static bool BrandAnchorHit(string h, string b) {
        bool hasDot = h.IndexOf('.') >= 0;
        int from = 0;
        while (from <= h.Length - b.Length) {
            int k = h.IndexOf(b, from, StringComparison.Ordinal);
            if (k < 0) return false;
            int after = k + b.Length;
            bool prevOk = k == 0 || h[k - 1] == '.' || h[k - 1] == '-';
            bool afterOk = after >= h.Length || !char.IsLetter(h[after]);
            bool junk = hasDot || (after < h.Length && (h[after] == '-' || char.IsDigit(h[after])));
            if (prevOk && afterOk && junk) return true;
            from = after;
        }
        return false;
    }

    // Легитимный домен бренда: <sub>.brand.<tld> или <sub>.brand.co/com.<tld>,
    // где tld — известный (paypal.com, sber.ru, google.co.uk, apple.com.cn).
    // Перед брендом — точка или начало хоста ("evilpaypal.com" — не легитимен).
    static bool IsLegitBrandDomain(string host, string b) {
        int d = host.LastIndexOf('.');
        if (d < 0 || d == host.Length - 1) return false;
        string tld = host.Substring(d + 1);
        string tail = b + "." + tld;
        int p;
        if (host.EndsWith(tail, StringComparison.Ordinal)) {
            p = host.Length - tail.Length;
        } else {
            // двухуровневый TLD: brand.co.uk / brand.com.cn — страновой, не "com.com"
            int d2 = host.LastIndexOf('.', d - 1);
            if (d2 < 0 || d2 == d - 1) return false;
            string mid = host.Substring(d2 + 1, d - d2 - 1);
            if (mid != "co" && mid != "com") return false;
            if (tld == "com" || tld == "co") return false;
            tail = b + "." + mid + "." + tld;
            if (!host.EndsWith(tail, StringComparison.Ordinal)) return false;
            p = host.Length - tail.Length;
        }
        if (p > 0 && host[p - 1] != '.') return false;
        return IsLegitTld(tld);
    }

    // ---------- Правило 7: подозрительные TLD ----------

    static bool IsSuspTld(string host) {
        int d = host.LastIndexOf('.');
        if (d < 0 || d == host.Length - 1) return false;
        string tld = host.Substring(d + 1);
        foreach (var t in SUS_TLDS) if (tld == t) return true;
        return false;
    }

    // Подозрительный TLD: с бренд-якорем — вес 10, без — 3. Вызывается только
    // если правило 1 не сработало (иначе двойное начисление за один домен).
    static void CheckSuspTld(ScanResult res, string url, string host, HashSet<string> added) {
        if (!IsSuspTld(host)) return;
        foreach (var b in URL_BRANDS) {
            if (BrandAnchorAny(host, b)) {
                TryAdd(res, added, "url_tld_brand|" + host, "phishing",
                    "бренд «" + b + "» на подозрительном TLD: " + host, 10, url);
                return;
            }
        }
        TryAdd(res, added, "url_tld|" + host, "network", "URL на подозрительном TLD: " + host, 3, url);
    }

    // Якорь бренда без требований «мусора» — для оценки TLD-доменов
    // (bankofamerica.xyz тоже считается бренд-сквоттингом).
    static bool BrandAnchorAny(string h, string b) {
        int from = 0;
        while (from <= h.Length - b.Length) {
            int k = h.IndexOf(b, from, StringComparison.Ordinal);
            if (k < 0) return false;
            if (k == 0 || h[k - 1] == '.' || h[k - 1] == '-') return true;
            from = k + b.Length;
        }
        return false;
    }

    static bool IsLegitTld(string tld) {
        foreach (var t in LEGIT_TLDS) if (t == tld) return true;
        return false;
    }

    // ---------- Правила 2/3/4: IP, punycode, сокращатели ----------

    // Разбор IPv4: ровно 4 октета, каждый 0..255, без букв.
    static bool TryParseIPv4(string h, out long ip) {
        ip = 0;
        if (h.Length < 7 || h.Length > 15) return false;
        int octets = 0, start = 0;
        for (int k = 0; k <= h.Length; k++) {
            if (k == h.Length || h[k] == '.') {
                if (k == start) return false; // пустой октет ("1..2")
                int v = 0;
                for (int j = start; j < k; j++) {
                    char c = h[j];
                    if (c < '0' || c > '9') return false;
                    v = v * 10 + (c - '0');
                    if (v > 255) return false;
                }
                ip = (ip << 8) | v;
                if (++octets > 4) return false;
                start = k + 1;
            }
        }
        return octets == 4;
    }

    // Публичный IP: исключаем частные/служебные диапазоны (роутеры, локальные
    // сети, loopback, link-local, CGNAT, multicast).
    static bool IsPublicIPv4(long ip) {
        int a = (int)((ip >> 24) & 0xFF), b = (int)((ip >> 16) & 0xFF);
        if (a == 0 || a == 127) return false;                 // any / loopback
        if (a == 10) return false;                            // 10.0.0.0/8
        if (a == 169 && b == 254) return false;               // link-local
        if (a == 192 && b == 168) return false;               // 192.168.0.0/16
        if (a == 172 && b >= 16 && b <= 31) return false;     // 172.16.0.0/12
        if (a == 100 && b >= 64 && b <= 127) return false;    // CGNAT
        if (a >= 224) return false;                           // multicast / резерв
        return true;
    }

    static bool IsShortenerHost(string host) {
        foreach (var s in URL_SHORTENERS)
            if (host == s || host.EndsWith("." + s, StringComparison.Ordinal)) return true;
        return false;
    }
}

// Тонкая обёртка под вызов из ScanFile (ScannerCore.cs):
//     try { UrlEngine.ScanUrls(res, allText); } catch { }
static class UrlEngine {
    public static void ScanUrls(ScanResult res, string allText) => ScannerCore.ScanUrls(res, allText);
}
