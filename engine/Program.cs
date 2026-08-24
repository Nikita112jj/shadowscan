// ShadowScan engine — статический анализ файлов на вредоносные признаки.
// PE-структуры, энтропия, импорты, строки, обфускация скриптов, скоринг.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

class Finding { public string Severity; public string Category; public string Rule; public string Detail; }

class ScanResult {
    public string File; public long Size; public string Sha256; public string Type;
    public string Verdict; public int Score; public List<string> Categories = new();
    public List<Finding> Findings = new(); public long Ms;
    public string ThreatType;
}

class Rule {
    public string Category; public string Name; public int Weight;
    public string[] Patterns; public bool CaseInsensitive;
    // PeSafe=false — правило шумит на нативных PE (имена API вроде VirtualAlloc/
    // GetProcAddress встречаются в любом легитимном бинарнике): применяем только
    // к .NET (строки из метаданных) и скриптам, где совпадение осмысленно.
    public bool PeSafe;
    // MinHits — сколько разных паттернов должно совпасть (для шумных правил:
    // одиночный "PING " есть у python, но IRC-ботнет содержит NICK+PRIVMSG+JOIN).
    public int MinHits;
    public Rule(string c, string n, int w, string[] p, bool ci = true, bool peSafe = true, int minHits = 1) {
        Category = c; Name = n; Weight = w; Patterns = p; CaseInsensitive = ci; PeSafe = peSafe; MinHits = minHits;
    }
}

class Program {
    static readonly byte[] MZ = { 0x4D, 0x5A };
    static readonly string[] PE_SUS_SECTIONS = { "UPX0","UPX1","UPX2","UPX3",".UPX0",".UPX1",".UPX2",".UPX3",".UPX",
        ".vmp0",".vmp1",".vmp2",".vmp3",".aspack",".adata",".petite",".mpress1",".mpress2",".nsp0",".nsp1",
        ".nsp2",".nsp3",".packed",".kkrunchy",".themida",".enigma1",".enigma2",".armadillo",".safengine",
        ".molebox",".y0da",".winlicense",".ndata",".data1",".nspv",".pespin" };

    static readonly List<Rule> IMPORT_RULES = new() {
        // Веса снижены: RegSetValueEx/OpenProcess/GetProcAddress и т.п. — обычные API
        // в легитимных системных утилитах. Одиночное совпадение не должно давать malicious.
        new("injection","процесс-инъекция",6,new[]{"VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","NtCreateThreadEx","QueueUserAPC","NtUnmapViewOfSection","SetThreadContext","RtlCreateUserThread","NtQueueApcThread"}),
        new("keylogger","кейлоггер",6,new[]{"GetAsyncKeyState","GetKeyboardState","SetWindowsHookExW","SetWindowsHookExA"}),
        new("credential","доступ к учётным данным",6,new[]{"CryptUnprotectData","CredEnumerate","CredRead"}),
        new("persistence","автозапуск/реестр",5,new[]{"RegSetValueEx","RegCreateKeyEx","CreateService","StartServiceCtrlDispatcher","MoveFileEx"}),
        new("anti_debug","анти-отладка",4,new[]{"IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess","OutputDebugString"}),
        new("screenshot","скриншот/клипборд",3,new[]{"BitBlt","CreateCompatibleDC","GetForegroundWindow","OpenClipboard","GetClipboardData","SetClipboardData"}),
        new("network","сетевая активность",3,new[]{"WSAStartup","InternetOpenUrl","URLDownloadToFile","HttpSendRequest","WinHttpOpen","WNetAddConnection"}),
        new("process","работа с процессами",3,new[]{"OpenProcess","TerminateProcess","CreateToolhelp32Snapshot","Process32Next"}),
        new("evasion","скрытие окна",2,new[]{"ShowWindow","FindWindow","SW_HIDE"}),
        new("loader","загрузчик кода",3,new[]{"GetProcAddress","LoadLibrary","VirtualProtect","RtlMoveMemory"}),
    };

    static readonly List<Rule> STRING_RULES = new() {
        new("stealer","пути к данным браузеров (стилер)",10,new[]{"User Data","Login Data","Cookies","Web Data","Local Storage","\\Chrome\\","BraveSoftware","\\Edge\\","\\Opera Software\\","Autofill","CreditCards","Web Data"}),
        new("stealer","крипто-кошельки",8,new[]{"metamask","exodus","atomicwallet","ledger","wallet.dat","phantom","coinbase","binance"}),
        new("stealer","мессенджеры/токены",8,new[]{"discord","telegram","api.telegram.org","webhook","t.me/","steam","fortnite","riotgames","epicgames"}),
        new("c2","паттерны IRC-ботнета",8,new[]{"PRIVMSG","JOIN ","NICK ",":6667",":6697","PING ","identd"}, true, true, 2),
        new("c2","C2-индикаторы",8,new[]{"onion","pastebin.com","hastebin","ghostbin","raw.githubusercontent.com","gist.github.com","discord.com/api/webhooks","cdn.discordapp.com"}),
        new("downloader","крэдлы загрузки",8,new[]{"DownloadString","DownloadFile","Invoke-WebRequest","Invoke-Expression","IEX(","WebClient","URLDownloadToFile","bitsadmin","certutil -urlcache","mshta","wscript","cscript","Start-Process"}),
        new("evasion","обход sandbox/VM",6,new[]{"IsDebuggerPresent","AntiVM","vmware","vbox","VirtualBox","QEMU","sandboxie","GetTickCount","QueryPerformanceCounter","tasklist","wmic ","systeminfo"}, true, false),
        new("obfuscated","кодирование base64",5,new[]{"FromBase64String","Convert.FromBase64","b64decode","base64.b64","certutil -decode","ToBase64String"}),
        new("obfuscated","крипто-примитивы",3,new[]{"AES","Rijndael","TripleDES","RSACryptoServiceProvider","XOR","Salsa20","ChaCha"}, true, false, 2),
        new("rat","удалённое управление",8,new[]{"cmd.exe /c","/c ","powershell -enc","powershell -w hidden","-WindowStyle Hidden","Rundll32","regsvr32 /s","schtasks","CurrentVersion\\Run","RunOnce","Startup\\"}),
        new("wiper","деструктив/вандализм",12,new[]{"taskkill /f /im explorer","BootExecute","bcdedit /set {current} recoveryenabled no","bootstatuspolicy ignoreallfailures","powercfg -h off","shutdown /r /f /t 0","vssadmin delete shadows","0.0.0.0 microsoft.com","0.0.0.0 windowsupdate","format c: /q","del /f /s /q"}, true, true, 2),
        new("rat","shellcode-раннеры",8,new[]{"VirtualAlloc","CreateThread","GetProcAddress","msfvenom","meterpreter","CobaltStrike","Sliver","shellcode"}, true, false),
    };

    static readonly List<Rule> PS_RULES = new() {
        new("obfuscated","PS: IEX/Invoke-Expression",10,new[]{"IEX(","Invoke-Expression","iex $","[scriptblock]::create"}),
        new("obfuscated","PS: base64 -enc",10,new[]{"-enc","-EncodedCommand","FromBase64String","ToBase64String"}),
        new("obfuscated","PS: сборка строк из кодов",8,new[]{"[char]","[Convert]::ToChar","-join","[string]::Join"}),
        new("downloader","PS: download cradle",10,new[]{"DownloadString","DownloadFile","Invoke-WebRequest","Invoke-Expression (New-Object Net.WebClient)","System.Net.WebClient"}),
        new("rat","PS: P/Invoke и инъекция",10,new[]{"Add-Type","DllImport","GetProcAddress","VirtualAlloc","CopyMemory","Marshal"}, true, true, 2),
        new("rat","PS: mimikatz/пост-эксплойт",10,new[]{"mimikatz","Invoke-Mimikatz","sekurlsa","kerberos","lsass"}, true, true, 1),
        new("persistence","PS: автозапуск",8,new[]{"New-ScheduledTask","Register-ScheduledTask","CurrentVersion\\Run","RunOnce","WScript.Shell","Startup"}),
        new("evasion","PS: скрытность",5,new[]{"-WindowStyle Hidden","-w hidden","-ExecutionPolicy Bypass","-ep bypass","hidden"}),
        new("rat","PS: загрузчик через легитимные бинарники",6,new[]{"regsvr32","rundll32","mshta","certutil","bitsadmin"}),
    };

    static readonly List<Rule> PY_RULES = new() {
        // Внимание: это ML-код-френдли правила. Одиночные слова вроде "token"/"hidden"/
        // "persist"/"subprocess" НЕ детектятся: они встречаются в токенизаторах,
        // hidden_size, persistent=False и стандартной библиотеке.
        new("obfuscated","PY: base64/hex-обфускация",10,new[]{"b64decode","base64.b64","bytes.fromhex","fromhex(","unicode_escape","marshal.loads","pickle.loads","zlib.decompress","gzip.decompress"}, true, true, 2),
        new("obfuscated","PY: сборка строк chr/ord",8,new[]{"chr(0x","chr(9","chr(3","join(chr","[chr(","\\x","\\u00"}, true, true, 2),
        new("rat","PY: exec/eval-обфускация",10,new[]{"exec(compile(","exec(base64","eval(compile(","exec(__import__","marshal.loads(exec","lambda",":b64decode(exec"}, true, true, 2),
        new("stealer","PY: кража данных",8,new[]{"webhook","api.telegram.org","t.me/","discord.com/api","requests.post","Login Data","User Data","Local Storage","cookies.db","password-store","autofill","credit_cards"}, true, true, 1),
        new("network","PY: сеть/шелл",6,new[]{"socket.socket","s.connect((","reverse shell","os.system","ctypes.windll","powershell.exe","cmd.exe /c","shell=True"}, true, true, 2),
        new("persistence","PY: автозапуск",8,new[]{"CurrentVersion\\Run","HKEY_CURRENT_USER","schtasks /create","startup folder","winreg.CreateKey","winreg.SetValue","autorun","RunOnce"}, true, true, 1),
        new("wiper","PY: деструктив/вандализм",12,new[]{"taskkill /f /im explorer","BootExecute","bcdedit","recoveryenabled","bootstatuspolicy","powercfg -h off","shutdown /r /f","shutdown -r -f","vssadmin delete shadows","0.0.0.0 microsoft","0.0.0.0 windowsupdate","del /f /s /q","format c:"}, true, true, 2),
        new("evasion","PY: скрытность",4,new[]{"-WindowStyle Hidden","-w hidden","windowed","GetForegroundWindow","ShowWindow","SetWindowLong"}, true, true, 1),
    };

    static readonly List<Rule> BAT_RULES = new() {
        new("downloader","BAT: загрузка через certutil/bitsadmin",10,new[]{"certutil","bitsadmin","curl ","wget ","powershell","Invoke-WebRequest"}),
        new("rat","BAT: скрытый запуск",8,new[]{"-w hidden","-WindowStyle Hidden","start /min","@echo off"}, true, true, 2),
        new("persistence","BAT: автозапуск",8,new[]{"reg add","CurrentVersion\\Run","schtasks","startup"}),
    };

    // Встроенная база известных хэшей (SHA256). Расширяется внешним signatures.json рядом с движком.
    static readonly Dictionary<string, string[]> KNOWN_HASHES = new() {
        // EICAR test string
        ["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"] = new[]{"EICAR test file","high"},
    };

    static int Main(string[] args) {
        Console.InputEncoding = Encoding.UTF8;
        Console.OutputEncoding = Encoding.UTF8;
        LoadExternalSignatures();
        InitYara();
        var paths = new List<string>();
        if (args.Length > 0 && args[0] == "scan") paths.AddRange(args.Skip(1));
        else if (args.Length > 0) paths.AddRange(args);

        // Пути можно передать и через stdin (GUI шлёт большие пачки)
        if (paths.Count == 0 && Console.IsInputRedirected) {
            string line; while ((line = Console.ReadLine()) != null) { line = line.Trim(); if (line.Length > 0) paths.Add(line); }
        }
        if (paths.Count == 0) { Console.Error.WriteLine("usage: engine scan <file...>  |  engine (paths from stdin)"); return 1; }

        var results = new List<ScanResult>();
        foreach (var p in paths) {
            try { results.Add(ScanFile(p)); }
            catch (Exception ex) { results.Add(ErrorResult(p, ex.Message)); }
        }
        // Батч-yara: один процесс yr.exe на все файлы вместо одного на файл
        RunYaraBatch(results);
        var json = JsonSerializer.Serialize(results, new JsonSerializerOptions {
            IncludeFields = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        });
        Console.WriteLine(json);
        return 0;
    }

    static ScanResult ErrorResult(string file, string msg) => new() {
        File = file, Verdict = "error", Score = 0, Type = "unknown",
        Findings = new List<Finding> { new() { Severity = "medium", Category = "error", Rule = "io", Detail = msg } }
    };

    // Внешние сигнатуры из signatures.json: кэшируем один раз на процесс (пачки файлов)
    static Dictionary<string, string[]> _extHashCache;
    static List<Rule> _extRuleCache;
    static List<(string hex, int offset, string name, string category, string note)> _magicCache;
    static List<(string ext, string category, int weight, string note)> _extCache;
    static bool _sigLoaded;

    static void LoadExternalSignatures() {
        if (_sigLoaded) return;
        _sigLoaded = true;
        _extHashCache = new Dictionary<string, string[]>();
        _extRuleCache = new List<Rule>();
        _magicCache = new List<(string, int, string, string, string)>();
        _extCache = new List<(string, string, int, string)>();
        try {
            var ext = Path.Combine(AppContext.BaseDirectory, "signatures.json");
            if (!File.Exists(ext)) return;
            using var doc = JsonDocument.Parse(File.ReadAllText(ext));
            var root = doc.RootElement;
            if (root.TryGetProperty("hashes", out var h)) {
                foreach (var prop in h.EnumerateObject())
                    _extHashCache[prop.Name.ToLowerInvariant()] = new[] {
                        prop.Value.TryGetProperty("name", out var n2) ? n2.GetString() ?? "unknown" : "unknown",
                        prop.Value.TryGetProperty("severity", out var s2) ? s2.GetString() ?? "medium" : "medium"
                    };
            }
            if (root.TryGetProperty("string_rules", out var sr) && sr.ValueKind == JsonValueKind.Array) {
                foreach (var item in sr.EnumerateArray()) {
                    try {
                        var patterns = new List<string>();
                        foreach (var p in item.GetProperty("patterns").EnumerateArray()) patterns.Add(p.GetString() ?? "");
                        _extRuleCache.Add(new Rule(
                            item.TryGetProperty("category", out var c) ? c.GetString() ?? "unknown" : "unknown",
                            item.TryGetProperty("name", out var n) ? n.GetString() ?? "rule" : "rule",
                            item.TryGetProperty("weight", out var w) ? w.GetInt32() : 8,
                            patterns.ToArray(),
                            ci: !item.TryGetProperty("case_insensitive", out var ci) || ci.GetBoolean(),
                            peSafe: !item.TryGetProperty("pe_safe", out var ps) || ps.GetBoolean(),
                            minHits: item.TryGetProperty("min_hits", out var mh) ? mh.GetInt32() : 1
                        ));
                    } catch { /* пропускаем битые правила */ }
                }
            }
            if (root.TryGetProperty("magic", out var mg) && mg.ValueKind == JsonValueKind.Array) {
                foreach (var item in mg.EnumerateArray()) {
                    try {
                        _magicCache.Add((
                            item.GetProperty("hex").GetString() ?? "",
                            item.TryGetProperty("offset", out var o) ? o.GetInt32() : 0,
                            item.TryGetProperty("name", out var n) ? n.GetString() ?? "magic" : "magic",
                            item.TryGetProperty("category", out var c) ? c.GetString() ?? "format" : "format",
                            item.TryGetProperty("note", out var nt) ? nt.GetString() ?? "" : ""
                        ));
                    } catch { }
                }
            }
            if (root.TryGetProperty("extensions", out var ex) && ex.ValueKind == JsonValueKind.Array) {
                foreach (var item in ex.EnumerateArray()) {
                    try {
                        string sev = item.TryGetProperty("severity", out var s) ? s.GetString() ?? "medium" : "medium";
                        _extCache.Add((
                            (item.GetProperty("extension").GetString() ?? "").ToLowerInvariant(),
                            item.TryGetProperty("category", out var c) ? c.GetString() ?? "suspicious_ext" : "suspicious_ext",
                            sev == "high" ? 8 : sev == "medium" ? 5 : 2,
                            item.TryGetProperty("note", out var nt) ? nt.GetString() ?? "" : ""
                        ));
                    } catch { }
                }
            }
        } catch { /* внешние сигнатуры опциональны */ }
    }

    static void CheckMagic(ScanResult res, byte[] data) {
        foreach (var (hex, offset, name, category, note) in _magicCache) {
            if (hex.Length < 2 || offset < 0 || offset + hex.Length / 2 > data.Length) continue;
            bool match = true;
            for (int i = 0; i < hex.Length; i += 2) {
                byte b = Convert.ToByte(hex.Substring(i, 2), 16);
                if (data[offset + i / 2] != b) { match = false; break; }
            }
            if (match && res.Type != "pe" && res.Type != "zip") {
                // уже известные форматы не дублируем; новый тип — уточняем
                if (hex.StartsWith("4D5A")) res.Type = "pe";
                else if (hex.StartsWith("504B")) res.Type = "zip";
            }
        }
    }

    // Внешний движок yara-x (BSD-3-Clause): yr.exe + rules.yarx рядом с engine.exe
    static bool _yaraReady;
    static string _yaraExe, _yaraRules;

    static void InitYara() {
        if (_yaraReady) return;
        _yaraReady = true;
        // ищем в подпапке engine_ext или в корне (PyInstaller)
        string[] candidates = {
            Path.Combine(AppContext.BaseDirectory, "engine_ext"),
            AppContext.BaseDirectory,
        };
        foreach (var dir in candidates) {
            string exe = Path.Combine(dir, "yr.exe");
            string rules = Path.Combine(dir, "rules.yarx");
            if (File.Exists(exe) && File.Exists(rules)) { _yaraExe = exe; _yaraRules = rules; return; }
        }
        _yaraExe = null; _yaraRules = null;
    }

    // Маппинг имени yara-правила -> категория угрозы (по семейству в имени)
    static readonly (string sub, string cat)[] YARA_CAT_MAP = {
        ("redline", "stealer"), ("lumma", "stealer"), ("vidar", "stealer"), ("stealc", "stealer"),
        ("whitesnake", "stealer"), ("raccoon", "stealer"), ("stealer", "stealer"), ("infostealer", "stealer"),
        ("grabber", "stealer"), ("acorn", "stealer"), ("meduza", "stealer"), ("meta", "stealer"),
        ("asyncrat", "rat"), ("dcrat", "rat"), ("njrat", "rat"), ("quasar", "rat"), ("rat", "rat"),
        ("remcos", "rat"), ("darkcomet", "rat"), ("xworm", "rat"), ("venom", "rat"), ("lime", "rat"),
        ("cobaltstrike", "c2"), ("sliver", "c2"), ("havoc", "c2"), ("beacon", "c2"), ("c2", "c2"),
        ("xmrig", "miner"), ("miner", "miner"), ("mining", "miner"), ("coinhive", "miner"),
        ("lockbit", "ransomware"), ("blackcat", "ransomware"), ("alphv", "ransomware"), ("akira", "ransomware"),
        ("ransom", "ransomware"), ("wannacry", "ransomware"), ("petya", "wiper"), ("notpetya", "wiper"),
        ("wiper", "wiper"), ("shamoon", "wiper"),
        ("mirai", "botnet"), ("botnet", "botnet"), ("gafgyt", "botnet"),
        ("keylog", "keylogger"),
    };

    // Батч-yara: один процесс yr.exe на все файлы пачки (--scan-list).
    // Раньше yr.exe спавнился на каждый файл (~0.4-1.5 с) — пачка 100 файлов
    // обходилась в 40-150 с только на yara-фазе. Теперь один запуск на пачку.
    static void RunYaraBatch(List<ScanResult> results) {
        if (_yaraExe == null || _yaraRules == null) return;
        // отбираем файлы, которые стоит проверить (исполняемые/скрипты/данные)
        var targets = new List<ScanResult>();
        foreach (var r in results) {
            string t = r.Type ?? "";
            if (t.StartsWith("pe") || t == "script" || t == "elf" || t == "ole" || t == "data")
                if (r.Verdict != "error") targets.Add(r);
        }
        if (targets.Count == 0) return;

        string listFile = null;
        try {
            listFile = Path.Combine(Path.GetTempPath(), "shadowscan_yara_" + Guid.NewGuid().ToString("N") + ".txt");
            var sb = new StringBuilder();
            foreach (var r in targets) sb.AppendLine(r.File.Replace('/', '\\'));
            File.WriteAllText(listFile, sb.ToString(), new UTF8Encoding(false));

            var psi = new System.Diagnostics.ProcessStartInfo {
                FileName = _yaraExe,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
            };
            psi.ArgumentList.Add("scan");
            psi.ArgumentList.Add("--compiled-rules");
            psi.ArgumentList.Add("-o");
            psi.ArgumentList.Add("ndjson");
            psi.ArgumentList.Add("--scan-list");
            psi.ArgumentList.Add(_yaraRules);
            psi.ArgumentList.Add(listFile);
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return;
            string stdout = proc.StandardOutput.ReadToEnd();
            string stderr = proc.StandardError.ReadToEnd();
            if (!proc.WaitForExit(60_000)) { try { proc.Kill(); } catch { } return; }
            if (proc.ExitCode != 0 || string.IsNullOrWhiteSpace(stdout)) return;

            // маппинг вывода (путь C:/...) -> ScanResult
            var byPath = new Dictionary<string, ScanResult>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in targets) byPath[Path.GetFullPath(r.File)] = r;
            foreach (var line in stdout.Split('\n')) {
                if (string.IsNullOrWhiteSpace(line) || !line.Contains("\"rules\"")) continue;
                try {
                    using var doc = JsonDocument.Parse(line);
                    var root = doc.RootElement;
                    string p = root.TryGetProperty("path", out var pp) ? pp.GetString() : null;
                    if (p == null || !byPath.TryGetValue(Path.GetFullPath(p.Replace('/', '\\')), out var res)) continue;
                    if (!root.TryGetProperty("rules", out var rulesArr) || rulesArr.ValueKind != JsonValueKind.Array) continue;
                    foreach (var r in rulesArr.EnumerateArray()) {
                        string id = r.TryGetProperty("identifier", out var idp) ? idp.GetString() ?? "yara" : "yara";
                        string cat = "yara";
                        string lowerId = id.ToLowerInvariant();
                        foreach (var (sub, c) in YARA_CAT_MAP)
                            if (lowerId.Contains(sub)) { cat = c; break; }
                        Add(res, cat, "YARA: " + id, 8, "yara_" + Truncate(id, 30), id);
                    }
                } catch { /* пропускаем битые строки вывода */ }
            }
            // повторная финализация: yara могла добавить категории
            foreach (var r in targets) Finalize(r, r.File);
        } catch { /* yara-x опционален */ }
        finally {
            if (listFile != null) { try { File.Delete(listFile); } catch { } }
        }
    }

    static ScanResult ScanFile(string path) {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var fi = new FileInfo(path);
        var res = new ScanResult { File = path, Size = fi.Length, Verdict = "clean", Score = 0, Type = "unknown" };

        // Самоисключение: не сканируем собственный процесс (NativeAOT-бинарник
        // этого движка имеет высокую энтропию — это норма, а не упаковка)
        try {
            string self = Environment.ProcessPath;
            if (self != null && string.Equals(Path.GetFullPath(self), Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase)) {
                res.Type = "pe"; res.ThreatType = "Чисто";
                res.Findings.Add(new Finding { Severity = "info", Category = "format", Rule = "self",
                    Detail = "собственный процесс ShadowScan — пропущен" });
                return res;
            }
        } catch { }

        // Анализ: до 64 МБ основного буфера + хвост 1 МБ для больших файлов
        // (overlay-данные, строки и сигнатуры в конце). SHA-256 — стримингом по
        // всему файлу (инкрементально, ~1 ГБ/с): хэш всегда соответствует файлу
        // и работает с базой известных хэшей.
        const long MAIN_CAP = 64L * 1024 * 1024;
        const long TAIL_CAP = 1L * 1024 * 1024;
        byte[] data;
        bool truncated = fi.Length > MAIN_CAP + TAIL_CAP;
        using (var fs = File.OpenRead(path)) {
            using (var sha = SHA256.Create()) {
                long readLen = Math.Min(fi.Length, MAIN_CAP);
                data = new byte[readLen];
                int off = 0;
                // хэшируем весь файл чанками, попутно заполняя анализируемый буфер
                var chunk = new byte[1024 * 1024];
                long pos = 0;
                while (pos < fi.Length) {
                    int want = (int)Math.Min(chunk.Length, fi.Length - pos);
                    int got = fs.Read(chunk, 0, want);
                    if (got <= 0) break;
                    sha.TransformBlock(chunk, 0, got, null, 0);
                    // заполняем data только из первых MAIN_CAP байт
                    if (pos < readLen) {
                        int copy = (int)Math.Min(got, readLen - pos);
                        Buffer.BlockCopy(chunk, 0, data, (int)pos, copy);
                    }
                    pos += got;
                }
                sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                res.Sha256 = BitConverter.ToString(sha.Hash).Replace("-", "").ToLowerInvariant();
            }
            // хвост: читаем последние TAIL_CAP байт, если файл большой
            if (fi.Length > MAIN_CAP) {
                long tailStart = Math.Max(MAIN_CAP, fi.Length - TAIL_CAP);
                int tailLen = (int)(fi.Length - tailStart);
                var tail = new byte[tailLen];
                fs.Position = tailStart;
                int toff = 0;
                while (toff < tailLen) { int n = fs.Read(tail, toff, tailLen - toff); if (n <= 0) break; toff += n; }
                var combined = new byte[data.Length + tail.Length];
                Buffer.BlockCopy(data, 0, combined, 0, data.Length);
                Buffer.BlockCopy(tail, 0, combined, data.Length, tail.Length);
                data = combined;
            }
        }
        // Честная пометка усечённого анализа: файл больше буфера
        if (truncated) {
            res.Findings.Add(new Finding { Severity = "low", Category = "format", Rule = "truncated",
                Detail = "файл больше 65 МБ — проанализированы начало и хвост, середина пропущена" });
        }

        // 1. Известные хэши (встроенные + внешние, кэшированные)
        if (KNOWN_HASHES.TryGetValue(res.Sha256, out var sig)) {
            Add(res, "signature", "известный хэш: " + sig[0], sig[1] == "high" ? 10 : 6, "signature", res.File);
        }
        if (_extHashCache.TryGetValue(res.Sha256, out var esig)) {
            Add(res, "signature", "известный хэш: " + esig[0], esig[1] == "high" ? 10 : 6, "signature", res.File);
        }

        // 2. Опасные расширения из базы
        string fext = Path.GetExtension(path).ToLowerInvariant();
        foreach (var (ext, category, weight, note) in _extCache) {
            if (fext == ext) Add(res, category, note.Length > 0 ? note : "расширение: " + ext, weight, "ext_" + ext.TrimStart('.'), res.File);
        }

        // 2. Определение типа
        string type = DetectType(path, data);
        res.Type = type;
        bool isDotnet = type == "pe_dotnet";
        CheckMagic(res, data); // уточнение типа по магическим байтам из базы

        if (type.StartsWith("pe")) AnalyzePE(res, path, data, isDotnet);
        else if (type == "zip") AnalyzeZip(res, data);
        else if (type == "script") AnalyzeScript(res, path, data);
        else if (type == "elf") Add(res, "unknown", "ELF-бинарник — анализ ограничен", 2, "format", res.File);
        else if (type == "pdf") Add(res, "document", "PDF — проверь на JS-макросы и эксплойты", 2, "format", res.File);
        else if (type == "ole") Add(res, "document", "OLE2-документ (DOC/XLS/PPT) — проверь на макросы", 2, "format", res.File);

        // 3. Строки и правила (для PE тоже — строки часто содержат RAT-маркеры)
        if (type.StartsWith("pe") || type == "script" || type == "zip") {
            var strings = ExtractStrings(data);
            // Для .NET host-exe сами строки лежат в управляемой сборке (sibling .dll) или вшиты (self-contained).
            // Строки самого host-бинарника — это мусор .NET runtime (RegOpenKeyEx, GetProcAddress и т.п.), их не сканируем.
            if (isDotnet) {
                var managed = LoadSiblingAssembly(path, data);
                if (managed != null) strings = ExtractStrings(managed);
                else {
                    strings = new List<string>();
                    Add(res, "dotnet", "управляемая сборка не найдена (сжатая self-contained?) — строковый анализ ограничен", 0, "dotnet_limited", res.File);
                }
            }
            var allText = strings.Count > 0 ? string.Join("\n", strings) : "";

            // Токены и URL-паттерны (regex-фаза: кап длины + NonBacktracking против ReDoS)
            string scanText = allText.Length > 1_500_000 ? allText.Substring(0, 1_500_000) : allText;
            var rxOpts = RegexOptions.Multiline | RegexOptions.NonBacktracking;
            foreach (Match m in Regex.Matches(scanText, @"\b\d{8,10}:[A-Za-z0-9_-]{30,40}\b", rxOpts))
                Add(res, "stealer", "Telegram bot token", 8, "token", Truncate(m.Value, 48));
            foreach (Match m in Regex.Matches(scanText, @"discord(?:app)?\.com/api/webhooks/\d{15,25}/[A-Za-z0-9_-]{40,}", rxOpts))
                Add(res, "stealer", "Discord webhook (кража через ботов)", 8, "webhook", Truncate(m.Value, 60));
            foreach (Match m in Regex.Matches(scanText, @"(?i)https?://[^\s""'<>]{8,}", rxOpts))
                if (IsSuspiciousUrl(m.Value)) Add(res, "network", "подозрительный URL", 5, "url", Truncate(m.Value, 80));

            // Двойные расширения и опасные расширения в именах (Multiline: $ на каждой строке)
            foreach (Match m in Regex.Matches(scanText, @"[A-Za-z0-9_\-. ]+\.(exe|scr|pif|bat|cmd|vbs|js|jar|ps1|hta|msi|docm)\s*$", rxOpts))
                if (Regex.IsMatch(m.Value, @"(?i)\.[a-z0-9]{1,5}\.(exe|scr|pif|bat|cmd|vbs|js|jar|ps1|hta|msi)$"))
                    Add(res, "evasion", "двойное расширение (маскировка)", 8, "dbl_ext", Truncate(m.Value, 60));

            // base64-блоб длиннее 60 символов (NonBacktracking — линейный поиск)
            int b64count = 0;
            foreach (Match m in Regex.Matches(scanText, @"[A-Za-z0-9+/]{60,}={0,2}", rxOpts)) { b64count++; if (b64count >= 3) break; }
            if (b64count >= 3) Add(res, "obfuscated", "несколько длинных base64-блоков", 6, "b64_blob", res.File);

            // Общие строковые правила
            var rules = STRING_RULES;
            if (type == "script") {
                string ext = Path.GetExtension(path).ToLowerInvariant();
                if (ext == ".ps1" || allText.Contains("powershell")) rules = rules.Concat(PS_RULES).ToList();
                if (ext == ".py" || allText.Contains("b64decode") || allText.Contains("import socket")) rules = rules.Concat(PY_RULES).ToList();
                if (ext == ".bat" || ext == ".cmd") rules = rules.Concat(BAT_RULES).ToList();
            } else if (type == "pe") {
                // Нативный PE: шумные API-правила не применяем (строки из любого бинарника)
                rules = rules.Where(r => r.PeSafe).ToList();
            }
            ApplyRules(res, rules, allText, strings);
            // Внешние строковые правила из signatures.json (семейства стилеров/раток)
            if (_extRuleCache.Count > 0) {
                if (type == "pe") ApplyRules(res, _extRuleCache.Where(r => r.PeSafe).ToList(), allText, strings);
                else ApplyRules(res, _extRuleCache, allText, strings);
            }
            // Для .NET: P/Invoke-имена функций лежат в метаданных, а не в таблице импортов
            if (isDotnet) ApplyImportRulesToStrings(res, strings);
        }

        // yara-x теперь запускается батчем на всю пачку в Main (RunYaraBatch),
        // а не на каждый файл — так в 20-50 раз быстрее.

        Finalize(res, path);
        res.Ms = sw.ElapsedMilliseconds;
        return res;
    }

    static bool IsSuspiciousUrl(string url) {
        string u = url.ToLowerInvariant();
        // localhost, частные IP и многоадресные — не подозрительны
        if (u.Contains("127.0.0.") || u.Contains("0.0.0.0") || u.Contains("192.168.") || u.Contains("::1"))
            return false;
        if (u.Contains("pastebin") || u.Contains("hastebin") || u.Contains("ghostbin") || u.Contains("transfer.sh")
            || u.Contains("raw.githubusercontent") || u.Contains("gist.github") || u.Contains("discord.com/api/webhooks")
            || u.Contains("cdn.discordapp") || u.Contains("onion") || u.Contains("api.telegram") || u.Contains("top4top")
            || u.Contains("anonfiles") || u.Contains("mediafire") || u.Contains("googledrive.com") || u.Contains("bit.ly")
            || u.Contains("t.me/") || u.Contains("filetransfer.io") || u.Contains("tmpfiles.org"))
            return true;
        return Regex.IsMatch(u, @"\d{1,3}(\.\d{1,3}){3}(:\d+)?[/\w]");
    }

    static void ApplyRules(ScanResult res, List<Rule> rules, string allText, List<string> strings) {
        foreach (var rule in rules) {
            var hitPats = new List<string>();
            foreach (var pat in rule.Patterns) {
                if (rule.CaseInsensitive ? allText.IndexOf(pat, StringComparison.OrdinalIgnoreCase) >= 0 : allText.Contains(pat)) hitPats.Add(pat);
                if (hitPats.Count >= rule.MinHits) break;
            }
            if (hitPats.Count >= rule.MinHits) Add(res, rule.Category, rule.Name + " (" + Truncate(string.Join(", ", hitPats), 60) + ")", rule.Weight, rule.Name.ToLowerInvariant().Replace(' ','_'), Truncate(allText, 120));
        }
    }

    static void ApplyImportRules(ScanResult res, HashSet<string> imports) {
        foreach (var rule in IMPORT_RULES) {
            foreach (var pat in rule.Patterns) {
                if (imports.Contains(pat)) { Add(res, rule.Category, rule.Name + " (" + pat + ")", rule.Weight, "import_" + rule.Name.Replace(' ','_'), pat); break; }
            }
        }
    }

    // P/Invoke-имена в .NET и API при динамическом импорте лежат в строках, а не в таблице импортов
    static void ApplyImportRulesToStrings(ScanResult res, List<string> strings) {
        var joined = string.Join("\n", strings);
        foreach (var rule in IMPORT_RULES) {
            foreach (var pat in rule.Patterns) {
                if (joined.Contains(pat, StringComparison.OrdinalIgnoreCase)) {
                    Add(res, rule.Category, rule.Name + " (" + pat + ")", rule.Weight, "api_" + rule.Name.Replace(' ','_'), pat);
                    break;
                }
            }
        }
    }

    // Для .NET host-exe читаем управляемую сборку рядом (apphost + dll).
    // Если её нет (self-contained, сжатые метаданные) — строковый анализ бессмыслен,
    // поэтому возвращаем null, чтобы не тащить шум из host-бинарника.
    static bool HasSiblingAssembly(string path) {
        try {
            string dll = Path.Combine(Path.GetDirectoryName(path) ?? "", Path.GetFileNameWithoutExtension(path) + ".dll");
            if (!File.Exists(dll)) return false;
            // Нативный exe + одноимённая DLL (C++ delay-load) — НЕ .NET apphost.
            // Отличаем по размеру: apphost-лаунчер маленький (< 1.5 МБ),
            // а рядом лежит управляемая сборка с COR20-заголовком.
            var exeInfo = new FileInfo(path);
            if (exeInfo.Length > 1_500_000) return false;
            var dllData = File.ReadAllBytes(dll);
            if (dllData.Length < 4) return false;
            uint peOff = BitConverter.ToUInt32(dllData, 0x3C);
            if (peOff + 120 >= dllData.Length || dllData[peOff] != 0x50 || dllData[peOff + 1] != 0x45) return false;
            ushort magic = BitConverter.ToUInt16(dllData, (int)peOff + 24);
            if (magic != 0x10B && magic != 0x20B) return false;
            uint comRva = BitConverter.ToUInt32(dllData, (int)peOff + 24 + 96 + 14 * 8);
            return comRva != 0;
        } catch { return false; }
    }

    static byte[] LoadSiblingAssembly(string path, byte[] hostData) {
        try {
            string dll = Path.Combine(Path.GetDirectoryName(path) ?? "", Path.GetFileNameWithoutExtension(path) + ".dll");
            if (File.Exists(dll)) {
                long len = new FileInfo(dll).Length;
                if (len < 50 * 1024 * 1024) return File.ReadAllBytes(dll);
            }
        } catch { }
        // Self-contained без сжатия: метаданные вшиты в exe (маркер BSJB — начало #~ потоков)
        bool hasMetadata = false;
        for (int i = 0; i + 4 <= hostData.Length && i < 64 * 1024 * 1024; i++) {
            if (hostData[i] == 0x42 && hostData[i+1] == 0x53 && hostData[i+2] == 0x4A && hostData[i+3] == 0x42) { hasMetadata = true; break; }
        }
        return hasMetadata ? hostData : null;
    }

    static void Add(ScanResult res, string category, string detail, int weight, string rule, string src) {
        string sev = weight >= 8 ? "high" : weight >= 5 ? "medium" : "low";
        if (!res.Categories.Contains(category)) res.Categories.Add(category);
        if (res.Findings.Count < 80) {
            res.Findings.Add(new Finding { Severity = sev, Category = category, Rule = rule, Detail = detail });
        }
        res.Score += weight;
    }

    // Приоритеты типа угрозы: специфичные категории важнее generic.
    // «rat» — только если нет более точного типа (стилер/випер/майнер/ботнет).
    static readonly (string cat, string label)[] THREAT_TYPES = {
        ("wiper", "Випер/деструктивный"),
        ("ransomware", "Шифровальщик (ransomware)"),
        ("stealer", "Стилер (кража данных)"),
        ("miner", "Скрытый майнер"),
        ("botnet", "Ботнет"),
        ("keylogger", "Кейлоггер"),
        ("injection", "Инъекция кода"),
        ("rat", "RAT (удалённое управление)"),
        ("c2", "C2-инфраструктура"),
        ("downloader", "Загрузчик (dropper)"),
        ("banker", "Банковский троян"),
        ("obfuscated", "Обфусцированный код"),
        ("packed", "Упакованный файл"),
        ("persistence", "Автозапуск"),
        ("network", "Сетевая активность"),
        ("evasion", "Обход защиты"),
    };

    static string InferThreatType(ScanResult res) {
        foreach (var (cat, label) in THREAT_TYPES)
            if (res.Categories.Contains(cat)) return label;
        if (res.Verdict == "malicious") return "Вредоносное ПО";
        if (res.Verdict == "suspicious") return "Подозрительное ПО";
        return "Чисто";
    }

    static void Finalize(ScanResult res, string path) {
        res.Score = Math.Min(100, res.Score);
        res.Verdict = res.Score >= 30 ? "malicious" : res.Score >= 12 ? "suspicious" : "clean";
        // Комбинация разных подозрительных категорий с высокой оценкой — усиленный сигнал
        if (res.Score >= 20 && res.Categories.Count >= 3 && res.Verdict == "suspicious")
            res.Verdict = "malicious";
        // Випер-команды (уничтожение данных/системы) — всегда опасны, даже при 20+
        if (res.Categories.Contains("wiper") && res.Score >= 20)
            res.Verdict = "malicious";
        res.ThreatType = InferThreatType(res);
    }

    static string format_bytes_cap(long b) {
        if (b >= 1024 * 1024) return (b / (1024.0 * 1024.0)).ToString("0.0") + " МБ";
        if (b >= 1024) return (b / 1024.0).ToString("0.0") + " КБ";
        return b + " байт";
    }

    static string Truncate(string s, int n) {
        // Убираем управляющие символы (ESC-инъекция в терминал) и служебные
        var sb = new StringBuilder(s.Length);
        foreach (char c in s) {
            if (c == '\r' || c == '\n' || c == '\t') sb.Append(' ');
            else if (c < 32 || c == 0x7F) continue;
            else sb.Append(c);
        }
        string clean = sb.ToString();
        return clean.Length <= n ? clean : clean.Substring(0, n - 3) + "...";
    }

    static string DetectType(string path, byte[] data) {
        if (data.Length >= 2 && data[0] == 0x4D && data[1] == 0x5A) {
            try {
                uint peOff = BitConverter.ToUInt32(data, 0x3C);
                if (peOff + 4 < data.Length && data[peOff] == 0x50 && data[peOff + 1] == 0x45) {
                    ushort optSize = BitConverter.ToUInt16(data, (int)peOff + 20);
                    ushort magic = BitConverter.ToUInt16(data, (int)peOff + 24);
                    if (magic == 0x10B || magic == 0x20B) {
                        int ddBase = (int)peOff + 24 + 96;
                        uint comRva = BitConverter.ToUInt32(data, ddBase + 14 * 8);
                        if (comRva != 0) {
                            var secs = ParseSectionsLight(data, peOff, optSize);
                            // Настоящая managed-сборка: COR20-заголовок по RVA
                            if (HasValidClrHeader(data, comRva, secs)) return "pe_dotnet";
                            // .NET Core apphost: нативный лаунчер, управляемая сборка рядом (sibling .dll)
                            if (HasSiblingAssembly(path)) return "pe_dotnet";
                        }
                    }
                }
            } catch { }
            return "pe";
        }
        if (data.Length >= 4 && data[0] == 0x50 && data[1] == 0x4B && (data[2] == 0x03 || data[2] == 0x05 || data[2] == 0x07)) return "zip";
        if (data.Length >= 4 && data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C && data[3] == 0x46) return "elf";
        if (data.Length >= 4 && data[0] == 0x25 && data[1] == 0x50 && data[2] == 0x44 && data[3] == 0x46) return "pdf";
        string ext = Path.GetExtension(path).ToLowerInvariant();
        if (ext == ".ps1" || ext == ".py" || ext == ".bat" || ext == ".cmd" || ext == ".vbs" || ext == ".js" || ext == ".jse"
            || ext == ".hta" || ext == ".vbe" || ext == ".pl" || ext == ".rb" || ext == ".sh" || ext == ".php" || ext == ".lua")
            return "script";
        // Текстовый файл с признаками скрипта
        if (data.Length > 8 && data.Length < 2 * 1024 * 1024 && LooksLikeText(data)) {
            string s = Encoding.UTF8.GetString(data, 0, Math.Min(data.Length, 8192)).ToLowerInvariant();
            if (s.Contains("invoke-expression") || s.Contains("b64decode") || s.Contains("import socket")
                || s.Contains("frombase64string") || s.Contains("powershell") || s.Contains("def main")
                || s.Contains("wscript") || s.Contains("scripting.filesystemobject") || s.Contains("activexobject")
                || s.Contains("createobject") || s.Contains("mshta") || s.Contains("#!/"))
                return "script";
        }
        return "data";
    }

    static bool LooksLikeText(byte[] d) {
        int printable = 0, total = Math.Min(d.Length, 4096);
        for (int i = 0; i < total; i++) { byte b = d[i]; if (b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127)) printable++; }
        return printable * 10 >= total * 9;
    }

    static void AnalyzeZip(ScanResult res, byte[] data) {
        Add(res, "archive", "архив — содержимое требует распаковки", 2, "archive", res.File);
        try {
            using var ms = new MemoryStream(data);
            using var za = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Read);
            int exeCount = 0;
            foreach (var e in za.Entries) {
                string n = e.Name.ToLowerInvariant();
                if (n.EndsWith(".exe") || n.EndsWith(".scr") || n.EndsWith(".pif") || n.EndsWith(".bat")
                    || n.EndsWith(".vbs") || n.EndsWith(".js") || n.EndsWith(".jar") || n.EndsWith(".ps1")
                    || n.EndsWith(".hta") || n.EndsWith(".msi") || n.EndsWith(".docm") || n.EndsWith(".lnk")) {
                    exeCount++;
                    if (exeCount <= 10) Add(res, "archive", "исполняемый файл внутри архива: " + e.FullName, 6, "archive_exe", e.FullName);
                }
                if (Regex.IsMatch(n, @"\.[a-z0-9]{1,5}\.(exe|scr|pif|bat|vbs|js|jar|ps1|hta|msi)$"))
                    Add(res, "evasion", "двойное расширение в архиве: " + e.FullName, 8, "dbl_ext", e.FullName);
            }
            if (exeCount >= 3) Add(res, "archive", "много исполняемых файлов в архиве (" + exeCount + ")", 6, "archive_many", res.File);
        } catch { Add(res, "archive", "не удалось разобрать архив", 1, "archive", res.File); }
    }

    static void AnalyzeScript(ScanResult res, string path, byte[] data) {
        // UTF-16 (BOM FF FE / FE FF) и Windows-1251 для .bat/.cmd: иначе mojibake
        string text;
        if (data.Length >= 2 && data[0] == 0xFF && data[1] == 0xFE) text = Encoding.Unicode.GetString(data, 2, data.Length - 2);
        else if (data.Length >= 2 && data[0] == 0xFE && data[1] == 0xFF) text = Encoding.BigEndianUnicode.GetString(data, 2, data.Length - 2);
        else if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) text = Encoding.UTF8.GetString(data, 3, data.Length - 3);
        else if (Path.GetExtension(path).ToLowerInvariant() is ".bat" or ".cmd") text = Encoding.GetEncoding(1251).GetString(data);
        else text = Encoding.UTF8.GetString(data);
        string lower = text.ToLowerInvariant();

        // Плотность hex-escape-последовательностей — маркер обфускации
        int hexEscapes = Regex.Matches(lower, @"\\x[0-9a-f]{2}", RegexOptions.NonBacktracking).Count;
        if (hexEscapes > 40) Add(res, "obfuscated", "много hex-escape последовательностей (" + hexEscapes + ") — обфускация", 8, "hex_escape", res.File);

        int charCodes = Regex.Matches(lower, @"[\[\(]?char\(?\s*\d{1,3}\s*\)", RegexOptions.NonBacktracking).Count;
        if (charCodes > 20) Add(res, "obfuscated", "массовая сборка строк из кодов символов", 8, "charcode", res.File);

        // Реверс строк — без Split('\n') на весь файл (OOM на 8 МБ переводов строк):
        // считаем посимвольно вхождения маркеров
        int reversed = 0;
        int idxRev = 0;
        while ((idxRev = lower.IndexOf("::-1]", idxRev, StringComparison.Ordinal)) >= 0 && reversed < 4) { reversed++; idxRev += 6; }
        if (lower.IndexOf("-join", StringComparison.Ordinal) >= 0 || lower.IndexOf("::join", StringComparison.Ordinal) >= 0) reversed++;
        if (reversed > 3) Add(res, "obfuscated", "реверс строк — типичный приём обфускации", 6, "reverse_str", res.File);

        // Много длинных строк без пробелов (обфускация идентификаторов) — через IndexOf, без массива
        int longTight = 0, lineStart = 0;
        while (lineStart < text.Length && longTight <= 12) {
            int nl = text.IndexOf('\n', lineStart);
            if (nl < 0) nl = text.Length;
            int len = nl - lineStart;
            if (len > 120) {
                bool hasSpace = false;
                for (int i = lineStart; i < nl; i++) { if (text[i] == ' ') { hasSpace = true; break; } }
                if (!hasSpace) longTight++;
            }
            lineStart = nl + 1;
        }
        if (longTight > 8) Add(res, "obfuscated", "много длинных однострочных конструкций без пробелов", 6, "tight_lines", res.File);

        if (lower.Contains("base64") || lower.Contains("b64decode") || lower.Contains("frombase64"))
            Add(res, "obfuscated", "base64-кодирование в скрипте", 6, "b64_script", res.File);
    }

    // Лёгкий парсинг секций для RVA→offset (только заголовки, без энтропии)
    static List<SectionInfo> ParseSectionsLight(byte[] d, uint peOff, ushort optSize) {
        var sections = new List<SectionInfo>();
        ushort nSections = BitConverter.ToUInt16(d, (int)peOff + 6);
        int secBase = (int)peOff + 24 + optSize;
        for (int i = 0; i < nSections; i++) {
            int off = secBase + i * 40;
            if (off + 40 > d.Length) break;
            sections.Add(new SectionInfo {
                Name = Encoding.ASCII.GetString(d, off, 8).TrimEnd('\0'),
                VirtualSize = BitConverter.ToUInt32(d, off + 8),
                VirtualAddress = BitConverter.ToUInt32(d, off + 12),
                RawSize = BitConverter.ToUInt32(d, off + 16),
                RawPtr = BitConverter.ToUInt32(d, off + 20),
            });
        }
        return sections;
    }

    static bool HasValidClrHeader(byte[] d, uint comRva, List<SectionInfo> sections) {
        // COR20-заголовок (magic 0x48 0x02) по RVA COM descriptor'а, через RVA→offset.
        int off = RvaToOff(d, comRva, sections);
        return off >= 0 && off + 4 <= d.Length && d[off] == 0x48 && d[off + 1] == 0x02;
    }

    static void AnalyzePE(ScanResult res, string path, byte[] data, bool isDotnet) {
        if (isDotnet) {
            string s = Encoding.ASCII.GetString(data);
            foreach (var obf in new[]{"ConfusedByAttribute","ConfuserEx","SmartAssembly","Dotfuscator","Eazfuscator",
                ".NET Reactor","DotNet_Reactor","Obfuscar","Babel","Agile.NET","CryptoObfuscator","Xenocode","Skater"}) {
                if (s.Contains(obf, StringComparison.OrdinalIgnoreCase))
                    Add(res, "dotnet", ".NET-обфускатор: " + obf, 8, "dotnet_obf", obf);
            }
        }
        try { ParsePe(res, data, isDotnet); }
        catch (Exception) { Add(res, "format", "не удалось разобрать PE-заголовки (повреждён или намеренно сломан)", 5, "pe_parse", res.File); }
    }

    class SectionInfo { public string Name; public uint VirtualSize, VirtualAddress, RawSize, RawPtr; public double Entropy; }

    static void ParsePe(ScanResult res, byte[] d, bool isDotnet) {
        uint peOff = BitConverter.ToUInt32(d, 0x3C);
        if (peOff + 4 >= d.Length || d[peOff] != 0x50 || d[peOff+1] != 0x45) throw new Exception("no PE");
        ushort nSections = BitConverter.ToUInt16(d, (int)peOff + 6);
        ushort optSize = BitConverter.ToUInt16(d, (int)peOff + 20);
        ushort magic = BitConverter.ToUInt16(d, (int)peOff + 24);
        bool pe32 = magic == 0x10B;
        if (magic != 0x10B && magic != 0x20B) throw new Exception("bad optional magic");

        // Data directories (offset 96 в optional header)
        int ddBase = (int)peOff + 24 + 96;
        uint comRva = BitConverter.ToUInt32(d, ddBase + 14*8);
        uint tlsRva = BitConverter.ToUInt32(d, ddBase + 9*8);

        // Секции
        int secBase = (int)peOff + 24 + optSize;
        var sections = new List<SectionInfo>();
        for (int i = 0; i < nSections; i++) {
            int off = secBase + i * 40;
            if (off + 40 > d.Length) break;
            var name = Encoding.ASCII.GetString(d, off, 8).TrimEnd('\0');
            uint vsize = BitConverter.ToUInt32(d, off + 8);
            uint va = BitConverter.ToUInt32(d, off + 12);
            uint rawSize = BitConverter.ToUInt32(d, off + 16);
            uint rawPtr = BitConverter.ToUInt32(d, off + 20);
            double ent = 0;
            if (rawSize > 0 && rawPtr + rawSize <= d.Length) {
                int len = (int)Math.Min(rawSize, 4 * 1024 * 1024);
                ent = Entropy(d, (int)rawPtr, len);
            }
            sections.Add(new SectionInfo { Name = name, VirtualSize = vsize, VirtualAddress = va, RawSize = rawSize, RawPtr = rawPtr, Entropy = ent });
        }

        if (nSections == 0) Add(res, "format", "PE без секций", 6, "pe_nosec", res.File);
        if (nSections > 8) Add(res, "packed", "аномально много секций (" + nSections + ")", 4, "pe_manysec", res.File);

        // .NET-детект: COM descriptor должен указывать на валидный COR20-заголовок
        // (magic 0x48 0x02), иначе это мусор/иное использование data directory.
        if (comRva != 0) {
            int clrOff = RvaToOff(d, comRva, sections);
            if (clrOff < 0 || clrOff + 4 > d.Length || d[clrOff] != 0x48 || d[clrOff + 1] != 0x02) comRva = 0;
        }
        if (comRva != 0 && !isDotnet) Add(res, "dotnet", "CLR-заголовок в неожиданном месте", 5, "pe_com", res.File);
        if (tlsRva != 0) Add(res, "evasion", "TLS-колбэки (скрытый запуск кода)", 6, "pe_tls", res.File);

        var imports = new HashSet<string>();
        // NativeAOT-маркеры (.NET NativeAOT exe: секция hydrated заполняется в рантайме,
        // высокая энтропия кода — норма, не упаковка)
        bool isNativeAot = sections.Any(s => s.Name.Equals("hydrated", StringComparison.OrdinalIgnoreCase));
        foreach (var sec in sections) {
            string sn = sec.Name;
            foreach (var bad in PE_SUS_SECTIONS)
                if (sn.Equals(bad, StringComparison.OrdinalIgnoreCase)) Add(res, "packed", "секция упаковщика: " + sn, 8, "packer_section", sn);
            // hydrated без raw — особенность NativeAOT, не упаковка
            if (sec.VirtualSize > 0 && sec.RawSize == 0
                && !sn.Equals("hydrated", StringComparison.OrdinalIgnoreCase))
                Add(res, "packed", "секция без raw-данных (упаковка): " + sn, 6, "packer_noraw", sn);
            // .rsrc (ресурсы), .reloc (релокации), .pdata (таблицы исключений) — шумные у легитимных файлов;
            // для NativeAOT-бинарников высокая энтропия кода (.text/.rdata) — норма компилятора
            if (sn.Equals(".rsrc", StringComparison.OrdinalIgnoreCase)
                || sn.Equals(".reloc", StringComparison.OrdinalIgnoreCase)
                || sn.Equals(".pdata", StringComparison.OrdinalIgnoreCase)) continue;
            if (sec.Entropy > 7.2) Add(res, "packed", "высокая энтропия секции " + sn + " (" + sec.Entropy.ToString("0.00") + ") — упаковка/шифрование", 6, "high_entropy", sn);
            else if (sec.Entropy > 6.5 && !isNativeAot) Add(res, "packed", "повышенная энтропия секции " + sn + " (" + sec.Entropy.ToString("0.00") + ")", 3, "mid_entropy", sn);
        }
        if (isNativeAot)
            res.Findings.Add(new Finding { Severity = "info", Category = "format", Rule = "nativeaot",
                Detail = "NativeAOT-сборка (нативная компиляция .NET): высокая энтропия кода — норма" });

        // Энтропия всего файла. Большие файлы (> 20 МБ) — обычно легитимные бандлы
        // (PyInstaller, Electron, инсталляторы): они тоже "зашифрованы", но это норма.
        // Энтропия анализируемого буфера. Файлы >20 МБ (PyInstaller/Electron бандлы)
        // почти всегда «зашифрованы» легитимно — без доп. признаков не флагаем.
        double fileEnt = Entropy(d, 0, d.Length);
        if (fileEnt > 7.4 && res.Size > 64 * 1024 && res.Size < 20 * 1024 * 1024)
            Add(res, "packed", "энтропия файла " + fileEnt.ToString("0.00") + " — вероятно зашифрован", 7, "file_entropy", res.File);

        // Импорты
        try {
            uint importRva = BitConverter.ToUInt32(d, ddBase + 1*8);
            uint iatRva = BitConverter.ToUInt32(d, ddBase + 12*8);
            if (importRva != 0) ParseImports(d, importRva, sections, imports, pe32);
            // Для .NET импорты почти всегда скрыты в метаданных (нет классической таблицы) — не штрафуем.
            // IAT без import-директории — легитимная особенность (напр. System32), не упаковка.
            if (imports.Count == 0 && !isDotnet && importRva == 0 && iatRva == 0)
                Add(res, "packed", "импорты отсутствуют или скрыты (упаковка)", 5, "no_imports", res.File);
            ApplyImportRules(res, imports);
        } catch { /* импорты опциональны */ }

        // Overlay. Большие хвосты — норма для самораспаковывающихся бандлов
        // (PyInstaller и т.п.). Подозрительно, только когда файл маленький,
        // а overlay заметно больше самого кода (дописанный конфиг/полезная нагрузка).
        uint maxRawEnd = 0;
        foreach (var s in sections) maxRawEnd = Math.Max(maxRawEnd, s.RawPtr + s.RawSize);
        if (maxRawEnd > 0 && d.Length < 10 * 1024 * 1024 && d.Length > maxRawEnd + 1024
            && (d.Length - maxRawEnd) * 2 > maxRawEnd)
            Add(res, "packed", "overlay-данные после секций (" + (d.Length - maxRawEnd) + " байт)", 4, "overlay", res.File);
    }

    static void ParseImports(byte[] d, uint importRva, List<SectionInfo> sections, HashSet<string> imports, bool pe32) {
        int off = RvaToOff(d, importRva, sections);
        if (off < 0) return;
        bool is64 = !pe32;
        int maxDlls = 0;
        while (off + 20 <= d.Length && maxDlls++ < 100) {
            uint oft = BitConverter.ToUInt32(d, off);
            uint nameRva = BitConverter.ToUInt32(d, off + 12);
            if (oft == 0 && nameRva == 0) break;
            if (nameRva != 0) {
                int noff = RvaToOff(d, nameRva, sections);
                if (noff >= 0) {
                    int end = noff; while (end < d.Length && d[end] != 0) end++;
                    if (end > noff) imports.Add(Encoding.ASCII.GetString(d, noff, end - noff));
                }
            }
            uint thunkRva = oft != 0 ? oft : BitConverter.ToUInt32(d, off + 16);
            int toff = RvaToOff(d, thunkRva, sections);
            int maxFns = 0;
            int thunkSize = is64 ? 8 : 4;
            if (toff >= 0) {
                while (toff + thunkSize <= d.Length && maxFns++ < 1000) {
                    ulong thunk = is64 ? BitConverter.ToUInt64(d, toff) : BitConverter.ToUInt32(d, toff);
                    if (thunk == 0) break;
                    ulong ordinalFlag = is64 ? 0x8000000000000000UL : 0x80000000UL;
                    if ((thunk & ordinalFlag) == 0) {
                        uint hintNameRva = (uint)(thunk & 0x7FFFFFFF);
                        int hoff = RvaToOff(d, hintNameRva, sections);
                        if (hoff >= 0 && hoff + 2 <= d.Length) {
                            int end = hoff + 2; while (end < d.Length && d[end] != 0) end++;
                            if (end > hoff + 2) imports.Add(Encoding.ASCII.GetString(d, hoff + 2, end - (hoff + 2)));
                        }
                    }
                    toff += thunkSize;
                }
            }
            off += 20;
        }
    }

    static int RvaToOff(byte[] d, uint rva, List<SectionInfo> sections) {
        foreach (var s in sections) {
            if (s.RawSize == 0) continue;
            uint vaStart = s.VirtualAddress;
            uint vaEnd = vaStart + Math.Max(s.VirtualSize, s.RawSize);
            if (rva >= vaStart && rva < vaEnd) return (int)(s.RawPtr + (rva - vaStart));
        }
        return -1;
    }

    static double Entropy(byte[] d, int start, int len) {
        if (start < 0 || len <= 0 || start + len > d.Length) return 0;
        long[] counts = new long[256];
        for (int i = start; i < start + len; i++) counts[d[i]]++;
        double e = 0;
        for (int i = 0; i < 256; i++) {
            if (counts[i] == 0) continue;
            double p = (double)counts[i] / len;
            e -= p * Math.Log2(p);
        }
        return e;
    }

    static List<string> ExtractStrings(byte[] d) {
        var list = new List<string>();
        int n = d.Length;
        var sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            byte b = d[i];
            if (b >= 32 && b < 127) { sb.Append((char)b); }
            else {
                if (sb.Length >= 5) list.Add(sb.ToString());
                sb.Clear();
            }
        }
        if (sb.Length >= 5) list.Add(sb.ToString());
        // UTF-16LE
        sb.Clear();
        for (int i = 0; i + 1 < n; i += 2) {
            byte lo = d[i], hi = d[i + 1];
            if (hi == 0 && lo >= 32 && lo < 127) sb.Append((char)lo);
            else {
                if (sb.Length >= 4) list.Add(sb.ToString());
                sb.Clear();
            }
        }
        if (sb.Length >= 4) list.Add(sb.ToString());
        // Кап на память
        if (list.Count > 20000) list = list.Take(20000).ToList();
        return list;
    }
}
