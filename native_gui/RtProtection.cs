// ShadowScan native — real-time protection (папки + процессы + автозапуск).
// NativeAOT-совместимо: без System.Management, без reflection-сериализации,
// весь P/Invoke через DllImport, реестр через Microsoft.Win32.Registry.
//
// ==================== ЧТО НУЖНО ДОБАВИТЬ В Program.cs (этот файл не редактируем) ====================
//  1) Поле App.Notify — статический WindowNotificationManager для всплывающих
//     уведомлений (модуль обращается к нему через App.Notify?.Show(...)):
//         using Avalonia.Controls.Notifications;
//         public static WindowNotificationManager Notify;
//     и в App.Initialize() сразу после создания окна:
//         Notify = new WindowNotificationManager(win)
//         { Position = NotificationPosition.BottomRight, MaxItems = 3 };
//
//  2) Запуск/остановка из MainWindow (например):
//         private readonly RtProtection _rt = new RtProtection
//         {
//             onThreat = (path, type) => _status.Text = "RT: " + Path.GetFileName(path) + " — " + type
//         };
//     в конструкторе MainWindow:
//         if (RtProtection.Settings.RealtimeEnabled) _rt.Start();
//     при закрытии окна:
//         _rt.Stop();
//
// ==================== ЧТО НУЖНО В native_gui.csproj ====================
//   <PackageReference Include="Microsoft.Win32.Registry" Version="5.0.0" />
//  TFM net8.0 (без net8.0-windows) не включает Registry в framework reference;
//  пакет совместим с NativeAOT (внутри — обычные P/Invoke).
// ========================================================================
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls.Notifications;
using Avalonia.Threading;
using Microsoft.Win32;

namespace ShadowScanNative;

// ==================== настройки real-time ====================
public class Settings
{
    public int ThresholdSuspicious = 12;
    public int ThresholdMalicious = 30;
    public bool BlockDangerousScripts = true;
    public bool RealtimeEnabled = false;
    // Самозащита: ограничение доступа к процессу через DACL — вирус не сможет
    // завершить антивирус или внедриться в него (права администратора не помогут,
    // DACL переприменяется каждые 10 сек). Без BSOD и драйвера.
    public bool SelfDefend = false;
    // Мониторинг сетевых соединений: проверка новых процессов на подозрительные
    // исходящие соединения (необычные порты, процесс из Temp/AppData).
    public bool NetworkMonitor = false;
}

// ==================== real-time protection ====================
public class RtProtection
{
    // Общий доступ из GUI: RtProtection.Settings.BlockDangerousScripts = true; и т.п.
    public static readonly Settings Settings = new Settings();
    // Колбэк для GUI: (путь/источник, тип угрозы). Вызывается на UI-потоке.
    public Action<string, string> onThreat;

    // ---------- P/Invoke: снимок процессов (Toolhelp32) ----------
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;   // ULONG_PTR — на x64 8 байт, layout совпадает с нативным
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;           // WCHAR[MAX_PATH]
    }

    static class Native
    {
        const uint TH32CS_SNAPPROCESS = 0x00000002;
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000; // работает без SeDebugPrivilege

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags,
            StringBuilder lpExeName, ref uint lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        // Снимок всех процессов: (pid, имя exe-модуля).
        public static List<(uint pid, string name)> SnapshotProcesses()
        {
            var list = new List<(uint, string)>();
            var entry = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
            IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == (IntPtr)(-1)) return list; // INVALID_HANDLE_VALUE
            try
            {
                if (Process32FirstW(snap, ref entry))
                {
                    do { list.Add((entry.th32ProcessID, entry.szExeFile)); }
                    while (Process32NextW(snap, ref entry));
                }
            }
            finally { CloseHandle(snap); }
            return list;
        }

        // Полный путь к exe процесса (null, если недоступен — системные/защищённые).
        public static string GetProcessPath(uint pid)
        {
            IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) return null;
            try
            {
                uint size = 1024;
                var sb = new StringBuilder((int)size);
                if (QueryFullProcessImageNameW(h, 0, sb, ref size)) return sb.ToString();
                return null;
            }
            finally { CloseHandle(h); }
        }

        // ---------- самозащита: урезание DACL процесса ----------
        // Убирает у процесса права на завершение/запись/создание потоков даже
        // для администраторов (остаётся только SYSTEM). Зловред не сможет убить
        // антивирус или внедриться в него через OpenProcess+CreateRemoteThread.
        const uint PROCESS_TERMINATE = 0x0001;
        const uint PROCESS_CREATE_THREAD = 0x0002;
        const uint PROCESS_VM_WRITE = 0x0020;
        const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        const uint READ_CONTROL = 0x00020000;
        const uint WRITE_DAC = 0x00040000;
        const uint ACCESS_SYSTEM_SECURITY = 0x01000000;
        const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;

        // SID администраторов (S-1-5-32-544)
        static byte[] _adminsSid = null;
        static byte[] AdminsSid()
        {
            if (_adminsSid != null) return _adminsSid;
            IntPtr p = IntPtr.Zero;
            try
            {
                // BUILTIN\Administrators SID: S-1-5-32-544
                if (ConvertStringSidToSid("S-1-5-32-544", out p))
                {
                    int len = 8 + 4 + 4; // SID: revision+subauthCount (8) + 1 subauthority
                    _adminsSid = new byte[len];
                    System.Runtime.InteropServices.Marshal.Copy(p, _adminsSid, 0, len);
                }
            }
            catch { }
            finally { if (p != IntPtr.Zero) LocalFree(p); }
            return _adminsSid;
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool ConvertStringSidToSid(string StringSid, out IntPtr Sid);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LocalFree(IntPtr hMem);

        // SetSecurityInfo с типом SE_KERNEL_OBJECT: применяет новый DACL к процессу
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int SetSecurityInfo(IntPtr handle, int ObjectType, uint SecurityInfo,
            IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);

        // CreateWellKnownSid для "Администраторы"
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CreateWellKnownSid(int WellKnownSidType, IntPtr DomainSid, IntPtr pSid, ref int cbSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool InitializeAcl(IntPtr pAcl, int nAclLength, int dwAclRevision);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AddAccessDeniedAce(IntPtr pAcl, int dwAceRevision, uint AccessMask, IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AddAccessAllowedAce(IntPtr pAcl, int dwAceRevision, uint AccessMask, IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetSecurityInfo(IntPtr handle, int ObjectType, uint SecurityInfo,
            out IntPtr pSidOwner, out IntPtr pSidGroup, out IntPtr pDacl, out IntPtr pSacl,
            out IntPtr pSecurityDescriptor);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetProcessHandleCount(IntPtr hProcess, out uint pdwHandleCount);

        public static void RestrictProcessDacl(IntPtr hProcess)
        {
            try
            {
                // 1. Открываем процесс с WRITE_DAC, чтобы изменить его DACL
                IntPtr hSelf = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | WRITE_DAC | READ_CONTROL, false, (uint)System.Diagnostics.Process.GetCurrentProcess().Id);
                if (hSelf == IntPtr.Zero) hSelf = hProcess;

                // 2. Получаем SID администраторов
                int sidLen = 68;
                IntPtr admins = System.Runtime.InteropServices.Marshal.AllocHGlobal(sidLen);
                try
                {
                    if (!CreateWellKnownSid(5 /*WinBuiltinAdministratorsSid*/, IntPtr.Zero, admins, ref sidLen))
                        return;

                    // 3. Строим новый DACL: явно ЗАПРЕЩАЕМ админам TERMINATE/VM_WRITE/CREATE_THREAD,
                    //    SYSTEM и владельцу — полный доступ
                    const int ACL_REVISION = 2;
                    const int ACL_SIZE = 512;
                    IntPtr acl = System.Runtime.InteropServices.Marshal.AllocHGlobal(ACL_SIZE);
                    try
                    {
                        if (!InitializeAcl(acl, ACL_SIZE, ACL_REVISION)) return;

                        // Запрет администраторам: завершение, запись в память, создание потоков
                        if (!AddAccessDeniedAce(acl, ACL_REVISION, PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_WRITE, admins)) return;

                        // SYSTEM — полный доступ (не ломаем систему и обновления)
                        IntPtr sysSid = System.Runtime.InteropServices.Marshal.AllocHGlobal(68);
                        int sysLen = 68;
                        try
                        {
                            if (CreateWellKnownSid(18 /*WinLocalSystemSid*/, IntPtr.Zero, sysSid, ref sysLen))
                                AddAccessAllowedAce(acl, ACL_REVISION, PROCESS_ALL_ACCESS, sysSid);
                        }
                        finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(sysSid); }

                        // 4. Применяем новый DACL (SE_KERNEL_OBJECT = 6)
                        SetSecurityInfo(hSelf, 6, 0x00000004 /*DACL_SECURITY_INFORMATION*/,
                            IntPtr.Zero, IntPtr.Zero, acl, IntPtr.Zero);
                    }
                    finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(acl); }
                }
                finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(admins); }
            }
            catch { /* самозащита не должна ломать запуск */ }
        }

        // ---------- сетевые соединения (GetExtendedTcpTable) ----------
        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort,
            int ipVersion, int tblClass, int reserved);

        public struct MIB_TCPROW_OWNER_PID
        {
            public uint state, localAddr, localPort, remoteAddr, remotePort, owningPid;
        }

        // Активные TCP-соединения: (pid, remoteIp, remotePort, state). state 5 = ESTABLISHED.
        public static List<(uint pid, string remoteIp, ushort remotePort, uint state)> GetTcpConnections()
        {
            var result = new List<(uint, string, ushort, uint)>();
            try
            {
                int size = 0;
                GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 5, 0); // AF_INET, TCP_TABLE_OWNER_PID_ALL
                if (size <= 0) return result;
                IntPtr buf = Marshal.AllocHGlobal(size);
                try
                {
                    if (GetExtendedTcpTable(buf, ref size, false, 2, 5, 0) != 0) return result;
                    int count = Marshal.ReadInt32(buf);
                    int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                    IntPtr p = buf + 4;
                    for (int i = 0; i < count; i++)
                    {
                        var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(p);
                        p += rowSize;
                        var ip = new System.Net.IPAddress(row.remoteAddr);
                        result.Add((row.owningPid, ip.ToString(), (ushort)(row.remotePort >> 8 | row.remotePort << 8), row.state));
                    }
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            catch { }
            return result;
        }
    }

    // ---------- наблюдаемые расширения ----------
    static readonly HashSet<string> WATCH_EXT = new(StringComparer.OrdinalIgnoreCase)
    { ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".hta", ".msi", ".lnk", ".docm", ".py" };

    static bool IsWatchExt(string path) => WATCH_EXT.Contains(Path.GetExtension(path));

    // ---------- опасные скрипты (Settings.BlockDangerousScripts) ----------
    static readonly HashSet<string> SCRIPT_EXT = new(StringComparer.OrdinalIgnoreCase)
    { ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".py" };

    static bool IsScriptExt(string path) => SCRIPT_EXT.Contains(Path.GetExtension(path));

    // ---------- состояние ----------
    readonly object _lock = new();
    // путь -> время последнего события ФС (для отложенного скана)
    readonly Dictionary<string, DateTime> _pending = new();
    // путь -> размер при прошлой проверке стабильности (-1 — ещё не проверялся)
    readonly Dictionary<string, long> _sizes = new();
    // пути, уже поставленные в очередь сканирования (защита от дублей Created+Changed)
    readonly HashSet<string> _scanning = new();

    FileSystemWatcher _wDownloads, _wDesktop, _wTemp;
    string _downloads, _desktop, _temp;
    DispatcherTimer _mainTimer;
    int _tick;
    volatile int _diffBusy;            // 1 = уже идёт проход процессов/автозапуска
    HashSet<uint> _prevPids;           // базовый снимок процессов для диффа
    Dictionary<string, string> _prevAutorun; // базовый снимок автозапуска для диффа
    string _selfPath;
    volatile bool _started;

    const int STABLE_DELAY_SEC = 3;    // сколько ждём после последнего события
    const long MAX_RT_SIZE = 200L * 1024 * 1024; // файлы больше не сканируем в real-time (как GUI-очередь)

    // ---------- жизненный цикл ----------
    public void Start()
    {
        if (_started) return;
        _started = true;
        _selfPath = Process.GetCurrentProcess().MainModule?.FileName;
        StartWatchers();
        _mainTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _mainTimer.Tick += OnTick;
        _mainTimer.Start();
        Log("real-time protection запущен");
    }

    public void Stop()
    {
        if (!_started) return;
        _started = false;
        _mainTimer?.Stop();
        _mainTimer = null;
        StopWatchers();
        lock (_lock) { _pending.Clear(); _sizes.Clear(); _scanning.Clear(); }
        _prevPids = null;
        _prevAutorun = null;
        Log("real-time protection остановлен");
    }

    // ---------- таймер: 1 с — отложенные сканы; каждые 10 с — процессы + автозапуск ----------
    void OnTick(object s, EventArgs e)
    {
        _tick++;
        Task.Run(FlushPendingScans);
        if (_tick % 10 == 0 && Interlocked.CompareExchange(ref _diffBusy, 1, 0) == 0)
        {
            Task.Run(() =>
            {
                try { ProcessTick(); AutorunTick(); SelfDefendTick(); NetworkTick(); }
                finally { _diffBusy = 0; }
            });
        }
    }

    // ---------- самозащита: урезание DACL процесса (опция) ----------
    // Убирает у процесса права PROCESS_TERMINATE / PROCESS_VM_WRITE /
    // PROCESS_CREATE_THREAD даже для администраторов — зловред не сможет убить
    // или внедриться в антивирус. Без драйвера, работает в user-mode.
    // Переприменяется каждый тик (10 с): если зловред перезаписал DACL, мы
    // восстанавливаем его на следующем проходе.
    void SelfDefendTick()
    {
        if (!Settings.SelfDefend) return;
        try
        {
            Native.RestrictProcessDacl(System.Diagnostics.Process.GetCurrentProcess().Handle);
        }
        catch { }
    }

    // ---------- мониторинг сетевых соединений (базовый файрвол-наблюдатель) ----------
    void NetworkTick()
    {
        if (!Settings.NetworkMonitor || _lastNetScan.AddSeconds(30) > DateTime.Now) return;
        _lastNetScan = DateTime.Now;
        try
        {
            var conns = Native.GetTcpConnections();
            if (conns == null) return;
            foreach (var c in conns)
            {
                if (c.remotePort == 0 || c.state != 5) continue; // только ESTABLISHED (5)
                // известные безопасные порты
                if (c.remotePort is 80 or 443 or 53 or 22 or 21 or 25 or 993 or 995 or 587 or 465 or 8443 or 8080 or 123) continue;
                string path = Native.GetProcessPath(c.pid);
                if (path == null) continue;
                bool sus = path.IndexOf("\\temp\\", StringComparison.OrdinalIgnoreCase) >= 0
                        || path.IndexOf("\\appdata\\", StringComparison.OrdinalIgnoreCase) >= 0;
                if (sus)
                    Log($"СЕТЬ: {Path.GetFileName(path)} ({c.pid}) -> {c.remoteIp}:{c.remotePort} — подозрительное соединение из {path}");
            }
        }
        catch { }
    }
    DateTime _lastNetScan = DateTime.MinValue;

    // ==================== 1. FileSystemWatcher: Загрузки/Рабочий стол (рекурсивно) + Temp ====================
    void StartWatchers()
    {
        _downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        _desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        _temp = Path.GetTempPath();
        _wDownloads = MakeWatcher(_downloads, recursive: true);
        _wDesktop = MakeWatcher(_desktop, recursive: true);
        _wTemp = MakeWatcher(_temp, recursive: false);
        foreach (var w in new[] { _wDownloads, _wDesktop, _wTemp })
        {
            if (w == null) continue;
            try { w.EnableRaisingEvents = true; }
            catch (Exception ex) { Log($"не удалось наблюдать {w.Path}: {ex.Message}"); }
        }
    }

    void StopWatchers()
    {
        foreach (var w in new[] { _wDownloads, _wDesktop, _wTemp })
            try { w?.Dispose(); } catch { }
        _wDownloads = _wDesktop = _wTemp = null;
    }

    FileSystemWatcher MakeWatcher(string dir, bool recursive)
    {
        if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return null;
        var w = new FileSystemWatcher(dir)
        {
            InternalBufferSize = 64 * 1024, // максимум FileSystemWatcher; 64 КБ снижает риск переполнения буфера
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite
                         | NotifyFilters.CreationTime | NotifyFilters.DirectoryName,
            IncludeSubdirectories = recursive,
            EnableRaisingEvents = false,
        };
        w.Created += OnCreated;
        w.Changed += OnChanged;
        w.Renamed += OnRenamed;
        w.Error += OnError;
        return w;
    }

    void OnCreated(object s, FileSystemEventArgs e) => OnFileEvent(e.FullPath);
    void OnChanged(object s, FileSystemEventArgs e) => OnFileEvent(e.FullPath);

    // Событие ФС: ставим файл в очередь отложенного скана (ждём стабильности размера).
    void OnFileEvent(string path)
    {
        if (!IsWatchExt(path)) return;
        lock (_lock)
        {
            // Кап очереди: Temp-шум (браузеры, установщики) не должен порождать бесконечный скан
            if (_pending.Count >= 300) return;
            _pending[path] = DateTime.Now;
            _sizes[path] = -1; // сброс проверки стабильности
        }
    }

    void OnRenamed(object s, RenamedEventArgs e)
    {
        try
        {
            // Переименована папка: вложенные файлы не дают собственных событий —
            // обходим её рекурсивно и ставим найденное на скан.
            if (Directory.Exists(e.FullPath)) { Task.Run(() => WalkAndEnqueue(e.FullPath)); return; }
            OnFileEvent(e.FullPath); // переименование .crdownload -> .exe и т.п.
        }
        catch { }
    }

    // Переполнение буфера наблюдателя: события потеряны. Перезапускаем наблюдатели и
    // обходим корни заново, чтобы подобрать файлы, изменённые за последние 5 минут.
    void OnError(object s, ErrorEventArgs e)
    {
        Log("ошибка FileSystemWatcher: " + (e.GetException()?.Message ?? "переполнение буфера") + " — повторный обход");
        StopWatchers();
        StartWatchers();
        Task.Run(() =>
        {
            // Мягкий рестарт: только пересоздаём наблюдатели, БЕЗ полного рескана корней —
            // иначе переполнение буфера (Temp-шум) порождает бесконечный цикл ресканов.
            StopWatchers();
            StartWatchers();
            WalkAndRescan(_downloads, true);
            WalkAndRescan(_desktop, true);
        });
    }

    void WalkAndRescan(string root, bool recursive)
    {
        if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) return;
        try
        {
            var opts = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            var cutoff = DateTime.Now.AddMinutes(-5);
            foreach (var f in Directory.EnumerateFiles(root, "*", opts))
            {
                try
                {
                    if (IsWatchExt(f) && File.GetLastWriteTime(f) > cutoff)
                        lock (_lock) { _pending[f] = DateTime.Now; _sizes[f] = -1; }
                }
                catch { }
            }
        }
        catch { }
    }

    void WalkAndEnqueue(string dir)
    {
        try
        {
            foreach (var f in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                if (IsWatchExt(f)) EnqueueDirect(f);
        }
        catch { }
    }

    // Ставим файл на скан немедленно (файл уже стабилен). Дубль по _scanning отсекается.
    void EnqueueDirect(string path)
    {
        lock (_lock)
        {
            if (_scanning.Contains(path)) return;
            _scanning.Add(path);
        }
        Task.Run(() => ScanPath(path));
    }

    // Отложенный скан: файл попадает в работу, когда 3 с не было событий по нему
    // И размер стабилен между двумя проверками (т.е. запись завершена).
    void FlushPendingScans()
    {
        List<string> ready = null;
        lock (_lock)
        {
            var now = DateTime.Now;
            foreach (var kv in _pending.ToList())
            {
                if ((now - kv.Value).TotalSeconds < STABLE_DELAY_SEC) continue;
                long len;
                try { len = new FileInfo(kv.Key).Length; }
                catch { _pending.Remove(kv.Key); _sizes.Remove(kv.Key); continue; } // файл исчез
                long prev = _sizes.TryGetValue(kv.Key, out var p) ? p : -1;
                if (prev >= 0 && prev == len)
                {
                    // размер не меняется два тика подряд — файл дописан
                    _pending.Remove(kv.Key);
                    _sizes.Remove(kv.Key);
                    if (!_scanning.Contains(kv.Key))
                    {
                        _scanning.Add(kv.Key);
                        (ready ??= new List<string>()).Add(kv.Key);
                    }
                }
                else _sizes[kv.Key] = len; // ещё пишется — проверим на следующем тике
            }
        }
        if (ready == null) return;
        // rate-limit: не более 20 файлов за тик — Temp-шум не должен забивать CPU
        if (ready.Count > 20) ready = ready.GetRange(0, 20);
        foreach (var p in ready) Task.Run(() => ScanPath(p));
    }

    // ---------- общий скан одного файла ----------
    void ScanPath(string path)
    {
        try
        {
            if (Directory.Exists(path)) return;
            long size;
            try { size = new FileInfo(path).Length; }
            catch { return; }
            if (size > MAX_RT_SIZE) return; // гигантские файлы пропускаем
            var res = ScannerCore.ScanFile(path);
            if (res.Verdict != "clean") HandleThreat(res.File, res.ThreatType, res.Verdict);
        }
        catch (Exception ex) { Log($"ошибка сканирования {path}: {ex.Message}"); }
        finally { lock (_lock) _scanning.Remove(path); }
    }

    // ==================== 2. Новые процессы (дифф по pid каждые 10 с) ====================
    void ProcessTick()
    {
        try
        {
            var now = Native.SnapshotProcesses();
            if (_prevPids == null) { _prevPids = new HashSet<uint>(now.Select(p => p.pid)); return; } // первый проход — только база
            var newPids = now.Where(p => !_prevPids.Contains(p.pid)).Select(p => p.pid).ToList();
            _prevPids = new HashSet<uint>(now.Select(p => p.pid));
            if (newPids.Count == 0) return;

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var pid in newPids)
            {
                try
                {
                    string exe = Native.GetProcessPath(pid);
                    if (exe == null || !exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
                    if (string.Equals(exe, _selfPath, StringComparison.OrdinalIgnoreCase)) continue; // себя не сканируем
                    if (!seen.Add(exe)) continue; // несколько новых pid с одним exe — скан один раз
                    var res = ScannerCore.ScanFile(exe);
                    if (res.Verdict != "clean") HandleThreat(exe, res.ThreatType, res.Verdict, pid);
                }
                catch (Exception ex) { Log($"процесс {pid}: {ex.Message}"); }
            }
        }
        catch (Exception ex) { Log("мониторинг процессов: " + ex.Message); }
    }

    // ==================== 3. Автозапуск (реестр Run/RunOnce + Startup) ====================
    void AutorunTick()
    {
        try
        {
            var entries = CollectAutorun();
            if (_prevAutorun == null) { _prevAutorun = entries; return; } // первый проход — только база
            foreach (var kv in entries)
            {
                if (_prevAutorun.ContainsKey(kv.Key)) continue; // запись не новая
                if (!IsSuspiciousAutorun(kv.Value)) continue;
                Log($"подозрительный автозапуск: {kv.Key} = {kv.Value}");
                Dispatcher.UIThread.Post(() =>
                {
                    try
                    {
                        onThreat?.Invoke(kv.Key, "Автозапуск");
                        App.Notify?.Show(new Notification("ShadowScan RT — автозапуск",
                            kv.Key + " = " + Truncate(kv.Value, 90), NotificationType.Warning, TimeSpan.FromSeconds(6)));
                    }
                    catch { }
                });
            }
            _prevAutorun = entries;
        }
        catch (Exception ex) { Log("мониторинг автозапуска: " + ex.Message); }
    }

    // Собираем все записи автозапуска: HKCU+HKLM (Registry64) Run/RunOnce + Startup-папки.
    Dictionary<string, string> CollectAutorun()
    {
        var res = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        const string baseSub = @"Software\Microsoft\Windows\CurrentVersion";
        // OpenBaseKey + Registry64: на 64-битной ОС видим 64-битный реестр
        // (перегрузки OpenSubKey с RegistryView в пакете Microsoft.Win32.Registry нет).
        var hives = new (RegistryKey baseKey, string label)[]
        {
            (RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64), "HKCU"),
            (RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64), "HKLM"),
        };

        foreach (var (baseKey, label) in hives)
        using (baseKey)
        foreach (var name in new[] { "Run", "RunOnce" })
        {
            RegistryKey key = null;
            try { key = baseKey.OpenSubKey(baseSub + "\\" + name, false); } catch { }
            using (key)
            {
                if (key == null) continue;
                foreach (var vname in key.GetValueNames())
                {
                    try
                    {
                        if (key.GetValue(vname) is string cmd && !string.IsNullOrWhiteSpace(cmd))
                            res[$"{label}\\{name}\\{vname}"] = cmd;
                    }
                    catch { }
                }
            }
        }

        // Startup: текущий пользователь + все пользователи (CommonStartup).
        foreach (var dir in new[] { Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                                    Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup) })
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
            try
            {
                foreach (var f in Directory.EnumerateFiles(dir))
                    res["Startup\\" + Path.GetFileName(f)] = f;
            }
            catch { }
        }
        return res;
    }

    // Подозрительные паттерны в команде автозапуска (по отчёту исследователя).
    static bool IsSuspiciousAutorun(string cmd)
    {
        string c = cmd.ToLowerInvariant();
        if (c.Contains("powershell") && (c.Contains("-enc") || c.Contains("-encodedcommand"))) return true;
        if (c.Contains("mshta")) return true;
        if (c.Contains("regsvr32") && c.Contains("/s")) return true;
        if (c.Contains("%temp%") || c.Contains("%tmp%")) return true; // запуск из временной папки
        return false;
    }

    // ==================== 4. Реакция на угрозу ====================
    // malicious — ВСЕГДА карантин + уведомление (работа real-time защиты, без вопросов);
    // подозрительные скрипты — карантин при Settings.BlockDangerousScripts;
    // запущенный malicious-процесс — сначала kill, затем карантин exe.
    void HandleThreat(string path, string threatType, string verdict, uint pid = 0)
    {
        bool mal = verdict == "malicious";
        bool quarantine = mal
            || (Settings.BlockDangerousScripts && verdict == "suspicious" && IsScriptExt(path));
        Log($"УГРОЗА [{verdict}]: {path} — {threatType}" + (quarantine ? " — отправлен в карантин" : ""));

        // Запущенный опасный процесс завершаем ДО перемещения файла —
        // иначе exe заблокирован и Quarantine.File.Move не удастся.
        if (mal && pid != 0 && Settings.RealtimeEnabled) KillProcess(pid, path);

        string file = Path.GetFileName(path);
        string note = quarantine ? " — перемещён в карантин" : "";
        Dispatcher.UIThread.Post(() =>
        {
            try
            {
                onThreat?.Invoke(path, threatType);
                App.Notify?.Show(new Notification("ShadowScan RT — " + (mal ? "ОПАСНО" : "подозрительно"),
                    file + " — " + threatType + note, mal ? NotificationType.Error : NotificationType.Warning, TimeSpan.FromSeconds(6)));
            }
            catch { }
        });

        if (quarantine)
        {
            if (Quarantine.QuarantineFile(path, null, "обнаружено real-time protection", out var qres))
                Log($"карантин: {path} -> {qres}");
            else
                Log($"карантин не удался: {path} ({qres})");

            // Очистка следов: удаляем копии файла из Temp/AppData и откатываем
            // реестровые ключи автозапуска, указывающие на этот файл.
            if (mal) CleanupThreatTraces(path);
        }
    }

    // Удаляет следы зловреда: копии файла в Temp/AppData + ключи Run/RunOnce
    static void CleanupThreatTraces(string threatPath)
    {
        try
        {
            string fileName = Path.GetFileName(threatPath);
            string threatDir = Path.GetDirectoryName(threatPath) ?? "";
            var now = DateTime.Now;

            // 1. Копии в Temp и AppData с тем же именем (созданные за последние 48 ч)
            string[] dirs = { Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp") };
            foreach (var dir in dirs)
            {
                try
                {
                    if (!Directory.Exists(dir)) continue;
                    foreach (var f in Directory.EnumerateFiles(dir, fileName, SearchOption.TopDirectoryOnly))
                    {
                        if (string.Equals(Path.GetFullPath(f), Path.GetFullPath(threatPath), StringComparison.OrdinalIgnoreCase)) continue;
                        if ((now - File.GetLastWriteTime(f)).TotalHours < 48)
                        {
                            try { File.Delete(f); Log($"след удалён: {f}"); }
                            catch { }
                        }
                    }
                }
                catch { }
            }

            // 2. Реестр: Run/RunOnce (HKCU + HKLM), значения со ссылкой на файл/его папку
            string[] roots = {
                @"Software\Microsoft\Windows\CurrentVersion\Run",
                @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                @"Software\Microsoft\Windows\CurrentVersion\RunServices",
            };
            foreach (var sub in roots)
            {
                CleanRegKey(Microsoft.Win32.Registry.CurrentUser, sub, fileName, threatDir);
                CleanRegKey(Microsoft.Win32.Registry.LocalMachine, sub, fileName, threatDir);
            }
            Log($"очистка следов завершена для {threatPath}");
        }
        catch (Exception ex) { Log($"очистка следов: {ex.Message}"); }
    }

    static void CleanRegKey(Microsoft.Win32.RegistryKey hive, string sub, string fileName, string threatDir)
    {
        try
        {
            using var key = hive.OpenSubKey(sub, writable: true);
            if (key == null) return;
            foreach (var name in key.GetValueNames())
            {
                try
                {
                    string val = key.GetValue(name)?.ToString() ?? "";
                    bool hit = val.IndexOf(fileName, StringComparison.OrdinalIgnoreCase) >= 0
                        || (threatDir.Length > 3 && val.IndexOf(threatDir, StringComparison.OrdinalIgnoreCase) >= 0)
                        || (val.IndexOf("\\temp\\", StringComparison.OrdinalIgnoreCase) >= 0
                            && val.IndexOf("\\appdata\\", StringComparison.OrdinalIgnoreCase) >= 0);
                    if (hit)
                    {
                        key.DeleteValue(name, throwOnMissingValue: false);
                        Log($"реестр откачен: {hive} \\ {sub} \\ {name} = {Truncate(val, 80)}");
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    // Завершение опасного процесса (NativeAOT-совместимо: Process.Kill, без System.Management).
    static void KillProcess(uint pid, string path)
    {
        try
        {
            var p = Process.GetProcessById((int)pid);
            p.Kill();
            Log($"опасный процесс завершён (pid {pid}): {path}");
        }
        catch (Exception ex) { Log($"не удалось завершить процесс {pid}: {ex.Message}"); }
    }

    // ==================== лог ====================
    static void Log(string msg)
    {
        try
        {
            File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "shadowscan.log"),
                $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [RT] {msg}{Environment.NewLine}");
        }
        catch { }
    }

    static string Truncate(string s, int n)
    {
        if (s == null) return "";
        return s.Length <= n ? s : s.Substring(0, n - 3) + "...";
    }

    /// <summary>Краткий список автозагрузок: (имя, команда, источник). Полная логика — в Autoruns.Collect().</summary>
    public static List<(string Name, string Command, string Location)> CollectAutoruns()
        => Autoruns.CollectAutoruns().Select(i => (i.Name, i.Command, i.Location)).ToList();
}
