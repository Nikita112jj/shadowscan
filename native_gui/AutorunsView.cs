// ShadowScan Native — Автозагрузки (аналог Sysinternals Autoruns).
// Источники: реестр Run/RunOnce (HKCU + HKLM, включая Wow6432Node через 32-битный вид),
// папки автозагрузки пользователя и общие, Winlogon Shell/Userinit,
// службы (Start=2), драйверы (Start=0/1), планировщик задач, AppInit_DLLs, BootExecute.
//
// Механика отключения/включения (своя, надёжная):
//  - реестровые значения переносятся в служебный ключ
//    HKCU\Software\ShadowScan\DisabledAutoruns\<hive>[.wow64]\<subPath> (то же имя значения,
//    с сохранением типа) и удаляются из оригинала; «Включить» возвращает обратно;
//  - файлы Startup/задач переименовываются в <name>.disabled и обратно;
//  - службы: Start 2→3 (Manual); драйверы: Start →4 (Disabled). Исходный Start
//    сохраняется в HKCU\...\DisabledAutoruns\SVC|DRV\<имя службы> и восстанавливается.
//
// Подписи: только наличие Authenticode-сертификата в файле (быстро, без проверки цепочки).
// NativeAOT-совместимо: только Microsoft.Win32.Registry, без reflection.
// ВНИМАНИЕ: классы в ГЛОБАЛЬНОМ namespace — как весь остальной движок
// (типы из именованных namespace под NativeAOT+шаблоны давали краш).
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Styling;
using Avalonia.Threading;
using Microsoft.Win32;

namespace ShadowScanNative;

// ==================== тип записи автозагрузки ====================
public enum AutorunKind
{
    RegValue = 0,    // значение Run/RunOnce
    StartupFile = 1, // файл в папке автозагрузки
    Winlogon = 2,    // Shell/Userinit (только просмотр)
    Service = 3,     // служба WIN32_SERVICE с Start=2
    Driver = 4,      // драйвер Start=0/1
    Task = 5,        // задача планировщика
    AppInit = 6,     // AppInit_DLLs (только просмотр)
    BootExecute = 7, // BootExecute (только просмотр)
}

// ==================== модель записи автозагрузки ====================
public class AutorunEntry
{
    public string Name;        // имя значения в реестре / имя файла / имя службы / путь задачи
    public string Command;     // команда (значение реестра) или полный путь файла
    public string Location;    // откуда: "HKCU: Run", "Service", "Driver", "Task", "Winlogon" ...
    public string ImagePath;   // извлечённый exe из Command (без кавычек и аргументов)
    public bool Suspicious;    // Winlogon: нестандартное значение / wscript/powershell

    public AutorunKind Kind;   // тип записи — определяет механику включения/отключения
    public bool Disabled;      // отключено через ShadowScan
    public bool SystemProtected; // только просмотр (Winlogon, задачи Microsoft, AppInit, BootExecute)
    public string OriginalPath;  // где лежало до отключения (путь раздела/файла для восстановления)
    public string Signature;     // "✓ компания" | "—" | "" (нет файла)

    // данные для удаления/переключения реестровых записей (null = недоступно):
    public string RegHive;     // "HKCU" или "HKLM"
    public string RegKeyPath;  // путь раздела внутри куста
    public string RegValue;    // имя значения
    public bool RegWow64;      // хранится в Wow6432Node (32-битный вид реестра)
    public string FilePath;    // текущий полный путь файла (Startup / Task)

    // данные для служб/драйверов:
    public string ServiceName;    // имя раздела в SYSTEM\CurrentControlSet\Services
    public int ServiceStart = -1; // исходный Start для восстановления при включении

    public bool CanDelete =>
        (Kind == AutorunKind.RegValue && RegKeyPath != null && RegValue != null) ||
        (Kind == AutorunKind.StartupFile && FilePath != null);

    /// <summary>Можно переключать Вкл/Откл (кнопка выбирается по Disabled).</summary>
    public bool CanToggle => !SystemProtected &&
        ((Kind == AutorunKind.RegValue && RegKeyPath != null && RegValue != null) ||
         (Kind == AutorunKind.StartupFile && FilePath != null) ||
         (Kind == AutorunKind.Task && FilePath != null) ||
         Kind == AutorunKind.Service ||
         Kind == AutorunKind.Driver);

    /// <summary>"Вкл" / "Откл" / "Сист." для колонки «Состояние».</summary>
    public string StateText => Disabled ? "Откл" : SystemProtected ? "Сист." : "Вкл";
}

// ==================== сбор, удаление, включение/отключение ====================
public static class Autoruns
{
    const string RunPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    const string RunOncePath = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";
    const string WinlogonPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    const string ServicesPath = @"SYSTEM\CurrentControlSet\Services";
    const string SessionManagerPath = @"SYSTEM\CurrentControlSet\Control\Session Manager";
    const string AppInitPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
    // хранилище отключённых записей: <root>\<hive>[.wow64]\<subPath> — скопированные значения;
    // <root>\SVC\<имя> и <root>\DRV\<имя> — исходный Start служб/драйверов.
    const string StorageRoot = @"Software\ShadowScan\DisabledAutoruns";
    const string DisabledSuffix = ".disabled";

    /// <summary>Краткий список: (имя, команда, источник, путь к exe).</summary>
    public static List<(string Name, string Command, string Location, string ImagePath)> CollectAutoruns()
        => Collect().Select(i => (i.Name, i.Command, i.Location, i.ImagePath)).ToList();

    /// <summary>Полный список со всеми источниками и данными для удаления/переключения.</summary>
    public static List<AutorunEntry> Collect()
    {
        var list = new List<AutorunEntry>();
        try
        {
            // 1. Реестр Run / RunOnce: HKCU + HKLM (оба), на 64-битной ОС ещё 32-битный вид HKLM
            AddRegKey(list, RegistryHive.CurrentUser, false, "HKCU", RunPath, "Run");
            AddRegKey(list, RegistryHive.CurrentUser, false, "HKCU", RunOncePath, "RunOnce");
            AddRegKey(list, RegistryHive.LocalMachine, false, "HKLM", RunPath, "Run");
            AddRegKey(list, RegistryHive.LocalMachine, false, "HKLM", RunOncePath, "RunOnce");
            if (Environment.Is64BitOperatingSystem)
            {
                AddRegKey(list, RegistryHive.LocalMachine, true, "HKLM", RunPath, "Run");
                AddRegKey(list, RegistryHive.LocalMachine, true, "HKLM", RunOncePath, "RunOnce");
            }

            // 1a. Отключённые нами значения из служебного хранилища
            AddDisabledRegCopies(list);

            // 2. Папки автозагрузки: пользовательская и общая (включая *.disabled)
            AddStartupDir(list, Environment.GetFolderPath(Environment.SpecialFolder.Startup), "Startup: пользователь");
            AddStartupDir(list, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Startup: общая");

            // 3. Winlogon Shell / Userinit (только пометка)
            AddWinlogon(list);

            // 4. Службы (Start=2) и драйверы (Start=0/1)
            AddServicesAndDrivers(list);

            // 5. Планировщик задач (задачи \Microsoft\ — только просмотр)
            AddScheduledTasks(list);

            // 6. AppInit_DLLs (+WOW64) и Boot Execute — только просмотр
            AddAppInit(list);
            AddBootExecute(list);
        }
        catch { /* сбор опционален: любые сбои не роняют GUI */ }

        // подпись: наличие сертификата в ImagePath (выполняется в фоновом потоке Collect)
        foreach (var e in list)
            e.Signature = GetSignature(e.ImagePath);

        return list.OrderBy(x => x.Location, StringComparer.OrdinalIgnoreCase)
                   .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Удаление записи (значение реестра или файл Startup). Возвращает true при успехе.</summary>
    public static bool Delete(AutorunEntry e, out string error)
    {
        error = "";
        try
        {
            if (e.Kind == AutorunKind.StartupFile && e.FilePath != null)
            {
                if (!File.Exists(e.FilePath)) { error = "Файл не найден: " + e.FilePath; return false; }
                File.Delete(e.FilePath);
                return true;
            }
            if (e.Kind == AutorunKind.RegValue && e.RegKeyPath != null && e.RegValue != null)
            {
                using var baseKey = RegistryKey.OpenBaseKey(ParseHive(e.RegHive), e.RegWow64 ? RegistryView.Registry32 : RegistryView.Default);
                using var key = baseKey.OpenSubKey(e.RegKeyPath, writable: true);
                if (key == null) { error = "Раздел реестра не найден: " + e.RegKeyPath; return false; }
                key.DeleteValue(e.RegValue, throwOnMissingValue: false);
                return true;
            }
            error = "Этот элемент защищён системой — удаление недоступно (можно отключить).";
            return false;
        }
        catch (Exception ex) { error = ex.Message; return false; }
    }

    /// <summary>
    /// Включение/отключение записи. Механика зависит от типа:
    /// RegValue — перенос значения в служебное хранилище и обратно;
    /// StartupFile/Task — переименование в *.disabled и обратно;
    /// Service — Start 2→3; Driver — Start →4 (исходный Start хранится в хранилище).
    /// </summary>
    public static bool SetDisabled(AutorunEntry e, bool disable, out string error)
    {
        error = "";
        try
        {
            if (!e.CanToggle) { error = "Эта запись защищена системой — переключение недоступно."; return false; }
            switch (e.Kind)
            {
                case AutorunKind.RegValue:
                    return ToggleRegValue(e, disable, out error);
                case AutorunKind.StartupFile:
                case AutorunKind.Task:
                    return ToggleFileRename(e, disable, out error);
                case AutorunKind.Service:
                case AutorunKind.Driver:
                    return ToggleService(e, disable, out error);
                default:
                    error = "Этот тип записи нельзя включать/отключать.";
                    return false;
            }
        }
        catch (Exception ex) { error = ex.Message + " (возможно, нужны права администратора)"; return false; }
    }

    // ---------- включение/отключение: реестровые значения ----------
    static bool ToggleRegValue(AutorunEntry e, bool disable, out string error)
    {
        error = "";
        var opts = RegistryValueOptions.DoNotExpandEnvironmentNames;
        using var bOrig = RegistryKey.OpenBaseKey(ParseHive(e.RegHive), e.RegWow64 ? RegistryView.Registry32 : RegistryView.Default);
        using var origKey = bOrig.OpenSubKey(e.RegKeyPath, writable: true);
        if (origKey == null) { error = "Раздел недоступен: " + e.RegKeyPath; return false; }
        string storageSub = StorageSubKey(e);

        if (disable)
        {
            var val = origKey.GetValue(e.RegValue, null, opts);
            if (val == null) { error = "Значение не найдено: " + e.RegValue; return false; }
            var kind = origKey.GetValueKind(e.RegValue);
            using (var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default))
            using (var st = hkcu.CreateSubKey(storageSub))
            {
                if (st.GetValueNames().Any(n => string.Equals(n, e.RegValue, StringComparison.OrdinalIgnoreCase)))
                { error = "Запись уже отключена."; return false; }
                st.SetValue(e.RegValue, val, kind); // копия с тем же именем и типом
            }
            origKey.DeleteValue(e.RegValue, throwOnMissingValue: false);
            e.Disabled = true;
            e.OriginalPath = e.RegHive + @"\" + e.RegKeyPath;
            return true;
        }
        else
        {
            object val;
            RegistryValueKind kind;
            using (var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default))
            using (var st = hkcu.OpenSubKey(storageSub))
            {
                if (st == null) { error = "В хранилище нет записи — вернуть нельзя."; return false; }
                val = st.GetValue(e.RegValue, null, opts);
                if (val == null) { error = "В хранилище нет значения " + e.RegValue; return false; }
                kind = st.GetValueKind(e.RegValue);
            }
            origKey.SetValue(e.RegValue, val, kind); // возврат на место
            RemoveStoredValue(e);
            e.Disabled = false;
            e.OriginalPath = null;
            return true;
        }
    }

    static string StorageSubKey(AutorunEntry e)
        => StorageRoot + @"\" + e.RegHive + (e.RegWow64 ? ".wow64" : "") + @"\" + e.RegKeyPath;

    /// <summary>Удалить скопированное значение из хранилища и подчистить опустевшие разделы.</summary>
    static void RemoveStoredValue(AutorunEntry e)
    {
        try
        {
            string storageSub = StorageSubKey(e);
            using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using (var st = hkcu.OpenSubKey(storageSub, writable: true))
            {
                if (st != null) st.DeleteValue(e.RegValue, throwOnMissingValue: false);
            }
            string path = storageSub;
            while (!string.IsNullOrEmpty(path) && path.Length > StorageRoot.Length &&
                   !path.Equals(StorageRoot, StringComparison.OrdinalIgnoreCase))
            {
                var k = hkcu.OpenSubKey(path, writable: true);
                if (k == null) break;
                bool empty = k.SubKeyCount == 0 && k.ValueCount == 0;
                k.Close();
                if (!empty) break;
                try { hkcu.DeleteSubKeyTree(path, false); } catch { break; }
                int idx = path.LastIndexOf('\\');
                if (idx < 0) break;
                path = path.Substring(0, idx);
            }
        }
        catch { /* чистка опциональна */ }
    }

    // ---------- включение/отключение: файлы Startup и задач ----------
    static bool ToggleFileRename(AutorunEntry e, bool disable, out string error)
    {
        error = "";
        try
        {
            if (disable)
            {
                string src = e.FilePath;
                if (src == null || !File.Exists(src)) { error = "Файл не найден: " + src; return false; }
                if (src.EndsWith(DisabledSuffix, StringComparison.OrdinalIgnoreCase)) { error = "Запись уже отключена."; return false; }
                string dst = src + DisabledSuffix;
                if (File.Exists(dst)) { error = "Целевой файл уже существует: " + dst; return false; }
                File.Move(src, dst);
                e.Disabled = true;
                e.OriginalPath = src;
                e.FilePath = dst;
                return true;
            }
            else
            {
                string src = e.FilePath;
                string dst = e.OriginalPath;
                if (dst == null && src != null && src.EndsWith(DisabledSuffix, StringComparison.OrdinalIgnoreCase))
                    dst = src.Substring(0, src.Length - DisabledSuffix.Length);
                if (src == null || dst == null) { error = "Нет данных для восстановления."; return false; }
                if (!File.Exists(src)) { error = "Файл не найден: " + src; return false; }
                if (File.Exists(dst)) { error = "Место занято: " + dst; return false; }
                File.Move(src, dst);
                e.Disabled = false;
                e.FilePath = dst;
                e.OriginalPath = null;
                return true;
            }
        }
        catch (Exception ex) { error = ex.Message + " (возможно, нужны права администратора)"; return false; }
    }

    // ---------- включение/отключение: службы и драйверы ----------
    static bool ToggleService(AutorunEntry e, bool disable, out string error)
    {
        error = "";
        bool driver = e.Kind == AutorunKind.Driver;
        string sub = ServicesPath + @"\" + e.ServiceName;
        string marker = StorageRoot + @"\" + (driver ? "DRV" : "SVC") + @"\" + e.ServiceName;
        using var bLm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = bLm.OpenSubKey(sub, writable: true);
        if (key == null) { error = "Раздел службы недоступен: " + sub; return false; }

        if (disable)
        {
            int cur = AsInt(key.GetValue("Start"));
            if (cur < 0) { error = "Не удалось прочитать Start службы " + e.ServiceName; return false; }
            using (var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default))
            using (var mk = hkcu.CreateSubKey(marker))
                mk.SetValue("Start", cur, RegistryValueKind.DWord); // запомнить исходный
            key.SetValue("Start", driver ? 4 : 3, RegistryValueKind.DWord); // 4=Disabled, 3=Manual
            e.Disabled = true;
            e.OriginalPath = @"HKLM\" + sub;
            e.ServiceStart = cur;
            return true;
        }
        else
        {
            int orig;
            using (var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default))
            using (var mk = hkcu.OpenSubKey(marker))
                orig = mk != null ? AsInt(mk.GetValue("Start")) : -1;
            if (orig < 0) orig = driver ? 1 : 2; // запасной вариант: SERVICE_AUTO_START
            key.SetValue("Start", orig, RegistryValueKind.DWord);
            try
            {
                using var hkcu2 = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
                hkcu2.DeleteSubKeyTree(marker, false); // метка больше не нужна
            }
            catch { }
            e.Disabled = false;
            e.OriginalPath = null;
            e.ServiceStart = orig;
            return true;
        }
    }

    static bool ReadSvcMarker(string kindDir, string name, out int orig)
    {
        orig = -1;
        try
        {
            using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using var k = hkcu.OpenSubKey(StorageRoot + @"\" + kindDir + @"\" + name);
            if (k == null) return false;
            orig = AsInt(k.GetValue("Start"));
            return true;
        }
        catch { return false; }
    }

    // ---------- реестр Run/RunOnce ----------
    static void AddRegKey(List<AutorunEntry> list, RegistryHive hive, bool wow64, string hiveName, string subPath, string keyLabel)
    {
        try
        {
            var view = wow64 ? RegistryView.Registry32 : RegistryView.Default;
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var key = baseKey.OpenSubKey(subPath);
            if (key == null) return;
            var loc = FriendlyRegLoc(subPath, hiveName, wow64);
            foreach (var name in key.GetValueNames())
            {
                try
                {
                    var kind = key.GetValueKind(name);
                    if (kind != RegistryValueKind.String && kind != RegistryValueKind.ExpandString) continue;
                    var cmd = key.GetValue(name)?.ToString();
                    if (string.IsNullOrWhiteSpace(cmd)) continue;
                    list.Add(new AutorunEntry
                    {
                        Name = name,
                        Command = cmd,
                        Location = loc,
                        ImagePath = ExtractExe(cmd),
                        Kind = AutorunKind.RegValue,
                        RegHive = hiveName,
                        RegKeyPath = subPath,
                        RegValue = name,
                        RegWow64 = wow64,
                    });
                }
                catch { /* отдельное значение может быть повреждено — пропускаем */ }
            }
        }
        catch { /* раздел может отсутствовать — это нормально */ }
    }

    static string FriendlyRegLoc(string subPath, string hiveName, bool wow)
    {
        string label = subPath.Equals(RunPath, StringComparison.OrdinalIgnoreCase) ? "Run"
            : subPath.Equals(RunOncePath, StringComparison.OrdinalIgnoreCase) ? "RunOnce"
            : subPath;
        return hiveName + ": " + label + (wow ? " (WOW64)" : "");
    }

    // ---------- отключённые значения из хранилища ----------
    static void AddDisabledRegCopies(List<AutorunEntry> list)
    {
        try
        {
            using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using var root = hkcu.OpenSubKey(StorageRoot);
            if (root == null) return;
            foreach (var hiveDir in root.GetSubKeyNames())
            {
                if (hiveDir == "SVC" || hiveDir == "DRV") continue; // маркеры служб — не значения
                try
                {
                    bool wow = hiveDir.EndsWith(".wow64", StringComparison.OrdinalIgnoreCase);
                    string hiveName = wow ? hiveDir.Substring(0, hiveDir.Length - 6) : hiveDir;
                    using var hiveKey = root.OpenSubKey(hiveDir);
                    if (hiveKey == null) continue;
                    WalkStoredValues(list, hiveKey, hiveName, wow, "");
                }
                catch { }
            }
        }
        catch { /* хранилища может не быть — нормально */ }
    }

    static void WalkStoredValues(List<AutorunEntry> list, RegistryKey key, string hiveName, bool wow, string prefix)
    {
        try
        {
            foreach (var name in key.GetValueNames())
            {
                try
                {
                    var kind = key.GetValueKind(name);
                    if (kind != RegistryValueKind.String && kind != RegistryValueKind.ExpandString) continue;
                    var cmd = key.GetValue(name)?.ToString();
                    if (string.IsNullOrWhiteSpace(cmd)) continue;
                    list.Add(new AutorunEntry
                    {
                        Name = name,
                        Command = cmd,
                        Location = FriendlyRegLoc(prefix, hiveName, wow) + " (отключено)",
                        ImagePath = ExtractExe(cmd),
                        Kind = AutorunKind.RegValue,
                        Disabled = true,
                        OriginalPath = hiveName + @"\" + prefix,
                        RegHive = hiveName,
                        RegKeyPath = prefix,
                        RegValue = name,
                        RegWow64 = wow,
                    });
                }
                catch { }
            }
        }
        catch { }
        try
        {
            foreach (var sub in key.GetSubKeyNames())
            {
                try
                {
                    using var sk = key.OpenSubKey(sub);
                    if (sk == null) continue;
                    WalkStoredValues(list, sk, hiveName, wow, prefix.Length == 0 ? sub : prefix + "\\" + sub);
                }
                catch { }
            }
        }
        catch { }
    }

    // ---------- папки Startup ----------
    static void AddStartupDir(List<AutorunEntry> list, string dir, string loc)
    {
        try
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;
            foreach (var f in Directory.EnumerateFiles(dir).OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    var ext = Path.GetExtension(f).ToLowerInvariant();
                    bool disabled = ext == DisabledSuffix;
                    // ".exe.disabled" — рабочий расширением считаем внутреннее
                    var effExt = disabled ? Path.GetExtension(Path.GetFileNameWithoutExtension(f))?.ToLowerInvariant() ?? "" : ext;
                    if (effExt != ".lnk" && effExt != ".exe" && effExt != ".bat" && effExt != ".cmd" && effExt != ".vbs" && effExt != ".ps1") continue;
                    list.Add(new AutorunEntry
                    {
                        Name = Path.GetFileName(f),
                        Command = f,
                        Location = loc + (disabled ? " (отключено)" : ""),
                        ImagePath = f,
                        Kind = AutorunKind.StartupFile,
                        FilePath = f,
                        Disabled = disabled,
                        OriginalPath = disabled ? f.Substring(0, f.Length - DisabledSuffix.Length) : null,
                    });
                }
                catch { }
            }
        }
        catch { /* папка может быть недоступна */ }
    }

    // ---------- Winlogon ----------
    static void AddWinlogon(List<AutorunEntry> list)
    {
        try
        {
            RegistryKey key = null;
            using (var b64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                key = b64.OpenSubKey(WinlogonPath);
            if (key == null)
            {
                using var b32 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
                key = b32.OpenSubKey(WinlogonPath);
            }
            using (key)
            {
                if (key == null) return;
                AddWinlogonValue(list, key, "Shell", isShell: true);
                AddWinlogonValue(list, key, "Userinit", isShell: false);
            }
        }
        catch { }
    }

    static void AddWinlogonValue(List<AutorunEntry> list, RegistryKey key, string name, bool isShell)
    {
        try
        {
            var v = key.GetValue(name)?.ToString();
            if (string.IsNullOrWhiteSpace(v)) return;
            var susp = isShell
                ? !v.Trim().Equals("explorer.exe", StringComparison.OrdinalIgnoreCase)
                : !Path.GetFileName(v.Split(',')[0].Trim()).Equals("userinit.exe", StringComparison.OrdinalIgnoreCase);
            list.Add(new AutorunEntry
            {
                Name = name,
                Command = v,
                Location = "Winlogon" + (susp ? " (подозрительно)" : ""),
                ImagePath = ExtractExe(v),
                Kind = AutorunKind.Winlogon,
                Suspicious = susp,
                SystemProtected = true,
            });
        }
        catch { }
    }

    // ---------- службы (Start=2) и драйверы (Start=0/1) ----------
    static void AddServicesAndDrivers(List<AutorunEntry> list)
    {
        try
        {
            using var b64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = b64.OpenSubKey(ServicesPath);
            if (key == null) return;
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            foreach (var svc in key.GetSubKeyNames())
            {
                try
                {
                    using var sk = key.OpenSubKey(svc);
                    if (sk == null) continue;
                    int start = AsInt(sk.GetValue("Start"));
                    int type = AsInt(sk.GetValue("Type"));
                    if (start < 0 || type < 0) continue;
                    string rawImg = sk.GetValue("ImagePath")?.ToString() ?? "";
                    bool isDriver = type >= 1 && type <= 3;   // SERVICE_KERNEL_DRIVER / FILE_SYSTEM_DRIVER
                    bool isWin32 = (type & 0x10) != 0;        // WIN32_OWN_PROCESS / SHARE_PROCESS

                    if (isWin32 && !isDriver)
                    {
                        // автозагрузка служб: Automatic (2). Manual (3) показываем только если
                        // отключили мы — есть метка в хранилище (иначе сотни системных Manual-служб).
                        if (start == 2)
                            AddServiceEntry(list, svc, rawImg, winDir, driver: false, disabled: false, origStart: start);
                        else if (start == 3 && ReadSvcMarker("SVC", svc, out int orig))
                            AddServiceEntry(list, svc, rawImg, winDir, driver: false, disabled: true, origStart: orig < 0 ? 2 : orig);
                    }
                    else if (isDriver)
                    {
                        // драйверы: Boot/System (0/1). Disabled (4) показываем только наши (с меткой).
                        if (start == 0 || start == 1)
                            AddServiceEntry(list, svc, rawImg, winDir, driver: true, disabled: false, origStart: start);
                        else if (start == 4 && ReadSvcMarker("DRV", svc, out int orig2))
                            AddServiceEntry(list, svc, rawImg, winDir, driver: true, disabled: true, origStart: orig2 < 0 ? 1 : orig2);
                    }
                }
                catch { /* отдельная служба может читаться с ошибкой */ }
            }
        }
        catch { }
    }

    static void AddServiceEntry(List<AutorunEntry> list, string name, string rawImage, string winDir, bool driver, bool disabled, int origStart)
    {
        string cmd = SafeExpand(rawImage);
        list.Add(new AutorunEntry
        {
            Name = name,
            Command = cmd,
            Location = (driver ? "Driver" : "Service") + (disabled ? " (отключено)" : ""),
            ImagePath = NormalizeImagePath(cmd, winDir),
            Kind = driver ? AutorunKind.Driver : AutorunKind.Service,
            ServiceName = name,
            ServiceStart = origStart,
            Disabled = disabled,
            OriginalPath = disabled ? @"HKLM\" + ServicesPath + @"\" + name : null,
        });
    }

    /// <summary>Разворачивает %SystemRoot%, "\SystemRoot\", "\??\" и относительные пути к exe.</summary>
    static string NormalizeImagePath(string cmd, string winDir)
    {
        try
        {
            var exe = ExtractExe(cmd);
            if (string.IsNullOrEmpty(exe)) return "";
            if (exe.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
                exe = exe.Substring(4);
            if (exe.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                exe = Path.Combine(winDir, exe.Substring(12));
            else if (exe.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase))
                exe = Path.Combine(winDir, exe);
            return exe;
        }
        catch { return ""; }
    }

    // ---------- планировщик задач ----------
    static void AddScheduledTasks(List<AutorunEntry> list)
    {
        try
        {
            string root = Path.Combine(Environment.SystemDirectory, "Tasks");
            if (!Directory.Exists(root)) return;
            WalkTasks(list, root, "", depth: 0);
        }
        catch { }
    }

    static void WalkTasks(List<AutorunEntry> list, string dir, string relPrefix, int depth)
    {
        try
        {
            foreach (var f in Directory.EnumerateFiles(dir))
            {
                try
                {
                    string rel = relPrefix.Length == 0 ? Path.GetFileName(f) : relPrefix + "\\" + Path.GetFileName(f);
                    AddTaskFile(list, f, rel);
                }
                catch { }
            }
        }
        catch { /* доступ к подпапкам задач часто запрещён — нормально */ }
        if (depth >= 8) return;
        try
        {
            foreach (var d in Directory.EnumerateDirectories(dir))
            {
                try
                {
                    string rel = relPrefix.Length == 0 ? Path.GetFileName(d) : relPrefix + "\\" + Path.GetFileName(d);
                    WalkTasks(list, d, rel, depth + 1);
                }
                catch { }
            }
        }
        catch { }
    }

    static void AddTaskFile(List<AutorunEntry> list, string path, string relName)
    {
        try
        {
            var fi = new FileInfo(path);
            if (fi.Length == 0 || fi.Length > 512 * 1024) return;
            byte[] bytes = File.ReadAllBytes(path);
            if (bytes.Length < 4) return;
            // задачи планировщика часто в UTF-16: BOM FFFE либо "<\0?\0"
            bool utf16 = (bytes[0] == 0xFF && bytes[1] == 0xFE) || (bytes[0] == '<' && bytes[1] == 0);
            string text = utf16 ? Encoding.Unicode.GetString(bytes) : Encoding.UTF8.GetString(bytes);
            string cmd = ExtractXmlTag(text, "Command");
            if (cmd == null) return; // нет <Command> — это не задача
            string args = ExtractXmlTag(text, "Arguments");
            string full = cmd.Trim() + (string.IsNullOrWhiteSpace(args) ? "" : " " + args.Trim());

            bool disabled = path.EndsWith(DisabledSuffix, StringComparison.OrdinalIgnoreCase);
            bool ms = relName.StartsWith(@"Microsoft\", StringComparison.OrdinalIgnoreCase);
            list.Add(new AutorunEntry
            {
                Name = relName,
                Command = full,
                Location = "Task" + (disabled ? " (отключено)" : ""),
                ImagePath = SafeExpand(cmd.Trim()),
                Kind = AutorunKind.Task,
                FilePath = path,
                Disabled = disabled,
                OriginalPath = disabled ? path.Substring(0, path.Length - DisabledSuffix.Length) : null,
                // задачи Microsoft трогать нельзя — только просмотр
                SystemProtected = ms,
            });
        }
        catch { }
    }

    /// <summary>Содержимое простого XML-тега "&lt;tag&gt;...&lt;/tag&gt;" (без полного парсинга).</summary>
    static string ExtractXmlTag(string text, string tag)
    {
        try
        {
            int open = text.IndexOf("<" + tag + ">", StringComparison.Ordinal);
            if (open < 0) return null;
            int start = open + tag.Length + 2;
            int close = text.IndexOf("</" + tag + ">", start, StringComparison.Ordinal);
            if (close < 0) return null;
            return text.Substring(start, close - start).Trim();
        }
        catch { return null; }
    }

    // ---------- AppInit_DLLs ----------
    static void AddAppInit(List<AutorunEntry> list)
    {
        AddAppInitView(list, RegistryView.Registry64, false, "AppInit_DLLs");
        if (Environment.Is64BitOperatingSystem)
            AddAppInitView(list, RegistryView.Registry32, true, "AppInit_DLLs (WOW64)");
    }

    static void AddAppInitView(List<AutorunEntry> list, RegistryView view, bool wow, string label)
    {
        try
        {
            using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var k = b.OpenSubKey(AppInitPath);
            var v = k?.GetValue("AppInit_DLLs")?.ToString();
            if (string.IsNullOrWhiteSpace(v)) return;
            string first = v.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
            list.Add(new AutorunEntry
            {
                Name = "AppInit_DLLs",
                Command = v,
                Location = label,
                ImagePath = SafeExpand(first),
                Kind = AutorunKind.AppInit,
                SystemProtected = true, // только просмотр
            });
        }
        catch { }
    }

    // ---------- Boot Execute ----------
    static void AddBootExecute(List<AutorunEntry> list)
    {
        try
        {
            using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var k = b.OpenSubKey(SessionManagerPath);
            if (k == null) return;
            var v = k.GetValue("BootExecute");
            if (v == null) return;
            string text = v is string[] arr ? string.Join(" ; ", arr) : v.ToString() ?? "";
            if (string.IsNullOrWhiteSpace(text)) return;
            // "autocheck autochk *" → образ autochk.exe (легальное значение, но показываем)
            string img = "";
            try
            {
                var parts = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                {
                    var cand = parts[1];
                    if (!cand.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) cand += ".exe";
                    img = Path.Combine(Environment.SystemDirectory, cand);
                }
            }
            catch { }
            list.Add(new AutorunEntry
            {
                Name = "BootExecute",
                Command = text,
                Location = "Boot Execute",
                ImagePath = img,
                Kind = AutorunKind.BootExecute,
                SystemProtected = true, // только просмотр
                Suspicious = !text.Contains("autocheck", StringComparison.OrdinalIgnoreCase),
            });
        }
        catch { }
    }

    // ---------- подпись (наличие Authenticode, без проверки цепочки) ----------
    static string GetSignature(string imagePath)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(imagePath)) return "";
            string p = imagePath;
            if (!Path.IsPathRooted(p))
            {
                p = Path.Combine(Environment.SystemDirectory, p); // "explorer.exe" → system32
                if (!File.Exists(p)) return "";
            }
            else if (!File.Exists(p)) return "";

            var cert2 = new X509Certificate2(X509Certificate.CreateFromSignedFile(p)); // бросает, если подписи нет
            var cn = cert2.GetNameInfo(X509NameType.SimpleName, false);
            return string.IsNullOrWhiteSpace(cn) ? "✓" : "✓ " + cn;
        }
        catch { return "—"; } // файла нет подписи / файл отсутствует
    }

    // ---------- вспомогательные ----------
    static RegistryHive ParseHive(string hive) => hive == "HKLM" ? RegistryHive.LocalMachine : RegistryHive.CurrentUser;

    static int AsInt(object v)
    {
        try { return Convert.ToInt32(v); } catch { return -1; }
    }

    static string SafeExpand(string s)
    {
        try { return Environment.ExpandEnvironmentVariables(s ?? "") ?? ""; } catch { return s ?? ""; }
    }

    // ---------- извлечение exe из команды ----------
    static string ExtractExe(string cmd)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(cmd)) return "";
            cmd = cmd.Trim();
            string exe;
            if (cmd.StartsWith("\""))
            {
                var end = cmd.IndexOf('"', 1);
                exe = end < 0 ? cmd.Substring(1) : cmd.Substring(1, end - 1);
            }
            else
            {
                var sp = cmd.IndexOf(' ');
                exe = sp < 0 ? cmd : cmd.Substring(0, sp);
            }
            exe = Environment.ExpandEnvironmentVariables(exe).Trim();
            return string.IsNullOrEmpty(exe) ? "" : exe;
        }
        catch { return ""; }
    }
}
