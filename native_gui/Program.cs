// ShadowScan Native — единый нативный exe (Avalonia 11.2 GUI + ScannerCore, NativeAOT).
// Весь GUI строится кодом без XAML: тёмная тема, иконки Lucide, бейджи вердиктов,
// трей, уведомления, настройки, журнал и карантин.
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Collections;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Controls.Notifications;
using Avalonia.Controls.Templates;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform.Storage;
using Avalonia.Styling;
using Avalonia.Themes.Fluent;
using Avalonia.Threading;

namespace ShadowScanNative;

[System.Text.Json.Serialization.JsonSourceGenerationOptions(IncludeFields = true, PropertyNameCaseInsensitive = true)]
[System.Text.Json.Serialization.JsonSerializable(typeof(List<ScanResult>))]
[System.Text.Json.Serialization.JsonSerializable(typeof(List<QuarantineEntry>))]
[System.Text.Json.Serialization.JsonSerializable(typeof(Settings))]
internal partial class ScanJsonContext : System.Text.Json.Serialization.JsonSerializerContext
{
}

class Program
{
    // Единственный экземпляр: повторный запуск не плодит процессы, а активирует окно.
    static Mutex _singleInstance;

    static void Main(string[] args)
    {
        // Ловушка крашей: полный стек в crash.log рядом с exe (NativeAOT без отладчика)
        try
        {
            string crashPath = System.IO.Path.Combine(AppContext.BaseDirectory, "crash.log");
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            {
                try { File.WriteAllText(crashPath, DateTime.Now + " UNHANDLED\r\n" + (e.ExceptionObject as Exception)); } catch { }
            };
            System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (s, e) =>
            {
                try { File.AppendAllText(crashPath, DateTime.Now + " UNOBSERVED TASK\r\n" + e.Exception); } catch { }
                e.SetObserved();
            };
        }
        catch { }
        EnsureNativeLibs();
        ScannerCore.LoadExternalSignatures();
        ScannerCore.InitYara();
        if (args.Length > 0 && args[0] == "--scan")
        {
            AttachConsole(-1); // родительская консоль (cmd/powershell)
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            var files = args.Skip(1).ToList();
            var results = new List<ScanResult>();
            foreach (var p in files)
            {
                try { results.Add(ScannerCore.ScanFile(p)); }
                catch (Exception ex) { results.Add(ScannerCore.ErrorResult(p, "ошибка сканирования: " + ex.Message)); }
            }
            ScannerCore.RunYaraBatch(results);
            // source generator (NativeAOT не поддерживает reflection-сериализацию)
            Console.WriteLine(JsonSerializer.Serialize(results, ScanJsonContext.Default.ListScanResult));
            return;
        }
        bool createdNew = false;
        _singleInstance = new Mutex(true, "Global\\ShadowScan_SingleInstance", out createdNew);
        if (!createdNew)
        {
            // уже запущен: показываем окно существующего экземпляра и выходим
            try
            {
                var evt = System.Threading.EventWaitHandle.OpenExisting("Global\\ShadowScan_ShowWindow");
                evt.Set();
            }
            catch { }
            return;
        }
        AppBuilder.Configure<App>().UsePlatformDetect().WithInterFont().StartWithClassicDesktopLifetime(args);
        _singleInstance.ReleaseMutex();
    }

    // Нативные DLL (Skia/HarfBuzz/ANGLE) вшиты в exe — при первом запуске
    // распаковываются рядом с exe; если папка только для чтения — в
    // %LOCALAPPDATA%\ShadowScan (и добавляется в путь поиска DLL).
    static void EnsureNativeLibs()
    {
        string[] dlls = { "libSkiaSharp.dll", "libHarfBuzzSharp.dll", "av_libglesv2.dll" };
        var asm = System.Reflection.Assembly.GetExecutingAssembly();
        string exeDir = AppContext.BaseDirectory;
        string fallback = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ShadowScan");
        bool needFallback = false;

        foreach (var dll in dlls)
        {
            if (File.Exists(Path.Combine(exeDir, dll))) continue;
            try
            {
                using var s = asm.GetManifestResourceStream(dll);
                if (s == null) continue;
                using var f = File.Create(Path.Combine(exeDir, dll));
                s.CopyTo(f);
            }
            catch (Exception)
            {
                needFallback = true; // папка exe недоступна для записи
                try
                {
                    Directory.CreateDirectory(fallback);
                    using var s = asm.GetManifestResourceStream(dll);
                    if (s == null) continue;
                    using var f = File.Create(Path.Combine(fallback, dll));
                    s.CopyTo(f);
                }
                catch { }
            }
        }
        if (needFallback && Directory.Exists(fallback))
            SetDllDirectoryW(fallback);
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    static extern bool SetDllDirectoryW(string path);

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    static extern bool AttachConsole(int pid);
}

// ============ Иконки Lucide (d-пути, открытые данные, ISC-лицензия) ============
static class Icons
{
    public const string Shield = "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z";
    public const string ShieldCheck = Shield + "M9 12l2 2 4-4";
    public const string ShieldAlert = Shield + "M12 8v4M12 16h.01";
    public const string FolderPlus = "M12 10v6M9 13h6M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z";
    public const string Copy = "M8 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2Z M16 8h2a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-8a2 2 0 0 1-2-2v-2";
    public const string FolderOpen = "m6 14 1.5-2.9A2 2 0 0 1 9.24 10H20a2 2 0 0 1 1.94 2.5l-1.54 6a2 2 0 0 1-1.95 1.5H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3.9a2 2 0 0 1 1.69.9l.81 1.2a2 2 0 0 0 1.67.9H18a2 2 0 0 1 2 2v2";
    public const string X = "M18 6 6 18M6 6 18 18";
    public const string Play = "M5 5a2 2 0 0 1 3.008-1.728l11.997 6.998a2 2 0 0 1 .003 3.458l-12 7A2 2 0 0 1 5 19z";
    public const string Square = "M5 3h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z";
    public const string Trash2 = "M10 11v6M14 11v6M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2";
    public const string FileSearch = "M6 22a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h8a2.4 2.4 0 0 1 1.704.706l3.588 3.588A2.4 2.4 0 0 1 20 8v12a2 2 0 0 1-2 2zM14 2v5a1 1 0 0 0 1 1h5M9 14.5a2.5 2.5 0 1 0 5 0 2.5 2.5 0 1 0-5 0M13.3 16.3 15 18";
    public const string Download = "M12 15V3M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5";
    public const string Settings = "M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2zM9 12a3 3 0 1 0 6 0 3 3 0 1 0-6 0";
    public const string RotateCcw = "M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8M3 3v5h5";
    public const string Zap = "M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z";
}

// ============ Утилиты интерфейса ============
static class Ui
{
    public static SolidColorBrush C(string hex) => new(Color.Parse(hex));

    /// <summary>Иконка Lucide: Path + StreamGeometry.Parse, обводка как в оригинале (fill=none, stroke=currentColor).</summary>
    public static Avalonia.Controls.Shapes.Path MakeIcon(string pathData, IBrush color, double size, double strokeWidth = 2.0)
    {
        return new Avalonia.Controls.Shapes.Path
        {
            Data = StreamGeometry.Parse(pathData),
            Stroke = color,
            StrokeThickness = strokeWidth,
            StrokeLineCap = PenLineCap.Round,
            StrokeJoin = PenLineJoin.Round,
            Width = size,
            Height = size,
            Stretch = Stretch.Uniform,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
        };
    }

    public static StackPanel IconText(Avalonia.Controls.Shapes.Path icon, string text)
    {
        return new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 7,
            Children =
            {
                icon,
                new TextBlock { Text = text, VerticalAlignment = VerticalAlignment.Center },
            },
        };
    }

    /// <summary>Иконка приложения: градиентный щит с галочкой — сканировать и защищать.</summary>
    public static Bitmap CreateAppIconBitmap()
    {
        const int size = 64;
        // градиент: тёмно-синий -> голубой (диагональ)
        var gradient = new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
            EndPoint = new RelativePoint(1, 1, RelativeUnit.Relative),
            GradientStops = new GradientStops
            {
                new GradientStop(Color.Parse("#1a5276"), 0),
                new GradientStop(Color.Parse("#2980b9"), 0.55),
                new GradientStop(Color.Parse("#3498db"), 1),
            },
        };
        var badge = new Border
        {
            Width = size,
            Height = size,
            Background = gradient,
            CornerRadius = new CornerRadius(15),
            // тонкая внутренняя окантовка для глубины
            BorderBrush = new SolidColorBrush(Color.Parse("#5dade2")) { Opacity = 0.55 },
            BorderThickness = new Thickness(1.5),
            Child = new Panel
            {
                Children =
                {
                    MakeIcon(Icons.Shield, new SolidColorBrush(Color.Parse("#154360")) { Opacity = 0.35 }, 40, 3.2),
                    // щит с галочкой чуть выше и левее нижнего щита — эффект двойного щита
                    MakeIcon(Icons.ShieldCheck, Brushes.White, 34, 2.6),
                },
            },
        };
        badge.Measure(new Size(size, size));
        badge.Arrange(new Rect(0, 0, size, size));
        var bmp = new RenderTargetBitmap(new PixelSize(size, size), new Vector(96, 96));
        bmp.Render(badge);
        return bmp;
    }

    public static void Error(Window owner, string title, string message)
    {
        var win = Dialog(owner, title, 460, 210);
        var panel = new StackPanel { Margin = new Thickness(18), Spacing = 12 };
        var head = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
        head.Children.Add(MakeIcon(Icons.ShieldAlert, C("#e74c3c"), 26));
        head.Children.Add(new TextBlock { Text = title, FontSize = 15, FontWeight = FontWeight.SemiBold, VerticalAlignment = VerticalAlignment.Center });
        panel.Children.Add(head);
        panel.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap });
        var ok = new Button { Content = "OK", Classes = { "primary" }, HorizontalAlignment = HorizontalAlignment.Right, MinWidth = 90 };
        ok.Click += (s, e) => win.Close();
        panel.Children.Add(ok);
        win.Content = panel;
        win.ShowDialog(owner);
    }

    public static bool Confirm(Window owner, string message, string title = "Подтверждение")
    {
        bool result = false;
        var win = Dialog(owner, title, 460, 230);
        var panel = new StackPanel { Margin = new Thickness(18), Spacing = 14 };
        panel.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap });
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, HorizontalAlignment = HorizontalAlignment.Right };
        var yes = new Button { Content = "Да", Classes = { "danger" }, MinWidth = 90 };
        yes.Click += (s, e) => { result = true; win.Close(); };
        var no = new Button { Content = "Нет", MinWidth = 90 };
        no.Click += (s, e) => win.Close();
        row.Children.Add(yes);
        row.Children.Add(no);
        panel.Children.Add(row);
        win.Content = panel;
        win.ShowDialog(owner);
        return result;
    }

    static Window Dialog(Window owner, string title, double width, double height)
    {
        return new Window
        {
            Title = title,
            Width = width,
            Height = height,
            CanResize = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Background = C("#161e28"),
        };
    }
}

// ============ Настройки (settings.json рядом с exe) ============
// Модель Settings объявлена в RtProtection.cs (поля + общий экземпляр
// RtProtection.Settings) — здесь только загрузка/сохранение в JSON.
static class SettingsIO
{
    static string Path => System.IO.Path.Combine(AppContext.BaseDirectory, "settings.json");

    public static Settings Load()
    {
        try
        {
            if (File.Exists(Path))
                return JsonSerializer.Deserialize(File.ReadAllText(Path), ScanJsonContext.Default.Settings) ?? new Settings();
        }
        catch { /* битый файл — значения по умолчанию */ }
        return new Settings();
    }

    public static void Save(Settings s)
    {
        try { File.WriteAllText(Path, JsonSerializer.Serialize(s, ScanJsonContext.Default.Settings)); }
        catch { }
    }
}

// ============ Журнал событий (shadowscan.log рядом с exe) ============
static class Log
{
    static readonly object Sync = new();
    static string Path => System.IO.Path.Combine(AppContext.BaseDirectory, "shadowscan.log");

    public static void Write(string message)
    {
        try
        {
            lock (Sync)
                File.AppendAllText(Path, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + message + "\r\n");
        }
        catch { /* журнал опционален */ }
    }

    public static string Read()
    {
        try
        {
            lock (Sync)
                return File.Exists(Path) ? File.ReadAllText(Path) : "(журнал пуст)";
        }
        catch { return "(не удалось прочитать журнал)"; }
    }

    public static void Clear()
    {
        try { lock (Sync) File.WriteAllText(Path, ""); } catch { }
    }
}

// ============ Приложение: тема и стили ============
public class App : Application
{
    public static IClassicDesktopStyleApplicationLifetime Lifetime;
    // Общий уведомитель: real-time модуль (RtProtection.cs) обращается к нему через App.Notify
    public static WindowNotificationManager Notify;

    public override void Initialize()
    {
        // Тёмная тема Fluent + акцент (в 11.2 акцент задаётся через палитру темы)
        RequestedThemeVariant = ThemeVariant.Dark;
        var fluent = new FluentTheme();
        fluent.Palettes[ThemeVariant.Dark] = new ColorPaletteResources { Accent = Color.Parse("#2980b9") };
        Styles.Add(fluent);
        AddStyles();
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            Lifetime = desktop;
            // окно сворачивается в трей, а не завершает приложение
            desktop.ShutdownMode = ShutdownMode.OnExplicitShutdown;
            var win = new MainWindow();
            desktop.MainWindow = win;
            win.Show();
        }
        base.OnFrameworkInitializationCompleted();
    }

    void AddStyles()
    {
        // Кнопки: тёмный фон, бордер, скругление 6
        Styles.Add(new Style(x => x.OfType<Button>())
        {
            Setters =
            {
                new Setter(Button.BackgroundProperty, Ui.C("#22303e")),
                new Setter(Button.ForegroundProperty, Ui.C("#e8eef5")),
                new Setter(Button.BorderBrushProperty, Ui.C("#2c3a47")),
                new Setter(Button.BorderThicknessProperty, new Thickness(1)),
                new Setter(Button.CornerRadiusProperty, new CornerRadius(6)),
                new Setter(Button.PaddingProperty, new Thickness(11, 5)),
                new Setter(Button.FontSizeProperty, 13.0),
            }
        });
        Styles.Add(new Style(x => x.OfType<Button>().Class(":pointerover"))
        {
            Setters = { new Setter(Button.BackgroundProperty, Ui.C("#2a3a4d")) },
        });
        Styles.Add(new Style(x => x.OfType<Button>().Class(":pressed"))
        {
            Setters = { new Setter(Button.BackgroundProperty, Ui.C("#243348")) },
        });
        // primary — акцентная кнопка (сканировать, сохранить)
        Styles.Add(new Style(x => x.OfType<Button>().Class("primary"))
        {
            Setters =
            {
                new Setter(Button.BackgroundProperty, Ui.C("#2980b9")),
                new Setter(Button.BorderBrushProperty, Ui.C("#3d94cf")),
                new Setter(Button.ForegroundProperty, Brushes.White),
            }
        });
        Styles.Add(new Style(x => x.OfType<Button>().Class("primary").Class(":pointerover"))
        {
            Setters = { new Setter(Button.BackgroundProperty, Ui.C("#3498db")) },
        });
        // danger — удаление навсегда
        Styles.Add(new Style(x => x.OfType<Button>().Class("danger"))
        {
            Setters =
            {
                new Setter(Button.BackgroundProperty, Ui.C("#c0392b")),
                new Setter(Button.BorderBrushProperty, Ui.C("#d6554a")),
                new Setter(Button.ForegroundProperty, Brushes.White),
            }
        });
        Styles.Add(new Style(x => x.OfType<Button>().Class("danger").Class(":pointerover"))
        {
            Setters = { new Setter(Button.BackgroundProperty, Ui.C("#e74c3c")) },
        });
        // warning — карантин (оранжевый)
        Styles.Add(new Style(x => x.OfType<Button>().Class("warning"))
        {
            Setters =
            {
                new Setter(Button.BackgroundProperty, Ui.C("#e67e22")),
                new Setter(Button.BorderBrushProperty, Ui.C("#f0923e")),
                new Setter(Button.ForegroundProperty, Brushes.White),
            }
        });
        Styles.Add(new Style(x => x.OfType<Button>().Class("warning").Class(":pointerover"))
        {
            Setters = { new Setter(Button.BackgroundProperty, Ui.C("#f39c12")) },
        });

        // TextBox
        Styles.Add(new Style(x => x.OfType<TextBox>())
        {
            Setters =
            {
                new Setter(TextBox.BackgroundProperty, Ui.C("#1b2430")),
                new Setter(TextBox.ForegroundProperty, Ui.C("#e8eef5")),
                new Setter(TextBox.BorderBrushProperty, Ui.C("#2c3a47")),
                new Setter(TextBox.BorderThicknessProperty, new Thickness(1)),
                new Setter(TextBox.CornerRadiusProperty, new CornerRadius(6)),
                new Setter(TextBox.PaddingProperty, new Thickness(8, 4)),
                new Setter(TextBox.CaretBrushProperty, Ui.C("#2980b9")),
            }
        });

        // ListBox
        Styles.Add(new Style(x => x.OfType<ListBox>())
        {
            Setters =
            {
                new Setter(ListBox.BackgroundProperty, Ui.C("#1b2430")),
                new Setter(ListBox.BorderBrushProperty, Ui.C("#2c3a47")),
                new Setter(ListBox.BorderThicknessProperty, new Thickness(1)),
                new Setter(ListBox.CornerRadiusProperty, new CornerRadius(6)),
                new Setter(ListBox.PaddingProperty, new Thickness(4)),
            }
        });
        Styles.Add(new Style(x => x.OfType<ListBoxItem>())
        {
            Setters =
            {
                new Setter(ListBoxItem.PaddingProperty, new Thickness(8, 4)),
                new Setter(ListBoxItem.CornerRadiusProperty, new CornerRadius(4)),
            }
        });

        // DataGrid — тёмные заголовки и ячейки
        Styles.Add(new Style(x => x.OfType<DataGridColumnHeader>())
        {
            Setters =
            {
                new Setter(DataGridColumnHeader.BackgroundProperty, Ui.C("#1b2430")),
                new Setter(DataGridColumnHeader.ForegroundProperty, Ui.C("#b8c4d0")),
                new Setter(DataGridColumnHeader.FontWeightProperty, FontWeight.SemiBold),
                new Setter(DataGridColumnHeader.PaddingProperty, new Thickness(10, 7)),
                new Setter(DataGridColumnHeader.BorderBrushProperty, Ui.C("#2c3a47")),
                new Setter(DataGridColumnHeader.BorderThicknessProperty, new Thickness(0, 0, 0, 1)),
            }
        });
        Styles.Add(new Style(x => x.OfType<DataGridCell>())
        {
            Setters =
            {
                new Setter(DataGridCell.PaddingProperty, new Thickness(10, 5)),
                new Setter(DataGridCell.VerticalContentAlignmentProperty, VerticalAlignment.Center),
                new Setter(DataGridCell.BorderThicknessProperty, new Thickness(0)),
            }
        });
    }
}

// ============ Главное окно ============
public class MainWindow : Window
{
    readonly ObservableCollection<string> _queueItems = new();
    readonly ObservableCollection<GridRow> _rows = new();
    readonly Dictionary<string, ScanResult> _results = new(StringComparer.OrdinalIgnoreCase);
    // Вкладки главного окна: Скан / Автозагрузки / Журнал / Настройки
    StackPanel _tabRow;
    ContentControl _contentHost;
    Control _scanRoot;
    Control _autorunsPanel, _journalPanel, _settingsPanel, _quarantinePanel;
    readonly List<Button> _tabButtons = new();
    int _activeTab = -1;
    // Кэш сканирования: (размер, время изменения) -> результат. Повторный скан
    // неизменённых файлов не пересчитывает движок — скорость скана папки растёт в разы.
    readonly Dictionary<string, (long Size, DateTime Mtime, ScanResult Result)> _scanCache = new(StringComparer.OrdinalIgnoreCase);
    readonly WindowNotificationManager _notifier;
    readonly RtProtection _rt;

    readonly ListBox _queue;
    readonly ListBox _grid;
    readonly TextBlock _details;
    readonly ScrollViewer _detailsHost;
    readonly TextBlock _status;
    readonly TextBlock _selectedLabel;
    readonly Button _btnScan, _btnCancel, _btnClear;
    readonly Button _btnQuarantine, _btnDelete;
    readonly Avalonia.Controls.Shapes.Rectangle _zoneRect;
    readonly Border _zone;

    readonly List<string> _pending = new();
    volatile bool _cancelled;
    bool _exiting;
    int _done, _total;
    int _cleanCount, _suspCount, _malCount, _errCount;

    public MainWindow()
    {
        _rt = new RtProtection { onThreat = OnRtThreat };
        Title = "ShadowScan — нативный антивирус";
        Width = 1160;
        Height = 800;
        MinWidth = 940;
        MinHeight = 660;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Background = Ui.C("#141b24");
        _notifier = new WindowNotificationManager(this)
        {
            Position = NotificationPosition.BottomRight,
            MaxItems = 3,
        };
        App.Notify = _notifier;

        var root = new Grid { Margin = new Thickness(14, 10, 14, 12) };
        root.RowDefinitions.Add(new RowDefinition(new GridLength(50)));  // заголовок
        root.RowDefinitions.Add(new RowDefinition(new GridLength(44)));  // панель кнопок
        root.RowDefinitions.Add(new RowDefinition(new GridLength(70)));  // drop-зона
        root.RowDefinitions.Add(new RowDefinition(new GridLength(104))); // очередь
        root.RowDefinitions.Add(new RowDefinition(new GridLength(28)));  // статус-бар
        root.RowDefinitions.Add(new RowDefinition(GridLength.Star));     // результаты
        root.RowDefinitions.Add(new RowDefinition(new GridLength(200))); // детали

        // ---- Вкладки: Скан | Автозагрузки | Журнал | Настройки (вместо отдельных окон) ----
        var outer = new Grid();
        outer.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
        outer.RowDefinitions.Add(new RowDefinition(GridLength.Star));
        _tabRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 4, Margin = new Thickness(14, 8, 14, 4) };
        Grid.SetRow(_tabRow, 0);
        outer.Children.Add(_tabRow);
        _contentHost = new ContentControl { HorizontalContentAlignment = HorizontalAlignment.Stretch };
        Grid.SetRow(_contentHost, 1);
        outer.Children.Add(_contentHost);

        // вкладка «Скан» = вся существующая разметка (root)
        Content = outer;
        AddTabButton("Скан", Icons.ShieldCheck);
        AddTabButton("Автозагрузки", Icons.Zap);
        AddTabButton("Журнал", Icons.FileSearch);
        AddTabButton("Настройки", Icons.Settings);
        AddTabButton("Карантин", Icons.ShieldCheck);
        _contentHost.Content = root; // стартовая вкладка

        // ---- Заголовок: щит + имя ----
        var header = new Grid();
        header.ColumnDefinitions.Add(new ColumnDefinition(GridLength.Auto));
        header.ColumnDefinitions.Add(new ColumnDefinition(GridLength.Star));
        header.ColumnDefinitions.Add(new ColumnDefinition(GridLength.Auto));
        header.Children.Add(new Border
        {
            Background = Ui.C("#1d6fa5"),
            CornerRadius = new CornerRadius(9),
            Width = 34,
            Height = 34,
            Margin = new Thickness(0, 0, 10, 0),
            Child = Ui.MakeIcon(Icons.Shield, Brushes.White, 19),
        });
        var titleBlock = new StackPanel
        {
            Orientation = Orientation.Vertical,
            VerticalAlignment = VerticalAlignment.Center,
            Children =
            {
                new TextBlock { Text = "ShadowScan", FontSize = 17, FontWeight = FontWeight.Bold, Foreground = Ui.C("#f2f6fa") },
                new TextBlock { Text = "статический анализ файлов на вредоносные признаки", FontSize = 11.5, Foreground = Ui.C("#7d8b9b") },
            },
        };
        Grid.SetColumn(titleBlock, 1);
        header.Children.Add(titleBlock);
        var nativeTag = new TextBlock
        {
            Text = "NativeAOT",
            FontSize = 11,
            Foreground = Ui.C("#5d6b7a"),
            VerticalAlignment = VerticalAlignment.Center,
        };
        Grid.SetColumn(nativeTag, 2);
        header.Children.Add(nativeTag);
        Grid.SetRow(header, 0);
        root.Children.Add(header);

        // ---- Панель кнопок (иконка + текст) ----
        var toolbar = new Grid();
        toolbar.ColumnDefinitions.Add(new ColumnDefinition(GridLength.Star));
        toolbar.ColumnDefinitions.Add(new ColumnDefinition(GridLength.Auto));
        var left = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 6, 0, 2) };
        var btnAddFiles = MakeToolButton("Добавить файлы", Icons.FolderPlus, Ui.C("#cfe0ee"), null);
        btnAddFiles.Click += async (s, e) =>
        {
            var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Добавить файлы", AllowMultiple = true });
            AddPaths(files.Select(f => f.TryGetLocalPath()).Where(p => p != null).ToArray());
        };
        var btnAddFolder = MakeToolButton("Добавить папку", Icons.FolderOpen, Ui.C("#cfe0ee"), null);
        btnAddFolder.Click += async (s, e) =>
        {
            var dirs = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = "Добавить папку", AllowMultiple = true });
            AddPaths(dirs.Select(d => d.TryGetLocalPath()).Where(p => p != null).ToArray());
        };
        _btnScan = MakeToolButton("Сканировать", Icons.Play, Brushes.White, "primary");
        _btnScan.Click += (s, e) => StartScan();
        _btnCancel = MakeToolButton("Отмена", Icons.Square, Ui.C("#cfe0ee"), null);
        _btnCancel.IsVisible = false;
        _btnCancel.Click += (s, e) => { _cancelled = true; _status.Text = "Отмена…"; };
        _btnClear = MakeToolButton("Очистить", Icons.X, Ui.C("#cfe0ee"), null);
        _btnClear.Click += (s, e) => { _pending.Clear(); _queueItems.Clear(); _status.Text = "Очередь очищена."; };
        left.Children.Add(btnAddFiles);
        left.Children.Add(btnAddFolder);
        left.Children.Add(_btnScan);
        left.Children.Add(_btnCancel);
        left.Children.Add(_btnClear);
        var right = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 6, 0, 2) };
        var btnQuarantineList = MakeToolButton("Карантин", Icons.ShieldCheck, Ui.C("#cfe0ee"), null);
        btnQuarantineList.Click += (s, e) => new QuarantineWindow(this).ShowDialog(this);
        right.Children.Add(btnQuarantineList);
        toolbar.Children.Add(left);
        Grid.SetColumn(right, 1);
        toolbar.Children.Add(right);
        Grid.SetRow(toolbar, 1);
        root.Children.Add(toolbar);

        // ---- Drop-зона (пунктирный бордер) ----
        _zone = new Border { Margin = new Thickness(0, 4, 0, 4) };
        _zoneRect = new Avalonia.Controls.Shapes.Rectangle
        {
            Stroke = Ui.C("#2f4150"),
            StrokeThickness = 2,
            StrokeDashArray = new AvaloniaList<double> { 6, 4 },
            RadiusX = 8,
            RadiusY = 8,
            Fill = Ui.C("#182230"),
        };
        _zone.Child = new Grid
        {
            Children =
            {
                _zoneRect,
                new StackPanel
                {
                    Orientation = Orientation.Horizontal,
                    Spacing = 10,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center,
                    Children =
                    {
                        Ui.MakeIcon(Icons.Download, Ui.C("#2980b9"), 22, 2.2),
                        new TextBlock
                        {
                            Text = "Перетащите файлы сюда или нажмите, чтобы выбрать",
                            FontSize = 13,
                            Foreground = Ui.C("#8fa1b3"),
                            VerticalAlignment = VerticalAlignment.Center,
                        },
                    },
                },
            },
        };
        _zone.Cursor = new Cursor(StandardCursorType.Hand);
        _zone.PointerPressed += (s, e) => OpenAddFilesDialog();
        _zone.AddHandler(DragDrop.DragOverEvent, (s, e) =>
        {
            if (e.Data.Contains(DataFormats.Files))
            {
                e.DragEffects = DragDropEffects.Copy;
                _zoneRect.Stroke = Ui.C("#2980b9");
                _zoneRect.Fill = Ui.C("#1c2f40");
            }
            else e.DragEffects = DragDropEffects.None;
        });
        _zone.AddHandler(DragDrop.DragLeaveEvent, (s, e) => ResetZone());
        _zone.AddHandler(DragDrop.DropEvent, (s, e) =>
        {
            ResetZone();
            if (!e.Data.Contains(DataFormats.Files)) return;
            var paths = e.Data.GetFiles()?.Select(f => f.TryGetLocalPath()).Where(p => p != null).ToArray();
            if (paths != null && paths.Length > 0) AddPaths(paths);
        });
        Grid.SetRow(_zone, 2);
        root.Children.Add(_zone);

        // ---- Очередь ----
        var queuePanel = new Grid();
        queuePanel.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
        queuePanel.RowDefinitions.Add(new RowDefinition(GridLength.Star));
        queuePanel.Children.Add(Caption("ОЧЕРЕДЬ"));
        _queue = new ListBox { ItemsSource = _queueItems };
        Grid.SetRow(_queue, 1);
        queuePanel.Children.Add(_queue);
        Grid.SetRow(queuePanel, 3);
        root.Children.Add(queuePanel);

        // ---- Статус-бар ----
        _status = new TextBlock
        {
            Text = "Готов к работе. Добавьте файлы или папки.",
            Foreground = Ui.C("#93a4b5"),
            FontSize = 12.5,
            VerticalAlignment = VerticalAlignment.Center,
        };
        Grid.SetRow(_status, 4);
        root.Children.Add(_status);

        // ---- Таблица результатов (ListBox + Grid-колонки: 100% NativeAOT, без DataGrid/XAML-темы) ----
        var resultsPanel = new Grid();
        resultsPanel.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
        resultsPanel.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
        resultsPanel.RowDefinitions.Add(new RowDefinition(GridLength.Star));
        resultsPanel.Children.Add(Caption("РЕЗУЛЬТАТЫ"));

        ColumnDefinitions TableCols() => new()
        {
            new ColumnDefinition(new GridLength(150)),
            new ColumnDefinition(new GridLength(3, GridUnitType.Star)),
            new ColumnDefinition(new GridLength(90)),
            new ColumnDefinition(new GridLength(2, GridUnitType.Star)),
        };

        // заголовок колонок
        var tableHeader = new Border { Background = Ui.C("#141b24"), Padding = new Thickness(8, 6),
            Child = new Grid { ColumnDefinitions = TableCols() } };
        var tableHeaderGrid = (Grid)tableHeader.Child;
        foreach (var (t, i) in new[] { "ВЕРДИКТ", "ФАЙЛ", "ОЦЕНКА", "ТИП УГРОЗЫ" }.Select((t, i) => (t, i)))
        {
            var tb = new TextBlock { Text = t, FontWeight = FontWeight.SemiBold, Foreground = Ui.C("#8b98a5"), FontSize = 12 };
            Grid.SetColumn(tb, i);
            tableHeaderGrid.Children.Add(tb);
        }
        Grid.SetRow(tableHeader, 1);
        resultsPanel.Children.Add(tableHeader);

        _grid = new ListBox
        {
            ItemsSource = _rows, // ObservableCollection — пересоздавать не нужно
            Background = Ui.C("#141b24"),
            Foreground = Ui.C("#dbe4ee"),
            ItemTemplate = new FuncDataTemplate<GridRow>((row, _) =>
            {
                var g = new Grid { ColumnDefinitions = TableCols() };
                var badge = BuildVerdictBadge(row);
                Grid.SetColumn(badge, 0);
                badge.VerticalAlignment = VerticalAlignment.Center;
                var file = new TextBlock { Text = row?.FileName ?? "", TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center };
                Grid.SetColumn(file, 1);
                var score = new TextBlock { Text = row?.ScoreStr ?? "", HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
                Grid.SetColumn(score, 2);
                var threat = new TextBlock { Text = row?.ThreatType ?? "", TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center };
                Grid.SetColumn(threat, 3);
                g.Children.AddRange(new Control[] { badge, file, score, threat });
                return new Border { Child = g, MinHeight = 32, Padding = new Thickness(8, 4) };
            }),
        };
        // звёздчатые колонки строк выравниваются с заголовком только при Stretch
        _grid.Styles.Add(new Style(x => x.OfType<ListBoxItem>())
        {
            Setters = { new Setter(ListBoxItem.HorizontalContentAlignmentProperty, HorizontalAlignment.Stretch) }
        });
        _grid.SelectionChanged += (s, e) => ShowDetails();
        Grid.SetRow(_grid, 2);
        resultsPanel.Children.Add(_grid);
        Grid.SetRow(resultsPanel, 5);
        root.Children.Add(resultsPanel);

        // ---- Детали + кнопки действий ----
        var detPanel = new Grid();
        detPanel.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
        detPanel.RowDefinitions.Add(new RowDefinition(GridLength.Star));
        var actRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 6, 0, 6) };
        _btnQuarantine = MakeToolButton("В карантин", Icons.ShieldCheck, Brushes.White, "warning");
        _btnQuarantine.IsVisible = false;
        _btnQuarantine.Click += (s, e) => QuarantineSelected();
        _btnDelete = MakeToolButton("Удалить навсегда", Icons.Trash2, Brushes.White, "danger");
        _btnDelete.IsVisible = false;
        _btnDelete.Click += (s, e) => DeleteSelected();
        _selectedLabel = new TextBlock
        {
            VerticalAlignment = VerticalAlignment.Center,
            Foreground = Ui.C("#7d8b9b"),
            TextTrimming = TextTrimming.CharacterEllipsis,
            Margin = new Thickness(6, 0, 0, 0),
        };
        actRow.Children.Add(_btnQuarantine);
        actRow.Children.Add(_btnDelete);
        actRow.Children.Add(_selectedLabel);
        detPanel.Children.Add(actRow);
        // TextBlock в ScrollViewer: никаких признаков редактирования (без каретки)
        _details = new TextBlock
        {
            Text = "Выберите файл в таблице, чтобы увидеть детали анализа.",
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12.5,
            TextWrapping = TextWrapping.NoWrap,
        };
        _detailsHost = new ScrollViewer
        {
            Content = _details, Background = Ui.C("#141b24"), Padding = new Thickness(8),
            HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Auto,
            VerticalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Auto,
        };
        Grid.SetRow(_detailsHost, 1);
        detPanel.Children.Add(_detailsHost);

        // Кнопка «Копировать» поверх панели деталей (правый верхний угол)
        var copyBtn = new Button
        {
            Content = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6,
                Children = { Ui.MakeIcon(Icons.Copy, Brushes.White, 14), new TextBlock { Text = "Копировать", FontSize = 11.5 } } },
            Padding = new Thickness(8, 3),
            VerticalAlignment = VerticalAlignment.Top,
            HorizontalAlignment = HorizontalAlignment.Right,
            ZIndex = 10,
            Background = Ui.C("#22303e"),
            Opacity = 0.92,
        };
        copyBtn.Click += (s, e) =>
        {
            try
            {
                if (!string.IsNullOrEmpty(_details.Text))
                {
                    TopLevel.GetTopLevel(this)?.Clipboard?.SetTextAsync(_details.Text);
                    _status.Text = "Детали скопированы в буфер обмена.";
                }
            }
            catch { }
        };
        _detailsHost.Opacity = 1;
        Grid.SetRow(copyBtn, 1);
        detPanel.Children.Add(copyBtn);
        Grid.SetRow(detPanel, 6);
        root.Children.Add(detPanel);

        // ---- Трей: сворачивание в трей при закрытии ----
        Closing += (s, e) =>
        {
            if (_exiting) return;
            e.Cancel = true; // закрытие = свернуть в трей
            Hide();
        };
        try
        {
            var appIcon = Ui.CreateAppIconBitmap();
            Icon = new WindowIcon(appIcon);
            SetupTray(appIcon);
        }
        catch { /* иконка/трей опциональны */ }

        // Слушатель повторного запуска: сигнал «показать окно» из нового экземпляра
        Task.Run(() =>
        {
            try
            {
                using var evt = new System.Threading.EventWaitHandle(false, System.Threading.EventResetMode.AutoReset, "Global\\ShadowScan_ShowWindow");
                while (true)
                {
                    evt.WaitOne();
                    Dispatcher.UIThread.Post(() => { Show(); Activate(); });
                }
            }
            catch { /* не критично */ }
        });

        // применяем сохранённые настройки к общему экземпляру RtProtection.Settings
        var saved = SettingsIO.Load();
        var st = RtProtection.Settings;
        st.ThresholdSuspicious = saved.ThresholdSuspicious;
        st.ThresholdMalicious = saved.ThresholdMalicious;
        st.BlockDangerousScripts = saved.BlockDangerousScripts;
        st.RealtimeEnabled = saved.RealtimeEnabled;
        st.SelfDefend = saved.SelfDefend;
        st.NetworkMonitor = saved.NetworkMonitor;
        if (st.RealtimeEnabled) _rt.Start();

        // сохранить скан-панель и активировать первую вкладку
        _scanRoot = root;
        SelectTab(0);

        Log.Write("Запуск ShadowScan");
    }

    // ---------- вкладки ----------
    void AddTabButton(string label, string icon)
    {
        var b = MakeToolButton(label, icon, Ui.C("#cfe0ee"), null);
        int idx = _tabButtons.Count;
        b.Click += (s, e) => SelectTab(idx);
        _tabButtons.Add(b);
        _tabRow.Children.Add(b);
    }

    void SelectTab(int idx)
    {
        if (idx == _activeTab && _contentHost.Content != null) { RefreshTab(idx); return; }
        _activeTab = idx;
        for (int i = 0; i < _tabButtons.Count; i++)
        {
            _tabButtons[i].Classes.Remove("primary");
            if (i == idx) _tabButtons[i].Classes.Add("primary");
        }
        switch (idx)
        {
            case 1:
                if (_autorunsPanel == null) _autorunsPanel = BuildAutorunsPanel();
                _contentHost.Content = _autorunsPanel;
                ReloadAutorunsPanel();
                break;
            case 2:
                if (_journalPanel == null) _journalPanel = BuildJournalPanel();
                else RefreshJournalPanel();
                _contentHost.Content = _journalPanel;
                break;
            case 3:
                if (_settingsPanel == null) _settingsPanel = BuildSettingsPanel();
                _contentHost.Content = _settingsPanel;
                break;
            case 4:
                if (_quarantinePanel == null) _quarantinePanel = BuildQuarantinePanel();
                else RefreshQuarantinePanel();
                _contentHost.Content = _quarantinePanel;
                break;
            default:
                _contentHost.Content = _scanRoot;
                break;
        }
    }

    void RefreshTab(int idx)
    {
        if (idx == 1) ReloadAutorunsPanel();
        else if (idx == 2) RefreshJournalPanel();
        else if (idx == 4) RefreshQuarantinePanel();
    }

    void ReloadAutorunsPanel()
    {
        try { RtProtection.CollectAutoruns(); } catch { }
        if (_autorunsReload != null) _autorunsReload();
    }
    Action _autorunsReload;
    List<AutorunEntry> _autorunsAll = new(); // полный собранный список — источник для живого фильтра

    Control BuildAutorunsPanel()
    {
        var grid = new Grid { Margin = new Thickness(0) };
        grid.RowDefinitions.Add(new RowDefinition(GridLength.Auto)); // кнопки
        grid.RowDefinitions.Add(new RowDefinition(GridLength.Auto)); // фильтр
        grid.RowDefinitions.Add(new RowDefinition(GridLength.Auto)); // заголовок таблицы
        grid.RowDefinitions.Add(new RowDefinition(GridLength.Star)); // список
        grid.RowDefinitions.Add(new RowDefinition(GridLength.Auto)); // статус

        // ---- Кнопки: Обновить | Отключить | Включить | Открыть расположение | Удалить ----
        var actRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 0, 0, 8) };
        var btnRefresh = new Button { Content = Ui.IconText(Ui.MakeIcon(Icons.RotateCcw, Ui.C("#cfe0ee"), 14), "Обновить") };
        var btnDisable = new Button { Content = Ui.IconText(Ui.MakeIcon(Icons.Square, Ui.C("#cfe0ee"), 14), "Отключить"), MinWidth = 110 };
        var btnEnable = new Button { Content = Ui.IconText(Ui.MakeIcon(Icons.Play, Ui.C("#cfe0ee"), 14), "Включить"), MinWidth = 110 };
        var btnShow = new Button { Content = Ui.IconText(Ui.MakeIcon(Icons.FolderOpen, Ui.C("#cfe0ee"), 14), "Открыть расположение") };
        var btnDelete = new Button { Content = Ui.IconText(Ui.MakeIcon(Icons.Trash2, Brushes.White, 14), "Удалить"), Classes = { "danger" }, MinWidth = 110 };
        actRow.Children.Add(btnRefresh);
        actRow.Children.Add(btnDisable);
        actRow.Children.Add(btnEnable);
        actRow.Children.Add(btnShow);
        actRow.Children.Add(btnDelete);
        Grid.SetRow(actRow, 0);
        grid.Children.Add(actRow);

        // ---- Строка живого фильтра ----
        var filter = new TextBox
        {
            Watermark = "Живой фильтр: имя, команда, источник…",
            Width = 420,
            HorizontalAlignment = HorizontalAlignment.Left,
            Margin = new Thickness(2, 0, 0, 8),
        };
        Grid.SetRow(filter, 1);
        grid.Children.Add(filter);

        // ---- Таблица: Имя | Команда | Источник | Путь | Подпись | Состояние ----
        ColumnDefinitions Cols() => new()
        {
            new ColumnDefinition(new GridLength(175)),
            new ColumnDefinition(new GridLength(2.8, GridUnitType.Star)),
            new ColumnDefinition(new GridLength(140)),
            new ColumnDefinition(new GridLength(1.7, GridUnitType.Star)),
            new ColumnDefinition(new GridLength(150)),
            new ColumnDefinition(new GridLength(72)),
        };

        var tableHeader = new Border
        {
            Background = Ui.C("#141b24"),
            Padding = new Thickness(8, 6),
            Child = new Grid { ColumnDefinitions = Cols() },
        };
        var headerGrid = (Grid)tableHeader.Child;
        foreach (var (t, i) in new[] { "ИМЯ", "КОМАНДА", "ИСТОЧНИК", "ПУТЬ", "ПОДПИСЬ", "СОСТОЯНИЕ" }.Select((t, i) => (t, i)))
        {
            var tb = new TextBlock { Text = t, FontWeight = FontWeight.SemiBold, Foreground = Ui.C("#8b98a5"), FontSize = 12 };
            Grid.SetColumn(tb, i);
            headerGrid.Children.Add(tb);
        }
        Grid.SetRow(tableHeader, 2);
        grid.Children.Add(tableHeader);

        var list = new ListBox
        {
            Background = Ui.C("#141b24"),
            Foreground = Ui.C("#dbe4ee"),
            ItemTemplate = new FuncDataTemplate<AutorunEntry>((e, _) =>
            {
                if (e == null) return new Border { Child = new TextBlock { Text = "" }, MinHeight = 30 };
                try
                {
                    // цвет строки: серый — отключено, жёлтый — подозрительно, обычный — остальное
                    IBrush fg = e.Disabled ? Ui.C("#66727f")
                        : e.Suspicious ? Ui.C("#f0b429")
                        : Ui.C("#dbe4ee");
                    IBrush stFg = e.Disabled ? Ui.C("#e05555")
                        : e.SystemProtected ? Ui.C("#8fa1b3")
                        : Ui.C("#7bc47f");
                    var g = new Grid { ColumnDefinitions = Cols() };
                    var name = new TextBlock { Text = e.Name ?? "", TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center, Foreground = fg };
                    Grid.SetColumn(name, 0);
                    var cmd = new TextBlock { Text = e.Command ?? "", TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center, Foreground = fg };
                    Grid.SetColumn(cmd, 1);
                    var loc = new TextBlock { Text = e.Location ?? "", TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center, Foreground = fg };
                    Grid.SetColumn(loc, 2);
                    var img = new TextBlock { Text = e.ImagePath ?? "", TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center, Foreground = fg };
                    Grid.SetColumn(img, 3);
                    var sig = new TextBlock { Text = e.Signature ?? "", TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center, Foreground = fg };
                    Grid.SetColumn(sig, 4);
                    var state = new TextBlock { Text = e.StateText ?? "", VerticalAlignment = VerticalAlignment.Center, Foreground = stFg, FontWeight = FontWeight.SemiBold };
                    Grid.SetColumn(state, 5);
                    g.Children.AddRange(new Control[] { name, cmd, loc, img, sig, state });
                    var border = new Border { Child = g, MinHeight = 30, Padding = new Thickness(8, 4) };
                    ToolTip.SetTip(border, (e.Location ?? "") + "\n" + (e.Command ?? ""));
                    return border;
                }
                catch (Exception tex)
                {
                    try { Log.Write("автозагрузки: ОШИБКА шаблона строки — " + tex.Message); } catch { }
                    return new Border { Child = new TextBlock { Text = "(ошибка строки)" }, MinHeight = 30 };
                }
            }),
        };
        list.Styles.Add(new Style(x => x.OfType<ListBoxItem>())
        {
            Setters = { new Setter(ListBoxItem.HorizontalContentAlignmentProperty, HorizontalAlignment.Stretch) }
        });

        Grid.SetRow(list, 3);
        grid.Children.Add(list);

        var status = new TextBlock { Foreground = Ui.C("#93a4b5"), FontSize = 12.5, Margin = new Thickness(2, 8, 0, 0), TextWrapping = TextWrapping.Wrap };
        Grid.SetRow(status, 4);
        grid.Children.Add(status);

        // ---- Контекстное меню (правый клик) ----
        var ctx = new ContextMenu();
        var miOpen = new MenuItem { Header = "Открыть расположение" };
        miOpen.Click += (_, _) => OpenLocation(list.SelectedItem as AutorunEntry);
        var miDisable = new MenuItem { Header = "Отключить" };
        miDisable.Click += (_, _) =>
        {
            var sel = list.SelectedItem as AutorunEntry;
            if (sel == null) { status.Text = "Выберите запись в списке."; return; }
            if (!sel.CanToggle || sel.Disabled) { status.Text = "Эта запись защищена системой или уже отключена."; return; }
            if (Autoruns.SetDisabled(sel, true, out var err))
            {
                Log.Write($"Автозагрузки: отключено «{sel.Name}» — {sel.Location}");
                status.Text = $"Отключено: {sel.Name}";
                Reload();
            }
            else status.Text = "Ошибка отключения: " + err;
        };
        var miEnable = new MenuItem { Header = "Включить" };
        miEnable.Click += (_, _) =>
        {
            var sel = list.SelectedItem as AutorunEntry;
            if (sel == null) { status.Text = "Выберите запись в списке."; return; }
            if (!sel.CanToggle || !sel.Disabled) { status.Text = "Эта запись защищена системой или уже включена."; return; }
            if (Autoruns.SetDisabled(sel, false, out var err))
            {
                Log.Write($"Автозагрузки: включено «{sel.Name}» — {sel.Location}");
                status.Text = $"Включено: {sel.Name}";
                Reload();
            }
            else status.Text = "Ошибка включения: " + err;
        };
        var miDelete = new MenuItem { Header = "Удалить" };
        miDelete.Click += (_, _) =>
        {
            var sel = list.SelectedItem as AutorunEntry;
            if (sel == null) { status.Text = "Выберите запись в списке."; return; }
            if (!sel.CanDelete) { status.Text = "Удаление недоступно — используйте «Отключить»."; return; }
            if (!Ui.Confirm(this, $"Удалить автозагрузку?\n\n{sel.Name}\n{sel.Location}", "Удаление автозагрузки")) return;
            if (Autoruns.Delete(sel, out var err))
            {
                Log.Write($"Автозагрузки: удалено «{sel.Name}» — {sel.Location}");
                status.Text = $"Удалено: {sel.Name}";
                Reload();
            }
            else status.Text = "Ошибка удаления: " + err;
        };
        ctx.Items.Add(miOpen);
        ctx.Items.Add(new Separator());
        ctx.Items.Add(miDisable);
        ctx.Items.Add(miEnable);
        ctx.Items.Add(new Separator());
        ctx.Items.Add(miDelete);
        list.ContextMenu = ctx;

        // ---------- логика ----------
        void UpdateButtons()
        {
            var sel = list.SelectedItem as AutorunEntry;
            bool tog = sel != null && sel.CanToggle;
            btnDisable.IsEnabled = tog && !sel.Disabled;
            btnEnable.IsEnabled = tog && sel.Disabled;
            btnDelete.IsEnabled = sel != null && sel.CanDelete;
            btnShow.IsEnabled = sel != null && !string.IsNullOrWhiteSpace(sel.ImagePath);
        }

        void ApplyFilter()
        {
            try
            {
                var q = filter.Text?.Trim();
                List<AutorunEntry> src;
                if (string.IsNullOrEmpty(q))
                    src = _autorunsAll;
                else
                    src = _autorunsAll.Where(x =>
                            (x.Name ?? "").Contains(q, StringComparison.OrdinalIgnoreCase) ||
                            (x.Command ?? "").Contains(q, StringComparison.OrdinalIgnoreCase) ||
                            (x.Location ?? "").Contains(q, StringComparison.OrdinalIgnoreCase) ||
                            (x.ImagePath ?? "").Contains(q, StringComparison.OrdinalIgnoreCase) ||
                            (x.Signature ?? "").Contains(q, StringComparison.OrdinalIgnoreCase) ||
                            (x.StateText ?? "").Contains(q, StringComparison.OrdinalIgnoreCase))
                        .ToList();
                list.ItemsSource = src;
                UpdateButtons();
            }
            catch { }
        }

        void OpenLocation(AutorunEntry sel)
        {
            if (sel == null) { status.Text = "Выберите запись в списке."; return; }
            var p = sel.ImagePath;
            if (string.IsNullOrWhiteSpace(p)) { status.Text = "Для этой записи нет пути к файлу."; return; }
            if (!File.Exists(p)) { status.Text = "Файл не найден: " + p; return; }
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = "/select,\"" + p + "\"",
                    UseShellExecute = true,
                });
                status.Text = "Открыто в Проводнике: " + p;
            }
            catch (Exception oex) { status.Text = "Не удалось открыть Проводник: " + oex.Message; }
        }

        void Reload()
        {
            status.Text = "Загрузка…";
            btnDisable.IsEnabled = btnEnable.IsEnabled = btnDelete.IsEnabled = btnShow.IsEnabled = false;
            Log.Write("автозагрузки: сбор начат");
            Task.Run(() =>
            {
                List<AutorunEntry> items = null;
                string collectError = null;
                try
                {
                    items = Autoruns.Collect();
                    Log.Write($"автозагрузки: собрано {items.Count} записей");
                }
                catch (Exception cex)
                {
                    collectError = cex.GetType().Name + ": " + cex.Message;
                    Log.Write("автозагрузки: ОШИБКА сбора — " + collectError);
                }
                Dispatcher.UIThread.Post(() =>
                {
                    try
                    {
                        if (collectError != null)
                        {
                            status.Text = "Ошибка загрузки: " + collectError;
                            return;
                        }
                        _autorunsAll = items ?? new List<AutorunEntry>();
                        ApplyFilter();
                        int dis = _autorunsAll.Count(x => x.Disabled);
                        int susp = _autorunsAll.Count(x => x.Suspicious);
                        status.Text = _autorunsAll.Count == 0
                            ? "Автозагрузок не найдено."
                            : $"Всего: {_autorunsAll.Count} · отключено: {dis} · подозрительных: {susp} (жёлтым — подозрительные, серым — отключённые, «Сист.» — только просмотр)";
                        Log.Write("автозагрузки: список отрисован");
                    }
                    catch (Exception uex) { try { Log.Write("автозагрузки: ОШИБКА UI — " + uex.Message); } catch { } }
                });
            });
        }
        _autorunsReload = Reload;

        filter.TextChanged += (s, e) => ApplyFilter();
        list.SelectionChanged += (s, e) => UpdateButtons();
        list.DoubleTapped += (s, e) => OpenLocation(list.SelectedItem as AutorunEntry);

        btnRefresh.Click += (s, e) => Reload();
        btnShow.Click += (s, e) => OpenLocation(list.SelectedItem as AutorunEntry);

        btnDisable.Click += (s, e) =>
        {
            var sel = list.SelectedItem as AutorunEntry;
            if (sel == null) { status.Text = "Выберите запись в списке."; return; }
            if (!sel.CanToggle || sel.Disabled) { status.Text = "Эта запись защищена системой или уже отключена."; return; }
            if (Autoruns.SetDisabled(sel, true, out var err))
            {
                Log.Write($"Автозагрузки: отключено «{sel.Name}» — {sel.Location}");
                status.Text = $"Отключено: {sel.Name}";
                Reload();
            }
            else status.Text = "Ошибка отключения: " + err;
        };

        btnEnable.Click += (s, e) =>
        {
            var sel = list.SelectedItem as AutorunEntry;
            if (sel == null) { status.Text = "Выберите запись в списке."; return; }
            if (!sel.CanToggle || !sel.Disabled) { status.Text = "Эта запись защищена системой или уже включена."; return; }
            if (Autoruns.SetDisabled(sel, false, out var err))
            {
                Log.Write($"Автозагрузки: включено «{sel.Name}» — {sel.Location}");
                status.Text = $"Включено: {sel.Name}";
                Reload();
            }
            else status.Text = "Ошибка включения: " + err;
        };

        btnDelete.Click += (s, e) =>
        {
            var sel = list.SelectedItem as AutorunEntry;
            if (sel == null) { status.Text = "Выберите запись в списке."; return; }
            if (!sel.CanDelete) { status.Text = "Удаление недоступно — используйте «Отключить»."; return; }
            if (!Ui.Confirm(this, $"Удалить автозагрузку?\n\n{sel.Name}\n{sel.Location}", "Удаление автозагрузки")) return;
            if (Autoruns.Delete(sel, out var err))
            {
                Log.Write($"Автозагрузки: удалено «{sel.Name}» — {sel.Location}");
                status.Text = $"Удалено: {sel.Name}";
                Reload();
            }
            else status.Text = "Ошибка удаления: " + err;
        };
        return grid;
    }

    TextBox _journalBox;
    Control BuildJournalPanel()
    {
        var grid = new Grid { Margin = new Thickness(0), RowDefinitions = { new RowDefinition(GridLength.Auto), new RowDefinition(GridLength.Star) } };
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 0, 0, 10) };
        var refresh = new Button { Content = Ui.IconText(Ui.MakeIcon(Icons.RotateCcw, Ui.C("#cfe0ee"), 14), "Обновить") };
        var clear = new Button { Content = "Очистить журнал", Classes = { "danger" } };
        refresh.Click += (s, e) => RefreshJournalPanel();
        clear.Click += (s, e) => { Log.Clear(); RefreshJournalPanel(); };
        row.Children.Add(refresh);
        row.Children.Add(clear);
        Grid.SetRow(row, 0);
        grid.Children.Add(row);

        _journalBox = new TextBox
        {
            IsReadOnly = true,
            AcceptsReturn = true,
            TextWrapping = TextWrapping.NoWrap,
            FontFamily = new Avalonia.Media.FontFamily("Consolas, monospace"),
            FontSize = 12.5,
            Background = Ui.C("#10161e"),
            Foreground = Ui.C("#c9d6e3"),
        };
        Grid.SetRow(_journalBox, 1);
        grid.Children.Add(_journalBox);

        RefreshJournalPanel();
        return grid;
    }

    void RefreshJournalPanel()
    {
        if (_journalBox == null) return;
        _journalBox.Text = Log.Read();
        _journalBox.CaretIndex = _journalBox.Text?.Length ?? 0;
    }

    // ---------- вкладка: карантин ----------
    ListBox _qList;
    TextBlock _qStatus;
    Button _qRestore, _qDelete;

    Control BuildQuarantinePanel()
    {
        var root = new Grid { Margin = new Thickness(14) };
        root.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
        root.RowDefinitions.Add(new RowDefinition(GridLength.Star));
        root.RowDefinitions.Add(new RowDefinition(GridLength.Auto));

        var actRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 0, 0, 10) };
        _qRestore = new Button { Content = Ui.IconText(Ui.MakeIcon(Icons.FolderOpen, Ui.C("#cfe0ee"), 14), "Восстановить"), MinWidth = 130 };
        _qRestore.Click += (s, e) => RestoreQuarantined();
        _qDelete = new Button { Content = Ui.IconText(Ui.MakeIcon(Icons.Trash2, Brushes.White, 14), "Удалить"), Classes = { "danger" }, MinWidth = 110 };
        _qDelete.Click += (s, e) => DeleteQuarantined();
        var qRefresh = new Button { Content = Ui.IconText(Ui.MakeIcon(Icons.RotateCcw, Ui.C("#cfe0ee"), 14), "Обновить") };
        qRefresh.Click += (s, e) => RefreshQuarantinePanel();
        actRow.Children.Add(_qRestore);
        actRow.Children.Add(_qDelete);
        actRow.Children.Add(qRefresh);
        root.Children.Add(actRow);

        _qList = new ListBox
        {
            ItemTemplate = new FuncDataTemplate<QuarantineEntry>((e, _) =>
            {
                var tb = new TextBlock
                {
                    Text = $"{e.Date}   {Path.GetFileName(e.Original)}   —   {e.Reason}",
                    TextTrimming = TextTrimming.CharacterEllipsis,
                };
                ToolTip.SetTip(tb, $"Оригинал: {e.Original}\nКарантин: {e.Quarantined}\nSHA-256: {e.Sha256}");
                return tb;
            }),
        };
        Grid.SetRow(_qList, 1);
        root.Children.Add(_qList);

        _qStatus = new TextBlock { Foreground = Ui.C("#93a4b5"), FontSize = 12.5, Margin = new Thickness(2, 8, 0, 0) };
        Grid.SetRow(_qStatus, 2);
        root.Children.Add(_qStatus);

        RefreshQuarantinePanel();
        return root;
    }

    void RefreshQuarantinePanel()
    {
        if (_qList == null) return;
        var entries = Quarantine.List();
        _qList.ItemsSource = entries;
        _qStatus.Text = entries.Count == 0 ? "Карантин пуст." : $"Всего в карантине: {entries.Count}";
        _qRestore.IsEnabled = entries.Count > 0;
        _qDelete.IsEnabled = entries.Count > 0;
    }

    void RestoreQuarantined()
    {
        var sel = _qList.SelectedItem as QuarantineEntry;
        if (sel == null) { _qStatus.Text = "Выберите запись в списке."; return; }
        if (Quarantine.Restore(sel.Quarantined, out var restored))
        {
            Log.Write($"Восстановлено из карантина: {restored}");
            _qStatus.Text = $"Восстановлено: {restored}";
            RefreshQuarantinePanel();
        }
        else Ui.Error(this, "Ошибка восстановления", restored);
    }

    void DeleteQuarantined()
    {
        var sel = _qList.SelectedItem as QuarantineEntry;
        if (sel == null) { _qStatus.Text = "Выберите запись в списке."; return; }
        if (!Ui.Confirm(this, $"Удалить файл из карантина без восстановления?\n\n{Path.GetFileName(sel.Original)}", "Удаление из карантина")) return;
        if (Quarantine.Delete(sel.Quarantined, out var deleted))
        {
            Log.Write($"Удалено из карантина: {sel.Original}");
            _qStatus.Text = $"Удалено: {deleted}";
            RefreshQuarantinePanel();
        }
        else Ui.Error(this, "Ошибка удаления", deleted);
    }

    NumericUpDown _setSusp, _setMal;
    CheckBox _setScripts, _setRt, _setSelfDefend, _setNetMon;
    Control BuildSettingsPanel()
    {
        var settings = RtProtection.Settings;
        var sp = new StackPanel { Margin = new Thickness(4, 4, 20, 4), Spacing = 12, MaxWidth = 760, HorizontalAlignment = HorizontalAlignment.Left };
        sp.Children.Add(new TextBlock { Text = "Пороги вердиктов", FontSize = 15, FontWeight = FontWeight.SemiBold, Foreground = Ui.C("#e8eef5") });

        NumericUpDown ThresholdRow(string label, int value)
        {
            var row = new StackPanel { Orientation = Orientation.Horizontal };
            row.Children.Add(new TextBlock { Text = label, VerticalAlignment = VerticalAlignment.Center, Width = 320 });
            var nud = new NumericUpDown { Minimum = 0, Maximum = 100, Increment = 1, Value = value, FormatString = "0", Width = 120, HorizontalAlignment = HorizontalAlignment.Right };
            row.Children.Add(nud);
            sp.Children.Add(row);
            return nud;
        }
        _setSusp = ThresholdRow("Оценка «подозрительно» (минимум)", settings.ThresholdSuspicious);
        _setMal = ThresholdRow("Оценка «опасно» (минимум)", settings.ThresholdMalicious);

        sp.Children.Add(new TextBlock { Text = "Защита", FontSize = 15, FontWeight = FontWeight.SemiBold, Foreground = Ui.C("#e8eef5"), Margin = new Thickness(0, 8, 0, 0) });

        CheckBox Check(string label, bool val)
        {
            var cb = new CheckBox { Content = label, IsChecked = val };
            sp.Children.Add(cb);
            return cb;
        }
        _setScripts = Check("Блокировать опасные скрипты (карантин .ps1, .bat, .cmd, .vbs, .js, .hta, .py)", settings.BlockDangerousScripts);
        _setRt = Check("Real-time защита (папки, процессы, автозапуск)", settings.RealtimeEnabled);
        _setSelfDefend = Check("Самозащита: защита процесса от завершения и инъекций (DACL)", settings.SelfDefend);
        _setNetMon = Check("Мониторинг подозрительных сетевых соединений", settings.NetworkMonitor);

        var hint = new TextBlock
        {
            Text = "Порог «опасно» должен быть больше порога «подозрительно». Real-time всегда помещает опасные файлы в карантин.",
            Foreground = Ui.C("#7d8b9b"), FontSize = 11.5, TextWrapping = TextWrapping.Wrap,
        };
        sp.Children.Add(hint);

        var save = new Button { Content = "Сохранить", Classes = { "primary" }, MinWidth = 130, HorizontalAlignment = HorizontalAlignment.Left };
        save.Click += (s, e) =>
        {
            int sv = (int)(_setSusp.Value ?? 0), mv = (int)(_setMal.Value ?? 0);
            if (sv < 0 || sv >= mv || mv > 100) { hint.Foreground = Ui.C("#e74c3c"); hint.IsVisible = true; return; }
            var st = RtProtection.Settings;
            st.ThresholdSuspicious = sv; st.ThresholdMalicious = mv;
            st.BlockDangerousScripts = _setScripts.IsChecked == true;
            st.RealtimeEnabled = _setRt.IsChecked == true;
            st.SelfDefend = _setSelfDefend.IsChecked == true;
            st.NetworkMonitor = _setNetMon.IsChecked == true;
            SettingsIO.Save(st);
            if (st.RealtimeEnabled) _rt.Start(); else _rt.Stop();
            Log.Write($"Настройки сохранены: подозрительно ≥ {sv}, опасно ≥ {mv}, RT: {st.RealtimeEnabled}, самозащита: {st.SelfDefend}, сеть: {st.NetworkMonitor}");
            hint.Foreground = Ui.C("#7bc47f");
            hint.Text = "Настройки сохранены.";
        };
        sp.Children.Add(save);
        return sp;
    }

    // Колбэк real-time модуля (вызывается на UI-потоке)
    void OnRtThreat(string path, string threatType)
    {
        _status.Text = $"RT: {Path.GetFileName(path)} — {threatType}";
    }

    static TextBlock Caption(string text) => new()
    {
        Text = text,
        FontSize = 11.5,
        FontWeight = FontWeight.SemiBold,
        Foreground = Ui.C("#7d8b9b"),
        Margin = new Thickness(2, 0, 0, 4),
    };

    Button MakeToolButton(string text, string iconPath, IBrush iconColor, string styleClass)
    {
        var b = new Button
        {
            Content = Ui.IconText(Ui.MakeIcon(iconPath, iconColor, 15), text),
            Padding = new Thickness(11, 5),
        };
        if (styleClass != null) b.Classes.Add(styleClass);
        return b;
    }

    void SetupTray(Bitmap appIcon)
    {
        var menu = new NativeMenu();
        var open = new NativeMenuItem("Открыть ShadowScan");
        open.Click += (s, e) => ShowFromTray();
        var exit = new NativeMenuItem("Выход");
        exit.Click += (s, e) =>
        {
            _exiting = true;
            _rt.Stop();
            App.Lifetime?.Shutdown();
        };
        menu.Items.Add(open);
        menu.Items.Add(new NativeMenuItemSeparator());
        menu.Items.Add(exit);
        var tray = new TrayIcon
        {
            Icon = new WindowIcon(appIcon),
            ToolTipText = "ShadowScan — нативный антивирус",
            Menu = menu,
        };
        tray.Clicked += (s, e) => ShowFromTray();
        TrayIcon.SetIcons(Application.Current, new TrayIcons { tray });
    }

    void ShowFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    async void OpenAddFilesDialog()
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Добавить файлы", AllowMultiple = true });
        AddPaths(files.Select(f => f.TryGetLocalPath()).Where(p => p != null).ToArray());
    }

    void ResetZone()
    {
        _zoneRect.Stroke = Ui.C("#2f4150");
        _zoneRect.Fill = Ui.C("#182230");
    }

    void AddPaths(string[] paths)
    {
        if (paths == null) return;
        int added = 0;
        var pendingSet = new HashSet<string>(_pending, StringComparer.OrdinalIgnoreCase);
        foreach (var p in paths)
        {
            if (p == null) continue;
            if (File.Exists(p) && pendingSet.Add(p)) { _pending.Add(p); _queueItems.Add(p); added++; }
            else if (Directory.Exists(p))
                try
                {
                    int dirLimit = 50000;
                    foreach (var f in Directory.EnumerateFiles(p, "*", SearchOption.AllDirectories))
                    {
                        if (--dirLimit <= 0) break;
                        if (pendingSet.Add(f)) { _pending.Add(f); _queueItems.Add(f); added++; }
                    }
                }
                catch { /* папка может быть недоступна */ }
        }
        if (added > 0) _status.Text = $"Добавлено: {added}. Всего в очереди: {_pending.Count}.";
    }

    // ---- Сканирование ----
    void StartScan()
    {
        if (_btnCancel.IsVisible) return;
        if (_pending.Count == 0) { _status.Text = "Очередь пуста — добавьте файлы или папки."; return; }
        _cancelled = false;
        _done = 0;
        _total = _pending.Count;
        _cleanCount = _suspCount = _malCount = _errCount = 0;
        _btnScan.IsVisible = false;
        _btnCancel.IsVisible = true;
        _status.Text = $"Сканирование {_total} файлов…";
        _rows.Clear();
        _results.Clear();
        var files = new List<string>(_pending);
        _pending.Clear();
        _queueItems.Clear();
        int susp = RtProtection.Settings.ThresholdSuspicious, mal = RtProtection.Settings.ThresholdMalicious;
        Log.Write($"Скан: {files.Count} файлов (пороги: подозрительно ≥ {susp}, опасно ≥ {mal})");
        new Thread(() => ScanLoop(files, susp, mal)) { IsBackground = true }.Start();
    }

    void ScanLoop(List<string> files, int susp, int mal)
    {
        var q = new Queue<string>(files);
        var resultsQ = new Queue<ScanResult>();
        var lockObj = new object();
        bool allWorkersDone = false;
        // Воркеры = число ядер (2..8): скан CPU-bound (энтропия, строки) + IO —
        // параллелизм даёт 3-6x ускорение.
        int workers = Math.Clamp(Environment.ProcessorCount, 2, 8);

        // Сборщик: батчит результаты, гоняет yara (один yr.exe на батч) и только
        // ПОТОМ показывает строки — yara-находки попадают в вердикт до отрисовки.
        // При отмене yara пропускается — скан обязан завершиться быстро.
        var collector = new Thread(() =>
        {
            var batch = new List<ScanResult>();
            while (true)
            {
                ScanResult r = null;
                bool done = false;
                lock (lockObj)
                {
                    if (resultsQ.Count > 0) r = resultsQ.Dequeue();
                    else if (allWorkersDone) done = true;
                }
                if (r != null) batch.Add(r);
                if (batch.Count >= 200)
                {
                    if (!_cancelled) ScannerCore.RunYaraBatch(batch);
                    foreach (var rr in batch)
                    {
                        ApplyThresholds(rr, susp, mal);
                        Dispatcher.UIThread.Post(() => OnFileDone(rr));
                    }
                    batch.Clear();
                }
                if (done) break; // выходим даже с непустым батчем — хвост допишет код ниже
                if (r == null) Thread.Sleep(5);
            }
            if (batch.Count > 0)
            {
                if (!_cancelled) ScannerCore.RunYaraBatch(batch);
                foreach (var rr in batch)
                {
                    ApplyThresholds(rr, susp, mal);
                    Dispatcher.UIThread.Post(() => OnFileDone(rr));
                }
            }
        }) { IsBackground = true };
        collector.Start();

        var threads = new List<Thread>();
        for (int w = 0; w < workers; w++)
        {
            threads.Add(new Thread(() =>
            {
                while (true)
                {
                    if (_cancelled) break;
                    string file;
                    lock (lockObj)
                    {
                        if (q.Count == 0) break;
                        file = q.Dequeue();
                    }
                    ScanResult r = null;
                    try
                    {
                        var fi = new FileInfo(file);
                        if (_scanCache.TryGetValue(file, out var ce) && ce.Size == fi.Length && ce.Mtime == fi.LastWriteTimeUtc)
                            r = ce.Result;
                    }
                    catch { }
                    if (r == null)
                    {
                        try { r = ScannerCore.ScanFile(file); }
                        catch (Exception ex) { r = ScannerCore.ErrorResult(file, ex.Message); }
                        try
                        {
                            var fi = new FileInfo(file);
                            lock (lockObj) _scanCache[file] = (fi.Length, fi.LastWriteTimeUtc, r);
                        }
                        catch { }
                    }
                    if (r.Verdict == "error")
                        Dispatcher.UIThread.Post(() => OnFileDone(r));
                    else
                        lock (lockObj) resultsQ.Enqueue(r);
                }
            }) { IsBackground = true });
        }
        try
        {
            foreach (var t in threads) t.Start();
            foreach (var t in threads) t.Join();
            lock (lockObj) allWorkersDone = true;
            collector.Join();
        }
        catch (Exception ex)
        {
            try { Log.Write("ошибка сканирования: " + ex.Message); } catch { }
        }
        finally
        {
            // Кнопки возвращаются при ЛЮБОМ сценарии (исключение, отмена, конец)
            try { Dispatcher.UIThread.Post(ScanFinished); } catch { }
        }
    }

    // Пороги из настроек применяются поверх вердикта движка
    static void ApplyThresholds(ScanResult r, int susp, int mal)
    {
        if (r.Verdict == "error") return;
        string v = r.Score >= mal ? "malicious" : r.Score >= susp ? "suspicious" : "clean";
        if (v == r.Verdict) return;
        r.Verdict = v;
        r.ThreatType = v == "clean" ? "Чисто"
            : v == "suspicious" ? (r.ThreatType == null || r.ThreatType == "Вредоносное ПО" ? "Подозрительное ПО" : r.ThreatType)
            : (r.ThreatType == null || r.ThreatType is "Чисто" or "Подозрительное ПО" ? "Вредоносное ПО" : r.ThreatType);
    }

    void OnFileDone(ScanResult r)
    {
        _results[r.File] = r;
        _rows.Add(new GridRow(r));
        switch (r.Verdict)
        {
            case "malicious":
                _malCount++;
                _notifier.Show(new Notification("Обнаружена угроза!", $"{Path.GetFileName(r.File)} — {r.ThreatType} (оценка {r.Score})", NotificationType.Warning, TimeSpan.FromSeconds(5)));
                break;
            case "suspicious": _suspCount++; break;
            case "clean": _cleanCount++; break;
            default: _errCount++; break;
        }
        _status.Text = $"Обработано {_rows.Count} из {_total} — угроз: {_malCount}";
    }

    void ScanFinished()
    {
        _btnScan.IsVisible = true;
        _btnCancel.IsVisible = false;
        var summary = $"Готово: чисто — {_cleanCount}, подозрительно — {_suspCount}, опасно — {_malCount}, ошибок — {_errCount}.";
        _status.Text = summary;
        Log.Write("Скан завершён: " + summary);
        if (_malCount > 0)
            _notifier.Show(new Notification("ShadowScan", $"Обнаружено опасных файлов: {_malCount}", NotificationType.Warning, TimeSpan.FromSeconds(8)));
    }


    // ---- Детали выбранной строки ----
    void ShowDetails()
    {
        var sel = _grid.SelectedItem as GridRow;
        bool mal = sel != null && sel.Item.Verdict == "malicious";
        _btnQuarantine.IsVisible = mal;
        _btnDelete.IsVisible = mal;
        if (sel == null)
        {
            _selectedLabel.Text = "";
            _details.Text = "Выберите файл в таблице, чтобы увидеть детали анализа.";
            return;
        }
        var r = sel.Item;
        _selectedLabel.Text = r.File;
        var sb = new StringBuilder();
        sb.AppendLine($"Файл: {r.File}");
        sb.AppendLine($"SHA-256: {r.Sha256}");
        sb.AppendLine($"Вердикт: {sel.VerdictLabel} (оценка {r.Score}/100, {r.Ms} мс)");
        sb.AppendLine($"Тип угрозы: {r.ThreatType ?? "—"}");
        if (r.Categories.Count > 0) sb.AppendLine("Категории: " + string.Join(", ", r.Categories));
        sb.AppendLine(new string('═', 70));
        foreach (var f in r.Findings) sb.AppendLine($"[{f.Severity.ToUpperInvariant()}] {f.Category} — {f.Detail}");
        _details.Text = sb.ToString();
    }

    void RemoveRow(string path)
    {
        var row = _rows.FirstOrDefault(x => string.Equals(x.Item.File, path, StringComparison.OrdinalIgnoreCase));
        if (row != null) _rows.Remove(row);
        _results.Remove(path);
    }

    // ---- Действия с выбранным файлом ----
    void QuarantineSelected()
    {
        var row = _grid.SelectedItem as GridRow;
        if (row == null) return;
        var r = row.Item;
        if (Quarantine.QuarantineFile(r.File, r.Sha256, "выбран пользователем", out var msg))
        {
            RemoveRow(r.File);
            _status.Text = $"В карантин: {Path.GetFileName(r.File)}";
            Log.Write($"Карантин: {r.File} — {r.ThreatType}");
            _notifier.Show(new Notification("Помещено в карантин", Path.GetFileName(r.File), NotificationType.Success, TimeSpan.FromSeconds(4)));
        }
        else Ui.Error(this, "Ошибка карантина", msg);
    }

    void DeleteSelected()
    {
        var row = _grid.SelectedItem as GridRow;
        if (row == null) return;
        var path = row.Item.File;
        if (!Ui.Confirm(this, $"Удалить файл навсегда?\n\n{path}", "Удаление")) return;
        try
        {
            File.Delete(path);
            RemoveRow(path);
            _status.Text = $"Удалён навсегда: {Path.GetFileName(path)}";
            Log.Write($"Удаление навсегда: {path}");
            _notifier.Show(new Notification("Файл удалён", Path.GetFileName(path), NotificationType.Success, TimeSpan.FromSeconds(4)));
        }
        catch (Exception ex) { Ui.Error(this, "Ошибка удаления", ex.Message); }
    }

    // Цветной бейдж вердикта
    static Border BuildVerdictBadge(GridRow row)
    {
        string verdict = row?.Item?.Verdict ?? "error";
        string text, color;
        switch (verdict)
        {
            case "malicious": text = "ОПАСНО"; color = "#e74c3c"; break;
            case "suspicious": text = "ПОДОЗРИТЕЛЬНО"; color = "#f39c12"; break;
            case "clean": text = "ЧИСТО"; color = "#27ae60"; break;
            default: text = "ОШИБКА"; color = "#7f8c8d"; break;
        }
        return new Border
        {
            Background = Ui.C(color),
            CornerRadius = new CornerRadius(10),
            Padding = new Thickness(9, 3),
            VerticalAlignment = VerticalAlignment.Center,
            HorizontalAlignment = HorizontalAlignment.Left,
            Child = new TextBlock
            {
                Text = text,
                Foreground = Brushes.White,
                FontSize = 11.5,
                FontWeight = FontWeight.Bold,
            },
        };
    }

    // Свойства для отображения в таблице (колонки — FuncDataTemplate, без биндингов)
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.PublicFields)]
    sealed class GridRow
    {
        public ScanResult Item;
        public GridRow(ScanResult r) => Item = r;
        public string FileName => Path.GetFileName(Item.File);
        public string VerdictLabel => Item.Verdict == "malicious" ? "ОПАСНО" : Item.Verdict == "suspicious" ? "ПОДОЗРИТЕЛЬНО" : Item.Verdict == "clean" ? "ЧИСТО" : "ОШИБКА";
        public string ScoreStr => Item.Score + " / 100";
        public string ThreatType => string.IsNullOrEmpty(Item.ThreatType) ? "—" : Item.ThreatType;
    }
}

// ============ Окно настроек ============
public class SettingsWindow : Window
{
    readonly Settings _settings;
    readonly NumericUpDown _susp, _mal;
    readonly CheckBox _scripts, _rt, _selfDefend, _netMon;
    readonly TextBlock _hint;
    readonly Action<bool> _onRealtimeChanged;

    public SettingsWindow(Settings settings, Window owner, Action<bool> onRealtimeChanged = null)
    {
        _settings = settings;
        _onRealtimeChanged = onRealtimeChanged;
        Title = "Настройки";
        Width = 440;
        Height = 560;
        CanResize = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = Ui.C("#161e28");

        var root = new StackPanel { Margin = new Thickness(18), Spacing = 12 };
        root.Children.Add(new TextBlock { Text = "Пороги вердиктов", FontSize = 14, FontWeight = FontWeight.SemiBold, Foreground = Ui.C("#e8eef5") });

        _susp = ThresholdRow(root, "Оценка «подозрительно» (минимум)", settings.ThresholdSuspicious);
        _mal = ThresholdRow(root, "Оценка «опасно» (минимум)", settings.ThresholdMalicious);

        _scripts = new CheckBox
        {
            Content = "Блокировать опасные скрипты (карантин .ps1, .bat, .cmd, .vbs, .js, .hta, .py)",
            IsChecked = settings.BlockDangerousScripts,
            Margin = new Thickness(0, 6, 0, 0),
        };
        _rt = new CheckBox
        {
            Content = "Real-time защита (папки, процессы, автозапуск)",
            IsChecked = settings.RealtimeEnabled,
        };
        _selfDefend = new CheckBox
        {
            Content = "Самозащита: защита процесса от завершения и инъекций (DACL)",
            IsChecked = settings.SelfDefend,
        };
        _netMon = new CheckBox
        {
            Content = "Мониторинг подозрительных сетевых соединений",
            IsChecked = settings.NetworkMonitor,
        };
        _hint = new TextBlock
        {
            Text = "Порог «опасно» должен быть больше порога «подозрительно».",
            Foreground = Ui.C("#e74c3c"),
            TextWrapping = TextWrapping.Wrap,
            IsVisible = false,
        };
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 10, 0, 0) };
        var save = new Button { Content = "Сохранить", Classes = { "primary" }, MinWidth = 110 };
        save.Click += (s, e) => Save();
        var cancel = new Button { Content = "Отмена", MinWidth = 90 };
        cancel.Click += (s, e) => Close();
        row.Children.Add(save);
        row.Children.Add(cancel);
        root.Children.Add(_scripts);
        root.Children.Add(_rt);
        root.Children.Add(_selfDefend);
        root.Children.Add(_netMon);
        root.Children.Add(new TextBlock
        {
            Text = "Real-time защита всегда автоматически помещает опасные файлы в карантин.",
            Foreground = Ui.C("#7d8b9b"),
            FontSize = 11.5,
            TextWrapping = TextWrapping.Wrap,
        });
        root.Children.Add(_hint);
        root.Children.Add(row);
        // ScrollViewer: на маленьких экранах кнопки не уезжают за край окна
        Content = new ScrollViewer { Content = root, VerticalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Auto };
    }

    NumericUpDown ThresholdRow(StackPanel root, string label, int value)
    {
        var sp = new StackPanel { Orientation = Orientation.Horizontal };
        sp.Children.Add(new TextBlock { Text = label, VerticalAlignment = VerticalAlignment.Center });
        var nud = new NumericUpDown
        {
            Minimum = 0,
            Maximum = 100,
            Increment = 1,
            Value = (decimal)value,
            FormatString = "0",
            Width = 110,
            HorizontalAlignment = HorizontalAlignment.Right,
        };
        sp.Children.Add(nud);
        root.Children.Add(sp);
        return nud;
    }

    void Save()
    {
        int s = (int)(_susp.Value ?? 0);
        int m = (int)(_mal.Value ?? 0);
        if (s < 0 || s >= m || m > 100)
        {
            _hint.IsVisible = true;
            return;
        }
        _settings.ThresholdSuspicious = s;
        _settings.ThresholdMalicious = m;
        _settings.BlockDangerousScripts = _scripts.IsChecked == true;
        _settings.RealtimeEnabled = _rt.IsChecked == true;
        _settings.SelfDefend = _selfDefend.IsChecked == true;
        _settings.NetworkMonitor = _netMon.IsChecked == true;
        SettingsIO.Save(_settings);
        Log.Write($"Настройки сохранены: подозрительно ≥ {s}, опасно ≥ {m}, блок.скриптов: {_settings.BlockDangerousScripts}, RT: {_settings.RealtimeEnabled}, самозащита: {_settings.SelfDefend}, сеть: {_settings.NetworkMonitor}");
        _onRealtimeChanged?.Invoke(_settings.RealtimeEnabled);
        Close();
    }
}

// ============ Окно журнала ============
public class JournalWindow : Window
{
    readonly TextBox _box;

    public JournalWindow(Window owner)
    {
        Title = "Журнал событий";
        Width = 760;
        Height = 500;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = Ui.C("#161e28");

        var root = new DockPanel { Margin = new Thickness(14) };
        var top = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 0, 0, 10) };
        var refresh = new Button { Content = Ui.IconText(Ui.MakeIcon(Icons.RotateCcw, Ui.C("#cfe0ee"), 14), "Обновить") };
        refresh.Click += (s, e) => Reload();
        top.Children.Add(refresh);
        top.Children.Add(new TextBlock { Text = "shadowscan.log", Foreground = Ui.C("#7d8b9b"), VerticalAlignment = VerticalAlignment.Center });
        DockPanel.SetDock(top, Dock.Top);
        root.Children.Add(top);
        _box = new TextBox
        {
            IsReadOnly = true,
            AcceptsReturn = true,
            TextWrapping = TextWrapping.NoWrap,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12.5,
        };
        root.Children.Add(_box);
        Content = root;
        Reload();
    }

    void Reload()
    {
        _box.Text = Log.Read();
        _box.CaretIndex = _box.Text.Length; // прокрутка в конец
    }
}

// ============ Окно карантина ============
public class QuarantineWindow : Window
{
    readonly ListBox _list;
    readonly TextBlock _status;
    readonly Button _btnRestore, _btnDelete;

    public QuarantineWindow(Window owner)
    {
        Title = "Карантин";
        Width = 780;
        Height = 470;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = Ui.C("#161e28");

        var root = new Grid { Margin = new Thickness(14) };
        root.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
        root.RowDefinitions.Add(new RowDefinition(GridLength.Star));
        root.RowDefinitions.Add(new RowDefinition(GridLength.Auto));

        var actRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 0, 0, 10) };
        _btnRestore = new Button { Content = Ui.IconText(Ui.MakeIcon(Icons.FolderOpen, Ui.C("#cfe0ee"), 14), "Восстановить"), MinWidth = 130 };
        _btnRestore.Click += (s, e) => RestoreSelected();
        _btnDelete = new Button { Content = Ui.IconText(Ui.MakeIcon(Icons.Trash2, Brushes.White, 14), "Удалить"), Classes = { "danger" }, MinWidth = 110 };
        _btnDelete.Click += (s, e) => DeleteSelected();
        var btnRefresh = new Button { Content = Ui.IconText(Ui.MakeIcon(Icons.RotateCcw, Ui.C("#cfe0ee"), 14), "Обновить") };
        btnRefresh.Click += (s, e) => Reload();
        actRow.Children.Add(_btnRestore);
        actRow.Children.Add(_btnDelete);
        actRow.Children.Add(btnRefresh);
        root.Children.Add(actRow);

        _list = new ListBox
        {
            ItemTemplate = new FuncDataTemplate<QuarantineEntry>((e, _) =>
            {
                var tb = new TextBlock
                {
                    Text = $"{e.Date}   {Path.GetFileName(e.Original)}   —   {e.Reason}",
                    TextTrimming = TextTrimming.CharacterEllipsis,
                };
                ToolTip.SetTip(tb, $"Оригинал: {e.Original}\nКарантин: {e.Quarantined}\nSHA-256: {e.Sha256}");
                return tb;
            }),
        };
        Grid.SetRow(_list, 1);
        root.Children.Add(_list);

        _status = new TextBlock { Foreground = Ui.C("#93a4b5"), FontSize = 12.5, Margin = new Thickness(2, 8, 0, 0) };
        Grid.SetRow(_status, 2);
        root.Children.Add(_status);
        Content = root;
        Reload();
    }

    void Reload()
    {
        var entries = Quarantine.List();
        _list.ItemsSource = entries;
        _status.Text = entries.Count == 0 ? "Карантин пуст." : $"Всего в карантине: {entries.Count}";
        _btnRestore.IsEnabled = entries.Count > 0;
        _btnDelete.IsEnabled = entries.Count > 0;
    }

    void RestoreSelected()
    {
        var sel = _list.SelectedItem as QuarantineEntry;
        if (sel == null) { _status.Text = "Выберите запись в списке."; return; }
        if (Quarantine.Restore(sel.Quarantined, out var restored))
        {
            Log.Write($"Восстановлено из карантина: {restored}");
            _status.Text = $"Восстановлено: {restored}";
            Reload();
        }
        else Ui.Error(this, "Ошибка восстановления", restored);
    }

    void DeleteSelected()
    {
        var sel = _list.SelectedItem as QuarantineEntry;
        if (sel == null) { _status.Text = "Выберите запись в списке."; return; }
        if (!Ui.Confirm(this, $"Удалить файл из карантина без восстановления?\n\n{Path.GetFileName(sel.Original)}", "Удаление из карантина")) return;
        if (Quarantine.Delete(sel.Quarantined, out var deleted))
        {
            Log.Write($"Удалено из карантина: {sel.Original}");
            _status.Text = $"Удалено: {deleted}";
            Reload();
        }
        else Ui.Error(this, "Ошибка удаления", deleted);
    }
}

// ============ Карантин ============
public class QuarantineEntry { public string Original; public string Quarantined; public string Sha256; public string Date; public string Reason; }

public static class Quarantine
{
    static string Dir => Path.Combine(AppContext.BaseDirectory, "quarantine");
    static string Manifest => Path.Combine(Dir, "quarantine.json");

    public static bool QuarantineFile(string path, string sha256, string reason, out string result)
    {
        result = "";
        try
        {
            Directory.CreateDirectory(Dir);
            if (sha256 == null) { using var sha = System.Security.Cryptography.SHA256.Create(); using var fs = File.OpenRead(path); sha256 = BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLowerInvariant(); }
            var qdir = Path.Combine(Dir, sha256); Directory.CreateDirectory(qdir);
            var qpath = Path.Combine(qdir, Path.GetFileName(path) ?? "q.bin");
            File.Move(path, qpath);
            var list = List();
            list.Add(new QuarantineEntry { Original = path, Quarantined = qpath, Sha256 = sha256, Date = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Reason = reason });
            File.WriteAllText(Manifest, JsonSerializer.Serialize(list, ScanJsonContext.Default.ListQuarantineEntry));
            result = qpath; return true;
        }
        catch (Exception ex) { result = ex.Message; return false; }
    }

    public static List<QuarantineEntry> List()
    {
        try { return File.Exists(Manifest) ? JsonSerializer.Deserialize(File.ReadAllText(Manifest), ScanJsonContext.Default.ListQuarantineEntry) ?? new() : new(); }
        catch { return new(); }
    }

    public static bool Restore(string qpath, out string result)
    {
        result = "";
        try
        {
            var list = List();
            var e = list.FirstOrDefault(x => x.Quarantined.Equals(qpath, StringComparison.OrdinalIgnoreCase));
            if (e == null) { result = "не найдено"; return false; }
            Directory.CreateDirectory(Path.GetDirectoryName(e.Original));
            File.Move(qpath, e.Original);
            list.Remove(e); File.WriteAllText(Manifest, JsonSerializer.Serialize(list, ScanJsonContext.Default.ListQuarantineEntry));
            result = e.Original; return true;
        }
        catch (Exception ex) { result = ex.Message; return false; }
    }

    public static bool Delete(string qpath, out string result)
    {
        result = "";
        try
        {
            var list = List();
            var e = list.FirstOrDefault(x => x.Quarantined.Equals(qpath, StringComparison.OrdinalIgnoreCase));
            if (e == null) { result = "запись не найдена"; return false; }
            if (File.Exists(qpath)) File.Delete(qpath);
            list.Remove(e); File.WriteAllText(Manifest, JsonSerializer.Serialize(list, ScanJsonContext.Default.ListQuarantineEntry));
            result = e.Original; return true;
        }
        catch (Exception ex) { result = ex.Message; return false; }
    }
}
