using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using DetectAcUI.Scanning;

namespace DetectAcUI;

// ==================== Модальное окно отчёта сканирования ====================
// Дизайн повторяет основной лаунчер: тёмный фон, красный акцент, Consolas,
// тонкие скроллбары, анимации появления/переключения разделов.

public partial class ReportWindow : Window
{
    private readonly ScanReport _report;
    private readonly string _lang;
    private ReportSection? _current;
    private readonly Dictionary<string, Border> _sideItems = new();
    private readonly List<ReportRow> _filtered = new();

    private static readonly Brush CellBrush = Freeze(new SolidColorBrush(Color.FromRgb(0xB9, 0xBC, 0xC4)));
    private static readonly Brush CellHiBrush = Freeze(new SolidColorBrush(Color.FromRgb(0xFF, 0x8C, 0x97)));
    private static readonly Brush MutedBrush = Freeze(new SolidColorBrush(Color.FromRgb(0x6A, 0x6D, 0x76)));
    private static readonly Brush IdBrush = Freeze(new SolidColorBrush(Color.FromRgb(0x9C, 0xA0, 0xA8)));
    private static readonly Brush AccentBrush = Freeze(new SolidColorBrush(Color.FromRgb(0xFF, 0x5C, 0x6B)));

    private static readonly SolidColorBrush ItemBg = Freeze(new SolidColorBrush(Color.FromRgb(0x10, 0x10, 0x14)));
    private static readonly SolidColorBrush ItemBgHover = Freeze(new SolidColorBrush(Color.FromRgb(0x15, 0x15, 0x1B)));
    private static readonly SolidColorBrush ItemBgSelected = Freeze(new SolidColorBrush(Color.FromRgb(0x17, 0x0F, 0x13)));
    private static readonly SolidColorBrush ItemBorder = Freeze(new SolidColorBrush(Color.FromRgb(0x22, 0x22, 0x2A)));

    private static T Freeze<T>(T b) where T : Brush
    {
        b.Freeze();
        return b;
    }

    // ==================== Локализация ====================

    private static readonly Dictionary<string, string> Ru = new()
    {
        ["title"] = "sentinel — отчёт",
        ["meta"] = "scan report",
        ["search"] = "поиск…",
        ["empty"] = "нет данных",
        ["noMatches"] = "ничего не найдено",
        ["close"] = "Закрыть",
        ["hint"] = "Esc — закрыть · поиск фильтрует таблицу · F11 — весь экран",
        ["fullscreen"] = "На весь экран (F11)",
        ["fullscreenOff"] = "Выйти из полного экрана (Esc/F11)",
        ["openFolder"] = "Открыть папку",
        ["entries"] = "записей: {0}",
        ["found"] = "найдено: {0} из {1}",
        ["statOk"] = "данные собраны",
        ["statEmpty"] = "артефактов не найдено",
        ["statNoAccess"] = "нет доступа",
        ["statError"] = "ошибка сбора",
        ["pc"] = "ПК: {0} · пользователь: {1} · админ: {2} · сформирован: {3}",
        ["yes"] = "да",
        ["no"] = "нет"
    };

    private static readonly Dictionary<string, string> En = new()
    {
        ["title"] = "sentinel — report",
        ["meta"] = "scan report",
        ["search"] = "search…",
        ["empty"] = "no data",
        ["noMatches"] = "nothing found",
        ["close"] = "Close",
        ["hint"] = "Esc — close · search filters the table · F11 — fullscreen",
        ["fullscreen"] = "Fullscreen (F11)",
        ["fullscreenOff"] = "Exit fullscreen (Esc/F11)",
        ["openFolder"] = "Open folder",
        ["entries"] = "entries: {0}",
        ["found"] = "found: {0} of {1}",
        ["statOk"] = "collected",
        ["statEmpty"] = "no artifacts found",
        ["statNoAccess"] = "no access",
        ["statError"] = "collection error",
        ["pc"] = "PC: {0} · user: {1} · admin: {2} · generated: {3}",
        ["yes"] = "yes",
        ["no"] = "no"
    };

    private string L(string key) => _lang == "ru" ? Ru[key] : En[key];

    private bool _fullscreen;

    public ReportWindow(string lang, ScanReport report)
    {
        _lang = lang;
        _report = report;
        InitializeComponent();

        Title = L("title");
        TitleText.Text = L("title");
        TitleMeta.Text = L("meta");
        SearchHint.Text = L("search");
        EmptyText.Text = L("empty");
        CloseButton.Content = L("close");
        FooterHint.Text = L("hint");
        FullscreenButton.ToolTip = L("fullscreen");

        FooterMeta.Text = string.Format(L("pc"),
            _report.MachineName, _report.UserName,
            _report.IsAdmin ? L("yes") : L("no"),
            (_report.FinishedAt == default ? DateTime.Now : _report.FinishedAt).ToString("yyyy-MM-dd HH:mm"))
            + (_report.LicenseExpires is { } exp
                ? " · " + (_lang == "ru" ? "ключ до " : "key until ") + exp.ToString("yyyy-MM-dd")
                : "");

        BuildSidebar();
        SelectSection(_report.Sections.FirstOrDefault());
    }

    // ==================== Боковой список разделов ====================

    private void BuildSidebar()
    {
        SidePanel.Children.Clear();
        _sideItems.Clear();

        foreach (var section in _report.Sections)
        {
            var dot = new Ellipse
            {
                Width = 7,
                Height = 7,
                Fill = section.Status switch
                {
                    SectionStatus.Ok => new SolidColorBrush(Color.FromRgb(0x8F, 0x9B, 0xA8)),
                    SectionStatus.NoAccess => AccentBrush,
                    SectionStatus.Error => AccentBrush,
                    _ => new SolidColorBrush(Color.FromRgb(0x4E, 0x51, 0x58))
                },
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 9, 0)
            };

            var title = new TextBlock
            {
                Text = section.Title(_lang),
                FontSize = 12.5,
                Foreground = CellBrush,
                VerticalAlignment = VerticalAlignment.Center
            };

            var count = new TextBlock
            {
                Text = section.Rows.Count.ToString(),
                FontFamily = new FontFamily("Consolas"),
                FontSize = 10.5,
                Foreground = MutedBrush,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(8, 1, 0, 0)
            };

            var row = new StackPanel { Orientation = Orientation.Horizontal };
            row.Children.Add(dot);
            row.Children.Add(title);
            row.Children.Add(count);

            var item = new Border
            {
                CornerRadius = new CornerRadius(8),
                Background = ItemBg,
                BorderBrush = ItemBorder,
                BorderThickness = new Thickness(1),
                Padding = new Thickness(12, 10, 10, 10),
                Margin = new Thickness(0, 0, 0, 6),
                Cursor = Cursors.Hand,
                Child = row,
                Tag = section
            };

            item.MouseEnter += (_, _) =>
            {
                if (!ReferenceEquals(_current, section)) item.Background = ItemBgHover;
            };
            item.MouseLeave += (_, _) =>
            {
                if (!ReferenceEquals(_current, section)) item.Background = ItemBg;
            };
            item.MouseLeftButtonDown += (_, _) => SelectSection(section);

            _sideItems[section.Key] = item;
            SidePanel.Children.Add(item);
        }
    }

    private void SelectSection(ReportSection? section)
    {
        if (section == null) return;
        _current = section;

        // визуальное состояние элементов списка
        foreach (var (key, item) in _sideItems)
        {
            var selected = key == section.Key;
            item.Background = selected ? ItemBgSelected : ItemBg;
            item.BorderBrush = selected ? AccentBrush : ItemBorder;
            item.Effect = selected
                ? new System.Windows.Media.Effects.DropShadowEffect
                {
                    Color = Color.FromRgb(0xFF, 0x3B, 0x4B),
                    BlurRadius = 16,
                    ShadowDepth = 0,
                    Opacity = 0.25
                }
                : null;
            if (item.Child is StackPanel sp && sp.Children.Count > 1 && sp.Children[1] is TextBlock tb)
                tb.Foreground = selected ? new SolidColorBrush(Color.FromRgb(0xF4, 0xF4, 0xF6)) : CellBrush;
        }

        SectionTitle.Text = section.Title(_lang);

        var meta = string.Format(L("entries"), section.Rows.Count);
        meta += " · " + section.Status switch
        {
            SectionStatus.Ok => L("statOk"),
            SectionStatus.Empty => L("statEmpty"),
            SectionStatus.NoAccess => L("statNoAccess"),
            _ => L("statError")
        };
        SectionMeta.Text = meta;

        SectionNote.Text = section.Note(_lang) ?? "";
        SectionNote.Visibility = string.IsNullOrEmpty(SectionNote.Text)
            ? Visibility.Collapsed
            : Visibility.Visible;

        var canSearch = section.Rows.Count > 0;
        SearchBox.IsEnabled = canSearch;
        SearchBox.Opacity = canSearch ? 1 : 0.35;
        SearchInput.Text = string.Empty;

        BuildColumns(section);
        Filter();
        FadeTable();
    }

    // ==================== Таблица ====================

    private void BuildColumns(ReportSection section)
    {
        var gridView = new GridView();
        var headers = section.Columns(_lang);

        for (var i = 0; i < headers.Length; i++)
        {
            var index = i;
            var width = index < section.ColumnWidths.Length ? section.ColumnWidths[index] : 120;

            var column = new GridViewColumn
            {
                Header = headers[index].ToUpperInvariant(),
                Width = width,
                CellTemplate = MakeTextTemplate(index)
            };
            gridView.Columns.Add(column);
        }

        // колонка действий («открыть папку») — только если в разделе есть кнопки
        if (section.Rows.Any(r => r.Actions.Count > 0))
        {
            gridView.Columns.Add(new GridViewColumn
            {
                Header = "",
                Width = 130,
                CellTemplate = MakeActionsTemplate()
            });
        }

        Table.View = gridView;
    }

    // Текстовая ячейка: подсветка строки-подозреваемого + тултип с полным текстом
    private DataTemplate MakeTextTemplate(int index)
    {
        var text = new FrameworkElementFactory(typeof(TextBlock));
        text.SetBinding(TextBlock.TextProperty, new Binding($"Cells[{index}]"));
        text.SetBinding(ToolTipProperty, new Binding($"Cells[{index}]"));

        var style = new Style(typeof(TextBlock));
        style.Setters.Add(new Setter(TextBlock.ForegroundProperty, CellBrush));
        style.Setters.Add(new Setter(TextBlock.FontSizeProperty, 12.0));
        style.Setters.Add(new Setter(TextBlock.MarginProperty, new Thickness(10, 5, 8, 5)));
        style.Setters.Add(new Setter(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center));
        style.Setters.Add(new Setter(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis));

        var highlight = new DataTrigger
        {
            Binding = new Binding("Highlight"),
            Value = true
        };
        highlight.Setters.Add(new Setter(TextBlock.ForegroundProperty, CellHiBrush));
        style.Triggers.Add(highlight);
        text.SetValue(FrameworkElement.StyleProperty, style);

        return new DataTemplate { VisualTree = text };
    }

    // Ячейка действий: кнопки «открыть папку», привязанные к списку RowAction
    private DataTemplate MakeActionsTemplate()
    {
        var itemsControl = new FrameworkElementFactory(typeof(ItemsControl));
        itemsControl.SetValue(FrameworkElement.MarginProperty, new Thickness(8, 2, 6, 2));
        itemsControl.SetBinding(ItemsControl.ItemsSourceProperty, new Binding("Actions"));

        var panel = new FrameworkElementFactory(typeof(StackPanel));
        panel.SetValue(StackPanel.OrientationProperty, Orientation.Horizontal);
        itemsControl.SetValue(ItemsControl.ItemsPanelProperty, new ItemsPanelTemplate(panel));

        var button = new FrameworkElementFactory(typeof(Button));
        button.SetBinding(ContentControl.ContentProperty,
            new Binding("ActionLabel") { RelativeSource = new RelativeSource(RelativeSourceMode.FindAncestor, typeof(ReportWindow), 1) });
        button.SetValue(FrameworkElement.CursorProperty, Cursors.Hand);
        button.SetValue(Button.BackgroundProperty, Brushes.Transparent);
        button.SetValue(Button.BorderThicknessProperty, new Thickness(0));
        button.SetValue(Control.PaddingProperty, new Thickness(0));
        button.SetValue(TextBlock.ForegroundProperty, AccentBrush);
        button.SetValue(TextElement.FontSizeProperty, 11.5);
        button.SetValue(FrameworkElement.MarginProperty, new Thickness(0, 0, 10, 0));
        button.SetValue(FrameworkElement.ToolTipProperty, "…");
        button.AddHandler(Button.ClickEvent, new RoutedEventHandler(OpenFolder_Click));

        var hover = new Style(typeof(Button));
        var template = new ControlTemplate(typeof(Button));
        var border = new FrameworkElementFactory(typeof(TextBlock));
        border.SetBinding(TextBlock.TextProperty, new Binding("Content")
        {
            RelativeSource = new RelativeSource(RelativeSourceMode.TemplatedParent)
        });
        border.SetValue(TextBlock.ForegroundProperty, AccentBrush);
        border.SetValue(TextBlock.TextDecorationsProperty, TextDecorations.Underline);
        template.VisualTree = border;
        hover.Setters.Add(new Setter(Control.TemplateProperty, template));
        button.SetValue(FrameworkElement.StyleProperty, hover);

        var itemTemplate = new DataTemplate { VisualTree = button };
        itemsControl.SetValue(ItemsControl.ItemTemplateProperty, itemTemplate);

        return new DataTemplate { VisualTree = itemsControl };
    }

    // Подпись кнопки действия (локализуется окном)
    public string ActionLabel => L("openFolder");

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { DataContext: RowAction action }) return;
        try
        {
            var path = action.Path;
            if (System.IO.Directory.Exists(path))
                Process.Start(new ProcessStartInfo("explorer.exe", $"\"{path}\"") { UseShellExecute = true });
            else if (System.IO.File.Exists(path))
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
        }
        catch
        {
            // папка могла исчезнуть между сканом и кликом
        }
    }

    // ==================== Поиск и фильтрация ====================

    private void SearchInput_TextChanged(object sender, TextChangedEventArgs e)
    {
        SearchHint.Visibility = string.IsNullOrEmpty(SearchInput.Text)
            ? Visibility.Visible
            : Visibility.Collapsed;
        Filter();
    }

    private void Filter()
    {
        if (_current == null) return;

        var query = SearchInput.Text.Trim();
        _filtered.Clear();

        if (query.Length == 0)
        {
            _filtered.AddRange(_current.Rows);
        }
        else
        {
            foreach (var row in _current.Rows)
            {
                foreach (var cell in row.Cells)
                {
                    if (cell.Contains(query, StringComparison.OrdinalIgnoreCase))
                    {
                        _filtered.Add(row);
                        break;
                    }
                }
            }
        }

        Table.ItemsSource = _filtered.ToList();

        var total = _current.Rows.Count;
        if (query.Length > 0)
            SectionMeta.Text = string.Format(L("found"), _filtered.Count, total);
        else
            SectionMeta.Text = string.Format(L("entries"), total);

        if (_filtered.Count == 0)
        {
            EmptyText.Text = query.Length > 0 ? L("noMatches") : L("empty");
            EmptyText.Visibility = Visibility.Visible;
        }
        else
        {
            EmptyText.Visibility = Visibility.Collapsed;
        }
    }

    // ==================== Полноэкранный режим ====================

    private void FullscreenButton_Click(object sender, RoutedEventArgs e) => ToggleFullscreen();

    private void ToggleFullscreen()
    {
        ApplyFullscreen(!_fullscreen);
    }

    // Полный экран: разворачиваем поверх всего (включая панель задач),
    // убираем тени-отступы и скругление рамки
    private void ApplyFullscreen(bool on)
    {
        if (_fullscreen == on) return;
        _fullscreen = on;

        Root.Margin = on ? new Thickness(0) : new Thickness(24);
        ChromeBorder.CornerRadius = new CornerRadius(on ? 0 : 12);
        ChromeBorder.Effect = on
            ? null
            : new System.Windows.Media.Effects.DropShadowEffect
            {
                Color = Color.FromRgb(0x00, 0x00, 0x00),
                BlurRadius = 40,
                ShadowDepth = 0,
                Opacity = 0.55
            };

        WindowState = on ? WindowState.Maximized : WindowState.Normal;
        FullscreenButton.ToolTip = on ? L("fullscreenOff") : L("fullscreen");
    }

    // если окно развернули/свернули штатными средствами Windows — синхронизируем вид
    protected override void OnStateChanged(EventArgs e)
    {
        base.OnStateChanged(e);
        if (!_fullscreen && WindowState == WindowState.Maximized)
        {
            _fullscreen = true;
            Root.Margin = new Thickness(0);
            ChromeBorder.CornerRadius = new CornerRadius(0);
            ChromeBorder.Effect = null;
            FullscreenButton.ToolTip = L("fullscreenOff");
        }
    }

    // ==================== Разворот ровно по монитору ====================
    // Без этого хука безрамочное окно при развороте вылезает за края экрана
    // на толщину ресайз-рамки (известная особенность WPF).

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        if (PresentationSource.FromVisual(this) is HwndSource source)
            source.AddHook(WndProc);
    }

    private const int WmGetMinMaxInfo = 0x0024;
    private const uint MonitorDefaultToNearest = 2;

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg != WmGetMinMaxInfo) return IntPtr.Zero;

        var monitor = MonitorFromWindow(hwnd, MonitorDefaultToNearest);
        var info = new MonitorInfo { cbSize = Marshal.SizeOf<MonitorInfo>() };
        if (!GetMonitorInfo(monitor, ref info)) return IntPtr.Zero;

        var mmi = Marshal.PtrToStructure<MINMAXINFO>(lParam);
        mmi.ptMaxPosition.x = info.rcMonitor.l;
        mmi.ptMaxPosition.y = info.rcMonitor.t;
        mmi.ptMaxSize.x = info.rcMonitor.r - info.rcMonitor.l;
        mmi.ptMaxSize.y = info.rcMonitor.b - info.rcMonitor.t;
        mmi.ptMaxTrackSize = mmi.ptMaxSize;
        Marshal.StructureToPtr(mmi, lParam, false);
        handled = true;
        return IntPtr.Zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int x, y; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MINMAXINFO
    {
        public POINT ptReserved;
        public POINT ptMaxSize;
        public POINT ptMaxPosition;
        public POINT ptMinTrackSize;
        public POINT ptMaxTrackSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MonitorRect { public int l, t, r, b; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MonitorInfo
    {
        public int cbSize;
        public MonitorRect rcMonitor;
        public MonitorRect rcWork;
        public uint dwFlags;
    }

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MonitorInfo info);

    // ==================== Анимации и закрытие ====================

    private void FadeTable()
    {
        var fade = new DoubleAnimation(0.35, 1, TimeSpan.FromMilliseconds(220))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };
        Table.BeginAnimation(OpacityProperty, fade);
    }

    protected override void OnContentRendered(EventArgs e)
    {
        base.OnContentRendered(e);
        RootTrans.Y = 14;
        RootTrans.BeginAnimation(TranslateTransform.YProperty,
            new DoubleAnimation(14, 0, TimeSpan.FromMilliseconds(420))
            {
                EasingFunction = new CircleEase { EasingMode = EasingMode.EaseOut }
            });

        var fade = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(320))
        {
            EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut },
            FillBehavior = FillBehavior.Stop
        };
        fade.Completed += (_, _) => Root.Opacity = 1;
        Root.BeginAnimation(OpacityProperty, fade);
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            ToggleFullscreen();
            return;
        }
        if (e.ButtonState == MouseButtonState.Pressed) DragMove();
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            // Esc сначала выходит из полного экрана, затем закрывает окно
            if (_fullscreen)
            {
                ApplyFullscreen(false);
                e.Handled = true;
            }
            else
            {
                Close();
            }
        }
        else if (e.Key == Key.F11)
        {
            ToggleFullscreen();
            e.Handled = true;
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
