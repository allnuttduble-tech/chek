using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using DetectAcUI.Licensing;
using DetectAcUI.Scanning;

namespace DetectAcUI;

public partial class MainWindow : Window
{
    // Сообщения этапов реального сканирования (печатная машинка);
    // последний этап — финальный, порядок совпадает с ScanEngine.StageKeys
    private static readonly string[] ScanMessagesEn =
    {
        "Reading Steam accounts...",
        "Indexing recent documents...",
        "Parsing ShellBags for deleted paths...",
        "Decompressing Windows Prefetch...",
        "Collecting browser history (last 30 days)...",
        "Enumerating PCI devices for DMA hardware...",
        "Checking gaming software and macro folders...",
        "Tracing USB storage devices...",
        "Compiling report..."
    };

    private static readonly string[] ScanMessagesRu =
    {
        "Чтение аккаунтов Steam...",
        "Индексация недавних документов...",
        "Разбор ShellBags: удалённые пути...",
        "Распаковка Prefetch: запуски программ...",
        "Сбор истории браузеров за 30 дней...",
        "Перечисление PCI-устройств: поиск DMA...",
        "Проверка игрового софта и папок макросов...",
        "Трассировка USB-накопителей...",
        "Формирование отчёта..."
    };

    private string[] _scanMessages = ScanMessagesEn;

    // Подписи этапов для журнала под статусом
    private static readonly Dictionary<string, string> StageRu = new()
    {
        ["steam"] = "Steam-аккаунты",
        ["recent"] = "Recent-файлы",
        ["shellbags"] = "ShellBags",
        ["prefetch"] = "Prefetch",
        ["history"] = "История браузеров",
        ["dma"] = "PCI / DMA",
        ["software"] = "Игровой софт",
        ["usb"] = "USB-накопители"
    };

    private static readonly Dictionary<string, string> StageEn = new()
    {
        ["steam"] = "Steam accounts",
        ["recent"] = "Recent files",
        ["shellbags"] = "ShellBags",
        ["prefetch"] = "Prefetch",
        ["history"] = "Browser history",
        ["dma"] = "PCI / DMA",
        ["software"] = "Gaming software",
        ["usb"] = "USB devices"
    };

    private static readonly Dictionary<string, string> StageStatusRu = new()
    {
        ["empty"] = "нет данных",
        ["noaccess"] = "нет доступа",
        ["error"] = "ошибка"
    };

    private static readonly Dictionary<string, string> StageStatusEn = new()
    {
        ["empty"] = "no data",
        ["noaccess"] = "no access",
        ["error"] = "error"
    };

    private CancellationTokenSource? _scanCts;
    private CancellationTokenSource? _ambientCts;
    private bool _introDone;
    private bool _agreeStarted;
    private string? _lang;
    private bool _langChosen;
    private bool _keyViewActive;
    private bool _activating;
    private DateTime? _sessionExpires;
    private ScanEngine? _engine;
    private ScanReport? _report;
    private bool _reportReady;
    private readonly List<string> _scanLog = new();

    // Вложенное свойство для визуального состояния «выбрано» у карточек языка
    public static readonly DependencyProperty IsCardSelectedProperty =
        DependencyProperty.RegisterAttached("IsCardSelected", typeof(bool), typeof(MainWindow),
            new PropertyMetadata(false));

    public static void SetIsCardSelected(DependencyObject element, bool value)
        => element.SetValue(IsCardSelectedProperty, value);

    public static bool GetIsCardSelected(DependencyObject element)
        => (bool)element.GetValue(IsCardSelectedProperty);

    public MainWindow()
    {
        InitializeComponent();
    }

    // ==================== Запуск ====================

    protected override async void OnContentRendered(EventArgs e)
    {
        base.OnContentRendered(e);
        if (_introDone) return;
        _introDone = true;

        StartHexRain();
        await PlayIntroAsync();
        StartAmbientEffects();
        await StartupGate();
    }

    // Появление: окно проявляется целиком (экраны включаются после проверки доступа)
    private async Task PlayIntroAsync()
    {
        Root.Opacity = 0;
        RootTrans.Y = 12;
        RootTrans.BeginAnimation(TranslateTransform.YProperty,
            new DoubleAnimation(12, 0, TimeSpan.FromMilliseconds(520)) { EasingFunction = Soft() });
        _ = FadeAsync(Root, 0, 1, 420);

        // Фон: медленно проявляемся поверх дампа памяти (итоговая непрозрачность 3-6%)
        _ = FadeAsync(HexLayer, 0, 0.06, 1500);
        await Task.Delay(400);
    }

    // экран языка появляется после успешной проверки ключа
    private async Task ShowLanguageAsync()
    {
        LangView.Visibility = Visibility.Visible;
        // каскад с мягким перехлёстом: заголовок -> карточки -> продолжить
        _ = PlayStagger(LangHead, LangHeadTrans, -14, 140, 480);
        _ = PlayStagger(LangCards, LangCardsTrans, 18, 260, 540);
        _ = PlayStagger(ContinueButton, ContinueTrans, 14, 380, 480);
        await Task.Delay(1020);
    }

    // Основная кривая почти всех движений: длинный плавный выбег без рывков
    private static CircleEase Soft() => new() { EasingMode = EasingMode.EaseOut };

    // ==================== Фон: дамп памяти (hex dump / code rain) ====================

    private static readonly Random HexRandom = new();

    private static readonly string[] LogLines =
    {
        "[sentinel] verifying page 0x00007FF6A3C14B20 ... ok",
        "[sentinel] module integrity: kernel32.dll ok",
        "[sentinel] module integrity: ntdll.dll ok",
        "[sentinel] handle scan: 0 foreign processes",
        "ntdll!RtlAllocateHeap -> 0x0000025B4E7F9A30",
        "[sentinel] thread 4820 start address validated",
        "[sentinel] signature db v2026.10.2 loaded",
        "[sentinel] forensic trace: 0 anomalies in region"
    };

    private const double HexLineHeight = 15;      // px, должно совпадать с LineHeight строки
    private const double HexSpeedPerSecond = 9.0; // px/с — скорость «дождя»
    private const int HexRowCount = 40;           // строк в пуле (одновременно видно ~26)

    private double _hexOffset;
    private long _hexNextAddr;
    private Stopwatch? _hexWatch;

    // Бесконечная прокрутка: верхняя строка, уходя за край, удаляется,
    // а снизу генерируется новая — пустоту за контентом встретить невозможно
    private void StartHexRain()
    {
        HexColumn.Children.Clear();
        _hexNextAddr = 0x00007FF6A3C14B20;
        _hexOffset = 0;
        HexDrift.Y = 0;
        for (var i = 0; i < HexRowCount; i++)
            HexColumn.Children.Add(MakeHexLine(NextHexLine()));

        // покадровое обновление с delta-time: движение идеально плавное
        // на любой герцовке и не зависит от таймерных джиттеров
        _hexWatch = Stopwatch.StartNew();
        CompositionTarget.Rendering += HexRain_Render;
    }

    private string NextHexLine()
    {
        var line = HexRandom.Next(9) == 0 ? PickLogLine() : FormatHexRow(_hexNextAddr);
        _hexNextAddr += 16;
        return line;
    }

    private void HexRain_Render(object? sender, EventArgs e)
    {
        var dt = _hexWatch!.Elapsed.TotalSeconds;
        _hexWatch.Restart();
        if (dt <= 0 || dt > 0.25) dt = 0.016; // защита от скачка после сна/на первом кадре

        _hexOffset += HexSpeedPerSecond * dt;
        while (_hexOffset >= HexLineHeight)
        {
            _hexOffset -= HexLineHeight; // кадр не меняется: строка ушла ровно на свою высоту
            HexColumn.Children.RemoveAt(0);
            HexColumn.Children.Add(MakeHexLine(NextHexLine()));
        }
        HexDrift.Y = -_hexOffset;
    }

    private static TextBlock MakeHexLine(string text) => new()
    {
        Text = text,
        FontFamily = new FontFamily("Consolas"),
        FontSize = 11,
        LineHeight = 15,
        LineStackingStrategy = LineStackingStrategy.BlockLineHeight,
        Foreground = new SolidColorBrush(Colors.White), // свой экземпляр кисти — для плавной анимации цвета
        HorizontalAlignment = HorizontalAlignment.Left
    };

    private static List<string> BuildHexLines(int count)
    {
        var lines = new List<string>(count);
        long addr = 0x00007FF6A3C14B20;
        for (var i = 0; i < count; i++)
        {
            lines.Add(HexRandom.Next(9) == 0 ? PickLogLine() : FormatHexRow(addr));
            addr += 16;
        }
        return lines;
    }

    private static string FormatHexRow(long addr)
    {
        var bytes = new byte[16];
        HexRandom.NextBytes(bytes);
        var hex = string.Join(" ", bytes.Take(8).Select(b => b.ToString("X2"))) + "  " +
                  string.Join(" ", bytes.Skip(8).Select(b => b.ToString("X2")));
        var ascii = new string(bytes.Select(b => b >= 0x20 && b < 0x7F ? (char)b : '.').ToArray());
        return $"0x{addr:X12}  {hex}  |{ascii}|";
    }

    private static string PickLogLine() => LogLines[HexRandom.Next(LogLines.Length)];

    private void StartAmbientEffects()
    {
        _ambientCts = new CancellationTokenSource();
        _ = RunFlickerAsync(_ambientCts.Token);
    }

    // Случайные строки плавно «вспыхивают» красным — «сканирование памяти»
    private async Task RunFlickerAsync(CancellationToken ct)
    {
        var flickColor = Color.FromRgb(0xFF, 0x3B, 0x4B);
        try
        {
            while (true)
            {
                await Task.Delay(700, ct);
                if (HexColumn.Children.Count == 0) continue;
                if (HexColumn.Children[HexRandom.Next(HexColumn.Children.Count)] is TextBlock line &&
                    line.Foreground is SolidColorBrush brush)
                {
                    // кроссфейд вместо резкой смены цвета
                    brush.BeginAnimation(SolidColorBrush.ColorProperty,
                        new ColorAnimation(flickColor, TimeSpan.FromMilliseconds(180))
                        {
                            EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
                        });
                    await Task.Delay(320, ct);
                    brush.BeginAnimation(SolidColorBrush.ColorProperty,
                        new ColorAnimation(Colors.White, TimeSpan.FromMilliseconds(420))
                        {
                            EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseInOut }
                        });
                }
            }
        }
        catch (OperationCanceledException)
        {
            // окно закрыто
        }
    }

    private async Task PlayStagger(UIElement element, TranslateTransform translate, double fromY, int delayMs, int durationMs)
    {
        element.Opacity = 0;
        translate.Y = fromY;
        await Task.Delay(delayMs);
        translate.BeginAnimation(TranslateTransform.YProperty,
            new DoubleAnimation(fromY, 0, TimeSpan.FromMilliseconds(durationMs)) { EasingFunction = Soft() });
        await FadeAsync(element, 0, 1, durationMs);
    }

    // ==================== Чекбокс активирует "I Agree" ====================

    private void AgreeCheck_Changed(object sender, RoutedEventArgs e)
        => AgreeButton.IsEnabled = AgreeCheck.IsChecked == true;

    // ==================== Выбор языка и локализация ====================

    private static readonly Dictionary<string, string> LocRu = new()
    {
        ["eulaDate"] = "Обновлено: 14 октября 2026 — внимательно прочитайте условия перед продолжением.",
        ["eulaTitle"] = "Лицензионное соглашение",
        ["eulaSubtitle"] = "Ознакомьтесь с условиями и политикой конфиденциальности перед продолжением.",
        ["required"] = "ОБЯЗАТЕЛЬНО",
        ["decline"] = "Отклонить",
        ["agree"] = "Принять",
        ["acceptPre"] = "Я прочитал и принимаю ",
        ["acceptLink"] = "условия",
        ["scanTitle"] = "Идёт форензик-сканирование",
        ["scanComplete"] = "Сканирование завершено",
        ["scanDone"] = "Сбор данных завершён — отчёт готов.",
        ["keyTitle"] = "Активация доступа",
        ["keySubtitle"] = "Введите ключ, выданный модератором",
        ["keyActivate"] = "Активировать",
        ["keyChecking"] = "Проверка ключа на сервере…",
        ["keyInvalid"] = "Неверный формат ключа.",
        ["keyUsed"] = "Ключ уже был использован.",
        ["keyNotFound"] = "Ключ не найден.",
        ["keyDeadlineExpired"] = "Срок активации ключа истёк.",
        ["keyRevoked"] = "Ключ отозван модератором.",
        ["keySessionExpired"] = "Сессия истекла — введите новый ключ.",
        ["keyForeign"] = "Ключ привязан к другому компьютеру.",
        ["keyNetwork"] = "Сервер проверки недоступен.",
        ["keyNoServer"] = "Сервер проверки не настроен (sentinel.config.json).",
        ["keyUnknown"] = "Доступ не подтверждён сервером.",
        ["keyClosing"] = "Лаунчер будет закрыт…",
        ["keyHint"] = "Ключ одноразовый: действует выбранный модератором срок и привязывается к этому ПК",
        ["keyValidUntil"] = "доступ до",
        ["keyDaysLeft"] = "осталось {0} дн.",
        ["emailLabel"] = "Email: ",
        ["emailAddr"] = "sentinel@sentinel.app",
        ["discord"] = "sentinel.app/discord"
    };

    private static readonly Dictionary<string, string> LocEn = new()
    {
        ["eulaDate"] = "Last updated: October 14, 2026 — please read these terms carefully before continuing.",
        ["eulaTitle"] = "End-User License Agreement",
        ["eulaSubtitle"] = "Review the terms & privacy policy before continuing.",
        ["required"] = "REQUIRED",
        ["decline"] = "Decline",
        ["agree"] = "I Agree",
        ["acceptPre"] = "I have read and accept ",
        ["acceptLink"] = "the terms",
        ["scanTitle"] = "Forensic scan in progress",
        ["scanComplete"] = "Scan complete",
        ["scanDone"] = "Data collection complete — report is ready.",
        ["keyTitle"] = "Access activation",
        ["keySubtitle"] = "Enter the key provided by a moderator",
        ["keyActivate"] = "Activate",
        ["keyChecking"] = "Checking the key with the server…",
        ["keyInvalid"] = "Invalid key format.",
        ["keyUsed"] = "This key has already been used.",
        ["keyNotFound"] = "Key not found.",
        ["keyDeadlineExpired"] = "The activation window for this key has expired.",
        ["keyRevoked"] = "The key was revoked by a moderator.",
        ["keySessionExpired"] = "Session expired — enter a new key.",
        ["keyForeign"] = "The key is bound to another machine.",
        ["keyNetwork"] = "The validation server is unreachable.",
        ["keyNoServer"] = "Validation server is not configured (sentinel.config.json).",
        ["keyUnknown"] = "Access was not confirmed by the server.",
        ["keyClosing"] = "The launcher will now close…",
        ["keyHint"] = "The key is one-time: it works for the chosen period and binds to this PC",
        ["keyValidUntil"] = "access until",
        ["keyDaysLeft"] = "{0} day(s) left",
        ["emailLabel"] = "Email: ",
        ["emailAddr"] = "sentinel@sentinel.app",
        ["discord"] = "sentinel.app/discord"
    };

    private string L(string key) => _lang == "ru" ? LocRu[key] : LocEn[key];

    private sealed record EulaSection(string Head, string[] Paras);

    private static readonly EulaSection[] EulaRu =
    {
        new("01 — ПРИНЯТИЕ УСЛОВИЙ", new[]
        {
            "Нажимая «Принять» ниже, вы подтверждаете, что прочитали, поняли и принимаете настоящие Лицензионные условия, а также политику конфиденциальности, упомянутую в разделе 05."
        }),
        new("02 — ПРЕДОСТАВЛЕНИЕ ЛИЦЕНЗИИ", new[]
        {
            "SENTINEL SOFTWARE LTD предоставляет вам ограниченную, личную, неисключительную и отзывную лицензию на установку и запуск ПО sentinel исключительно для проверки целостности вашей системы."
        }),
        new("03 — ДОБРОСОВЕСТНОЕ ИСПОЛЬЗОВАНИЕ", new[]
        {
            "Одна лицензия на человека. Запрещается передавать, перепродавать доступ третьим лицам и использовать ПО на машинах, которые вам не принадлежат или не находятся под вашим управлением."
        }),
        new("04 — ПРОВЕРКИ ЦЕЛОСТНОСТИ", new[]
        {
            "ПО проверяет только память и модули, уже доступные вашей пользовательской сессии. Оно не открывает личные документы, не записывает нажатия клавиш и не передаёт содержимое файлов."
        }),
        new("05 — КОНФИДЕНЦИАЛЬНОСТЬ И ДАННЫЕ", new[]
        {
            "Мы собираем минимальный объём диагностических данных, необходимый для работы сервиса. Диагностические данные никогда не продаются. Подробности — в политике конфиденциальности на sentinel.app/privacy."
        }),
        new("06 — ПОДПИСКИ", new[]
        {
            "Доступ предоставляется на основе подписки. Функции и частота проверок могут меняться между релизами без влияния на уже собранные данные."
        }),
        new("07 — ВОЗВРАТЫ", new[]
        {
            "Если ПО не запускается на вашей системе, напишите на sentinel@sentinel.app в течение 72 часов после покупки — мы рассмотрим полный возврат."
        }),
        new("08 — ЗАПРЕЩЁННЫЕ ДЕЙСТВИЯ", new[]
        {
            "Вмешательство в проверки целостности, обратная разработка или их обход, а также использование ПО для притеснения других пользователей немедленно прекращает действие лицензии."
        }),
        new("09 — ОТКАЗ ОТ ГАРАНТИЙ", new[]
        {
            "ПО предоставляется «как есть» и «как доступно», без гарантий любого рода, явных или подразумеваемых, включая пригодность для конкретной цели."
        }),
        new("10 — ОГРАНИЧЕНИЕ ОТВЕТСТВЕННОСТИ", new[]
        {
            "В максимальной степени, допускаемой законом, SENTINEL SOFTWARE LTD не несёт ответственности за косвенные, случайные или последующие убытки, возникшие при использовании ПО."
        }),
        new("11 — ДОСТУПНОСТЬ", new[]
        {
            "Мы стремимся к постоянной доступности сервиса, но не гарантируем бесперебойную работу, особенно в периоды планового обслуживания."
        }),
        new("12 — ИНТЕЛЛЕКТУАЛЬНАЯ СОБСТВЕННОСТЬ", new[]
        {
            "Все права на ПО, название sentinel и связанный брендинг остаются исключительной собственностью SENTINEL SOFTWARE LTD."
        }),
        new("13 — ПРЕКРАЩЕНИЕ ДЕЙСТВИЯ", new[]
        {
            "Мы можем приостановить или отозвать доступ при нарушении условий. Вы можете прекратить использование в любой момент; разделы 04, 05, 09 и 10 сохраняют силу после прекращения."
        }),
        new("14 — ИЗМЕНЕНИЕ УСЛОВИЙ", new[]
        {
            "Условия могут обновляться между релизами. Продолжение использования после обновления означает согласие с пересмотренными условиями."
        }),
        new("15 — ПРИМЕНИМОЕ ПРАВО", new[]
        {
            "Условия регулируются правом Англии и Уэльса; споры подсудны исключительно судам Англии и Уэльса."
        }),
        new("16 — ПОЛНОТА ДОГОВОРА", new[]
        {
            "Настоящие условия вместе с политикой конфиденциальности составляют полное соглашение между вами и SENTINEL SOFTWARE LTD в отношении ПО."
        }),
        new("17 — КОНТАКТЫ И РЕКВИЗИТЫ", new[]
        {
            "SENTINEL SOFTWARE LTD · Company number 16079772 (England & Wales)",
            "Юридический адрес: 167-169 Great Portland Street, London, England, W1W 5PF",
            "Контакт по защите данных: Benjamin Edward Warner-Deards"
        })
    };

    private static readonly EulaSection[] EulaEn =
    {
        new("01 — ACCEPTANCE OF TERMS", new[]
        {
            "By clicking \"I Agree\" below you confirm that you have read, understood and accept these End-User License Terms together with the privacy policy referenced in section 05."
        }),
        new("02 — LICENCE GRANT", new[]
        {
            "SENTINEL SOFTWARE LTD grants you a limited, personal, non-exclusive and revocable licence to install and run the sentinel software for the sole purpose of verifying the integrity of your system."
        }),
        new("03 — FAIR USE", new[]
        {
            "One licence per person. You may not share, resell or transfer your access, and you may not use the software on machines you do not own or have explicit permission to scan."
        }),
        new("04 — INTEGRITY CHECKS", new[]
        {
            "The software inspects only memory and modules that are already accessible to your user session. It does not open personal documents, does not record keystrokes and does not upload file contents."
        }),
        new("05 — PRIVACY & DATA", new[]
        {
            "We collect the minimum diagnostic data required to operate the service. Diagnostic data is never sold. Full details are available in the privacy policy at sentinel.app/privacy."
        }),
        new("06 — SUBSCRIPTIONS", new[]
        {
            "Access is provided on a subscription basis. Features and scan frequency may change between releases without affecting already-collected data."
        }),
        new("07 — REFUNDS", new[]
        {
            "If the software cannot run on your system, contact sentinel@sentinel.app within 72 hours of purchase for a full refund review."
        }),
        new("08 — PROHIBITED CONDUCT", new[]
        {
            "Tampering with, reverse engineering or bypassing the integrity checks, or using the software to harass other users, terminates this licence immediately."
        }),
        new("09 — DISCLAIMER OF WARRANTY", new[]
        {
            "The software is provided \"as is\" and \"as available\", without warranties of any kind, express or implied, including fitness for a particular purpose."
        }),
        new("10 — LIMITATION OF LIABILITY", new[]
        {
            "To the maximum extent permitted by law, SENTINEL SOFTWARE LTD is not liable for indirect, incidental or consequential damages arising from the use of the software."
        }),
        new("11 — AVAILABILITY", new[]
        {
            "We aim for continuous availability of the service but do not guarantee uninterrupted operation, particularly during scheduled maintenance windows."
        }),
        new("12 — INTELLECTUAL PROPERTY", new[]
        {
            "All rights, title and interest in the software, the sentinel name and associated branding remain the exclusive property of SENTINEL SOFTWARE LTD."
        }),
        new("13 — TERMINATION", new[]
        {
            "We may suspend or revoke access if these terms are breached. You may stop using the software at any time; sections 04, 05, 09 and 10 survive termination."
        }),
        new("14 — CHANGES TO THESE TERMS", new[]
        {
            "Terms may be updated between releases. Continued use after an update constitutes acceptance of the revised terms."
        }),
        new("15 — GOVERNING LAW", new[]
        {
            "These terms are governed by the laws of England & Wales, and disputes fall under the exclusive jurisdiction of the courts of England & Wales."
        }),
        new("16 — ENTIRE AGREEMENT", new[]
        {
            "These terms, together with the privacy policy, form the entire agreement between you and SENTINEL SOFTWARE LTD regarding the software."
        }),
        new("17 — CONTACT & COMPANY DETAILS", new[]
        {
            "SENTINEL SOFTWARE LTD · Company number 16079772 (England & Wales)",
            "Registered office: 167-169 Great Portland Street, London, England, W1W 5PF",
            "Data protection contact: Benjamin Edward Warner-Deards"
        })
    };

    private void LangRu_Click(object sender, RoutedEventArgs e) => SelectLanguage("ru");
    private void LangEn_Click(object sender, RoutedEventArgs e) => SelectLanguage("en");

    private void SelectLanguage(string lang)
    {
        if (_lang == lang) return;
        _lang = lang;
        SetIsCardSelected(LangRuButton, lang == "ru");
        SetIsCardSelected(LangEnButton, lang == "en");
        ContinueButton.IsEnabled = true;
    }

    private async void Continue_Click(object sender, RoutedEventArgs e)
    {
        if (_lang == null || _langChosen) return;
        _langChosen = true;
        ApplyLanguage();

        // экран языка уезжает вверх с ускорением и растворяется
        LangTrans.BeginAnimation(TranslateTransform.YProperty,
            new DoubleAnimation(0, -22, TimeSpan.FromMilliseconds(300))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
            });
        await FadeAsync(LangView, 1, 0, 300);
        LangView.Visibility = Visibility.Collapsed;

        // EULA появляется каскадом
        EulaView.Visibility = Visibility.Visible;
        _ = PlayStagger(HeaderRow, HeaderTrans, -14, 80, 480);
        _ = PlayStagger(LicenseCard, CardTrans, 18, 180, 540);
        _ = PlayStagger(FooterRow, FooterTrans, 14, 280, 480);
    }

    private void ApplyLanguage()
    {
        EulaTitleText.Text = L("eulaTitle");
        EulaSubtitleText.Text = L("eulaSubtitle");
        RequiredText.Text = L("required");
        DeclineButton.Content = L("decline");
        AgreeButton.Content = L("agree");
        ScanTitle.Text = L("scanTitle");
        _scanMessages = _lang == "ru" ? ScanMessagesRu : ScanMessagesEn;
        BuildAgreeCheckbox();
        BuildEulaContent();
    }

    private void BuildAgreeCheckbox()
    {
        var text = new TextBlock
        {
            FontSize = 12,
            Foreground = new SolidColorBrush(Color.FromRgb(0x9C, 0xA0, 0xA8))
        };
        text.Inlines.Add(new Run(L("acceptPre")));
        text.Inlines.Add(new Run(L("acceptLink"))
        {
            Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0x5C, 0x6B)),
            TextDecorations = TextDecorations.Underline
        });
        AgreeCheck.Content = text;
    }

    private void BuildEulaContent()
    {
        var sections = _lang == "ru" ? EulaRu : EulaEn;
        var headStyle = (Style)FindResource("SectionHead");
        var bodyStyle = (Style)FindResource("Body");
        var introStyle = (Style)FindResource("IntroLine");

        EulaBody.Children.Clear();
        EulaBody.Children.Add(new TextBlock { Style = introStyle, Text = L("eulaDate") });

        for (var i = 0; i < sections.Length; i++)
        {
            var section = sections[i];
            EulaBody.Children.Add(new TextBlock
            {
                Style = headStyle,
                Text = section.Head,
                Margin = i == 0 ? new Thickness(0, 4, 0, 6) : new Thickness(0, 16, 0, 6)
            });
            foreach (var paragraph in section.Paras)
                EulaBody.Children.Add(new TextBlock { Style = bodyStyle, Text = paragraph });
        }

        var linkColor = new SolidColorBrush(Color.FromRgb(0xFF, 0x5C, 0x6B));
        var mutedColor = new SolidColorBrush(Color.FromRgb(0x6A, 0x6D, 0x76));
        var links = new TextBlock { Style = bodyStyle, Margin = new Thickness(0, 0, 0, 6) };
        links.Inlines.Add(new Run(L("emailLabel")));
        links.Inlines.Add(new Run(L("emailAddr")) { Foreground = linkColor, TextDecorations = TextDecorations.Underline });
        links.Inlines.Add(new Run("  ·  ") { Foreground = mutedColor });
        links.Inlines.Add(new Run(L("discord")) { Foreground = linkColor, TextDecorations = TextDecorations.Underline });
        EulaBody.Children.Add(links);
    }

    // ==================== Окно: перетаскивание, клавиши, закрытие ====================

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed) DragMove();
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            _ = ExitAsync();
        }
        else if (e.Key == Key.Enter)
        {
            if (!_langChosen)
            {
                if (_lang != null) Continue_Click(sender, e);
            }
            else if (!_agreeStarted && AgreeButton.IsEnabled)
            {
                Agree_Click(sender, e);
            }
            else if (_keyViewActive && ActivateButton.IsEnabled)
            {
                ActivateKey_Click(sender, e);
            }
            else if (_reportReady)
            {
                OpenReport();
            }
        }
    }

    private async void Close_Click(object sender, RoutedEventArgs e) => await ExitAsync();
    private async void Decline_Click(object sender, RoutedEventArgs e) => await ExitAsync();

    private async Task ExitAsync()
    {
        _scanCts?.Cancel();
        await FadeAsync(this, Opacity, 0, 200);
        Close();
    }

    // ==================== I Agree → переход к сканированию ====================

    private async void Agree_Click(object sender, RoutedEventArgs e)
    {
        if (_agreeStarted) return;
        _agreeStarted = true;

        // EULA уезжает влево с ускорением и растворяется
        EulaTrans.BeginAnimation(TranslateTransform.XProperty,
            new DoubleAnimation(0, -26, TimeSpan.FromMilliseconds(280))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
            });
        await FadeAsync(EulaView, 1, 0, 280);

        EulaView.Visibility = Visibility.Collapsed;
        StartScan();
    }

    // ==================== Ключ доступа: одноразовая онлайн-активация ====================

    // Старт: если есть сохранённая сессия — проверяем её на сервере,
    // иначе показываем экран ключа. Без действующей сессии доступа нет.
    private async Task StartupGate()
    {
        _keyViewActive = true;
        ApplyKeyTexts();

        var session = LicenseStore.LoadSession();
        if (session != null)
        {
            ActivateButton.IsEnabled = false;
            KeyInput.IsEnabled = false;
            SetKeyStatus(L("keyChecking"), muted: true);

            var check = await LicenseClient.ValidateSessionAsync(session.Token, LicenseStore.MachineFingerprint());
            if (check.Success && check.ExpiresAt != null)
            {
                _sessionExpires = check.ExpiresAt;
                _keyViewActive = false;
                await FadeOutKeyView();
                await ShowLanguageAsync();
                return;
            }

            // сессию сервер не принял — нужен новый ключ от модератора
            KeyInput.IsEnabled = true;
            ShowKeyError(check.Reason, fatal: false);
        }

        KeyView.Visibility = Visibility.Visible;
        _ = PlayStagger(KeyHead, KeyHeadTrans, -14, 80, 480);
        _ = PlayStagger(KeyCard, KeyCardTrans, 18, 180, 540);
        _ = PlayStagger(KeyHint, KeyHintTrans, 14, 280, 480);
        if (KeyInput.IsEnabled)
        {
            _ = Task.Run(async () =>
            {
                await Task.Delay(600);
                Dispatcher.Invoke(() => KeyInput.Focus());
            });
        }
    }

    private void ApplyKeyTexts()
    {
        KeyTitle.Text = L("keyTitle");
        KeySubtitle.Text = L("keySubtitle");
        ActivateButton.Content = L("keyActivate");
        KeyHint.Text = L("keyHint");
    }

    private void SetKeyStatus(string text, bool muted = false)
    {
        KeyStatus.Foreground = new SolidColorBrush(muted
            ? Color.FromRgb(0x7A, 0x7E, 0x88)
            : Color.FromRgb(0xFF, 0x6B, 0x7A));
        KeyStatus.Text = text;
    }

    // коды причин от сервера → тексты (сервер отвечает машинными кодами)
    private string ReasonText(string reason) => reason switch
    {
        "KEY_USED" => L("keyUsed"),
        "KEY_INVALID" => L("keyNotFound"),
        "KEY_EXPIRED" => L("keyDeadlineExpired"),
        "KEY_REVOKED" => L("keyRevoked"),
        "SESSION_EXPIRED" => L("keySessionExpired"),
        "SESSION_UNKNOWN" => L("keySessionExpired"),
        "SESSION_REVOKED" => L("keyRevoked"),
        "MACHINE_MISMATCH" => L("keyForeign"),
        "NETWORK" => L("keyNetwork"),
        "NO_SERVER" => L("keyNoServer"),
        "PROTOCOL" => L("keyNetwork"),
        _ => L("keyUnknown")
    };

    // fatal = ключ не принят → по правилам лаунчер закрывается
    private void ShowKeyError(string reason, bool fatal)
    {
        SetKeyStatus(fatal ? ReasonText(reason) + "\n" + L("keyClosing") : ReasonText(reason));
        if (fatal) _ = CloseAfterDelay(3500);
    }

    private async Task CloseAfterDelay(int ms)
    {
        await Task.Delay(ms);
        await ExitAsync();
    }

    private async Task FadeOutKeyView()
    {
        KeyTrans.BeginAnimation(TranslateTransform.YProperty,
            new DoubleAnimation(0, -22, TimeSpan.FromMilliseconds(300))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
            });
        await FadeAsync(KeyView, 1, 0, 300);
        KeyView.Visibility = Visibility.Collapsed;
    }

    private void KeyInput_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (ActivateButton == null) return;
        ActivateButton.IsEnabled = !_activating
            && LicenseClient.LooksLikeKey(LicenseClient.NormalizeKey(KeyInput.Text));
    }

    private async void ActivateKey_Click(object sender, RoutedEventArgs e)
    {
        if (_activating) return;

        var normalized = LicenseClient.NormalizeKey(KeyInput.Text);
        if (!LicenseClient.LooksLikeKey(normalized))
        {
            SetKeyStatus(L("keyInvalid"));
            ShakeKeyCard();
            return;
        }

        _activating = true;
        ActivateButton.IsEnabled = false;
        KeyInput.IsEnabled = false;
        SetKeyStatus(L("keyChecking"), muted: true);

        // одноразовая активация на сервере; сессия привязывается к этому ПК
        var result = await LicenseClient.ActivateAsync(normalized, LicenseStore.MachineFingerprint());
        if (!result.Success || result.SessionTicket == null || result.ExpiresAt == null)
        {
            KeyInput.IsEnabled = true;
            ShowKeyError(result.Reason, fatal: true);
            _activating = false;
            return;
        }

        LicenseStore.SaveSession(result.SessionTicket, result.ExpiresAt.Value, LicenseStore.MachineFingerprint());
        _sessionExpires = result.ExpiresAt;
        _keyViewActive = false;

        await FadeOutKeyView();
        await ShowLanguageAsync();
    }

    // короткая тряска карточки при ошибке
    private void ShakeKeyCard()
    {
        var anim = new DoubleAnimationUsingKeyFrames { Duration = TimeSpan.FromMilliseconds(380) };
        double[] offsets = { 0, -7, 7, -5, 5, -2, 0 };
        for (var i = 0; i < offsets.Length; i++)
            anim.KeyFrames.Add(new LinearDoubleKeyFrame(offsets[i], KeyTime.FromPercent(i / (double)(offsets.Length - 1))));
        KeyCardTrans.BeginAnimation(TranslateTransform.XProperty, anim);
    }

    private void StartScan()
    {
        ScanView.Visibility = Visibility.Visible;
        StatusText.Opacity = 0;

        // экран скана мягко всплывает снизу с лёгким масштабированием (глубина)
        ScanView.Opacity = 0;
        ScanTrans.Y = 24;
        ScanScale.ScaleX = 0.985;
        ScanScale.ScaleY = 0.985;
        StartSpinner();
        ScanTrans.BeginAnimation(TranslateTransform.YProperty,
            new DoubleAnimation(24, 0, TimeSpan.FromMilliseconds(480)) { EasingFunction = Soft() });
        ScanScale.BeginAnimation(ScaleTransform.ScaleXProperty,
            new DoubleAnimation(0.985, 1, TimeSpan.FromMilliseconds(480)) { EasingFunction = Soft() });
        ScanScale.BeginAnimation(ScaleTransform.ScaleYProperty,
            new DoubleAnimation(0.985, 1, TimeSpan.FromMilliseconds(480)) { EasingFunction = Soft() });
        _ = FadeAsync(ScanView, 0, 1, 420);

        _ = RunScanSequenceAsync();
    }

    // Вращение дуги + лёгкое «дыхание» спиннера
    private void StartSpinner()
    {
        var spin = new DoubleAnimation(0, 360, new Duration(TimeSpan.FromMilliseconds(1400)));
        spin.RepeatBehavior = RepeatBehavior.Forever;
        SpinnerRotate.BeginAnimation(RotateTransform.AngleProperty, spin);

        SpinnerScale.BeginAnimation(ScaleTransform.ScaleXProperty, MakeBreathe());
        SpinnerScale.BeginAnimation(ScaleTransform.ScaleYProperty, MakeBreathe());
    }

    private static DoubleAnimation MakeBreathe() => new(1, 1.045, new Duration(TimeSpan.FromMilliseconds(1100)))
    {
        AutoReverse = true,
        RepeatBehavior = RepeatBehavior.Forever,
        EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut }
    };

    // ==================== Последовательность сканирования (реальные модули) ====================

    private async Task RunScanSequenceAsync()
    {
        _scanCts = new CancellationTokenSource();
        var ct = _scanCts.Token;

        _engine = new ScanEngine(_lang ?? "ru");
        _engine.Report.IsAdmin = IsCurrentUserAdmin();
        _engine.Report.StartedAt = DateTime.Now;

        // срок лицензии — первой строкой журнала этапов
        if (_sessionExpires != null)
        {
            var days = Math.Max(0, (int)Math.Ceiling((_sessionExpires.Value - DateTime.Now).TotalDays));
            _scanLog.Add($"· {L("keyValidUntil")} {_sessionExpires.Value:yyyy-MM-dd} ({string.Format(L("keyDaysLeft"), days)})");
            ScanLogText.Text = string.Join("\n", _scanLog);
            ScanLogText.Opacity = 0.9;
        }

        try
        {
            var stages = ScanEngine.StageKeys;
            for (var i = 0; i < stages.Length; i++)
            {
                await FadeAsync(StatusText, 0, 1, 150);
                await TypeLineAsync(_scanMessages[i], ct);

                ScanEngine.StageResult result;
                try
                {
                    result = await _engine.RunStageAsync(stages[i], ct);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch
                {
                    result = new ScanEngine.StageResult(0, SectionStatus.Error);
                }

                AppendScanLog(StageLabel(stages[i]), result);

                if (i < stages.Length - 1)
                {
                    await Task.Delay(260, ct);
                    await FadeAsync(StatusText, 1, 0, 150);
                    StatusText.Text = string.Empty;
                }
            }

            // финальная строка «Формирование отчёта...»
            await FadeAsync(StatusText, 0, 1, 150);
            await TypeLineAsync(_scanMessages[^1], ct);
            await Task.Delay(420, ct);

            _report = _engine.BuildReport();
            _report.LicenseExpires = _sessionExpires;
            await ShowCompletionAsync();
            await RevealReportButtonAsync();
        }
        catch (OperationCanceledException)
        {
            // окно закрыто во время сканирования — просто выходим
        }
    }

    private static bool IsCurrentUserAdmin()
    {
        try
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(identity)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private string StageLabel(string key)
        => (_lang == "ru" ? StageRu : StageEn).TryGetValue(key, out var label) ? label : key;

    // Журнал этапов: последние 4 строки под статусом
    private void AppendScanLog(string label, ScanEngine.StageResult result)
    {
        var suffix = result.Status switch
        {
            SectionStatus.Ok => result.Count.ToString(),
            SectionStatus.Empty => (_lang == "ru" ? StageStatusRu : StageStatusEn)["empty"],
            SectionStatus.NoAccess => (_lang == "ru" ? StageStatusRu : StageStatusEn)["noaccess"],
            _ => (_lang == "ru" ? StageStatusRu : StageStatusEn)["error"]
        };

        _scanLog.Add($"· {label}: {suffix}");
        while (_scanLog.Count > 4) _scanLog.RemoveAt(0);
        ScanLogText.Text = string.Join("\n", _scanLog);

        if (ScanLogText.Opacity < 0.5)
        {
            var fade = new DoubleAnimation(0, 0.9, TimeSpan.FromMilliseconds(260));
            ScanLogText.BeginAnimation(OpacityProperty, fade);
        }
    }

    // Кнопка отчёта появляется после галочки
    private async Task RevealReportButtonAsync()
    {
        _reportReady = true;
        ReportButton.Visibility = Visibility.Visible;
        ReportHint.Visibility = Visibility.Visible;
        ReportHint.Opacity = 0;

        var fade = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(340))
        {
            EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
        };
        ReportButton.BeginAnimation(OpacityProperty, fade);
        await Task.Delay(140);
        ReportHint.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(300)));
    }

    private void ReportButton_Click(object sender, RoutedEventArgs e) => OpenReport();

    private void OpenReport()
    {
        try
        {
            System.IO.File.WriteAllText(
                System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sentinel_openreport_called.txt"),
                $"called at {DateTime.Now:T}; reportNull={_report == null}; lang={_lang}");
        }
        catch { /* диагностика не должна мешать */ }
        if (_report == null) return;
        var window = new ReportWindow(_lang ?? "ru", _report) { Owner = this };
        window.ShowDialog();
    }

    // Эффект печатной машинки с курсором-блоком
    private async Task TypeLineAsync(string line, CancellationToken ct)
    {
        for (var i = 1; i <= line.Length; i++)
        {
            ct.ThrowIfCancellationRequested();
            StatusText.Text = line.Substring(0, i) + "\u258C";
            await Task.Delay(22, ct);
        }
        StatusText.Text = line;
    }

    // Финал: спиннер → красная галочка с «пружинкой»
    private async Task ShowCompletionAsync()
    {
        ScanTitle.Text = L("scanComplete");
        await FadeAsync(SpinHost, 1, 0, 200);
        SpinHost.Visibility = Visibility.Collapsed;

        CheckHost.Visibility = Visibility.Visible;
        var pop = new DoubleAnimation(0.6, 1, TimeSpan.FromMilliseconds(480))
        {
            EasingFunction = new BackEase { Amplitude = 0.6, EasingMode = EasingMode.EaseOut }
        };
        CheckScale.BeginAnimation(ScaleTransform.ScaleXProperty, pop);
        CheckScale.BeginAnimation(ScaleTransform.ScaleYProperty, pop);
        await FadeAsync(CheckHost, 0, 1, 240);

        StatusText.Text = L("scanDone");
    }

    // ==================== Утилита плавного изменения прозрачности ====================

    private static Task FadeAsync(UIElement element, double from, double to, int milliseconds)
    {
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var animation = new DoubleAnimation(from, to, TimeSpan.FromMilliseconds(milliseconds))
        {
            FillBehavior = FillBehavior.Stop,
            EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseInOut }
        };
        animation.Completed += (_, _) =>
        {
            element.Opacity = to;
            tcs.TrySetResult(true);
        };
        element.BeginAnimation(UIElement.OpacityProperty, animation);
        return tcs.Task;
    }

    protected override void OnClosed(EventArgs e)
    {
        CompositionTarget.Rendering -= HexRain_Render;
        _scanCts?.Cancel();
        _ambientCts?.Cancel();
        base.OnClosed(e);
    }
}
