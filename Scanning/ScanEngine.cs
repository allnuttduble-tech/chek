using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DetectAcUI.Scanning;

// ==================== Оркестратор сканирования ====================
// Запускает модули по этапам и собирает ScanReport для модального окна.

public sealed class ScanEngine
{
    public static readonly string[] StageKeys =
    {
        "steam", "recent", "shellbags", "prefetch", "history", "dma", "software", "usb"
    };

    private readonly string _lang;
    private readonly Dictionary<string, ReportSection> _sections = new();

    public ScanEngine(string lang) => _lang = lang;

    public ScanReport Report { get; } = new();

    // Результат этапа для строки лога в окне сканирования
    public sealed record StageResult(int Count, SectionStatus Status);

    public Task<StageResult> RunStageAsync(string key, CancellationToken ct) => Task.Run(() =>
    {
        ct.ThrowIfCancellationRequested();
        var section = key switch
        {
            "steam" => RunSteam(),
            "recent" => RunRecent(),
            "shellbags" => RunShellBags(),
            "prefetch" => RunPrefetch(),
            "history" => RunHistory(),
            "dma" => RunDma(),
            "software" => RunSoftware(),
            "usb" => RunUsb(),
            _ => throw new ArgumentException("unknown stage: " + key)
        };
        _sections[key] = section;
        return new StageResult(section.Rows.Count, section.Status);
    }, ct);

    public ScanReport BuildReport()
    {
        Report.Sections.Clear();
        foreach (var key in StageKeys)
            if (_sections.TryGetValue(key, out var section))
                Report.Sections.Add(section);
        Report.FinishedAt = DateTime.Now;
        return Report;
    }

    // ==================== Этапы ====================

    private ReportSection RunSteam()
    {
        var section = NewSection("steam",
            "Steam-аккаунты", "Steam accounts",
            new[] { "SteamID64", "Аккаунт", "Отображаемое имя", "Последний вход", "Примечание" },
            new[] { "SteamID64", "Account", "Persona name", "Last login", "Note" },
            new double[] { 130, 130, 160, 125, 90 });

        var res = SteamScanner.Scan();
        var t = _lang == "ru" ? "автологин" : "auto-login";
        foreach (var acc in res.Accounts)
        {
            section.Rows.Add(new ReportRow(new[]
            {
                acc.SteamId64,
                acc.AccountName,
                acc.PersonaName,
                TimeUtils.Fmt(acc.LastLogin),
                acc.MostRecent ? t : (acc.RememberPassword ? "•" : "—")
            }));
        }

        if (res.Accounts.Count == 0)
        {
            section.Status = SectionStatus.Empty;
            section.NoteRu = res.SteamPath == null
                ? "Steam не найден на этом компьютере."
                : "Учётные записи Steam не найдены (" + res.SteamPath + ").";
            section.NoteEn = res.SteamPath == null
                ? "Steam was not found on this computer."
                : "No Steam accounts found (" + res.SteamPath + ").";
        }
        else if (res.AutoLoginUser != null)
        {
            section.NoteRu = "Текущий автологин: " + res.AutoLoginUser;
            section.NoteEn = "Current auto-login: " + res.AutoLoginUser;
        }
        return section;
    }

    private ReportSection RunRecent()
    {
        var section = NewSection("recent",
            "Recent-файлы", "Recent files",
            new[] { "Имя", "Цель", "Последнее открытие" },
            new[] { "Name", "Target", "Last opened" },
            new double[] { 170, 300, 125 });

        var res = RecentFilesScanner.Scan();
        foreach (var item in res.Items)
        {
            section.Rows.Add(new ReportRow(new[]
            {
                item.Name,
                string.IsNullOrEmpty(item.Target) ? "—" : item.Target,
                TimeUtils.Fmt(item.LastOpen)
            }));
        }
        if (res.Items.Count == 0)
        {
            section.Status = SectionStatus.Empty;
            section.NoteRu = "Список Recent пуст.";
            section.NoteEn = "The Recent list is empty.";
        }
        return section;
    }

    private ReportSection RunShellBags()
    {
        var section = NewSection("shellbags",
            "ShellBags — удалённые пути", "ShellBags — deleted paths",
            new[] { "Путь", "Последняя активность", "Состояние", "Примечание" },
            new[] { "Path", "Last activity", "State", "Note" },
            new double[] { 300, 125, 85, 110 });

        var res = ShellBagsScanner.Scan();
        var del = _lang == "ru" ? "удалён" : "deleted";
        var ok = _lang == "ru" ? "существует" : "exists";
        var recycled = _lang == "ru" ? "из корзины, удалён {0}" : "from Recycle Bin, deleted {0}";

        foreach (var e in res.Entries)
        {
            string note;
            if (e.IsRecycled && e.DeletedTime != null)
                note = string.Format(_lang == "ru" ? "из корзины, удалён {0}" : "from Recycle Bin, deleted {0}",
                    TimeUtils.Fmt(e.DeletedTime));
            else if (e.Deleted)
                note = _lang == "ru" ? "пути нет на диске" : "path missing on disk";
            else
                note = "—";

            section.Rows.Add(new ReportRow(
                new[]
                {
                    e.Path,
                    TimeUtils.Fmt(e.DeletedTime ?? e.NodeTime),
                    e.IsRecycled || e.Deleted ? del : ok,
                    note
                },
                highlight: e.Deleted));
        }

        if (res.Entries.Count == 0)
        {
            section.Status = res.NoAccess ? SectionStatus.NoAccess : SectionStatus.Empty;
        }
        return section;
    }

    private ReportSection RunPrefetch()
    {
        var section = NewSection("prefetch",
            "Prefetch — запуск программ", "Prefetch — program executions",
            new[] { "Программа", "Запусков", "Последний запуск", "Файл" },
            new[] { "Executable", "Runs", "Last run", "File" },
            new double[] { 210, 70, 130, 170 });

        var res = PrefetchScanner.Scan();
        section.Status = res.Status;

        foreach (var e in res.Entries)
        {
            section.Rows.Add(new ReportRow(new[]
            {
                e.Executable,
                e.RunCount.ToString(),
                TimeUtils.Fmt(e.LastRun),
                e.PfFile
            }));
        }

        if (res.Status == SectionStatus.NoAccess)
        {
            section.NoteRu = "Нет доступа к C:\\Windows\\Prefetch — запустите лаунчер от имени администратора.";
            section.NoteEn = "No access to C:\\Windows\\Prefetch — run the launcher as administrator.";
        }
        else if (res.Status == SectionStatus.Empty)
        {
            section.NoteRu = "Prefetch-файлы не найдены (функция отключена или очищена).";
            section.NoteEn = "No Prefetch files found (feature disabled or cleaned).";
        }
        return section;
    }

    private ReportSection RunHistory()
    {
        var section = NewSection("history",
            "История браузеров — 30 дней", "Browser history — 30 days",
            new[] { "Браузер", "Профиль", "Заголовок", "URL", "Последнее посещение" },
            new[] { "Browser", "Profile", "Title", "URL", "Last visited" },
            new double[] { 75, 90, 190, 240, 120 });

        var res = HistoryScanner.Scan();
        foreach (var item in res.Items)
        {
            section.Rows.Add(new ReportRow(new[]
            {
                item.Browser,
                item.Profile,
                string.IsNullOrWhiteSpace(item.Title) ? "—" : item.Title,
                item.Url,
                TimeUtils.Fmt(item.LastVisit)
            }));
        }

        if (res.Items.Count == 0)
        {
            section.Status = SectionStatus.Empty;
            section.NoteRu = res.BrowsersFound.Count == 0
                ? "Браузеры не найдены или история пуста."
                : "За последние 30 дней посещений не найдено.";
            section.NoteEn = res.BrowsersFound.Count == 0
                ? "No browsers found or history is empty."
                : "No visits found in the last 30 days.";
        }
        else if (res.TruncatedAt > 0)
        {
            section.NoteRu = $"Показаны первые {res.TruncatedAt} записей (отсортированы по дате).";
            section.NoteEn = $"Showing first {res.TruncatedAt} rows (sorted by date).";
        }
        return section;
    }

    private ReportSection RunDma()
    {
        var section = NewSection("dma",
            "PCI-устройства и DMA", "PCI devices & DMA",
            new[] { "Устройство", "PCI ID", "Статус", "Флаг" },
            new[] { "Device", "PCI ID", "Status", "Flag" },
            new double[] { 280, 150, 110, 120 });

        var res = DmaScanner.Scan();
        var suspect = _lang == "ru" ? "возможна DMA-карта" : "possible DMA card";
        var noDriver = _lang == "ru" ? "без драйвера/сервиса" : "no driver/service";

        foreach (var d in res.Devices)
        {
            var status = d.Present
                ? (d.HasProblem
                    ? (_lang == "ru" ? "проблема (код " + d.ProblemCode + ")" : "problem (code " + d.ProblemCode + ")")
                    : (_lang == "ru" ? "подключено" : "present"))
                : (_lang == "ru" ? "не подключено" : "not present");

            var flag = d.Suspect ? suspect : (d.NoDriver ? noDriver : "—");

            section.Rows.Add(new ReportRow(
                new[] { d.Name, d.VendorDevice, status, flag },
                highlight: d.Suspect));
        }

        if (res.Devices.Count == 0)
        {
            section.Status = SectionStatus.Empty;
            section.NoteRu = "Список PCI-устройств пуст.";
            section.NoteEn = "The PCI device list is empty.";
        }
        return section;
    }

    private ReportSection RunSoftware()
    {
        var section = NewSection("software",
            "Игровой софт и макросы", "Gaming software & macros",
            new[] { "Продукт", "Издатель", "Версия", "Запущен", "Папки" },
            new[] { "Product", "Vendor", "Version", "Running", "Folders" },
            new double[] { 200, 120, 90, 75, 140 });

        var res = GamingSoftwareScanner.Scan();
        var yes = _lang == "ru" ? "да" : "yes";
        var no = _lang == "ru" ? "нет" : "no";

        foreach (var p in res.Products)
        {
            section.Rows.Add(new ReportRow(
                new[]
                {
                    p.Name,
                    p.Vendor,
                    string.IsNullOrEmpty(p.Version) ? "—" : p.Version,
                    p.Running ? yes : no,
                    p.MacroFolders.Count > 0 ? p.MacroFolders.Count.ToString() : "—"
                },
                actions: p.MacroFolders.Count > 0 ? p.MacroFolders : null));
        }

        if (res.Products.Count == 0)
        {
            section.Status = SectionStatus.Empty;
            section.NoteRu = "Игровой/периферийный софт (Logitech, Razer, iCUE и т.п.) не найден.";
            section.NoteEn = "No gaming/peripheral software (Logitech, Razer, iCUE etc.) found.";
        }
        return section;
    }

    private ReportSection RunUsb()
    {
        var section = NewSection("usb",
            "USB-накопители", "USB devices",
            new[] { "Устройство", "Тип", "Серийный номер", "Подключён", "Отключён", "Первое подключение" },
            new[] { "Device", "Type", "Serial", "Connected", "Disconnected", "First seen" },
            new double[] { 180, 70, 160, 115, 115, 115 });

        var res = UsbScanner.Scan();
        foreach (var d in res.Devices)
        {
            section.Rows.Add(new ReportRow(new[]
            {
                d.Name,
                d.Type,
                d.Serial,
                TimeUtils.Fmt(d.LastArrival),
                TimeUtils.Fmt(d.LastRemoval),
                TimeUtils.Fmt(d.FirstSeen)
            }));
        }

        if (res.Devices.Count == 0)
        {
            section.Status = SectionStatus.Empty;
            section.NoteRu = "USB-накопители в USBSTOR не найдены.";
            section.NoteEn = "No USB storage devices found in USBSTOR.";
        }
        else if (res.Devices.All(d => d.LastArrival == null && d.LastRemoval == null && d.FirstSeen == null))
        {
            section.NoteRu = "Даты подключений недоступны: ключи Properties закрыты ACL, журнал setupapi.dev.log не содержит событий по этим устройствам.";
            section.NoteEn = "Connection dates unavailable: Properties keys are ACL-protected and setupapi.dev.log has no events for these devices.";
        }
        return section;
    }

    private ReportSection NewSection(string key, string titleRu, string titleEn,
        string[] columnsRu, string[] columnsEn, double[] widths)
    {
        var s = new ReportSection(key, titleRu, titleEn, columnsRu, columnsEn, widths);
        Report.StartedAt = Report.StartedAt == default ? DateTime.Now : Report.StartedAt;
        return s;
    }
}
