using System;
using System.Collections.Generic;
using System.Globalization;

namespace DetectAcUI.Scanning;

// ==================== Модели отчёта сканирования ====================

public enum SectionStatus
{
    Ok,       // данные собраны
    Empty,    // раздел пуст (артефактов нет)
    NoAccess, // нет доступа (например, Prefetch без прав администратора)
    Error     // ошибка при разборе
}

// Кнопка в строке таблицы (например, «открыть папку с макросами»)
public sealed class RowAction
{
    public RowAction(string label, string path)
    {
        Label = label;
        Path = path;
    }

    public string Label { get; }
    public string Path { get; }
}

// Строка таблицы раздела
public sealed class ReportRow
{
    public ReportRow(string[] cells, bool highlight = false, IReadOnlyList<RowAction>? actions = null)
    {
        Cells = cells;
        Highlight = highlight;
        Actions = actions ?? Array.Empty<RowAction>();
    }

    public string[] Cells { get; }
    public bool Highlight { get; } // подозрительная строка (красная подсветка текста)
    public IReadOnlyList<RowAction> Actions { get; }
}

// Раздел отчёта (одна вкладка модального окна)
public sealed class ReportSection
{
    public ReportSection(string key, string titleRu, string titleEn,
                         string[] columnsRu, string[] columnsEn, double[] columnWidths)
    {
        Key = key;
        TitleRu = titleRu;
        TitleEn = titleEn;
        ColumnsRu = columnsRu;
        ColumnsEn = columnsEn;
        ColumnWidths = columnWidths;
    }

    public string Key { get; }
    public string TitleRu { get; }
    public string TitleEn { get; }
    public string[] ColumnsRu { get; }
    public string[] ColumnsEn { get; }
    public double[] ColumnWidths { get; }

    public List<ReportRow> Rows { get; } = new();
    public SectionStatus Status { get; set; } = SectionStatus.Ok;
    public string? NoteRu { get; set; }   // доп. пояснение (нет доступа, усечение выборки и т.п.)
    public string? NoteEn { get; set; }

    public string Title(string lang) => lang == "ru" ? TitleRu : TitleEn;
    public string[] Columns(string lang) => lang == "ru" ? ColumnsRu : ColumnsEn;
    public string? Note(string lang) => lang == "ru" ? NoteRu : NoteEn;
}

// Итоговый отчёт
public sealed class ScanReport
{
    public List<ReportSection> Sections { get; } = new();

    public string MachineName { get; set; } = Environment.MachineName;
    public string UserName { get; set; } = Environment.UserName;
    public bool IsAdmin { get; set; }
    public DateTime? LicenseExpires { get; set; }
    public DateTime StartedAt { get; set; }
    public DateTime FinishedAt { get; set; }

    public ReportSection? Find(string key)
    {
        foreach (var s in Sections)
            if (s.Key == key) return s;
        return null;
    }
}

// ==================== Общие утилиты времени/строк ====================

public static class TimeUtils
{
    private static readonly DateTime ChromeEpoch = new(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    // Windows FILETIME (100 нс с 1601) -> локальное время
    public static DateTime? FromFileTime(long ft)
    {
        if (ft <= 0 || ft > 2_650_467_743_999_999_999L) return null; // вне допустимого диапазона
        try
        {
            var utc = DateTime.FromFileTimeUtc(ft);
            if (utc.Year < 1980 || utc.Year > 2100) return null;
            return utc.ToLocalTime();
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    public static DateTime? FromFileTime(byte[] buf, int offset)
        => FromFileTime(BitConverter.ToInt64(buf, offset));

    // Chromium: микросекунды с 1601-01-01 UTC
    public static DateTime? FromChromeTime(long us)
    {
        if (us <= 0) return null;
        return FromFileTime(us * 10);
    }

    // Firefox: микросекунды с 1970-01-01 UTC
    public static DateTime? FromUnixMicro(long us)
    {
        if (us <= 0) return null;
        try
        {
            var utc = DateTimeOffset.FromUnixTimeMilliseconds(us / 1000).UtcDateTime;
            if (utc.Year < 1980 || utc.Year > 2100) return null;
            return utc.ToLocalTime();
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    // Unix-секунды (Steam Timestamp)
    public static DateTime? FromUnixSeconds(long sec)
    {
        if (sec <= 0) return null;
        try
        {
            var utc = DateTimeOffset.FromUnixTimeSeconds(sec).UtcDateTime;
            if (utc.Year < 2000 || utc.Year > 2100) return null;
            return utc.ToLocalTime();
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    public static string Fmt(DateTime? dt) => dt?.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) ?? "—";

    public static string FmtDay(DateTime? dt) => dt?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "—";
}
