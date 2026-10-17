using System;
using System.Collections.Generic;
using System.IO;

namespace DetectAcUI.Scanning;

// ==================== Сканер истории браузеров (последние 30 дней) ====================
// Chromium-семейство: <User Data>\<профиль>\History (таблица urls, µs с 1601).
// Firefox: <Profiles>\<профиль>\places.sqlite (moz_places, µs с 1970).
// База копируется во временную папку (браузер держит файл открытым),
// WAL накладывается мини-ридером, чтобы видеть свежие визиты.

public static class HistoryScanner
{
    public sealed class HistoryItem
    {
        public string Browser = "";
        public string Profile = "";
        public string Title = "";
        public string Url = "";
        public DateTime? LastVisit;
    }

    public sealed class HistoryResult
    {
        public List<HistoryItem> Items { get; } = new();
        public List<string> BrowsersFound { get; } = new();
        public int TruncatedAt; // 0 = без усечения

        public static HistoryResult Empty() => new();
    }

    private const int MaxRows = 4000;

    public static HistoryResult Scan()
    {
        var result = new HistoryResult();
        var since = DateTime.UtcNow.AddDays(-30);

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        // Chromium-семейство
        ScanChromium(result, "Chrome", Path.Combine(localAppData, "Google", "Chrome", "User Data"), since);
        ScanChromium(result, "Edge", Path.Combine(localAppData, "Microsoft", "Edge", "User Data"), since);
        ScanChromium(result, "Yandex", Path.Combine(localAppData, "Yandex", "YandexBrowser", "User Data"), since);
        ScanChromium(result, "Brave", Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data"), since);
        ScanOpera(result, "Opera", roamingAppData, since);

        // Firefox
        ScanFirefox(result, Path.Combine(roamingAppData, "Mozilla", "Firefox", "Profiles"), since);

        result.Items.Sort((a, b) => (b.LastVisit ?? DateTime.MinValue).CompareTo(a.LastVisit ?? DateTime.MinValue));
        return result;
    }

    private static void ScanChromium(HistoryResult result, string browser, string userDataDir, DateTime sinceUtc)
    {
        if (!Directory.Exists(userDataDir)) return;

        foreach (var dir in Directory.EnumerateDirectories(userDataDir))
        {
            var profileName = Path.GetFileName(dir);
            if (!IsUserProfile(profileName)) continue;
            var historyFile = Path.Combine(dir, "History");
            if (!File.Exists(historyFile)) continue;

            result.BrowsersFound.Add(browser);
            ReadChromiumHistory(result, browser, profileName, historyFile, sinceUtc);
        }
    }

    private static bool IsUserProfile(string name)
        => name == "Default" || name.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase);

    private static void ScanOpera(HistoryResult result, string browser, string roaming, DateTime sinceUtc)
    {
        var operaDir = Path.Combine(roaming, "Opera Software");
        if (!Directory.Exists(operaDir)) return;

        foreach (var dir in Directory.EnumerateDirectories(operaDir))
        {
            var historyFile = Path.Combine(dir, "History");
            if (!File.Exists(historyFile)) continue;
            result.BrowsersFound.Add(browser);
            ReadChromiumHistory(result, browser, Path.GetFileName(dir), historyFile, sinceUtc);
        }
    }

    private static void ReadChromiumHistory(HistoryResult result, string browser, string profile,
        string historyFile, DateTime sinceUtc)
    {
        var (dbPath, cleanup) = CopyToTemp(historyFile);
        try
        {
            var db = MiniSql.TryOpen(dbPath);
            if (db == null) return;

            var rows = db.ReadTable("urls", MaxRows * 2);
            foreach (var row in rows)
            {
                if (row.Count < 6) continue;
                if (row[1] is not string url || url.Length == 0) continue;
                var lastVisitUs = row[5] as long? ?? 0;
                var dt = TimeUtils.FromChromeTime(lastVisitUs);
                if (dt == null) continue;
                var local = dt.Value;
                if (dt.Value.ToUniversalTime() < sinceUtc) continue;

                var title = row[2] as string ?? "";
                result.Items.Add(new HistoryItem
                {
                    Browser = browser,
                    Profile = profile,
                    Url = url,
                    Title = title,
                    LastVisit = local
                });
                if (result.Items.Count >= MaxRows)
                {
                    result.TruncatedAt = MaxRows;
                    return;
                }
            }
        }
        finally
        {
            if (cleanup != null)
                try { Directory.Delete(cleanup, true); } catch { }
        }
    }

    private static void ScanFirefox(HistoryResult result, string profilesDir, DateTime sinceUtc)
    {
        if (!Directory.Exists(profilesDir)) return;

        foreach (var dir in Directory.EnumerateDirectories(profilesDir))
        {
            var places = Path.Combine(dir, "places.sqlite");
            if (!File.Exists(places)) continue;
            result.BrowsersFound.Add("Firefox");

            var (dbPath, cleanup) = CopyToTemp(places);
            try
            {
                var db = MiniSql.TryOpen(dbPath);
                if (db == null) continue;

                var rows = db.ReadTable("moz_places", MaxRows * 2);
                foreach (var row in rows)
                {
                    if (row.Count < 9) continue;
                    if (row[1] is not string url || url.Length == 0) continue;
                    var lastVisitUs = row[8] as long? ?? 0;
                    var dt = TimeUtils.FromUnixMicro(lastVisitUs);
                    if (dt == null) continue;
                    if (dt.Value.ToUniversalTime() < sinceUtc) continue;

                    var title = row[2] as string ?? "";
                    result.Items.Add(new HistoryItem
                    {
                        Browser = "Firefox",
                        Profile = Path.GetFileName(dir),
                        Url = url,
                        Title = title,
                        LastVisit = dt.Value
                    });
                    if (result.Items.Count >= MaxRows)
                    {
                        result.TruncatedAt = MaxRows;
                        return;
                    }
                }
            }
            finally
            {
                if (cleanup != null)
                    try { Directory.Delete(cleanup, true); } catch { }
            }
        }
    }

    // ==================== Временные копии ====================

    // Копируем базу (+ wal/shm) во временную папку, чтобы читать независимо от браузера
    private static (string Path, string? TempDir) CopyToTemp(string source)
    {
        try
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_scan_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(tempDir);
            var dest = Path.Combine(tempDir, Path.GetFileName(source));
            CopyFileShared(source, dest);

            foreach (var suffix in new[] { "-wal", "-shm" })
            {
                if (File.Exists(source + suffix))
                    CopyFileShared(source + suffix, dest + suffix);
            }
            return (dest, tempDir);
        }
        catch
        {
            return ("", null);
        }
    }

    private static void CopyFileShared(string src, string dst)
    {
        using var input = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var output = new FileStream(dst, FileMode.Create, FileAccess.Write);
        input.CopyTo(output);
    }
}
