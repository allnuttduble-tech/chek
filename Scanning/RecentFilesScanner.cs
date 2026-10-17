using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace DetectAcUI.Scanning;

// ==================== Сканер Recent files ====================
// Читает ярлыки %APPDATA%\Microsoft\Windows\Recent: цель (разбор .lnk),
// дата последнего открытия (по времени изменения ярлыка).

public static class RecentFilesScanner
{
    public sealed class RecentItem
    {
        public string Name = "";
        public string Target = "";
        public DateTime? LastOpen;
        public bool Pinned; // находится в закреплённых (subdir Quick Access использует те же ярлыки)
    }

    public sealed class RecentResult
    {
        public List<RecentItem> Items { get; } = new();
        public string? RecentDir { get; set; }

        public static RecentResult Empty() => new();
    }

    public static RecentResult Scan()
    {
        var result = new RecentResult();
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Microsoft", "Windows", "Recent");

        if (!Directory.Exists(dir)) return result;
        result.RecentDir = dir;

        string[] files;
        try
        {
            files = Directory.GetFiles(dir, "*.lnk", SearchOption.TopDirectoryOnly);
        }
        catch
        {
            return result;
        }

        foreach (var file in files)
        {
            try
            {
                var info = new FileInfo(file);
                var item = new RecentItem
                {
                    Name = Path.GetFileNameWithoutExtension(file),
                    LastOpen = info.LastWriteTimeUtc.ToLocalTime()
                };

                // целевой путь: сначала быстрый ручной разбор .lnk, затем COM (STA)
                var target = ParseLnkTarget(file);
                if (string.IsNullOrEmpty(target))
                    target = ComTargetSta(file) ?? "";
                item.Target = target;

                result.Items.Add(item);
            }
            catch
            {
                // одиночный битый ярлык не должен ломать весь раздел
            }
        }

        result.Items.Sort((a, b) => (b.LastOpen ?? DateTime.MinValue).CompareTo(a.LastOpen ?? DateTime.MinValue));
        return result;
    }

    // ==================== Ручной разбор Shell Link (.lnk) ====================

    private static string? ParseLnkTarget(string path)
    {
        try
        {
            byte[] b;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                if (fs.Length < 0x4C) return null;
                b = new byte[fs.Length];
                using var br = new BinaryReader(fs);
                b = br.ReadBytes((int)fs.Length);
            }

            if (BitConverter.ToUInt32(b, 0) != 0x0000004C) return null; // LinkClsId

            var flags = BitConverter.ToUInt32(b, 0x14);
            const uint hasTargetIdList = 0x1;
            const uint hasLinkInfo = 0x2;

            var offset = 0x4C;
            if ((flags & hasTargetIdList) != 0)
            {
                if (offset + 2 > b.Length) return null;
                var idListSize = BitConverter.ToUInt16(b, offset);
                offset += 2 + idListSize;
            }

            if ((flags & hasLinkInfo) == 0) return null;
            if (offset + 0x1C > b.Length) return null;

            var linkInfoSize = BitConverter.ToUInt32(b, offset);
            var headerSize = BitConverter.ToUInt32(b, offset + 4);
            if (headerSize < 0x1C || linkInfoSize == 0) return null;

            var localBasePathOffset = BitConverter.ToUInt32(b, offset + 16);
            if (localBasePathOffset == 0 || localBasePathOffset >= linkInfoSize) return null;

            var abs = (int)(offset + localBasePathOffset);
            if (abs >= b.Length) return null;

            // ANSI-строка с нулевым терминатором
            var end = abs;
            while (end < b.Length && b[end] != 0) end++;
            var target = Encoding.Default.GetString(b, abs, end - abs);
            return string.IsNullOrWhiteSpace(target) ? null : target;
        }
        catch
        {
            return null;
        }
    }

    // Fallback: WScript.Shell COM требует STA-поток
    private static string? ComTargetSta(string path)
    {
        string? result = null;
        try
        {
            var thread = new Thread(() => result = ComTarget(path))
            {
                IsBackground = true
            };
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            if (!thread.Join(1500)) return null;
        }
        catch
        {
            return null;
        }
        return result;
    }

    private static string? ComTarget(string path)
    {
        try
        {
            var type = Type.GetTypeFromProgID("WScript.Shell");
            if (type == null) return null;
            dynamic shell = Activator.CreateInstance(type)!;
            dynamic lnk = shell.CreateShortcut(path);
            var t = (string)(lnk.TargetPath ?? "");
            return string.IsNullOrWhiteSpace(t) ? null : t;
        }
        catch
        {
            return null;
        }
    }
}
