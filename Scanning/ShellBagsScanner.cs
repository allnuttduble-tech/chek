using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace DetectAcUI.Scanning;

// ==================== Сканер ShellBags ====================
// Обход HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU:
// восстанавливаем пути, которые пользователь открывал в Проводнике.
// Путь, которого больше нет на диске, помечается как «удалён».
// Extension block 0xbeef0008 даёт оригинальный путь и время удаления (корзина).

public static class ShellBagsScanner
{
    public sealed class ShellBagEntry
    {
        public string Path = "";
        public DateTime? NodeTime;     // время последней записи в узле BagMRU
        public DateTime? DeletedTime;  // время удаления (из 0xbeef0008, если есть)
        public bool Exists;
        public bool IsRecycled;        // запись из корзины

        public bool Deleted => !Exists && IsLocalPath(Path);

        public static bool IsLocalPath(string p)
            => p.Length > 3 && char.IsLetter(p[0]) && p[1] == ':' && p[2] == '\\'
               || p.StartsWith(@"\\", StringComparison.Ordinal);
    }

    public sealed class ShellBagsResult
    {
        public List<ShellBagEntry> Entries { get; } = new();
        public bool NoAccess;

        public static ShellBagsResult Empty() => new();
    }

    private static readonly HashSet<string> NamespaceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Desktop", "This PC", "Recycle Bin", "Control Panel", "Network",
        "Users", "User Files", "Libraries", "Games"
    };

    private static readonly Dictionary<string, string> GuidNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["00021400-0000-0000-C000-000000000046"] = "Desktop",
        ["20D04FE0-3AEA-1069-A2D8-08002B30309D"] = "This PC",
        ["645FF040-5081-101B-9F08-00AA002F954E"] = "Recycle Bin",
        ["21EC2020-3AEA-1069-A2DD-08002B30309D"] = "Control Panel",
        ["208D2C60-3AEA-1069-A2D7-08002B30309D"] = "Network",
        ["59031A47-3F72-44A7-89C5-5595FE6B30EE"] = "Users",
        ["F3364BA0-E04C-4E09-8D0B-9DD2BA4548A7"] = "User Files",
        ["031E4825-7B94-4DC3-B131-E946B44C8DD5"] = "Libraries",
        ["ED228FDF-9EA8-4870-83B1-96B02CFE0D52"] = "Games"
    };

    private const int MaxEntries = 4000;

    public static ShellBagsResult Scan()
    {
        var result = new ShellBagsResult();
        RegistryKey? root = null;
        try
        {
            root = Registry.CurrentUser.OpenSubKey(
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU");
        }
        catch
        {
            root = null;
        }

        if (root == null)
        {
            result.NoAccess = true;
            return result;
        }

        using (root)
        {
            // ВАЖНО: IDList узла хранится не в его дефолт-значении, а в именованном
            // значении РОДИТЕЛЬСКОГО ключа (совпадает с именем подключа).
            var queue = new Queue<(RegistryKey Key, byte[]? Blob, string DiskPath)>();
            foreach (var name in root.GetSubKeyNames())
            {
                RegistryKey? child = null;
                try { child = root.OpenSubKey(name); } catch { }
                if (child == null) continue;
                var blob = root.GetValue(name) as byte[];
                queue.Enqueue((child, blob, ""));
            }

            while (queue.Count > 0 && result.Entries.Count < MaxEntries)
            {
                var (key, blob, diskPath) = queue.Dequeue();
                using (key)
                {
                    var component = "";
                    var isVolume = false;
                    ShellItemInfo? info = null;

                    if (blob != null && blob.Length >= 4)
                    {
                        info = ParseShellItem(blob);
                        component = info.Name;
                        isVolume = component.Length == 2 &&
                                   char.IsLetter(component[0]) && component[1] == ':';
                    }

                    // Путь: namespace-компоненты сбрасывают накопленный путь,
                    // диски начинают новый, обычные имена добавляются к текущему.
                    string childPath;
                    if (info?.Recycled == true)
                    {
                        // запись корзины: реальный путь + время удаления
                        result.Entries.Add(new ShellBagEntry
                        {
                            Path = info.OriginalPath ?? "",
                            NodeTime = TryGetKeyTime(key),
                            DeletedTime = info.DeletedTime,
                            Exists = false,
                            IsRecycled = true
                        });
                        childPath = "";
                    }
                    else if (component.Length == 0 || component.StartsWith("::{", StringComparison.Ordinal)
                             || NamespaceNames.Contains(component))
                    {
                        childPath = "";
                    }
                    else if (isVolume)
                    {
                        childPath = component + "\\";
                    }
                    else
                    {
                        childPath = diskPath.Length == 0
                            ? component
                            : diskPath.EndsWith("\\", StringComparison.Ordinal)
                                ? diskPath + component
                                : diskPath + "\\" + component;
                    }

                    if (component.Length > 0 && info?.Recycled != true)
                    {
                        var isLocal = ShellBagEntry.IsLocalPath(childPath);
                        result.Entries.Add(new ShellBagEntry
                        {
                            Path = childPath,
                            NodeTime = TryGetKeyTime(key),
                            Exists = !isLocal || Directory.Exists(childPath) || File.Exists(childPath)
                        });
                    }

                    foreach (var sub in key.GetSubKeyNames())
                    {
                        RegistryKey? child = null;
                        try { child = key.OpenSubKey(sub); } catch { }
                        if (child == null) continue;
                        var childBlob = key.GetValue(sub) as byte[];
                        queue.Enqueue((child, childBlob, childPath));
                    }
                }
            }
        }

        // удалённые — первыми, затем по времени
        result.Entries.Sort((a, b) =>
        {
            if (a.Deleted != b.Deleted) return a.Deleted ? -1 : 1;
            var ta = a.DeletedTime ?? a.NodeTime ?? DateTime.MinValue;
            var tb = b.DeletedTime ?? b.NodeTime ?? DateTime.MinValue;
            return tb.CompareTo(ta);
        });

        return result;
    }

    private static DateTime? TryGetKeyTime(RegistryKey key) => RegUtils.GetKeyLastWriteTime(key);

    // ==================== Разбор Shell Item ====================

    private sealed class ShellItemInfo
    {
        public string Name = "";
        public bool Recycled;
        public string? OriginalPath;
        public DateTime? DeletedTime;
    }

    private static ShellItemInfo ParseShellItem(byte[] b)
    {
        var info = new ShellItemInfo();
        if (b.Length < 5) return info;

        var cb = (int)BitConverter.ToUInt16(b, 0);
        if (cb <= 4 || cb > b.Length) cb = b.Length;
        var type = b[2];

        switch (type & 0x70)
        {
            case 0x10: // root: GUID
            {
                var g = TryReadGuid(b, 4);
                if (g != null) info.Name = GuidNames.TryGetValue(g, out var n) ? n : "::{ " + g + " }";
                break;
            }
            case 0x20: // volume / диск
            {
                if ((type & 0x01) != 0)
                {
                    info.Name = ReadAnsi(b, 3, Math.Min(cb, 24)) ?? "";
                }
                else if (b.Length >= 4 && b[3] >= 'A' && b[3] <= 'Z')
                {
                    info.Name = (char)b[3] + ":";
                }
                else
                {
                    var g = TryReadGuid(b, 4);
                    if (g != null) info.Name = GuidNames.TryGetValue(g, out var n) ? n : "::{ " + g + " }";
                }
                break;
            }
            case 0x30: // file/folder entry
            {
                var longName = TryReadBeef0004LongName(b, cb);
                var recycle = TryReadBeef0008Recycle(b, cb);
                // первичное имя — по смещению 0x0E (после size/type/zero/filesize/FAT-mtime/attrs)
                var primary = (type & 0x04) != 0
                    ? ReadUtf16(b, 0x0E, cb)
                    : BestReadable(ReadAnsiAligned(b, 0x0E, cb), ReadUtf16(b, 0x0E, cb));

                if (!string.IsNullOrEmpty(recycle.OriginalPath))
                {
                    info.Recycled = true;
                    info.OriginalPath = recycle.OriginalPath;
                    info.DeletedTime = recycle.DeletedTime;
                }
                else if (Score(longName) >= 60)
                {
                    info.Name = longName!;
                }
                else if (Score(primary) >= 60)
                {
                    info.Name = primary!;
                }
                else
                {
                    info.Name = FallbackScanName(b, cb) ?? (longName ?? primary ?? "");
                }
                break;
            }
            case 0x40: // network location
            {
                info.Name = ReadAnsi(b, 5, cb) ?? "";
                break;
            }
            case 0x70: // control panel и прочие GUID-элементы
            {
                var g = TryReadGuid(b, 4);
                if (g != null) info.Name = GuidNames.TryGetValue(g, out var n) ? n : "::{ " + g + " }";
                break;
            }
        }

        info.Name = info.Name?.Trim() ?? "";
        return info;
    }

    // Extension block 0xbeef0004: +0 size, +2 version, +4 signature,
    // +16 WORD long-name offset (относительно начала блока)
    private static string? TryReadBeef0004LongName(byte[] b, int cb)
    {
        var ext = FindSignature(b, cb, 0xbeef0004);
        if (ext < 0) return null;
        var extSize = (int)BitConverter.ToUInt16(b, ext);
        if (extSize < 0x1E || ext + extSize > cb) extSize = cb - ext;
        if (ext + 18 > cb) return null;

        var nameOffset = BitConverter.ToUInt16(b, ext + 16);
        if (nameOffset < 0x18 || nameOffset >= extSize) return null;

        var name = ReadUtf16(b, ext + nameOffset, Math.Min(ext + extSize, cb));
        return string.IsNullOrWhiteSpace(name) ? null : name;
    }

    private sealed class RecycleInfo
    {
        public string? OriginalPath;
        public DateTime? DeletedTime;
    }

    // Extension block 0xbeef0008 (корзина): +16 FILETIME удаления, +24 оригинальный путь UTF-16
    private static RecycleInfo TryReadBeef0008Recycle(byte[] b, int cb)
    {
        var res = new RecycleInfo();
        var ext = FindSignature(b, cb, 0xbeef0008);
        if (ext < 0) return res;

        if (ext + 24 <= cb)
            res.DeletedTime = TimeUtils.FromFileTime(BitConverter.ToInt64(b, ext + 16));

        if (ext + 24 + 2 <= cb)
        {
            var p = ReadUtf16(b, ext + 24, Math.Min(ext + 24 + 520, cb));
            if (!string.IsNullOrWhiteSpace(p) && ShellBagEntry.IsLocalPath(p!))
                res.OriginalPath = p;
        }
        return res;
    }

    private static int FindSignature(byte[] b, int cb, uint signature)
    {
        for (var off = 0x16; off + 8 <= cb; off += 2)
        {
            if (BitConverter.ToUInt32(b, off) == signature)
                return off;
        }
        return -1;
    }

    private static string? TryReadGuid(byte[] b, int offset)
    {
        if (b.Length < offset + 16) return null;
        var g = new Guid(BitConverter.ToInt32(b, offset), BitConverter.ToInt16(b, offset + 4),
            BitConverter.ToInt16(b, offset + 6), b[offset + 8], b[offset + 9], b[offset + 10], b[offset + 11],
            b[offset + 12], b[offset + 13], b[offset + 14], b[offset + 15]);
        return g.ToString();
    }

    private static string? ReadAnsi(byte[] b, int start, int limit)
    {
        if (start >= b.Length) return null;
        var end = Math.Min(limit, b.Length);
        var i = start;
        while (i < end && b[i] != 0) i++;
        if (i == start) return null;
        return Encoding.Default.GetString(b, start, i - start);
    }

    // первичное имя выровнено на 16 бит — возможен лишний нулевой байт
    private static string? ReadAnsiAligned(byte[] b, int start, int limit)
    {
        if (start < b.Length && b[start] == 0 && start + 1 < b.Length && b[start + 1] != 0)
            start++;
        return ReadAnsi(b, start, limit);
    }

    private static string? ReadUtf16(byte[] b, int start, int limit)
    {
        if (start + 2 > b.Length) return null;
        var end = Math.Min(limit, b.Length - 1);
        var sb = new StringBuilder();
        for (var i = start; i + 1 < end; i += 2)
        {
            var ch = BitConverter.ToUInt16(b, i);
            if (ch == 0) break;
            sb.Append((char)ch);
        }
        var s = sb.ToString();
        return s.Length == 0 ? null : s;
    }

    // выбираем вариант имени с большей долей читаемых символов
    // (часть записей хранит UTF-16 без флага 0x04)
    private static string? BestReadable(string? ansi, string? utf16)
    {
        if (ansi == null) return utf16;
        if (utf16 == null) return ansi;
        return Score(utf16) > Score(ansi) ? utf16 : ansi;
    }

    private static int Score(string? s)
    {
        if (string.IsNullOrEmpty(s)) return -1;
        var good = 0;
        foreach (var ch in s)
        {
            // латиница/цифры/пунктуация или кириллица — читаемо;
            // CJK и прочий мусор из неверной кодировки — нет
            if (ch < 0x0500 && (char.IsLetterOrDigit(ch) ||
                                ch is ' ' or '.' or '_' or '-' or '(' or ')' or '[' or ']' or '—' or '–'))
                good++;
        }
        return good * 100 / s.Length;
    }

    // крайний случай: ищем самую длинную печатную UTF-16-цепочку в записи
    // (нестандартные варианты file entry, где имя лежит со смещением)
    private static string? FallbackScanName(byte[] b, int cb)
    {
        string? best = null;
        var bestLen = 0;

        for (var start = 4; start + 6 < Math.Min(cb, b.Length - 1); start += 1)
        {
            var len = 0;
            var i = start;
            while (i + 1 < b.Length && len < 128)
            {
                var ch = BitConverter.ToUInt16(b, i);
                if (ch == 0) break;
                if (!IsPrintable(ch)) break;
                len++;
                i += 2;
            }
            if (len > bestLen && len >= 3)
            {
                best = ReadUtf16(b, start, cb);
                bestLen = len;
            }
        }
        return best;
    }

    private static bool IsPrintable(uint ch)
        => ch is >= 0x20 and <= 0x7E || ch is >= 0x0400 and <= 0x04FF;
}

// ==================== P/Invoke для времени ключа реестра ====================

internal static class RegUtils
{
    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
    private static extern int RegQueryInfoKey(
        IntPtr hKey, IntPtr @class, IntPtr classSize, IntPtr reserved,
        out uint subKeys, out uint maxSubKeyLen, out uint maxClassLen,
        out uint values, out uint maxValueNameLen, out uint maxValueLen, out uint maxDataLen,
        out long lastWriteTime /* FILETIME */);

    public static DateTime? GetKeyLastWriteTime(RegistryKey key)
    {
        try
        {
            // .NET 8: публичное свойство Handle
            var handle = key.Handle.DangerousGetHandle();
            var r = RegQueryInfoKey(handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                out _, out _, out _, out _, out _, out _, out _, out var ft);
            if (r != 0) return null;
            return TimeUtils.FromFileTime(ft);
        }
        catch
        {
            return null;
        }
    }
}
