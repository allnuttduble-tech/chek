using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace DetectAcUI.Scanning;

// ==================== Сканер Windows Prefetch ====================
// C:\Windows\Prefetch\*.pf. Файлы Win10/11 сжаты MAM (LZXPRESS Huffman) —
// распаковка через ntdll!RtlDecompressBufferEx. Старые версии хранятся как есть.
// Формат по спецификации libyal/libscca:
//   MAM-заголовок 8 байт: "MAM\x04" + DWORD uncompressed size;
//   заголовок PF: version @0, "SCCA" @4, имя @16 (UTF-16, до 29 симв.);
//   file information начинается с 0x54:
//     v17: last run @0x78, run count @0x90
//     v23: last run @0x80, run count @0x98
//     v26: 8 run times @0x80 (первый — самый свежий), run count @0xD0
//     v30v1: run count @0xD0 (metrics offset 0x130)
//     v30v2/v31: run count @0xC8 (metrics offset 0x128)

public static class PrefetchScanner
{
    public sealed class PrefetchEntry
    {
        public string Executable = "";
        public string PfFile = "";
        public int RunCount;
        public DateTime? LastRun;
    }

    public sealed class PrefetchResult
    {
        public List<PrefetchEntry> Entries { get; } = new();
        public SectionStatus Status { get; set; } = SectionStatus.Ok;
        public bool NoAccess;

        public static PrefetchResult Empty() => new();
    }

    private const int MaxEntries = 5000;

    public static PrefetchResult Scan()
    {
        var result = new PrefetchResult();
        const string dir = @"C:\Windows\Prefetch";

        string[] files;
        try
        {
            if (!Directory.Exists(dir))
            {
                result.Status = SectionStatus.Empty;
                return result;
            }
            files = Directory.GetFiles(dir, "*.pf", SearchOption.TopDirectoryOnly);
            if (files.Length == 0)
            {
                result.Status = SectionStatus.Empty;
                return result;
            }
        }
        catch (UnauthorizedAccessException)
        {
            result.Status = SectionStatus.NoAccess;
            result.NoAccess = true;
            return result;
        }
        catch
        {
            result.Status = SectionStatus.NoAccess;
            result.NoAccess = true;
            return result;
        }

        foreach (var file in files)
        {
            if (result.Entries.Count >= MaxEntries) break;
            try
            {
                var entry = ParseFile(file);
                if (entry != null) result.Entries.Add(entry);
            }
            catch
            {
                // одиночный битый .pf пропускаем
            }
        }

        result.Entries.Sort((a, b) =>
        {
            var la = a.LastRun ?? DateTime.MinValue;
            var lb = b.LastRun ?? DateTime.MinValue;
            return lb.CompareTo(la);
        });

        return result;
    }

    private static PrefetchEntry? ParseFile(string file)
    {
        byte[] raw;
        try
        {
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Length < 0x54) return null;
            raw = new byte[fs.Length];
            using var br = new BinaryReader(fs);
            raw = br.ReadBytes((int)fs.Length);
        }
        catch
        {
            return null;
        }

        var data = raw;

        // MAM-контейнер: 'M','A','M',0x04 (возможен флаг 0x80 — контрольная сумма)
        if (raw.Length > 8 && raw[0] == 'M' && raw[1] == 'A' && raw[2] == 'M' && (raw[3] & 0x7F) == 4)
        {
            var uncompressedSize = BitConverter.ToUInt32(raw, 4);
            if (uncompressedSize == 0 || uncompressedSize > 64_000_000) return null;
            var decompressed = LzxpressHuffmanDecompress(raw, 8, (int)raw.Length - 8, (int)uncompressedSize);
            if (decompressed == null) return null;
            data = decompressed;
        }

        if (data.Length < 0x54) return null;
        if (data[4] != 'S' || data[5] != 'C' || data[6] != 'C' || data[7] != 'A') return null;

        var version = BitConverter.ToUInt32(data, 0);
        var name = ReadUtf16(data, 0x10, 60);
        if (string.IsNullOrEmpty(name)) return null;

        long lastRun = 0;
        if (version == 17)
        {
            lastRun = BitConverter.ToInt64(data, 0x78);
        }
        else if (version >= 23)
        {
            // 8 слотов @0x80; первый ненулевой — самый свежий запуск
            for (var i = 0; i < 8; i++)
            {
                var t = BitConverter.ToInt64(data, 0x80 + i * 8);
                if (t > 0) { lastRun = t; break; }
            }
        }

        uint runCount;
        if (version == 17) runCount = BitConverter.ToUInt32(data, 0x90);
        else if (version == 23) runCount = BitConverter.ToUInt32(data, 0x98);
        else if (version == 26) runCount = BitConverter.ToUInt32(data, 0xD0);
        else
        {
            // v30/v31: вариант определяем по смещению file metrics array @0x54
            var metricsOffset = BitConverter.ToUInt32(data, 0x54);
            runCount = metricsOffset == 0x130
                ? BitConverter.ToUInt32(data, 0xD0)
                : BitConverter.ToUInt32(data, 0xC8);
        }

        return new PrefetchEntry
        {
            Executable = name!,
            PfFile = Path.GetFileName(file),
            RunCount = runCount > 0 && runCount < 1_000_000 ? (int)runCount : 0,
            LastRun = TimeUtils.FromFileTime(lastRun)
        };
    }

    // ==================== LZXPRESS Huffman (ntdll) ====================

    private const ushort CompressionFormatXpressHuff = 4;

    // последний NTSTATUS распаковки — для диагностики
    internal static int LastNtStatus;

    [DllImport("ntdll.dll")]
    private static extern int RtlGetCompressionWorkSpaceSize(
        ushort compressionFormat, out uint compressBufferWorkSpaceSize, out uint compressFragmentWorkSpaceSize);

    [DllImport("ntdll.dll")]
    private static extern int RtlDecompressBufferEx(
        ushort compressionFormat, byte[] uncompressedBuffer, uint uncompressedBufferSize,
        byte[] compressedBuffer, uint compressedBufferSize, out uint finalUncompressedSize, IntPtr workSpace);

    [DllImport("ntdll.dll")]
    private static extern int RtlDecompressBuffer(
        ushort compressionFormat, byte[] uncompressedBuffer, uint uncompressedBufferSize,
        byte[] compressedBuffer, uint compressedBufferSize, out uint finalUncompressedSize);

    private static byte[]? LzxpressHuffmanDecompress(byte[] src, int offset, int count, int expectedSize)
    {
        try
        {
            var compressed = new byte[count];
            Array.Copy(src, offset, compressed, 0, count);
            var dest = new byte[expectedSize];

            // XPRESS_Huff требует рабочий буфер — через RtlDecompressBufferEx
            var status = RtlGetCompressionWorkSpaceSize(CompressionFormatXpressHuff, out _, out var wsSize);
            if (status == 0 && wsSize > 0 && wsSize < 64_000_000)
            {
                var ws = Marshal.AllocHGlobal((int)wsSize);
                try
                {
                    status = RtlDecompressBufferEx(CompressionFormatXpressHuff,
                        dest, (uint)dest.Length, compressed, (uint)compressed.Length, out var finalSize, ws);
                    LastNtStatus = status;
                    if (status == 0 && finalSize > 0 && finalSize <= (uint)dest.Length)
                    {
                        Array.Resize(ref dest, (int)finalSize);
                        return dest;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(ws);
                }
            }
            else
            {
                LastNtStatus = status;
            }

            // запасной путь без workspace
            status = RtlDecompressBuffer(CompressionFormatXpressHuff,
                dest, (uint)dest.Length, compressed, (uint)compressed.Length, out var finalSize2);
            LastNtStatus = status;
            if (status != 0 || finalSize2 == 0 || finalSize2 > (uint)dest.Length) return null;
            Array.Resize(ref dest, (int)finalSize2);
            return dest;
        }
        catch
        {
            return null;
        }
    }

    private static string? ReadUtf16(byte[] b, int start, int maxBytes)
    {
        if (start + 2 > b.Length) return null;
        var end = Math.Min(start + maxBytes, b.Length - 1);
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
}
