using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DetectAcUI.Scanning;

// ==================== Мини-ридер SQLite (только чтение) ====================
// Достаточно для таблиц Chromium History (urls) и Firefox places (moz_places).
// Поддерживает: b-tree таблиц (interior/leaf), overflow-страницы, WAL-оверлей
// (чтобы видеть свежие записи, не выгруженные из журнала браузером).

public sealed class MiniSql
{
    private readonly byte[] _db;
    private readonly uint _pageSize;
    private readonly uint _usable;
    private readonly Dictionary<uint, byte[]> _walPages = new();

    private MiniSql(byte[] db, uint pageSize, uint reserved)
    {
        _db = db;
        _pageSize = pageSize;
        _usable = pageSize - reserved;
    }

    // Открыть копию базы; при наличии рядом "<path>-wal" — наложить WAL
    public static MiniSql? TryOpen(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var db = File.ReadAllBytes(path);
            if (db.Length < 208) return null;
            if (Encoding.ASCII.GetString(db, 0, 16) != "SQLite format 3\0") return null;

            var pageSize = ReadU16(db, 16);
            if (pageSize == 1) pageSize = 65536;
            if (pageSize < 512 || (pageSize & (pageSize - 1)) != 0) return null;
            var reserved = db[20];
            if (pageSize - reserved < 480) return null;

            var sql = new MiniSql(db, (uint)pageSize, reserved);
            sql.TryLoadWal(path + "-wal");
            return sql;
        }
        catch
        {
            return null;
        }
    }

    // Найти rootpage таблицы по имени (по sqlite_master, страница 1)
    public uint? FindTableRoot(string tableName)
    {
        // в sqlite_master десятки таблиц — берём все
        foreach (var row in WalkTable(1, 500, 500))
        {
            // sqlite_master: type, name, tbl_name, rootpage, sql
            if (row.Count < 5) continue;
            if (row[0] is string t && t == "table" &&
                row[1] is string n && string.Equals(n, tableName, StringComparison.OrdinalIgnoreCase))
            {
                return row[3] switch
                {
                    long l => (uint)l,
                    _ => null
                };
            }
        }
        return null;
    }

    // Диагностика: сколько строк выдаёт обход страницы 1 (используется харнессом)
    public int DebugRowCount()
    {
        var n = 0;
        foreach (var r in WalkTable(1, 500, 500)) n++;
        return n;
    }

    // Полный обход таблицы; rows = список значений колонок
    public List<List<object?>> ReadTable(string tableName, int limit)
    {
        var result = new List<List<object?>>();
        var root = FindTableRoot(tableName);
        if (root == null) return result;
        foreach (var row in WalkTable(root.Value, limit, limit))
            result.Add(row);
        return result;
    }

    // ==================== Обход b-tree ====================

    private IEnumerable<List<object?>> WalkTable(uint rootPage, int maxRows, int limit)
    {
        var pages = new Stack<uint>();
        pages.Push(rootPage);
        var visited = new HashSet<uint>();
        var yielded = 0;

        while (pages.Count > 0 && yielded < Math.Min(maxRows, limit))
        {
            var pageNo = pages.Pop();
            if (pageNo == 0 || !visited.Add(pageNo)) continue;
            var page = ReadPage(pageNo);
            if (page == null) continue;

            var hdr = pageNo == 1 ? 100 : 0;
            var type = page[hdr];
            var cellCount = ReadU16(page, hdr + 3);

            if (type == 5) // interior table
            {
                // правый потомок
                if (hdr + 12 <= page.Length)
                {
                    var right = ReadU32(page, hdr + 8);
                    if (right != 0) pages.Push(right);
                }
                for (var i = 0; i < cellCount; i++)
                {
                    var ptrOff = hdr + 12 + i * 2;
                    if (ptrOff + 2 > page.Length) break;
                    var cellOff = ReadU16(page, ptrOff);
                    if (cellOff + 4 > page.Length) continue;
                    var left = ReadU32(page, cellOff);
                    if (left != 0) pages.Push(left);
                }
            }
            else if (type == 13) // leaf table
            {
                for (var i = 0; i < cellCount; i++)
                {
                    var ptrOff = hdr + 8 + i * 2;
                    if (ptrOff + 2 > page.Length) break;
                    var cellOff = ReadU16(page, ptrOff);
                    if (cellOff >= page.Length) continue;

                    if (!TryReadLeafCell(page, cellOff, out var record)) continue;
                    yielded++;
                    yield return record;
                    if (yielded >= Math.Min(maxRows, limit)) yield break;
                }
            }
        }
    }

    private bool TryReadLeafCell(byte[] page, int cellOff, out List<object?> record)
    {
        record = new List<object?>();
        var pos = cellOff;
        if (!ReadVarint(page, ref pos, out var payloadLen)) return false;
        if (!ReadVarint(page, ref pos, out _)) return false; // rowid

        var payload = ReadPayload(page, pos, payloadLen);
        if (payload == null) return false;

        return TryDecodeRecord(payload, record);
    }

    // Сборка payload с учётом overflow-страниц
    private byte[]? ReadPayload(byte[] page, int pos, long payloadLen)
    {
        if (payloadLen < 0 || payloadLen > 8_000_000) return null;

        var usable = (long)_usable;
        var maxLocal = usable - 35;
        var local = payloadLen;

        if (payloadLen > maxLocal)
        {
            var minLocal = ((usable - 12) * 32 / 255) - 23;
            var k = minLocal + ((payloadLen - minLocal) % (usable - 4));
            local = k <= maxLocal ? k : minLocal;
        }

        if (pos + local > page.Length) return null;
        var result = new byte[payloadLen];
        Array.Copy(page, pos, result, 0, local);
        var written = local;

        if (payloadLen > maxLocal)
        {
            if (pos + local + 4 > page.Length) return null;
            var nextPage = ReadU32(page, pos + (int)local);
            var guard = 0;
            while (nextPage != 0 && written < payloadLen && guard++ < 2000)
            {
                var op = ReadPage(nextPage);
                if (op == null) return null;
                var next = ReadU32(op, 0);
                var chunk = (int)Math.Min((long)_usable - 4, payloadLen - written);
                if (4 + chunk > op.Length) return null;
                Array.Copy(op, 4, result, written, chunk);
                written += chunk;
                nextPage = next;
            }
            if (written < payloadLen) return null;
        }

        return result;
    }

    private bool TryDecodeRecord(byte[] payload, List<object?> values)
    {
        var pos = 0;
        if (!ReadVarint(payload, ref pos, out var headerSize)) return false;
        if (headerSize < 1 || headerSize > payload.Length) return false;

        var types = new List<long>();
        var hpos = pos;
        while (hpos < headerSize)
        {
            if (!ReadVarint(payload, ref hpos, out var st)) return false;
            types.Add(st);
        }

        var bpos = (int)headerSize;
        foreach (var st in types)
        {
            object? value;
            switch (st)
            {
                case 0: value = null; break;
                case 1: value = (long)(sbyte)(bpos < payload.Length ? (sbyte)payload[bpos] : 0); bpos += 1; break;
                case 2: value = (long)(short)ReadSigned(payload, bpos, 2); bpos += 2; break;
                case 3: value = ReadSigned(payload, bpos, 3); bpos += 3; break;
                case 4: value = (long)(int)ReadSigned(payload, bpos, 4); bpos += 4; break;
                case 5: value = ReadSigned(payload, bpos, 6); bpos += 6; break;
                case 6: value = ReadSigned(payload, bpos, 8); bpos += 8; break;
                case 7:
                    value = bpos + 8 <= payload.Length ? BitConverter.Int64BitsToDouble(ReadSigned(payload, bpos, 8)) : 0.0;
                    bpos += 8;
                    break;
                case 8: value = 0L; break;
                case 9: value = 1L; break;
                case 10:
                case 11: value = null; break;
                default:
                {
                    var len = (int)((st - 12) / 2);
                    if (bpos + len > payload.Length) { value = null; break; }
                    value = st % 2 == 0
                        ? (object)CopyRange(payload, bpos, len)                     // blob
                        : (object)Encoding.UTF8.GetString(payload, bpos, len);      // text
                    bpos += len;
                    break;
                }
            }
            values.Add(value);
        }
        return true;
    }

    // ==================== WAL ====================

    private void TryLoadWal(string walPath)
    {
        try
        {
            if (!File.Exists(walPath)) return;
            var wal = File.ReadAllBytes(walPath);
            if (wal.Length < 32) return;

            var magic = ReadU32(wal, 0);
            if (magic != 0x377F0682 && magic != 0x377F0683) return;
            var bigEndianWords = magic == 0x377F0683;

            var walPageSize = ReadU32(wal, 8);
            if (walPageSize != _pageSize) return;

            var salt1 = ReadU32(wal, 16);
            var salt2 = ReadU32(wal, 20);
            var s0 = ReadU32(wal, 24);
            var s1 = ReadU32(wal, 28);

            var frameSize = 24 + (int)_pageSize;
            var lastCommit = -1;
            var frameCount = (wal.Length - 32) / frameSize;

            for (var f = 0; f < frameCount; f++)
            {
                var off = 32 + f * frameSize;
                if (ReadU32(wal, off + 8) != salt1 || ReadU32(wal, off + 12) != salt2) break;

                // контрольная сумма: первые 8 байт заголовка фрейма + страница
                var c0 = s0; var c1 = s1;
                Cksum(wal, off, 8, bigEndianWords, ref c0, ref c1);
                Cksum(wal, off + 24, (int)_pageSize, bigEndianWords, ref c0, ref c1);
                if (c0 != ReadU32(wal, off + 16) || c1 != ReadU32(wal, off + 20)) break;

                s0 = c0; s1 = c1;
                if (ReadU32(wal, off + 4) != 0) lastCommit = f; // commit-фрейм
            }

            if (lastCommit < 0) return;

            for (var f = 0; f <= lastCommit; f++)
            {
                var off = 32 + f * frameSize;
                var pgno = ReadU32(wal, off);
                if (pgno == 0 || pgno > 100_000_000) continue;
                var data = new byte[_pageSize];
                Array.Copy(wal, off + 24, data, 0, _pageSize);
                _walPages[pgno] = data;
            }
        }
        catch
        {
            // без WAL обойдёмся основной базой
        }
    }

    private static void Cksum(byte[] data, int offset, int len, bool bigEndian, ref uint s0, ref uint s1)
    {
        for (var i = 0; i + 8 <= len; i += 8)
        {
            uint x0 = bigEndian ? ReadU32(data, offset + i) : BitConverter.ToUInt32(data, offset + i);
            uint x1 = bigEndian ? ReadU32(data, offset + i + 4) : BitConverter.ToUInt32(data, offset + i + 4);
            s0 += x0 + s1;
            s1 += x1 + s0;
        }
    }

    // ==================== Страницы/примитивы ====================

    // Диагностика внутренностей базы (используется тестовым харнессом)
    public string DebugInfo()
    {
        var sb = new StringBuilder();
        var p = ReadPage(1);
        if (p == null) return "page1=null";
        var hdr = 100;
        sb.Append($"pageSize={_pageSize} walPages={_walPages.Count} p1type={p[hdr]} ");
        var cellCount = ReadU16(p, hdr + 3);
        sb.Append($"cells={cellCount} ");

        // спускаемся к первому листу и декодируем первую запись
        var pageNo = 1u;
        for (var depth = 0; depth < 5; depth++)
        {
            var page = ReadPage(pageNo);
            if (page == null) { sb.Append($" page{pageNo}=null"); break; }
            var h = pageNo == 1 ? 100 : 0;
            var type = page[h];
            if (type == 5)
            {
                var off = ReadU16(page, h + 12);
                pageNo = ReadU32(page, off);
                sb.Append($" ->{pageNo}");
                continue;
            }
            if (type == 13)
            {
                var cells = ReadU16(page, h + 3);
                var off = ReadU16(page, h + 8);
                var pos = off;
                ReadVarint(page, ref pos, out var plen);
                ReadVarint(page, ref pos, out var rowid);
                sb.Append($" leaf p{pageNo} cells={cells} off={off} plen={plen} rowid={rowid}");
                if (TryReadLeafCell(page, off, out var record))
                    sb.Append($" record cols={record.Count} v0={record.FirstOrDefault()} v1={record.Skip(1).FirstOrDefault()}");
                else
                    sb.Append(" record DECODE-FAIL");
                break;
            }
            sb.Append($" p{pageNo} unknown-type={type}");
            break;
        }
        return sb.ToString();
    }

    private byte[]? ReadPage(uint pageNo)
    {
        if (_walPages.TryGetValue(pageNo, out var p)) return p;
        var offset = (long)(pageNo - 1) * _pageSize;
        if (offset < 0 || offset + _pageSize > _db.Length) return null;
        var page = new byte[_pageSize];
        Array.Copy(_db, offset, page, 0, _pageSize);
        return page;
    }

    private static bool ReadVarint(byte[] b, ref int pos, out long value)
    {
        value = 0;
        for (var i = 0; i < 8; i++)
        {
            if (pos >= b.Length) return false;
            var byteVal = b[pos++];
            value = (value << 7) | (long)(byteVal & 0x7F);
            if ((byteVal & 0x80) == 0) return true;
        }
        if (pos >= b.Length) return false;
        value = (value << 8) | (long)b[pos++];
        return true;
    }

    private static long ReadSigned(byte[] b, int pos, int len)
    {
        long v = 0;
        for (var i = 0; i < len; i++)
            v = (v << 8) | (long)(pos + i < b.Length ? (uint)b[pos + i] : 0u);
        // знаковое расширение
        var shift = 64 - len * 8;
        return len == 8 ? v : (v << shift) >> shift;
    }

    private static uint ReadU32(byte[] b, int pos)
        => ((uint)b[pos] << 24) | ((uint)b[pos + 1] << 16) | ((uint)b[pos + 2] << 8) | (uint)b[pos + 3];
    private static int ReadU16(byte[] b, int pos)
        => (b[pos] << 8) | b[pos + 1];

    private static byte[] CopyRange(byte[] src, int pos, int len)
    {
        var r = new byte[len];
        Array.Copy(src, pos, r, 0, len);
        return r;
    }
}
