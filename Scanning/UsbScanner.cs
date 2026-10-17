using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace DetectAcUI.Scanning;

// ==================== Сканер USB-накопителей (аналог USBDeview) ====================
// HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR — устройства,
// Properties\{83da6326-...}\0066/0067 — последнее подключение/отключение (FILETIME),
// setupapi.dev.log — первая дата, когда устройство видели в системе.

public static class UsbScanner
{
    public sealed class UsbDevice
    {
        public string Name = "";
        public string Type = "";
        public string Serial = "";
        public string InstanceId = "";
        public DateTime? LastArrival;    // последнее подключение
        public DateTime? LastRemoval;    // последнее отключение
        public DateTime? FirstSeen;      // первая установка в системе (setupapi.dev.log)
    }

    public sealed class UsbResult
    {
        public List<UsbDevice> Devices { get; } = new();

        public static UsbResult Empty() => new();
    }

    private const string DeviceSetupClass = "{83da6326-97a6-4088-9453-a1923f573b29}";
    private const string LastArrivalValue = "0066";
    private const string LastRemovalValue = "0067";

    public static UsbResult Scan()
    {
        var result = new UsbResult();

        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var usbStor = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR");
        if (usbStor == null) return result;

        var setupApiDates = ParseSetupApiLog();

        foreach (var deviceKey in usbStor.GetSubKeyNames())
        {
            using var devKey = usbStor.OpenSubKey(deviceKey);
            if (devKey == null) continue;

            foreach (var serial in devKey.GetSubKeyNames())
            {
                using var instKey = devKey.OpenSubKey(serial);
                if (instKey == null) continue;

                var device = new UsbDevice
                {
                    InstanceId = $"USBSTOR\\{deviceKey}\\{serial}",
                    Serial = serial,
                    Type = ExtractType(deviceKey)
                };

                if (instKey.GetValue("FriendlyName") is string fn && !string.IsNullOrWhiteSpace(fn))
                    device.Name = fn;
                else if (instKey.GetValue("DeviceDesc") is string dd)
                {
                    var idx = dd.LastIndexOf(';');
                    device.Name = idx >= 0 && idx + 1 < dd.Length ? dd[(idx + 1)..] : dd;
                }
                else
                {
                    device.Name = ParseProduct(deviceKey);
                }

                // свойства времени подключения/отключения:
                // Properties\{83da6326-...}\0066/0067 — подключи, данные в дефолт-значении
                try
                {
                    device.LastArrival = ReadDeviceProperty(instKey, LastArrivalValue);
                    device.LastRemoval = ReadDeviceProperty(instKey, LastRemovalValue);
                }
                catch
                {
                    // нет доступа к Properties — остаются только даты из setupapi-лога
                }

                // первая дата в setupapi.dev.log (точное совпадение, иначе по серийнику)
                if (setupApiDates.TryGetValue(device.InstanceId.ToUpperInvariant(), out var first))
                    device.FirstSeen = first;
                else
                {
                    var baseSerial = serial.EndsWith("&0", StringComparison.OrdinalIgnoreCase)
                        ? serial[..^2]
                        : serial;
                    if (baseSerial.Length >= 6)
                    {
                        foreach (var (id, date) in setupApiDates)
                        {
                            if (id.Contains(baseSerial.ToUpperInvariant()) &&
                                (device.FirstSeen == null || date < device.FirstSeen))
                                device.FirstSeen = date;
                        }
                    }
                }

                result.Devices.Add(device);
            }
        }

        result.Devices.Sort((a, b) =>
            (b.LastArrival ?? DateTime.MinValue).CompareTo(a.LastArrival ?? DateTime.MinValue));

        return result;
    }

    private static string ExtractType(string deviceKey)
    {
        // "Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP"
        return deviceKey.Split('&')[0];
    }

    private static DateTime? ReadDeviceProperty(RegistryKey instKey, string pid)
    {
        using var pk = instKey.OpenSubKey($"Properties\\{DeviceSetupClass}\\{pid}");
        if (pk?.GetValue(null) is not byte[] data || data.Length != 8) return null;
        return TimeUtils.FromFileTime(BitConverter.ToInt64(data, 0));
    }

    private static string ParseProduct(string deviceKey)
    {
        string ven = "", prod = "";
        foreach (var part in deviceKey.Split('&'))
        {
            if (part.StartsWith("Ven_", StringComparison.OrdinalIgnoreCase)) ven = part[4..];
            else if (part.StartsWith("Prod_", StringComparison.OrdinalIgnoreCase)) prod = part[5..];
        }
        var name = $"{ven} {prod}".Trim();
        return name.Length == 0 ? deviceKey : name;
    }

    // ==================== setupapi.dev.log ====================
    // Секции: ">>>  [Device Install (Hardware initiated) - USB\VID_...&PID_...\SERIAL]"
    //         ">>>  Section start 2024/01/05 12:33:44.567"

    private static Dictionary<string, DateTime> ParseSetupApiLog()
    {
        var dates = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);

        foreach (var path in new[] { @"C:\Windows\INF\setupapi.dev.log", @"C:\Windows\INF\setupapi.dev.log.1" })
        {
            string text;
            try
            {
                if (!File.Exists(path)) continue;
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var sr = new StreamReader(fs);
                text = sr.ReadToEnd();
            }
            catch
            {
                continue;
            }

            // «>>>  [Device Install (Hardware initiated) - USB\VID_0781&PID_5583\ABC]»
            // → id = то, что после последнего « - » внутри скобок
            var sectionRegex = new Regex(@"\[[^\]]*?\s-\s(?<id>[^\]]+)\]",
                RegexOptions.Compiled);
            var startRegex = new Regex(@"Section start\s+(?<d>\d{4}/\d{2}/\d{2})\s+(?<t>\d{2}:\d{2}:\d{2})",
                RegexOptions.Compiled);

            string? currentId = null;
            foreach (var line in text.Split('\n'))
            {
                var trimmed = line.TrimEnd('\r');
                if (trimmed.StartsWith(">>>", StringComparison.Ordinal))
                {
                    // строки-заголовки секций: «[<событие> - <ID устройства>]»
                    var m = sectionRegex.Match(trimmed);
                    if (m.Success)
                    {
                        var id = m.Groups["id"].Value.Trim().ToUpperInvariant();
                        // отбираем только идентификаторы устройств (содержат «\»)
                        currentId = id.Contains('\\') ? id : null;
                    }

                    // «>>>  Section start 2026/10/05 23:53:18.263» — дата текущей секции
                    if (currentId != null)
                    {
                        var sm = startRegex.Match(trimmed);
                        if (sm.Success &&
                            DateTime.TryParse(sm.Groups["d"].Value + " " + sm.Groups["t"].Value,
                                System.Globalization.CultureInfo.InvariantCulture,
                                System.Globalization.DateTimeStyles.None, out var dt))
                        {
                            if (!dates.TryGetValue(currentId, out var existing) || dt < existing)
                                dates[currentId] = dt;
                        }
                    }
                    continue;
                }
            }
        }

        return dates;
    }
}
