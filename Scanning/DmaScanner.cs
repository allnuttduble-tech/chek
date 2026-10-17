using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace DetectAcUI.Scanning;

// ==================== Сканер PCI-устройств (DMA-карты) ====================
// Перечень PCI-устройств из HKLM\SYSTEM\CurrentControlSet\Enum\PCI + состояние
// через cfgmgr32 (подключено / проблема / отсутствует) + эвристика DMA по названию.

public static class DmaScanner
{
    public sealed class PciDevice
    {
        public string Name = "";
        public string InstanceId = "";
        public string VendorDevice = "";   // VEN_xxxx&DEV_xxxx
        public bool Present;
        public bool HasProblem;
        public uint ProblemCode;
        public bool Suspect;               // эвристика: похоже на DMA-устройство
        public bool NoDriver;
    }

    public sealed class DmaResult
    {
        public List<PciDevice> Devices { get; } = new();

        public static DmaResult Empty() => new();
    }

    // Известные семейства DMA-карт и FPGA-плат, используемых для них
    private static readonly string[] SuspectKeywords =
    {
        "dma", "pcileech", "screamer", "captain", "leet", "stark", "enigma", "viper",
        "xilinx", "artix", "kintex", "zynq", "spartan", "sp601", "sp605", "kc705", "vc707",
        "xc7a", "xc7k", "xc7z", "ft601", "ft4222", "ft232h", "cypress", "fx2", "fx3",
        "altera", "cyclone", "intel fpga", "fdma", "memdma"
    };

    public static DmaResult Scan()
    {
        var result = new DmaResult();

        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var pci = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\PCI");
        if (pci == null) return result;

        foreach (var hardwareId in pci.GetSubKeyNames())
        {
            using var hwKey = pci.OpenSubKey(hardwareId);
            if (hwKey == null) continue;

            foreach (var instance in hwKey.GetSubKeyNames())
            {
                using var instKey = hwKey.OpenSubKey(instance);
                if (instKey == null) continue;

                var instanceId = $"PCI\\{hardwareId}\\{instance}";
                var device = new PciDevice
                {
                    InstanceId = instanceId,
                    VendorDevice = ExtractVendorDevice(hardwareId)
                };

                device.Name = ResolveName(instKey, instanceId);
                var service = instKey.GetValue("Service") as string;
                device.NoDriver = string.IsNullOrWhiteSpace(service);

                QueryPresence(instanceId, out var present, out var hasProblem, out var problem);
                device.Present = present;
                device.HasProblem = hasProblem;
                device.ProblemCode = problem;

                var haystack = (device.Name + " " + hardwareId).ToLowerInvariant();
                foreach (var kw in SuspectKeywords)
                {
                    if (haystack.Contains(kw)) { device.Suspect = true; break; }
                }

                result.Devices.Add(device);
            }
        }

        // подозрительные и работающие — вперёд
        result.Devices.Sort((a, b) =>
        {
            if (a.Suspect != b.Suspect) return a.Suspect ? -1 : 1;
            if (a.Present != b.Present) return a.Present ? -1 : 1;
            return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
        });

        return result;
    }

    private static string ExtractVendorDevice(string hardwareId)
    {
        // VEN_10DE&DEV_2484&SUBSYS_...&REV_A1
        var ven = ""; var dev = "";
        foreach (var part in hardwareId.Split('&'))
        {
            if (part.StartsWith("VEN_", StringComparison.OrdinalIgnoreCase)) ven = part;
            else if (part.StartsWith("DEV_", StringComparison.OrdinalIgnoreCase)) dev = part;
        }
        return ven.Length > 0 || dev.Length > 0 ? $"{ven}&{dev}".Trim('&') : hardwareId;
    }

    private static string ResolveName(RegistryKey instKey, string instanceId)
    {
        // 1) реестр: FriendlyName (без косвенных строк)
        if (instKey.GetValue("FriendlyName") is string fn &&
            !string.IsNullOrWhiteSpace(fn) && !fn.StartsWith("@"))
            return fn;

        // 2) cfgmgr32: разрешённое имя устройства
        var viaCm = QueryName(instanceId);
        if (!string.IsNullOrWhiteSpace(viaCm) && !viaCm.StartsWith("@"))
            return viaCm!;

        // 3) реестр: DeviceDesc вида "@inf,%id%;Name" — берём текст после последней ';'
        if (instKey.GetValue("DeviceDesc") is string dd)
        {
            var idx = dd.LastIndexOf(';');
            if (idx >= 0 && idx + 1 < dd.Length) return dd[(idx + 1)..];
            return dd;
        }

        return viaCm ?? instanceId;
    }

    // ==================== cfgmgr32 ====================

    [StructLayout(LayoutKind.Sequential)]
    private struct DevPropKey
    {
        public Guid FmtId;
        public uint Pid;
    }

    private static readonly DevPropKey DevPropName = new()
    {
        FmtId = new Guid("b725f130-1ef2-44f3-8393-5fc3d5f4f5e8"),
        Pid = 10
    };

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    private static extern int CM_Locate_DevNodeW(out uint devInst, string deviceId, uint flags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    private static extern int CM_Get_DevNode_PropertyW(uint devInst, ref DevPropKey key,
        out uint propertyType, byte[] buffer, ref uint bufferSize, uint flags);

    [DllImport("cfgmgr32.dll")]
    private static extern int CM_Get_DevNode_Status(out uint status, out uint problemNumber, uint devInst, uint flags);

    private const int CrSuccess = 0;
    private const uint DnHasProblem = 0x00000400;

    private static string? QueryName(string instanceId)
    {
        try
        {
            if (CM_Locate_DevNodeW(out var devInst, instanceId, 0) != CrSuccess) return null;

            var buffer = new byte[1024];
            var size = (uint)buffer.Length;
            var key = DevPropName;
            if (CM_Get_DevNode_PropertyW(devInst, ref key, out var type, buffer, ref size, 0) != CrSuccess)
                return null;

            // DEVPROP_TYPE_STRING = 0x0012 (18)
            if (type != 18) return null;
            var s = System.Text.Encoding.Unicode.GetString(buffer, 0, (int)Math.Min(size, (uint)buffer.Length));
            var nul = s.IndexOf('\0');
            if (nul >= 0) s = s[..nul];
            return s.Trim().Length == 0 ? null : s.Trim();
        }
        catch
        {
            return null;
        }
    }

    private static void QueryPresence(string instanceId, out bool present, out bool hasProblem, out uint problem)
    {
        present = false;
        hasProblem = false;
        problem = 0;
        try
        {
            if (CM_Locate_DevNodeW(out var devInst, instanceId, 0) != CrSuccess) return;
            present = true;
            if (CM_Get_DevNode_Status(out var status, out var problemNumber, devInst, 0) == CrSuccess)
            {
                hasProblem = (status & DnHasProblem) != 0;
                problem = problemNumber;
            }
        }
        catch
        {
            // cfgmgr32 недоступен — считаем устройство неизвестным
        }
    }
}
