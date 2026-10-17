using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace DetectAcUI.Scanning;

// ==================== Сканер игрового/периферийного софта ====================
// Ключи Uninstall (HKLM/HKCU, 32/64) на предмет Logitech G HUB/LGS, Razer Synapse,
// iCUE, SteelSeries, Bloody, A4Tech и т.д. + найденные папки макросов/конфигов
// (кнопки «открыть папку») + флаг «запущен сейчас» по процессам.

public static class GamingSoftwareScanner
{
    public sealed class GamingProduct
    {
        public string Name = "";
        public string Vendor = "";
        public string Version = "";
        public string InstallLocation = "";
        public bool Running;
        public List<RowAction> MacroFolders { get; } = new();
    }

    public sealed class GamingResult
    {
        public List<GamingProduct> Products { get; } = new();

        public static GamingResult Empty() => new();
    }

    private sealed record VendorRule(string Vendor, Regex Pattern, string[] MacroDirs);

    private static readonly VendorRule[] Rules =
    {
        new("Logitech", new Regex(@"logitech g ?hub|lghub|logitech gaming software", RegexOptions.IgnoreCase),
            new[] { @"%LOCALAPPDATA%\LGHUB", @"%APPDATA%\Logitech\Logitech Gaming Software", @"%PROGRAMDATA%\LGHUB" }),
        new("Razer", new Regex(@"razer synapse", RegexOptions.IgnoreCase),
            new[] { @"%PROGRAMDATA%\Razer", @"%LOCALAPPDATA%\Razer", @"%APPDATA%\Razer" }),
        new("Corsair", new Regex(@"icue|corsair (utility engine|link)", RegexOptions.IgnoreCase),
            new[] { @"%LOCALAPPDATA%\Corsair", @"%PROGRAMDATA%\Corsair" }),
        new("SteelSeries", new Regex(@"steelseries (gg|engine)", RegexOptions.IgnoreCase),
            new[] { @"%PROGRAMDATA%\SteelSeries", @"%APPDATA%\SteelSeries" }),
        new("ROCCAT", new Regex(@"roccat", RegexOptions.IgnoreCase),
            new[] { @"%PROGRAMDATA%\ROCCAT", @"%LOCALAPPDATA%\ROCCAT" }),
        new("HyperX", new Regex(@"ngenuity", RegexOptions.IgnoreCase),
            new[] { @"%PROGRAMDATA%\HyperX", @"%LOCALAPPDATA%\HyperX" }),
        new("Bloody / A4Tech", new Regex(@"bloody|a4tech", RegexOptions.IgnoreCase),
            new[] { @"%PROGRAMDATA%\Bloody", @"%PROGRAMDATA%\A4Tech" }),
        new("A4Tech X7 / Oscar", new Regex(@"oscar editor|x7 oscar", RegexOptions.IgnoreCase),
            new[] { @"%PROGRAMDATA%\Oscar Editor", @"%PROGRAMFILES(X86)%\Oscar Editor" }),
        new("Marvo", new Regex(@"marvo", RegexOptions.IgnoreCase),
            new[] { @"%PROGRAMDATA%\Marvo" }),
        new("Redragon", new Regex(@"redragon", RegexOptions.IgnoreCase),
            new[] { @"%PROGRAMDATA%\Redragon" }),
        new("Glorious", new Regex(@"glorious core", RegexOptions.IgnoreCase),
            new[] { @"%LOCALAPPDATA%\Glorious Core" }),
        new("ASUS", new Regex(@"armoury ?crate", RegexOptions.IgnoreCase),
            new[] { @"%PROGRAMDATA%\ASUS" })
    };

    private static readonly (string Vendor, string[] ProcessNames)[] RunningHints =
    {
        ("Logitech", new[] { "lghub", "lghub_agent", "lghub_system_tray", "lgs" }),
        ("Razer", new[] { "rzsynapse", "razercentral", "razersynapse" }),
        ("Corsair", new[] { "icue", "corsairservice" }),
        ("SteelSeries", new[] { "steelseriesgg", "steelseriesengine", "ssgg" }),
        ("ROCCAT", new[] { "roccat" }),
        ("HyperX", new[] { "ngenuity" }),
        ("Bloody / A4Tech", new[] { "bloody", "a4tech" }),
        ("ASUS", new[] { "armourycrate", "lightingservice" })
    };

    public static GamingResult Scan()
    {
        var result = new GamingResult();

        // 1) установленный софт из Uninstall-ключей
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (root, view) in new[]
                 {
                     (RegistryHive.LocalMachine, RegistryView.Registry64),
                     (RegistryHive.LocalMachine, RegistryView.Registry32),
                     (RegistryHive.CurrentUser, RegistryView.Default)
                 })
        {
            using var baseKey = RegistryKey.OpenBaseKey(root, view);
            using var uninstall = baseKey.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall");
            if (uninstall == null) continue;

            foreach (var keyName in uninstall.GetSubKeyNames())
            {
                using var key = uninstall.OpenSubKey(keyName);
                if (key == null) continue;
                var displayName = key.GetValue("DisplayName") as string;
                if (string.IsNullOrWhiteSpace(displayName)) continue;

                VendorRule? rule = null;
                foreach (var r in Rules)
                {
                    if (r.Pattern.IsMatch(displayName)) { rule = r; break; }
                }
                if (rule == null) continue;

                var dedupe = rule.Vendor + "|" + displayName.Trim();
                if (!seen.Add(dedupe)) continue;

                var product = new GamingProduct
                {
                    Name = displayName.Trim(),
                    Vendor = rule.Vendor,
                    Version = (key.GetValue("DisplayVersion") as string ?? "").Trim(),
                    InstallLocation = (key.GetValue("InstallLocation") as string ?? "").Trim()
                };

                // папки макросов/конфигов вендора, которые реально существуют
                foreach (var raw in rule.MacroDirs)
                {
                    var expanded = Environment.ExpandEnvironmentVariables(raw);
                    if (Directory.Exists(expanded))
                        product.MacroFolders.Add(new RowAction("Папка", expanded));
                }
                if (product.InstallLocation.Length > 2 && Directory.Exists(product.InstallLocation))
                    product.MacroFolders.Add(new RowAction("Папка", product.InstallLocation));

                result.Products.Add(product);
            }
        }

        // 2) папки/конфиги вендоров, установленных без записи в Uninstall
        foreach (var rule in Rules)
        {
            foreach (var raw in rule.MacroDirs)
            {
                var expanded = Environment.ExpandEnvironmentVariables(raw);
                if (!Directory.Exists(expanded)) continue;
                var already = result.Products.Exists(p => p.Vendor == rule.Vendor);
                if (already) break;

                var product = new GamingProduct
                {
                    Name = rule.Vendor,
                    Vendor = rule.Vendor,
                    Version = "",
                };
                foreach (var raw2 in rule.MacroDirs)
                {
                    var expanded2 = Environment.ExpandEnvironmentVariables(raw2);
                    if (Directory.Exists(expanded2))
                        product.MacroFolders.Add(new RowAction("Папка", expanded2));
                }
                result.Products.Add(product);
                break;
            }
        }

        // 3) процессы: «запущен сейчас»
        HashSet<string> running;
        try
        {
            running = new HashSet<string>(
                Process.GetProcesses().Select(p => p.ProcessName.ToLowerInvariant()),
                StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            running = new HashSet<string>();
        }

        foreach (var product in result.Products)
        {
            foreach (var (vendor, names) in RunningHints)
            {
                if (vendor != product.Vendor) continue;
                foreach (var procName in names)
                {
                    foreach (var actual in running)
                    {
                        if (actual.Contains(procName))
                        {
                            product.Running = true;
                            break;
                        }
                    }
                    if (product.Running) break;
                }
                if (product.Running) break;
            }
        }

        result.Products.Sort((a, b) =>
        {
            if (a.Running != b.Running) return a.Running ? -1 : 1;
            return string.Compare(a.Vendor, b.Vendor, StringComparison.OrdinalIgnoreCase);
        });

        return result;
    }
}
