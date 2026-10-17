using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using Microsoft.Win32;

namespace DetectAcUI.Scanning;

// ==================== Сканер аккаунтов Steam ====================
// Источник: <Steam>\config\loginusers.vdf (все пользователи ПК) + реестр Steam.

public static class SteamScanner
{
    public sealed class SteamAccount
    {
        public string SteamId64 = "";
        public string AccountName = "";
        public string PersonaName = "";
        public DateTime? LastLogin;
        public bool MostRecent;
        public bool RememberPassword;
    }

    public sealed class SteamResult
    {
        public List<SteamAccount> Accounts { get; } = new();
        public string? SteamPath { get; set; }
        public string? AutoLoginUser { get; set; }

        public static SteamResult Empty() => new();
    }

    public static SteamResult Scan()
    {
        var result = new SteamResult();
        var steamPath = FindSteamPath();
        result.SteamPath = steamPath;
        if (steamPath == null) return result;

        result.AutoLoginUser = ReadAutoLoginUser();

        var vdf = Path.Combine(steamPath, "config", "loginusers.vdf");
        if (!File.Exists(vdf)) return result;

        try
        {
            var text = File.ReadAllText(vdf, Encoding.UTF8);
            foreach (var (steamId, props) in VdfParser.ParseUsers(text))
            {
                var acc = new SteamAccount
                {
                    SteamId64 = steamId,
                    AccountName = props.TryGetValue("AccountName", out var an) ? an : "",
                    PersonaName = props.TryGetValue("PersonaName", out var pn) ? pn : "",
                    MostRecent = props.TryGetValue("mostrecent", out var mr) && mr.Trim() == "1",
                    RememberPassword = props.TryGetValue("RememberPassword", out var rp) && rp.Trim() == "1"
                };
                if (props.TryGetValue("Timestamp", out var ts) &&
                    long.TryParse(ts.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var unix))
                    acc.LastLogin = TimeUtils.FromUnixSeconds(unix);

                if (acc.SteamId64.Length >= 17)
                    result.Accounts.Add(acc);
            }

            // последний логин — сверху, затем по SteamID
            result.Accounts.Sort((a, b) =>
            {
                var la = a.LastLogin ?? DateTime.MinValue;
                var lb = b.LastLogin ?? DateTime.MinValue;
                return lb.CompareTo(la);
            });
        }
        catch
        {
            // повреждённый/нечитаемый файл — вернём то, что успели
        }

        return result;
    }

    // Путь установки Steam: HKCU → HKLM (WOW6432Node) → Program Files (x86)
    private static string? FindSteamPath()
    {
        string? path = null;

        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam");
            path = k?.GetValue("SteamPath") as string;
        }
        catch { }

        if (string.IsNullOrWhiteSpace(path))
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Valve\Steam");
                path = k?.GetValue("InstallPath") as string;
            }
            catch { }
        }

        if (string.IsNullOrWhiteSpace(path))
        {
            var guess = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Steam");
            if (Directory.Exists(guess)) path = guess;
        }

        if (string.IsNullOrWhiteSpace(path)) return null;
        path = path.Replace('/', '\\');
        return Directory.Exists(path) ? path : null;
    }

    private static string? ReadAutoLoginUser()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam");
            var v = k?.GetValue("AutoLoginUser") as string;
            return string.IsNullOrWhiteSpace(v) ? null : v;
        }
        catch
        {
            return null;
        }
    }

    // ==================== Минимальный парсер Valve VDF ====================

    public static class VdfParser
    {
        // Ожидаем структуру: "users" { "7656119..." { "AccountName" "..." ... } ... }
        public static List<(string SteamId, Dictionary<string, string> Props)> ParseUsers(string text)
        {
            var list = new List<(string, Dictionary<string, string>)>();
            var tokens = Tokenize(text);

            var i = 0;
            // ищем корень "users"
            while (i < tokens.Count - 1)
            {
                if (tokens[i].Equals("users", StringComparison.OrdinalIgnoreCase) && tokens[i + 1] == "{")
                {
                    i += 2;
                    break;
                }
                i++;
            }

            while (i < tokens.Count)
            {
                // "steamid" { props }
                if (i + 1 < tokens.Count && tokens[i + 1] == "{" && tokens[i].StartsWith("7656119", StringComparison.Ordinal))
                {
                    var steamId = tokens[i];
                    i += 2;
                    var props = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    while (i + 1 < tokens.Count && tokens[i + 1] != "}") // до закрывающей скобки блока
                    {
                        if (tokens[i] == "{" || tokens[i] == "}") break;
                        props[tokens[i]] = tokens[i + 1];
                        i += 2;
                    }
                    list.Add((steamId, props));
                    // перематываем до конца этого блока
                    while (i < tokens.Count && tokens[i] != "}") i++;
                    i++; // '}'
                    continue;
                }
                i++;
            }

            return list;
        }

        private static List<string> Tokenize(string text)
        {
            var tokens = new List<string>();
            var sb = new StringBuilder();
            var inQuote = false;

            for (var i = 0; i < text.Length; i++)
            {
                var c = text[i];
                if (inQuote)
                {
                    if (c == '"')
                    {
                        tokens.Add(sb.ToString());
                        sb.Clear();
                        inQuote = false;
                    }
                    else if (c == '\\' && i + 1 < text.Length)
                    {
                        sb.Append(text[++i]);
                    }
                    else
                    {
                        sb.Append(c);
                    }
                    continue;
                }

                if (c == '"')
                {
                    inQuote = true;
                    continue;
                }

                if (c == '{' || c == '}')
                {
                    tokens.Add(c.ToString());
                    continue;
                }

                if (c == '/' && i + 1 < text.Length && text[i + 1] == '/')
                {
                    while (i < text.Length && text[i] != '\n') i++;
                    continue;
                }

                if (char.IsWhiteSpace(c))
                {
                    if (sb.Length > 0)
                    {
                        tokens.Add(sb.ToString());
                        sb.Clear();
                    }
                    continue;
                }

                sb.Append(c);
            }

            if (sb.Length > 0) tokens.Add(sb.ToString());
            return tokens;
        }
    }
}
