using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using DetectAcUI.Scanning;
using Microsoft.Win32;

namespace DetectAcUI.Licensing;

// ==================== Локальное хранилище сессии ====================
// %LOCALAPPDATA%\sentinel\session.dat: token, срок, отпечаток машины.
// Сессия выдаётся сервером на срок, выбранный модератором; состояние доступа
// остаётся на сервере — здесь только токен для проверки при запуске.

public sealed record StoredSession(string Token, DateTime ExpiresAt, string MachineFingerprint);

public static class LicenseStore
{
    private static string StorePath
        => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "sentinel", "session.dat");

    /// <summary>Прочитать сохранённую сессию (null — нет/истекла/чужая машина).</summary>
    public static StoredSession? LoadSession()
    {
        try
        {
            if (!File.Exists(StorePath)) return null;

            var lines = File.ReadAllLines(StorePath);
            if (lines.Length < 3) return null;

            var token = lines[0].Trim();
            var expiryUnix = long.Parse(lines[1].Trim(), CultureInfo.InvariantCulture);
            var fingerprint = lines[2].Trim();

            if (fingerprint != MachineFingerprint()) return null; // скопировали с другого ПК

            var expires = TimeUtils.FromUnixSeconds(expiryUnix);
            if (expires == null || expires.Value.ToUniversalTime() <= DateTime.UtcNow)
            {
                Clear();
                return null;
            }

            return new StoredSession(token, expires.Value, fingerprint);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Сохранить токен сессии с привязкой к машине.</summary>
    public static void SaveSession(string token, DateTime expiresAt, string fingerprint)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(StorePath)!);
        var expiryUnix = new DateTimeOffset(expiresAt.ToUniversalTime()).ToUnixTimeSeconds();
        File.WriteAllLines(StorePath, new[] { token, expiryUnix.ToString(CultureInfo.InvariantCulture), fingerprint });
    }

    /// <summary>Удалить сохранённую сессию.</summary>
    public static void Clear()
    {
        try { if (File.Exists(StorePath)) File.Delete(StorePath); } catch { }
    }

    /// <summary>Отпечаток машины: имя ПК + пользователь + MachineGuid реестра.</summary>
    public static string MachineFingerprint()
    {
        string machineGuid;
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var k = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            machineGuid = k?.GetValue("MachineGuid") as string ?? "no-guid";
        }
        catch
        {
            machineGuid = "no-guid";
        }

        var source = $"{Environment.MachineName}|{Environment.UserDomainName}\\{Environment.UserName}|{machineGuid}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(source));
        var sb = new StringBuilder(32);
        for (var i = 0; i < 16; i++)
            sb.Append(hash[i].ToString("x2", CultureInfo.InvariantCulture));
        return sb.ToString();
    }
}
