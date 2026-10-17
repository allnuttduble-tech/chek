using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace DetectAcUI.Licensing;

// ==================== Клиент проверки доступа (онлайн) ====================
// Запросы к панели модератора: одноразовая активация ключа и проверка сессии.
// URL сервера читается из sentinel.config.json рядом с exe ("ServerUrl").

public sealed record LicenseCheckResult(bool Success, string Reason, DateTime? ExpiresAt, string? SessionTicket);

public static class LicenseClient
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(8) };

    public static string? ServerUrl { get; }

    static LicenseClient()
    {
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "sentinel.config.json");
            if (File.Exists(path))
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(path));
                ServerUrl = doc.RootElement.GetProperty("ServerUrl").GetString();
            }
        }
        catch
        {
            ServerUrl = null;
        }

        if (string.IsNullOrWhiteSpace(ServerUrl)) ServerUrl = null;
        else ServerUrl = ServerUrl.TrimEnd('/');
    }

    /// <summary>Нормализовать введённый ключ: без пробелов/дефисов, верхний регистр.</summary>
    public static string NormalizeKey(string input)
    {
        var sb = new StringBuilder(input.Length);
        foreach (var ch in input)
        {
            if (ch is '-' or ' ' or '\t' or '\r' or '\n' or '"') continue;
            sb.Append(char.ToUpperInvariant(ch));
        }
        return sb.ToString();
    }

    /// <summary>Быстрая проверка формата: SENT + 15 символов без разделителей
    /// (полная проверка — на сервере).</summary>
    public static bool LooksLikeKey(string normalized)
        => normalized.Length == 4 + 15
           && normalized.StartsWith("SENT", StringComparison.OrdinalIgnoreCase)
           && normalized[4..].All(char.IsLetterOrDigit);

    /// <summary>Одноразовая активация ключа (сервер привязывает сессию к ПК).</summary>
    public static Task<LicenseCheckResult> ActivateAsync(string key, string machineId)
        => Post("/api/activate", new { key, machineId });

    /// <summary>Проверка сохранённой сессии при запуске.</summary>
    public static Task<LicenseCheckResult> ValidateSessionAsync(string sessionTicket, string machineId)
        => Post("/api/validate", new { ticket = sessionTicket, machineId });

    private static async Task<LicenseCheckResult> Post(string path, object body)
    {
        if (ServerUrl == null)
            return new LicenseCheckResult(false, "NO_SERVER", null, null);

        try
        {
            var json = JsonSerializer.Serialize(body);
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var response = await Http.PostAsync(ServerUrl + path, content);
            var text = await response.Content.ReadAsStringAsync();

            using var doc = JsonDocument.Parse(text);
            var root = doc.RootElement;

            var ok = root.TryGetProperty("ok", out var okEl) && okEl.ValueKind == JsonValueKind.True;
            var reason = root.TryGetProperty("reason", out var reasonEl) ? reasonEl.GetString() ?? "" : "";
            DateTime? expires = null;
            if (root.TryGetProperty("expiresAt", out var expEl) && expEl.ValueKind == JsonValueKind.Number)
                expires = DateTimeOffset.FromUnixTimeSeconds(expEl.GetInt64()).UtcDateTime.ToLocalTime();
            var sessionTicket = root.TryGetProperty("ticket", out var ticketEl) && ticketEl.ValueKind == JsonValueKind.String
                ? ticketEl.GetString()
                : null;

            return new LicenseCheckResult(ok, reason, expires, sessionTicket);
        }
        catch (HttpRequestException)
        {
            return new LicenseCheckResult(false, "NETWORK", null, null);
        }
        catch (TaskCanceledException)
        {
            return new LicenseCheckResult(false, "NETWORK", null, null);
        }
        catch (JsonException)
        {
            return new LicenseCheckResult(false, "PROTOCOL", null, null);
        }
        catch (Exception)
        {
            return new LicenseCheckResult(false, "NETWORK", null, null);
        }
    }
}
