using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

// ==================== sentinel-panel: панель модератора ====================
//
// Модератор в браузере заходит на панель (код доступа задаётся в appsettings.json →
// Panel:AdminCode, либо переменной окружения SENTINEL_PANEL_CODE),
// выпускает одноразовый ключ с нужным сроком и передаёт его пользователю.
//
// Жизненный цикл ключа (состояние — только на сервере):
//   выдан → (не использован, живёт до ExpiresAt)
//         → активирован пользователем: привязка к machineId, создаётся сессия
//           на DurationHours; ключ помечается использованным НАВСЕГДА
//         → сессия истекла → запись удаляется; нужен новый ключ.
//
// API для лаунчера:
//   POST /api/activate  { key, machineId }        → одноразовая активация
//   POST /api/validate  { ticket, machineId }     → проверка сессии при запуске
//
// Админка (cookie после /login или заголовок X-Panel-Code):
//   POST /admin/keys          { hours, count }    → выпустить ключи
//   GET  /admin/keys                              → список
//   POST /admin/keys/revoke   { id }

var builder = WebApplication.CreateBuilder(args);
var port = int.TryParse(builder.Configuration["Panel:Port"], out var p) ? p : 5177;
// пустое значение в конфиге считается «не задано» — тогда берётся переменная окружения
var adminCode = builder.Configuration["Panel:AdminCode"];
if (string.IsNullOrWhiteSpace(adminCode))
    adminCode = Environment.GetEnvironmentVariable("SENTINEL_PANEL_CODE");

if (string.IsNullOrWhiteSpace(adminCode))
{
    Console.Error.WriteLine("Не задан код доступа панели: заполните Panel:AdminCode в appsettings.json " +
                            "или переменную окружения SENTINEL_PANEL_CODE.");
    return 1;
}

builder.WebHost.UseUrls($"http://0.0.0.0:{port}");
builder.Logging.SetMinimumLevel(LogLevel.Warning);

var app = builder.Build();

var store = new KeyStore(Path.Combine(AppContext.BaseDirectory, "data"));
var adminSessions = new ConcurrentDictionary<string, DateTime>();

const string CookieName = "sentinel_panel";

// ---------- вспомогательные ----------

bool IsAdmin(HttpContext ctx)
{
    if (ctx.Request.Headers.TryGetValue("X-Panel-Code", out var header))
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(header.ToString()), Encoding.UTF8.GetBytes(adminCode));

    if (ctx.Request.Cookies.TryGetValue(CookieName, out var ticket) && ticket != null &&
        adminSessions.TryGetValue(ticket, out var until) && until > DateTime.UtcNow)
        return true;

    return false;
}

IResult Json(object value, int status = 200) => Results.Json(value, statusCode: status);

// ---------- авторизация панели ----------

app.MapPost("/login", (LoginRequest req, HttpContext ctx) =>
{
    var provided = req.Pass ?? "";
    var ok = CryptographicOperations.FixedTimeEquals(
        Encoding.UTF8.GetBytes(provided), Encoding.UTF8.GetBytes(adminCode));
    if (!ok) return Json(new { ok = false, error = "Неверный код доступа" }, 401);

    var sessionTicket = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    adminSessions[sessionTicket] = DateTime.UtcNow.AddHours(12);
    ctx.Response.Cookies.Append(CookieName, sessionTicket, new CookieOptions
    {
        HttpOnly = true,
        SameSite = SameSiteMode.Strict,
        Expires = DateTimeOffset.UtcNow.AddHours(12)
    });
    return Json(new { ok = true });
});

// ---------- админка ----------

app.MapPost("/admin/keys", (CreateKeysRequest req, HttpContext ctx) =>
{
    if (!IsAdmin(ctx)) return Json(new { ok = false, error = "unauthorized" }, 401);

    var hours = Math.Clamp(req.Hours <= 0 ? 24 : req.Hours, 1, 24 * 365);
    var count = Math.Clamp(req.Count <= 0 ? 1 : req.Count, 1, 50);
    var keys = store.Create(hours, count);
    return Json(new { ok = true, keys = keys.Select(k => new { k.Id, k.Key, k.ExpiresAt, k.DurationHours }) });
});

app.MapGet("/admin/keys", (HttpContext ctx) =>
{
    if (!IsAdmin(ctx)) return Json(new { ok = false, error = "unauthorized" }, 401);
    return Json(new { ok = true, keys = store.List() });
});

app.MapPost("/admin/keys/revoke", (RevokeRequest req, HttpContext ctx) =>
{
    if (!IsAdmin(ctx)) return Json(new { ok = false, error = "unauthorized" }, 401);
    var ok = store.Revoke(req.Id);
    return Json(new { ok, error = ok ? null : "not found" }, ok ? 200 : 404);
});

// ---------- API лаунчера ----------

app.MapPost("/api/activate", (ActivateRequest req, HttpContext ctx) =>
{
    if (string.IsNullOrWhiteSpace(req.Key) || string.IsNullOrWhiteSpace(req.MachineId))
        return Json(new { ok = false, reason = "BAD_REQUEST" }, 400);

    var result = store.Activate(req.Key!, req.MachineId!);
    return Json(new { ok = result.Ok, reason = result.Reason, ticket = result.SessionTicket, expiresAt = result.ExpiresAt },
        result.Ok ? 200 : 401);
});

app.MapPost("/api/validate", (ValidateRequest req, HttpContext ctx) =>
{
    if (string.IsNullOrWhiteSpace(req.SessionTicket) || string.IsNullOrWhiteSpace(req.MachineId))
        return Json(new { ok = false, reason = "BAD_REQUEST" }, 400);

    var result = store.Validate(req.SessionTicket!, req.MachineId!);
    return Json(new { ok = result.Ok, reason = result.Reason, expiresAt = result.ExpiresAt },
        result.Ok ? 200 : 401);
});

app.MapGet("/health", () => Results.Text("ok"));

// ---------- страница панели ----------

app.MapGet("/", () => Results.Content(SentinelPanel.AdminPage.Html, "text/html; charset=utf-8"));

// ---------- фоновая чистка истёкших ----------

var cleanupTimer = new Timer(_ => store.CleanupExpired(), null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(60));

Console.WriteLine($"sentinel-panel слушает http://0.0.0.0:{port}  (ключи: {store.DataDirectory})");
Console.WriteLine("Код доступа панели задаётся в appsettings.json → Panel:AdminCode");
app.Run();
return 0;

// ==================== модель и хранилище ====================

internal sealed class KeyRecord
{
    public string Id { get; set; } = "";
    public string Key { get; set; } = "";
    public long CreatedAt { get; set; }
    public long ExpiresAt { get; set; }        // дедлайн активации ключа
    public int DurationHours { get; set; }     // длительность сессии после активации
    public long? UsedAt { get; set; }
    public string? MachineId { get; set; }
    public string? SessionTicket { get; set; }
    public long? SessionExpiresAt { get; set; }
    public bool Revoked { get; set; }

    public string Status => Revoked ? "revoked"
        : UsedAt != null && SessionExpiresAt > Now() ? "active"
        : UsedAt != null ? "expired"
        : ExpiresAt < Now() ? "expired"
        : "unused";

    public static long Now() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();
}

internal sealed class KeyStore
{
    private readonly object _lock = new();
    private readonly string _file;
    private List<KeyRecord> _records;

    public string DataDirectory { get; }

    public KeyStore(string dataDir)
    {
        DataDirectory = dataDir;
        Directory.CreateDirectory(dataDir);
        _file = Path.Combine(dataDir, "keys.json");
        _records = Load();
    }

    private List<KeyRecord> Load()
    {
        try
        {
            return File.Exists(_file)
                ? JsonSerializer.Deserialize<List<KeyRecord>>(File.ReadAllText(_file)) ?? new()
                : new List<KeyRecord>();
        }
        catch
        {
            return new List<KeyRecord>();
        }
    }

    private void Save()
    {
        var tmp = _file + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(_records, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(tmp, _file, overwrite: true);
    }

    private const string Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    // «плотная» форма ключа: без дефисов/пробелов, в верхнем регистре
    private static string KeyNorm(string k)
        => k.Trim().Replace("-", "").Replace(" ", "").ToUpperInvariant();

    private static string NewKey()
    {
        var sb = new StringBuilder("SENT-");
        for (var group = 0; group < 3; group++)
        {
            if (group > 0) sb.Append('-');
            for (var i = 0; i < 5; i++)
                sb.Append(Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)]);
        }
        return sb.ToString();
    }

    public List<KeyRecord> Create(int hours, int count)
    {
        lock (_lock)
        {
            CleanupExpiredLocked();
            var created = new List<KeyRecord>();
            var now = KeyRecord.Now();

            for (var i = 0; i < count; i++)
            {
                string key;
                do { key = NewKey(); } while (_records.Any(r => r.Key == key));

                var record = new KeyRecord
                {
                    Id = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant(),
                    Key = key,
                    CreatedAt = now,
                    ExpiresAt = now + (long)hours * 3600, // использовать ключ нужно успеть за этот срок
                    DurationHours = hours
                };
                _records.Add(record);
                created.Add(record);
            }

            Save();
            return created;
        }
    }

    public bool Revoke(string id)
    {
        lock (_lock)
        {
            var record = _records.FirstOrDefault(r => r.Id == id);
            if (record == null) return false;
            record.Revoked = true;
            Save();
            return true;
        }
    }

    public List<object> List()
    {
        lock (_lock)
        {
            CleanupExpiredLocked();
            return _records
                .OrderByDescending(r => r.CreatedAt)
                .Select(r => (object)new
                {
                    r.Id,
                    r.Key,
                    r.CreatedAt,
                    r.ExpiresAt,
                    r.DurationHours,
                    r.UsedAt,
                    r.MachineId,
                    r.SessionExpiresAt,
                    r.Revoked,
                    status = r.Status
                })
                .ToList();
        }
    }

    public (bool Ok, string Reason, string? SessionTicket, long? ExpiresAt) Activate(string key, string machineId)
    {
        lock (_lock)
        {
            CleanupExpiredLocked();
            // клиент может прислать ключ как с дефисами, так и без — сравниваем «плотно»
            var normalized = KeyNorm(key);

            var record = _records.FirstOrDefault(r => KeyNorm(r.Key) == normalized);
            if (record == null) return (false, "KEY_INVALID", null, null);
            if (record.Revoked) return (false, "KEY_REVOKED", null, null);
            if (record.UsedAt != null) return (false, "KEY_USED", null, null);
            if (record.ExpiresAt < KeyRecord.Now()) return (false, "KEY_EXPIRED", null, null);

            var now = KeyRecord.Now();
            record.UsedAt = now;
            record.MachineId = machineId;
            record.SessionTicket = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            record.SessionExpiresAt = now + (long)record.DurationHours * 3600;
            Save();

            return (true, "OK", record.SessionTicket, record.SessionExpiresAt);
        }
    }

    public (bool Ok, string Reason, long? ExpiresAt) Validate(string sessionTicket, string machineId)
    {
        lock (_lock)
        {
            CleanupExpiredLocked();

            var record = _records.FirstOrDefault(r => r.SessionTicket == sessionTicket);
            if (record == null) return (false, "SESSION_UNKNOWN", null);
            if (record.Revoked) return (false, "SESSION_REVOKED", null);
            if (!string.Equals(record.MachineId, machineId, StringComparison.Ordinal))
                return (false, "MACHINE_MISMATCH", null);
            if (record.SessionExpiresAt == null || record.SessionExpiresAt < KeyRecord.Now())
                return (false, "SESSION_EXPIRED", null);

            return (true, "OK", record.SessionExpiresAt);
        }
    }

    // после истечения записи удаляются — доступ без нового ключа невозможен
    private void CleanupExpiredLocked()
    {
        var now = KeyRecord.Now();
        var removed = _records.RemoveAll(r =>
            (r.UsedAt != null && r.SessionExpiresAt < now) ||   // сессия истекла
            (r.UsedAt == null && r.ExpiresAt < now));           // ключ так и не активировали

        if (removed > 0) Save();
    }

    public void CleanupExpired()
    {
        lock (_lock) CleanupExpiredLocked();
    }
}

// ==================== DTO ====================

internal sealed record LoginRequest([property: JsonPropertyName("pass")] string? Pass);
internal sealed record CreateKeysRequest(int Hours, int Count);
internal sealed record RevokeRequest(string Id);
internal sealed record ActivateRequest(
    [property: JsonPropertyName("key")] string? Key,
    [property: JsonPropertyName("machineId")] string? MachineId);
internal sealed record ValidateRequest(
    [property: JsonPropertyName("ticket")] string? SessionTicket,
    [property: JsonPropertyName("machineId")] string? MachineId);
