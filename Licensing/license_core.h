#pragma once
// ==================== sentinel: лицензионный клиент (C++) ====================
// Одноразовая активация ключа и проверка сессии на панели модератора.
// Используется main.cpp (лоадер) и tools/liccli.cpp (консольный тест).
//
//   Конфиг:  sentinel.config.json рядом с exe  { "ServerUrl": "http://host:port" }
//   Сессия:  %LOCALAPPDATA%\sentinel\session.dat — токен / срок / отпечаток ПК.
//            Состояние доступа хранится на сервере, локально только токен.
//
// Схема совпадает с C#-клиентом (Licensing/LicenseClient.cs, LicenseStore.cs):
//   POST /api/activate { key, machineId }   -> { ok, reason, ticket, expiresAt }
//   POST /api/validate { ticket, machineId } -> { ok, reason, expiresAt }

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <ctime>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace sentinel_lic {

struct LicResult
{
    bool ok = false;
    std::string reason;        // машинный код: OK / KEY_USED / KEY_INVALID / NETWORK ...
    std::wstring ticket;       // заполняется при активации
    long long expiresAt = 0;   // unix-секунды
};

// ASCII-строки (URL, токен, имя ПК): явное сужение без предупреждений
inline std::string NarrowAscii(const std::wstring& w)
{
    std::string s;
    s.reserve(w.size());
    for (wchar_t c : w) s += (char)(c & 0xFF);
    return s;
}

// ---------- конфиг ----------

inline std::wstring ExeDirectory()
{
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    return std::filesystem::path(path).parent_path().wstring();
}

// адрес панели: переменная окружения SENTINEL_SERVER_URL (приоритет)
// либо sentinel.config.json рядом с exe; пустая строка — адрес не задан
inline std::wstring ServerUrl()
{
    wchar_t env[512] = {};
    if (GetEnvironmentVariableW(L"SENTINEL_SERVER_URL", env, 512) && env[0])
        return env;

    std::ifstream f(std::filesystem::path(ExeDirectory()) / L"sentinel.config.json");
    if (!f) return L"";
    std::stringstream ss; ss << f.rdbuf();
    const std::string s = ss.str();

    const auto key = s.find("\"ServerUrl\"");
    if (key == std::string::npos) return L"";
    const auto colon = s.find(':', key);
    if (colon == std::string::npos) return L"";
    const auto q1 = s.find('"', colon);
    if (q1 == std::string::npos) return L"";
    const auto q2 = s.find('"', q1 + 1);
    if (q2 == std::string::npos) return L"";

    const std::string url = s.substr(q1 + 1, q2 - q1 - 1);
    return std::wstring(url.begin(), url.end()); // URL только ASCII — сужение безопасно
}

// ---------- отпечаток машины ----------

// первые 16 байт SHA-256 в hex; пустая строка при ошибке
inline std::string Sha256Hex16(const std::string& data)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    std::string hex;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0)
    {
        BCRYPT_HASH_HANDLE h = nullptr;
        // объект хэша создаётся от алгоритма: BCryptHashData принимает именно его
        if (BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) == 0)
        {
            BYTE hash[32] = {};
            if (BCryptHashData(h, (PUCHAR)data.data(), (ULONG)data.size(), 0) == 0 &&
                BCryptFinishHash(h, hash, sizeof(hash), 0) == 0)
            {
                static const char* digits = "0123456789abcdef";
                for (int i = 0; i < 16; i++)
                {
                    hex += digits[hash[i] >> 4];
                    hex += digits[hash[i] & 0x0F];
                }
            }
            BCryptDestroyHash(h);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return hex;
}

inline std::string MachineFingerprint()
{
    std::string guid = "no-guid";
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0,
                      KEY_READ | KEY_WOW64_64KEY, &k) == ERROR_SUCCESS)
    {
        wchar_t buf[128] = {};
        DWORD size = sizeof(buf), type = 0;
        if (RegQueryValueExW(k, L"MachineGuid", nullptr, &type, (LPBYTE)buf, &size) == ERROR_SUCCESS &&
            type == REG_SZ)
        {
            for (DWORD i = 0; i < size / sizeof(wchar_t) && buf[i]; i++) guid += (char)buf[i];
        }
        RegCloseKey(k);
    }

    wchar_t pc[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD pcLen = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(pc, &pcLen);

    char user[256] = {}; DWORD userLen = sizeof(user);
    GetUserNameA(user, &userLen);

    char domain[256] = {}; DWORD domLen = GetEnvironmentVariableA("USERDOMAIN", domain, sizeof(domain));

    std::string source = NarrowAscii(pc) + "|";
    if (domLen > 0 && domLen < sizeof(domain)) source.append(domain, domLen);
    source += "\\";
    source += user;
    source += "|";
    source += guid;

    return Sha256Hex16(source);
}

// ---------- хранилище сессии ----------

struct StoredSession
{
    std::wstring token;
    long long expiresAt = 0;     // unix-секунды UTC
    std::string fingerprint;
};

inline std::filesystem::path SessionPath()
{
    wchar_t buf[MAX_PATH] = {};
    std::wstring local = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH) ? buf : L".";
    return std::filesystem::path(local) / L"sentinel" / L"session.dat";
}

inline void ClearSession()
{
    std::error_code ec;
    std::filesystem::remove(SessionPath(), ec);
}

inline bool LoadSession(StoredSession& out)
{
    std::ifstream f(SessionPath());
    if (!f) return false;

    std::string token, expiry, fp;
    if (!std::getline(f, token) || !std::getline(f, expiry) || !std::getline(f, fp)) return false;

    auto trim = [](std::string s)
    {
        while (!s.empty() && isspace((unsigned char)s.front())) s.erase(s.begin());
        while (!s.empty() && isspace((unsigned char)s.back())) s.pop_back();
        return s;
    };
    token = trim(token); expiry = trim(expiry); fp = trim(fp);
    if (token.empty() || expiry.empty() || fp.empty()) return false;

    // сессия привязана к машине — с чужого ПК не принимается
    if (fp != MachineFingerprint()) return false;

    out.expiresAt = _atoi64(expiry.c_str());
    if (out.expiresAt <= (long long)time(nullptr))
    {
        ClearSession();
        return false;
    }

    out.token = std::wstring(token.begin(), token.end()); // токен — hex ASCII (сужение безопасно)
    out.fingerprint = fp;
    return true;
}

inline void SaveSession(const std::wstring& token, long long expiresAtUnix, const std::string& fingerprint)
{
    auto path = SessionPath();
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    std::ofstream f(path, std::ios::trunc);
    if (!f) return;
    f << NarrowAscii(token) << "\n"
      << expiresAtUnix << "\n"
      << fingerprint;
}

// ---------- мини-JSON (ответы панели — плоские объекты) ----------

struct JVal
{
    bool found = false;
    bool b = false;
    std::string str;
    long long num = 0;
};

inline JVal JsonGet(const std::string& s, const char* key)
{
    JVal v;
    const std::string pat = "\"" + std::string(key) + "\"";
    auto pos = s.find(pat);
    if (pos == std::string::npos) return v;
    pos = s.find(':', pos + pat.size());
    if (pos == std::string::npos) return v;
    pos++;
    while (pos < s.size() && isspace((unsigned char)s[pos])) pos++;
    if (pos >= s.size()) return v;

    const char c = s[pos];
    if (c == 't') { v.found = true; v.b = true; }
    else if (c == 'f') { v.found = true; v.b = false; }
    else if (c == '"')
    {
        const auto e = s.find('"', pos + 1);
        if (e == std::string::npos) return v;
        v.found = true;
        v.str = s.substr(pos + 1, e - pos - 1);
    }
    else if (c == '-' || (c >= '0' && c <= '9'))
    {
        v.found = true;
        v.num = _atoi64(s.c_str() + pos);
    }
    // 'n' (null) остаётся found=false
    return v;
}

// ---------- HTTP ----------

// POST JSON; возвращает false при любой сетевой проблеме (тело не пришло)
inline bool PostJson(const std::wstring& url, const std::string& body, std::string& response)
{
    URL_COMPONENTSW uc{};
    uc.dwStructSize = sizeof(uc);
    uc.dwSchemeLength = uc.dwHostNameLength = uc.dwUrlPathLength = uc.dwExtraInfoLength = (DWORD)-1;
    if (!WinHttpCrackUrl(url.c_str(), (DWORD)url.size(), 0, &uc)) return false;

    const std::wstring scheme(uc.lpszScheme, uc.dwSchemeLength);
    const std::wstring host(uc.lpszHostName, uc.dwHostNameLength);
    std::wstring path(uc.lpszUrlPath, uc.dwUrlPathLength);
    if (path.empty()) path = L"/";

    bool ok = false;
    HINTERNET ses = WinHttpOpen(L"sentinel-loader/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) return false;
    WinHttpSetTimeouts(ses, 8000, 8000, 8000, 8000);

    HINTERNET con = WinHttpConnect(ses, host.c_str(), uc.nPort, 0);
    HINTERNET req = con ? WinHttpOpenRequest(con, L"POST", path.c_str(), nullptr,
                                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             scheme == L"https" ? WINHTTP_FLAG_SECURE : 0)
                        : nullptr;
    if (req)
    {
        const std::wstring headers = L"Content-Type: application/json\r\n";
        if (WinHttpSendRequest(req, headers.c_str(), (DWORD)headers.size(),
                               (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0) &&
            WinHttpReceiveResponse(req, nullptr))
        {
            for (;;)
            {
                DWORD avail = 0;
                if (!WinHttpQueryDataAvailable(req, &avail) || avail == 0) break;
                std::vector<char> buf(avail);
                DWORD read = 0;
                if (!WinHttpReadData(req, buf.data(), avail, &read) || read == 0) break;
                response.append(buf.data(), read);
            }
            ok = true; // тело получено (даже при 4xx — там код причины)
        }
        WinHttpCloseHandle(req);
    }
    if (con) WinHttpCloseHandle(con);
    WinHttpCloseHandle(ses);
    return ok;
}

// ---------- формат ключа ----------

// «плотная» форма: без дефисов/пробелов, верхний регистр
inline std::string NormalizeKey(const std::wstring& input)
{
    std::string out;
    for (wchar_t ch : input)
    {
        if (ch == L'-' || ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n') continue;
        out += (char)towupper(ch);
    }
    return out;
}

inline bool LooksLikeKey(const std::string& normalized)
{
    return normalized.size() == 19
        && normalized.compare(0, 4, "SENT") == 0
        && std::all_of(normalized.begin() + 4, normalized.end(),
                       [](char c) { return isalnum((unsigned char)c) != 0; });
}

// ---------- вызовы API ----------

inline LicResult CallApi(const std::wstring& path, const std::string& body)
{
    LicResult r;
    const auto url = ServerUrl();
    if (url.empty())
    {
        r.reason = "NO_SERVER";
        return r;
    }

    std::string resp;
    if (!PostJson(url + path, body, resp))
    {
        r.reason = "NETWORK";
        return r;
    }

    const auto ok = JsonGet(resp, "ok");
    if (!ok.found)
    {
        r.reason = "PROTOCOL";
        return r;
    }

    r.ok = ok.b;
    if (auto v = JsonGet(resp, "reason"); v.found) r.reason = v.str;
    if (auto v = JsonGet(resp, "ticket"); v.found) r.ticket = std::wstring(v.str.begin(), v.str.end());
    if (auto v = JsonGet(resp, "expiresAt"); v.found) r.expiresAt = v.num;
    return r;
}

inline std::string MakeBody(const char* field, const std::string& value, const std::string& machine)
{
    return std::string("{\"") + field + "\":\"" + value + "\",\"machineId\":\"" + machine + "\"}";
}

// Одноразовая активация: сервер принимает ключ ровно один раз и
// привязывает сессию к machineId. normalizedKey — уже в «плотной» форме.
inline LicResult Activate(const std::string& normalizedKey, const std::string& machine)
{
    return CallApi(L"/api/activate", MakeBody("key", normalizedKey, machine));
}

// Проверка сохранённой сессии при запуске.
inline LicResult Validate(const std::wstring& sessionTicket, const std::string& machine)
{
    return CallApi(L"/api/validate", MakeBody("ticket", NarrowAscii(sessionTicket), machine));
}

} // namespace sentinel_lic
