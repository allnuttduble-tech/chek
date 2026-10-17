// ==================== liccli — консольный тест лицензионного клиента ====================
// Прогоняет те же вызовы, что и лоадер (Licensing/license_core.h), без GUI —
// для автоматической проверки связки с панелью.
//
// Сборка (Developer Command Prompt):
//   cl /nologo /std:c++17 /EHsc /DUNICODE /D_UNICODE tools\liccli.cpp /Fe:tools\liccli.exe
//
// Использование:
//   liccli activate SENT-XXXXX-XXXXX-XXXXX [serverUrl]  — активировать ключ
//   liccli validate [serverUrl]                          — проверить сохранённую сессию
//   liccli reset                                         — удалить сохранённую сессию
//
// Если serverUrl не задан, берётся sentinel.config.json рядом с liccli.exe.

#include <windows.h>
#include <iostream>
#include <string>
#include "../Licensing/license_core.h"

int wmain(int argc, wchar_t** argv)
{
    if (argc >= 2 && (std::wcscmp(argv[1], L"fp") == 0))
    {
        const auto fp = sentinel_lic::MachineFingerprint();
        const auto url = sentinel_lic::ServerUrl();
        std::cout << "fingerprint: '" << fp << "' len=" << fp.size() << "\n";
        std::wcout << L"server url: '" << url << L"'\n";
        return fp.empty() ? 1 : 0;
    }

    if (argc >= 2 && (std::wcscmp(argv[1], L"reset") == 0))
    {
        sentinel_lic::ClearSession();
        std::cout << "session cleared\n";
        return 0;
    }

    if (argc >= 2 && (std::wcscmp(argv[1], L"activate") == 0))
    {
        if (argc < 3) { std::cout << "usage: liccli activate KEY [serverUrl]\n"; return 2; }
        if (argc >= 4) SetEnvironmentVariableW(L"SENTINEL_SERVER_URL", argv[3]);

        const auto norm = sentinel_lic::NormalizeKey(argv[2]);
        if (!sentinel_lic::LooksLikeKey(norm))
        {
            std::cout << "bad key format (expected SENT-XXXXX-XXXXX-XXXXX)\n";
            return 2;
        }

        auto r = sentinel_lic::Activate(norm, sentinel_lic::MachineFingerprint());
        std::cout << "activate: ok=" << (r.ok ? 1 : 0) << " reason=" << r.reason << "\n";
        if (r.ok)
        {
            sentinel_lic::SaveSession(r.ticket, r.expiresAt, sentinel_lic::MachineFingerprint());
            std::cout << "session saved, expiresAt=" << r.expiresAt << "\n";
        }
        return r.ok ? 0 : 1;
    }

    if (argc >= 2 && (std::wcscmp(argv[1], L"validate") == 0))
    {
        if (argc >= 3) SetEnvironmentVariableW(L"SENTINEL_SERVER_URL", argv[2]);

        sentinel_lic::StoredSession ses;
        if (!sentinel_lic::LoadSession(ses))
        {
            std::cout << "validate: no local session\n";
            return 1;
        }
        auto r = sentinel_lic::Validate(ses.token, sentinel_lic::MachineFingerprint());
        std::cout << "validate: ok=" << (r.ok ? 1 : 0) << " reason=" << r.reason
                  << " expiresAt=" << r.expiresAt << "\n";
        return r.ok ? 0 : 1;
    }

    std::cout << "usage: liccli activate KEY [serverUrl] | validate [serverUrl] | reset\n";
    return 2;
}
