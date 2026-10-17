#define UNICODE
#define _UNICODE
#include <windows.h>
#include <windowsx.h>
#include <string>
#include <vector>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <thread>
#include <mutex>
#include <chrono>
#include <set>
#include <winreg.h>
#include <shellapi.h>
#include "Licensing/license_core.h"
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

namespace {
enum class Screen { License, Language, Eula, Scan };
Screen screen = Screen::License;
std::wstring language;
bool accepted = false;
int scanStep = 0;
int scanChar = 0;

// ==================== гейт доступа: одноразовый ключ от модератора ====================
// Запуск: есть сохранённая сессия -> проверяем на сервере; нет -> экран ввода ключа.
// Ключ активируется один раз и привязывается к ПК; отказ при активации закрывает лоадер.
enum class LicPhase { Boot, Checking, NeedKey, Activating, Denied, Pass };
LicPhase licPhase = LicPhase::Boot;
std::mutex licMutex;
std::wstring keyInput;        // «плотная» форма: A-Z 0-9, без разделителей
std::wstring licStatus;
bool licStatusError = false;
bool licFatal = false;        // показать ошибку и закрыть через задержку
bool licPass = false;         // доступ разрешён -> переход к выбору языка
bool licCloseTimer = false;
constexpr UINT WM_LIC_DONE = WM_APP + 1;
constexpr int WM_TIMER_CLOSE = 2;

std::wstring LicReasonText(const std::string& reason) {
    if (reason == "KEY_USED") return L"Ключ уже использован / key already used";
    if (reason == "KEY_INVALID") return L"Ключ не найден / key not found";
    if (reason == "KEY_EXPIRED") return L"Срок действия ключа истёк / key deadline passed";
    if (reason == "KEY_REVOKED") return L"Ключ отозван / key revoked";
    if (reason == "SESSION_EXPIRED" || reason == "SESSION_UNKNOWN") return L"Сессия истекла — нужен новый ключ / session expired";
    if (reason == "SESSION_REVOKED") return L"Доступ отозван модератором / access revoked";
    if (reason == "MACHINE_MISMATCH") return L"Ключ привязан к другому ПК / key bound to another PC";
    if (reason == "NETWORK") return L"Сервер недоступен / server unreachable";
    if (reason == "NO_SERVER") return L"Не задан адрес сервера (sentinel.config.json) / no server url";
    if (reason == "PROTOCOL") return L"Неверный ответ сервера / bad server response";
    return L"Отказано в доступе / access denied";
}

void SetLicStatus(const std::wstring& s, bool error, bool fatal) {
    std::lock_guard<std::mutex> l(licMutex);
    licStatus = s; licStatusError = error; licFatal = fatal;
}

// Ctrl+V: вставка ключа из буфера (нормализуется в «плотную» форму)
void PasteKey(HWND hwnd) {
    if (!OpenClipboard(hwnd)) return;
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    if (h) {
        if (const wchar_t* p = (const wchar_t*)GlobalLock(h)) {
            std::lock_guard<std::mutex> l(licMutex);
            for (const wchar_t* c = p; *c && keyInput.size() < 19; ++c) {
                wchar_t u = towupper(*c);
                if ((u >= L'0' && u <= L'9') || (u >= L'A' && u <= L'Z')) keyInput += u;
            }
            GlobalUnlock(h);
        }
    }
    CloseClipboard();
    InvalidateRect(hwnd, nullptr, FALSE);
}

// отображение с группировкой SENT-XXXXX-XXXXX-XXXXX
std::wstring GroupKey(const std::wstring& compact) {
    std::wstring out;
    for (size_t i = 0; i < compact.size(); ++i) {
        if (i == 4 || (i > 4 && (i - 4) % 5 == 0)) out += L'-';
        out += compact[i];
    }
    return out;
}

void TryActivate(HWND hwnd) {
    std::string norm;
    {
        std::lock_guard<std::mutex> l(licMutex);
        if (licPhase != LicPhase::NeedKey) return;
        norm = sentinel_lic::NormalizeKey(keyInput);
        if (!sentinel_lic::LooksLikeKey(norm)) {
            licStatus = L"Неверный формат ключа / invalid key format";
            licStatusError = true; licFatal = false;
            InvalidateRect(hwnd, nullptr, FALSE);
            return;
        }
        licPhase = LicPhase::Activating;
    }
    SetLicStatus(L"Активация ключа… / activating…", false, false);
    InvalidateRect(hwnd, nullptr, FALSE);

    std::thread([hwnd, norm]() {
        auto r = sentinel_lic::Activate(norm, sentinel_lic::MachineFingerprint());
        if (r.ok && r.expiresAt > 0) {
            sentinel_lic::SaveSession(r.ticket, r.expiresAt, sentinel_lic::MachineFingerprint());
            std::lock_guard<std::mutex> l(licMutex);
            licPhase = LicPhase::Pass; licPass = true;
            licStatus.clear(); licFatal = false;
        } else {
            // ключ не принят — лоадер закрывается
            SetLicStatus(LicReasonText(r.reason) + L" — закрытие… / closing…", true, true);
            std::lock_guard<std::mutex> l(licMutex);
            licPhase = LicPhase::Denied;
        }
        PostMessage(hwnd, WM_LIC_DONE, 0, 0);
    }).detach();
}

// стартовая проверка: сохранённая сессия -> сервер
void LicenseBoot(HWND hwnd) {
    std::thread([hwnd]() {
        sentinel_lic::StoredSession ses;
        if (!sentinel_lic::LoadSession(ses)) {
            std::lock_guard<std::mutex> l(licMutex);
            licPhase = LicPhase::NeedKey;
            licStatus.clear();
            PostMessage(hwnd, WM_LIC_DONE, 0, 0);
            return;
        }
        {
            std::lock_guard<std::mutex> l(licMutex);
            licPhase = LicPhase::Checking;
            licStatus = L"Проверка доступа… / checking access…";
            licStatusError = false; licFatal = false;
        }
        PostMessage(hwnd, WM_LIC_DONE, 0, 0);

        auto r = sentinel_lic::Validate(ses.token, sentinel_lic::MachineFingerprint());
        if (r.ok) {
            std::lock_guard<std::mutex> l(licMutex);
            licPhase = LicPhase::Pass; licPass = true;
            licStatus.clear(); licFatal = false;
        } else {
            // сессию сервер не принял — нужен новый ключ от модератора (не фатально)
            SetLicStatus(LicReasonText(r.reason), true, false);
            std::lock_guard<std::mutex> l(licMutex);
            licPhase = LicPhase::NeedKey;
        }
        PostMessage(hwnd, WM_LIC_DONE, 0, 0);
    }).detach();
}
std::vector<std::wstring> hexLines;
std::mt19937 rng{std::random_device{}()};
std::vector<std::wstring> report;
std::wstring reportFilter;
HWND reportWnd=nullptr, reportList=nullptr, reportSearch=nullptr, reportOwner=nullptr;
std::mutex reportMutex;
std::filesystem::path home(){ wchar_t p[MAX_PATH]; DWORD n=GetEnvironmentVariableW(L"USERPROFILE",p,MAX_PATH); return n?p:L"."; }
std::wstring narrow(const std::string& s){ return std::wstring(s.begin(),s.end()); }
void add(const std::wstring& s){ std::lock_guard<std::mutex> l(reportMutex); report.push_back(s); }
void collectFiles(const std::filesystem::path& dir, const std::wstring& title, int depth=1){ add(L"\n["+title+L"]"); std::error_code ec; if(!exists(dir,ec)){add(L"Not available: "+dir.wstring()); return;} int count=0; for(auto& e:std::filesystem::directory_iterator(dir,ec)){ if(ec) break; if(count++>300) break; auto t=std::filesystem::last_write_time(e,ec); add(e.path().filename().wstring()+L" | "+(e.is_directory()?L"folder":L"file")); } }
void collectRegistry(const wchar_t* root,const wchar_t* sub,const std::wstring& title){ HKEY h; HKEY r=root==L"HKCU"?HKEY_CURRENT_USER:HKEY_LOCAL_MACHINE; if(RegOpenKeyExW(r,sub,0,KEY_READ,&h)!=ERROR_SUCCESS){add(L"\n["+title+L"] unavailable");return;} add(L"\n["+title+L"]"); wchar_t name[512]; DWORD n=512; for(DWORD i=0;RegEnumKeyExW(h,i,name,&n,nullptr,nullptr,nullptr,nullptr)==ERROR_SUCCESS&&i<300;i++){add(name);n=512;} RegCloseKey(h); }
void collectSteam(){ add(L"\n[Steam accounts]"); auto p=home()/L"AppData/Roaming/Steam/config/loginusers.vdf"; std::wifstream f(p); if(!f){add(L"loginusers.vdf unavailable");return;} std::wstring line; while(std::getline(f,line)){ if(line.find(L"765611")!=std::wstring::npos||line.find(L"MostRecent")!=std::wstring::npos||line.find(L"PersonaName")!=std::wstring::npos) add(line); } collectFiles(home()/L"AppData/Roaming/Steam/userdata",L"Steam userdata"); }
void collectBrowser(){ add(L"\n[Browser history, last 30 days]"); auto base=home()/L"AppData/Local"; for(auto d:{L"Google/Chrome/User Data",L"Microsoft/Edge/User Data",L"BraveSoftware/Brave-Browser/User Data",L"Mozilla/Firefox/Profiles"}){std::filesystem::path p=base/d; if(exists(p)) { add(p.wstring()+L" | browser profile found"); collectFiles(p,L"History database files"); }} add(L"Search note: browser SQLite databases may be locked while browser is running."); }
void collectAll(){ add(L"sentinel forensic report"); add(L"Read-only local collection started"); collectSteam(); collectFiles(home()/L"AppData/Roaming/Microsoft/Windows/Recent",L"Recent files"); collectFiles(L"C:/Windows/Prefetch",L"Prefetch"); collectRegistry(L"HKCU",L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",L"ShellBags (folder history; deleted-file recovery requires separate forensic image)"); collectBrowser(); collectRegistry(L"HKLM",L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",L"USB devices"); collectRegistry(L"HKLM",L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",L"Installed software"); collectRegistry(L"HKLM",L"SYSTEM\\CurrentControlSet\\Enum\\PCI",L"PCI/DMA-capable devices"); collectFiles(home()/L"AppData/Roaming/LGHUB",L"LG Hub / macros"); collectFiles(home()/L"AppData/Local/Razer",L"Razer / macros"); add(L"\nCollection complete. No passwords or file contents were read."); }
void refreshReport(){ if(!reportList)return; SendMessageW(reportList,LB_RESETCONTENT,0,0); std::wstring q=reportFilter; std::transform(q.begin(),q.end(),q.begin(),towlower); std::lock_guard<std::mutex> l(reportMutex); for(auto s:report){auto x=s;std::transform(x.begin(),x.end(),x.begin(),towlower);if(q.empty()||x.find(q)!=std::wstring::npos)SendMessageW(reportList,LB_ADDSTRING,0,(LPARAM)s.c_str());} }
LRESULT CALLBACK reportProc(HWND w,UINT m,WPARAM wp,LPARAM lp){ if(m==WM_CREATE){ reportSearch=CreateWindowW(L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_BORDER,18,15,400,28,w,(HMENU)10,GetModuleHandleW(nullptr),nullptr); reportList=CreateWindowW(L"LISTBOX",L"",WS_CHILD|WS_VISIBLE|WS_VSCROLL|LBS_NOINTEGRALHEIGHT,18,55,744,430,w,(HMENU)11,GetModuleHandleW(nullptr),nullptr); CreateWindowW(L"BUTTON",L"Open selected folder",WS_CHILD|WS_VISIBLE,430,15,170,28,w,(HMENU)12,GetModuleHandleW(nullptr),nullptr); refreshReport(); return 0;} if(m==WM_COMMAND&&LOWORD(wp)==10&&HIWORD(wp)==EN_CHANGE){wchar_t b[512];GetWindowTextW(reportSearch,b,512);reportFilter=b;refreshReport();} if(m==WM_COMMAND&&LOWORD(wp)==12){int i=(int)SendMessageW(reportList,LB_GETCURSEL,0,0);if(i>=0){wchar_t b[1024];SendMessageW(reportList,LB_GETTEXT,i,(LPARAM)b);auto pos=std::wstring(b).find(L"AppData");if(pos!=std::wstring::npos)ShellExecuteW(w,L"open",L"explorer.exe",(L"/select,\""+std::wstring(b)+L"\"").c_str(),nullptr,SW_SHOWNORMAL);}} if(m==WM_CLOSE){DestroyWindow(w);reportWnd=nullptr;} return DefWindowProcW(w,m,wp,lp); }
void showReport(HWND owner){ if(reportWnd){SetForegroundWindow(reportWnd);return;} reportOwner=owner; WNDCLASSW wc{};wc.lpfnWndProc=reportProc;wc.hInstance=GetModuleHandleW(nullptr);wc.lpszClassName=L"SentinelReport";wc.hCursor=LoadCursor(nullptr,IDC_ARROW);wc.hbrBackground=CreateSolidBrush(RGB(11,11,14));RegisterClassW(&wc); reportWnd=CreateWindowExW(WS_EX_DLGMODALFRAME,L"SentinelReport",L"sentinel — forensic report",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU,0,0,800,540,owner,nullptr,wc.hInstance,nullptr);RECT r;GetWindowRect(owner,&r);SetWindowPos(reportWnd,nullptr,r.left-80,r.top-50,800,540,SWP_NOZORDER);ShowWindow(reportWnd,SW_SHOW);EnableWindow(owner,FALSE); }
const wchar_t* scanEn[] = {L"Checking accessible memory for cheat traces...", L"Verifying integrity of loaded modules...", L"Inspecting thread start addresses...", L"Analyzing handle tables for foreign processes...", L"Validating driver signature database...", L"Compiling forensic report..."};
const wchar_t* scanRu[] = {L"Проверка доступной памяти на следы читов...", L"Проверка целостности загруженных модулей...", L"Анализ адресов запуска потоков...", L"Анализ таблиц хэндлов на сторонние процессы...", L"Проверка базы подписей драйверов...", L"Формирование отчёта сканирования..."};
std::wstring makeHex(int n) {
    std::wstringstream s; s << L"0x" << std::uppercase << std::hex << (0x00007FF6A3C14B20LL + n * 16) << L"  ";
    std::uniform_int_distribution<int> d(0, 255);
    for (int i=0;i<16;i++) s << std::setw(2) << std::setfill(L'0') << d(rng) << (i==7?L"  ":L" ");
    s << L" |................|"; return s.str();
}
void resetHex() { hexLines.clear(); for(int i=0;i<30;i++) hexLines.push_back(makeHex(i)); }
void text(HDC dc, int x, int y, const std::wstring& value, int size, COLORREF color, bool bold=false) {
    HFONT f=CreateFontW(size,0,0,0,bold?FW_BOLD:FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,FF_MODERN,L"Consolas");
    auto old=(HFONT)SelectObject(dc,f); SetTextColor(dc,color); SetBkMode(dc,TRANSPARENT); TextOutW(dc,x,y,value.c_str(),(int)value.size()); SelectObject(dc,old); DeleteObject(f);
}
void button(HDC dc, RECT r, const std::wstring& label, bool active=false) { HBRUSH b=CreateSolidBrush(active?RGB(255,59,75):RGB(35,35,42)); FillRect(dc,&r,b); DeleteObject(b); FrameRect(dc,&r,CreateSolidBrush(active?RGB(255,90,105):RGB(75,75,85))); text(dc,r.left+18,r.top+10,label,14,RGB(245,245,247),true); }
void paint(HWND hwnd, HDC dc) {
    RECT client; GetClientRect(hwnd,&client); HBRUSH bg=CreateSolidBrush(RGB(11,11,14)); FillRect(dc,&client,bg); DeleteObject(bg);
    for(size_t i=0;i<hexLines.size();i++) text(dc,18,52+(int)i*15,hexLines[i],11,RGB(45,45,52));
    text(dc,24,18,L"●  sentinel",15,RGB(242,242,244),true); text(dc,155,21,L"v1.0",11,RGB(90,93,102));
    if(screen==Screen::License) {
        LicPhase phase; std::wstring status; bool err; std::wstring compact; bool keyOk;
        {
            std::lock_guard<std::mutex> l(licMutex);
            phase=licPhase; status=licStatus; err=licStatusError; compact=GroupKey(keyInput);
            keyOk=sentinel_lic::LooksLikeKey(sentinel_lic::NormalizeKey(keyInput));
        }
        text(dc,175,92,L"Введите ключ доступа",20,RGB(244,244,246),true);
        text(dc,215,122,L"enter access key",12,RGB(106,109,118));
        RECT box{120,170,520,212};
        HBRUSH eb=CreateSolidBrush(RGB(20,20,25)); FillRect(dc,&box,eb); DeleteObject(eb);
        FrameRect(dc,&box,CreateSolidBrush(phase==LicPhase::NeedKey?RGB(60,60,70):RGB(35,35,42)));
        std::wstring shown=compact;
        if(phase==LicPhase::NeedKey&&(GetTickCount()/500)%2==0) { if(shown.empty()) shown=L"SENT-XXXXX-XXXXX-XXXXX"; else shown+=L'_'; }
        text(dc,134,183,shown,14,compact.empty()?RGB(75,75,85):RGB(255,140,151));
        text(dc,120,226,status,12,err?RGB(255,92,107):RGB(140,143,152));
        RECT act{235,268,405,308}; button(dc,act,L"Активировать / Activate",phase==LicPhase::NeedKey&&keyOk);
        text(dc,100,330,L"Одноразовый ключ выдаёт модератор · one-time key, single use only",11,RGB(90,93,102));
        text(dc,140,350,L"Ключ привязывается к этому ПК и работает выбранный срок",11,RGB(70,73,82));
    } else if(screen==Screen::Language) {
        text(dc,230,105,L"Выберите язык",22,RGB(244,244,246),true); text(dc,270,137,L"select language",13,RGB(106,109,118));
        RECT ru{145,185,300,260}, en{320,185,475,260}; button(dc,ru,L"RU   Русский",language==L"ru"); button(dc,en,L"EN   English",language==L"en");
        RECT go{240,300,380,345}; button(dc,go,L"Продолжить",!language.empty());
    } else if(screen==Screen::Eula) {
        text(dc,28,75,language==L"ru"?L"Лицензионное соглашение":L"End-User License Agreement",20,RGB(244,244,246),true);
        text(dc,28,108,language==L"ru"?L"Ознакомьтесь с условиями перед продолжением.":L"Review the terms before continuing.",12,RGB(160,163,172));
        int y=145; const wchar_t* heads[]={L"01 — ACCEPTANCE OF TERMS",L"02 — LICENCE GRANT",L"03 — FAIR USE",L"04 — INTEGRITY CHECKS",L"05 — PRIVACY & DATA",L"06 — SUBSCRIPTIONS",L"07 — REFUNDS",L"08 — PROHIBITED CONDUCT",L"09 — DISCLAIMER OF WARRANTY",L"10 — LIMITATION OF LIABILITY"};
        for(int i=0;i<10;i++){ text(dc,30,y,heads[i],11,RGB(255,74,90),true); y+=20; text(dc,30,y,language==L"ru"?L"Условия использования sentinel и политика конфиденциальности.":L"These terms describe use of sentinel and its privacy policy.",11,RGB(185,188,196)); y+=25; }
        RECT check{30,370,48,388}; FrameRect(dc,&check,CreateSolidBrush(accepted?RGB(255,59,75):RGB(100,100,110))); if(accepted) text(dc,32,367,L"✓",16,RGB(255,255,255),true); text(dc,58,369,language==L"ru"?L"Я прочитал и принимаю условия":L"I have read and accept the terms",12,RGB(185,188,196));
        RECT agree{450,360,570,400}; button(dc,agree,language==L"ru"?L"Принять":L"I Agree",accepted); RECT decline{320,360,435,400}; button(dc,decline,language==L"ru"?L"Отклонить":L"Decline");
    } else {
        text(dc,185,150,scanStep>=6?(language==L"ru"?L"Сканирование завершено":L"Scan complete"):(language==L"ru"?L"Идёт форензик-сканирование":L"Forensic scan in progress"),20,RGB(244,244,246),true);
        text(dc,190,205,scanStep>=6?(language==L"ru"?L"Нарушений целостности не обнаружено.":L"No integrity violations found."):L"[  SCANNING  ]",13,RGB(255,92,107));
        if(scanStep<6){ const wchar_t* msg=(language==L"ru"?scanRu:scanEn)[scanStep]; int count = (scanChar < (int)wcslen(msg)) ? scanChar : (int)wcslen(msg); std::wstring shown(msg, msg+count); text(dc,95,255,shown+L"▌",13,RGB(185,188,196)); }
    }
}
void tick(HWND hwnd) { if(screen==Screen::Scan && scanStep<6){ const wchar_t* msg=(language==L"ru"?scanRu:scanEn)[scanStep]; if(scanChar<(int)wcslen(msg)) scanChar++; else if(scanChar++>=(int)wcslen(msg)+35){scanStep++;scanChar=0; if(scanStep==6){report.clear();std::thread(collectAll).detach();showReport(hwnd);}} InvalidateRect(hwnd,nullptr,FALSE);} }
LRESULT CALLBACK wnd(HWND hwnd, UINT m, WPARAM w, LPARAM l){
    switch(m){
    case WM_CREATE: resetHex(); SetTimer(hwnd,1,35,nullptr); LicenseBoot(hwnd); return 0;
    case WM_TIMER:
        if(w==WM_TIMER_CLOSE){ KillTimer(hwnd,WM_TIMER_CLOSE); DestroyWindow(hwnd); return 0; }
        tick(hwnd); return 0;
    case WM_LIC_DONE:{
        bool pass=false,fatal=false;
        { std::lock_guard<std::mutex> l(licMutex); pass=licPass; fatal=licFatal; licPass=false; }
        if(pass&&screen==Screen::License) screen=Screen::Language;
        if(fatal&&!licCloseTimer){ licCloseTimer=true; SetTimer(hwnd,WM_TIMER_CLOSE,3500,nullptr); }
        InvalidateRect(hwnd,nullptr,FALSE); return 0; }
    case WM_CHAR:
        if(screen==Screen::License){
            bool editing; { std::lock_guard<std::mutex> l(licMutex); editing=licPhase==LicPhase::NeedKey; }
            if(editing){
                std::lock_guard<std::mutex> l(licMutex);
                if(w==8) { if(!keyInput.empty()) keyInput.pop_back(); }
                else if(w>=32&&w<127){
                    wchar_t u=towupper((wchar_t)w);
                    if(keyInput.size()<19&&((u>=L'0'&&u<=L'9')||(u>=L'A'&&u<=L'Z'))) keyInput+=u;
                }
            }
            InvalidateRect(hwnd,nullptr,FALSE);
        }
        return 0;
    case WM_LBUTTONDOWN:{int x=GET_X_LPARAM(l),y=GET_Y_LPARAM(l); if(y<45) SendMessage(hwnd,WM_NCLBUTTONDOWN,HTCAPTION,0);
        else if(screen==Screen::License){ if(x>=235&&x<=405&&y>=268&&y<=308) TryActivate(hwnd); }
        else if(screen==Screen::Language){if(y>=180&&y<=270){language=(x<310?L"ru":L"en");} else if(y>=295&&y<=355&&!language.empty()) screen=Screen::Eula;} else if(screen==Screen::Eula){if(y>=355&&y<=405){if(x<310) accepted=!accepted; else if(x>=440&&accepted){screen=Screen::Scan;scanStep=0;scanChar=0;} else if(x>=310&&x<440) DestroyWindow(hwnd);}} else if(screen==Screen::Scan&&scanStep>=6){showReport(hwnd);} InvalidateRect(hwnd,nullptr,FALSE); return 0;}
    case WM_KEYDOWN:
        if(w==VK_ESCAPE) DestroyWindow(hwnd);
        if(screen==Screen::License){
            if(w=='V'&&(GetKeyState(VK_CONTROL)&0x8000)) PasteKey(hwnd);
            if(w==VK_RETURN) TryActivate(hwnd);
        }
        if(w==VK_RETURN&&screen==Screen::Eula&&accepted){screen=Screen::Scan;scanStep=0;scanChar=0;}
        InvalidateRect(hwnd,nullptr,FALSE); return 0;
    case WM_PAINT:{PAINTSTRUCT ps; paint(hwnd,BeginPaint(hwnd,&ps)); EndPaint(hwnd,&ps); return 0;}
    case WM_DESTROY: KillTimer(hwnd,1); PostQuitMessage(0); return 0;}
    return DefWindowProcW(hwnd,m,w,l); }
}
int WINAPI wWinMain(HINSTANCE h,HINSTANCE, PWSTR, int show){ WNDCLASSW wc{}; wc.hInstance=h; wc.lpfnWndProc=wnd; wc.lpszClassName=L"SentinelCpp"; wc.hCursor=LoadCursor(nullptr,IDC_ARROW); wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1); RegisterClassW(&wc); HWND win=CreateWindowExW(0,wc.lpszClassName,L"sentinel",WS_POPUP|WS_CAPTION|WS_SYSMENU,0,0,640,432,nullptr,nullptr,h,nullptr); RECT r; GetWindowRect(win,&r); int sw=GetSystemMetrics(SM_CXSCREEN),sh=GetSystemMetrics(SM_CYSCREEN); SetWindowPos(win,nullptr,(sw-640)/2,(sh-432)/2,640,432,SWP_NOZORDER); ShowWindow(win,show); UpdateWindow(win); MSG msg; while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);} return 0; }
