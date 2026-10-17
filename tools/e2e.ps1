param([string]$ExePath = 'D:\chek\bin\Debug\net8.0-windows\DetectAcUI.exe')
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Windows.Forms

$env:DOTNET_ROOT = 'C:\Program Files\dotnet'
$env:APPDATA = "$env:USERPROFILE\AppData\Roaming"
$env:LOCALAPPDATA = "$env:USERPROFILE\AppData\Local"
$env:SENTINEL_PANEL_CODE = 'e2e-panel-code'
$exe = $ExePath
$clientDir = Split-Path $exe

$sig = '[DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindowW(string cls, string title);'
$w32 = @(Add-Type -MemberDefinition $sig -Name W32F -Namespace W -PassThru)[0]

function Find-ById($parent, $id) {
    $c = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $id)
    return $parent.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $c)
}
function Wait-ById($parent, $id, $seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        $el = Find-ById $parent $id
        if ($el) { return $el }
        Start-Sleep -Milliseconds 400
    }
    return $null
}
function Find-ByName($parent, $name) {
    $c = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, $name)
    return $parent.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $c)
}
function Find-ByType($parent, $type) {
    $c = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, $type)
    return $parent.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $c)
}
function Click-At($x, $y) {
    [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point([int]$x, [int]$y)
    $t = @(Add-Type -MemberDefinition '[DllImport("user32.dll")] public static extern void mouse_event(uint f, uint x, uint y, uint d, UIntPtr i);' -Name W32M -Namespace W -PassThru)[0]
    $t::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero)
    $t::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)
}
function Click-Element($el) {
    $r = $el.Current.BoundingRectangle
    Click-At ($r.X + $r.Width / 2) ($r.Y + $r.Height / 2)
}
function Invoke-El($el) {
    $el.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
}
function HttpPost($url, $json, $session) {
    try {
        if ($session) { $r = Invoke-WebRequest -Uri $url -Method POST -ContentType 'application/json' -Body $json -WebSession $session -UseBasicParsing -TimeoutSec 15 }
        else { $r = Invoke-WebRequest -Uri $url -Method POST -ContentType 'application/json' -Body $json -UseBasicParsing -TimeoutSec 15 }
        return @{ status = [int]$r.StatusCode; content = $r.Content }
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        $sr = New-Object IO.StreamReader($resp.GetResponseStream())
        return @{ status = [int]$resp.StatusCode; content = $sr.ReadToEnd() }
    }
}

# ---------- панель ----------
$panel = Start-Process -FilePath 'C:\Program Files\dotnet\dotnet.exe' -ArgumentList 'run','--project','D:\chek\panel\sentinel-panel.csproj','--no-build' -PassThru -WindowStyle Hidden
try {
    $deadline = (Get-Date).AddSeconds(25)
    $panelUp = $false
    while ((Get-Date) -lt $deadline -and -not $panelUp) {
        try { $h = Invoke-WebRequest -Uri 'http://127.0.0.1:5177/health' -UseBasicParsing -TimeoutSec 3; $panelUp = ($h.Content -eq 'ok') } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $panelUp) { Write-Host 'FAIL: panel not up'; Stop-Process -Id $panel.Id -Force; exit 1 }
    Write-Host 'OK: panel up'

    # конфиг клиента рядом с exe + чистая сессия
    Set-Content -Path (Join-Path $clientDir 'sentinel.config.json') -Value '{"ServerUrl":"http://127.0.0.1:5177"}' -Encoding UTF8
    Remove-Item "$env:LOCALAPPDATA\sentinel\session.dat" -Force -ErrorAction SilentlyContinue

    # ключ через админ-API
    $s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    [void](HttpPost 'http://127.0.0.1:5177/login' '{"pass":"e2e-panel-code"}' $s)
    $r = HttpPost 'http://127.0.0.1:5177/admin/keys' '{"hours":2,"count":1}' $s
    $key = ($r.content | ConvertFrom-Json).keys[0].key
    Write-Host "KEY: $key"

    # ---------- лаунчер ----------
    $proc = Start-Process -FilePath $exe -PassThru
    Start-Sleep -Milliseconds 3000
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $procCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $proc.Id)
    $win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $procCond)
    if (-not $win) { Write-Host 'FAIL: main window'; Stop-Process -Id $proc.Id -Force; Stop-Process -Id $panel.Id -Force; exit 1 }
    Write-Host "OK: main window '$($win.Current.Name)'"

    # экран ключа
    $keyInput = Wait-ById $win 'KeyInput' 15
    if (-not $keyInput) { Write-Host 'FAIL: KeyInput'; Stop-Process -Id $proc.Id -Force; Stop-Process -Id $panel.Id -Force; exit 1 }
    Write-Host 'OK: key screen visible'

    $keyInput.SetFocus()
    [System.Windows.Forms.SendKeys]::SendWait($key)
    Start-Sleep -Milliseconds 600
    $activate = Find-ById $win 'ActivateButton'
    if (-not $activate) { Write-Host 'FAIL: ActivateButton'; Stop-Process -Id $proc.Id -Force; Stop-Process -Id $panel.Id -Force; exit 1 }
    Invoke-El $activate
    Write-Host 'OK: key submitted'

    # выбор языка (после валидного ключа)
    $ru = Wait-ById $win 'LangRuButton' 20
    if (-not $ru) { Write-Host 'FAIL: LangRuButton (after key)'; Stop-Process -Id $proc.Id -Force; Stop-Process -Id $panel.Id -Force; exit 1 }
    Invoke-El $ru
    Write-Host 'OK: RU selected'

    $cont = Wait-ById $win 'ContinueButton' 5
    if (-not $cont) { Write-Host 'FAIL: ContinueButton'; Stop-Process -Id $proc.Id -Force; Stop-Process -Id $panel.Id -Force; exit 1 }
    Invoke-El $cont
    Start-Sleep -Milliseconds 1400
    $check = Find-ByType $win ([System.Windows.Automation.ControlType]::CheckBox)
    if (-not $check) { Write-Host 'FAIL: checkbox'; Stop-Process -Id $proc.Id -Force; Stop-Process -Id $panel.Id -Force; exit 1 }
    $check.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern).Toggle()
    Start-Sleep -Milliseconds 500
    $agree = Find-ById $win 'AgreeButton'
    if (-not $agree) { Write-Host 'FAIL: AgreeButton'; Stop-Process -Id $proc.Id -Force; Stop-Process -Id $panel.Id -Force; exit 1 }
    Invoke-El $agree
    Write-Host 'OK: agree, scanning...'

    $reportBtn = Wait-ById $win 'ReportButton' 150
    if (-not $reportBtn) { Write-Host 'FAIL: ReportButton'; Stop-Process -Id $proc.Id -Force; Stop-Process -Id $panel.Id -Force; exit 1 }
    Write-Host 'OK: report button visible'
    $log = Find-ById $win 'ScanLogText'
    if ($log) { Write-Host "LOG: $(($log.Current.Name -replace '\r?\n', ' | '))" }

    # отчёт
    Invoke-El $reportBtn
    Start-Sleep -Milliseconds 1500
    $rep = $null
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline -and -not $rep) {
        $wins = $root.FindAll([System.Windows.Automation.TreeScope]::Children, $procCond)
        foreach ($w in $wins) {
            # главное окно называется ровно 'sentinel'; окно отчёта — 'sentinel - …'
            if ($w.Current.Name -like 'sentinel *' -and $w.Current.ProcessId -eq $proc.Id) { $rep = $w; break }
        }
        if (-not $rep) { Start-Sleep -Milliseconds 500 }
    }
    if (-not $rep) { Write-Host 'FAIL: report window'; Stop-Process -Id $proc.Id -Force; Stop-Process -Id $panel.Id -Force; exit 1 }
    Write-Host "OK: report window '$($rep.Current.Name)'"

    foreach ($name in @('Steam-аккаунты', 'История браузеров — 30 дней')) {
        $el = Find-ByName $rep $name
        if ($el) { Click-Element $el; Start-Sleep -Milliseconds 600; Write-Host "OK: section '$name'" }
        else { Write-Host "WARN: section not found: $name" }
    }
    $closeBtn = Find-ById $rep 'CloseButton'
    if ($closeBtn) { Invoke-El $closeBtn; Write-Host 'OK: report closed' }
    Start-Sleep -Milliseconds 900

    # повторный запуск: сохранённая сессия должна пройти без ключа
    $proc2 = Start-Process -FilePath $exe -PassThru
    Start-Sleep -Milliseconds 3000
    $win2 = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $procCond)
    $ru2 = Wait-ById $win2 'LangRuButton' 25
    if ($ru2) { Write-Host 'OK: second launch skipped key screen (session valid)' }
    else {
        $stillKey = Find-ById $win2 'KeyInput'
        Write-Host $(if ($stillKey) { 'WARN: second launch shows key screen again' } else { 'FAIL: second launch stuck' })
    }
    Stop-Process -Id $proc2.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Write-Host 'E2E DONE'
} finally {
    Stop-Process -Id $panel.Id -Force -ErrorAction SilentlyContinue
}
