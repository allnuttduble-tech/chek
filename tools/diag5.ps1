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

$enumSig = @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
public delegate bool EnumProc(IntPtr h, IntPtr l);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, System.Text.StringBuilder sb, int max);
[DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
'@
$ew = @(Add-Type -MemberDefinition $enumSig -Name W32EE -Namespace W -PassThru)[0]

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

$panel = Start-Process -FilePath 'C:\Program Files\dotnet\dotnet.exe' -ArgumentList 'run','--project','D:\chek\panel\sentinel-panel.csproj','--no-build' -PassThru -WindowStyle Hidden
try {
    $deadline = (Get-Date).AddSeconds(25)
    $panelUp = $false
    while ((Get-Date) -lt $deadline -and -not $panelUp) {
        try { $h = Invoke-WebRequest -Uri 'http://127.0.0.1:5177/health' -UseBasicParsing -TimeoutSec 3; $panelUp = ($h.Content -eq 'ok') } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $panelUp) { Write-Host 'FAIL: panel not up'; Stop-Process -Id $panel.Id -Force; exit 1 }
    Write-Host 'OK: panel up'

    Set-Content -Path (Join-Path $clientDir 'sentinel.config.json') -Value '{"ServerUrl":"http://127.0.0.1:5177"}' -Encoding UTF8
    Remove-Item "$env:LOCALAPPDATA\sentinel\session.dat" -Force -ErrorAction SilentlyContinue

    $s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    [void](HttpPost 'http://127.0.0.1:5177/login' '{"pass":"e2e-panel-code"}' $s)
    $r = HttpPost 'http://127.0.0.1:5177/admin/keys' '{"hours":2,"count":1}' $s
    $key = ($r.content | ConvertFrom-Json).keys[0].key
    Write-Host "KEY: $key"

    $proc = Start-Process -FilePath $exe -PassThru
    Start-Sleep -Milliseconds 3000
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $procCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $proc.Id)
    $win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $procCond)
    if (-not $win) { Write-Host 'FAIL: main window'; Stop-Process -Id $proc.Id -Force; Stop-Process -Id $panel.Id -Force; exit 1 }

    $keyInput = Wait-ById $win 'KeyInput' 15
    if (-not $keyInput) { Write-Host 'FAIL: KeyInput'; Stop-Process -Id $proc.Id -Force; Stop-Process -Id $panel.Id -Force; exit 1 }
    Write-Host 'OK: key screen'
    $keyInput.SetFocus()
    [System.Windows.Forms.SendKeys]::SendWait($key)
    Start-Sleep -Milliseconds 600
    Invoke-El (Find-ById $win 'ActivateButton')
    Write-Host 'OK: key submitted'

    $ru = Wait-ById $win 'LangRuButton' 20
    if (-not $ru) { Write-Host 'FAIL: LangRuButton'; Stop-Process -Id $proc.Id -Force; Stop-Process -Id $panel.Id -Force; exit 1 }
    Invoke-El $ru
    $cont = Wait-ById $win 'ContinueButton' 5
    Invoke-El $cont
    Start-Sleep -Milliseconds 1400
    $check = Find-ByType $win ([System.Windows.Automation.ControlType]::CheckBox)
    $check.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern).Toggle()
    Start-Sleep -Milliseconds 500
    Invoke-El (Find-ById $win 'AgreeButton')
    Write-Host 'OK: agree, scanning...'

    $reportBtn = Wait-ById $win 'ReportButton' 150
    if (-not $reportBtn) { Write-Host 'FAIL: ReportButton'; Stop-Process -Id $proc.Id -Force; Stop-Process -Id $panel.Id -Force; exit 1 }
    Write-Host 'OK: report button visible'
    Invoke-El $reportBtn
    Start-Sleep -Milliseconds 1500

    $rep = $null
    $hwnd = $w32::FindWindowW($null, 'sentinel — отчёт')
    if ($hwnd -ne [IntPtr]::Zero) { $rep = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd) }

    if (-not $rep) {
        Write-Host 'FAIL: report window — process windows:'
        $targetPid = [uint32]$proc.Id
        $cb = [W.W32EE+EnumProc] { param($h, $l)
            $wpid = [uint32]0
            [void]$ew::GetWindowThreadProcessId($h, [ref]$wpid)
            if ($wpid -eq $targetPid) {
                $sb = New-Object System.Text.StringBuilder 256
                [void]$ew::GetWindowText($h, $sb, 256)
                Write-Host ("  hwnd=0x{0:X} vis={1} title='{2}'" -f $h, ($ew::IsWindowVisible($h)), $sb.ToString())
            }
            return $true
        }
        [void]$ew::EnumWindows($cb, [IntPtr]::Zero)
        Write-Host "proc alive: $(-not $proc.HasExited)"
    } else {
        Write-Host "OK: report window '$($rep.Current.Name)'"
    }
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
} finally {
    Stop-Process -Id $panel.Id -Force -ErrorAction SilentlyContinue
}
Write-Host 'DIAG5 DONE'
