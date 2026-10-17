# Debug: full launcher flow via UIA, then dump ALL top-level windows of the
# process (handle, class, title) after clicking the report button.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Windows.Forms

$env:DOTNET_ROOT = 'C:\Program Files\dotnet'
$env:SENTINEL_PANEL_CODE = 'dbg-panel-code'
$exe = 'D:\chek\bin\Debug\net8.0-windows\DetectAcUI.exe'
$clientDir = Split-Path $exe

$sig = @'
[DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindowW(string cls, string title);
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lp);
[DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, System.Text.StringBuilder s, int n);
[DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, System.Text.StringBuilder s, int n);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
public delegate bool EnumProc(IntPtr h, IntPtr lp);
'@
$w32 = @(Add-Type -MemberDefinition $sig -Name W32E -Namespace W -PassThru)[0]

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
function Invoke-El($el) { $el.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke() }

$panel = Start-Process -FilePath 'C:\Program Files\dotnet\dotnet.exe' -ArgumentList 'run','--project','D:\chek\panel\sentinel-panel.csproj','--no-build' -PassThru -WindowStyle Hidden
try {
    $deadline = (Get-Date).AddSeconds(25); $panelUp = $false
    while ((Get-Date) -lt $deadline -and -not $panelUp) {
        try { $h = Invoke-WebRequest -Uri 'http://127.0.0.1:5177/health' -UseBasicParsing -TimeoutSec 3; $panelUp = ($h.Content -eq 'ok') } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $panelUp) { Write-Host 'panel not up'; exit 1 }
    Write-Host 'panel up'

    Set-Content -Path (Join-Path $clientDir 'sentinel.config.json') -Value '{"ServerUrl":"http://127.0.0.1:5177"}' -Encoding UTF8
    Remove-Item "$env:LOCALAPPDATA\sentinel\session.dat" -Force -ErrorAction SilentlyContinue

    $s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    [void](Invoke-WebRequest -Uri 'http://127.0.0.1:5177/login' -Method POST -ContentType 'application/json' -Body '{"pass":"dbg-panel-code"}' -WebSession $s -UseBasicParsing)
    $r = Invoke-WebRequest -Uri 'http://127.0.0.1:5177/admin/keys' -Method POST -ContentType 'application/json' -Body '{"hours":2,"count":1}' -WebSession $s -UseBasicParsing
    $key = ($r.Content | ConvertFrom-Json).keys[0].key
    Write-Host "KEY: $key"

    $proc = Start-Process -FilePath $exe -PassThru
    Start-Sleep -Milliseconds 3000
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $procCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $proc.Id)
    $win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $procCond)
    if (-not $win) { Write-Host 'main window not found'; exit 1 }
    Write-Host ('main window: [' + $win.Current.Name + ']')

    $keyInput = Wait-ById $win 'KeyInput' 15
    if (-not $keyInput) { Write-Host 'KeyInput not found'; exit 1 }
    $keyInput.SetFocus()
    [System.Windows.Forms.SendKeys]::SendWait($key)
    Start-Sleep -Milliseconds 600
    Invoke-El (Find-ById $win 'ActivateButton')
    Write-Host 'key submitted'

    $ru = Wait-ById $win 'LangRuButton' 20
    if (-not $ru) { Write-Host 'LangRuButton not found'; exit 1 }
    Invoke-El $ru
    Invoke-El (Wait-ById $win 'ContinueButton' 5)
    Start-Sleep -Milliseconds 1400
    $check = $win.FindFirst([System.Windows.Automation.TreeScope]::Descendants, (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::CheckBox)))
    $check.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern).Toggle()
    Start-Sleep -Milliseconds 500
    Invoke-El (Find-ById $win 'AgreeButton')
    Write-Host 'scanning...'

    $reportBtn = Wait-ById $win 'ReportButton' 150
    if (-not $reportBtn) { Write-Host 'ReportButton not found'; exit 1 }
    Write-Host 'report button visible'

    Invoke-El $reportBtn
    Write-Host 'report button clicked'
    Start-Sleep -Seconds 4

    # dump all UIA children for the pid
    Write-Host '--- UIA children of root for pid ---'
    $wins = $root.FindAll([System.Windows.Automation.TreeScope]::Children, $procCond)
    Write-Host ('count: ' + $wins.Count)
    foreach ($w in $wins) {
        Write-Host ('uia: [' + $w.Current.Name + '] type=' + $w.Current.ControlType.ProgrammaticName + ' class=' + $w.Current.ClassName)
    }

    # dump all win32 top-level windows for the pid
    Write-Host '--- EnumWindows for pid ---'
    $pidTarget = $proc.Id
    $cb = {
        param($h, $lp)
        $wpid = 0
        [void]$w32::GetWindowThreadProcessId($h, [ref]$wpid)
        if ($wpid -eq $pidTarget) {
            $sb = New-Object System.Text.StringBuilder 256
            [void]$w32::GetWindowTextW($h, $sb, 256)
            $title = $sb.ToString()
            $sb2 = New-Object System.Text.StringBuilder 256
            [void]$w32::GetClassNameW($h, $sb2, 256)
            $cls = $sb2.ToString()
            Write-Host ('win: h=' + $h + ' class=[' + $cls + '] title=[' + $title + ']')
        }
        return $true
    }
    $gc = [System.Runtime.InteropServices.GCHandle]::Alloc($cb)
    try {
        $fp = [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate([System.Runtime.InteropServices.Delegate]$cb)
        [void]$w32::EnumWindows($fp, [IntPtr]::Zero)
    } finally { $gc.Free() }

    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Write-Host 'done'
} finally {
    Stop-Process -Id $panel.Id -Force -ErrorAction SilentlyContinue
}
