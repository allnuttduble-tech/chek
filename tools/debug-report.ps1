# Debug: open report window via ScanHarness (--report-ui); wait up to 150 s,
# list windows of dotnet/ScanHarness processes and any with 'sentinel' in title.
$p = Start-Process -FilePath 'C:\Program Files\dotnet\dotnet.exe' `
    -ArgumentList 'run','--project','D:\chek\tools\ScanHarness','--','--report-ui' `
    -PassThru -WindowStyle Hidden
try {
    $deadline = (Get-Date).AddSeconds(150)
    $found = $false
    while ((Get-Date) -lt $deadline -and -not $found) {
        Start-Sleep -Seconds 5
        $wins = Get-Process | Where-Object { $_.MainWindowTitle -ne '' -and ($_.ProcessName -match 'dotnet|ScanHarness' -or $_.MainWindowTitle -match 'sentinel|report') }
        foreach ($w in $wins) {
            Write-Host ($w.Id.ToString() + ' | ' + $w.ProcessName + ' | [' + $w.MainWindowTitle + ']')
            $found = $true
        }
    }
    if (-not $found) { Write-Host 'no matching window in 150s' }
    else {
        Start-Sleep -Seconds 3
        $wins2 = Get-Process | Where-Object { $_.MainWindowTitle -ne '' -and ($_.ProcessName -match 'dotnet|ScanHarness' -or $_.MainWindowTitle -match 'sentinel|report') }
        foreach ($w in $wins2) { Write-Host ('final: ' + $w.Id.ToString() + ' | ' + $w.ProcessName + ' | [' + $w.MainWindowTitle + ']') }
    }
} finally {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Get-Process | Where-Object { $_.ProcessName -eq 'ScanHarness' } | Stop-Process -Force -ErrorAction SilentlyContinue
}
