# Сквозной тест панели модератора: выдача ключа -> активация -> повторная активация
# -> проверка сессии -> чужая машина -> отзыв ключа. Запускать при работающей панели.
param(
    [string]$BaseUrl = 'http://127.0.0.1:5177',
    [string]$Code = 'test-admin-code'
)

$ErrorActionPreference = 'Stop'
$fail = 0
function Check($name, $cond, $extra = '') {
    if ($cond) { Write-Host ("[OK]   " + $name) }
    else { Write-Host ("[FAIL] " + $name + "  " + $extra); $script:fail++ }
}
# тело ответа из WebException (PS 5.1 бросает исключение на 4xx)
function RespBody($ex) {
    try {
        $resp = $ex.Exception.Response
        if ($resp -eq $null) { return "$($ex.ErrorDetails.Message)" }
        $sr = New-Object IO.StreamReader($resp.GetResponseStream())
        return $sr.ReadToEnd()
    } catch { return "$($ex.ErrorDetails.Message)" }
}
function Post($path, $body, [switch]$Admin) {
    $headers = if ($Admin) { @{ 'X-Panel-Code' = $Code } } else { @{} }
    Invoke-RestMethod -Method Post -Uri ($BaseUrl + $path) -ContentType 'application/json' -Headers $headers -Body ($body | ConvertTo-Json -Compress)
}
# POST, ожидающий отказа: возвращает тело ответа или исключения
function PostFail($path, $body) {
    try { $r = Post $path $body; return ($r | ConvertTo-Json -Compress) }
    catch { return RespBody $_ }
}

# 0. доступность
try { $health = Invoke-RestMethod -Method Get -Uri ($BaseUrl + '/health') } catch { $health = $null }
Check 'health' ($health -eq 'ok') ("$health")

# 1. неверный код панели отклоняется
$bad = PostFail '/login' @{ pass = 'wrong-code' }
Check 'login with wrong code rejected' ($bad -match 'ok.*false') ($bad)

# 2. вход модератора
$login = Post '/login' @{ pass = $Code }
Check 'login ok' ($login.ok)

# 3. выдача двух ключей на 24 ч
$created = Post '/admin/keys' @{ hours = 24; count = 2 } -Admin
Check 'create 2 keys' ($created.ok -and $created.keys.Count -eq 2)
$k1 = $created.keys[0].key
$k2 = $created.keys[1].key
Write-Host ("       k1 = " + $k1 + ", k2 = " + $k2)

# 4. ключ без дефисов тоже должен работать (нормализация)
$k1compact = $k1.Replace('-', '')

# 5. активация k1 -> ok + ticket
$machine1 = 'test-machine-aaaa'
$act = Post '/api/activate' @{ key = $k1compact; machineId = $machine1 }
Check 'activate k1 ok' ($act.ok -and $act.ticket -and $act.expiresAt)
$ticket = $act.ticket

# 6. повторная активация того же ключа -> KEY_USED (одноразовость)
$err = PostFail '/api/activate' @{ key = $k1; machineId = $machine1 }
Check 'second activation of k1 rejected' ($err -match 'KEY_USED') ($err)

# 7. активация несуществующего ключа -> KEY_INVALID
$err = PostFail '/api/activate' @{ key = 'SENT-XXXXX-XXXXX-XXXXX'; machineId = $machine1 }
Check 'unknown key rejected' ($err -match 'KEY_INVALID') ($err)

# 8. проверка сессии на той же машине -> ok
$val = Post '/api/validate' @{ ticket = $ticket; machineId = $machine1 }
Check 'validate session ok' ($val.ok -and $val.expiresAt)

# 9. проверка сессии с другой машины -> MACHINE_MISMATCH
$err = PostFail '/api/validate' @{ ticket = $ticket; machineId = 'other-machine-bbbb' }
Check 'foreign machine rejected' ($err -match 'MACHINE_MISMATCH') ($err)

# 10. проверка мусорного тикета -> SESSION_UNKNOWN
$err = PostFail '/api/validate' @{ ticket = 'DEADBEEF'; machineId = $machine1 }
Check 'unknown ticket rejected' ($err -match 'SESSION_UNKNOWN') ($err)

# 11. отзыв k2, затем активация -> KEY_REVOKED
$rev = Post '/admin/keys/revoke' @{ id = $created.keys[1].id } -Admin
Check 'revoke k2' ($rev.ok)
$err = PostFail '/api/activate' @{ key = $k2; machineId = $machine1 }
Check 'revoked key rejected' ($err -match 'KEY_REVOKED') ($err)

# 12. админские endpoint-ы без авторизации -> 401
$err = PostFail '/admin/keys' @{ hours = 1; count = 1 }
Check 'admin create requires auth' ($err -match 'unauthorized') ($err)

Write-Host ''
if ($fail -eq 0) { Write-Host 'PASSED: all checks passed' }
else { Write-Host ("FAILED: " + $fail + " checks failed"); exit 1 }
