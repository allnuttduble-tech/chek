namespace SentinelPanel;

// ==================== HTML страницы панели ====================

internal static class AdminPage
{
    public const string Html = """
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sentinel — панель модератора</title>
<style>
  :root { --bg:#0b0b0e; --card:#101014; --line:#1f1f26; --txt:#f4f4f6; --muted:#6a6d76; --red:#ff3b4b; }
  * { box-sizing:border-box; }
  body { background:var(--bg); color:var(--txt); font-family:'Segoe UI',sans-serif; margin:0; padding:32px; }
  h1 { font-size:20px; display:flex; align-items:center; gap:10px; }
  h1 .dot { width:9px; height:9px; border-radius:50%; background:var(--red); box-shadow:0 0 12px var(--red); }
  h1 .tag { font-family:Consolas,monospace; font-size:11px; color:var(--muted); font-weight:normal; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:18px; margin-top:16px; }
  .row { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
  label { color:var(--muted); font-size:13px; }
  input { background:#141419; border:1px solid #28282f; color:var(--txt); border-radius:7px;
          padding:9px 12px; font-size:14px; outline:none; }
  input:focus { border-color:var(--red); }
  button { background:#232329; color:#6e6e78; border:0; border-radius:8px; padding:10px 22px;
           font-size:13px; font-weight:600; cursor:pointer; transition:.2s; }
  button:hover { background:var(--red); color:#fff; }
  button.primary { background:var(--red); color:#fff; }
  table { width:100%; border-collapse:collapse; margin-top:12px; font-size:13px; }
  th { text-align:left; color:var(--muted); font-family:Consolas,monospace; font-size:11px;
       text-transform:uppercase; border-bottom:1px solid var(--line); padding:8px 10px; }
  td { padding:8px 10px; border-bottom:1px solid #141419; }
  td.key { font-family:Consolas,monospace; color:#ff8c97; user-select:all; }
  .status { font-family:Consolas,monospace; font-size:11px; padding:2px 8px; border-radius:5px; }
  .s-unused { background:#141419; color:#9ca0a8; }
  .s-active { background:#1d1230; color:#b78cff; }
  .s-expired { background:#1a1a1f; color:#6a6d76; }
  .s-revoked { background:#2a1216; color:var(--red); }
  .muted { color:var(--muted); font-family:Consolas,monospace; font-size:12px; }
  .error { color:var(--red); font-size:13px; margin-top:8px; min-height:16px; }
  .newkeys { font-family:Consolas,monospace; background:#141419; border-radius:8px; padding:12px;
             margin-top:10px; color:#ff8c97; user-select:all; white-space:pre-wrap; }
  .hidden { display:none; }
  .small { font-size:12px; color:var(--muted); }
</style>
</head>
<body>
<h1><span class="dot"></span> sentinel <span class="tag">панель модератора · выдача ключей</span></h1>

<div id="login" class="card" style="max-width:380px">
  <div class="row">
    <input id="pass" type="password" placeholder="пароль панели" style="flex:1">
    <button class="primary" onclick="login()">Войти</button>
  </div>
  <div class="error" id="loginError"></div>
</div>

<div id="panel" class="hidden">
  <div class="card">
    <div class="row">
      <label>Срок доступа после активации, часов:</label>
      <input id="hours" type="number" min="1" max="8760" value="24" style="width:90px">
      <label>Количество:</label>
      <input id="count" type="number" min="1" max="50" value="1" style="width:70px">
      <button class="primary" onclick="createKeys()">Выдать ключи</button>
      <span class="small">ключ одноразовый: активируется один раз, затем привязывается к ПК</span>
    </div>
    <div class="newkeys hidden" id="newKeys"></div>
  </div>

  <div class="card">
    <table>
      <thead><tr>
        <th>Ключ</th><th>Создан</th><th>Активировать до</th><th>Срок сессии</th>
        <th>Использован</th><th>ПК (hash)</th><th>Статус</th><th></th>
      </tr></thead>
      <tbody id="rows"></tbody>
    </table>
    <div class="small" style="margin-top:10px">истёкшие записи удаляются автоматически · обновление каждые 5 с</div>
  </div>
</div>

<script>
const dt = s => s ? new Date(s * 1000).toLocaleString('ru-RU').replace(',','') : '—';
let authed = false;

async function api(path, body) {
  const r = await fetch(path, {
    method: body ? 'POST' : 'GET',
    headers: body ? {'Content-Type':'application/json'} : {},
    body: body ? JSON.stringify(body) : undefined
  });
  return await r.json();
}

async function login() {
  const res = await api('/login', { pass: document.getElementById('pass').value });
  if (!res.ok) { document.getElementById('loginError').textContent = res.error || 'Ошибка'; return; }
  authed = true;
  document.getElementById('login').classList.add('hidden');
  document.getElementById('panel').classList.remove('hidden');
  refresh();
  setInterval(refresh, 5000);
}

async function createKeys() {
  document.getElementById('newKeys').classList.add('hidden');
  const res = await api('/admin/keys', {
    hours: parseInt(document.getElementById('hours').value) || 24,
    count: parseInt(document.getElementById('count').value) || 1
  });
  if (!res.ok) { alert(res.error || 'Ошибка'); return; }
  const box = document.getElementById('newKeys');
  box.textContent = res.keys.map(k => k.key).join('\\n');
  box.classList.remove('hidden');
  refresh();
}

async function revoke(id) {
  if (!confirm('Отозвать ключ?')) return;
  await api('/admin/keys/revoke', { id });
  refresh();
}

async function refresh() {
  const res = await api('/admin/keys');
  if (!res.ok) { if (authed) { location.reload(); } return; }
  const rows = document.getElementById('rows');
  rows.innerHTML = res.keys.map(k => `
    <tr>
      <td class="key">${k.key}</td>
      <td class="muted">${dt(k.createdAt)}</td>
      <td class="muted">${dt(k.expiresAt)}</td>
      <td class="muted">${k.durationHours} ч</td>
      <td class="muted">${dt(k.usedAt)}</td>
      <td class="muted">${k.machineId ? k.machineId.slice(0,10) + '…' : '—'}</td>
      <td><span class="status s-${k.status}">${k.status}</span></td>
      <td>${k.status === 'unused' ? `<button onclick="revoke('${k.id}')">отозвать</button>` : ''}</td>
    </tr>`).join('');
}

document.getElementById('pass').addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
</script>
</body>
</html>
""";
}
