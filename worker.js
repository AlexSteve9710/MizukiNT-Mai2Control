/**
 * SDEZ Remote Control — Cloudflare Worker (Serverless WebSocket Broker)
 *
 * 架构：
 *   Cabinet (Unity, ClientWebSocket)  ──ws──▶  Worker  ◀──ws──  Admin Browser
 *                                                │
 *                                                └─ Durable Object（Hibernatable WS）
 *
 * 鉴权（v2，本次重构）：
 *   - 控制台改成「登录页 + KV 账户」模型，所有 admin 入口（HTML / WS / JSON API）
 *     都靠 HttpOnly cookie 携带的 session token 鉴权；ADMIN_TOKEN env var 已废弃。
 *   - cabinet 入口 /token 仍走老的 CABINET_TOKEN env var（机器侧硬编码 token，
 *     与人类账户分离，不要混用）。
 *
 * KV namespace 「AUTH」：
 *   user:<username>     → {salt, hash, createdAt, role, cabinets:[{name,key},…]}
 *   session:<token>     → {username, createdAt}                (TTL 24h)
 *   lockout:<ip>        → {fails, lockedUntil}                 (TTL 5min)
 *
 * 路由：
 *   GET  /                 cookie 有效 → 控制台 HTML，否则 302 → /login
 *   GET  /login            登录页 HTML
 *   GET  /logout           清 cookie + 删 session + 跳 /login（GET 也支持，方便链接）
 *   POST /api/login        {username,password} → set-cookie + 200
 *   POST /api/logout       cookie 必须 → 删 session + 清 cookie
 *   GET  /api/whoami       cookie 必须 → {username, role}
 *   GET  /api/cabinets     cookie 必须 → 用户绑定的 cabinet 列表
 *   PUT  /api/cabinets     cookie 必须 → 整个数组覆盖
 *   GET  /config.json      默认 cabinet key（兼容老前端，无鉴权但只读）
 *   WS   /token?=<KEY>     CABINET_TOKEN env（不变）
 *   WS   /admin?key=<KEY>  cookie 必须有效会话
 */

// ============================================================================
// 鉴权常量（与 tools/make-user.mjs 必须严格一致 —— 改任意一项都会让旧账户失效）
// ============================================================================
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_KEYLEN_BITS = 256;
const PBKDF2_SALT_BYTES  = 16;

const SESSION_TTL_SEC    = 24 * 3600;   // cookie + KV 同步过期
const LOCKOUT_TTL_SEC    = 300;         // 失败计数器 5 分钟自动清零
const LOCKOUT_THRESHOLD  = 5;           // 5 次失败 → 锁定到 lockedUntil
const COOKIE_NAME        = 'sdez_session';

// ============================================================================
// HTML 页面（两份模板）
// ============================================================================

// ---- 登录页 ---------------------------------------------------------------
const HTML_LOGIN = String.raw`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>登录 · SDEZ 远程控制</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; min-height: 100vh;
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, 'Segoe UI Variable Display',
      'Segoe UI', 'Microsoft YaHei', sans-serif;
    background: #0d1117; color: #e6edf3; }
  body { display: grid; place-items: center; padding: 20px; }
  .login-card { width: 100%; max-width: 340px; background: #161b22;
    border: 1px solid #30363d; border-radius: 12px; padding: 28px 24px 24px; }
  .brand { text-align: center; margin-bottom: 20px; }
  .brand h1 { margin: 0; font-size: 18px; font-weight: 600; letter-spacing: -.01em; }
  .brand p { margin: 4px 0 0; font-size: 12px; color: #8b949e; }
  label { display: block; margin: 14px 0 6px; font-size: 12px;
    font-weight: 600; color: #c9d1d9; }
  input { width: 100%; padding: 7px 12px; border-radius: 6px;
    border: 1px solid #30363d; background: #0d1117; color: #e6edf3;
    font: inherit; font-size: 14px; transition: border-color .12s, box-shadow .12s; }
  input:focus { outline: none; border-color: #58a6ff;
    box-shadow: 0 0 0 3px rgba(56,139,253,0.4); }
  .btn { width: 100%; margin-top: 18px; padding: 7px 16px; border-radius: 6px;
    border: 1px solid rgba(240,246,252,0.1); background: #238636; color: #fff;
    font: inherit; font-weight: 500; cursor: pointer;
    transition: background .12s; }
  .btn:hover:not(:disabled) { background: #2ea043; }
  .btn:disabled { background: #238636aa; cursor: not-allowed; }
  .err { margin-top: 14px; padding: 8px 12px; border-radius: 6px;
    background: #da363322; border: 1px solid #da363355; color: #ffa198;
    font-size: 12px; display: none; }
  .err.show { display: block; }
  .foot { margin-top: 18px; text-align: center; font-size: 11px; color: #6e7681; }
</style>
</head>
<body>
  <form class="login-card" id="loginForm" autocomplete="on">
    <div class="brand">
      <h1>SDEZ 远程控制台</h1>
      <p>请使用管理员账号登录</p>
    </div>
    <label for="u">用户名</label>
    <input id="u" name="username" autocomplete="username" autofocus required
      pattern="[A-Za-z0-9._-]{1,32}" />
    <label for="p">密码</label>
    <input id="p" name="password" type="password"
      autocomplete="current-password" required />
    <button type="submit" class="btn" id="submit">登 录</button>
    <div class="err" id="err"></div>
    <div class="foot">© SDEZ Remote Control · KV-backed Auth</div>
  </form>
<script>
const form = document.getElementById('loginForm');
const errEl = document.getElementById('err');
const btn   = document.getElementById('submit');
function showErr(msg) { errEl.textContent = msg; errEl.classList.add('show'); }
function clearErr() { errEl.classList.remove('show'); }
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearErr();
  btn.disabled = true; btn.textContent = '登 录 中…';
  try {
    const r = await fetch('/api/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        username: document.getElementById('u').value.trim(),
        password: document.getElementById('p').value,
      }),
    });
    if (r.ok) {
      // 登录成功 → 跳回控制台。replace 避免「后退」回到登录页又自动跳一次。
      const next = new URLSearchParams(location.search).get('next') || '/';
      location.replace(next);
      return;
    }
    if (r.status === 429) showErr('失败次数过多，请 5 分钟后再试');
    else if (r.status === 401) showErr('用户名或密码错误');
    else if (r.status === 503) showErr('AUTH KV namespace 未绑定，请先按 README §7 部署');
    else { const t = await r.text(); showErr('登录失败 (' + r.status + '): ' + t); }
  } catch (err) {
    showErr('网络错误: ' + err.message);
  } finally {
    btn.disabled = false; btn.textContent = '登 录';
  }
});
</script>
</body>
</html>`;

// ---- 控制台（GitHub Primer 风格） ----------------------------------------
const HTML_CONSOLE = String.raw`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>SDEZ 远程控制</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; min-height: 100vh;
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, 'Segoe UI Variable Display',
      'Segoe UI', 'Microsoft YaHei', sans-serif;
    background: #0d1117; color: #e6edf3; }

  /* ---- 顶栏 (GitHub style header) ---- */
  .topbar { position: sticky; top: 0; z-index: 10; background: #161b22;
    border-bottom: 1px solid #30363d; padding: 12px 20px;
    display: flex; align-items: center; gap: 14px; }
  .topbar h1 { margin: 0; font-size: 16px; font-weight: 600;
    display: flex; align-items: center; gap: 8px; letter-spacing: -.01em; }
  .topbar .spacer { flex: 1; }
  .pill { display: inline-flex; align-items: center; gap: 6px;
    padding: 2px 10px; border-radius: 999px; font-size: 12px; font-weight: 500;
    border: 1px solid; }
  .pill::before { content: ''; width: 6px; height: 6px; border-radius: 50%;
    background: currentColor; }
  .pill.gray   { color: #8b949e;  border-color: #30363d;  background: #21262d; }
  .pill.blue   { color: #58a6ff;  border-color: #1f6feb55;background: #1f6feb22; }
  .pill.green  { color: #56d364;  border-color: #23863655;background: #23863622; }
  .pill.amber  { color: #ffd33d;  border-color: #9e6a0355;background: #9e6a0333; }
  .pill.red    { color: #f85149;  border-color: #da363355;background: #da363322; }
  .user-chip { display: inline-flex; align-items: center; gap: 8px;
    padding: 4px 10px 4px 8px; border-radius: 999px; background: #21262d;
    border: 1px solid #30363d; font-size: 12px; color: #c9d1d9; }
  .user-chip svg { width: 14px; height: 14px; opacity: .8; }
  .user-chip a { color: #8b949e; margin-left: 4px; padding-left: 8px;
    border-left: 1px solid #30363d; text-decoration: none; }
  .user-chip a:hover { color: #f85149; }

  /* ---- 主体 ---- */
  main { max-width: 980px; margin: 0 auto; padding: 20px;
    display: grid; gap: 16px;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); }
  .card { background: #161b22; border: 1px solid #30363d;
    border-radius: 8px; padding: 16px; }
  .card h2 { margin: 0 0 14px; font-size: 12px; font-weight: 600;
    color: #8b949e; text-transform: uppercase; letter-spacing: .06em; }

  /* ---- 表单 ---- */
  label { display: block; margin: 8px 0 4px; font-size: 12px;
    font-weight: 600; color: #c9d1d9; }
  label.muted { color: #8b949e; font-weight: 400; }
  input, button, select, textarea {
    width: 100%; padding: 6px 12px; border-radius: 6px;
    border: 1px solid #30363d; background: #0d1117; color: #e6edf3;
    font: inherit; font-size: 14px;
    transition: border-color .12s, box-shadow .12s, background .12s; }
  input:focus, textarea:focus, select:focus {
    outline: none; border-color: #58a6ff;
    box-shadow: 0 0 0 3px rgba(56,139,253,0.35); }
  textarea { resize: vertical; min-height: 50px; font: inherit; font-size: 14px; }
  select option { background: #0d1117; }

  /* ---- 按钮 (Primer style) ---- */
  button { cursor: pointer; background: #21262d; border-color: #30363d;
    color: #c9d1d9; font-weight: 500; }
  button:hover:not(:disabled) { background: #30363d; border-color: #8b949e; }
  button:active:not(:disabled) { background: #282e33; }
  button:disabled { opacity: .55; cursor: not-allowed; }
  .btn-primary { background: #238636; border-color: rgba(240,246,252,0.1);
    color: #fff; }
  .btn-primary:hover:not(:disabled) { background: #2ea043;
    border-color: rgba(240,246,252,0.1); }
  .btn-danger { background: #21262d; border-color: #30363d; color: #f85149; }
  .btn-danger:hover:not(:disabled) { background: #da3633;
    border-color: #da3633; color: #fff; }
  .btn-warn { background: #21262d; border-color: #30363d; color: #d29922; }
  .btn-warn:hover:not(:disabled) { background: #9e6a03;
    border-color: #9e6a03; color: #fff; }

  .row { display: flex; gap: 8px; }
  .row > * { flex: 1; }
  .row.tight { gap: 6px; }
  .grid2 { display: grid; gap: 6px; grid-template-columns: 1fr 1fr; }
  .grid3 { display: grid; gap: 6px; grid-template-columns: 1fr 1fr 1fr; }
  .grid4 { display: grid; gap: 6px; grid-template-columns: auto 1fr 1fr 1fr;
    align-items: center; }
  .grid4 input[type="color"] { padding: 2px; height: 32px; cursor: pointer; }

  /* ---- 已保存 cabinet 列表 ---- */
  .saved-row { display: grid; grid-template-columns: 1fr auto auto;
    gap: 6px; margin-bottom: 8px; }
  .saved-row select:disabled { opacity: .55; }

  /* ---- 日志 ---- */
  pre.log { background: #010409; border: 1px solid #30363d; border-radius: 6px;
    padding: 12px; max-height: 280px; overflow: auto;
    font: 12px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    white-space: pre-wrap; color: #c9d1d9; }
  pre.log .ok  { color: #56d364; }
  pre.log .err { color: #f85149; }
  pre.log .tx  { color: #79c0ff; }
  pre.log .rx  { color: #d2a8ff; }

  .hint { margin: 10px 0 0; font-size: 11px; color: #6e7681; line-height: 1.55; }
  .hint code { background: #161b2299; border: 1px solid #30363d;
    padding: 1px 5px; border-radius: 3px; font-size: 11px; }
</style>
</head>
<body>
<header class="topbar">
  <h1>
    <svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M3.5 1.75v11.5c0 .138.112.25.25.25H8a.75.75 0 0 1 0 1.5H3.75A1.75 1.75 0 0 1 2 13.25V1.75C2 .784 2.784 0 3.75 0h6.586c.464 0 .909.184 1.237.513l2.914 2.914c.329.328.513.773.513 1.237V8a.75.75 0 0 1-1.5 0V5h-3.25A1.75 1.75 0 0 1 8.5 3.25V1.5h-4.75a.25.25 0 0 0-.25.25Zm6.75-.058v1.558c0 .138.112.25.25.25h1.558a.25.25 0 0 0-.073-.176L10.426 1.75a.25.25 0 0 0-.176-.073Zm5.024 9.073-3.5 3.5a.751.751 0 0 1-1.042-1.042l2.22-2.22-3.97-.001a.75.75 0 0 1 0-1.5h3.97L10.732 7.28a.751.751 0 0 1 1.042-1.042l3.5 3.5a.75.75 0 0 1 0 1.027Z"/>
    </svg>
    SDEZ 远程控制台
  </h1>
  <span class="spacer"></span>
  <span class="pill gray" id="conn">未连接</span>
  <span class="user-chip" id="userChip">
    <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M10.561 8.073a6.005 6.005 0 0 1 3.432 5.142.75.75 0 1 1-1.498.07 4.5 4.5 0 0 0-8.99 0 .75.75 0 0 1-1.498-.07 6.004 6.004 0 0 1 3.431-5.142 3.999 3.999 0 1 1 5.123 0ZM10.5 5a2.5 2.5 0 1 0-5 0 2.5 2.5 0 0 0 5 0Z"/>
    </svg>
    <span id="username">…</span>
    <a href="#" id="logoutLink" title="退出登录">退出</a>
  </span>
</header>

<main>

  <section class="card">
    <h2>连接</h2>

    <label class="muted">已保存的 Cabinet</label>
    <div class="saved-row">
      <select id="savedKey">
        <option value="">— 选择已保存的 Cabinet —</option>
      </select>
      <button type="button" onclick="saveCurrent()" title="把当前 key 起名保存到账户">+ 保存</button>
      <button type="button" class="btn-danger" onclick="deleteSaved()" title="删除选中项">删除</button>
    </div>

    <label>Cabinet Key（[keys] name=）</label>
    <input id="key" placeholder="例：A737-23717353437" autocomplete="off" />
    <div class="row tight" style="margin-top: 10px;">
      <button class="btn-primary" type="button" onclick="manualConnect()">连 接</button>
      <button type="button" onclick="manualDisconnect()">断 开</button>
      <button type="button" onclick="refreshStatus()">查询状态</button>
    </div>
  </section>

  <section class="card">
    <h2>投币</h2>
    <div class="row tight">
      <input id="coinCount" type="number" min="1" max="99" value="1" />
      <button class="btn-primary" type="button" onclick="insertCoin()">投 币</button>
    </div>
    <div class="grid2" style="margin-top:8px;">
      <button type="button" onclick="insertCoinN(1)">+1</button>
      <button type="button" onclick="insertCoinN(2)">+2</button>
      <button type="button" onclick="insertCoinN(5)">+5</button>
      <button type="button" onclick="insertCoinN(10)">+10</button>
    </div>
  </section>

  <section class="card">
    <h2>电源</h2>
    <button type="button" class="btn-warn" onclick="power('GotoTest')"
      style="margin-bottom:6px;">进入测试模式</button>
    <button type="button" class="btn-warn" onclick="power('Reboot')"
      style="margin-bottom:6px;">重启</button>
    <button type="button" class="btn-danger" onclick="power('PowerOff')">关机 / 退出</button>
  </section>

  <section class="card" style="grid-column: 1 / -1;">
    <h2>窗口文字</h2>
    <textarea id="textMsg" rows="2"
      placeholder="文本（支持多行 / Rich Text）"></textarea>
    <label class="muted" style="margin-top:8px;">位置（X / Y，留空 = segatools.ini 默认；负值从右/下偏移）</label>
    <div class="grid2" style="margin-top:4px;">
      <input id="ovX" type="number" placeholder="X 坐标（可留空）" />
      <input id="ovY" type="number" placeholder="Y 坐标（可留空）" />
    </div>
    <label class="muted" style="margin-top:8px;">颜色（RGB 0–255，留空 = segatools.ini 默认）</label>
    <div class="grid4" style="margin-top:4px;">
      <input id="ovColor" type="color" value="#ffffff" title="拖动调色板会自动填充右侧 R/G/B" />
      <input id="ovR" type="number" min="0" max="255" placeholder="R" />
      <input id="ovG" type="number" min="0" max="255" placeholder="G" />
      <input id="ovB" type="number" min="0" max="255" placeholder="B" />
    </div>
    <div class="row tight" style="margin-top:8px;">
      <input id="textDur" type="number" min="0" step="0.1" value="3" placeholder="停留秒数 (0=常驻)" />
      <button class="btn-primary" type="button" onclick="showText()">显示</button>
      <button type="button" onclick="clearText()">清空</button>
    </div>
    <p class="hint">
      持久文字请写到 <code>segatools.ini</code> 的 <code>[overlay] enable=1 / text=…</code>，
      游戏每次启动都会自动渲染。这里发的 ShowText 是「实时活字幕」，
      duration=0 也只在本次进程内有效；新一条 ShowText 会自动替换上一条（不再叠加）。
    </p>
  </section>

  <section class="card" style="grid-column: 1 / -1;">
    <h2>游戏内提示框</h2>
    <div class="grid2">
      <input id="dlgTitle" type="text" maxlength="80"
        placeholder="标题（WarningWindow 顶部）" />
      <select id="dlgMonitor" title="0=左屏 / 1=右屏">
        <option value="0">左屏（Monitor 0）</option>
        <option value="1">右屏（Monitor 1）</option>
      </select>
    </div>
    <textarea id="dlgMsg" rows="3" style="margin-top:8px;"
      placeholder="正文（多行 OK，会原样塞进 WarningWindow.message）"></textarea>
    <div class="row tight" style="margin-top:8px;">
      <input id="dlgDur" type="number" min="0" step="0.1" value="5"
        placeholder="停留秒数 (0=常驻)" />
      <button class="btn-primary" type="button" onclick="showDialog()">显示对话框</button>
    </div>
    <p class="hint">
      直接调游戏内 <code>ProcessManager.EnqueueWarningMessage</code>，与官方维护提示
      共用同一套窗口管线（带 Prepare/Open/Close 动画）。<code>停留秒数</code> 内部转毫秒；
      留 <code>0</code> 表示常驻直到 ForceClose。
    </p>
  </section>

  <section class="card" style="grid-column: 1 / -1;">
    <h2>游戏内事件触发 <span class="hint" style="font-weight:normal;font-size:11px;">小型触发逻辑 / 直接刺激现成全局 UI</span></h2>

    <div class="grid2" style="gap:16px;align-items:start;">
      <!-- 左列：Ban + Error -->
      <div>
        <h3 style="margin:0 0 6px 0;font-size:13px;color:#7d8590;text-transform:uppercase;letter-spacing:0.5px;">封禁警告 / 错误模式</h3>
        <div class="row tight" style="margin-bottom:8px;">
          <button class="btn-warn" type="button" onclick="showBan()" title="EntryProcess 中弹出 BanExecution 警告窗口（仅 entry 流程中有效）">弹出 Ban 警告</button>
        </div>
        <div class="row tight" style="margin-bottom:4px;">
          <input id="errNo" type="number" value="9999" min="0" max="99999" style="width:100px;" title="AMDaemon 错误号（4 位）" />
          <button class="btn-danger" type="button" onclick="showError()" title="调 AMDaemon.Error.Set(errorNo) 进入全屏错误模式">触发错误模式</button>
        </div>
        <p class="hint" style="margin-top:4px;">
          Ban 警告仅在 entry / 刷卡确认阶段有效；错误模式立即全屏接管，需要重启或干预才能退出。
        </p>
      </div>

      <!-- 右列：ShopEnd -->
      <div>
        <h3 style="margin:0 0 6px 0;font-size:13px;color:#7d8590;text-transform:uppercase;letter-spacing:0.5px;">营业结束倒计时</h3>
        <div class="row tight" style="margin-bottom:8px;">
          <input id="shopEndMin" type="number" value="30" min="0" max="240" style="width:100px;" title="剩余分钟数。≤60 进入「即将关店」UI；≤15 进入「已关店」UI" />
          <button class="btn-primary" type="button" onclick="shopEndOn()">ShopEnd ON</button>
          <button type="button" onclick="shopEndOff()">OFF</button>
        </div>
        <p class="hint" style="margin-top:4px;">
          每帧压制 <code>ClosingTimer._remainingMinutes</code>。闲置时双屏弹通知，
          游玩时只在对侧 P 位提示。OFF 立刻恢复上游真实剩余分钟。
        </p>
      </div>
    </div>

    <!-- 下方整行：CommonMessage -->
    <div style="margin-top:14px;padding-top:14px;border-top:1px solid #30363d;">
      <h3 style="margin:0 0 6px 0;font-size:13px;color:#7d8590;text-transform:uppercase;letter-spacing:0.5px;">DB.CommonMessageID 预定义文字</h3>
      <div class="grid2">
        <select id="cmPreset" onchange="onCmPreset()" title="常用 CommonMessageID 速选；选「自定义」则用 ID/Name 字段">
          <option value="">— 自定义 / 手填 —</option>
          <option value="67">67 · UnderServerMaintenance（服务器维护中）</option>
          <option value="68">68 · AimeOffline</option>
          <option value="195">195 · EntryTimeOutCredit</option>
          <option value="196">196 · EntryTimeOut</option>
          <option value="215">215 · CreditInsertCoin</option>
          <option value="124">124 · ErrorIDTitle</option>
          <option value="125">125 · ErrorMessageTitle</option>
          <option value="126">126 · ErrorDateTitle</option>
        </select>
        <select id="cmMonitor" title="0=左屏 / 1=右屏">
          <option value="0">左屏（Monitor 0）</option>
          <option value="1">右屏（Monitor 1）</option>
        </select>
      </div>
      <div class="grid2" style="margin-top:8px;">
        <input id="cmId" type="number" min="-1" max="306" placeholder="messageId（int，-1=用 name）" />
        <input id="cmName" type="text" maxlength="60" placeholder="messageName（EnumName，例如 UnderServerMaintenance）" />
      </div>
      <div class="grid2" style="margin-top:8px;">
        <input id="cmTitle" type="text" maxlength="80" placeholder="title（可选；留空则用 EnumName）" />
        <input id="cmDur" type="number" min="0" step="0.1" value="5" placeholder="停留秒数 (0=常驻)" />
      </div>
      <div class="row tight" style="margin-top:8px;">
        <button class="btn-primary" type="button" onclick="showCommonMessage()">弹出 CommonMessage</button>
      </div>
      <p class="hint" style="margin-top:4px;">
        从 <code>DB.CommonMessageID</code>（306 项）查表取本地化文本，复用 WarningWindow 渲染。
        ID 和 Name 二选一；ID 优先，无则按 Name 解析。
      </p>
    </div>
  </section>

  <section class="card" style="grid-column: 1 / -1;">
    <h2>状态 / 日志</h2>
    <pre id="log" class="log"></pre>
  </section>

</main>

<script>
'use strict';

// =============================================================================
// 通用工具
// =============================================================================
const $ = (s) => document.querySelector(s);

function log(msg, kind) {
  const el = $('#log');
  const t = new Date().toLocaleTimeString();
  const tag = kind === 'err' ? 'ERR' : kind === 'ok' ? 'OK ' :
    kind === 'tx' ? '→  ' : kind === 'rx' ? '←  ' : '   ';
  const span = document.createElement('span');
  span.className = kind || '';
  span.textContent = '[' + t + '] ' + tag + ' ' + msg + '\n';
  el.appendChild(span);
  el.scrollTop = el.scrollHeight;
}
function setConn(text, cls) {
  const el = $('#conn');
  el.textContent = text;
  el.className = 'pill ' + (cls || 'gray');
}

// =============================================================================
// Cabinet 列表 (GET/PUT /api/cabinets)
// =============================================================================
let savedCabinets = [];   // [{name, key}]

async function loadCabinets() {
  try {
    const r = await fetch('/api/cabinets', { credentials: 'same-origin' });
    if (!r.ok) {
      // 没有登录 → 跳登录页（不太可能：进 / 时已经 gate 过了）
      if (r.status === 401) { location.replace('/login?next=/'); return; }
      throw new Error('HTTP ' + r.status);
    }
    const d = await r.json();
    savedCabinets = Array.isArray(d.cabinets) ? d.cabinets : [];
    renderSaved();
  } catch (e) {
    log('载入已保存的 cabinet 失败: ' + e.message, 'err');
  }
}
async function persistCabinets() {
  try {
    const r = await fetch('/api/cabinets', {
      method: 'PUT',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ cabinets: savedCabinets }),
    });
    if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + (await r.text()));
    log('cabinet 列表已保存到账户', 'ok');
  } catch (e) {
    log('保存失败: ' + e.message, 'err');
  }
}
function renderSaved() {
  const sel = $('#savedKey');
  const cur = sel.value;
  // 重建 options
  while (sel.options.length > 1) sel.remove(1);
  for (const c of savedCabinets) {
    const opt = document.createElement('option');
    opt.value = c.key;
    opt.textContent = c.name + ' — ' + c.key;
    sel.appendChild(opt);
  }
  // 尽量保留之前选的
  if (cur && savedCabinets.some(c => c.key === cur)) sel.value = cur;
}
function saveCurrent() {
  const key = $('#key').value.trim();
  if (!key) { log('先在下面填好 cabinet key 再保存', 'err'); return; }
  if (savedCabinets.length >= 30) { log('最多保存 30 个 cabinet', 'err'); return; }
  if (savedCabinets.some(c => c.key === key)) {
    log('这个 key 已经在列表里了', 'err'); return;
  }
  const name = (prompt('给这个 cabinet 起个名字（例如 1号机）：', key) || '').trim();
  if (!name) return;
  if (name.length > 40) { log('名字过长（≤40 字符）', 'err'); return; }
  savedCabinets.push({ name, key });
  renderSaved();
  $('#savedKey').value = key;
  persistCabinets();
}
function deleteSaved() {
  const sel = $('#savedKey');
  const key = sel.value;
  if (!key) { log('请先在下拉里选中要删除的项', 'err'); return; }
  const idx = savedCabinets.findIndex(c => c.key === key);
  if (idx < 0) return;
  if (!confirm('从列表删除「' + savedCabinets[idx].name + '」？\n（不会影响 cabinet 本身）')) return;
  savedCabinets.splice(idx, 1);
  renderSaved();
  persistCabinets();
}
// 选中下拉项 → 把 key 填进输入框 + 立刻连接
$_savedListener: {
  document.addEventListener('DOMContentLoaded', () => {
    $('#savedKey').addEventListener('change', (e) => {
      const v = e.target.value;
      if (!v) return;
      $('#key').value = v;
      manualConnect();
    });
  });
}

// =============================================================================
// Admin WebSocket：自动重连 + 心跳 + 状态机
// =============================================================================
let ws = null;
let reqSeq = 1;
let wsManualClose = false;
let reconnectDelay = 1000;       // 1s → 2s → 5s → 10s → 15s
let reconnectTimer = null;
let countdownTimer = null;
let heartbeatTimer = null;
let cabinetOnline = null;        // null = 未知；true/false = 已知

function nextDelay(d) {
  if (d < 2000)  return 2000;
  if (d < 5000)  return 5000;
  if (d < 10000) return 10000;
  return 15000;
}

function clearTimers() {
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  if (countdownTimer) { clearInterval(countdownTimer); countdownTimer = null; }
  if (heartbeatTimer) { clearInterval(heartbeatTimer); heartbeatTimer = null; }
}

function wsUrl() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const key = $('#key').value.trim();
  return proto + '//' + location.host + '/admin?key=' + encodeURIComponent(key);
}

function manualConnect() {
  const key = $('#key').value.trim();
  if (!key) { log('请先填 Cabinet Key', 'err'); return; }
  wsManualClose = false;
  reconnectDelay = 1000;
  cabinetOnline = null;
  doConnect();
}
function manualDisconnect() {
  wsManualClose = true;
  clearTimers();
  if (ws) { try { ws.close(1000, 'manual'); } catch (e) {} ws = null; }
  setConn('已断开', 'red');
}

function doConnect() {
  clearTimers();
  if (ws) { try { ws.close(); } catch (e) {} ws = null; }
  setConn('连接中…', 'blue');
  let url;
  try { url = wsUrl(); } catch (e) {
    setConn('URL 错误', 'red'); log('ws err: ' + e.message, 'err'); return;
  }
  let s;
  try { s = new WebSocket(url); }
  catch (e) {
    setConn('URL 错误', 'red'); log('ws err: ' + e.message, 'err');
    scheduleReconnect(); return;
  }
  ws = s;
  s.onopen = () => {
    log('admin connected', 'ok');
    reconnectDelay = 1000;
    if (cabinetOnline === null) setConn('已连接', 'green');
    // 应用层心跳：每 25s 发一次 ping。同 DO 的 setWebSocketAutoResponse
    // 会让 Cloudflare 边缘自动回 pong，不唤醒 DO，也保活 ~100s 空闲断连。
    heartbeatTimer = setInterval(() => {
      if (s.readyState === 1) { try { s.send('{"type":"ping"}'); } catch (e) {} }
    }, 25_000);
  };
  s.onclose = (ev) => {
    log('admin closed (' + ev.code + (ev.reason ? ', ' + ev.reason : '') + ')');
    clearTimers();
    if (ev.code === 1008 || ev.code === 4401) {
      // 服务端拒绝 = 会话过期。回登录页。
      log('会话过期或未授权，跳转登录页', 'err');
      location.replace('/login?next=' + encodeURIComponent(location.pathname));
      return;
    }
    if (wsManualClose) { setConn('已断开', 'red'); return; }
    scheduleReconnect();
  };
  s.onerror = () => log('ws error', 'err');
  s.onmessage = (ev) => {
    if (ev.data === '{"type":"pong"}') return;   // 心跳 pong 不刷屏
    log(ev.data, 'rx');
    try {
      const m = JSON.parse(ev.data);
      if (m.type === 'cabinet') {
        cabinetOnline = !!m.online;
        setConn(cabinetOnline ? '在线 (cabinet ON)' : '已连接 (cabinet OFF)',
          cabinetOnline ? 'green' : 'red');
      }
    } catch (e) {}
  };
}

function scheduleReconnect() {
  if (wsManualClose) return;
  let remaining = Math.round(reconnectDelay / 1000);
  setConn('重连中… (' + remaining + 's)', 'amber');
  countdownTimer = setInterval(() => {
    remaining -= 1;
    if (remaining > 0) setConn('重连中… (' + remaining + 's)', 'amber');
  }, 1000);
  reconnectTimer = setTimeout(() => {
    reconnectDelay = nextDelay(reconnectDelay);
    doConnect();
  }, reconnectDelay);
}

// =============================================================================
// 命令发送（不变 + r/g/b 颜色）
// =============================================================================
function send(obj) {
  if (!ws || ws.readyState !== 1) { log('未连接', 'err'); return; }
  obj.id = String(reqSeq++);
  const s = JSON.stringify(obj);
  ws.send(s);
  log(s, 'tx');
}
function insertCoin() {
  const n = parseInt($('#coinCount').value || '1', 10);
  send({ type: 'cmd', cmd: 'InsertCoin', count: n });
}
function insertCoinN(n) { $('#coinCount').value = n; insertCoin(); }
function power(cmd) {
  if ((cmd === 'PowerOff' || cmd === 'Reboot') &&
      !confirm('确认执行: ' + cmd + ' ?')) return;
  send({ type: 'cmd', cmd });
}
function showText() {
  const msg = $('#textMsg').value;
  const dur = parseFloat($('#textDur').value || '0');
  const obj = { type: 'cmd', cmd: 'ShowText', msg, duration: dur };
  const xRaw = $('#ovX').value, yRaw = $('#ovY').value;
  if (xRaw !== '' && !isNaN(parseInt(xRaw, 10))) obj.x = parseInt(xRaw, 10);
  if (yRaw !== '' && !isNaN(parseInt(yRaw, 10))) obj.y = parseInt(yRaw, 10);
  const ri = parseInt($('#ovR').value, 10);
  const gi = parseInt($('#ovG').value, 10);
  const bi = parseInt($('#ovB').value, 10);
  if (!isNaN(ri)) obj.r = Math.max(0, Math.min(255, ri));
  if (!isNaN(gi)) obj.g = Math.max(0, Math.min(255, gi));
  if (!isNaN(bi)) obj.b = Math.max(0, Math.min(255, bi));
  send(obj);
}
function clearText() { send({ type: 'cmd', cmd: 'ClearText' }); }

function showDialog() {
  const title = $('#dlgTitle').value || '';
  const msg   = $('#dlgMsg').value   || '';
  const dur   = parseFloat($('#dlgDur').value || '0');
  const mon   = parseInt($('#dlgMonitor').value, 10);
  if (!title && !msg) { log('对话框：标题和正文都为空，已忽略', 'err'); return; }
  send({
    type: 'cmd', cmd: 'ShowDialog',
    title, msg,
    duration: isNaN(dur) ? 0 : dur,
    monitorId: (mon === 1) ? 1 : 0,
  });
}

// =============================================================================
// 事件触发：ShowBan / ShowError / ShopEnd / ShowCommonMessage
// =============================================================================
function showBan() {
  send({ type: 'cmd', cmd: 'ShowBan' });
}

function showError() {
  const n = parseInt($('#errNo').value, 10);
  const errorNo = isNaN(n) ? 9999 : Math.max(0, n);
  send({ type: 'cmd', cmd: 'ShowError', errorNo });
}

function shopEndOn() {
  const m = parseInt($('#shopEndMin').value, 10);
  const minutes = isNaN(m) ? 30 : Math.max(0, m);
  send({ type: 'cmd', cmd: 'ShopEnd', state: 'on', minutes });
}
function shopEndOff() {
  send({ type: 'cmd', cmd: 'ShopEnd', state: 'off' });
}

// CommonMessage 速选下拉变化时：同步 ID 输入框 + 清空 Name（避免冲突）
function onCmPreset() {
  const v = $('#cmPreset').value;
  if (v === '') return;
  $('#cmId').value = v;
  $('#cmName').value = '';
}

function showCommonMessage() {
  const idRaw = $('#cmId').value;
  const name  = ($('#cmName').value || '').trim();
  const title = $('#cmTitle').value || '';
  const dur   = parseFloat($('#cmDur').value || '0');
  const mon   = parseInt($('#cmMonitor').value, 10);
  const id    = (idRaw === '' || isNaN(parseInt(idRaw, 10))) ? -1 : parseInt(idRaw, 10);
  if (id < 0 && !name) {
    log('CommonMessage：messageId 和 messageName 都为空，已忽略', 'err');
    return;
  }
  const obj = {
    type: 'cmd', cmd: 'ShowCommonMessage',
    messageId: id,
    messageName: name,
    title,
    duration: isNaN(dur) ? 0 : dur,
    monitorId: (mon === 1) ? 1 : 0,
  };
  send(obj);
}
function refreshStatus() { send({ type: 'status?' }); }

// =============================================================================
// 拾色器 ↔ R/G/B 双向同步
// =============================================================================
function syncColorFromPicker() {
  const hex = $('#ovColor').value || '#ffffff';
  $('#ovR').value = parseInt(hex.slice(1, 3), 16);
  $('#ovG').value = parseInt(hex.slice(3, 5), 16);
  $('#ovB').value = parseInt(hex.slice(5, 7), 16);
}
function syncColorFromRgb() {
  const r = parseInt($('#ovR').value, 10);
  const g = parseInt($('#ovG').value, 10);
  const b = parseInt($('#ovB').value, 10);
  if (isNaN(r) && isNaN(g) && isNaN(b)) return;
  const clamp = v => Math.max(0, Math.min(255, isNaN(v) ? 255 : v));
  const toHex = v => clamp(v).toString(16).padStart(2, '0');
  $('#ovColor').value = '#' + toHex(r) + toHex(g) + toHex(b);
}

// =============================================================================
// 退出登录
// =============================================================================
async function doLogout(e) {
  if (e) e.preventDefault();
  manualDisconnect();
  try {
    await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' });
  } catch (err) {}
  location.replace('/login');
}

// =============================================================================
// 初始化
// =============================================================================
async function init() {
  // 1) whoami → 顶栏用户名
  try {
    const r = await fetch('/api/whoami', { credentials: 'same-origin' });
    if (r.status === 401) { location.replace('/login?next=/'); return; }
    if (r.ok) {
      const d = await r.json();
      $('#username').textContent = d.username || '?';
    }
  } catch (e) {}

  // 2) 默认 cabinet key（兼容老 /config.json）
  try {
    const r = await fetch('/config.json', { credentials: 'same-origin' });
    if (r.ok) {
      const d = await r.json();
      if (d.key) $('#key').value = d.key;
    }
  } catch (e) {}

  // 3) 已保存的 cabinet 列表
  await loadCabinets();

  // 4) 颜色同步
  $('#ovColor').addEventListener('input', syncColorFromPicker);
  ['ovR', 'ovG', 'ovB'].forEach(id =>
    $('#' + id).addEventListener('input', syncColorFromRgb));

  // 5) 退出登录
  $('#logoutLink').addEventListener('click', doLogout);

  // 6) 如果已经有 cabinet key（来自 config 或第一项 saved），自动连
  if ($('#key').value || (savedCabinets[0] && savedCabinets[0].key)) {
    if (!$('#key').value) $('#key').value = savedCabinets[0].key;
    manualConnect();
  }
}
document.addEventListener('DOMContentLoaded', init);
</script>
</body>
</html>`;

// ============================================================================
// 鉴权辅助
// ============================================================================
const enc = new TextEncoder();
function bufToHex(buf) {
  const b = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}
function hexToBuf(hex) {
  if (!hex || hex.length % 2 !== 0) return new Uint8Array(0);
  const a = new Uint8Array(hex.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(hex.substr(i * 2, 2), 16);
  return a;
}
async function hashPassword(password, saltHex) {
  const km = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hexToBuf(saltHex), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    km, PBKDF2_KEYLEN_BITS);
  return bufToHex(bits);
}
function constantTimeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let v = 0;
  for (let i = 0; i < a.length; i++) v |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return v === 0;
}
async function verifyPassword(password, saltHex, expectedHashHex) {
  const got = await hashPassword(password, saltHex);
  return constantTimeEqualHex(got, expectedHashHex);
}
function randomToken(bytes = 32) {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return bufToHex(b.buffer);
}

function parseCookieToken(req) {
  const raw = req.headers.get('cookie') || '';
  // 简单 cookie 解析；只关心一项
  for (const part of raw.split(/;\s*/)) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq) === COOKIE_NAME) {
      const v = part.slice(eq + 1);
      // 32 字节 hex = 64 字符；做长度合法性检查防 KV key 注入
      if (/^[a-f0-9]{16,128}$/i.test(v)) return v;
      return null;
    }
  }
  return null;
}
function setSessionCookie(token) {
  return `${COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_SEC}`;
}
function clearSessionCookie() {
  return `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

// 返回 {username, role} 或 null
async function requireSession(env, req) {
  if (!env.AUTH) return null;
  const token = parseCookieToken(req);
  if (!token) return null;
  const raw = await env.AUTH.get('session:' + token);
  if (!raw) return null;
  let s;
  try { s = JSON.parse(raw); } catch (e) { return null; }
  if (!s || !s.username) return null;
  // 顺手把 role 带上（从用户记录里取，万一中途调过角色）
  const userRaw = await env.AUTH.get('user:' + s.username);
  if (!userRaw) return null;
  let user;
  try { user = JSON.parse(userRaw); } catch (e) { return null; }
  return { username: s.username, role: user.role || 'admin' };
}

// 读/写用户记录（顺便规范化 cabinets 字段）
async function loadUser(env, username) {
  const raw = await env.AUTH.get('user:' + username);
  if (!raw) return null;
  let u;
  try { u = JSON.parse(raw); } catch (e) { return null; }
  if (!Array.isArray(u.cabinets)) u.cabinets = [];
  return u;
}
async function saveUser(env, username, user) {
  await env.AUTH.put('user:' + username, JSON.stringify(user));
}

function jsonRes(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...extraHeaders,
    },
  });
}
function htmlRes(html, status = 200, extraHeaders = {}) {
  return new Response(html, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      ...extraHeaders,
    },
  });
}
function redirectRes(loc, extraHeaders = {}) {
  return new Response(null, {
    status: 302,
    headers: { 'location': loc, 'cache-control': 'no-store', ...extraHeaders },
  });
}

// ============================================================================
// /api/login 失败限速（lockout）
// ============================================================================
async function checkLockout(env, ip) {
  const raw = await env.AUTH.get('lockout:' + ip);
  if (!raw) return null;
  let r;
  try { r = JSON.parse(raw); } catch (e) { return null; }
  if (r.fails >= LOCKOUT_THRESHOLD && r.lockedUntil && r.lockedUntil > Date.now())
    return r;
  return null;
}
async function bumpLockout(env, ip) {
  const raw = await env.AUTH.get('lockout:' + ip);
  let r = { fails: 0, lockedUntil: 0 };
  if (raw) { try { r = JSON.parse(raw); } catch (e) {} }
  r.fails = (r.fails || 0) + 1;
  if (r.fails >= LOCKOUT_THRESHOLD) r.lockedUntil = Date.now() + LOCKOUT_TTL_SEC * 1000;
  await env.AUTH.put('lockout:' + ip, JSON.stringify(r), { expirationTtl: LOCKOUT_TTL_SEC });
}
async function clearLockout(env, ip) {
  await env.AUTH.delete('lockout:' + ip);
}

// ============================================================================
// Worker 入口
// ============================================================================
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    if (method === 'OPTIONS')
      return new Response(null, { status: 204, headers: corsHeaders() });

    // ---------- 登录页 / 登录 API ----------
    if (path === '/login' && method === 'GET') {
      // 已登录就别看登录页了，直接进控制台
      const sess = await requireSession(env, request);
      if (sess) return redirectRes('/');
      return htmlRes(HTML_LOGIN);
    }
    if (path === '/api/login' && method === 'POST') {
      return handleLogin(request, env);
    }
    if ((path === '/api/logout' || path === '/logout') &&
        (method === 'POST' || method === 'GET')) {
      return handleLogout(request, env, /*returnHtml*/ method === 'GET');
    }
    if (path === '/api/whoami' && method === 'GET') {
      const sess = await requireSession(env, request);
      if (!sess) return jsonRes({ ok: false, err: 'unauthorized' }, 401);
      return jsonRes({ ok: true, username: sess.username, role: sess.role });
    }
    if (path === '/api/cabinets') {
      return handleCabinets(request, env, method);
    }

    // ---------- 控制台主页（必须登录）----------
    if (path === '/' || path === '/index.html') {
      const sess = await requireSession(env, request);
      if (!sess) return redirectRes('/login?next=' + encodeURIComponent(path));
      return htmlRes(HTML_CONSOLE);
    }

    if (path === '/config.json') {
      return jsonRes({ key: env.DEFAULT_CABINET_KEY || '' }, 200, corsHeaders());
    }

    // ---------- WebSocket 端点 ----------
    if (path === '/token' || path === '/admin') {
      if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket')
        return new Response('WebSocket required', { status: 426 });

      const role = (path === '/token') ? 'cabinet' : 'admin';
      const key = extractKey(url, role);
      if (!key) return new Response('missing key', { status: 400 });

      // 鉴权
      if (role === 'cabinet') {
        const token = url.searchParams.get('token') ||
                      request.headers.get('x-auth-token') || '';
        if (env.CABINET_TOKEN && token !== env.CABINET_TOKEN)
          return new Response('unauthorized', { status: 401 });
      } else {
        const sess = await requireSession(env, request);
        if (!sess) {
          // 用 4401（应用层未授权）让前端 onclose 立刻知道
          // 不是 1008 + 自定义 reason 因为浏览器只暴露 1006 给 onclose；这里直接 401
          return new Response('unauthorized', { status: 401 });
        }
      }

      // 路由到对应 cabinet key 的 Durable Object
      const id = env.CABINETS.idFromName(key);
      const stub = env.CABINETS.get(id);
      const internalPath = (role === 'cabinet') ? '/_cabinet' : '/_admin';
      const internalUrl = new URL(internalPath + '?key=' + encodeURIComponent(key), 'https://do');
      return stub.fetch(new Request(internalUrl.toString(), request));
    }

    return new Response('Not Found', { status: 404, headers: corsHeaders() });
  },
};

// ============================================================================
// 路由处理
// ============================================================================

async function handleLogin(request, env) {
  if (!env.AUTH) {
    return jsonRes({ ok: false, err: 'AUTH_KV_not_bound' }, 503);
  }
  let body;
  try { body = await request.json(); }
  catch (e) { return jsonRes({ ok: false, err: 'bad_json' }, 400); }
  const username = (body && typeof body.username === 'string') ? body.username.trim() : '';
  const password = (body && typeof body.password === 'string') ? body.password : '';
  if (!/^[A-Za-z0-9._-]{1,32}$/.test(username) || !password) {
    return jsonRes({ ok: false, err: 'bad_credentials' }, 400);
  }
  const ip = request.headers.get('cf-connecting-ip') ||
             request.headers.get('x-forwarded-for') || 'unknown';

  const lock = await checkLockout(env, ip);
  if (lock) {
    return jsonRes({ ok: false, err: 'rate_limited' }, 429);
  }
  const user = await loadUser(env, username);
  if (!user) {
    await bumpLockout(env, ip);
    return jsonRes({ ok: false, err: 'unauthorized' }, 401);
  }
  const ok = await verifyPassword(password, user.salt, user.hash);
  if (!ok) {
    await bumpLockout(env, ip);
    return jsonRes({ ok: false, err: 'unauthorized' }, 401);
  }
  // 登录成功
  await clearLockout(env, ip);
  const token = randomToken(32);
  await env.AUTH.put('session:' + token,
    JSON.stringify({ username, createdAt: Date.now() }),
    { expirationTtl: SESSION_TTL_SEC });
  return jsonRes(
    { ok: true, username, role: user.role || 'admin' },
    200,
    { 'set-cookie': setSessionCookie(token) },
  );
}

async function handleLogout(request, env, returnHtml) {
  const token = parseCookieToken(request);
  if (token && env.AUTH) {
    try { await env.AUTH.delete('session:' + token); } catch (e) {}
  }
  if (returnHtml) {
    return redirectRes('/login', { 'set-cookie': clearSessionCookie() });
  }
  return jsonRes({ ok: true }, 200, { 'set-cookie': clearSessionCookie() });
}

async function handleCabinets(request, env, method) {
  const sess = await requireSession(env, request);
  if (!sess) return jsonRes({ ok: false, err: 'unauthorized' }, 401);
  const user = await loadUser(env, sess.username);
  if (!user) return jsonRes({ ok: false, err: 'user_gone' }, 410);

  if (method === 'GET') {
    return jsonRes({ ok: true, cabinets: user.cabinets || [] });
  }
  if (method === 'PUT') {
    let body;
    try { body = await request.json(); }
    catch (e) { return jsonRes({ ok: false, err: 'bad_json' }, 400); }
    const arr = body && Array.isArray(body.cabinets) ? body.cabinets : null;
    if (!arr) return jsonRes({ ok: false, err: 'expect_cabinets_array' }, 400);
    if (arr.length > 30) return jsonRes({ ok: false, err: 'too_many' }, 400);
    const cleaned = [];
    for (const item of arr) {
      if (!item || typeof item !== 'object') continue;
      const name = typeof item.name === 'string' ? item.name.trim().slice(0, 40) : '';
      const key  = typeof item.key  === 'string' ? item.key.trim().slice(0, 80)  : '';
      if (!name || !key) continue;
      cleaned.push({ name, key });
    }
    user.cabinets = cleaned;
    await saveUser(env, sess.username, user);
    return jsonRes({ ok: true, cabinets: cleaned });
  }
  return jsonRes({ ok: false, err: 'method_not_allowed' }, 405);
}

// ============================================================================
// 兼容多种 cabinet URL 写法（原样保留）
// ============================================================================
function extractKey(url, role) {
  let k = url.searchParams.get('key');
  if (k) return k;
  if (role === 'cabinet') {
    k = url.searchParams.get('');
    if (k) return k;
    const s = url.search || '';
    if (s.startsWith('?=')) return decodeURIComponent(s.slice(2).split('&')[0]);
    if (s.startsWith('?') && !s.includes('=')) return decodeURIComponent(s.slice(1));
  }
  return null;
}

function corsHeaders() {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, POST, PUT, OPTIONS',
    'access-control-allow-headers': 'Content-Type, X-Auth-Token',
  };
}

// ============================================================================
// Durable Object（Hibernatable WS）—— 与上一版完全一致，本次重构未改
// ============================================================================
export class CabinetBroker {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const role = url.pathname === '/_cabinet' ? 'cabinet' : 'admin';

    // ★ 边缘 auto-pong：cabinet 与 admin 共用同一 DO，对 {"type":"ping"} 都自动回 pong
    try {
      this.state.setWebSocketAutoResponse(
        new WebSocketRequestResponsePair(
          JSON.stringify({ type: 'ping' }),
          JSON.stringify({ type: 'pong' })
        )
      );
    } catch (e) { /* 极老 runtime 没这 API；忽略 */ }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];

    this.state.acceptWebSocket(server, [role]);

    if (role === 'cabinet') {
      const dups = this.state.getWebSockets('cabinet').filter(w => w !== server);
      for (const old of dups) { try { old.close(1000, 'replaced'); } catch (e) {} }
      this.broadcastToAdmins({ type: 'cabinet', online: true });
    } else {
      const online = this.state.getWebSockets('cabinet').length > 0;
      safeSend(server, JSON.stringify({ type: 'cabinet', online }));
      const hello  = await this.state.storage.get('lastHello');
      const status = await this.state.storage.get('lastStatus');
      if (hello)  safeSend(server, hello);
      if (status) safeSend(server, status);
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, message) {
    const data = (typeof message === 'string')
      ? message
      : new TextDecoder().decode(message);
    const tags = this.state.getTags(ws);
    const role = tags[0];

    if (role === 'cabinet') {
      try {
        const m = JSON.parse(data);
        if (m.type === 'hello')       await this.state.storage.put('lastHello', data);
        else if (m.type === 'status') await this.state.storage.put('lastStatus', data);
        else if (m.type === 'pong')   return;
      } catch (e) {}
      this.broadcastToAdmins(data);
      return;
    }

    // admin → cabinet
    const cabinets = this.state.getWebSockets('cabinet');
    if (cabinets.length === 0) {
      try {
        const m = JSON.parse(data);
        safeSend(ws, JSON.stringify({
          type: 'ack', cmd: m.cmd, ok: false, id: m.id, err: 'cabinet_offline',
        }));
      } catch (e) {}
      return;
    }
    safeSend(cabinets[0], data);
  }

  async webSocketClose(ws, code, reason, wasClean) {
    const tags = this.state.getTags(ws);
    if (tags[0] === 'cabinet')
      this.broadcastToAdmins({ type: 'cabinet', online: false });
  }

  async webSocketError(ws) {
    const tags = this.state.getTags(ws);
    if (tags[0] === 'cabinet')
      this.broadcastToAdmins({ type: 'cabinet', online: false });
  }

  broadcastToAdmins(payload) {
    const s = (typeof payload === 'string') ? payload : JSON.stringify(payload);
    for (const a of this.state.getWebSockets('admin')) safeSend(a, s);
  }
}

function safeSend(ws, s) {
  try { ws.send(s); } catch (e) {}
}
