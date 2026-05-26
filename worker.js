/**
 * SDEZ Remote Control — Cloudflare Worker (Serverless WebSocket Broker)
 *
 * 架构：
 *   Cabinet (Unity, ClientWebSocket)  ──ws──▶  Worker  ◀──ws──  Admin Browser
 *                                                │
 *                                                └─ Durable Object（Hibernatable WS）
 *
 * "无服务器" 实现说明：
 *   - 使用 Cloudflare 的 WebSocket Hibernation API：
 *       state.acceptWebSocket(ws, [tag])
 *       webSocketMessage(ws, msg) / webSocketClose / webSocketError
 *   - DO isolate 在空闲时会被驱逐释放，重新有消息进来时才唤起。
 *     不像传统的 `server.accept()` + 事件监听那样把 isolate 钉住，
 *     用户在 cabinet 不发包时不计 CPU 时间，更贴近 serverless。
 *   - 跨调用持久状态：socket 的「角色 / 关联 key」放在 tags 里；
 *     最后一次 hello/status 放在 `state.storage`，新 admin 一上来就能收到回放。
 *
 * URL 路由（与 DLL 里 URL_PREFIX 配套）：
 *   GET  /                                    控制台 HTML
 *   GET  /config.json                         前端默认配置（cabinet key 等）
 *   WS   /token?=<KEY>     或  /token?key=<KEY>     cabinet 上行入口（匹配 mai2.wahleak.top/token?= 写法）
 *   WS   /admin?key=<KEY>                     admin 控制台入口
 *
 * 鉴权：
 *   - [vars] ADMIN_TOKEN / CABINET_TOKEN，分别给两侧加 token=<...> 校验。
 *   - 留空则关闭鉴权（仅限私有部署 / 测试）。
 */

const HTML = String.raw`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>SDEZ 远程控制</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; min-height: 100%;
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Microsoft YaHei', sans-serif;
    background: #0e1116; color: #e6edf3; }
  header { padding: 14px 18px; background: #161b22; border-bottom: 1px solid #30363d;
    display: flex; align-items: center; gap: 12px; }
  header h1 { margin: 0; font-size: 17px; font-weight: 600; }
  header .status { margin-left: auto; font-size: 12px; opacity: .8; }
  main { max-width: 880px; margin: 0 auto; padding: 18px; display: grid; gap: 16px;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 16px; }
  .card h2 { margin: 0 0 12px; font-size: 14px; font-weight: 600;
    color: #58a6ff; text-transform: uppercase; letter-spacing: .04em; }
  label { display: block; margin: 6px 0 4px; font-size: 12px; opacity: .8; }
  input, button, select, textarea {
    width: 100%; padding: 8px 10px; border-radius: 6px;
    border: 1px solid #30363d; background: #0d1117; color: #e6edf3; font-size: 14px; }
  input:focus, textarea:focus { outline: none; border-color: #58a6ff; }
  .row { display: flex; gap: 8px; }
  .row > * { flex: 1; }
  button { cursor: pointer; background: #21262d; transition: background .15s; font-weight: 500; }
  button:hover { background: #30363d; }
  button.primary { background: #238636; border-color: #238636; }
  button.primary:hover { background: #2ea043; }
  button.danger  { background: #da3633; border-color: #da3633; }
  button.danger:hover { background: #f85149; }
  button.warn    { background: #9e6a03; border-color: #9e6a03; }
  button.warn:hover { background: #bb8009; }
  pre.log { background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
    padding: 10px; max-height: 240px; overflow: auto;
    font: 12px/1.55 ui-monospace, Menlo, Consolas, monospace; white-space: pre-wrap; }
  .pill { display: inline-block; padding: 1px 8px; border-radius: 99px;
    background: #1f6feb33; color: #79c0ff; font-size: 11px; }
  .pill.green { background: #23863633; color: #56d364; }
  .pill.red   { background: #da363333; color: #f85149; }
  .grid2 { display: grid; gap: 6px; grid-template-columns: 1fr 1fr; }
</style>
</head>
<body>
<header>
  <h1>SDEZ 远程控制台</h1>
  <span class="status" id="conn">未连接</span>
</header>
<main>

  <section class="card">
    <h2>连接</h2>
    <label>Cabinet Key（[keys] name=）</label>
    <input id="key" placeholder="例：A737-23717353437" />
    <label>Admin Token（可选）</label>
    <input id="token" placeholder="ADMIN_TOKEN" />
    <div class="row" style="margin-top: 8px;">
      <button onclick="saveCfg()">保存并连接</button>
      <button onclick="disconnect()">断开</button>
      <button onclick="refreshStatus()">查询状态</button>
    </div>
  </section>

  <section class="card">
    <h2>投币</h2>
    <div class="row">
      <input id="coinCount" type="number" min="1" max="99" value="1" />
      <button class="primary" onclick="insertCoin()">投币</button>
    </div>
    <div class="grid2" style="margin-top:8px;">
      <button onclick="insertCoinN(1)">+1</button>
      <button onclick="insertCoinN(2)">+2</button>
      <button onclick="insertCoinN(5)">+5</button>
      <button onclick="insertCoinN(10)">+10</button>
    </div>
  </section>

  <section class="card">
    <h2>电源</h2>
    <button class="warn" onclick="power('GotoTest')">进入测试模式</button>
    <button class="warn" style="margin-top:6px;" onclick="power('Reboot')">重启</button>
    <button class="danger" style="margin-top:6px;" onclick="power('PowerOff')">关机 / 退出</button>
  </section>

  <section class="card" style="grid-column: 1 / -1;">
    <h2>窗口文字</h2>
    <textarea id="textMsg" rows="2" placeholder="文本（支持多行 / Rich Text）"></textarea>
    <div class="row" style="margin-top:6px;">
      <input id="textDur" type="number" min="0" step="0.1" value="3" placeholder="停留秒数 (0=常驻)" />
      <button class="primary" onclick="showText()">显示</button>
      <button onclick="clearText()">清空</button>
    </div>
    <hr style="border-color:#30363d; margin:12px 0;" />
    <label>画面位置 &amp; 样式</label>
    <div class="grid2" style="margin-top:4px;">
      <input id="ovX" type="number" min="-9999" max="9999" value="20" placeholder="X 坐标" />
      <input id="ovY" type="number" min="-9999" max="9999" value="-20" placeholder="Y 坐标" />
      <input id="ovFont" type="number" min="6" max="256" value="22" placeholder="字体大小" />
    </div>
    <button class="warn" style="margin-top:6px;" onclick="updateOverlayConfig()">应用位置 / 样式</button>
  </section>

  <section class="card" style="grid-column: 1 / -1;">
    <h2>状态 / 日志</h2>
    <pre id="log" class="log"></pre>
  </section>

</main>

<script>
const $ = s => document.querySelector(s);
const log = (msg, kind) => {
  const el = $('#log');
  const t = new Date().toLocaleTimeString();
  const tag = kind === 'err' ? '[ERR]' : kind === 'ok' ? '[OK ]' : '[   ]';
  el.textContent += '[' + t + '] ' + tag + ' ' + msg + '\n';
  el.scrollTop = el.scrollHeight;
};
const setConn = (text, cls) => {
  const el = $('#conn');
  el.textContent = text;
  el.className = 'status pill' + (cls ? ' ' + cls : '');
};

let cfg = { key: '', token: '' };
let ws = null;
let reqSeq = 1;

async function loadCfg() {
  try { cfg = JSON.parse(localStorage.getItem('sdez-cfg') || '{}'); } catch {}
  if (!cfg.key) {
    try {
      const r = await fetch('/config.json');
      if (r.ok) {
        const d = await r.json();
        cfg.key = d.key || '';
      }
    } catch {}
  }
  $('#key').value = cfg.key || '';
  $('#token').value = cfg.token || '';
}
function saveCfg() {
  cfg = { key: $('#key').value.trim(), token: $('#token').value.trim() };
  localStorage.setItem('sdez-cfg', JSON.stringify(cfg));
  log('配置已保存', 'ok');
  connect();
}

function wsUrl() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  let u = proto + '//' + location.host + '/admin?key=' + encodeURIComponent(cfg.key);
  if (cfg.token) u += '&token=' + encodeURIComponent(cfg.token);
  return u;
}

function disconnect() {
  if (ws) { try { ws.close(); } catch {} ws = null; }
  setConn('已断开', 'red');
}

function connect() {
  disconnect();
  if (!cfg.key) { log('请先填 Cabinet Key', 'err'); return; }
  setConn('连接中…', '');
  try { ws = new WebSocket(wsUrl()); }
  catch (e) { setConn('URL 错误', 'red'); log('ws err: ' + e.message, 'err'); return; }
  ws.onopen = () => { setConn('已连接', 'green'); log('admin connected', 'ok'); };
  ws.onclose = () => { setConn('已断开', 'red'); log('admin closed'); };
  ws.onerror = () => log('ws error', 'err');
  ws.onmessage = (ev) => {
    log('← ' + ev.data);
    try {
      const m = JSON.parse(ev.data);
      if (m.type === 'cabinet')
        setConn(m.online ? '在线 (cabinet ON)' : '已连接 (cabinet OFF)', m.online ? 'green' : 'red');
    } catch {}
  };
}

function send(obj) {
  if (!ws || ws.readyState !== 1) { log('未连接', 'err'); return; }
  obj.id = String(reqSeq++);
  const s = JSON.stringify(obj);
  ws.send(s);
  log('→ ' + s);
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
  send({ type: 'cmd', cmd: 'ShowText', msg, duration: dur });
}
function clearText() { send({ type: 'cmd', cmd: 'ClearText' }); }
function updateOverlayConfig() {
  const x = parseInt($('#ovX').value, 10);
  const y = parseInt($('#ovY').value, 10);
  const fs = parseInt($('#ovFont').value, 10);
  const obj = { type: 'cmd', cmd: 'UpdateOverlayConfig' };
  if (!isNaN(x)) obj.x = x;
  if (!isNaN(y)) obj.y = y;
  if (!isNaN(fs) && fs > 0) obj.fontSize = fs;
  send(obj);
}
function refreshStatus() { send({ type: 'status?' }); }

(async function init() { await loadCfg(); if (cfg.key) connect(); })();
</script>
</body>
</html>`;

// =============================== Worker 入口 ===============================
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS')
      return new Response(null, { status: 204, headers: corsHeaders() });

    if (path === '/' || path === '/index.html') {
      return new Response(HTML, {
        headers: {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          ...corsHeaders(),
        },
      });
    }

    if (path === '/config.json') {
      return Response.json({ key: env.DEFAULT_CABINET_KEY || '' }, { headers: corsHeaders() });
    }

    // ---------- WebSocket 端点 ----------
    // /token  ← cabinet 入口（兼容 ?=<KEY> 和 ?key=<KEY> 两种写法）
    // /admin  ← admin 控制台入口（?key=<KEY>）
    if (path === '/token' || path === '/admin') {
      if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket')
        return new Response('WebSocket required', { status: 426 });

      const role = (path === '/token') ? 'cabinet' : 'admin';
      const key = extractKey(url, role);
      if (!key) return new Response('missing key', { status: 400 });

      // 鉴权（query token 或 header）
      const token = url.searchParams.get('token') ||
                    request.headers.get('x-auth-token') || '';
      const expected = (role === 'cabinet') ? env.CABINET_TOKEN : env.ADMIN_TOKEN;
      if (expected && token !== expected)
        return new Response('unauthorized', { status: 401 });

      // 路由到对应 cabinet key 的 Durable Object（即 broker 实例）
      const id = env.CABINETS.idFromName(key);
      const stub = env.CABINETS.get(id);
      const internalPath = (role === 'cabinet') ? '/_cabinet' : '/_admin';
      const internalUrl = new URL(internalPath + '?key=' + encodeURIComponent(key), 'https://do');
      return stub.fetch(new Request(internalUrl.toString(), request));
    }

    return new Response('Not Found', { status: 404, headers: corsHeaders() });
  },
};

// 兼容多种 cabinet URL 写法。
//   /token?=A737-...           → 空名查询参数（用户偏好的 mai2.wahleak.top/token?= 风格）
//   /token?key=A737-...        → 标准命名查询参数
//   /admin?key=A737-...        → admin 固定走 ?key=
function extractKey(url, role) {
  // 标准命名参数优先
  let k = url.searchParams.get('key');
  if (k) return k;
  // cabinet 允许 ?=<KEY> 写法（空键名）
  if (role === 'cabinet') {
    k = url.searchParams.get('');
    if (k) return k;
    // 兜底：原始 search 形如 "?=ABC" 时，浏览器/WHATWG URL 标准把它视为 name="" value="ABC"，
    // 但有些环境不识别 — 这里再做一次手剥。
    const s = url.search || '';
    if (s.startsWith('?=')) return decodeURIComponent(s.slice(2).split('&')[0]);
    if (s.startsWith('?') && !s.includes('=')) return decodeURIComponent(s.slice(1));
  }
  return null;
}

function corsHeaders() {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'Content-Type, X-Auth-Token',
  };
}

// =========================== Durable Object (Hibernatable WS) ===========================
//
// 每个 cabinet key 一个 DO 实例。一个实例里同时挂着：
//   - 至多一条 cabinet socket（tag: "cabinet"）
//   - 任意多条 admin socket（tag: "admin"）
//
// 关键点（与传统 server.accept() 实现的差异）：
//   1. 用 state.acceptWebSocket(ws, [tag])，而不是 server.accept() + addEventListener。
//   2. 消息回调由运行时调用 webSocketMessage / webSocketClose / webSocketError
//      （类似事件钩子），而 DO isolate 可以在两次消息之间被驱逐再唤起，
//      此期间不计 CPU/内存费用 —— 这就是 Cloudflare 文档里说的「Hibernation」。
//   3. 因为可能 hibernate，实例字段（this.xxx）不保证存活到下一次回调。
//      想要持久状态必须放进 state.storage 或 socket 的 tag/attachment。
export class CabinetBroker {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const role = url.pathname === '/_cabinet' ? 'cabinet' : 'admin';

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];

    // ★ hibernation 关键 API：不要调 server.accept()，让运行时托管 socket。
    //   第二个参数是 tag 数组，之后可以用 getWebSockets(tag) 检索。
    this.state.acceptWebSocket(server, [role]);

    if (role === 'cabinet') {
      // 同一个 key 只允许一条 cabinet 连接；旧的关掉。
      const dups = this.state.getWebSockets('cabinet').filter(w => w !== server);
      for (const old of dups) {
        try { old.close(1000, 'replaced'); } catch {}
      }
      // 广播 cabinet 上线
      this.broadcastToAdmins({ type: 'cabinet', online: true });
    } else {
      // 新 admin：立刻补送 cabinet 在线状态 + 最近一次 hello/status 回放
      const online = this.state.getWebSockets('cabinet').length > 0;
      safeSend(server, JSON.stringify({ type: 'cabinet', online }));
      const hello  = await this.state.storage.get('lastHello');
      const status = await this.state.storage.get('lastStatus');
      if (hello)  safeSend(server, hello);
      if (status) safeSend(server, status);
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  // ★ hibernation 回调：消息进来时由运行时调
  async webSocketMessage(ws, message) {
    const data = (typeof message === 'string')
      ? message
      : new TextDecoder().decode(message);
    const tags = this.state.getTags(ws);
    const role = tags[0];

    if (role === 'cabinet') {
      // 缓存 hello/status，给后到的 admin 用
      try {
        const m = JSON.parse(data);
        if (m.type === 'hello')       await this.state.storage.put('lastHello', data);
        else if (m.type === 'status') await this.state.storage.put('lastStatus', data);
        else if (m.type === 'pong')   return;  // 心跳就别广播了
      } catch { /* 非 JSON 帧也照样转发，让 admin 自己看 */ }
      this.broadcastToAdmins(data);
      return;
    }

    // admin → cabinet
    const cabinets = this.state.getWebSockets('cabinet');
    if (cabinets.length === 0) {
      // cabinet 不在线：立即给 admin 一个失败 ack
      try {
        const m = JSON.parse(data);
        safeSend(ws, JSON.stringify({
          type: 'ack', cmd: m.cmd, ok: false, id: m.id, err: 'cabinet_offline',
        }));
      } catch {}
      return;
    }
    safeSend(cabinets[0], data);
  }

  async webSocketClose(ws, code, reason, wasClean) {
    const tags = this.state.getTags(ws);
    if (tags[0] === 'cabinet') {
      // cabinet 离线 — 广播给所有 admin
      this.broadcastToAdmins({ type: 'cabinet', online: false });
    }
    try { ws.close(code, reason); } catch {}
  }

  async webSocketError(ws /*, error */) {
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
  try { ws.send(s); } catch {}
}
