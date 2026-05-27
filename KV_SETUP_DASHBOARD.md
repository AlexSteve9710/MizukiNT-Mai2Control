# 在 Cloudflare Dashboard 里手工创建 `AUTH` KV namespace

本仓库的 Worker 鉴权 / 会话 / IP 锁定全部存在 **同一个 KV namespace**
里（前缀分区：`user:` / `session:` / `lockout:`）。如果你不想用 `wrangler kv
namespace create` 命令行（公司机器没装 wrangler、Windows 终端权限受限、想纯
点鼠标⋯⋯），用 Cloudflare Dashboard 也能完成全套操作。

下面按步骤来，5 分钟以内能跑完。

---

## 关键名字（**别填错**）

| 位置 | 字段 | 取值 | 说明 |
|---|---|---|---|
| Cloudflare Dashboard | Namespace Name | **`mizukint-mai2-auth`** | dashboard 里展示的人类可读名字。可以改，但建议跟下面 wrangler 的 binding 区分清楚 |
| `wrangler.toml` | `binding` | **`AUTH`**（**全大写、不能改**） | 代码里 `env.AUTH.get/put/list` 用的就是这个标识；改了它要同步改 `worker.js` 中所有 `env.AUTH.…` |
| `wrangler.toml` | `id` | dashboard 给的 32 位 hex（生产） | 见 §3 |
| `wrangler.toml` | `preview_id` | dashboard 给的 32 位 hex（preview） | 见 §3 |

> 易混点：**「Namespace Name」和「binding」是两回事**。
>   - Namespace Name 只是个标签，方便你在一堆 KV 里找它。
>   - binding 是 Worker 代码访问它时用的变量名 (`env.AUTH`)，必须与 `worker.js` 一致。
>
> 改 binding 而不同步改代码 = Worker 启动直接 500（`env.AUTH is undefined`）。

---

## 1. 登录 Cloudflare Dashboard

打开 <https://dash.cloudflare.com/> ，选你的账户。

## 2. 创建 production namespace

1. 左侧菜单 **Workers & Pages** → **KV**（如果你的账户菜单已经迁移到新版，
   路径可能是 **Storage & Databases** → **KV**）。
2. 右上角点 **Create a namespace**（创建 KV 命名空间）。
3. **Namespace Name** 填：`mizukint-mai2-auth`
4. **Create**。
5. 创建完成后页面上会显示一行 **Namespace ID**，形如
   `a1b2c3d4e5f6789012345678abcdef01`。**复制下来**，等会要填回 `wrangler.toml`。

## 3. 创建 preview namespace（用于 `wrangler dev` 本地调试）

如果你**只在生产里跑**、不打算 `wrangler dev`，这一步可以跳过，直接把
`preview_id` 填成跟 `id` 一样的值即可。要严格分离生产 / 预览：

1. 同样的菜单，**Create a namespace**。
2. **Namespace Name** 填：`mizukint-mai2-auth-preview`（或其它你喜欢的，便于和上面那条区分）。
3. **Create** → 复制 Namespace ID。

## 4. 把 ID 写回 `wrangler.toml`

打开仓库里的 `Worker/wrangler.toml`，找到这一段：

```toml
[[kv_namespaces]]
binding     = "AUTH"
id          = ""           # ← TODO: 填 `wrangler kv namespace create AUTH` 输出的 id
preview_id  = ""           # ← TODO: 填 `wrangler kv namespace create AUTH --preview` 输出的 id
```

把 `id =` 改成 §2 复制的 production Namespace ID，把 `preview_id =` 改成
§3 的 preview Namespace ID（或者复用 production ID）。例如：

```toml
[[kv_namespaces]]
binding     = "AUTH"
id          = "a1b2c3d4e5f6789012345678abcdef01"
preview_id  = "0fedcba87654321098765432109abcd1"
```

> **注意**：这两个 32 位 hex ID **不是机密**（任何能读 `wrangler.toml` 的人都看得到），
> 但仍然不建议把它放进**公开**仓库——KV namespace ID 一旦泄露，攻击者就有了
> 一个明确的 KV 攻击目标，可以在判断 Worker 鉴权漏洞时少走弯路。建议
> `wrangler.toml` 留在 private repo 里，或者用 `wrangler.toml.example` 模板 +
> `.gitignore` 忽略真本。

## 5. 把 namespace 绑定到 Worker（仅在你**已经手工部署过**的情况下需要）

如果你完整走了 `wrangler deploy`（CI 或本地）：**不需要做这一步**，因为
wrangler 会读 `wrangler.toml` 自动把 namespace 绑定上去。

如果你的 Worker 是先在 Dashboard 里手工创建的、没有走过一次 `wrangler deploy`：

1. **Workers & Pages** → 找到你的 Worker（`mizukint-mai2`）→ **Settings** → **Bindings**。
2. **Add binding** → **KV namespace**。
3. **Variable name** 填：`AUTH`（**必须全大写**）。
4. **KV namespace** 下拉里选 §2 创建的 `mizukint-mai2-auth`。
5. **Save and deploy**。

走过 `wrangler deploy` 之后这个面板里应当能看到 `AUTH → mizukint-mai2-auth`
那一行。

## 6. 创建首位管理员账户

KV 现在是空的，没有任何账户能登录。**Dashboard 里没有现成的「注册」按钮 ——
本仓库刻意没在线开放注册接口**。两条路二选一：

### 6.A 用 `tools/make-user.mjs` + Dashboard 手填

1. 本机随便找个装了 Node 的环境，跑：
   ```bash
   node tools/make-user.mjs alex 'mySecret!'
   ```
2. 它会输出一条 `wrangler kv key put …` 命令，但你没装 wrangler，**只看里面那
   段单引号包住的 JSON**（形如）：
   ```
   {"salt":"…","hash":"…","createdAt":…,"role":"admin","cabinets":[]}
   ```
3. 回 Dashboard：**Workers & Pages → KV → mizukint-mai2-auth → View**。
4. **Add entry**：
   - **Key**：`user:alex`
   - **Value**：把整段 JSON 粘进去（**不要带外面的单引号**）
   - **Save**

### 6.B 用 wrangler CLI（推荐，省事）

```bash
cd Worker
node tools/make-user.mjs alex 'mySecret!'
# 把它输出的那条 wrangler kv key put 命令直接粘到终端执行一次
```

效果与 6.A 相同，只是不用在 Dashboard 里点 Add entry。

> ⚠️ 6.A 也好 6.B 也好，**密码不要打在公共终端 / shared shell 历史**。Bash 用户
> 可以 `read -s pw && node tools/make-user.mjs alex "$pw"`。

## 7. 部署 / 自检

```bash
cd Worker
wrangler deploy
```

或者依赖你已配的「git push → 自动部署」。部署完之后访问
`https://mizukint-mai2.<your-subdomain>.workers.dev/`：

- 没登录 → **302 跳转到 `/login`**（看到登录卡片即代表 KV 已经绑上、Worker 能读 KV 了）
- 用 `alex` / `mySecret!` 登录 → 跳回 `/`，进入控制台
- 浏览器开 DevTools → **Application → Cookies**，能看到 `sdez_session`（HttpOnly）

如果 `/login` 页能看到、但登录失败：

| 现象 | 排查 |
|---|---|
| 提交后转圈、没反应 | DevTools Network 看 `/api/login` 状态码：500 通常是 KV binding 名字不是 `AUTH`；403/401 是密码错；429 是被 5-fail 锁了 5 分钟 |
| `Internal error: KV binding "AUTH" missing` | §5 没做、或者 `wrangler.toml` 的 binding 拼错（一定要全大写） |
| 一直 「用户名或密码错误」 | 6.A 粘 JSON 时把外面的单引号也粘进去了 → KV 里那条记录是 `'{...}'`（带引号）解析失败。Dashboard 里点开 `user:alex` 看 Value，**第一个字符必须是 `{`** |

## 8. 后续运维（一律走 Dashboard 或 wrangler）

| 操作 | Dashboard 路径 | wrangler 命令 |
|---|---|---|
| 列所有账户 | KV → mizukint-mai2-auth → 列表，可在 search 框输入 `user:` | `wrangler kv key list --binding=AUTH --prefix='user:'` |
| 改密码 | 重新跑 `make-user.mjs`，把新 JSON 覆盖 `user:alex` 那条 entry | 同 §6.B（同名 key 直接覆盖） |
| 删账户 | 在 entry 行右侧菜单 **Delete** | `wrangler kv key delete --binding=AUTH 'user:alex'` |
| 强制下线某账户全部会话 | search `session:`，**Delete** 所有该用户的会话 | `wrangler kv key list --binding=AUTH --prefix='session:'` 找出再 `delete` |
| 解开 IP 锁定 | search `lockout:1.2.3.4`，**Delete** | `wrangler kv key delete --binding=AUTH 'lockout:1.2.3.4'` |

> KV 是**最终一致**的，全球各边缘最多需要 ~60s 才能同步。改密之后头一分钟旧
> 密码可能仍能登录，这是 KV 行为，不是 bug。

---

## 名字速查（贴在屏幕边备查）

```
Namespace Name (Dashboard)   : mizukint-mai2-auth
Namespace Name (preview)     : mizukint-mai2-auth-preview   ← 可选
Binding (wrangler.toml)      : AUTH                          ← 不能改
Worker name                  : mizukint-mai2                 ← 来自 wrangler.toml
首位账户 key                 : user:<username>
会话 key                     : session:<32-byte-hex-token>
锁定 key                     : lockout:<ip>                  ← TTL 300s
```
