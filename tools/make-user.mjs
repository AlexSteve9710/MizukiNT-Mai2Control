#!/usr/bin/env node
// tools/make-user.mjs — 离线生成 wrangler kv key put 命令，往 AUTH namespace
// 写入一条 `user:<username>` 记录。用 Node 内置 crypto 跑 PBKDF2-HMAC-SHA256，
// 参数（迭代次数 / salt 长度 / 输出位宽）必须与 worker.js 里的 hashPassword() 完全一致，
// 否则登录验证永远失败。
//
// 用法：
//   node tools/make-user.mjs <username> <password> [role]
//
//   role 默认 admin；目前 Worker 没有差异化角色逻辑，留作未来扩展（审计、读权限分级等）。
//
// 输出示例：
//   wrangler kv key put --binding=AUTH 'user:alex' '{"salt":"...","hash":"...","createdAt":1717000000000,"role":"admin","cabinets":[]}'
//
// 把这条命令直接粘贴到终端跑一次就开账户。**不要把哈希结果提交进 git**。
//
// 安全提示：
//   - PBKDF2 100 000 轮 + 16 字节 salt 是 OWASP 2023 的下限，不是上限。
//     真要更稳可以提到 600 000，但要同步改 worker.js（迭代次数变了所有老账户都失效）。
//   - 这个脚本不需要联网。所有运算都在本地完成。
//   - 别把密码作为命令行参数粘到 shared shell 历史里 —— 见文末「更安全的输入方式」。

import { pbkdf2Sync, randomBytes } from 'node:crypto';
import { argv, exit, stdout, stderr } from 'node:process';

// 与 worker.js 保持一致的参数 —— 改任意一项都会让旧账户全军覆没
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_KEYLEN     = 32;        // 256-bit
const PBKDF2_DIGEST     = 'sha256';
const SALT_BYTES        = 16;

function usage() {
  stderr.write(
    '用法:\n' +
    '  node tools/make-user.mjs <username> <password> [role]\n\n' +
    '示例:\n' +
    '  node tools/make-user.mjs alex \'mySecret!\'\n' +
    '  node tools/make-user.mjs alex \'mySecret!\' admin\n\n' +
    '更安全（不留命令行历史）：\n' +
    '  read -s pw && node tools/make-user.mjs alex "$pw"\n');
  exit(1);
}

const args = argv.slice(2);
if (args.length < 2 || args.length > 3) usage();

const [username, password, roleArg] = args;
const role = (roleArg || 'admin').trim();

// 用户名只允许字母数字 . _ -；避免 KV key 里掺特殊字符
if (!/^[A-Za-z0-9._-]{1,32}$/.test(username)) {
  stderr.write('username 只允许 [A-Za-z0-9._-]，长度 1-32\n');
  exit(2);
}
if (password.length < 4) {
  stderr.write('password 至少 4 字符 (建议 ≥ 12)\n');
  exit(2);
}
if (!/^[a-z]{1,16}$/.test(role)) {
  stderr.write('role 只允许小写字母 1-16 字符\n');
  exit(2);
}

const saltBuf = randomBytes(SALT_BYTES);
const hashBuf = pbkdf2Sync(password, saltBuf, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST);

const record = {
  salt: saltBuf.toString('hex'),
  hash: hashBuf.toString('hex'),
  createdAt: Date.now(),
  role,
  cabinets: [],   // 命名 cabinet 列表，登录后通过 PUT /api/cabinets 更新
};

const recordJson = JSON.stringify(record);

// shell 单引号包裹 → 内部不允许出现单引号；JSON 里只可能在 string 值里有，但
// JSON.stringify 默认不会输出裸单引号，所以直接包就行。保险起见这里再 assert 一遍。
if (recordJson.includes("'")) {
  stderr.write('意外: JSON 含单引号，无法用单引号 shell-quote。请手动转义后写入。\n');
  stderr.write(recordJson + '\n');
  exit(3);
}

stdout.write(
  '# 把下面这条命令粘到终端执行一次（远程 KV 部署）：\n' +
  `wrangler kv key put --binding=AUTH 'user:${username}' '${recordJson}'\n\n` +
  '# 本地 wrangler dev 用的 preview namespace，加 --preview：\n' +
  `wrangler kv key put --binding=AUTH --preview 'user:${username}' '${recordJson}'\n`);
