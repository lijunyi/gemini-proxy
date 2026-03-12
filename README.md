# 💎 Gemini Key Rotation Proxy  v2.0

> 基于 **Cloudflare Workers** 的 Gemini API 密钥轮转代理，部署在 Cloudflare 边缘。
> 使用 [Gemini 官方 OpenAI 兼容层](https://ai.google.dev/gemini-api/docs/openai?hl=zh-cn)，支持多 Key 轮转、访问密钥防滥用、可视化面板、自动配额清零。

---

## 🚀 快速开始（5 步）

适合第一次部署，完成后即可通过 OpenAI 格式调用 Gemini。

1. **部署 Worker**

   ```bash
   npm install -g wrangler
   wrangler login
   wrangler deploy
   ```

2. **绑定 KV**：[Cloudflare Dashboard](https://dash.cloudflare.com) → 进入你的 Worker → **设置 → 绑定 → 添加 → KV 命名空间**，变量名填 `GEMINI_KV`。

3. **设置面板密码**

   ```bash
   wrangler secret put PASSWORD
   # 按提示输入一个强密码
   ```

4. **添加 Gemini API Key**：浏览器打开 Worker 地址（如 `https://gemini-proxy.你的子域.workers.dev`），用 `PASSWORD` 登录，在「🔑 Gemini 密钥」中添加至少一个 [Gemini API Key](https://aistudio.google.com/app/apikey)。

5. **生成 Access Token 并测试**：在「🎫 Access Tokens」中创建 Token，然后用下面的命令验证：

   ```bash
   curl https://your-worker.workers.dev/v1/chat/completions \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -d '{"model": "gemini-2.0-flash", "messages": [{"role": "user", "content": "Hello!"}], "stream": false}'
   ```

   > 💡 模型名请以你账号实际可用的为准，可在面板「🆘 备用模型」的支持模型列表中查看。

---

## 一、Cloudflare 部署

本应用部署在 **Cloudflare**：使用 **Workers** 运行代理逻辑，使用 **KV** 存储 Key 状态与访问 Token。

### 前置要求

- Node.js 18+（用于运行 wrangler）
- [Cloudflare 账号](https://dash.cloudflare.com/sign-up)
- 若干 [Gemini API Key](https://aistudio.google.com/app/apikey)（在面板中配置，可多个）

### 1. 安装 Wrangler 并登录

```bash
npm install -g wrangler
wrangler login
```

### 2. 绑定 KV 命名空间

**线上部署推荐方式：通过 Dashboard 绑定，`wrangler.toml` 无需填写 `id`。**

1. **创建 KV**（若还没有）：[Cloudflare Dashboard](https://dash.cloudflare.com) → **Workers & Pages** → **KV** → **创建命名空间**，名字自定义（例如 `ai`）。
2. **绑定到 Worker**：进入你的 Worker（如 `gemini-proxy`）→ **设置** → **绑定** → **添加绑定** → **KV 命名空间**：
   - **变量名称**填 **`GEMINI_KV`**（必须与代码一致）
   - **命名空间**选择你刚创建或已有的 → **保存**。

> ℹ️ `wrangler.toml` 中已注释掉 `[[kv_namespaces]]` 的 `id` 字段，线上部署时无需修改，Dashboard 绑定即可生效。
> 本地调试场景下 `wrangler.toml` 的作用见「[二、本地调试方法](#二本地调试方法)」。

### 3. 配置环境变量 / Secrets

| 变量 | 说明 | 示例 |
|------|------|------|
| `PASSWORD` | 管理面板登录密码 | 自定义强密码 |

**Gemini API 密钥**在登录面板后的「🔑 Gemini 密钥」中添加、编辑与删除，存储在 KV 中，无需环境变量。

**方式 A：Wrangler 命令行（推荐）**

```bash
wrangler secret put PASSWORD
# 按提示输入面板密码
```

**方式 B：Cloudflare 仪表板**

1. 打开 [Workers & Pages](https://dash.cloudflare.com/?to=/:account/workers) → 选择你的 Worker
2. **Settings** → **Variables and Secrets**
3. 添加 **Encrypted** 变量：`PASSWORD`

### 4. 部署

**本地部署：**

```bash
wrangler deploy
```

部署成功后得到 Worker 地址，例如：`https://gemini-proxy.你的子域.workers.dev`。
浏览器访问根地址 `/` 即为**管理面板登录页**，使用 `PASSWORD` 登录后在「Gemini 密钥」中添加 API Key，在「Access Tokens」中生成访问 Token。

**GitHub Actions 自动部署：**

推送代码到 `main` 分支时，由 workflow 自动执行 `wrangler deploy`。需在仓库 **Settings → Secrets and variables → Actions** 中配置：

| Secret | 说明 |
|--------|------|
| `CF_API_TOKEN` | Cloudflare API Token（需包含 Workers 编辑权限） |
| `CF_ACCOUNT_ID` | Cloudflare 账号 ID |

Workflow 文件：`.github/workflows/deploy.yml`。

---

## 二、本地调试方法

开发或排查问题时可在本机运行 Worker，再连远程或本地 KV。

### 1. 安装 Wrangler

```bash
npm install -g wrangler
# 或使用 npx，无需全局安装
```

### 2. 配置本地环境变量

在项目根目录创建 **`.dev.vars`**（已加入 .gitignore，不会提交）：

```
PASSWORD=admin
```

> ⚠️ **`admin` 仅为本地调试示例，切勿在生产环境使用。** 线上请通过 `wrangler secret put PASSWORD` 设置强密码。

`PASSWORD` 仅用于**登录管理面板**；API 调用需使用登录面板后生成的**访问 Token**（Bearer），二者不同。

### 3. KV 绑定（三选一）

根据你的情况选择其中一种：

| 场景 | 做法 |
|------|------|
| **已在 Cloudflare 创建了 KV，想用线上数据** | 在 Dashboard 将 Worker 绑定 KV（变量名 `GEMINI_KV`），然后直接运行 `wrangler dev`，本地会自动使用该绑定。 |
| **已在 Cloudflare 创建了 KV，想用本地空数据** | 在 `wrangler.toml` 中取消注释 `[[kv_namespaces]]` 并填入 KV 的 `id`，运行 `wrangler dev`，数据存储在本地沙盒中，不影响线上。 |
| **不想碰 KV 配置，直接连线上** | 运行 `wrangler dev --remote`，所有读写直接操作线上 KV。 |

> ℹ️ **尚未在 Cloudflare 创建 KV？** 先在 Dashboard 创建一个 KV 命名空间（见「[一-2](#2-绑定-kv-命名空间)」），再按上表操作。没有 KV 绑定时，代理功能可以运行，但 Key 状态、Token、日志等均无法持久化。

### 4. 启动本地服务

```bash
npx wrangler dev
# 或：wrangler dev
```

浏览器访问 **http://localhost:8787/** 或 **http://localhost:8787/panel**，应看到登录页；密码填 `.dev.vars` 里的 `PASSWORD`。
登录后先在「🔑 Gemini 密钥」中添加 API Key，再在「🎫 Access Tokens」中生成 API 用的 Bearer Token。

若出现 **Worker Error** 页面，会显示具体错误（例如缺少 `GEMINI_KV` 绑定或 `PASSWORD`），便于排查。

---

## 三、实现的功能

> 以下是 Worker 侧实现的具体能力，整体上「一、二」是部署与调试，「三」是原理与功能——方便二次开发者对照 `worker.js` 查看。

### 3.1 功能概览

| 功能 | 说明 |
|------|------|
| 🔑 多 Key 轮转 | 在面板中配置多个 Gemini Key，Round-Robin，429 自动跳 Key，24h 后自动恢复 |
| 🔄 OpenAI + Gemini 双接口 | 支持 `/v1/`（OpenAI 兼容）与 `/v1beta/`（Gemini 原生） |
| 🎫 访问密钥防滥用 | 面板内一键生成/吊销 Bearer Token，可设单 Token 最小访问间隔（秒），API 调用需携带 Token |
| 📊 可视化面板 | 查看 Key 状态、调用量、错误数，可在面板中手动刷新 |
| 🔒 面板密码保护 | 通过环境变量 `PASSWORD` 设置，Session Cookie 验证 |
| ⚡ 额度自动清零 | 每日计数自动归零，耗尽 Key 24h 后自动解封；面板可手动重置 |
| 🆘 备用模型 | 全部 Key 429 时，可自动改用面板配置的备用模型（如免费模型）再试一次 |
| 📋 请求日志 | 面板内查看最近 50 条 API 请求（路径、状态、模型等），可清空 |
| 🏠 默认即登录页 | 根路径 `/` 即为管理面板登录页 |
| 🌐 部署在 Cloudflare | Workers + KV，无需自建服务器 |

### 3.2 架构与路由

```
用户请求
   │
   ├─ /v1/chat/completions  →  /v1beta/openai/chat/completions  （官方 OpenAI 兼容）
   ├─ /v1/models            →  /v1beta/openai/models
   ├─ /v1/embeddings        →  /v1beta/openai/embeddings
   ├─ /v1/images/generations →  /v1beta/openai/images/generations
   ├─ /v1beta/models/...    →  /v1beta/models/...               （Gemini 原生透传）
   └─ / 或 /panel           →  管理面板 (HTML)

Cloudflare Worker
   ├─ Token 验证（Bearer token against KV）
   ├─ Key 轮转器（Round-Robin，跳过 429 的 Key）
   └─ 透明转发 → generativelanguage.googleapis.com（自动注入 Gemini API Key）
```

v2 使用 Google 官方 `/v1beta/openai/` 兼容层，无需手写协议转换，支持 Function Calling、结构化输出、图片理解、流式输出等。

### 3.3 代码结构概览

本项目的核心逻辑集中在 `worker.js` 中，主要分为以下几个模块（均在同一 Worker 中运行）：

- **KV 工具与常量**：封装 `kvGet/kvSet/kvDelete/kvList` 等操作，并统一管理 KV key / 前缀常量（如 `cfg:api_keys`、`ks:*`、`tok:*` 等）。
- **Key 状态与轮转**：管理每个 Gemini Key 的调用统计、每日重置、按模型维度的 429 封禁逻辑，以及轮询选择可用 Key。
- **访问令牌与认证**：生成与管理访问 Token（仅存哈希与脱敏预览）、限流（最小访问间隔）、`Bearer` 鉴权等。
- **模型缓存与备用模型**：周期性拉取官方 `/v1beta/models` 列表，缓存支持模型，并维护"全部 Key 429 时"的备用模型列表。
- **请求日志**：在 KV 中记录最近 50 条请求（路径、模型、状态码、输入摘要、转发目标 URL、脱敏后的 API Key），供面板查看与清空。
- **管理面板路由与 HTML**：`/panel` 路由返回完整的内联 HTML/CSS/JS 管理面板，前端通过 `/panel/*` JSON 接口调用上述功能。

若仅部署使用，一般只需关注 `wrangler.toml` / 环境变量配置与面板操作；仅在自定义行为或二次开发时，才需要深入阅读 `worker.js` 中相应模块。

### 3.4 API 端点

**OpenAI 格式（推荐）：**

```
POST /v1/chat/completions
GET  /v1/models
POST /v1/embeddings
POST /v1/images/generations
```

**Gemini 原生格式：**

```
POST /v1beta/models/{model}:generateContent
POST /v1beta/models/{model}:streamGenerateContent
```

**其他：**

- **GET /panel/health**：健康检查（无需登录），返回 `{ ok, issues }`，用于检查 KV 绑定、API 密钥、PASSWORD 等是否就绪。
- **GET /**（未匹配路径）：返回服务名、版本及端点列表的 JSON。

**curl 示例：**

```bash
curl https://your-worker.workers.dev/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"model": "gemini-2.0-flash", "messages": [{"role": "user", "content": "Hello!"}], "stream": false}'
```

> 💡 模型名请以你账号实际可用的为准，可在面板「🆘 备用模型」的支持模型列表中查看。

### 3.5 管理面板

访问 **`/`** 或 **`/panel`**，使用 `PASSWORD` 登录。

- **🔑 Gemini 密钥**：添加/编辑/删除 API Key，总览 Key 总数、活跃、耗尽、今日调用；每 Key 状态（ACTIVE/EXHAUSTED/IDLE）、耗尽倒计时、单 Key/全部重置。
- **🎫 Access Tokens**：生成 Token（Label、最小访问间隔秒数）、查看调用次数与最后使用时间、吊销 Token；内置接入示例（OpenAI SDK / gemini-cli）。
- **🆘 备用模型**：配置全部 429 时使用的备用模型列表；支持模型列表约 6 小时从 Gemini API 更新，添加免费模型时校验名称。
- **📋 请求日志**：最近 50 条请求（时间、路径、模型、状态码、输入摘要、脱敏后的 API Key），可清空。

### 3.6 Key 轮转逻辑

- 每次请求按 Round-Robin 选 Key，跳过 `exhausted_until > now` 的 Key。
- 返回 429 时：标记该 Key `exhausted_until = now + 24h`，重试下一个 Key（最多 3 次）。
- 每日自动重置：按每个 Key 的 `last_reset`，满 24h 则 `daily_calls`/`daily_errors` 归零、`exhausted_until` 清除。
- 全部 Key 均 429 时：若配置了备用模型，用第一个备用模型再试一次；仍失败则返回 429。

### 3.7 接入示例

**OpenAI 兼容客户端（Python）：**

```python
from openai import OpenAI
client = OpenAI(base_url="https://your-worker.workers.dev/v1/", api_key="YOUR_TOKEN")
response = client.chat.completions.create(
    model="gemini-2.0-flash",   # 请替换为你账号实际可用的模型名
    messages=[{"role": "user", "content": "Hello!"}]
)
```

**gemini-cli（原生接口）：**

```bash
export GOOGLE_GEMINI_BASE_URL="https://your-worker.workers.dev"
export GEMINI_API_KEY="YOUR_TOKEN"
gemini "写一首关于代码的诗"
```

**Cherry Studio / OpenCat / NextChat 等：**
API Base URL: `https://your-worker.workers.dev/v1`，API Key: `YOUR_TOKEN`。

### 3.8 注意事项

1. **必须先创建至少一个 Access Token**，否则 `/v1/` 与 `/v1beta/` 请求会返回 401。
2. **Token 生成后只显示一次**，请立即复制保存。
3. **KV 绑定**：必须在 Cloudflare 创建 KV 并将变量名 `GEMINI_KV` 绑定到 Worker，否则面板与轮转状态无法持久化。
4. **Gemini 免费限额**由 Google 控制，代理通过多 Key 轮转与可选「备用模型」充分利用额度。
5. **模型可用性**：不同账号/区域可用的模型不同，接入前请先在面板确认你的账号实际支持哪些模型。

---

## 📄 License

MIT