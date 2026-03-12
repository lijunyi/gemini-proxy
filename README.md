# 💎 Gemini Key Rotation Proxy  v2.0

> 基于 **Cloudflare Workers** 的 Gemini API 密钥轮转代理，部署在 Cloudflare 边缘。  
> 使用 [Gemini 官方 OpenAI 兼容层](https://ai.google.dev/gemini-api/docs/openai?hl=zh-cn)，支持多 Key 轮转、访问密钥防滥用、可视化面板、自动配额清零。

---

## ✨ 功能特性

| 功能 | 说明 |
|------|------|
| 🔑 多 Key 轮转 | 在面板中配置多个 Gemini Key，Round-Robin，429 自动跳 Key，24h 后自动恢复 |
| 🔄 OpenAI + Gemini 双接口 | 支持 `/v1/`（OpenAI 兼容）与 `/v1beta/`（Gemini 原生） |
| 🎫 访问密钥防滥用 | 面板内一键生成/吊销 Bearer Token，可设单 Token 最小访问间隔（秒），API 调用需携带 Token |
| 📊 可视化面板 | 实时查看 Key 状态、调用量、错误数，30s 自动刷新 |
| 🔒 面板密码保护 | 通过环境变量 `PASSWORD` 设置，Session Cookie 验证 |
| ⚡ 额度自动清零 | 每日计数自动归零，耗尽 Key 24h 后自动解封；面板可手动重置 |
| 🆘 备用模型 | 全部 Key 429 时，可自动改用面板配置的备用模型（如免费模型）再试一次 |
| 📋 请求日志 | 面板内查看最近 50 条 API 请求（路径、状态、模型等），便于排查 |
| 🏠 默认即登录页 | 根路径 `/` 即为管理面板登录页 |
| 🌐 部署在 Cloudflare | Workers + KV，无需自建服务器 |

---

## 🏗️ 架构原理

```
用户请求
   │
   ├─ /v1/chat/completions  →  /v1beta/openai/chat/completions  ← 官方 OpenAI 兼容端点
   ├─ /v1/models            →  /v1beta/openai/models
   ├─ /v1beta/models/...    →  /v1beta/models/...               ← Gemini 原生透传
   └─ /panel                →  管理面板 (HTML)

Cloudflare Worker
   ├─ Token 验证（Bearer token against KV）
   ├─ Key 轮转器（Round-Robin，跳过 429 的 Key）
   └─ 透明转发 → generativelanguage.googleapis.com
                （自动注入 Gemini API Key）
```

> **v2 核心改变**：不再手写 OpenAI↔Gemini 协议转换。  
> Google 官方已在 `/v1beta/openai/` 提供完整 OpenAI 兼容层，本代理直接透传，  
> 支持 Function Calling、结构化输出、图片理解、流式输出等全部功能。

---

## 🚀 部署到 Cloudflare

本应用**最终部署在 Cloudflare**：使用 **Workers** 运行代理逻辑，使用 **KV** 存储 Key 状态与访问 Token。

### 前置要求

- Node.js 18+（用于运行 wrangler）
- [Cloudflare 账号](https://dash.cloudflare.com/sign-up)
- 若干 [Gemini API Key](https://aistudio.google.com/app/apikey)（逗号分隔，可多个）

### 1. 安装 Wrangler 并登录

```bash
npm install -g wrangler
wrangler login
```

### 2. 绑定 KV（控制台填自定义命名空间即可）

无需在 `wrangler.toml` 里写 KV 的 id，在 **Cloudflare 控制台** 绑定即可：

1. **创建 KV**（若还没有）：[Cloudflare Dashboard](https://dash.cloudflare.com) → **Workers & Pages** → **KV** → **创建命名空间**，名字自定义（例如 `ai`）。
2. **绑定到 Worker**：进入你的 Worker（如 `gemini-proxy`）→ **设置** → **绑定** → **添加绑定** → **KV 命名空间**：
   - **变量名称**填 **`GEMINI_KV`**（必须与代码一致）
   - **命名空间**选择你刚创建或已有的（自定义名称即可）→ **保存**。

### 3. 配置环境变量 / Secrets

以下变量可通过 **Cloudflare 仪表板** 或 **wrangler secret** 设置（二选一）：

| 变量 | 说明 | 示例 |
|------|------|------|
| `PASSWORD` | 管理面板登录密码 | 自定义强密码 |

**Gemini API 密钥**在登录面板后的「🔑 Gemini 密钥」中添加、编辑与删除，存储在 KV 中，无需环境变量。

**方式 A：Wrangler 命令行（推荐）**

```bash
wrangler secret put PASSWORD
# 输入你的面板密码
```

**方式 B：Cloudflare 仪表板**

1. 打开 [Workers & Pages](https://dash.cloudflare.com/?to=/:account/workers) → 选择你的 Worker（如 `gemini-proxy`）
2. **Settings** → **Variables and Secrets**
3. 添加 **Encrypted** 变量：`PASSWORD`

### 4. 部署

```bash
wrangler deploy
```

部署成功后得到 Worker 地址，例如：
```
https://gemini-proxy.你的子域.workers.dev
```

- **默认页面**：浏览器访问该根地址 `https://xxx.workers.dev/` 即为**管理面板登录页**。
- 使用上面设置的 `PASSWORD` 登录后，在「Gemini 密钥」中添加 API Key，可查看 Key 状态、生成访问 Token 等。

---

## 🎫 访问密钥（防滥用）

部署后建议第一时间在面板中**生成访问 Token**，避免代理被未授权使用。

1. 打开 Worker 根地址（即登录页）：`https://your-worker.workers.dev/` 或 `https://your-worker.workers.dev/panel`
2. 使用环境变量中设置的 `PANEL_PASSWORD` 登录
3. 切换到「🎫 Access Tokens」标签
4. 填写 Label（如 `gemini-cli`、`my-app`），点击「＋ Generate Token」
5. **立即复制生成的 Token**（只显示一次！）

> **重要**：**必须先创建至少一个 Token**，否则所有 API 请求都会返回 `401`（提示 "No access tokens configured"）。  
> 生成 Token 时可设置「最小访问间隔」（秒），默认 10 秒，设为 0 表示不限制，用于防止单 Token 被刷。

---

## 🌐 API 端点

### OpenAI 格式（推荐，兼容所有 OpenAI 客户端）

```
POST https://your-worker.workers.dev/v1/chat/completions
GET  https://your-worker.workers.dev/v1/models
POST https://your-worker.workers.dev/v1/embeddings
POST https://your-worker.workers.dev/v1/images/generations
```

**curl 示例：**
```bash
curl https://your-worker.workers.dev/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "model": "gemini-2.5-flash-preview-05-20",
    "messages": [{"role": "user", "content": "Hello!"}],
    "stream": false
  }'
```

### Gemini 原生格式（透明代理）

```
POST https://your-worker.workers.dev/v1beta/models/{model}:generateContent
POST https://your-worker.workers.dev/v1beta/models/{model}:streamGenerateContent
```

### 其他

- **GET /panel/health**：健康检查（无需登录），返回 `{ ok, issues }`，用于检查 KV 绑定、API 密钥、PASSWORD 等是否就绪。
- 对未匹配的路径发起 GET 请求时，返回服务名、版本及端点列表的 JSON。

---

## 🔌 接入 gemini-cli

gemini-cli 使用原生 Gemini 接口，通过环境变量指向本代理：

```bash
export GOOGLE_GEMINI_BASE_URL="https://your-worker.workers.dev"
export GEMINI_API_KEY="YOUR_TOKEN"    # 面板中生成的 Token

gemini "写一首关于代码的诗"
```

---

## 🔌 接入各类 OpenAI 客户端

**Python openai SDK：**
```python
from openai import OpenAI

client = OpenAI(
    base_url="https://your-worker.workers.dev/v1/",
    api_key="YOUR_TOKEN"
)

response = client.chat.completions.create(
    model="gemini-2.5-flash-preview-05-20",
    messages=[{"role": "user", "content": "Hello!"}]
)
```

**JavaScript openai SDK：**
```javascript
import OpenAI from "openai";

const openai = new OpenAI({
  baseURL: "https://your-worker.workers.dev/v1/",
  apiKey:  "YOUR_TOKEN",
});
```

**Cherry Studio / OpenCat / NextChat 等 GUI：**
- API Base URL: `https://your-worker.workers.dev/v1`
- API Key: `YOUR_TOKEN`
- 模型: `gemini-2.5-flash-preview-05-20`（或其他 Gemini 模型）

---

## 📊 管理面板功能

访问 **根路径 `/`** 或 **`/panel`**，使用配置的 `PASSWORD` 登录（默认页面即为登录页）。

**🔑 Gemini 密钥 标签：**
- 配置 API 密钥：添加、编辑、删除 Gemini API Key（存于 KV）
- 总览：Key 总数 / 活跃 / 耗尽 / 今日调用
- 每个 Key 的状态（ACTIVE / EXHAUSTED / IDLE）
- 实时倒计时：Key 耗尽后多久自动恢复
- 单 Key 重置 / 全部重置按钮

**🎫 Access Tokens 标签：**
- 生成新 Token（Label 标注用途，可设最小访问间隔秒数，默认 10，0 为不限制）
- 查看所有 Token 的调用次数、最后使用时间
- 一键吊销 Token
- 内置接入示例代码（OpenAI SDK / gemini-cli）

**🆘 备用模型 标签：**
- 配置当所有 Key 均 429 时自动换用的模型列表（如 `gemini-2.5-flash-lite`）
- 代理会使用列表中的第一个模型再试一次请求

**📋 请求日志 标签：**
- 查看最近 50 条 API 请求记录（时间、路径、方法、模型、状态码、请求/响应摘要）

---

## 🔄 Key 轮转逻辑

```
每次请求
  ↓
读取 KV 中 Round-Robin 索引
  ↓
遍历各 Key（从当前位置起）
  ├─ exhausted_until > now?  → 跳过
  └─ 可用 → 注入 ?key= 转发请求
                ↓
          返回 429？
          ├─ Yes → 标记 exhausted_until = now + 24h
          │        重试下一个 Key（最多 3 次）
          └─ No  → 记录调用统计，返回响应

每日自动重置（基于每个 Key 的 last_reset 时间）
  → daily_calls = 0
  → daily_errors = 0
  → exhausted_until = null

全部 Key 均返回 429 时
  → 若面板中配置了「备用模型」列表，自动改用第一个备用模型再试一次
  → 仍失败则返回 429
```

---

## ⚙️ 环境变量参考（Cloudflare）

| 变量名 | 必填 | 说明 | 示例 |
|--------|------|------|------|
| `PASSWORD` | ✅ | 管理面板登录密码（Cloudflare 环境变量/Secret） | 自定义强密码 |

- **KV 命名空间**：需在 Cloudflare 创建并绑定 `GEMINI_KV`，用于存储 API 密钥、Key 状态与访问 Token。
- **Gemini API 密钥**在面板「🔑 Gemini 密钥」中添加、编辑、删除。
- 访问密钥（Bearer Token）在**面板内生成与吊销**，无需在环境变量中配置。

---

## 🛠️ 本地调试（建议先本地跑通再部署）

**说明**：`PASSWORD` 仅用于**登录管理面板**；API 调用需在登录面板后生成的**访问 Token**（Bearer），二者不同。

### 1. 安装 Wrangler（二选一）

```bash
npm install -g wrangler
# 或使用 npx，无需全局安装
```

### 2. 配置本地环境变量

在项目根目录创建 `.dev.vars`（已加入 .gitignore，不会提交）：

```
PASSWORD=admin
```

登录面板后，在「🔑 Gemini 密钥」中添加你的 Gemini API Key。

### 3. 本地 KV（可选）

若尚未在 Cloudflare 创建 KV，本地可用 `--local` 使用内存 KV。若已创建，在 **Cloudflare 控制台** 将 Worker 绑定 KV 命名空间（变量名 `GEMINI_KV`），或取消注释 `wrangler.toml` 中 `[[kv_namespaces]]` 并填写 `id`。

### 4. 启动本地服务

```bash
npx wrangler dev
# 若已全局安装：wrangler dev
```

浏览器访问 **http://localhost:8787/** 或 **http://localhost:8787/panel**，应看到登录页；密码填 `.dev.vars` 里的 `PASSWORD`。登录后先在「Gemini 密钥」中添加 API Key，再在「Access Tokens」中生成 API 用的 Bearer Token。

若出现 **Worker Error** 页面，会显示具体错误信息，便于排查（例如缺少 `GEMINI_KV` 绑定或环境变量）。

---

## 📌 注意事项

1. **部署后若只看到 “Hello World”**：请确认部署的是本仓库的 `worker.js`，且 `wrangler.toml` 中 `main = "worker.js"`。重新执行 `wrangler deploy` 后再访问根路径 `/`，应看到登录页。
2. **部署后必须先创建 Token**：未创建任何 Token 时，所有 `/v1/` 与 `/v1beta/` 请求都会返回 401，需在面板「Access Tokens」中生成至少一个 Token 后，API 才可用。
3. **Token 只显示一次**：生成后立即复制，无法再次查看完整 Token。
4. **KV 与 GEMINI_KV**：需在 Cloudflare 创建 KV 命名空间，并在 Worker 设置中绑定变量名 `GEMINI_KV`（或在 `wrangler.toml` 中配置 `[[kv_namespaces]]`），否则面板与轮转状态无法持久化。
5. **Gemini 官方免费限额**：每个 Key 的免费用量由 Google 控制，代理通过多 Key 轮转与可选「备用模型」充分利用免费额度。

---

## 📄 License

MIT
