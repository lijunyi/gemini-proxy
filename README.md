# Gemini Key Rotation Proxy  v2.0

基于 Cloudflare Workers 的 Gemini API 密钥轮转代理，支持 OpenAI 兼容接口与原生 Gemini 接口。

---

## 1. 基本用法

1. 访问面板 `/` 或 `/panel`，使用 `PASSWORD` 登录。
2. 在「🔑 Gemini 密钥」添加一个或多个 Gemini API Key。
3. 在「🎫 Access Tokens」创建访问令牌（Bearer Token）。
4. 用 OpenAI 兼容接口调用：

```bash
curl https://your-worker.workers.dev/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"model": "gemini-2.0-flash", "messages": [{"role": "user", "content": "Hello!"}], "stream": false}'
```

Gemini 原生接口：

```bash
curl https://your-worker.workers.dev/v1beta/models/gemini-2.0-flash:generateContent \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"contents":[{"parts":[{"text":"Hello!"}]}]}'
```

---

## 2. Cloudflare Workers 部署方法

### 2.1 前置要求

- Node.js 18+
- Cloudflare 账号
- 至少一个 Gemini API Key

### 2.2 安装 Wrangler 并登录

```bash
npm install -g wrangler
wrangler login
```

### 2.3 绑定 KV 命名空间

在 Cloudflare Dashboard 中为 Worker 绑定 KV（变量名必须为 `GEMINI_KV`）。

### 2.4 设置面板密码

```bash
wrangler secret put PASSWORD
```

### 2.5 部署

```bash
wrangler deploy
```

---

## 3. 本地部署调试

### 3.1 创建本地环境变量

在项目根目录创建 `.dev.vars`：

```
PASSWORD=admin
```

### 3.2 修改 wrangler.toml（本地 KV 绑定）

如需本地 KV 沙盒存储，请在 `wrangler.toml` 中取消注释 `[[kv_namespaces]]` 以及下面 `binding` 和 `id` 字段

### 3.3 运行本地开发服务器

```bash
npx wrangler dev
```

访问 `http://localhost:8787/` 或 `http://localhost:8787/panel`。

---

## 4. 实现的功能

- 多 Key 轮转：Round-Robin，429 自动跳 Key，默认 60 分钟后重试。
- OpenAI + Gemini 双接口：`/v1/` 与 `/v1beta/`。
- Access Token 管理：创建/吊销、最小访问间隔。
- 模型过滤：按访问令牌禁用指定模型，支持搜索。
- 支持模型列表：展示当前可用模型。
- 面板功能：统计、重置、日志查看、健康检查。
- 请求日志：固定 full 模式，最大长度 500，保留最近 100 条。
- 安全：面板密码保护，Token 哈希存储，API Key 脱敏显示。

---

## License

MIT
