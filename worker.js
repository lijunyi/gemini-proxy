/**
  * Gemini Key Rotation Proxy — Cloudflare Workers  v2.0
  *
  * ┌──────────────────────────────────────────────────────────────┐
  * │  Architecture (based on official Gemini OpenAI compat docs)  │
  * │                                                              │
  * │  OpenAI format  →  /v1beta/openai/...   (official endpoint)  │
  * │  Gemini native  →  /v1beta/models/...   (direct passthrough) │
  * │                                                              │
  * │  No manual protocol conversion needed — Google handles it.   │
  * └──────────────────────────────────────────────────────────────┘
  *
  * Environment Variables (set via `wrangler secret put`):
  *   PASSWORD  Panel login password  (default: "admin")
  *   (Gemini API keys are configured in the panel, stored in KV)
  *
  * KV Namespace Binding (wrangler.toml):
  *   GEMINI_KV       Stores key state, stats, and access tokens
  */

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTS & KV KEYS
// ─────────────────────────────────────────────────────────────────────────────

const GEMINI_BASE = 'https://generativelanguage.googleapis.com';
const COOKIE_NAME = 'gproxy_sess';
const DAY_MS      = 86_400_000;

// KV key names & prefixes（统一管理，便于后续维护）
const KV_KEY_API_KEYS             = 'cfg:api_keys';
const KV_KEY_SUPPORTED_MODELS     = 'cfg:supported_models_raw';
const KV_KEY_SUPPORTED_FETCHED_AT = 'cfg:supported_models_fetched_at';
const KV_KEY_FALLBACK_MODELS      = 'cfg:fallback_models';
const KV_KEY_LOG_ENTRIES          = 'log:entries';
// cfg:token_index 存储所有 thash 的数组，用 kvGet/kvSet 维护，
// 绕过 CF Workers KV list 操作的最终一致性延迟（最长 60s），
// 从根本上解决令牌列表不显示的问题。
const KV_KEY_TOKEN_INDEX          = 'cfg:token_index';
const KV_KEY_ROUND_ROBIN_INDEX    = 'rr_idx';
const KV_PREFIX_KEYSTATE          = 'ks:';
const KV_PREFIX_TOKEN             = 'tok:';
const KV_PREFIX_RATE_LIMIT        = 'rl:';
const KV_PREFIX_SESSION           = 'sess:';

// ─────────────────────────────────────────────────────────────────────────────
// SECURITY HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * 时序安全的字符串比较，防止时序攻击（timing attack）。
 * 使用随机 HMAC Key 对两个字符串分别签名后做逐字节 XOR 比较。
 */
async function timingSafeEqual(a, b) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const [sigA, sigB] = await Promise.all([
        crypto.subtle.sign('HMAC', key, enc.encode(a)),
        crypto.subtle.sign('HMAC', key, enc.encode(b)),
    ]);
    const arrA = new Uint8Array(sigA);
    const arrB = new Uint8Array(sigB);
    let diff = 0;
    for (let i = 0; i < arrA.length; i++) diff |= arrA[i] ^ arrB[i];
    return diff === 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// IN-PROCESS CACHE（Worker 实例生命周期内有效，减少 KV 读次数）
// ─────────────────────────────────────────────────────────────────────────────

const _modelsCache = { names: /** @type {string[]|null} */ (null), fetchedAt: 0 };

// ─────────────────────────────────────────────────────────────────────────────
// KV HELPERS
// ─────────────────────────────────────────────────────────────────────────────

async function kvGet(env, key) {
    if (!env.GEMINI_KV) return null;
    try { return await env.GEMINI_KV.get(key, 'json'); } catch { return null; }
}

async function kvSet(env, key, value, ttl) {
    if (!env.GEMINI_KV) return;
    const opts = ttl ? { expirationTtl: ttl } : undefined;
    try { await env.GEMINI_KV.put(key, JSON.stringify(value), opts); } catch {}
}

async function kvDelete(env, key) {
    if (!env.GEMINI_KV) return;
    try { await env.GEMINI_KV.delete(key); } catch {}
}

async function kvList(env, prefix) {
    if (!env.GEMINI_KV) return [];
    try {
        const all = [];
        let cursor;
        do {
            const result = await env.GEMINI_KV.list({ prefix, cursor, limit: 1000 });
            all.push(...(result.keys || []));
            cursor = result.list_complete ? undefined : result.cursor;
        } while (cursor);
        return all;
    } catch { return []; }
}

// ─────────────────────────────────────────────────────────────────────────────
// API KEYS (stored in KV, configured in panel)
// ─────────────────────────────────────────────────────────────────────────────

async function getApiKeys(env) {
    const raw = await kvGet(env, KV_KEY_API_KEYS);
    if (Array.isArray(raw)) return raw.filter(k => typeof k === 'string' && k.trim());
    return [];
}

async function setApiKeys(env, keys) {
    const list = Array.isArray(keys) ? keys.filter(k => typeof k === 'string' && k.trim()) : [];
    await kvSet(env, KV_KEY_API_KEYS, list);
}

// ─────────────────────────────────────────────────────────────────────────────
// KEY UTILITIES
// ─────────────────────────────────────────────────────────────────────────────

async function keyHash(key) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key));
    return Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
}

function maskKey(key) {
    if (!key || key.length < 10) return '****';
    return key.slice(0, 6) + '••••••••' + key.slice(-4);
}

function maskKeyForLog(key) {
    if (!key || key.length < 12) return '****';
    const head = key.slice(0, 6);
    const tail = key.slice(-6);
    const stars = '*'.repeat(Math.max(4, key.length - 12));
    return head + stars + tail;
}

// ─────────────────────────────────────────────────────────────────────────────
// KEY STATE
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULT_STATE = () => ({
    total_calls:     0,
    total_errors:    0,
    daily_calls:     0,
    daily_errors:    0,
    last_used:       null,
    last_error:      null,
    last_error_code: null,
    exhausted_until: null,          // Key 级别的耗尽截止时间（在没有模型信息时使用）
    exhausted_by_model: {},         // 模型级别的耗尽截止时间（short name → ts）
    model_stats:     {},            // 每个模型的累计调用与错误统计（short name → { total_calls, total_errors }）
    last_reset:      Date.now(),
});

async function getKeyState(env, kid) {
    const raw = (await kvGet(env, KV_PREFIX_KEYSTATE + kid)) || DEFAULT_STATE();
    // 防御性校验：确保字段存在且类型正确，避免 KV 中异常数据导致崩溃
    if (!raw || typeof raw !== 'object') return DEFAULT_STATE();
    if (!('exhausted_by_model' in raw) || typeof raw.exhausted_by_model !== 'object' || raw.exhausted_by_model === null) {
        raw.exhausted_by_model = {};
    }
    if (!('model_stats' in raw) || typeof raw.model_stats !== 'object' || raw.model_stats === null) {
        raw.model_stats = {};
    }
    return raw;
}

async function saveKeyState(env, kid, state) {
    await kvSet(env, KV_PREFIX_KEYSTATE + kid, state);
}

async function resetKeyState(env, kid) {
    const s = await getKeyState(env, kid);
    // 手动重置：清空当日与累计统计以及模型级明细，恢复为"全新"状态
    s.daily_calls     = 0;
    s.daily_errors    = 0;
    s.total_calls     = 0;
    s.total_errors    = 0;
    s.model_stats     = {};
    s.exhausted_until = null;
    s.exhausted_by_model = {};
    s.last_reset      = Date.now();
    await saveKeyState(env, kid, s);
}

// ─────────────────────────────────────────────────────────────────────────────
// KEY ROTATION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * 选择一个可用的 API Key。
 * @param {any} env
 * @param {string|null} modelShort 当前请求使用的模型 short name（如 "gemini-2.5-pro"），用于按模型维度跳过已耗尽的 key。
 */
async function pickKey(env, modelShort = null) {
    const keys = await getApiKeys(env);
    if (!keys.length) throw new Error('No API keys configured');
    const now = Date.now();

    let idx = (await kvGet(env, KV_KEY_ROUND_ROBIN_INDEX)) ?? 0;
    if (typeof idx !== 'number' || isNaN(idx)) idx = 0;

    // 并发预取所有 Key 的 hash 与状态，避免串行 KV 读（Fix #5）
    const kids   = await Promise.all(keys.map(k => keyHash(k)));
    const states = await Promise.all(kids.map(kid => getKeyState(env, kid)));

    // 自动每日重置：并发写入所有需要重置的 Key，不阻塞主流程
    const resetPromises = [];
    for (let i = 0; i < keys.length; i++) {
        const state = states[i];
        if (state.last_reset && (now - state.last_reset) >= DAY_MS) {
            state.daily_calls        = 0;
            state.daily_errors       = 0;
            state.last_reset         = now;
            state.exhausted_until    = null;
            state.exhausted_by_model = {};
            resetPromises.push(saveKeyState(env, kids[i], state));
        }
    }
    if (resetPromises.length) await Promise.all(resetPromises);

    // 找第一个可用 Key（round-robin 起点）
    for (let i = 0; i < keys.length; i++) {
        const pos   = (idx + i) % keys.length;
        const state = states[pos];

        // 优先按模型维度判断是否已耗尽；若未提供模型名，则使用 Key 级别的 exhausted_until
        if (modelShort && state.exhausted_by_model && typeof state.exhausted_by_model === 'object') {
            const ts = state.exhausted_by_model[modelShort];
            if (typeof ts === 'number' && ts > now) continue;
        } else if (state.exhausted_until && state.exhausted_until > now) {
            continue;
        }

        await kvSet(env, KV_KEY_ROUND_ROBIN_INDEX, (pos + 1) % keys.length);
        return { key: keys[pos], kid: kids[pos], state, pos };
    }

    // 全部耗尽：仍按 round-robin 顺序返回（Fix #1），确保调用方每次重试拿到不同的 Key，
    // 而不是每次都打到 keys[0]，让上层日志可以完整记录每个 Key 的 429。
    const pos = idx % keys.length;
    await kvSet(env, KV_KEY_ROUND_ROBIN_INDEX, (pos + 1) % keys.length);
    return { key: keys[pos], kid: kids[pos], state: states[pos], pos };
}

/**
 * 记录某个 Key 在一次请求中的成功调用。
 * @param {any} env
 * @param {string} kid key 的 hash
 * @param {any} state 当前 key 状态对象
 * @param {string|null} modelShort 当前请求使用的模型 short name（如 "gemini-2.5-pro"）
 */
async function onKeySuccess(env, kid, state, modelShort = null) {
    state.total_calls = (state.total_calls || 0) + 1;
    state.daily_calls = (state.daily_calls || 0) + 1;
    state.last_used   = Date.now();
    if (modelShort) {
        if (!state.model_stats || typeof state.model_stats !== 'object') state.model_stats = {};
        const ms = state.model_stats[modelShort] || { total_calls: 0, total_errors: 0 };
        ms.total_calls = (ms.total_calls || 0) + 1;
        ms.total_errors = ms.total_errors || 0;
        state.model_stats[modelShort] = ms;
    }
    await saveKeyState(env, kid, state);
}

/**
 * 记录某个 Key 在一次请求中的错误。
 * @param {any} env
 * @param {string} kid key 的 hash
 * @param {any} state 当前 key 状态对象
 * @param {number} statusCode HTTP 状态码
 * @param {string|null} modelShort 当前请求使用的模型 short name（如 "gemini-2.5-pro"）
 */
async function onKeyError(env, kid, state, statusCode, modelShort = null) {
    state.total_errors  = (state.total_errors  || 0) + 1;
    state.daily_errors  = (state.daily_errors  || 0) + 1;
    state.last_error    = Date.now();
    state.last_error_code = statusCode;
    if (modelShort) {
        if (!state.model_stats || typeof state.model_stats !== 'object') state.model_stats = {};
        const ms = state.model_stats[modelShort] || { total_calls: 0, total_errors: 0 };
        ms.total_errors = (ms.total_errors || 0) + 1;
        ms.total_calls = ms.total_calls || 0;
        state.model_stats[modelShort] = ms;
    }
    if (statusCode === 429) {
        const until = Date.now() + DAY_MS;
        // 若有模型信息，则只标记该模型已耗尽；否则退回到旧的“整 Key 封禁”逻辑
        if (modelShort) {
            if (!state.exhausted_by_model || typeof state.exhausted_by_model !== 'object') {
                state.exhausted_by_model = {};
            }
            state.exhausted_by_model[modelShort] = until;
        } else {
            state.exhausted_until = until;
        }
    }
    await saveKeyState(env, kid, state);
}

// ─────────────────────────────────────────────────────────────────────────────
// ACCESS TOKEN MANAGEMENT  (stored in KV under "tok:{token}")
// ─────────────────────────────────────────────────────────────────────────────

const ALPHANUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
function generateToken() {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    const suffix = Array.from(arr, b => ALPHANUM[b % ALPHANUM.length]).join('');
    return 'token-' + suffix;
}

async function tokenHash(token) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('tok-v2:' + token));
    return Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('').slice(0, 24);
}

/** 真实 token 脱敏：前6位 + 星号 + 后6位（仅创建时保存，用于列表预览） */
function maskTokenForPreview(token) {
    if (!token || token.length < 12) return '••••••••••••';
    return token.slice(0, 6) + '••••••••••' + token.slice(-6);
}

// ── Token Index helpers ─────────────────────────────────────────────────────
// CF Workers KV 的 list() 操作是最终一致的（最多延迟 60s），
// 导致刚创建的 token 无法立即在列表中显示。
// 解决方案：用一个独立索引 key（cfg:token_index）维护所有 thash 的数组，
// 读写均走 kvGet / kvSet（强一致），彻底绕过 kvList 的一致性问题。

async function getTokenIndex(env) {
    const raw = await kvGet(env, KV_KEY_TOKEN_INDEX);
    return Array.isArray(raw) ? raw : [];
}

async function addToTokenIndex(env, thash) {
    const index = await getTokenIndex(env);
    if (!index.includes(thash)) {
        index.push(thash);
        await kvSet(env, KV_KEY_TOKEN_INDEX, index);
    }
}

async function removeFromTokenIndex(env, thash) {
    const index = await getTokenIndex(env);
    const updated = index.filter(h => h !== thash);
    await kvSet(env, KV_KEY_TOKEN_INDEX, updated);
}

/** rate_limit_sec: 最小访问间隔（秒），0=不限制，默认 10 */
async function createToken(env, label, rateLimitSec) {
    const token = generateToken();
    const thash = await tokenHash(token);
    const sec   = rateLimitSec === 0 ? 0 : (Math.max(0, Math.min(3600, parseInt(rateLimitSec, 10) || 10)));
    const data  = { label: label || 'Token', created_at: Date.now(), last_used: null, calls: 0, rate_limit_sec: sec, token_preview: maskTokenForPreview(token) };
    // 同时写入 token 数据与索引，两者均使用强一致的 kvSet
    await kvSet(env, KV_PREFIX_TOKEN + thash, data);
    await addToTokenIndex(env, thash);
    return { token, thash, ...data };
}

async function listTokens(env) {
    // 从索引读取所有 thash（kvGet，强一致），再并发拉取每个 token 的数据
    const thashes = await getTokenIndex(env);
    if (!thashes.length) return [];
    const results = await Promise.all(thashes.map(h => kvGet(env, KV_PREFIX_TOKEN + h)));
    const tokens  = [];
    for (let i = 0; i < thashes.length; i++) {
        const data = results[i];
        // data 为 null 表示该 token 已被直接删除但索引未清理，跳过即可
        if (data) tokens.push({ thash: thashes[i], ...data });
    }
    return tokens.sort((a, b) => b.created_at - a.created_at);
}

async function revokeToken(env, thash) {
    await Promise.all([
        kvDelete(env, KV_PREFIX_TOKEN + thash),
        removeFromTokenIndex(env, thash),
    ]);
}

/** @returns {{ ok: boolean, message?: string, statusCode?: number }} */
async function validateToken(env, token) {
    if (!token) return { ok: false, message: 'Unauthorized: provide a valid Bearer token', statusCode: 401 };
    const thash = await tokenHash(token);
    const data  = await kvGet(env, KV_PREFIX_TOKEN + thash);
    if (!data) return { ok: false, message: 'Unauthorized: provide a valid Bearer token', statusCode: 401 };

    // 速率限制：用独立 TTL Key 作为"已使用"标记，避免 read-modify-write 竞态
    // 两个并发请求仍可能同时通过（KV 无原子操作），但窗口极小且不影响安全性
    const intervalSec = data.rate_limit_sec !== undefined ? data.rate_limit_sec : 10;
    if (intervalSec > 0) {
        const lockKey = KV_PREFIX_RATE_LIMIT + thash;
        const locked  = await kvGet(env, lockKey);
        if (locked) {
            return { ok: false, message: `访问过于频繁，请 ${intervalSec} 秒后再试`, statusCode: 429 };
        }
        // 写入锁，TTL = intervalSec；并发时后写覆盖先写，效果等同延续锁
        await kvSet(env, lockKey, 1, intervalSec);
    }

    // 异步更新调用统计（best-effort，不阻塞响应）
    // 注意：高并发下计数存在最终一致性偏差，属已知限制
    data.last_used = Date.now();
    data.calls     = (data.calls || 0) + 1;
    await kvSet(env, 'tok:' + thash, data);
    return { ok: true };
}

// ─────────────────────────────────────────────────────────────────────────────
// SUPPORTED MODELS (from GET /v1beta/models, refreshed every 6h)
// ─────────────────────────────────────────────────────────────────────────────

const SUPPORTED_MODELS_TTL_SEC = 6 * 3600; // 6 小时

/** 归一化：models/gemini-pro-latest → gemini-pro-latest */
function toShortModelName(name) {
    if (typeof name !== 'string') return '';
    const s = name.trim();
    return s.startsWith('models/') ? s.slice(7) : s;
}

// ─────────────────────────────────────────────────────────────────────────────
// FALLBACK MODELS (free models when quota exhausted, stored in KV)
// ─────────────────────────────────────────────────────────────────────────────

async function getSupportedModelsRaw(env) {
    const raw = await kvGet(env, KV_KEY_SUPPORTED_MODELS);
    return Array.isArray(raw) ? raw : [];
}
async function getSupportedModelsFetchedAt(env) {
    const v = await kvGet(env, KV_KEY_SUPPORTED_FETCHED_AT);
    return typeof v === 'number' && !isNaN(v) ? v : 0;
}
async function setSupportedModelsRaw(env, names, fetchedAt) {
    await kvSet(env, KV_KEY_SUPPORTED_MODELS, names);
    await kvSet(env, KV_KEY_SUPPORTED_FETCHED_AT, fetchedAt);
}
/**
 * 若列表为空或距上次刷新超过 6 小时，用任一 API Key 拉取 /v1beta/models 并更新 KV。
 * 优先使用进程内缓存（_modelsCache），避免每次请求都读 KV。
 * 成功后过滤 fallback_models，移除不在新支持列表中的项。
 */
async function maybeRefreshSupportedModels(env) {
    const now = Date.now();
    // 进程内缓存命中：直接返回，完全跳过 KV 读
    if (_modelsCache.names && (now - _modelsCache.fetchedAt) < SUPPORTED_MODELS_TTL_SEC * 1000) return;

    const keys = await getApiKeys(env);
    if (!keys.length) return;
    const fetchedAt = await getSupportedModelsFetchedAt(env);
    if (fetchedAt > 0 && (now - fetchedAt) < SUPPORTED_MODELS_TTL_SEC * 1000) {
        // KV 缓存仍有效，回填进程内缓存
        const raw = await getSupportedModelsRaw(env);
        if (raw.length) { _modelsCache.names = raw; _modelsCache.fetchedAt = fetchedAt; }
        return;
    }
    // 轮询所有 Key，避免 keys[0] 已耗尽时无法刷新模型列表（Fix #4）
    let data;
    let fetchOk = false;
    for (const key of keys) {
        const url = GEMINI_BASE + '/v1beta/models?key=' + encodeURIComponent(key);
        let resp;
        try { resp = await fetch(url); } catch (_) { continue; }
        if (!resp.ok) continue;
        try { data = await resp.json(); fetchOk = true; break; } catch (_) { continue; }
    }
    if (!fetchOk || !data) return;
    const names = Array.isArray(data.models) ? data.models.map(m => (m && m.name) || '').filter(Boolean) : [];
    await setSupportedModelsRaw(env, names, now);
    // 回填进程内缓存
    _modelsCache.names = names;
    _modelsCache.fetchedAt = now;
    const shortSet = new Set(names.map(toShortModelName));
    const fallback = await getFallbackModels(env);
    const filtered = fallback.filter(m => shortSet.has(toShortModelName(m)));
    if (filtered.length !== fallback.length) await setFallbackModels(env, filtered);
}

async function getFallbackModels(env) {
    const raw = await kvGet(env, KV_KEY_FALLBACK_MODELS);
    if (Array.isArray(raw)) return raw.filter(m => typeof m === 'string' && m.trim());
    return [];
}
async function setFallbackModels(env, models) {
    const list = Array.isArray(models) ? models.filter(m => typeof m === 'string' && m.trim()) : [];
    await kvSet(env, KV_KEY_FALLBACK_MODELS, list);
}

// ─────────────────────────────────────────────────────────────────────────────
// REQUEST LOG (last 50 entries in KV)
// ─────────────────────────────────────────────────────────────────────────────

const LOG_MAX = 50;

async function appendLogs(env, entries) {
    if (!env.GEMINI_KV) return;
    if (!Array.isArray(entries) || !entries.length) return;
    try {
        const raw = await env.GEMINI_KV.get(KV_KEY_LOG_ENTRIES, 'json');
        const list = Array.isArray(raw) ? raw : [];
        for (const entry of entries) {
            list.unshift(entry);
        }
        await env.GEMINI_KV.put(KV_KEY_LOG_ENTRIES, JSON.stringify(list.slice(0, LOG_MAX)));
    } catch (_) {}
}

async function getLogs(env) {
    if (!env.GEMINI_KV) return [];
    try {
        const raw = await env.GEMINI_KV.get(KV_KEY_LOG_ENTRIES, 'json');
        return Array.isArray(raw) ? raw : [];
    } catch (_) { return []; }
}

/** @returns {{ ok: boolean, message?: string, statusCode?: number }} */
async function checkApiAuth(req, env) {
    const auth  = req.headers.get('Authorization') || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
    // 直接验证 token，省去每次 kvList 扫描（O(n) KV 操作）
    const valid = await validateToken(env, token);
    if (!valid.ok) return { ok: false, message: valid.message || 'Unauthorized', statusCode: valid.statusCode || 401 };
    return { ok: true };
}

// ─────────────────────────────────────────────────────────────────────────────
// PANEL AUTH  (password → session cookie)
// ─────────────────────────────────────────────────────────────────────────────

/** 创建随机 session，存入 KV（TTL 24h），返回 sessionId */
async function createSession(env) {
    const arr = new Uint8Array(32);
    crypto.getRandomValues(arr);
    const sessionId = Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
    await kvSet(env, KV_PREFIX_SESSION + sessionId, { created_at: Date.now() }, 86400);
    return sessionId;
}

/** 销毁 session（登出时调用） */
async function destroySession(env, req) {
    const cookie = req.headers.get('Cookie') || '';
    const m = cookie.match(new RegExp(COOKIE_NAME + '=([^;]+)'));
    if (m) await kvDelete(env, KV_PREFIX_SESSION + m[1]);
}

/** 验证 session cookie 是否存在于 KV */
async function isAuthenticated(req, env) {
    const cookie = req.headers.get('Cookie') || '';
    const m = cookie.match(new RegExp(COOKIE_NAME + '=([^;]+)'));
    if (!m) return false;
    const session = await kvGet(env, KV_PREFIX_SESSION + m[1]);
    return !!session;
}

// ─────────────────────────────────────────────────────────────────────────────
// CORE PROXY  (with key retry on 429)
// ─────────────────────────────────────────────────────────────────────────────

/**
  * Forward a request to Gemini, injecting a rotated API key.
  * targetPath: the Gemini path to forward to (e.g. "/v1beta/openai/chat/completions")
  * When all keys return 429, if fallback models are configured, retries once with first fallback model.
  */
async function proxyToGemini(req, env, targetPath, maxRetries = 3, ctx) {
    const originalUrl = new URL(req.url);
    const keys        = await getApiKeys(env);
    if (!keys.length) {
        return jsonError('No API keys configured. Add keys in the panel (/) first.', 503);
    }
    const tries     = Math.min(keys.length, maxRetries);
    const logBuffer = [];

    // 重试前缓存 body：ReadableStream 只能消费一次，否则 429 重试时 POST 体为空
    let bodyBuffer = (req.method !== 'GET' && req.method !== 'HEAD')
        ? await req.arrayBuffer()
        : undefined;

    // Fix #10：拆分为两个语义独立的标志
    //   modelReplaced — 预处理阶段：请求模型不在支持列表中，已预先替换为备用模型
    //   fallbackTried — 运行时阶段：所有 Key 都 429 后，已尝试切换备用模型重试
    let modelReplaced = false;
    let fallbackTried = false;

    await maybeRefreshSupportedModels(env);
    let originalModel = null;
    let modelShort    = null; // 归一化后的模型名（如 gemini-2.5-pro）

    // Fix #3：bodyBuffer 只解析一次，缓存为 parsedBody 供后续日志复用，避免循环内重复 decode + parse
    let parsedBody = null;
    if (bodyBuffer) {
        try { parsedBody = JSON.parse(new TextDecoder().decode(bodyBuffer)); } catch (_) {}
    }

    if (parsedBody && typeof parsedBody.model === 'string') {
        // 记录用户最初请求的模型，供日志展示，避免因回退/归一化导致"看起来像用了别的模型"
        originalModel = parsedBody.model;
        const supportedRaw = await getSupportedModelsRaw(env);
        if (supportedRaw.length > 0) {
            const shortSet = new Set(supportedRaw.map(toShortModelName));
            if (!shortSet.has(toShortModelName(parsedBody.model))) {
                const fallbackModels = await getFallbackModels(env);
                if (fallbackModels[0]) {
                    parsedBody.model = fallbackModels[0];
                    modelReplaced = true; // 预处理阶段已替换，运行时无需再 fallback
                }
            }
        }
        // 统一为 models/xxx 再转发，避免同一模型因格式不同被 Google 计入不同配额导致 429
        if (parsedBody.model && !parsedBody.model.startsWith('models/')) {
            parsedBody.model = 'models/' + parsedBody.model;
        }
        modelShort = toShortModelName(parsedBody.model);
        bodyBuffer = new TextEncoder().encode(JSON.stringify(parsedBody)).buffer;
    }

    // 对于 Gemini 原生接口，如果 body 中没有显式 model 字段，则从路径中提取
    if (!modelShort && targetPath.startsWith('/v1beta/models/')) {
        const after     = targetPath.slice('/v1beta/models/'.length);
        const modelPart = after.split(':', 1)[0];
        if (modelPart) modelShort = toShortModelName(modelPart);
    }

    // 预先准备日志用的 input 摘要（Fix #3：不在循环内重复解析）
    const logInput = parsedBody
        ? (typeof parsedBody === 'object' ? JSON.stringify(parsedBody) : String(parsedBody)).slice(0, 500)
        : null;

    while (true) {
        for (let attempt = 0; attempt < tries; attempt++) {
            const { key, kid, state } = await pickKey(env, modelShort);

            const url = new URL(GEMINI_BASE + targetPath);
            originalUrl.searchParams.forEach((v, k) => { if (k !== 'key') url.searchParams.set(k, v); });
            url.searchParams.set('key', key);

            const fwdHeaders = new Headers();
            for (const [k, v] of req.headers) {
                const kl = k.toLowerCase();
                if (kl === 'authorization' || kl === 'host') continue;
                fwdHeaders.set(k, v);
            }
            // 仅当原始请求为 JSON（或未指定）时才强制设置 Content-Type，
            // 保留 multipart/form-data 等其他格式（如多模态上传）
            const origCT = (req.headers.get('Content-Type') || '').toLowerCase();
            if (!origCT || origCT.includes('application/json')) {
                fwdHeaders.set('Content-Type', 'application/json');
            }
            fwdHeaders.set('x-goog-api-key', key);
            // 仅 OpenAI 兼容层 /v1beta/openai/ 需要 Bearer；原生 /v1beta/models/ 用 Bearer 会报 ACCESS_TOKEN_TYPE_UNSUPPORTED
            if (targetPath.startsWith('/v1beta/openai/')) {
                fwdHeaders.set('Authorization', 'Bearer ' + key);
            }

            const resp = await fetch(url.toString(), {
                method:  req.method,
                headers: fwdHeaders,
                body:    bodyBuffer,
            });

            if (resp.status === 429) {
                // 记录本次 429 错误到 Key 状态与日志，然后尝试下一个 Key
                if (ctx) ctx.waitUntil(onKeyError(env, kid, state, 429, modelShort));
                else await onKeyError(env, kid, state, 429, modelShort);
                logBuffer.push({ ts: Date.now(), path: targetPath, method: req.method,
                    model: originalModel || modelShort || null, status: 429,
                    input: logInput, redirect: url.toString(), api_key: maskKeyForLog(key) });
                continue;
            }

            if (!resp.ok) {
                if (ctx) ctx.waitUntil(onKeyError(env, kid, state, resp.status, modelShort));
                else await onKeyError(env, kid, state, resp.status, modelShort);
            } else {
                if (ctx) ctx.waitUntil(onKeySuccess(env, kid, state, modelShort));
                else await onKeySuccess(env, kid, state, modelShort);
            }

            // 日志优先展示"用户请求的原始模型"，而非代理内部回退/归一化后的模型
            logBuffer.push({ ts: Date.now(), path: targetPath, method: req.method,
                model: originalModel || (parsedBody && parsedBody.model) || null,
                status: resp.status, input: logInput, redirect: url.toString(), api_key: maskKeyForLog(key) });

            const outHeaders = new Headers(resp.headers);
            outHeaders.set('Access-Control-Allow-Origin',  '*');
            outHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
            outHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
            if (logBuffer.length) {
                const logsToWrite = logBuffer.splice(0, logBuffer.length);
                if (ctx) ctx.waitUntil(appendLogs(env, logsToWrite));
                else await appendLogs(env, logsToWrite);
            }
            return new Response(resp.body, { status: resp.status, headers: outHeaders });
        }

        // 所有 Key 均返回 429 — 若配置了备用模型且尚未尝试，切换后重试一次（Fix #10）
        if (modelReplaced || fallbackTried || !bodyBuffer || !parsedBody) break;
        const fallbackModels = await getFallbackModels(env);
        if (!fallbackModels.length) break;
        if (typeof parsedBody.model === 'string') {
            const fallbackName = fallbackModels[0];
            parsedBody.model = fallbackName.startsWith('models/') ? fallbackName : 'models/' + fallbackName;
            modelShort = toShortModelName(parsedBody.model);
            bodyBuffer = new TextEncoder().encode(JSON.stringify(parsedBody)).buffer;
            fallbackTried = true;
            continue;
        }
        break;
    }

    if (logBuffer.length) {
        const logsToWrite = logBuffer.splice(0, logBuffer.length);
        if (ctx) ctx.waitUntil(appendLogs(env, logsToWrite));
        else await appendLogs(env, logsToWrite);
    }
    return jsonError('All API keys are exhausted (429). Please try again later.', 429);
}

// ─────────────────────────────────────────────────────────────────────────────
// SIMPLE HELPERS
// ─────────────────────────────────────────────────────────────────────────────

function jsonResp(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });
}

function jsonError(msg, status = 500) {
    return jsonResp({ error: { message: msg, type: 'error', code: status } }, status);
}

// 需要 KV 的路由：未绑定时返回明确错误，避免静默失效
function requireKV(env) {
    if (!env.GEMINI_KV) return jsonResp(
        { error: '未绑定 KV 命名空间（GEMINI_KV），请在 Cloudflare Worker 设置中绑定' },
        503
    );
    return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// PANEL ROUTES
// ─────────────────────────────────────────────────────────────────────────────

async function handlePanelHealth(req, env) {
    const issues = [];
    if (!env.GEMINI_KV)   issues.push({ key: 'kv', msg: '未绑定 KV 命名空间（GEMINI_KV），Key 状态与 Token 无法持久化' });
    const keys = await getApiKeys(env);
    if (!keys.length) issues.push({ key: 'keys', msg: '未配置 API 密钥，请在面板「Gemini 密钥」中添加' });
    if (!(env.PASSWORD || '').trim()) issues.push({ key: 'password', msg: '未配置 PASSWORD，建议设置以保护面板' });
    return jsonResp({ ok: issues.length === 0, issues });
}

async function handlePanelLogin(req, env) {
    let body;
    try { body = await req.json(); } catch { return jsonError('Invalid JSON', 400); }
    const inputPw    = (body.password || '').trim();
    const expectedPw = (env.PASSWORD || '').trim();
    if (!expectedPw) return jsonResp({ ok: false, error: '未配置 PASSWORD，请在 Cloudflare Worker 变量中设置' }, 401);
    const match = await timingSafeEqual(inputPw, expectedPw);
    if (!match) {
        return jsonResp({ ok: false, error: '密码错误' }, 401);
    }
    const sessionId = await createSession(env);
    return new Response(JSON.stringify({ ok: true }), {
        headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': COOKIE_NAME + '=' + sessionId + '; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400',
        },
    });
}

async function handlePanelLogout(req, env) {
    await destroySession(env, req);
    return new Response(JSON.stringify({ ok: true }), {
        headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': COOKIE_NAME + '=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0',
        },
    });
}

async function handlePanelStats(req, env) {
    if (!await isAuthenticated(req, env)) return jsonResp({ error: 'Unauthorized' }, 401);
    const kvErr = requireKV(env); if (kvErr) return kvErr;
    const keys = await getApiKeys(env);
    const now  = Date.now();
    const stats = [];
    // 并发预取所有 Key 的 hash 与状态（Fix #5）
    const kids   = await Promise.all(keys.map(k => keyHash(k)));
    const states = await Promise.all(kids.map(kid => getKeyState(env, kid)));
    for (let i = 0; i < keys.length; i++) {
        const kid   = kids[i];
        const state = states[i];
        const exByModel = state.exhausted_by_model || {};
        const modelStats = state.model_stats && typeof state.model_stats === 'object' ? state.model_stats : {};
        const models = [];
        let exhaustedFlag = false;
        let exhaustedUntil = state.exhausted_until && typeof state.exhausted_until === 'number' ? state.exhausted_until : null;
        for (const m of Object.keys(modelStats)) {
            const ms = modelStats[m] || {};
            const ts = typeof exByModel[m] === 'number' ? exByModel[m] : null;
            const isExhausted = !!(ts && ts > now);
            if (isExhausted) {
                exhaustedFlag = true;
                if (!exhaustedUntil || ts > exhaustedUntil) exhaustedUntil = ts;
            }
            models.push({
                model:         m,
                total_calls:   ms.total_calls || 0,
                total_errors:  ms.total_errors || 0,
                exhausted:     isExhausted,
                exhausted_until: ts,
            });
        }
        stats.push({
            index: i, kid,
            masked:          maskKey(keys[i]),
            total_calls:     state.total_calls    || 0,
            total_errors:    state.total_errors   || 0,
            daily_calls:     state.daily_calls    || 0,
            daily_errors:    state.daily_errors   || 0,
            last_used:       state.last_used,
            last_error:      state.last_error,
            last_error_code: state.last_error_code,
            exhausted:       exhaustedFlag,
            exhausted_until: exhaustedUntil,
            last_reset:      state.last_reset,
            models,
        });
    }
    return jsonResp({ ok: true, total: keys.length, keys: stats });
}

async function handlePanelReset(req, env) {
    if (!await isAuthenticated(req, env)) return jsonResp({ error: 'Unauthorized' }, 401);
    const kvErr = requireKV(env); if (kvErr) return kvErr;
    const kid = new URL(req.url).searchParams.get('kid');
    if (kid === 'all') {
        const keys = await getApiKeys(env);
        // 并发 reset 所有 Key（Fix #9）
        await Promise.all(keys.map(async k => resetKeyState(env, await keyHash(k))));
        await kvSet(env, KV_KEY_ROUND_ROBIN_INDEX, 0);
        return jsonResp({ ok: true, message: 'All keys reset' });
    }
    if (!kid) return jsonError('Missing kid parameter', 400);
    await resetKeyState(env, kid);
    return jsonResp({ ok: true, message: 'Key reset' });
}

async function handleTokenCreate(req, env) {
    if (!await isAuthenticated(req, env)) return jsonResp({ error: 'Unauthorized' }, 401);
    const kvErr = requireKV(env); if (kvErr) return kvErr;
    let body = {};
    try { body = await req.json(); } catch {}
    const result = await createToken(env, body.label, body.rate_limit_sec);
    return jsonResp({ ok: true, ...result });
}

async function handleTokenList(req, env) {
    if (!await isAuthenticated(req, env)) return jsonResp({ error: 'Unauthorized' }, 401);
    const kvErr = requireKV(env); if (kvErr) return kvErr;
    const tokens = await listTokens(env);
    const masked = tokens.map(t => ({
        label:          t.label,
        thash:          t.thash,
        token_preview:  t.token_preview || (t.thash.slice(0, 6) + '••••••••••••' + t.thash.slice(-4)),
        created_at:     t.created_at,
        last_used:      t.last_used,
        calls:          t.calls,
        rate_limit_sec: t.rate_limit_sec !== undefined ? t.rate_limit_sec : 10,
    }));
    return jsonResp({ ok: true, tokens: masked });
}

async function handleTokenRevoke(req, env) {
    if (!await isAuthenticated(req, env)) return jsonResp({ error: 'Unauthorized' }, 401);
    const kvErr = requireKV(env); if (kvErr) return kvErr;
    const thash = new URL(req.url).searchParams.get('thash');
    if (!thash) return jsonError('Missing thash parameter', 400);
    await revokeToken(env, thash);
    return jsonResp({ ok: true, message: 'Token revoked' });
}

async function handleApiKeysGet(req, env) {
    if (!await isAuthenticated(req, env)) return jsonResp({ error: 'Unauthorized' }, 401);
    const kvErr = requireKV(env); if (kvErr) return kvErr;
    const keys = await getApiKeys(env);
    const list = keys.map((k, i) => ({ index: i, masked: maskKey(k) }));
    return jsonResp({ ok: true, keys: list });
}

async function handleApiKeysPost(req, env) {
    if (!await isAuthenticated(req, env)) return jsonResp({ error: 'Unauthorized' }, 401);
    const kvErr = requireKV(env); if (kvErr) return kvErr;
    let body = {};
    try { body = await req.json(); } catch { return jsonError('Invalid JSON', 400); }
    const key = (body.key || '').trim();
    if (!key) return jsonError('请提供 key', 400);
    // Gemini API Key 格式校验（AIza 开头，共 39 字符）
    if (!/^AIza[0-9A-Za-z_\-]{35}$/.test(key)) {
        return jsonError('API Key 格式不正确（应以 AIza 开头，共 39 个字符）', 400);
    }
    const keys = await getApiKeys(env);
    if (keys.includes(key)) return jsonResp({ ok: false, error: '该 API Key 已存在' }, 400);
    keys.push(key);
    await setApiKeys(env, keys);
    return jsonResp({ ok: true, keys: keys.map((k, i) => ({ index: i, masked: maskKey(k) })) });
}

async function handleApiKeysPut(req, env) {
    if (!await isAuthenticated(req, env)) return jsonResp({ error: 'Unauthorized' }, 401);
    const kvErr = requireKV(env); if (kvErr) return kvErr;
    let body = {};
    try { body = await req.json(); } catch { return jsonError('Invalid JSON', 400); }
    const index = typeof body.index === 'number' ? body.index : parseInt(body.index, 10);
    const key = (body.key || '').trim();
    if (!key) return jsonError('请提供 key', 400);
    // 格式校验
    if (!/^AIza[0-9A-Za-z_\-]{35}$/.test(key)) {
        return jsonError('API Key 格式不正确（应以 AIza 开头，共 39 个字符）', 400);
    }
    const keys = await getApiKeys(env);
    if (index < 0 || index >= keys.length) return jsonError('无效的 index', 400);
    // 清理旧 Key 的孤儿状态
    const oldKid = await keyHash(keys[index]);
    await kvDelete(env, KV_PREFIX_KEYSTATE + oldKid);
    keys[index] = key;
    await setApiKeys(env, keys);
    await kvSet(env, KV_KEY_ROUND_ROBIN_INDEX, 0);
    return jsonResp({ ok: true, keys: keys.map((k, i) => ({ index: i, masked: maskKey(k) })) });
}

async function handleApiKeysDelete(req, env) {
    if (!await isAuthenticated(req, env)) return jsonResp({ error: 'Unauthorized' }, 401);
    const kvErr = requireKV(env); if (kvErr) return kvErr;
    const index = parseInt(new URL(req.url).searchParams.get('index'), 10);
    if (isNaN(index) || index < 0) return jsonError('请提供有效的 index 查询参数', 400);
    const keys = await getApiKeys(env);
    if (index >= keys.length) return jsonError('无效的 index', 400);
    // 清理被删除 Key 的孤儿状态
    const oldKid = await keyHash(keys[index]);
    await kvDelete(env, KV_PREFIX_KEYSTATE + oldKid);
    keys.splice(index, 1);
    await setApiKeys(env, keys);
    await kvSet(env, KV_KEY_ROUND_ROBIN_INDEX, 0);
    return jsonResp({ ok: true, keys: keys.map((k, i) => ({ index: i, masked: maskKey(k) })) });
}

async function handleFallbackModelsGet(req, env) {
    if (!await isAuthenticated(req, env)) return jsonResp({ error: 'Unauthorized' }, 401);
    const kvErr = requireKV(env); if (kvErr) return kvErr;
    await maybeRefreshSupportedModels(env);
    const models = await getFallbackModels(env);
    const fetchedAt = await getSupportedModelsFetchedAt(env);
    const supportedRaw = await getSupportedModelsRaw(env);
    return jsonResp({ ok: true, models, supported_fetched_at: fetchedAt, supported_count: supportedRaw.length });
}

async function handleFallbackModelsPut(req, env) {
    if (!await isAuthenticated(req, env)) return jsonResp({ error: 'Unauthorized' }, 401);
    const kvErr = requireKV(env); if (kvErr) return kvErr;
    let body = {};
    try { body = await req.json(); } catch { return jsonError('Invalid JSON', 400); }
    const models = Array.isArray(body.models) ? body.models.map(m => String(m).trim()).filter(Boolean) : [];
    await maybeRefreshSupportedModels(env);
    const supportedRaw = await getSupportedModelsRaw(env);
    if (supportedRaw.length > 0) {
        const shortSet = new Set(supportedRaw.map(toShortModelName));
        for (const m of models) {
            if (!shortSet.has(toShortModelName(m))) {
                return jsonResp({ ok: false, error: '模型不在当前支持列表中，请核对名称：' + m }, 400);
            }
        }
    }
    await setFallbackModels(env, models);
    return jsonResp({ ok: true, models });
}

async function handlePanelLogs(req, env) {
    if (!await isAuthenticated(req, env)) return jsonResp({ error: 'Unauthorized' }, 401);
    const kvErr = requireKV(env); if (kvErr) return kvErr;
    const entries = await getLogs(env);
    return jsonResp({ ok: true, logs: entries });
}

async function handlePanelLogsClear(req, env) {
    if (!await isAuthenticated(req, env)) return jsonResp({ error: 'Unauthorized' }, 401);
    const kvErr = requireKV(env); if (kvErr) return kvErr;
    try {
        await env.GEMINI_KV.put(KV_KEY_LOG_ENTRIES, JSON.stringify([]));
        return jsonResp({ ok: true });
    } catch (e) {
        return jsonError('清空日志失败', 500);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PANEL HTML
// ─────────────────────────────────────────────────────────────────────────────

const PANEL_HTML = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Gemini 代理 · 管理面板</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet"/>
<style>
:root{
    --bg:#f0f4f8;--s1:#fff;--s2:#f8fafc;--s3:#eef2f6;
    --b1:#e2e8f0;--b2:#cbd5e1;
    --tx:#334155;--tx2:#64748b;--txh:#0f172a;
    --bl:#0ea5e9;--bl2:#0284c7;
    --gn:#059669;--gn2:#047857;
    --yl:#d97706;--yl2:#b45309;
    --rd:#dc2626;--rd2:#b91c1c;
    --warn:#fef3c7;
    --pu:#7c3aed;--pu2:#6d28d9;
    --mono:'Fira Code',monospace;--sans:'Syne',sans-serif;
}
*{margin:0;padding:0;box-sizing:border-box}
html{scroll-behavior:smooth}
body{font-family:var(--sans);background:var(--bg);color:var(--tx);min-height:100vh;
    background-image:
        radial-gradient(ellipse 80% 50% at 10% -10%,rgba(14,165,233,.08) 0%,transparent 55%),
        radial-gradient(ellipse 60% 40% at 90% 110%,rgba(5,150,105,.06) 0%,transparent 55%)}

/* Login */
#login{display:flex;align-items:center;justify-content:center;min-height:100vh}
.lw{width:380px}
.lhead{text-align:center;margin-bottom:40px}
.licon{font-size:48px;margin-bottom:14px;display:block;
    filter:drop-shadow(0 0 16px rgba(14,165,233,.25))}
.ltit{font-size:22px;font-weight:700;color:var(--txh);letter-spacing:.04em}
.lsub{font-size:11px;color:var(--tx2);margin-top:6px;letter-spacing:.16em;text-transform:uppercase}
.card{background:var(--s1);border:1px solid var(--b1);border-radius:12px;padding:32px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
label{display:block;font-size:10px;font-weight:600;letter-spacing:.14em;text-transform:uppercase;color:var(--tx2);margin-bottom:8px}
input[type=password],input[type=text]{width:100%;background:var(--s2);border:1px solid var(--b1);border-radius:7px;
    padding:11px 14px;color:var(--txh);font-family:var(--mono);font-size:13px;outline:none;
    transition:border .18s,box-shadow .18s}
input:focus{border-color:var(--bl);box-shadow:0 0 0 3px rgba(14,165,233,.15)}
.fg{margin-bottom:18px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;
    padding:10px 18px;border-radius:7px;border:none;font-size:13px;font-weight:600;
    cursor:pointer;transition:all .15s;font-family:var(--sans);white-space:nowrap}
.btn:active{transform:scale(.97)}
.btn-pri{background:var(--bl);color:#fff;width:100%}
.btn-pri:hover{background:var(--bl2);box-shadow:0 2px 12px rgba(14,165,233,.35)}
.btn-out{background:var(--s1);color:var(--tx);border:1px solid var(--b1)}
.btn-out:hover{border-color:var(--b2);background:var(--s2)}
.btn-gn{background:rgba(5,150,105,.1);color:var(--gn);border:1px solid rgba(5,150,105,.3)}
.btn-gn:hover{background:rgba(5,150,105,.15)}
.btn-rd{background:rgba(220,38,38,.08);color:var(--rd);border:1px solid rgba(220,38,38,.25)}
.btn-rd:hover{background:rgba(220,38,38,.12)}
.btn-pu{background:rgba(124,58,237,.08);color:var(--pu);border:1px solid rgba(124,58,237,.25)}
.btn-pu:hover{background:rgba(124,58,237,.12)}
.btn-sm{padding:5px 12px;font-size:11px}
.btn-xs{padding:3px 9px;font-size:10px}
.lerr{font-size:12px;color:var(--rd);text-align:center;min-height:18px;margin-top:12px}

/* Dashboard — 1 / 2 / 3 三块统一在同一容器内，左右完全对齐 */
#dash{display:none;width:100%;min-height:100vh}
.dash-shell{width:100%;max-width:1280px;margin:0 auto;padding:0 24px;box-sizing:border-box}
.health-banner{display:flex;align-items:center;justify-content:space-between;gap:12px;
    padding:10px 16px;background:var(--warn);color:#333;font-size:13px;
    border-bottom:1px solid rgba(0,0,0,.1)}
.hdr{display:flex;align-items:center;justify-content:space-between;
    padding:14px 18px;border-bottom:1px solid var(--b1);background:var(--s1);
    box-shadow:0 1px 2px rgba(0,0,0,.04);position:sticky;top:0;z-index:10}
.hlogo{font-size:15px;font-weight:700;color:var(--txh);display:flex;align-items:center;gap:9px}
.hlogo span{color:var(--bl)}
.htags{display:flex;gap:6px}
.htag{font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;
    padding:2px 8px;border-radius:20px;border:1px solid}
.htag-b{color:var(--bl);border-color:rgba(14,165,233,.35);background:rgba(14,165,233,.08)}
.htag-g{color:var(--gn);border-color:rgba(5,150,105,.35);background:rgba(5,150,105,.06)}
.hright{display:flex;align-items:center;gap:8px}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}

/* Nav tabs */
.navtabs{display:flex;gap:2px;padding:16px 0 0;border-bottom:1px solid var(--b1);background:var(--s1)}
.navtab{padding:9px 18px;font-size:12px;font-weight:600;cursor:pointer;border-radius:7px 7px 0 0;
    color:var(--tx2);border:1px solid transparent;border-bottom:none;transition:all .15s;
    position:relative;bottom:-1px}
.navtab.active{background:var(--s2);color:var(--txh);border-color:var(--b1);border-bottom:2px solid var(--bl)}
.navtab:not(.active):hover{color:var(--tx);background:var(--s2)}

/* Content */
.content{padding:24px 0}

/* Stat grid */
.sg{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
.sc{background:var(--s1);border:1px solid var(--b1);border-radius:10px;padding:18px;
    position:relative;overflow:hidden;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.sc::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.sc.cb::before{background:linear-gradient(90deg,var(--bl),var(--bl2))}
.sc.cg::before{background:linear-gradient(90deg,var(--gn),var(--gn2))}
.sc.cr::before{background:linear-gradient(90deg,var(--rd),var(--rd2))}
.sc.cy::before{background:linear-gradient(90deg,var(--yl),var(--yl2))}
.sc.cp::before{background:linear-gradient(90deg,var(--pu),var(--pu2))}
.slbl{font-size:11px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--tx2);margin-bottom:10px}
.snum{font-family:var(--mono);font-size:28px;font-weight:600;line-height:1}
.snum.bl{color:var(--bl)}.snum.gn{color:var(--gn)}
.snum.rd{color:var(--rd)}.snum.yl{color:var(--yl)}.snum.pu{color:var(--pu)}

/* Panel box */
.pbox{background:var(--s1);border:1px solid var(--b1);border-radius:10px;overflow:hidden;margin-bottom:20px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.phead{display:flex;align-items:center;justify-content:space-between;
    padding:14px 18px;border-bottom:1px solid var(--b1);background:var(--s2)}
.ptit{font-size:13px;font-weight:600;color:var(--txh)}
.pacts{display:flex;gap:7px;align-items:center}

/* Table */
table{width:100%;border-collapse:collapse}
th{font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;
    color:var(--tx2);text-align:left;padding:9px 16px;border-bottom:1px solid var(--b1);
    background:var(--s2)}
td{padding:12px 16px;font-size:12px;border-bottom:1px solid var(--b1);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--s2)}
.mono{font-family:var(--mono);font-size:11px;color:var(--tx2);letter-spacing:.04em}
.monohi{font-family:var(--mono);font-size:11px;color:var(--txh)}
.num{font-family:var(--mono);font-size:13px}
.nb{color:var(--bl)}.ng{color:var(--gn)}.nr{color:var(--rd)}.nd{color:var(--tx2)}
.ts{font-size:10px;color:var(--tx2);font-family:var(--mono)}
.badge{display:inline-flex;align-items:center;gap:4px;font-size:10px;font-weight:600;
    padding:3px 8px;border-radius:4px;letter-spacing:.06em}
.bg-active{background:rgba(5,150,105,.1);color:var(--gn);border:1px solid rgba(5,150,105,.25)}
.bg-exhaust{background:rgba(220,38,38,.08);color:var(--rd);border:1px solid rgba(220,38,38,.25)}
.bg-idle{background:var(--s2);color:var(--tx2);border:1px solid var(--b1)}
.bdot{width:5px;height:5px;border-radius:50%;background:currentColor}
.bg-active .bdot{animation:blink 1.8s infinite}
.cdwn{font-size:10px;color:var(--yl);font-family:var(--mono);margin-left:4px}
.empty-row td{text-align:center;padding:40px;color:var(--tx2)}
table:has(#log-tbody) th:nth-child(4){white-space:nowrap}

/* Token section */
.newtoken{background:rgba(0,232,154,.06);border:1px solid rgba(0,232,154,.2);
    border-radius:8px;padding:14px 18px;margin-bottom:14px;display:none}
.newtoken.show{display:block}
.tokval{font-family:var(--mono);font-size:12px;color:var(--gn);word-break:break-all;
    background:var(--s2);border:1px solid rgba(5,150,105,.3);border-radius:6px;
    padding:10px 12px;margin:10px 0;cursor:pointer;transition:background .15s}
.tokval:hover{background:rgba(5,150,105,.08)}
.tokwarn{font-size:11px;color:var(--yl);display:flex;align-items:center;gap:5px}
.tokform{display:flex;gap:8px;align-items:center}
.tokform input{flex:1;min-width:0}

/* Copy feedback */
.copybtn{cursor:pointer;transition:color .2s}
.copybtn:hover{color:var(--bl)}

/* Toast：显示在 hdr 上方、居中，稍大 */
#toast{position:fixed;top:24px;left:50%;z-index:100;
    background:var(--s1);border:1px solid var(--b1);border-radius:10px;
    padding:14px 22px;font-size:14px;color:var(--txh);
    box-shadow:0 4px 20px rgba(0,0,0,.15);
    transform:translate(-50%,-80px);opacity:0;transition:all .3s cubic-bezier(.34,1.56,.64,1)}
#toast.show{transform:translate(-50%,0);opacity:1}
#toast.ok{border-color:rgba(5,150,105,.4)}#toast.err{border-color:rgba(220,38,38,.4)}

/* Tab panels */
.tabpanel{display:none}.tabpanel.active{display:block}

@media(max-width:800px){
    .sg{grid-template-columns:repeat(2,1fr)}
    .hdr,.navtabs,.content{padding-left:14px;padding-right:14px}
    .htags{display:none}
}
</style>
</head>
<body>

<!-- ── 登录 ── -->
<div id="login">
    <div class="lw">
        <div class="lhead">
            <span class="licon">💎</span>
            <div class="ltit">GEMINI 代理</div>
            <div class="lsub">密钥轮转 · 管理面板</div>
        </div>
        <div class="card">
            <div class="fg">
                <label>面板密码</label>
                <input type="password" id="pw" placeholder="请输入密码…" autocomplete="current-password"/>
            </div>
            <button class="btn btn-pri" id="lbtn" onclick="doLogin()">登录</button>
            <div class="lerr" id="lerr"></div>
        </div>
    </div>
</div>

<!-- ── 仪表盘 ── -->
<div id="dash">
    <div id="health-banner" class="health-banner" style="display:none">
        <span id="health-banner-msg"></span>
        <button type="button" class="btn btn-xs" onclick="document.getElementById('health-banner').style.display='none'">关闭</button>
    </div>
    <div class="dash-shell">
        <div class="hdr">
            <div style="display:flex;align-items:center;gap:12px">
                <div class="hlogo">💎 <span>GEMINI</span> 代理</div>
                <div class="htags">
                    <span class="htag htag-b">密钥轮转</span>
                    <span class="htag htag-g">OPENAI 兼容</span>
                </div>
            </div>
            <div class="hright">
                <button class="btn btn-out btn-sm" onclick="loadAll()">↻ 刷新</button>
                <button class="btn btn-out btn-sm" onclick="doLogout()">退出</button>
            </div>
        </div>

        <div class="navtabs">
        <div class="navtab active" id="tab-keys"   onclick="switchTab('keys')">🔑 Gemini 密钥</div>
        <div class="navtab"        id="tab-tokens" onclick="switchTab('tokens')">🎫 访问令牌</div>
        <div class="navtab"        id="tab-models" onclick="switchTab('models')">🔄 默认模型</div>
        <div class="navtab"        id="tab-log"    onclick="switchTab('log')">📋 日志</div>
    </div>

        <div class="content">

        <!-- 统计 -->
        <div class="sg" id="stats-grid">
            <div class="sc cb"><div class="slbl">密钥总数</div><div class="snum bl" id="s-total">—</div></div>
            <div class="sc cg"><div class="slbl">活跃密钥</div><div class="snum gn" id="s-active">—</div></div>
            <div class="sc cr"><div class="slbl">已耗尽</div><div class="snum rd" id="s-exhaust">—</div></div>
            <div class="sc cy"><div class="slbl">今日调用</div><div class="snum yl" id="s-today">—</div></div>
        </div>

        <!-- 密钥 Tab -->
        <div class="tabpanel active" id="tp-keys">
            <div class="pbox" style="margin-bottom:14px">
                <div class="phead">
                    <div class="ptit">配置 API 密钥</div>
                </div>
                <div style="padding:18px">
                    <p style="font-size:12px;color:var(--tx2);margin-bottom:14px">在此添加 Gemini API 密钥，代理将轮转使用。可编辑或删除已有密钥。</p>
                    <div style="display:flex;gap:10px;align-items:flex-end;margin-bottom:18px">
                        <div class="fg" style="flex:1;margin:0">
                            <label style="margin-bottom:6px">API Key</label>
                            <input type="password" id="api-key-input" placeholder="AIzaSy..." style="width:100%" autocomplete="off"/>
                        </div>
                        <button class="btn btn-gn" onclick="addApiKey()">＋ 添加</button>
                    </div>
                    <table>
                        <thead><tr><th>密钥</th><th>操作</th></tr></thead>
                        <tbody id="api-keys-tbody"><tr class="empty-row"><td colspan="2">加载中…</td></tr></tbody>
                    </table>
                </div>
            </div>
            <div class="pbox">
                <div class="phead">
                    <div class="ptit">Gemini API 密钥</div>
                    <div class="pacts">
                        <button class="btn btn-rd btn-sm" onclick="resetAll()">↺ 全部重置额度</button>
                    </div>
                </div>
                <table>
                    <thead><tr>
                        <th>#</th><th>密钥</th><th>状态</th>
                        <th>总调用</th><th>今日</th><th>错误</th>
                        <th>模型明细</th><th>最后使用</th><th>操作</th>
                    </tr></thead>
                    <tbody id="keys-tbody"><tr class="empty-row"><td colspan="9">加载中…</td></tr></tbody>
                </table>
            </div>
        </div>

        <!-- 令牌 Tab -->
        <div class="tabpanel" id="tp-tokens">

            <!-- 新令牌展示 -->
            <div class="newtoken" id="new-token-box">
                <div class="tokwarn">⚠️ 请立即复制此令牌，关闭后无法再次查看</div>
                <div class="tokval" id="new-token-val" onclick="copyToken(this)" title="点击复制">—</div>
                <div style="display:flex;align-items:center;justify-content:space-between">
                    <span class="ts" style="color:var(--tx2)">点击令牌可复制</span>
                    <button class="btn btn-out btn-xs" onclick="closeNewToken()">关闭</button>
                </div>
            </div>

            <!-- 创建令牌 -->
            <div class="pbox" style="margin-bottom:14px">
                <div class="phead">
                    <div class="ptit">创建访问令牌</div>
                </div>
                <div style="padding:16px 18px;display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
                    <div class="fg" style="flex:1;min-width:160px;margin:0">
                        <label style="margin-bottom:7px;display:block">备注（选填）</label>
                        <input type="text" id="tok-label" placeholder="如：gemini-cli、我的应用…" style="width:100%"/>
                    </div>
                    <div class="fg" style="width:140px;margin:0">
                        <label style="margin-bottom:7px;display:block">访问间隔（秒）</label>
                        <input type="number" id="tok-rate-limit" min="0" max="3600" value="10" placeholder="10=默认 0=不限制" style="width:100%"/>
                    </div>
                    <button class="btn btn-gn" onclick="createToken()" style="margin-bottom:0">＋ 生成令牌</button>
                </div>
            </div>

            <!-- 令牌列表 -->
            <div class="pbox">
                <div class="phead">
                    <div class="ptit">当前访问令牌</div>
                    <div class="pacts">
                        <span class="ts" id="tok-count">—</span>
                    </div>
                </div>
                <table>
                    <thead><tr>
                        <th>备注</th><th>令牌预览</th><th>创建时间</th>
                        <th>最后使用</th><th>访问间隔</th><th>调用次数</th><th>操作</th>
                    </tr></thead>
                    <tbody id="tokens-tbody"><tr class="empty-row"><td colspan="7">加载中…</td></tr></tbody>
                </table>
            </div>

            <!-- 使用说明 -->
            <div class="pbox">
                <div class="phead"><div class="ptit">使用说明</div></div>
                <div style="padding:18px;display:flex;flex-direction:column;gap:12px">

                    <!-- 1. OpenAI API 示例 -->
                    <div style="background:var(--s2);border:1px solid var(--b1);border-radius:8px;padding:14px">
                        <div style="font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--bl);margin-bottom:10px">OPENAI API · ${'cu'+'rl'}</div>
                        <pre style="font-family:var(--mono);font-size:11px;color:var(--tx);white-space:pre-wrap;line-height:1.7">${'cu'+'rl'} https://你的Worker地址/v1/chat/completions \\
    -H "Content-Type: application/json" \\
    -H "Authorization: Bearer 你的令牌" \\
    -d '{
        "model": "gemini-2.5-flash-lite",
        "messages": [
            {"role": "user", "content": "你好"}
        ]
    }'</pre>
                    </div>

                    <!-- 2. Gemini API 示例 -->
                    <div style="background:var(--s2);border:1px solid var(--b1);border-radius:8px;padding:14px">
                        <div style="font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--gn);margin-bottom:10px">GEMINI API · ${'cu'+'rl'}</div>
                        <pre style="font-family:var(--mono);font-size:11px;color:var(--tx);white-space:pre-wrap;line-height:1.7">${'cu'+'rl'} https://你的Worker地址/v1beta/models/gemini-2.5-flash-lite:generateContent \\
    -H "Content-Type: application/json" \\
    -H "Authorization: Bearer 你的令牌" \\
    -d '{
        "contents": [
            {"parts": [{"text": "你好"}]}
        ]
    }'</pre>
                    </div>

                    <!-- 3. GEMINI-CLI -->
                    <div style="background:var(--s2);border:1px solid var(--b1);border-radius:8px;padding:14px">
                        <div style="font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--gn);margin-bottom:10px">GEMINI-CLI</div>
                        <pre style="font-family:var(--mono);font-size:11px;color:var(--tx);white-space:pre-wrap;line-height:1.7">export GOOGLE_GEMINI_BASE_URL="https://你的Worker地址"
export GEMINI_API_KEY="你的令牌"

gemini "你好！"</pre>
                    </div>

                </div>
            </div>
        </div>

        <!-- 默认模型 Tab -->
        <div class="tabpanel" id="tp-models">
            <div class="pbox">
                <div class="phead">
                    <div class="ptit">额度耗尽时使用的免费模型</div>
                </div>
                <div style="padding:18px">
                    <p style="font-size:12px;color:var(--tx2);margin-bottom:14px">当所有密钥返回 429 时，将自动把请求中的模型替换为下列第一个模型并重试一次。可配置多个免费模型（如 gemini-2.5-flash、gemini-2.5-flash-lite）。</p>
                    <p id="supported-models-hint" style="font-size:11px;color:var(--tx2);margin-bottom:14px">支持模型列表：共 <span id="supported-count">—</span> 个，上次更新于 <span id="supported-fetched-at">—</span>（约 6 小时自动刷新）</p>
                    <div style="display:flex;gap:10px;align-items:flex-end;margin-bottom:18px">
                        <div class="fg" style="flex:1;margin:0">
                            <label style="margin-bottom:6px">模型 ID</label>
                            <input type="text" id="fallback-model-input" placeholder="如 gemini-2.5-flash-lite" style="width:100%"/>
                        </div>
                        <button class="btn btn-gn" onclick="addFallbackModel()">＋ 添加</button>
                    </div>
                    <table>
                        <thead><tr><th>模型</th><th>操作</th></tr></thead>
                        <tbody id="fallback-models-tbody"><tr class="empty-row"><td colspan="2">加载中…</td></tr></tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- 日志 Tab -->
        <div class="tabpanel" id="tp-log">
            <div class="pbox">
                <div class="phead">
                    <div class="ptit">最近 50 条请求日志</div>
                    <div class="pacts">
                        <button class="btn btn-out btn-sm" onclick="loadLogs()">↻ 刷新</button>
                        <button class="btn btn-out btn-sm btn-rd" onclick="clearLogs()">清空</button>
                    </div>
                </div>
                <div style="padding:18px;max-height:70vh;overflow:auto">
                    <table>
                        <thead><tr><th>时间</th><th>路径</th><th>模型</th><th>状态</th><th>输入</th><th>API Key</th></tr></thead>
                        <tbody id="log-tbody"><tr class="empty-row"><td colspan="6">加载中…</td></tr></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<div id="toast"></div>

<script>
var _tab = 'keys';

function switchTab(t) {
    _tab = t;
    document.querySelectorAll('.navtab').forEach(function (el) { el.classList.remove('active'); });
    document.querySelectorAll('.tabpanel').forEach(function (el) { el.classList.remove('active'); });
    var tabEl = document.getElementById('tab-' + t);
    var panelEl = document.getElementById('tp-' + t);
    if (tabEl) tabEl.classList.add('active');
    if (panelEl) panelEl.classList.add('active');
    if (t === 'keys') loadApiKeys();
    if (t === 'tokens') loadTokens();
    if (t === 'models') loadFallbackModels();
    if (t === 'log') loadLogs();
}

function toast(msg,type){
    var el=document.getElementById('toast');
    el.textContent=msg; el.className='show '+(type||'ok');
    setTimeout(function(){el.className=''},3000);
}

function timeAgo(ts){
    if(!ts) return '—';
    var d=Date.now()-ts;
    if(d<60000) return Math.floor(d/1000)+' 秒前';
    if(d<3600000) return Math.floor(d/60000)+' 分钟前';
    if(d<86400000) return Math.floor(d/3600000)+' 小时前';
    return Math.floor(d/86400000)+' 天前';
}

function formatDate(ts){
    if(!ts) return '—';
    return new Date(ts).toLocaleString();
}

function countdown(u){
    if(!u) return '';
    var r=u-Date.now();
    if(r<=0) return '重置中…';
    var h=Math.floor(r/3600000), m=Math.floor((r%3600000)/60000);
    return h+' 小时 '+m+' 分钟';
}

async function doLogin(){
    var pw=document.getElementById('pw').value;
    var btn=document.getElementById('lbtn');
    btn.textContent='…'; btn.disabled=true;
    try{
        var r=await fetch('/panel/login',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({password:pw}),credentials:'include'});
        var d=await r.json();
        if(d.ok){ showDash(); }
        else{ document.getElementById('lerr').textContent=d.error||'密码错误'; }
    }catch(e){ document.getElementById('lerr').textContent='网络错误'; }
    btn.textContent='Sign In'; btn.disabled=false;
}

async function doLogout() {
    await fetch('/panel/logout', { method: 'POST', credentials: 'include' });
    document.getElementById('dash').style.display = 'none';
    document.getElementById('login').style.display = 'flex';
    document.getElementById('pw').value = '';
    document.getElementById('lerr').textContent = '';
}

function showDash() {
    document.getElementById('login').style.display = 'none';
    document.getElementById('dash').style.display = 'block';
    loadHealth();
    loadAll();
}

async function loadHealth(){
    try{
        var r=await fetch('/panel/health',{credentials:'include'});
        var d=await r.json();
        var ban=document.getElementById('health-banner');
        var msg=document.getElementById('health-banner-msg');
        if(d.issues&&d.issues.length&&ban&&msg){
            msg.textContent=d.issues.map(function(i){return i.msg;}).join('；');
            ban.style.display='flex';
        }else if(ban) ban.style.display='none';
    }catch(e){}
}

function loadAll() {
    loadStats();
    if (_tab === 'keys') loadApiKeys();
    if (_tab === 'tokens') loadTokens();
    if (_tab === 'models') loadFallbackModels();
    if (_tab === 'log') loadLogs();
}

async function loadStats(){
    try{
        var r=await fetch('/panel/stats',{credentials:'include'});
        if(r.status===401){doLogout();return;}
        var d=await r.json();
        renderKeys(d);
    }catch(e){toast('加载统计失败','err');}
}

function renderKeys(d){
    var keys=d.keys||[];
    var ex=keys.filter(function(k){return k.exhausted;}).length;
    var ac=keys.filter(function(k){return !k.exhausted&&k.last_used;}).length;
    var td=keys.reduce(function(s,k){return s+(k.daily_calls||0);},0);
    document.getElementById('s-total').textContent=d.total||0;
    document.getElementById('s-active').textContent=ac;
    document.getElementById('s-exhaust').textContent=ex;
    document.getElementById('s-today').textContent=td.toLocaleString();

    var tb=document.getElementById('keys-tbody');
    if(!keys.length){tb.innerHTML='<tr class="empty-row"><td colspan="9">请在上方添加 API 密钥</td></tr>';return;}
    tb.innerHTML=keys.map(function(k){
        var badge, extra='';
        if(k.exhausted){
            badge='<span class="badge bg-exhaust"><span class="bdot"></span>已耗尽</span>';
            if(k.exhausted_until) extra='<span class="cdwn">'+countdown(k.exhausted_until)+'</span>';
        }else if(k.last_used){
            badge='<span class="badge bg-active"><span class="bdot"></span>活跃</span>';
        }else{
            badge='<span class="badge bg-idle"><span class="bdot"></span>空闲</span>';
        }
        var ec=k.total_errors>0?'num nr':'num nd';
        var mstats='';
        if(k.models && k.models.length){
            mstats=k.models.map(function(m){
                var flag=m.exhausted?'⚠ ':'';
                return '<div style="margin-bottom:0.125rem">'+flag+escapeHtml(m.model)+': '+(m.total_calls||0)+' / '+(m.total_errors||0)+'</div>';
            }).join('');
        }else{
            mstats='—';
        }
        return '<tr>'
            +'<td class="nd num">'+(k.index+1)+'</td>'
            +'<td class="mono">'+k.masked+'</td>'
            +'<td>'+badge+extra+'</td>'
            +'<td><span class="nb num">'+k.total_calls.toLocaleString()+'</span></td>'
            +'<td><span class="num">'+k.daily_calls.toLocaleString()+'</span></td>'
            +'<td><span class="'+ec+'">'+k.total_errors.toLocaleString()+'</span></td>'
            +'<td class="ts">'+mstats+'</td>'
            +'<td><span class="ts">'+timeAgo(k.last_used)+'</span></td>'
            +'<td><button class="btn btn-out btn-xs" data-kid="'+escapeHtml(k.kid)+'" onclick="resetKey(this.dataset.kid)">重置</button></td>'
            +'</tr>';
    }).join('');
}

async function resetKey(kid){
    try{
        var r=await fetch('/panel/reset?kid='+kid,{method:'POST',credentials:'include'});
        var d=await r.json();
        if(d.ok){toast('该密钥额度已清零 ✓');loadStats();}
    }catch(e){toast('重置失败','err');}
}

async function resetAll(){
    if(!confirm('确定要重置全部密钥额度与耗尽状态？')) return;
    try{
        var r=await fetch('/panel/reset?kid=all',{method:'POST',credentials:'include'});
        var d=await r.json();
        if(d.ok){toast('全部密钥已重置 ✓');loadStats();}
    }catch(e){toast('重置失败','err');}
}

var _apiKeys=[];

async function loadApiKeys(){
    var tb=document.getElementById('api-keys-tbody');
    if(!tb) return;
    try{
        var r=await fetch('/panel/api-keys',{credentials:'include'});
        if(r.status===401){doLogout();return;}
        var d=await r.json();
        _apiKeys=d.keys||[];
        renderApiKeys();
    }catch(e){toast('加载 API 密钥列表失败','err');}
}

function renderApiKeys(){
    var tb=document.getElementById('api-keys-tbody');
    if(!tb) return;
    if(!_apiKeys.length){
        tb.innerHTML='<tr class="empty-row"><td colspan="2">暂无，请在上方添加 Gemini API Key</td></tr>';
        return;
    }
    tb.innerHTML=_apiKeys.map(function(k){
        return '<tr><td class="mono">'+escapeHtml(k.masked)+'</td><td><button class="btn btn-out btn-xs" data-i="'+k.index+'" onclick="editApiKey(this.dataset.i)">编辑</button> <button class="btn btn-rd btn-xs" data-i="'+k.index+'" onclick="deleteApiKey(this.dataset.i)" style="margin-left:12px">删除</button></td></tr>';
    }).join('');
}

async function addApiKey(){
    var inp=document.getElementById('api-key-input');
    var v=(inp&&inp.value||'').trim();
    if(!v){toast('请输入 API Key','err');return;}
    try{
        var r=await fetch('/panel/api-keys',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:v})});
        var d=await r.json();
        if(d.ok){inp.value='';_apiKeys=d.keys||[];renderApiKeys();loadStats();toast('已添加 ✓');}
        else{toast(d.error||'添加失败','err');}
    }catch(e){toast('添加失败','err');}
}

async function editApiKey(i){
    i=parseInt(i,10);
    if(isNaN(i)||i<0||i>=_apiKeys.length) return;
    var newKey=prompt('请输入新的 API Key（将替换当前密钥）','');
    if(newKey===null) return;
    newKey=newKey.trim();
    if(!newKey){toast('未输入有效 Key','err');return;}
    try{
        var r=await fetch('/panel/api-keys',{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({index:i,key:newKey})});
        var d=await r.json();
        if(d.ok){_apiKeys=d.keys||[];renderApiKeys();loadStats();toast('已更新 ✓');}
        else{toast(d.error||'更新失败','err');}
    }catch(e){toast('更新失败','err');}
}

async function deleteApiKey(i){
    i=parseInt(i,10);
    if(isNaN(i)||i<0||i>=_apiKeys.length) return;
    if(!confirm('确定要删除该 API 密钥？')) return;
    try{
        var r=await fetch('/panel/api-keys?index='+i,{method:'DELETE',credentials:'include'});
        var d=await r.json();
        if(d.ok){_apiKeys=d.keys||[];renderApiKeys();loadStats();toast('已删除');}
        else{toast(d.error||'删除失败','err');}
    }catch(e){toast('删除失败','err');}
}

document.getElementById('api-key-input')&&document.getElementById('api-key-input').addEventListener('keydown',function(e){if(e.key==='Enter')addApiKey();});

var _fallbackModels=[];

async function loadFallbackModels(){
    try{
        var r=await fetch('/panel/fallback-models',{credentials:'include'});
        if(r.status===401){doLogout();return;}
        var d=await r.json();
        _fallbackModels=d.models||[];
        renderFallbackModels();
        var sc=document.getElementById('supported-count');var sf=document.getElementById('supported-fetched-at');
        if(sc) sc.textContent=(d.supported_count!= null)?d.supported_count:'—';
        if(sf) sf.textContent=(d.supported_fetched_at!= null&&d.supported_fetched_at>0)?formatDate(d.supported_fetched_at):'—';
    }catch(e){toast('加载默认模型失败','err');}
}

function renderFallbackModels(){
    var tb=document.getElementById('fallback-models-tbody');
    if(!tb) return;
    if(!_fallbackModels.length){
        tb.innerHTML='<tr class="empty-row"><td colspan="2">暂无，请在上方添加免费模型（如 gemini-2.5-flash-lite）</td></tr>';
        return;
    }
    tb.innerHTML=_fallbackModels.map(function(m,i){
        var upBtn = i > 0 ? '<button class="btn btn-out btn-xs" data-i="'+i+'" onclick="moveFallbackModelUp(this.dataset.i)" title="上移">↑</button> ' : '';
        var downBtn = i < _fallbackModels.length - 1 ? '<button class="btn btn-out btn-xs" data-i="'+i+'" onclick="moveFallbackModelDown(this.dataset.i)" title="下移">↓</button> ' : '';
        return '<tr><td class="monohi">'+escapeHtml(m)+'</td><td>'+upBtn+downBtn+'<button class="btn btn-rd btn-xs" data-i="'+i+'" onclick="removeFallbackModel(this.dataset.i)" style="margin-left:8px">删除</button></td></tr>';
    }).join('');
}

async function addFallbackModel() {
    var inp = document.getElementById('fallback-model-input');
    var v = (inp && inp.value || '').trim();
    if (!v) { toast('请输入模型 ID', 'err'); return; }
    if (_fallbackModels.indexOf(v) !== -1) { toast('该模型已在列表中', 'err'); return; }
    _fallbackModels.push(v);
    inp.value = '';
    try{
        var r=await fetch('/panel/fallback-models',{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({models:_fallbackModels})});
        var d=await r.json();
        if(d.ok){renderFallbackModels();toast('已添加 ✓');}
        else{_fallbackModels.pop();toast(d.error||'保存失败','err');}
    }catch(e){_fallbackModels.pop();toast('保存失败','err');}
}

async function moveFallbackModelUp(i){
    i=parseInt(i,10);
    if(isNaN(i)||i<=0||i>=_fallbackModels.length) return;
    var tmp=_fallbackModels[i]; _fallbackModels[i]=_fallbackModels[i-1]; _fallbackModels[i-1]=tmp;
    try{
        var r=await fetch('/panel/fallback-models',{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({models:_fallbackModels})});
        var d=await r.json();
        if(d.ok){renderFallbackModels();toast('已上移');}
        else{var t=_fallbackModels[i];_fallbackModels[i]=_fallbackModels[i-1];_fallbackModels[i-1]=t;toast('保存失败','err');}
    }catch(e){var t=_fallbackModels[i];_fallbackModels[i]=_fallbackModels[i-1];_fallbackModels[i-1]=t;toast('保存失败','err');}
}

async function moveFallbackModelDown(i){
    i=parseInt(i,10);
    if(isNaN(i)||i<0||i>=_fallbackModels.length-1) return;
    var tmp=_fallbackModels[i]; _fallbackModels[i]=_fallbackModels[i+1]; _fallbackModels[i+1]=tmp;
    try{
        var r=await fetch('/panel/fallback-models',{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({models:_fallbackModels})});
        var d=await r.json();
        if(d.ok){renderFallbackModels();toast('已下移');}
        else{var t=_fallbackModels[i];_fallbackModels[i]=_fallbackModels[i+1];_fallbackModels[i+1]=t;toast('保存失败','err');}
    }catch(e){var t=_fallbackModels[i];_fallbackModels[i]=_fallbackModels[i+1];_fallbackModels[i+1]=t;toast('保存失败','err');}
}

async function removeFallbackModel(i){
    i=parseInt(i,10);
    if(isNaN(i)||i<0||i>=_fallbackModels.length) return;
    var removed=_fallbackModels[i];
    _fallbackModels.splice(i,1);
    try{
        var r=await fetch('/panel/fallback-models',{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({models:_fallbackModels})});
        var d=await r.json();
        if(d.ok){renderFallbackModels();toast('已删除');}
        else{_fallbackModels.splice(i,0,removed);toast('保存失败','err');}
    }catch(e){_fallbackModels.splice(i,0,removed);toast('保存失败','err');}
}

async function loadLogs() {
    var tb = document.getElementById('log-tbody');
    if (!tb) return;
    try {
        var r = await fetch('/panel/logs', { credentials: 'include' });
        if (r.status === 401) { doLogout(); return; }
        var d = await r.json();
        renderLogs(d.logs || []);
    } catch (e) {
        tb.innerHTML = '<tr class="empty-row"><td colspan="6">加载失败</td></tr>';
    }
}

async function clearLogs() {
    if (!confirm('确定要清空全部请求日志吗？')) return;
    var tb = document.getElementById('log-tbody');
    if (!tb) return;
    try {
        var r = await fetch('/panel/logs', { method: 'DELETE', credentials: 'include' });
        if (r.status === 401) { doLogout(); return; }
        var d = await r.json();
        if (d && d.ok) {
            renderLogs([]);
            toast('日志已清空', 'ok');
        } else {
            toast(d && d.error ? d.error : '清空失败', 'err');
        }
    } catch (e) {
        toast('清空失败', 'err');
    }
}

function renderLogs(logs) {
    var tb = document.getElementById('log-tbody');
    if (!tb) return;
    if (!logs.length) {
        tb.innerHTML = '<tr class="empty-row"><td colspan="6">暂无日志</td></tr>';
        return;
    }
    tb.innerHTML = logs.map(function (e) {
        var ts = e.ts ? new Date(e.ts).toLocaleString() : '—';
        var statusCls = e.status >= 400 ? 'nr' : 'ng';
        var istr = e.input != null && String(e.input) !== '' ? String(e.input) : '';
        var ostr = e.redirect != null && String(e.redirect) !== '' ? String(e.redirect) : '';
        var kstr = e.api_key != null && String(e.api_key) !== '' ? String(e.api_key) : '';
        var inputD = istr ? escapeHtml(istr.slice(0, 120)) + (istr.length > 120 ? '…' : '') : '—';
        var keyD = kstr ? escapeHtml(kstr) : '—';
        return '<tr>'
            + '<td class="ts">' + ts + '</td>'
            + '<td class="mono" style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + escapeHtml(e.path || '—') + '">' + escapeHtml(e.path || '—') + '</td>'
            + '<td class="monohi">' + escapeHtml(e.model || '—') + '</td>'
            + '<td class="num ' + statusCls + '">' + (e.status || '—') + '</td>'
            + '<td class="mono" style="max-width:200px;overflow:hidden;text-overflow:ellipsis" title="' + escapeHtml(istr) + '">' + inputD + '</td>'
            + '<td class="mono" style="max-width:200px;overflow:hidden;text-overflow:ellipsis" title="' + escapeHtml(kstr) + '">' + keyD + '</td>'
            + '</tr>';
    }).join('');
}

async function loadTokens() {
    try {
        var r = await fetch('/panel/tokens', { credentials: 'include' });
        if (r.status === 401) { doLogout(); return; }
        // 先检查 r.ok：非 200 响应（如 KV 未绑定时的 503）body 是 error JSON，
        // d.tokens 会是 undefined，导致令牌列表静默显示为空
        if (!r.ok) {
            var errD = null;
            try { errD = await r.json(); } catch (_) {}
            toast((errD && errD.error) ? errD.error : ('加载令牌列表失败 (HTTP ' + r.status + ')'), 'err');
            return;
        }
        var d = await r.json();
        if (!d.ok) { toast(d.error || '加载令牌列表失败', 'err'); return; }
        renderTokens(d.tokens || []);
    } catch (e) { toast('加载令牌列表失败', 'err'); }
}

function renderTokens(tokens){
    var cnt=document.getElementById('tok-count');
    if(cnt) cnt.textContent=tokens.length+' token'+(tokens.length!==1?'s':'');
    var tb=document.getElementById('tokens-tbody');
    // 防御性 null 守卫：若元素不存在则直接返回，避免抛 TypeError 触发 loadTokens 的 catch
    if(!tb) return;
    if(!tokens.length){
        tb.innerHTML='<tr class="empty-row"><td colspan="7">尚无令牌，请在上方创建以限制 API 访问</td></tr>';
        return;
    }
    tb.innerHTML=tokens.map(function(t){
        var rateStr = (t.rate_limit_sec === 0 || t.rate_limit_sec == null) ? '不限制' : ('每 '+t.rate_limit_sec+' 秒');
        return '<tr>'
            +'<td><span class="monohi">'+escapeHtml(t.label||'—')+'</span></td>'
            +'<td class="mono">'+escapeHtml(t.token_preview)+'</td>'
            +'<td class="ts">'+formatDate(t.created_at)+'</td>'
            +'<td class="ts">'+timeAgo(t.last_used)+'</td>'
            +'<td class="ts">'+escapeHtml(rateStr)+'</td>'
            +'<td class="nb num">'+(t.calls||0)+'</td>'
            +'<td><button class="btn btn-rd btn-xs" data-thash="'+escapeHtml(t.thash)+'" onclick="revokeToken(this.dataset.thash)">吊销</button></td>'
            +'</tr>';
    }).join('');
}

async function createToken(){
    var label=document.getElementById('tok-label').value.trim()||'Token';
    var rateInput=document.getElementById('tok-rate-limit');
    var rateLimitSec=rateInput?parseInt(rateInput.value,10):10;
    if(isNaN(rateLimitSec)||rateLimitSec<0) rateLimitSec=10;
    try{
        var r=await fetch('/panel/tokens/create',{method:'POST',credentials:'include',
            headers:{'Content-Type':'application/json'},body:JSON.stringify({label:label,rate_limit_sec:rateLimitSec})});
        var d=await r.json();
        if(d.ok){
            document.getElementById('new-token-val').textContent=d.token;
            document.getElementById('new-token-box').classList.add('show');
            document.getElementById('tok-label').value='';
            toast('令牌已创建，请立即复制','ok');
            loadTokens();
        }else{toast('创建令牌失败','err');}
    }catch(e){toast('创建令牌出错','err');}
}

async function revokeToken(thash){
    if(!confirm('确定要吊销此令牌？吊销后将立即失效。')) return;
    try{
        var r=await fetch('/panel/tokens/revoke?thash='+encodeURIComponent(thash),{method:'POST',credentials:'include'});
        var d=await r.json();
        if(d.ok){toast('令牌已吊销');loadTokens();}
    }catch(e){toast('吊销失败','err');}
}

function copyToken(el){
    var text=el.textContent;
    navigator.clipboard.writeText(text).then(function(){
        toast('已复制到剪贴板 ✓');
    }).catch(function(){
        toast('复制失败，请手动选择','err');
    });
}

function closeNewToken(){
    document.getElementById('new-token-box').classList.remove('show');
}

function escapeHtml(s){
    return String(s).replace(/[&<>"']/g,function(c){
        return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
    });
}

function escJs(s){
    return String(s).replace(/\\\\/g,'\\\\\\\\').replace(/'/g,"\\\\'");
}

document.getElementById('pw').addEventListener('keydown',function(e){if(e.key==='Enter')doLogin();});
document.getElementById('tok-label') && document.getElementById('tok-label').addEventListener('keydown',function(e){if(e.key==='Enter')createToken();});

// 将示例中的“https://你的Worker地址”替换为当前域名
(function(){
    try{
        var origin = location.origin;
        document.querySelectorAll('pre').forEach(function(el){
            if(el && el.textContent && origin){
                el.textContent = el.textContent.replace(/https:\/\/你的Worker地址/g, origin);
            }
        });
    }catch(e){}
})();

// Auto-detect existing session
(async function(){
    try{
        var r=await fetch('/panel/stats',{credentials:'include'});
        if(r.ok){var d=await r.json();if(d.ok)showDash();}
    }catch(e){}
})();
</script>
</body>
</html>`;

// ─────────────────────────────────────────────────────────────────────────────
// MAIN FETCH HANDLER
// ─────────────────────────────────────────────────────────────────────────────

export default {
    async fetch(request, env, ctx) {
        try {
            return await handleRequest(request, env, ctx);
        } catch (err) {
            const msg = (err && err.message) ? String(err.message) : String(err);
            return new Response(
                '<!DOCTYPE html><html><head><meta charset="utf-8"/><title>Error</title></head><body style="font-family:sans-serif;padding:2rem;background:#0e1520;color:#9ab8d0;">' +
                '<h1 style="color:#ff3d60;">Worker Error</h1><pre style="white-space:pre-wrap;background:#131d2a;padding:1rem;border-radius:8px;">' +
                escapeHtml(msg) +
                '</pre><p>请检查环境变量（PASSWORD）与 KV 绑定（GEMINI_KV），并在面板中配置 API 密钥。</p></body></html>',
                { status: 500, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
            );
        }
    },
};

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

async function handleRequest(request, env, ctx) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    // ── CORS Preflight ────────────────────────────────────────────────────────
    if (method === 'OPTIONS') {
        return new Response(null, {
            status: 204,
            headers: {
                'Access-Control-Allow-Origin':  '*',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                'Access-Control-Max-Age':       '86400',
            },
        });
    }

    // ── Panel / 默认即登录页 ───────────────────────────────────────────────────
    if (path === '/' || path === '' || path === '/panel' || path === '/panel/') {
        return new Response(PANEL_HTML, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }
    if (path === '/panel/health'        && method === 'GET')  return handlePanelHealth(request, env);
    if (path === '/panel/login'         && method === 'POST') return handlePanelLogin(request, env);
    if (path === '/panel/logout'        && method === 'POST') return handlePanelLogout(request, env);
    if (path === '/panel/stats'         && method === 'GET')  return handlePanelStats(request, env);
    if (path === '/panel/reset'         && method === 'POST') return handlePanelReset(request, env);
    if (path === '/panel/api-keys'      && method === 'GET')  return handleApiKeysGet(request, env);
    if (path === '/panel/api-keys'      && method === 'POST') return handleApiKeysPost(request, env);
    if (path === '/panel/api-keys'      && method === 'PUT')  return handleApiKeysPut(request, env);
    if (path === '/panel/api-keys'      && method === 'DELETE') return handleApiKeysDelete(request, env);
    if (path === '/panel/tokens'        && method === 'GET')  return handleTokenList(request, env);
    if (path === '/panel/tokens/create' && method === 'POST') return handleTokenCreate(request, env);
    if (path === '/panel/tokens/revoke' && method === 'POST') return handleTokenRevoke(request, env);
    if (path === '/panel/fallback-models' && method === 'GET') return handleFallbackModelsGet(request, env);
    if (path === '/panel/fallback-models' && method === 'PUT') return handleFallbackModelsPut(request, env);
    if (path === '/panel/logs' && method === 'GET') return handlePanelLogs(request, env);
    if (path === '/panel/logs' && method === 'DELETE') return handlePanelLogsClear(request, env);

    // ── API Auth Check ────────────────────────────────────────────────────────
    const authResult = await checkApiAuth(request, env);
    if (!authResult.ok) {
        return jsonError(authResult.message || 'Unauthorized: provide a valid Bearer token', authResult.statusCode || 401);
    }

    // ── OpenAI-compatible endpoint (official Gemini OpenAI compat layer) ──────
    // Ref: https://ai.google.dev/gemini-api/docs/openai
    // Official base: https://generativelanguage.googleapis.com/v1beta/openai/
    if (path.startsWith('/v1/')) {
        // Map /v1/xxx → /v1beta/openai/xxx
        const geminiPath = '/v1beta/openai' + path.slice(3);   // /v1/chat/completions → /v1beta/openai/chat/completions
        return proxyToGemini(request, env, geminiPath, 3, ctx);
    }

    // ── Gemini native endpoint (direct passthrough) ───────────────────────────
    if (path.startsWith('/v1beta/')) {
        return proxyToGemini(request, env, path, 3, ctx);
    }

    // ── Root info ─────────────────────────────────────────────────────────────
    return jsonResp({
        name:    'Gemini Key Rotation Proxy',
        version: '2.0.0',
        docs:    'https://ai.google.dev/gemini-api/docs/openai',
        endpoints: {
            panel:              'GET  /panel',
            openai_chat:        'POST /v1/chat/completions',
            openai_models:      'GET  /v1/models',
            openai_embeddings:  'POST /v1/embeddings',
            gemini_native:      'POST /v1beta/models/{model}:generateContent',
        },
    });
}