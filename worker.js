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
const KV_KEY_LOG_ENTRIES          = 'log:entries';
const KV_KEY_RETRY_MINUTES        = 'cfg:retry_minutes';
// cfg:token_index 存储所有 thash 的数组，用 kvGet/kvSet 维护，
// 绕过 CF Workers KV list 操作的最终一致性延迟（最长 60s），
// 从根本上解决令牌列表不显示的问题。
const KV_KEY_TOKEN_INDEX          = 'cfg:token_index';
const KV_KEY_ROUND_ROBIN_INDEX    = 'rr_idx';
const KV_PREFIX_KEYSTATE          = 'ks:';
const KV_PREFIX_TOKEN             = 'tok:';
const KV_PREFIX_RATE_LIMIT        = 'rl:';
const KV_PREFIX_SESSION           = 'sess:';
const KV_PREFIX_LOGIN_ATTEMPT     = 'login:';

// Panel login rate limit
const LOGIN_WINDOW_SEC            = 600;  // 10 minutes
const LOGIN_MAX_ATTEMPTS          = 10;
const LOGIN_LOCK_SEC              = 900;  // 15 minutes
const LOG_BODY_MAX_DEFAULT        = 500;
const RETRY_CONFIG_CACHE_TTL_MS   = 60_000;
const RETRY_MINUTES_DEFAULT       = 60;
const RETRY_MINUTES_MIN           = 5;
const RETRY_MINUTES_MAX           = 1440;

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

function getClientIp(req) {
    return (req.headers.get('cf-connecting-ip') || req.headers.get('x-forwarded-for') || '').split(',')[0].trim();
}

async function getLoginState(env, ip) {
    if (!env.GEMINI_KV || !ip) return null;
    return await kvGet(env, KV_PREFIX_LOGIN_ATTEMPT + ip);
}

async function recordLoginFailure(env, ip) {
    if (!env.GEMINI_KV || !ip) return null;
    const now = Date.now();
    const key = KV_PREFIX_LOGIN_ATTEMPT + ip;
    const state = (await kvGet(env, key)) || { count: 0, first_ts: now, locked_until: 0 };
    if (state.locked_until && state.locked_until > now) return state;
    if (!state.first_ts || (now - state.first_ts) > LOGIN_WINDOW_SEC * 1000) {
        state.count = 0;
        state.first_ts = now;
    }
    state.count = (state.count || 0) + 1;
    if (state.count >= LOGIN_MAX_ATTEMPTS) {
        state.locked_until = now + LOGIN_LOCK_SEC * 1000;
    }
    await kvSet(env, key, state, Math.max(LOGIN_WINDOW_SEC, LOGIN_LOCK_SEC));
    return state;
}

async function clearLoginFailures(env, ip) {
    if (!env.GEMINI_KV || !ip) return;
    await kvDelete(env, KV_PREFIX_LOGIN_ATTEMPT + ip);
}

function redactKeyFromUrl(urlStr) {
    try {
        const u = new URL(urlStr);
        u.searchParams.delete('key');
        return u.toString();
    } catch (_) {
        return urlStr;
    }
}

async function getRetryMinutes(env) {
    const now = Date.now();
    if (_retryMinutesCache.value !== null && (now - _retryMinutesCache.fetchedAt) < RETRY_CONFIG_CACHE_TTL_MS) {
        return _retryMinutesCache.value;
    }
    const v = await kvGet(env, KV_KEY_RETRY_MINUTES);
    let out = RETRY_MINUTES_DEFAULT;
    if (typeof v === 'number' && !isNaN(v)) {
        out = Math.min(RETRY_MINUTES_MAX, Math.max(RETRY_MINUTES_MIN, Math.floor(v)));
    }
    _retryMinutesCache.value = out;
    _retryMinutesCache.fetchedAt = now;
    return out;
}

async function setRetryMinutes(env, minutes) {
    const m = Math.min(RETRY_MINUTES_MAX, Math.max(RETRY_MINUTES_MIN, Math.floor(minutes)));
    await kvSet(env, KV_KEY_RETRY_MINUTES, m);
    _retryMinutesCache.value = m;
    _retryMinutesCache.fetchedAt = Date.now();
    return m;
}

// ─────────────────────────────────────────────────────────────────────────────
// IN-PROCESS CACHE（Worker 实例生命周期内有效，减少 KV 读次数）
// ─────────────────────────────────────────────────────────────────────────────

const _modelsCache = { models: /** @type {any[]|null} */ (null), fetchedAt: 0 };
const _retryMinutesCache = { value: /** @type {number|null} */ (null), fetchedAt: 0 };

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
    model_stats_order: [],          // 最近使用的模型顺序（short name），用于裁剪体积
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
    if (!('model_stats_order' in raw) || !Array.isArray(raw.model_stats_order)) {
        raw.model_stats_order = [];
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
    s.model_stats_order = [];
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
async function pickKey(env, modelShort = null, keys = null, preloaded = null) {
    const list = Array.isArray(keys) ? keys : await getApiKeys(env);
    if (!list.length) throw new Error('No API keys configured');
    const now = Date.now();

    let idx = (await kvGet(env, KV_KEY_ROUND_ROBIN_INDEX)) ?? 0;
    if (typeof idx !== 'number' || isNaN(idx)) idx = 0;

    // 并发预取所有 Key 的 hash 与状态，避免串行 KV 读（Fix #5）
    const kids   = (preloaded && Array.isArray(preloaded.kids)) ? preloaded.kids : await Promise.all(list.map(k => keyHash(k)));
    const states = (preloaded && Array.isArray(preloaded.states)) ? preloaded.states : await Promise.all(kids.map(kid => getKeyState(env, kid)));

    // 自动每日重置：并发写入所有需要重置的 Key，不阻塞主流程
    const resetPromises = [];
    for (let i = 0; i < list.length; i++) {
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
    for (let i = 0; i < list.length; i++) {
        const pos   = (idx + i) % list.length;
        const state = states[pos];

        // 优先按模型维度判断是否已耗尽；若未提供模型名，则使用 Key 级别的 exhausted_until
        if (modelShort && state.exhausted_by_model && typeof state.exhausted_by_model === 'object') {
            const ts = state.exhausted_by_model[modelShort];
            if (typeof ts === 'number' && ts > now) continue;
            if (state.exhausted_until && state.exhausted_until > now) continue;
        } else if (state.exhausted_until && state.exhausted_until > now) {
            continue;
        }

        await kvSet(env, KV_KEY_ROUND_ROBIN_INDEX, (pos + 1) % list.length);
        return { key: list[pos], kid: kids[pos], state };
    }

    // 全部耗尽：仍按 round-robin 顺序返回（Fix #1），确保调用方每次重试拿到不同的 Key，
    // 而不是每次都打到 keys[0]，让上层日志可以完整记录每个 Key 的 429。
    const pos = idx % list.length;
    await kvSet(env, KV_KEY_ROUND_ROBIN_INDEX, (pos + 1) % list.length);
    return { key: list[pos], kid: kids[pos], state: states[pos] };
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
        if (!Array.isArray(state.model_stats_order)) state.model_stats_order = [];
        const ms = state.model_stats[modelShort] || { total_calls: 0, total_errors: 0 };
        ms.total_calls = (ms.total_calls || 0) + 1;
        ms.total_errors = ms.total_errors || 0;
        state.model_stats[modelShort] = ms;
        state.model_stats_order = state.model_stats_order.filter(m => m !== modelShort);
        state.model_stats_order.push(modelShort);
        if (state.model_stats_order.length > 20) {
            const toRemove = state.model_stats_order.splice(0, state.model_stats_order.length - 20);
            for (const m of toRemove) delete state.model_stats[m];
        }
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
        if (!Array.isArray(state.model_stats_order)) state.model_stats_order = [];
        const ms = state.model_stats[modelShort] || { total_calls: 0, total_errors: 0 };
        ms.total_errors = (ms.total_errors || 0) + 1;
        ms.total_calls = ms.total_calls || 0;
        state.model_stats[modelShort] = ms;
        state.model_stats_order = state.model_stats_order.filter(m => m !== modelShort);
        state.model_stats_order.push(modelShort);
        if (state.model_stats_order.length > 20) {
            const toRemove = state.model_stats_order.splice(0, state.model_stats_order.length - 20);
            for (const m of toRemove) delete state.model_stats[m];
        }
    }
    if (statusCode === 429) {
        const retryMin = await getRetryMinutes(env);
        const until = Date.now() + retryMin * 60 * 1000;
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
    const limit = 256 - (256 % ALPHANUM.length);
    let suffix = '';
    for (let i = 0; i < arr.length; i++) {
        let b = arr[i];
        while (b >= limit) {
            const tmp = new Uint8Array(1);
            crypto.getRandomValues(tmp);
            b = tmp[0];
        }
        suffix += ALPHANUM[b % ALPHANUM.length];
    }
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

async function getTokenByHash(env, thash) {
    if (!thash) return null;
    return await kvGet(env, KV_PREFIX_TOKEN + thash);
}

async function updateToken(env, thash, patch) {
    const data = await getTokenByHash(env, thash);
    if (!data) return null;
    const updated = { ...data, ...patch };
    await kvSet(env, KV_PREFIX_TOKEN + thash, updated);
    return updated;
}

/** rate_limit_sec: 最小访问间隔（秒），0=不限制，默认 10 */
async function createToken(env, label, rateLimitSec) {
    const token = generateToken();
    const thash = await tokenHash(token);
    const sec   = rateLimitSec === 0 ? 0 : (Math.max(0, Math.min(3600, parseInt(rateLimitSec, 10) || 10)));
    const data  = { label: label || 'Token', created_at: Date.now(), last_used: null, calls: 0, rate_limit_sec: sec, token_preview: maskTokenForPreview(token), blocked_models: [] };
    // 同时写入 token 数据与索引，两者均使用强一致的 kvSet
    await kvSet(env, KV_PREFIX_TOKEN + thash, data);
    await addToTokenIndex(env, thash);
    return { token, thash, ...data };
}

async function listTokens(env) {
    // 从索引读取所有 thash（kvGet，强一致），再并发拉取每个 token 的数据
    const thashes = await getTokenIndex(env);
    const results = thashes.length ? await Promise.all(thashes.map(h => kvGet(env, KV_PREFIX_TOKEN + h))) : [];
    const tokens  = [];
    let missing = 0;
    for (let i = 0; i < thashes.length; i++) {
        const data = results[i];
        // data 为 null 表示该 token 已被直接删除但索引未清理，跳过即可
        if (data) tokens.push({ thash: thashes[i], ...data });
        else missing++;
    }
    // 若索引为空或存在缺失，尝试通过 kvList 进行一次修复（最终一致，低频）
    if (!tokens.length || missing > 0) {
        const listed = await kvList(env, KV_PREFIX_TOKEN);
        const listedHashes = listed.map(k => (k && k.name) ? k.name.slice(KV_PREFIX_TOKEN.length) : '').filter(Boolean);
        const merged = Array.from(new Set([...thashes, ...listedHashes]));
        if (merged.length && merged.length !== thashes.length) {
            await kvSet(env, KV_KEY_TOKEN_INDEX, merged);
        }
        if (merged.length && (merged.length !== tokens.length)) {
            const mergedData = await Promise.all(merged.map(h => kvGet(env, KV_PREFIX_TOKEN + h)));
            tokens.length = 0;
            for (let i = 0; i < merged.length; i++) {
                const data = mergedData[i];
                if (data) tokens.push({ thash: merged[i], ...data });
            }
        }
    }
    return tokens.sort((a, b) => b.created_at - a.created_at);
}

function normalizeModelList(list) {
    if (!Array.isArray(list)) return [];
    const out = [];
    for (const m of list) {
        const s = toShortModelName(String(m || '').trim());
        if (s) out.push(s);
    }
    return Array.from(new Set(out));
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
    const statUpdate = kvSet(env, KV_PREFIX_TOKEN + thash, data);
    return { ok: true, token: data, statUpdate };
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

async function getSupportedModelsKV(env) {
    const raw = await kvGet(env, KV_KEY_SUPPORTED_MODELS);
    if (raw && typeof raw === 'object') {
        const models = Array.isArray(raw.models) ? raw.models : [];
        const fetchedAt = (typeof raw.fetchedAt === 'number' && !isNaN(raw.fetchedAt)) ? raw.fetchedAt : 0;
        return { models, fetchedAt };
    }
    return { models: Array.isArray(raw) ? raw : [], fetchedAt: 0 };
}
async function setSupportedModelsRaw(env, models, fetchedAt) {
    await kvSet(env, KV_KEY_SUPPORTED_MODELS, { models, fetchedAt });
}

function normalizeSupportedModels(raw) {
    if (!Array.isArray(raw)) return [];
    return raw.map(m => {
        if (typeof m === 'string') return { name: m };
        if (m && typeof m === 'object') {
            return {
                name: m.name,
                displayName: m.displayName,
                inputTokenLimit: m.inputTokenLimit,
                outputTokenLimit: m.outputTokenLimit,
                thinking: m.thinking,
            };
        }
        return null;
    }).filter(m => m && typeof m.name === 'string' && m.name.trim());
}

function supportedModelSet(models) {
    const set = new Set();
    for (const m of models) {
        const name = toShortModelName(m.name || '');
        if (name) set.add(name);
    }
    return set;
}
/**
 * 若列表为空或距上次刷新超过 6 小时，用任一 API Key 拉取 /v1beta/models 并更新 KV。
 * 优先使用进程内缓存（_modelsCache），避免每次请求都读 KV。
 * 成功后更新 KV 与进程内缓存。
 */
async function maybeRefreshSupportedModels(env, force = false) {
    const now = Date.now();
    // 进程内缓存命中：直接返回，完全跳过 KV 读
    if (!force && _modelsCache.models && (now - _modelsCache.fetchedAt) < SUPPORTED_MODELS_TTL_SEC * 1000) return;

    const keys = await getApiKeys(env);
    if (!keys.length) return;
    const cached = await getSupportedModelsKV(env);
    const fetchedAt = cached.fetchedAt;
    if (!force && fetchedAt > 0 && (now - fetchedAt) < SUPPORTED_MODELS_TTL_SEC * 1000) {
        // KV 缓存仍有效，回填进程内缓存
        const raw = normalizeSupportedModels(cached.models);
        if (raw.length) { _modelsCache.models = raw; _modelsCache.fetchedAt = fetchedAt; }
        return;
    }
    // 轮询所有 Key，避免 keys[0] 已耗尽时无法刷新模型列表（Fix #4）
    let data;
    let fetchOk = false;
    for (const key of keys) {
        const url = GEMINI_BASE + '/v1beta/models?key=' + encodeURIComponent(key);
        let resp;
        const ac = new AbortController();
        const timer = setTimeout(() => ac.abort(), 10_000);
        try { resp = await fetch(url, { signal: ac.signal }); } catch (_) { clearTimeout(timer); continue; }
        clearTimeout(timer);
        if (!resp.ok) continue;
        try { data = await resp.json(); fetchOk = true; break; } catch (_) { continue; }
    }
    if (!fetchOk || !data) return;
    const models = Array.isArray(data.models)
        ? data.models.map(m => (m && typeof m === 'object') ? ({
            name: m.name,
            displayName: m.displayName,
            inputTokenLimit: m.inputTokenLimit,
            outputTokenLimit: m.outputTokenLimit,
            thinking: m.thinking,
        }) : null).filter(m => m && typeof m.name === 'string' && m.name.trim())
        : [];
    await setSupportedModelsRaw(env, models, now);
    // 回填进程内缓存
    _modelsCache.models = models;
    _modelsCache.fetchedAt = now;
}

// ─────────────────────────────────────────────────────────────────────────────
// REQUEST LOG (last 100 entries in KV)
// ─────────────────────────────────────────────────────────────────────────────

const LOG_MAX = 100;

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
    return { ok: true, token: valid.token || null, statUpdate: valid.statUpdate || null };
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
  */
async function proxyToGemini(req, env, targetPath, maxRetries = 3, ctx, tokenData) {
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

    // 全部 Key 已耗尽时提前返回，避免无效重试
    let preloadedStates = null;
    {
        const now = Date.now();
        const kids = await Promise.all(keys.map(k => keyHash(k)));
        const states = await Promise.all(kids.map(kid => getKeyState(env, kid)));
        preloadedStates = { kids, states };
        let allExhausted = true;
        for (let i = 0; i < states.length; i++) {
            const state = states[i];
            if (state.last_reset && (now - state.last_reset) >= DAY_MS) { allExhausted = false; break; }
            let exhausted = false;
            if (state.exhausted_until && state.exhausted_until > now) exhausted = true;
            if (modelShort && state.exhausted_by_model && typeof state.exhausted_by_model === 'object') {
                const ts = state.exhausted_by_model[modelShort];
                if (typeof ts === 'number' && ts > now) exhausted = true;
            }
            if (!exhausted) { allExhausted = false; break; }
        }
        if (allExhausted) {
            return jsonError('All API keys are exhausted (429). Please try again later.', 429);
        }
    }

    // 若支持模型列表存在且请求模型不在列表中，按 Gemini 官方错误格式响应
    const supportedRaw = _modelsCache.models
        ? _modelsCache.models
        : normalizeSupportedModels((await getSupportedModelsKV(env)).models);
    if (modelShort && supportedRaw.length > 0) {
        const shortSet = supportedModelSet(supportedRaw);
        if (!shortSet.has(toShortModelName(modelShort))) {
            return jsonResp({ error: { code: 404, message: 'Model not found', status: 'NOT_FOUND' } }, 404);
        }
    }
    if (tokenData && Array.isArray(tokenData.blocked_models) && tokenData.blocked_models.length && modelShort) {
        const blocked = new Set(normalizeModelList(tokenData.blocked_models));
        if (blocked.has(toShortModelName(modelShort))) {
            return jsonResp({ error: { message: 'Model is blocked for this token', type: 'forbidden', code: 403 } }, 403);
        }
    }

    // 预先准备日志用的 input（Fix #3：不在循环内重复解析）
    const logInput = parsedBody
        ? (typeof parsedBody === 'object' ? JSON.stringify(parsedBody) : String(parsedBody)).slice(0, LOG_BODY_MAX_DEFAULT)
        : null;

    for (let attempt = 0; attempt < tries; attempt++) {
        const { key, kid, state } = await pickKey(env, modelShort, keys, preloadedStates);

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

        const ac = new AbortController();
        const timer = setTimeout(() => ac.abort(), 25_000);
        let resp;
        try {
            resp = await fetch(url.toString(), {
                method:  req.method,
                headers: fwdHeaders,
                body:    bodyBuffer,
                signal:  ac.signal,
            });
        } catch (e) {
            if (e && e.name === 'AbortError') {
                if (ctx) ctx.waitUntil(onKeyError(env, kid, state, 504, modelShort));
                else await onKeyError(env, kid, state, 504, modelShort);
                logBuffer.push({ ts: Date.now(), path: targetPath, method: req.method,
                    model: originalModel || modelShort || null, status: 504,
                    input: logInput, redirect: redactKeyFromUrl(url.toString()), api_key: maskKey(key) });
                if (logBuffer.length) {
                    const logsToWrite = logBuffer.splice(0, logBuffer.length);
                    if (ctx) ctx.waitUntil(appendLogs(env, logsToWrite));
                    else await appendLogs(env, logsToWrite);
                }
                return jsonError('Upstream timeout', 504);
            }
            throw e;
        } finally {
            clearTimeout(timer);
        }

        if (resp.status === 429) {
            // 记录本次 429 错误到 Key 状态与日志，然后尝试下一个 Key
            await onKeyError(env, kid, state, 429, modelShort);
            preloadedStates = null;
            logBuffer.push({ ts: Date.now(), path: targetPath, method: req.method,
                model: originalModel || modelShort || null, status: 429,
                input: logInput, redirect: redactKeyFromUrl(url.toString()), api_key: maskKey(key) });
            continue;
        }

        if (resp.status >= 500 && resp.status < 600) {
            // 5xx 属于上游服务错误，切换 Key 通常无效，避免污染多 Key 统计
            if (ctx) ctx.waitUntil(onKeyError(env, kid, state, resp.status, modelShort));
            else await onKeyError(env, kid, state, resp.status, modelShort);
            logBuffer.push({ ts: Date.now(), path: targetPath, method: req.method,
                model: originalModel || modelShort || null, status: resp.status,
                input: logInput, redirect: redactKeyFromUrl(url.toString()), api_key: maskKey(key) });
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

        if (!resp.ok) {
            if (ctx) ctx.waitUntil(onKeyError(env, kid, state, resp.status, modelShort));
            else await onKeyError(env, kid, state, resp.status, modelShort);
        } else {
            if (ctx) ctx.waitUntil(onKeySuccess(env, kid, state, modelShort));
            else await onKeySuccess(env, kid, state, modelShort);
        }

        // 日志优先展示"用户请求的原始模型"，而非代理内部回退/归一化后的模型
        logBuffer.push({ ts: Date.now(), path: targetPath, method: req.method,
            model: originalModel || modelShort || null,
            status: resp.status, input: logInput, redirect: redactKeyFromUrl(url.toString()), api_key: maskKey(key) });

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
    if (!env.GEMINI_KV) return jsonResp({ ok: false, error: '未绑定 KV 命名空间（GEMINI_KV），无法登录面板。请在 Cloudflare Worker 设置中绑定' }, 503);
    if (!expectedPw) return jsonResp({ ok: false, error: '未配置 PASSWORD，请在 Cloudflare Worker 变量中设置' }, 401);
    const ip = getClientIp(req);
    if (ip) {
        const st = await getLoginState(env, ip);
        if (st && st.locked_until && st.locked_until > Date.now()) {
            return jsonResp({ ok: false, error: '登录过于频繁，请稍后再试' }, 429);
        }
    }
    const match = await timingSafeEqual(inputPw, expectedPw);
    if (!match) {
        const st = await recordLoginFailure(env, ip);
        if (st && st.locked_until && st.locked_until > Date.now()) {
            return jsonResp({ ok: false, error: '登录过于频繁，请稍后再试' }, 429);
        }
        return jsonResp({ ok: false, error: '密码错误' }, 401);
    }
    await clearLoginFailures(env, ip);
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
    if (!await isAuthenticated(req, env)) return jsonResp({ ok: false, error: 'Unauthorized' }, 200);
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
        if (state.exhausted_until && state.exhausted_until > now) exhaustedFlag = true;
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
        blocked_models: Array.isArray(t.blocked_models) ? t.blocked_models : [],
    }));
    return jsonResp({ ok: true, tokens: masked });
}

async function handleTokenBlockedModels(req, env) {
    if (!await isAuthenticated(req, env)) return jsonResp({ error: 'Unauthorized' }, 401);
    const kvErr = requireKV(env); if (kvErr) return kvErr;
    let body = {};
    try { body = await req.json(); } catch { return jsonError('Invalid JSON', 400); }
    const thash = (body.thash || '').trim();
    if (!thash) return jsonError('Missing thash', 400);
    const models = normalizeModelList(body.models || []);
    const updated = await updateToken(env, thash, { blocked_models: models });
    if (!updated) return jsonError('Token not found', 404);
    return jsonResp({ ok: true, thash, blocked_models: updated.blocked_models || [] });
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

async function handleApiKeysVerify(req, env) {
    if (!await isAuthenticated(req, env)) return jsonResp({ error: 'Unauthorized' }, 401);
    const kvErr = requireKV(env); if (kvErr) return kvErr;
    const keys = await getApiKeys(env);
    const results = await Promise.all(keys.map(async key => {
        let ok = false;
        let status = null;
        const ac = new AbortController();
        const timer = setTimeout(() => ac.abort(), 10_000);
        try {
            const url = GEMINI_BASE + '/v1beta/models?key=' + encodeURIComponent(key);
            const resp = await fetch(url, { signal: ac.signal });
            status = resp.status;
            ok = resp.ok;
        } catch (_) {
            ok = false;
        } finally {
            clearTimeout(timer);
        }
        return { masked: maskKey(key), ok, status };
    }));
    const passed = results.filter(r => r.ok).length;
    return jsonResp({ ok: true, total: results.length, passed, results });
}

async function handleRetryConfigGet(req, env) {
    if (!await isAuthenticated(req, env)) return jsonResp({ error: 'Unauthorized' }, 401);
    const kvErr = requireKV(env); if (kvErr) return kvErr;
    const minutes = await getRetryMinutes(env);
    return jsonResp({ ok: true, retry_minutes: minutes });
}

async function handleRetryConfigPut(req, env) {
    if (!await isAuthenticated(req, env)) return jsonResp({ error: 'Unauthorized' }, 401);
    const kvErr = requireKV(env); if (kvErr) return kvErr;
    let body = {};
    try { body = await req.json(); } catch { return jsonError('Invalid JSON', 400); }
    const minutes = parseInt(body.retry_minutes, 10);
    if (isNaN(minutes)) return jsonError('Invalid retry_minutes', 400);
    const saved = await setRetryMinutes(env, minutes);
    return jsonResp({ ok: true, retry_minutes: saved });
}

async function handleSupportedModelsGet(req, env) {
    if (!await isAuthenticated(req, env)) return jsonResp({ error: 'Unauthorized' }, 401);
    const kvErr = requireKV(env); if (kvErr) return kvErr;
    const refresh = new URL(req.url).searchParams.get('refresh') === '1';
    await maybeRefreshSupportedModels(env, refresh);
    let kv = null;
    const raw = _modelsCache.models
        ? _modelsCache.models
        : (kv = await getSupportedModelsKV(env), normalizeSupportedModels(kv.models));
    const models = raw.map(m => ({
        displayName: m.displayName || m.name || '',
        name: toShortModelName(m.name || ''),
        rawName: m.name || '',
        inputTokenLimit: m.inputTokenLimit,
        outputTokenLimit: m.outputTokenLimit,
        thinking: m.thinking,
    })).filter(m => m.name);
    let fetchedAt = _modelsCache.fetchedAt;
    if (!fetchedAt) {
        if (!kv) kv = await getSupportedModelsKV(env);
        fetchedAt = kv.fetchedAt;
    }
    return jsonResp({ ok: true, models, supported_fetched_at: fetchedAt, supported_count: models.length });
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
<style>
:root{
    --bg:#f0f4f8;--s1:#fff;--s2:#f8fafc;
    --b1:#e2e8f0;--b2:#cbd5e1;
    --tx:#334155;--tx2:#64748b;--txh:#0f172a;
    --bl:#0ea5e9;--bl2:#0284c7;
    --gn:#059669;--gn2:#047857;
    --yl:#d97706;--yl2:#b45309;
    --rd:#dc2626;--rd2:#b91c1c;
    --warn:#fef3c7;
    --mono:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace;
    --sans:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Noto Sans','PingFang SC','Hiragino Sans GB','Microsoft YaHei',sans-serif;
}
*{margin:0;padding:0;box-sizing:border-box}
html{scroll-behavior:smooth}
body{font-size:16px}
body{font-family:var(--sans);background:var(--bg);color:var(--tx);min-height:100vh;
    background-image:
        radial-gradient(ellipse 80% 50% at 10% -10%,rgba(14,165,233,.08) 0%,transparent 55%),
        radial-gradient(ellipse 60% 40% at 90% 110%,rgba(5,150,105,.06) 0%,transparent 55%)}

/* Login */
#login{display:flex;align-items:center;justify-content:center;min-height:100vh}
.lw{width:380px;transform:translateY(-180px)}
.lhead{text-align:center;margin-bottom:40px}
.licon{font-size:48px;margin-bottom:14px;display:block;
    filter:drop-shadow(0 0 16px rgba(14,165,233,.25))}
.ltit{font-size:22px;font-weight:700;color:var(--txh);letter-spacing:.04em}
.lsub{font-size:13px;color:var(--tx2);margin-top:6px;letter-spacing:.04em;text-transform:uppercase}
.card{background:var(--s1);border:1px solid var(--b1);border-radius:12px;padding:32px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
label{display:block;font-size:13px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:var(--tx2);margin-bottom:8px}
input[type=password],input[type=text]{width:100%;background:var(--s2);border:1px solid var(--b1);border-radius:7px;
    padding:11px 14px;color:var(--txh);font-family:var(--mono);font-size:13px;outline:none;
    transition:border .18s,box-shadow .18s}
input:focus{border-color:var(--bl);box-shadow:0 0 0 3px rgba(14,165,233,.15)}
.fg{margin-bottom:18px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;
    padding:10px 18px;border-radius:7px;border:none;font-size:16px;font-weight:600;
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
.btn-wide{min-width:150px}
.btn-sm{padding:7px 18px;font-size:17px}
.btn-xs{padding:6px 14px;font-size:15px}
.lerr{font-size:14px;color:var(--rd);text-align:center;min-height:18px;margin-top:12px}

/* Dashboard — 1 / 2 / 3 三块统一在同一容器内，左右完全对齐 */
#dash{display:none;width:100%;min-height:100vh}
.dash-shell{width:100%;max-width:1280px;margin:0 auto;padding:0 24px;box-sizing:border-box}
.health-banner{display:flex;align-items:center;justify-content:space-between;gap:12px;
    padding:10px 16px;background:var(--warn);color:#333;font-size:15px;
    border-bottom:1px solid rgba(0,0,0,.1)}
.hdr{display:flex;align-items:center;justify-content:space-between;
    padding:14px 18px;border-bottom:1px solid var(--b1);background:var(--s1);
    box-shadow:0 1px 2px rgba(0,0,0,.04);position:sticky;top:0;z-index:10}
.hlogo{font-size:18px;font-weight:700;color:var(--txh);display:flex;align-items:center;gap:9px}
.hlogo span{color:var(--bl)}
.htags{display:flex;gap:6px}
.htag{font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;
    padding:2px 8px;border-radius:20px;border:1px solid}
.htag-b{color:var(--bl);border-color:rgba(14,165,233,.35);background:rgba(14,165,233,.08)}
.htag-g{color:var(--gn);border-color:rgba(5,150,105,.35);background:rgba(5,150,105,.06)}
.hright{display:flex;align-items:center;gap:8px}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}

/* Nav tabs */
.navtabs{display:flex;gap:2px;padding:16px 0 0;border-bottom:1px solid var(--b1);background:var(--s1)}
.navtab{padding:9px 18px;font-size:15px;font-weight:600;cursor:pointer;border-radius:7px 7px 0 0;
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
.slbl{font-size:14px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--tx2);margin-bottom:10px}
.snum{font-family:var(--mono);font-size:28px;font-weight:600;line-height:1}
.snum.bl{color:var(--bl)}.snum.gn{color:var(--gn)}
.snum.rd{color:var(--rd)}.snum.yl{color:var(--yl)}

/* Panel box */
.pbox{background:var(--s1);border:1px solid var(--b1);border-radius:10px;overflow:hidden;margin-bottom:20px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.phead{display:flex;align-items:center;justify-content:space-between;
    padding:14px 18px;border-bottom:1px solid var(--b1);background:var(--s2)}
.ptit{font-size:16px;font-weight:600;color:var(--txh)}
.pacts{display:flex;gap:7px;align-items:center}

/* Table */
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums; font-feature-settings:"tnum";}
th{font-size:13px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;
    color:var(--tx2);text-align:left;padding:9px 16px;border-bottom:1px solid var(--b1);
    background:var(--s2)}
td{padding:12px 16px;font-size:15px;border-bottom:1px solid var(--b1);vertical-align:middle;line-height:1.35}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--s2)}
.mono{font-family:var(--mono);font-size:14px;color:var(--tx2);letter-spacing:.02em;line-height:1.35}
.monohi{font-family:var(--mono);font-size:14px;color:var(--txh);line-height:1.35}
.model-line{margin-bottom:6px;line-height:1.6}
.model-line:last-child{margin-bottom:0}
.num{font-family:var(--mono);font-size:15px;line-height:1.35}
.nb{color:var(--bl)}.ng{color:var(--gn)}.nr{color:var(--rd)}.nd{color:var(--tx2)}
.ts{font-size:13px;color:var(--tx2);font-family:var(--mono)}
.badge{display:inline-flex;align-items:center;gap:4px;font-size:12px;font-weight:600;
    padding:3px 8px;border-radius:4px;letter-spacing:.04em}
.bg-active{background:rgba(5,150,105,.1);color:var(--gn);border:1px solid rgba(5,150,105,.25)}
.bg-exhaust{background:rgba(220,38,38,.08);color:var(--rd);border:1px solid rgba(220,38,38,.25)}
.bg-idle{background:var(--s2);color:var(--tx2);border:1px solid var(--b1)}
.bdot{width:5px;height:5px;border-radius:50%;background:currentColor}
.bg-active .bdot{animation:blink 1.8s infinite}
.cdwn{font-size:12px;color:var(--yl);font-family:var(--mono);margin-left:4px}
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
.tokwarn{font-size:12px;color:var(--yl);display:flex;align-items:center;gap:5px}

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
            <button class="btn btn-pri" id="lbtn" onclick="window.doLogin && window.doLogin()">登录</button>
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
                <button class="btn btn-out btn-sm" onclick="window.doLogout && window.doLogout()">退出</button>
            </div>
        </div>

        <div class="navtabs">
        <div class="navtab active" id="tab-keys"     onclick="switchTab('keys')">🔑 Gemini 密钥</div>
        <div class="navtab"        id="tab-tokens"   onclick="switchTab('tokens')">🎫 访问令牌</div>
        <div class="navtab"        id="tab-filter"   onclick="switchTab('filter')">🚫 模型过滤</div>
        <div class="navtab"        id="tab-settings" onclick="switchTab('settings')">⚙️ 设置</div>
        <div class="navtab"        id="tab-log"      onclick="switchTab('log')">📋 日志</div>
    </div>

        <div class="content">

        <!-- 统计 -->
        <div class="sg" id="stats-grid">
            <div class="sc cb"><div class="slbl">密钥总数</div><div class="snum bl" id="s-total">—</div></div>
            <div class="sc cg"><div class="slbl">活跃密钥</div><div class="snum gn" id="s-active">—</div></div>
            <div class="sc cr"><div class="slbl">受限密钥</div><div class="snum rd" id="s-exhaust">—</div></div>
            <div class="sc cy"><div class="slbl">今日调用</div><div class="snum yl" id="s-today">—</div></div>
        </div>

        <!-- 密钥 Tab -->
        <div class="tabpanel active" id="tp-keys">
            <div class="pbox" style="margin-bottom:14px">
                <div class="phead">
                    <div class="ptit">配置 API 密钥</div>
                </div>
                <div style="padding:18px">
                    <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px">
                        <p style="font-size:12px;color:var(--tx2);margin:0">在此添加 Gemini API 密钥，代理将轮转使用。可编辑或删除已有密钥。</p>
                        <button class="btn btn-out btn-xs" onclick="verifyApiKeys()">API 密钥连通性</button>
                    </div>
                    <div style="display:flex;gap:10px;align-items:flex-end;margin-bottom:18px">
                        <div class="fg" style="flex:1;margin:0">
                            <input type="password" id="api-key-input" placeholder="AIzaSy..." style="width:100%" autocomplete="off"/>
                        </div>
                        <button class="btn btn-gn" onclick="addApiKey()">＋ 添加</button>
                    </div>
                    <table>
                        <thead><tr><th>密钥</th><th>操作</th></tr></thead>
                        <tbody id="api-keys-tbody"><tr class="empty-row"><td colspan="2">加载中…</td></tr></tbody>
                    </table>
                    <div class="newtoken" id="key-verify-box">
                        <div class="tokwarn">🔍 连通性结果</div>
                        <div class="tokval" id="key-verify-val">—</div>
                        <div style="display:flex;align-items:center;justify-content:space-between">
                            <span class="ts" style="color:var(--tx2)">仅表示连通性与权限，不代表实际可用配额</span>
                            <button class="btn btn-out btn-xs" onclick="document.getElementById('key-verify-box').classList.remove('show')">关闭</button>
                        </div>
                    </div>
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
                        <div style="font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--bl);margin-bottom:10px">OPENAI API · ${'cu'+'rl'}</div>
                        <pre style="font-family:var(--mono);font-size:12px;color:var(--tx);white-space:pre-wrap;line-height:1.7">export GEMINI_WORKER_URL="https://你的Worker地址"
export GEMINI_ACCESS_TOKEN="你的令牌"
export GEMINI_MODEL="gemini-2.5-flash-lite"

${'cu'+'rl'} $GEMINI_WORKER_URL/v1/chat/completions \\
    -H "Content-Type: application/json" \\
    -H "Authorization: Bearer $GEMINI_ACCESS_TOKEN" \\
    -d '{
        "model": "'$GEMINI_MODEL'",
        "messages": [
            {"role": "user", "content": "你好"}
        ]
    }'</pre>
                    </div>

                    <!-- 2. Gemini API 示例 -->
                    <div style="background:var(--s2);border:1px solid var(--b1);border-radius:8px;padding:14px">
                        <div style="font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--gn);margin-bottom:10px">GEMINI API · ${'cu'+'rl'}</div>
                        <pre style="font-family:var(--mono);font-size:12px;color:var(--tx);white-space:pre-wrap;line-height:1.7">export GEMINI_WORKER_URL="https://你的Worker地址"
export GEMINI_ACCESS_TOKEN="你的令牌"
export GEMINI_MODEL="gemini-2.5-flash-lite"

${'cu'+'rl'} $GEMINI_WORKER_URL/v1beta/models/$GEMINI_MODEL:generateContent \\
    -H "Content-Type: application/json" \\
    -H "Authorization: Bearer $GEMINI_ACCESS_TOKEN" \\
    -d '{
        "contents": [
            {"parts": [{"text": "你好"}]}
        ]
    }'</pre>
                    </div>

                    <!-- 3. GEMINI-CLI -->
                    <div style="background:var(--s2);border:1px solid var(--b1);border-radius:8px;padding:14px">
                        <div style="font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--gn);margin-bottom:10px">GEMINI-CLI</div>
                        <pre style="font-family:var(--mono);font-size:12px;color:var(--tx);white-space:pre-wrap;line-height:1.7">export GOOGLE_GEMINI_BASE_URL="https://你的Worker地址"
export GEMINI_API_KEY="你的令牌"

gemini "你好！"</pre>
                    </div>

                </div>
            </div>
        </div>

        <!-- 模型过滤 Tab -->
        <div class="tabpanel" id="tp-filter">
            <div class="pbox">
                <div class="phead">
                    <div class="ptit">按访问令牌禁用模型</div>
                    <div class="pacts">
                        <span class="ts">从支持模型列表中勾选</span>
                    </div>
                </div>
                <table>
                    <thead><tr>
                        <th>备注</th><th>令牌预览</th><th>已禁用模型</th><th>操作</th>
                    </tr></thead>
                    <tbody id="filter-tbody"><tr class="empty-row"><td colspan="4">加载中…</td></tr></tbody>
                </table>
            </div>
            <div class="pbox">
                <div class="phead">
                    <div class="ptit">支持模型列表</div>
                </div>
                <div style="padding:18px">
                    <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px">
                        <p id="supported-models-hint" style="font-size:12px;color:var(--tx2);margin:0;font-family:var(--mono);font-variant-numeric:tabular-nums;line-height:1.35">支持模型列表：共 <span id="supported-count">—</span> 个，上次更新于 <span id="supported-fetched-at">—</span>（约 6 小时自动刷新）</p>
                        <button class="btn btn-out btn-xs" onclick="refreshSupportedModels()">刷新</button>
                    </div>
                    <div style="max-height:440px;overflow:auto;border:1px solid var(--b1);border-radius:8px;background:var(--s2)">
                        <table style="font-size:13px">
                            <thead><tr><th>名字</th><th>大模型</th><th>输入</th><th>输出</th><th>思考</th></tr></thead>
                            <tbody id="supported-models-tbody"><tr class="empty-row"><td colspan="5">加载中…</td></tr></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- 设置 Tab -->
        <div class="tabpanel" id="tp-settings">
            <div class="pbox">
                <div class="phead">
                    <div class="ptit">429 重试窗口（分钟）</div>
                </div>
                <div style="padding:18px;display:flex;flex-direction:column;gap:10px">
                    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                        <label style="font-size:14px;font-weight:600;letter-spacing:.14em;text-transform:uppercase;color:var(--tx2);margin:0">重试窗口</label>
                        <input type="number" id="retry-minutes-input" min="5" max="1440" value="60" placeholder="默认 60" style="width:160px"/>
                    </div>
                    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                        <span class="ts" id="retry-minutes-hint">当前 —</span>
                        <span class="ts">范围 5-1440，默认 60</span>
                    </div>
                    <button class="btn btn-gn btn-wide" onclick="saveRetryMinutes()">保存</button>
                </div>
            </div>
        </div>

        <!-- 日志 Tab -->
        <div class="tabpanel" id="tp-log">
            <div class="pbox">
                <div class="phead">
                    <div class="ptit">最近 100 条请求日志</div>
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

<div id="model-filter-modal" style="position:fixed;inset:0;background:rgba(0,0,0,.35);display:none;align-items:center;justify-content:center;z-index:200">
    <div style="width:720px;max-width:92vw;background:var(--s1);border:1px solid var(--b1);border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,.2)">
        <div style="padding:14px 18px;border-bottom:1px solid var(--b1);display:flex;align-items:center;justify-content:space-between">
            <div style="font-size:13px;font-weight:600;color:var(--txh)">选择禁用模型</div>
            <button class="btn btn-out btn-xs" onclick="closeModelFilter()">关闭</button>
        </div>
        <div style="padding:14px 18px">
            <div class="ts" style="margin-bottom:10px">勾选后保存，将对该访问令牌生效</div>
            <div style="display:flex;gap:8px;align-items:center;margin-bottom:10px">
                <input id="model-filter-search" type="text" placeholder="过滤模型（支持名称/ID）" oninput="filterModelList()" style="flex:1;background:var(--s2);border:1px solid var(--b1);border-radius:7px;padding:9px 12px;font-family:var(--mono);font-size:12px"/>
            </div>
            <div id="model-filter-list" style="max-height:360px;overflow:auto;border:1px solid var(--b1);border-radius:8px;background:var(--s2);padding:10px"></div>
        </div>
        <div style="padding:14px 18px;border-top:1px solid var(--b1);display:flex;align-items:center;justify-content:flex-end;gap:8px">
            <button class="btn btn-out btn-xs" onclick="selectAllModels(true)">全选</button>
            <button class="btn btn-out btn-xs" onclick="selectAllModels(false)">全不选</button>
            <button class="btn btn-gn btn-wide" onclick="saveBlockedModels()">保存</button>
        </div>
    </div>
</div>

<script>
var _tab = (function(){
    try { return localStorage.getItem('gproxy_tab') || 'keys'; } catch (e) { return 'keys'; }
})();

function setActiveTab(t){
    document.querySelectorAll('.navtab').forEach(function (el) { el.classList.remove('active'); });
    document.querySelectorAll('.tabpanel').forEach(function (el) { el.classList.remove('active'); });
    var tabEl = document.getElementById('tab-' + t);
    var panelEl = document.getElementById('tp-' + t);
    if (tabEl) tabEl.classList.add('active');
    if (panelEl) panelEl.classList.add('active');
}

function switchTab(t) {
    _tab = t;
    try { localStorage.setItem('gproxy_tab', t); } catch (e) {}
    setActiveTab(t);
    if (t === 'keys') loadApiKeys();
    if (t === 'tokens') loadTokens();
    if (t === 'filter') { loadTokenFilters(); loadSupportedModels(); }
    if (t === 'settings') { loadRetryConfig(); }
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

function toShortModelName(name){
    if(typeof name!=='string') return '';
    var s=name.trim();
    return s.indexOf('models/')===0 ? s.slice(7) : s;
}

function countdown(u){
    if(!u) return '';
    var r=u-Date.now();
    if(r<=0) return '重置中…';
    var h=Math.floor(r/3600000), m=Math.floor((r%3600000)/60000);
    return h+' 小时 '+m+' 分钟';
}

window.doLogin = async function(){
    var pw=document.getElementById('pw').value;
    var btn=document.getElementById('lbtn');
    btn.textContent='…'; btn.disabled=true;
    try{
        var r=await fetch('/panel/login',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({password:pw}),credentials:'include'});
        var d=null;
        try{ d=await r.json(); }catch(e){}
        if(r.ok && d && d.ok){ showDash(); }
        else{
            var msg = (d && (d.error || (d.error && d.error.message))) ? (d.error || d.error.message) : ('登录失败 (HTTP '+r.status+')');
            document.getElementById('lerr').textContent=msg;
        }
    }catch(e){ document.getElementById('lerr').textContent='网络错误'; }
    btn.textContent='登录'; btn.disabled=false;
};

window.doLogout = async function() {
    await fetch('/panel/logout', { method: 'POST', credentials: 'include' });
    document.getElementById('dash').style.display = 'none';
    document.getElementById('login').style.display = 'flex';
    document.getElementById('pw').value = '';
    document.getElementById('lerr').textContent = '';
};

function showDash() {
    document.getElementById('login').style.display = 'none';
    document.getElementById('dash').style.display = 'block';
    setActiveTab(_tab);
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
    if (_tab === 'filter') { loadTokenFilters(); loadSupportedModels(); }
    if (_tab === 'settings') { loadRetryConfig(); }
    if (_tab === 'log') loadLogs();
}

async function loadStats(){
    try{
        var r=await fetch('/panel/stats',{credentials:'include'});
        var d=await r.json();
        if (d && d.ok === false && d.error === 'Unauthorized') { doLogout(); return; }
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
            badge='<span class="badge bg-exhaust"><span class="bdot"></span>受限</span>';
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
                var hasErr=(m.total_errors||0)>0;
                var cls=hasErr?'nr':'nd';
                return '<div class="model-line '+cls+'">'+escapeHtml(m.model)+': '+(m.total_calls||0)+' / '+(m.total_errors||0)+'</div>';
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

async function verifyApiKeys(){
    try{
        var r = await fetch('/panel/api-keys/verify', { method: 'POST', credentials: 'include' });
        if (r.status === 401) { doLogout(); return; }
        var d = await r.json();
        if (!d || !d.ok) { toast('连通性检测失败','err'); return; }
        var lines = (d.results || []).map(function(it){
            return (it.ok ? '✓ ' : '✗ ') + it.masked + (it.ok ? '' : (' (HTTP ' + (it.status || 'ERR') + ')'));
        }).join('\\n');
        var box = document.getElementById('key-verify-box');
        var val = document.getElementById('key-verify-val');
        if (val) val.textContent = '连通性通过 ' + d.passed + ' / ' + d.total + '\\n' + lines;
        if (box) box.classList.add('show');
    }catch(e){ toast('连通性检测失败','err'); }
}

async function loadRetryConfig(){
    var inp = document.getElementById('retry-minutes-input');
    var hint = document.getElementById('retry-minutes-hint');
    if (!inp) return;
    try{
        var r = await fetch('/panel/retry-config', { credentials: 'include' });
        if (r.status === 401) { doLogout(); return; }
        var d = await r.json();
        if (d && d.ok) {
            inp.value = d.retry_minutes;
            if (hint) hint.textContent = '当前 ' + d.retry_minutes + ' 分钟';
        }
    }catch(e){
        if (hint) hint.textContent = '当前 —';
    }
}

async function loadSupportedModels(refresh){
    var tb = document.getElementById('supported-models-tbody');
    var sc = document.getElementById('supported-count');
    var sf = document.getElementById('supported-fetched-at');
    var hint = document.getElementById('supported-models-hint');
    if (!tb) return;
    try{
        var url = '/panel/supported-models' + (refresh ? '?refresh=1' : '');
        var r = await fetch(url, { credentials: 'include' });
        if (r.status === 401) { doLogout(); return; }
        var d = await r.json();
        if (!d || !d.ok) { tb.innerHTML='<tr class="empty-row"><td colspan="5">加载失败</td></tr>'; return; }
        _supportedCache = d.models || [];
        if (sc) sc.textContent = (d.supported_count != null) ? d.supported_count : '—';
        if (sf) sf.textContent = (d.supported_fetched_at && d.supported_fetched_at > 0) ? formatDate(d.supported_fetched_at) : '—';
        if (!d.models || !d.models.length) {
            tb.innerHTML = '<tr class="empty-row"><td colspan="5">暂无（可能尚未配置 API Key）</td></tr>';
            if (hint) hint.textContent = '支持模型列表：未获取到（可能尚未配置 API Key）';
            return;
        }
        tb.innerHTML = d.models.map(function(m){
            var t = (m.thinking === undefined || m.thinking === null) ? '—' : String(m.thinking);
            return '<tr>'
                + '<td class="monohi">' + escapeHtml(m.displayName || '—') + '</td>'
                + '<td class="mono">' + escapeHtml(m.name || '—') + '</td>'
                + '<td class="num">' + (m.inputTokenLimit != null ? String(m.inputTokenLimit) : '—') + '</td>'
                + '<td class="num">' + (m.outputTokenLimit != null ? String(m.outputTokenLimit) : '—') + '</td>'
                + '<td class="ts">' + t + '</td>'
                + '</tr>';
        }).join('');
    }catch(e){
        tb.innerHTML = '<tr class="empty-row"><td colspan="5">加载失败</td></tr>';
    }
}

function refreshSupportedModels(){
    _supportedCache = null;
    loadSupportedModels(true);
}

async function saveRetryMinutes(){
    var inp = document.getElementById('retry-minutes-input');
    if (!inp) return;
    var v = parseInt(inp.value, 10);
    if (isNaN(v) || v < 5 || v > 1440) { toast('请输入 5-1440 的整数', 'err'); return; }
    try{
        var r = await fetch('/panel/retry-config', { method: 'PUT', credentials: 'include',
            headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ retry_minutes: v }) });
        var d = await r.json();
        if (d && d.ok) {
            toast('已保存 ✓');
            if (document.getElementById('retry-minutes-hint')) {
                document.getElementById('retry-minutes-hint').textContent = '当前 ' + d.retry_minutes + ' 分钟';
            }
        } else {
            toast((d && d.error) ? d.error : '保存失败', 'err');
        }
    }catch(e){ toast('保存失败', 'err'); }
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
        var kstr = e.api_key != null && String(e.api_key) !== '' ? String(e.api_key) : '';
        var inputD = istr ? escapeHtml(istr.slice(0, 120)) + (istr.length > 120 ? '…' : '') : '—';
        var keyD = kstr ? escapeHtml(kstr) : '—';
        return '<tr>'
            + '<td class="ts">' + ts + '</td>'
            + '<td class="mono" style="word-break:break-all" title="' + escapeHtml(e.path || '—') + '">' + escapeHtml(e.path || '—') + '</td>'
            + '<td class="monohi">' + escapeHtml(e.model || '—') + '</td>'
            + '<td class="num ' + statusCls + '">' + (e.status || '—') + '</td>'
            + '<td class="mono" style="max-width:200px;overflow:hidden;text-overflow:ellipsis" title="' + escapeHtml(istr) + '">' + inputD + '</td>'
            + '<td class="mono" title="' + escapeHtml(kstr) + '">' + keyD + '</td>'
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

async function loadTokenFilters(){
    var tb = document.getElementById('filter-tbody');
    if (!tb) return;
    try{
        var r = await fetch('/panel/tokens', { credentials: 'include' });
        if (r.status === 401) { doLogout(); return; }
        var d = await r.json();
        if (!d || !d.ok) { tb.innerHTML = '<tr class="empty-row"><td colspan="4">加载失败</td></tr>'; return; }
        var tokens = d.tokens || [];
        if (!tokens.length) {
            tb.innerHTML = '<tr class="empty-row"><td colspan="4">暂无令牌</td></tr>';
            return;
        }
        tb.innerHTML = tokens.map(function(t){
            var blockedList = Array.isArray(t.blocked_models) ? t.blocked_models : [];
            var blocked = blockedList.length ? blockedList.join(',') : '';
            var blockedDisplay = blockedList.length
                ? blockedList.map(function(m){return '<div class="model-line">'+escapeHtml(m)+'</div>';}).join('')
                : '—';
            return '<tr>'
                + '<td><span class="monohi">' + escapeHtml(t.label||'—') + '</span></td>'
                + '<td class="mono">' + escapeHtml(t.token_preview) + '</td>'
                + '<td class="mono">' + blockedDisplay + '</td>'
                + '<td><button class="btn btn-out btn-xs" data-thash="' + escapeHtml(t.thash) + '" data-blocked="' + escapeHtml(blocked) + '" onclick="editBlockedModels(this.dataset.thash,this.dataset.blocked)">编辑</button></td>'
                + '</tr>';
        }).join('');
    }catch(e){
        tb.innerHTML = '<tr class="empty-row"><td colspan="4">加载失败</td></tr>';
    }
}

var _filterThash = null;
var _filterBlocked = [];
var _supportedCache = null;

async function editBlockedModels(thash, current){
    _filterThash = thash;
    _filterBlocked = (current || '').split(',').map(function(s){return s.trim();}).filter(Boolean);
    await openModelFilter();
}

async function openModelFilter(){
    var listEl = document.getElementById('model-filter-list');
    var modal = document.getElementById('model-filter-modal');
    var searchEl = document.getElementById('model-filter-search');
    if (!listEl || !modal) return;
    if (!_supportedCache) {
        try{
            var r = await fetch('/panel/supported-models', { credentials: 'include' });
            if (r.status === 401) { doLogout(); return; }
            var d = await r.json();
            if (d && d.ok) _supportedCache = d.models || [];
        }catch(e){}
    }
    if (searchEl) searchEl.value = '';
    renderModelFilterList('');
    modal.style.display = 'flex';
}

function closeModelFilter(){
    var modal = document.getElementById('model-filter-modal');
    if (modal) modal.style.display = 'none';
}

function selectAllModels(flag){
    var listEl = document.getElementById('model-filter-list');
    if (!listEl) return;
    listEl.querySelectorAll('input[type=checkbox]').forEach(function(cb){ cb.checked = !!flag; });
}

function filterModelList(){
    var searchEl = document.getElementById('model-filter-search');
    var q = searchEl ? searchEl.value : '';
    renderModelFilterList(q);
}

function renderModelFilterList(query){
    var listEl = document.getElementById('model-filter-list');
    if (!listEl) return;
    var models = Array.isArray(_supportedCache) ? _supportedCache : [];
    if (!models.length) {
        listEl.innerHTML = '<div class="ts">未获取到支持模型列表，请先配置 API Key。</div>';
        return;
    }
    var blockedSet = new Set(_filterBlocked);
    var q = (query || '').trim().toLowerCase();
    var rows = [];
    for (var i = 0; i < models.length; i++) {
        var m = models[i] || {};
        var name = m.name || '';
        var display = m.displayName || '';
        var label = (display ? (display + ' — ') : '') + name;
        if (q) {
            var hay = (display + ' ' + name).toLowerCase();
            if (hay.indexOf(q) === -1) continue;
        }
        var shortName = toShortModelName(name);
        var checked = blockedSet.has(shortName) ? ' checked' : '';
        rows.push(
            '<label style="display:flex;gap:8px;align-items:center;padding:6px 4px;border-bottom:1px dashed rgba(0,0,0,.06);text-transform:none;letter-spacing:0">'
            + '<input type="checkbox" data-name="' + escapeHtml(shortName) + '"' + checked + '/>'
            + '<span class="mono" style="font-size:12px;color:var(--tx)">' + escapeHtml(label) + '</span>'
            + '</label>'
        );
    }
    listEl.innerHTML = rows.length ? rows.join('') : '<div class="ts">未匹配到模型</div>';
}

async function saveBlockedModels(){
    if (!_filterThash) return;
    var listEl = document.getElementById('model-filter-list');
    if (!listEl) return;
    var selected = [];
    listEl.querySelectorAll('input[type=checkbox]').forEach(function(cb){
        if (cb.checked) selected.push(cb.getAttribute('data-name'));
    });
    try{
        var r = await fetch('/panel/tokens/blocked-models', { method: 'POST', credentials: 'include',
            headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ thash: _filterThash, models: selected }) });
        var d = await r.json();
        if (d && d.ok) {
            toast('已更新 ✓');
            closeModelFilter();
            loadTokenFilters();
        } else {
            toast((d && d.error) ? d.error : '更新失败', 'err');
        }
    }catch(e){ toast('更新失败', 'err'); }
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

document.getElementById('pw').addEventListener('keydown',function(e){if(e.key==='Enter' && window.doLogin)window.doLogin();});
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
    if (path === '/favicon.ico') {
        return new Response(null, { status: 204 });
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
    if (path === '/panel/api-keys/verify' && method === 'POST') return handleApiKeysVerify(request, env);
    if (path === '/panel/tokens'        && method === 'GET')  return handleTokenList(request, env);
    if (path === '/panel/tokens/create' && method === 'POST') return handleTokenCreate(request, env);
    if (path === '/panel/tokens/revoke' && method === 'POST') return handleTokenRevoke(request, env);
    if (path === '/panel/tokens/blocked-models' && method === 'POST') return handleTokenBlockedModels(request, env);
    if (path === '/panel/retry-config' && method === 'GET') return handleRetryConfigGet(request, env);
    if (path === '/panel/retry-config' && method === 'PUT') return handleRetryConfigPut(request, env);
    if (path === '/panel/supported-models' && method === 'GET') return handleSupportedModelsGet(request, env);
    if (path === '/panel/logs' && method === 'GET') return handlePanelLogs(request, env);
    if (path === '/panel/logs' && method === 'DELETE') return handlePanelLogsClear(request, env);

    // ── API Auth Check ────────────────────────────────────────────────────────
    const authResult = await checkApiAuth(request, env);
    if (!authResult.ok) {
        return jsonError(authResult.message || 'Unauthorized: provide a valid Bearer token', authResult.statusCode || 401);
    }
    if (authResult.statUpdate) {
        if (ctx) ctx.waitUntil(authResult.statUpdate);
        else authResult.statUpdate.catch(() => {});
    }

    // ── OpenAI-compatible endpoint (official Gemini OpenAI compat layer) ──────
    // Ref: https://ai.google.dev/gemini-api/docs/openai
    // Official base: https://generativelanguage.googleapis.com/v1beta/openai/
    if (path.startsWith('/v1/')) {
        // Map /v1/xxx → /v1beta/openai/xxx
        const geminiPath = '/v1beta/openai' + path.slice(3);   // /v1/chat/completions → /v1beta/openai/chat/completions
        return proxyToGemini(request, env, geminiPath, 3, ctx, authResult.token);
    }

    // ── Gemini native endpoint (direct passthrough) ───────────────────────────
    if (path.startsWith('/v1beta/')) {
        return proxyToGemini(request, env, path, 3, ctx, authResult.token);
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
