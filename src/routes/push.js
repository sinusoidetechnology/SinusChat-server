// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

"use strict";

const fs = require("fs");

const { FCM_SERVICE_ACCOUNT_FILE, NTFY_BASE } = require("../config");
const { randomHex, signRs256 } = require("../crypto");
const { db } = require("../db");
const { DAY_MS, perHour, perMinute } = require("../common");
const { scrubLog } = require("../log");
const { requireAuth } = require("./auth");

const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const FCM_SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
const PUSH_PREF_CACHE_MAX = 5000;
const NTFY_TOPIC_CACHE_MAX = 50000;
const PUSH_TIMEOUT_MS = 10_000;
const WAKE_COOLDOWN_MS = 3_000;
// Pilne budzenia idą jako FCM HIGH z data.w="1"; pozostałe (np. ciche ramki "quiet", klucze grup)
// jako NORMAL z w="0", żeby nie zużywać limitu pilnych pushy na Androidzie.
const URGENT_WAKE_KINDS = new Set(["msg", "group_attach", "sealed", "call", "kicked", "expiry_notice"]);
// Budzenie o wiadomości jest ważne tak długo, jak wiadomość czeka w kolejce (24 h); o połączeniu 2 min.
const FCM_WAKE_TTL = Math.round(DAY_MS / 1000) + "s";
const FCM_CALL_TTL = "120s";
// Tych rodzajów nie scalamy w oknie WAKE_COOLDOWN_MS — muszą dotrzeć od razu.
const IMMEDIATE_WAKE_KINDS = new Set(["call", "kicked"]);

const isUrgentWake = (kind) => URGENT_WAKE_KINDS.has(kind || "msg");

const ntfyTopicCache = new Map();
const pushPrefCache = new Map();
let fcmAccountCache;
const wakeWindows = new Map();
let fcmAccessToken = null;
let fcmTokenRequest = null;

function legacyTopicFor(userHash) {
  return "sinuschat_" + String(userHash).substring(0, 32);
}

function ntfyTopicFor(userHash) {
  return ntfyTopicCache.get(userHash) || legacyTopicFor(userHash);
}

async function loadNtfyTopic(userHash) {
  try {
    const { rows } = await db.query("SELECT ntfy_topic FROM users WHERE email_hash=$1", [userHash]);
    if (rows[0]?.ntfy_topic) ntfyTopicCache.set(userHash, rows[0].ntfy_topic);
  } catch (_) {}
}

async function ensureUserNtfyTopic(userHash) {
  const cached = ntfyTopicCache.get(userHash);
  if (cached) return cached;
  const legacy = legacyTopicFor(userHash);
  const { rows } = await db.query("SELECT ntfy_topic FROM users WHERE email_hash=$1", [userHash]);
  if (!rows.length) return legacy;
  let topic = rows[0].ntfy_topic;
  if (!topic || topic === legacy) {
    const updated = await db.query(
      `UPDATE users SET ntfy_topic = CASE WHEN ntfy_topic IS NULL OR ntfy_topic = $3 THEN $2 ELSE ntfy_topic END
        WHERE email_hash=$1 RETURNING ntfy_topic`,
      [userHash, "sinuschat_" + randomHex(24), legacy],
    );
    topic = updated.rows[0]?.ntfy_topic || legacy;
  }
  if (ntfyTopicCache.size > NTFY_TOPIC_CACHE_MAX) ntfyTopicCache.clear();
  ntfyTopicCache.set(userHash, topic);
  return topic;
}

async function pushViaNtfy(userHash, kind) {
  let topic;
  try {
    topic = await ensureUserNtfyTopic(userHash);
  } catch (_) {
    topic = ntfyTopicFor(userHash);
  }
  const headers = { "Content-Type": "text/plain" };
  if (kind === "call") {
    headers["X-Priority"] = "max";
    headers["X-Tags"] = "phone";
  }
  fetch(`${NTFY_BASE}/${topic}`, {
    method: "POST",
    headers,
    body: kind || "msg",
    signal: AbortSignal.timeout(PUSH_TIMEOUT_MS),
  }).catch(() => {});
}

function readFcmAccount() {
  if (!FCM_SERVICE_ACCOUNT_FILE) return null;
  try {
    const account = JSON.parse(fs.readFileSync(FCM_SERVICE_ACCOUNT_FILE, "utf8"));
    if (account.client_email && account.private_key && account.project_id) return account;
    console.warn("[FCM] niekompletny plik konta usługi");
  } catch (e) {
    console.warn("[FCM] nie można wczytać konta usługi:", scrubLog(e.message));
  }
  return null;
}

function fcmAccount() {
  if (fcmAccountCache === undefined) fcmAccountCache = readFcmAccount();
  return fcmAccountCache;
}

const fcmAvailable = () => !!fcmAccount();

async function fcmRequestAccessToken(account, now) {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const unsigned =
    b64({ alg: "RS256", typ: "JWT" }) +
    "." +
    b64({
      iss: account.client_email,
      scope: FCM_SCOPE,
      aud: GOOGLE_TOKEN_URL,
      iat: now,
      exp: now + 3600,
    });
  const res = await fetch(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: `${unsigned}.${signRs256(unsigned, account.private_key)}`,
    }),
    signal: AbortSignal.timeout(PUSH_TIMEOUT_MS),
  });
  if (!res.ok) {
    console.warn("[FCM] token OAuth:", res.status);
    return null;
  }
  const { access_token: token, expires_in: expiresIn } = await res.json();
  fcmAccessToken = { token, exp: now + (Number(expiresIn) || 3600) };
  return token;
}

async function fcmGetAccessToken() {
  const account = fcmAccount();
  if (!account) return null;
  const now = Math.floor(Date.now() / 1000);
  if (fcmAccessToken && fcmAccessToken.exp - 60 > now) return fcmAccessToken.token;
  fcmTokenRequest ??= fcmRequestAccessToken(account, now).finally(() => {
    fcmTokenRequest = null;
  });
  return fcmTokenRequest;
}

async function sendFcm(userHash, fcmToken, kind) {
  const account = fcmAccount();
  if (!account || !fcmToken) return false;
  try {
    const access = await fcmGetAccessToken();
    if (!access) return false;
    const call = kind === "call";
    const urgent = isUrgentWake(kind);
    const res = await fetch(`https://fcm.googleapis.com/v1/projects/${account.project_id}/messages:send`, {
      method: "POST",
      headers: { Authorization: `Bearer ${access}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        message: {
          token: fcmToken,
          data: { w: urgent ? "1" : "0" },
          android: {
            priority: urgent ? "HIGH" : "NORMAL",
            ttl: call ? FCM_CALL_TTL : FCM_WAKE_TTL,
            collapse_key: call ? "call" : urgent ? "wake" : "quiet",
          },
        },
      }),
      signal: AbortSignal.timeout(PUSH_TIMEOUT_MS),
    });
    if (res.ok) return true;
    const body = await res.text().catch(() => "");
    if (res.status === 404 || body.includes("UNREGISTERED") || body.includes("INVALID_ARGUMENT")) {
      await db.query("UPDATE users SET fcm_token=NULL WHERE email_hash=$1", [userHash]).catch(() => {});
      pushPrefCache.delete(userHash);
    } else {
      console.warn("[FCM] send:", res.status);
    }
    return false;
  } catch (e) {
    console.warn("[FCM] send error:", scrubLog(e.message));
    return false;
  }
}

async function pushPrefFor(userHash) {
  const cached = pushPrefCache.get(userHash);
  if (cached) return cached;
  let pref = { mode: "ntfy", token: null };
  try {
    const { rows } = await db.query("SELECT push_mode, fcm_token FROM users WHERE email_hash=$1", [userHash]);
    if (rows[0]) pref = { mode: rows[0].push_mode === "fcm" ? "fcm" : "ntfy", token: rows[0].fcm_token || null };
  } catch (_) {}
  if (pushPrefCache.size > PUSH_PREF_CACHE_MAX) pushPrefCache.clear();
  pushPrefCache.set(userHash, pref);
  return pref;
}

function rememberPushPref(userHash, pref) {
  pushPrefCache.set(userHash, pref);
}

async function sendWake(userHash, kind) {
  const pref = await pushPrefFor(userHash);
  if (pref.mode === "fcm" && pref.token && fcmAvailable() && (await sendFcm(userHash, pref.token, kind))) return;
  return pushViaNtfy(userHash, kind);
}

function closeWakeWindow(userHash) {
  const window = wakeWindows.get(userHash);
  wakeWindows.delete(userHash);
  if (window?.repeat) wakeUser(userHash, window.repeat).catch(() => {});
}

// Budzenia jednego konta są scalane w oknie WAKE_COOLDOWN_MS: pierwsze idzie od razu, kolejne
// najwyżej raz po zamknięciu okna. Pilne budzenie po cichym nie czeka — wychodzi od razu.
async function wakeUser(userHash, kind = "msg") {
  if (IMMEDIATE_WAKE_KINDS.has(kind)) return sendWake(userHash, kind);
  const urgent = isUrgentWake(kind);
  const window = wakeWindows.get(userHash);
  if (!window) {
    wakeWindows.set(userHash, { urgent, repeat: null });
    setTimeout(closeWakeWindow, WAKE_COOLDOWN_MS, userHash).unref();
    return sendWake(userHash, kind);
  }
  if (urgent && !window.urgent) {
    window.urgent = true;
    return sendWake(userHash, kind);
  }
  if (!window.repeat || (urgent && !isUrgentWake(window.repeat))) window.repeat = kind;
}

function forgetPushState(userHash) {
  ntfyTopicCache.delete(userHash);
  pushPrefCache.delete(userHash);
}

function pushRoutes(app) {
  app.post("/api/user/ntfy-topic", { preHandler: requireAuth }, async (req) => {
    const ntfyTopic = await ensureUserNtfyTopic(req.auth.sub);
    return { ok: true, ntfyTopic };
  });

  app.get("/api/push/config", { preHandler: requireAuth, config: perMinute(30) }, async () => {
    return { fcm: fcmAvailable() };
  });

  app.post("/api/user/push", { preHandler: requireAuth, config: perHour(30) }, async (req, reply) => {
    const myHash = req.auth.sub;
    const mode = req.body?.mode === "fcm" ? "fcm" : "ntfy";
    let token = null;
    if (mode === "fcm") {
      if (!fcmAvailable()) return reply.code(409).send({ error: "fcm_unavailable" });
      token = typeof req.body?.token === "string" ? req.body.token.trim() : "";
      if (!token || token.length > 4096 || !/^[A-Za-z0-9_:\-]+$/.test(token)) {
        return reply.code(400).send({ error: "Nieprawidłowy token" });
      }
    }
    try {
      await db.query("UPDATE users SET push_mode=$2, fcm_token=$3 WHERE email_hash=$1", [myHash, mode, token]);
    } catch (e) {
      return reply.code(500).send({ error: "Błąd zapisu" });
    }
    rememberPushPref(myHash, { mode, token });
    return { ok: true, mode };
  });
}

module.exports = { pushRoutes, wakeUser, loadNtfyTopic, ensureUserNtfyTopic, forgetPushState };
