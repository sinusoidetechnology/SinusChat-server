// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

"use strict";

const { accessKeyMatches } = require("../crypto");
const { db } = require("../db");
const {
  blockedAmong,
  contactsOf,
  DAY_MS,
  groupPeersOf,
  HIDDEN_LOOKUP_LIMIT,
  isHash,
  lookupAllowed,
  perMinute,
  sendToAll,
  strangerLookupAllowed,
  withoutBlockers,
} = require("../common");
const { requireAuth } = require("./auth");

const ONLINE_WINDOW_MS = 45_000;
const MAX_PRESENCE_HASHES = 200;
// Do tego dnia klient bez `keys` w /api/presence dostaje obecność po staremu (bez sprawdzania,
// czy zna klucz dostępu). Potem obecność widzą tylko osoby z kluczem albo ze wspólnej grupy.
const PRESENCE_LEGACY_UNTIL = Date.parse("2026-12-15T00:00:00Z");

const presence = new Map();
const activeDayWritten = new Map();
function todayNumber() {
  return Math.floor(Date.now() / DAY_MS);
}
function presenceOf(hash) {
  return presence.get(hash) || { hb: 0, seen: 0 };
}
function isOnlineNow(hash) {
  const p = presence.get(hash);
  return !!p && p.hb > 0 && Date.now() - p.hb < ONLINE_WINDOW_MS;
}
async function touchActiveDay(hash) {
  const d = todayNumber();
  if (activeDayWritten.get(hash) === d) return;
  activeDayWritten.set(hash, d);
  if (activeDayWritten.size > 200000) activeDayWritten.clear();
  try {
    await db.query("UPDATE users SET last_active_day=$2 WHERE email_hash=$1 AND COALESCE(last_active_day,0) <> $2", [hash, d]);
  } catch (_) {}
}
function forgetPresence(hash) {
  presence.delete(hash);
  activeDayWritten.delete(hash);
}
const groupDayWritten = new Map();
async function touchGroupDay(groupId) {
  const d = todayNumber();
  if (groupDayWritten.get(groupId) === d) return;
  groupDayWritten.set(groupId, d);
  if (groupDayWritten.size > 100000) groupDayWritten.clear();
  try {
    await db.query("UPDATE groups SET last_active_day=$2 WHERE id=$1 AND COALESCE(last_active_day,0) <> $2", [groupId, d]);
  } catch (_) {}
}
setInterval(
  () => {
    const cut = Date.now() - 7 * DAY_MS;
    for (const [h, p] of presence) if (Math.max(p.hb, p.seen) < cut) presence.delete(h);
  },
  10 * 60 * 1000,
);

function lastSeenAfterHeartbeat({ heartbeat, clearSeen, reportedSeen, wentOffline, previous, now }) {
  if (heartbeat > 0) return now;
  if (clearSeen) return 0;
  if (wentOffline) {
    if (!previous) return 0;
    return previous.hb > 0 ? previous.hb : previous.seen;
  }
  return Math.min(Number(reportedSeen) || now, now);
}

async function presenceAudience(userHash) {
  const contacts = await contactsOf(userHash);
  if (!contacts.length) return contacts;
  const blocked = await blockedAmong(userHash, contacts);
  return contacts.filter((hash) => !blocked.has(hash));
}

function presenceRoutes(app) {
  app.post("/api/heartbeat", { preHandler: requireAuth }, async (req) => {
    const myHash = req.auth.sub;
    const now = Date.now();
    const body = req.body;
    if (body?.touchOnly === true) {
      touchActiveDay(myHash);
      return { ok: true, server_now_ms: now };
    }

    const heartbeat = body?.heartbeatMs > 0 ? now : 0;
    const reportedSeen = body?.lastSeenMs !== undefined ? body.lastSeenMs : body?.last_seen_ms;
    const clearSeen = heartbeat === 0 && (reportedSeen === 0 || reportedSeen === "0");
    const lastSeen = lastSeenAfterHeartbeat({
      heartbeat,
      clearSeen,
      reportedSeen,
      now,
      wentOffline: body?.heartbeatMs === 0,
      previous: presence.get(myHash),
    });

    const wasOnline = isOnlineNow(myHash);
    presence.set(myHash, { hb: heartbeat, seen: lastSeen });
    if (heartbeat > 0) touchActiveDay(myHash);

    if (wasOnline !== heartbeat > 0 || clearSeen) {
      try {
        sendToAll(await presenceAudience(myHash), {
          type: "presence",
          senderHash: myHash,
          heartbeatMs: heartbeat,
          lastSeenMs: lastSeen,
        });
      } catch (_) {}
    }
    return { ok: true, server_now_ms: now };
  });

  app.post("/api/presence", { preHandler: requireAuth, config: perMinute(60) }, async (req) => {
    const myHash = req.auth.sub;
    const list = Array.isArray(req.body?.hashes) ? req.body.hashes.slice(0, MAX_PRESENCE_HASHES) : [];
    const hashes = [...new Set(list.map(String).filter(isHash))];
    if (!hashes.length) return {};
    // keys: { [hash]: klucz dostępu (base64) } — dowód, że pytający zna tę osobę.
    const keys = req.body?.keys && typeof req.body.keys === "object" ? req.body.keys : null;
    const legacy = !keys && Date.now() < PRESENCE_LEGACY_UNTIL;

    const { rows } = await db.query(
      `SELECT email_hash, activity_hidden, email_block, block_new, ua_hash
         FROM users WHERE email_hash = ANY($1::varchar[])`,
      [hashes],
    );
    const visible = new Set(
      await withoutBlockers(
        rows.map((r) => r.email_hash),
        myHash,
      ),
    );
    const groupPeers = await groupPeersOf(myHash, hashes);
    const found = new Map(rows.map((r) => [r.email_hash, r]));
    const result = {};
    for (const hash of hashes) {
      const row = found.get(hash);
      const proven = !!row && (accessKeyMatches(row.ua_hash, keys?.[hash]) || groupPeers.has(hash));
      if (!proven && (!legacy || !strangerLookupAllowed(myHash, hash))) continue;
      if (!row || row.activity_hidden === true || !visible.has(hash)) continue;
      if ((row.email_block === true || row.block_new === true) && !lookupAllowed("h", myHash, hash, HIDDEN_LOOKUP_LIMIT)) continue;
      result[hash] = { online: isOnlineNow(hash), seen: presenceOf(hash).seen || 0 };
    }
    return result;
  });
}

module.exports = { presenceRoutes, presenceOf, isOnlineNow, forgetPresence, touchGroupDay };
