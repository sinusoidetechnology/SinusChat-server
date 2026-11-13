// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

"use strict";

const { hashAccessKey, keyFingerprint, randomUuid, sameHex, sha256Hex } = require("../crypto");
const { db } = require("../db");
const {
  b64ok,
  canonicalPair,
  canUseConversation,
  DAY_MS,
  DIRECT_TARGET_LIMIT,
  groupAllows,
  isBlockedBy,
  isGroupId,
  isHash,
  isParticipant,
  lookupAllowed,
  membership,
  MESSAGE_MAX_BYTES,
  otherMemberHashes,
  otherParty,
  perMinute,
  SEALED_BUDGET_BYTES,
  SEALED_MAX_B64,
  sealedFlood,
  SENDER_BUDGET_BYTES,
  sendConfirmed,
  sendToUser,
  spendBudget,
  userExists,
  withoutBlockers,
} = require("../common");
const { scrubLog } = require("../log");
const { requireAuth } = require("./auth");
const { touchGroupDay } = require("./presence");
const { wakeUser } = require("./push");

const MESSAGE_TTL_MS = DAY_MS;
const NOTIFIABLE_KINDS = new Set(["msg", "group_attach"]);
const ADDRESSED_GROUP_KINDS = new Set(["group_key", "group_key_request"]);
const QUEUED_ACKS = `kind='ack' AND sender_hash=$1 AND recipient_hash=$2 AND conversation_id=$3 AND delivered_at IS NULL`;
const CONTENT_KINDS = new Set(["msg", "group_attach"]);
const MESSAGE_ID_RE = /^[A-Za-z0-9_~.-]{1,100}$/;
const KIND_RE = /^[a-z0-9_]{1,32}$/;
// Sealed sender wysłany z urgent:false — w kolejce jako osobny rodzaj, klientowi oddawany jako "sealed".
const QUIET_SEALED = "sealed_q";
const SERVER_ONLY_KINDS = new Set(["expiry_notice", "sealed", QUIET_SEALED]);
const MAX_NOTIFIED_AUTHORS = 50;
const MAX_ONLY_RECIPIENTS = 500;
const PENDING_MAX_ROWS = 2000;
const PENDING_MAX_BYTES = 16 * 1024 * 1024;
// Aplikacja pobiera kolejkę raz na odpytanie. Gdy coś zostało ponad limit odpowiedzi,
// budzimy ją, żeby od razu dociągnęła resztę (tak jakby dostała wszystko naraz).
const PENDING_REST_WAKE_MS = 1_000;
// Wiadomości pobrane przez /api/messages/pending?confirm=1 bez potwierdzenia w /api/messages/received
// w tym czasie wracają do kolejki.
const PENDING_LEASE_MS = 60_000;
const ACK_IDS_MAX = 500;
const ACK_ID_MAX_CHARS = 110;

function markDelivered(messageIds, at) {
  return db.query("UPDATE messages SET delivered_at=$1 WHERE id = ANY($2::varchar[])", [at, messageIds]);
}

// Rodzaj budzenia wybiera serwer: klient nie może np. wysłać kind "call" i obudzić adresata jak
// przy połączeniu. Treść (msg, group_attach) budzi pilnie, wszystko inne — cicho.
function wakeKindFor(kind) {
  return CONTENT_KINDS.has(kind) ? kind : "quiet";
}

function ackIds(body) {
  return Array.isArray(body?.ids) ? body.ids.filter((x) => typeof x === "string" && x.length <= ACK_ID_MAX_CHARS).slice(0, ACK_IDS_MAX) : [];
}

// Wysyła tę samą ramkę do wielu wierszy kolejki i oznacza dostarczone jednym UPDATE. Ramka, której
// gniazdo nie potwierdzi pongiem, wraca do kolejki (delivered_at=NULL) i budzi telefon; wiersz 1:1
// po potwierdzeniu jest od razu kasowany (grupowe czekają na /api/ack albo sprzątanie).
// Zwraca liczbę wierszy wysłanych na żywo; resztę adresatów budzi, o ile podano wakeKind.
async function deliverRows(targets, frame, wakeKind, now, isGroup) {
  let marked = null;
  const live = [];
  for (const { id, recipient } of targets) {
    const onLost = async (wake) => {
      await marked;
      const { rowCount } = await db.query("UPDATE messages SET delivered_at=NULL WHERE id=$1", [id]);
      if (rowCount && wake && wakeKind) wakeUser(recipient, wakeKind).catch(() => {});
    };
    const onOk = isGroup
      ? null
      : async () => {
          await marked;
          await db.query("DELETE FROM messages WHERE id=$1 AND delivered_at IS NOT NULL", [id]);
        };
    if (sendConfirmed(recipient, frame, onLost, onOk)) live.push(id);
    else if (wakeKind) wakeUser(recipient, wakeKind).catch(() => {});
  }
  if (live.length) {
    marked = markDelivered(live, now).catch(() => {});
    await marked;
  }
  return live.length;
}

async function deliverRow(recipient, id, frame, wakeKind, now) {
  return (await deliverRows([{ id, recipient }], JSON.stringify(frame), wakeKind, now, isGroupId(frame.conversationId))) > 0;
}

async function wakeIfMorePending(userHash) {
  try {
    const { rows } = await db.query("SELECT 1 FROM messages WHERE recipient_hash=$1 AND delivered_at IS NULL LIMIT 1", [userHash]);
    if (rows.length) setTimeout(() => wakeUser(userHash, "msg").catch(() => {}), PENDING_REST_WAKE_MS).unref();
  } catch (_) {}
}

const pendingLeases = new Map();

setInterval(async () => {
  const cutoff = Date.now() - PENDING_LEASE_MS;
  for (const [user, lease] of pendingLeases) {
    const stale = [];
    for (const [id, at] of lease) {
      if (at >= cutoff) continue;
      stale.push(id);
      lease.delete(id);
    }
    if (!lease.size) pendingLeases.delete(user);
    if (!stale.length) continue;
    console.warn(`[DELIVERY] niepotwierdzone pobranie, ${stale.length} wiadomości wraca do kolejki`);
    await db.query("UPDATE messages SET delivered_at=NULL WHERE recipient_hash=$1 AND id = ANY($2::varchar[])", [user, stale]).catch(() => {});
  }
}, 10_000).unref();

function leasePending(userHash, ids, at) {
  let lease = pendingLeases.get(userHash);
  if (!lease) pendingLeases.set(userHash, (lease = new Map()));
  for (const id of ids) lease.set(id, at);
}

function releasePending(userHash, ids) {
  const lease = pendingLeases.get(userHash);
  if (!lease) return;
  for (const id of ids) lease.delete(id);
  if (!lease.size) pendingLeases.delete(userHash);
}

function groupRowIds(messageId, recipients) {
  const used = new Set();
  return recipients.map((recipient) => {
    const rowId = `${messageId}_${recipient.slice(0, 16)}`;
    if (used.has(rowId)) return `${messageId}_${sha256Hex(recipient).slice(0, 24)}`;
    used.add(rowId);
    return rowId;
  });
}

function queueMessage({ conversationId, messageId, senderHash, kind, payload, recipients, isGroup, now }) {
  const rowIds = isGroup ? groupRowIds(messageId, recipients) : [messageId];
  return db.query(
    `INSERT INTO messages(id,conversation_id,sender_hash,recipient_hash,kind,payload,created_at)
     SELECT t.id, $1, $2, t.recipient, $3, $4, $5 FROM unnest($6::varchar[], $7::varchar[]) AS t(id, recipient)
     ON CONFLICT(id) DO NOTHING RETURNING id, recipient_hash`,
    [conversationId, senderHash, kind, payload, now, rowIds, recipients],
  );
}

function baseMessageId(rowId) {
  return String(rowId).replace(/_[0-9a-f]{16}$/, "");
}

function groupBySentMessage(expired) {
  const sent = new Map();
  for (const row of expired) {
    if (!NOTIFIABLE_KINDS.has(row.kind)) continue;
    const isGroup = isGroupId(row.conversation_id);
    const baseId = isGroup ? baseMessageId(row.id) : row.id;
    const key = `${row.conversation_id}|${row.sender_hash}|${baseId}`;
    const entry = sent.get(key);
    if (entry) entry.missed++;
    else
      sent.set(key, {
        conversationId: row.conversation_id,
        senderHash: row.sender_hash,
        baseId,
        isGroup,
        missed: 1,
      });
  }
  return sent;
}

async function notifySenderOfExpiry({ conversationId, senderHash, baseId, isGroup, missed: expired }, now) {
  let total = 1;
  if (isGroup) {
    const { rows } = await db.query("SELECT COUNT(*)::int AS c FROM conversation_participants WHERE conversation_id=$1 AND user_hash!=$2", [conversationId, senderHash]);
    total = rows[0]?.c ?? expired;
  }
  const missed = Math.min(expired, total);
  const delivered = Math.max(0, total - missed);

  const noticeBody = Buffer.from(
    JSON.stringify({
      originalId: baseId,
      conversationId,
      isGroup,
      total,
      delivered,
      missed,
      expiredAt: now,
    }),
    "utf8",
  );
  const noticeId = `exp_${baseId}`;

  await db.query(
    `INSERT INTO messages(id,conversation_id,sender_hash,recipient_hash,kind,payload,created_at)
     VALUES($1,$2,$3,$4,'expiry_notice',$5,$6) ON CONFLICT(id) DO NOTHING`,
    [noticeId, conversationId, senderHash, senderHash, noticeBody, now],
  );

  await deliverRow(
    senderHash,
    noticeId,
    {
      type: "message",
      conversationId,
      id: noticeId,
      kind: "expiry_notice",
      payloadB64: noticeBody.toString("base64"),
      senderHash,
      createdAt: now,
    },
    null,
    now,
  );
}

async function purgeOldMessages() {
  try {
    const now = Date.now();
    const { rows: expired } = await db.query(
      `SELECT id, conversation_id, sender_hash, kind
         FROM messages
        WHERE delivered_at IS NULL AND created_at < $1::bigint
        LIMIT 5000`,
      [now - MESSAGE_TTL_MS],
    );
    if (!expired.length) return;

    const sent = groupBySentMessage(expired);
    for (const message of sent.values()) {
      try {
        await notifySenderOfExpiry(message, now);
      } catch (e) {
        console.error("[PURGE] powiadomienie nadawcy nie powiodło się:", scrubLog(e.message));
      }
    }

    const res = await db.query("DELETE FROM messages WHERE id = ANY($1::varchar[])", [expired.map((r) => r.id)]);
    if (res.rowCount > 0) {
      console.log(`[PURGE] usunięto ${res.rowCount} niedostarczonych, powiadomiono ${sent.size} nadawców`);
    }
  } catch (e) {
    console.error("[PURGE] błąd czyszczenia:", scrubLog(e.message));
  }
}

async function queueDirectAck(fromHash, toHash, conversationId, deliveredUpTo, readUpTo) {
  const pair = [fromHash, toHash, conversationId];
  let delivered = deliveredUpTo;
  let read = readUpTo;
  const { rows } = await db.query(`SELECT payload FROM messages WHERE ${QUEUED_ACKS}`, pair);
  for (const row of rows) {
    try {
      const queued = JSON.parse(row.payload.toString("utf8"));
      delivered = Math.max(delivered, Number(queued.deliveredUpTo) || 0);
      read = Math.max(read, Number(queued.readUpTo) || 0);
    } catch (_) {}
  }
  await db.query(`DELETE FROM messages WHERE ${QUEUED_ACKS}`, pair);
  await db.query(
    `INSERT INTO messages(id,conversation_id,sender_hash,recipient_hash,kind,payload,created_at)
     VALUES($1,$2,$3,$4,'ack',$5,$6) ON CONFLICT(id) DO NOTHING`,
    ["ack_" + randomUuid(), conversationId, fromHash, toHash, Buffer.from(JSON.stringify({ deliveredUpTo: delivered, readUpTo: read }), "utf8"), Date.now()],
  );
}

async function relayDirectAck(fromHash, conversationId, deliveredUpTo, readUpTo) {
  const delivered = Number(deliveredUpTo) || 0;
  const read = Number(readUpTo) || 0;
  if (!delivered && !read) return;
  const other = otherParty(conversationId, fromHash);
  if (!other || other === fromHash) return;
  if (await isBlockedBy(fromHash, other)) return;
  const queue = async () => {
    if (!(await userExists(other))) return;
    try {
      await queueDirectAck(fromHash, other, conversationId, delivered, read);
    } catch (_) {}
  };
  const frame = {
    type: "ack",
    conversationId,
    fromHash,
    deliveredUpTo: delivered || undefined,
    readUpTo: read || undefined,
  };
  if (sendConfirmed(other, frame, queue)) return;
  await queue();
}

async function groupSendRefusal(conversationId, myHash, kind, recipientHash) {
  if (!(await membership(conversationId, myHash))) {
    return { status: 403, body: { error: "Nie jesteś członkiem tej rozmowy" } };
  }
  if (ADDRESSED_GROUP_KINDS.has(kind) && !(recipientHash && (await isParticipant(conversationId, String(recipientHash))))) {
    return { status: 400, body: { error: "Adresat nie należy do grupy" } };
  }
  if (CONTENT_KINDS.has(kind) && !(await groupAllows(conversationId, myHash, "sendMessages"))) {
    return { status: 403, body: { error: "Nie można pisać na tej grupie", code: "group_send_forbidden" } };
  }
  return null;
}

async function directSendRefusal(conversationId, myHash, recipientHash) {
  const recipient = String(recipientHash);
  const pairOk =
    conversationId === canonicalPair(myHash, recipient) || ((await isParticipant(conversationId, myHash)) && (await isParticipant(conversationId, recipient)));
  if (!pairOk) {
    return { status: 403, body: { error: "Nieprawidłowa rozmowa", code: "conversation_mismatch" } };
  }
  if (!lookupAllowed("d", myHash, recipient, DIRECT_TARGET_LIMIT)) {
    return { status: 429, body: { error: "Za dużo nowych odbiorców — spróbuj jutro", code: "too_many_recipients" } };
  }
  if (!(await userExists(recipient))) {
    return { status: 410, body: { error: "To konto zostało usunięte", code: "account_deleted", deleted: recipient } };
  }
  if (await isBlockedBy(recipientHash, myHash)) {
    return {
      status: 403,
      body: {
        error: "Nie można wysłać wiadomości do tego odbiorcy",
        code: "blocked_by_recipient",
        blockedBy: recipientHash,
      },
    };
  }
  return null;
}

// `only` (opcjonalna lista hashy) zawęża wysyłkę grupową do wybranych członków, np. przy ponowieniu.
async function groupRecipients(conversationId, myHash, kind, recipientHash, only) {
  let recipients;
  if (ADDRESSED_GROUP_KINDS.has(kind)) {
    recipients = [String(recipientHash)];
  } else {
    recipients = await otherMemberHashes(conversationId, myHash);
    if (Array.isArray(only)) {
      const wanted = new Set(only.slice(0, MAX_ONLY_RECIPIENTS).filter(isHash));
      recipients = recipients.filter((h) => wanted.has(h));
    }
  }
  return withoutBlockers(recipients, myHash);
}

function messageRoutes(app) {
  app.get("/api/messages/waiting", { preHandler: requireAuth }, async (req) => {
    const { rows } = await db.query(
      `SELECT COUNT(*)::int AS n FROM messages
        WHERE recipient_hash=$1 AND delivered_at IS NULL AND kind IN ('msg','group_attach','sealed')`,
      [req.auth.sub],
    );
    return { count: rows[0]?.n || 0 };
  });

  app.get("/api/messages/pending", { preHandler: requireAuth }, async (req) => {
    const { rows } = await db.query(
      `SELECT id, conversation_id, sender_hash, kind, payload, created_at
         FROM (SELECT *, SUM(octet_length(payload)) OVER (ORDER BY created_at, id) AS total_bytes
                 FROM messages
                WHERE recipient_hash = $1 AND delivered_at IS NULL
                ORDER BY created_at, id
                LIMIT ${PENDING_MAX_ROWS}) queued
        WHERE total_bytes - octet_length(payload) < ${PENDING_MAX_BYTES}
        ORDER BY created_at, id`,
      [req.auth.sub],
    );
    if (!rows.length) return [];

    const ids = rows.map((r) => r.id);
    const leasedAt = Date.now();
    await markDelivered(ids, leasedAt);
    if (req.query?.confirm === "1") leasePending(req.auth.sub, ids, leasedAt);
    wakeIfMorePending(req.auth.sub);

    return rows.map((r) => ({
      id: r.id,
      conversationId: r.conversation_id,
      senderHash: r.sender_hash,
      kind: r.kind === QUIET_SEALED ? "sealed" : r.kind,
      payloadB64: r.payload.toString("base64"),
      createdAt: r.created_at,
    }));
  });

  // Potwierdzenie odbioru wiadomości pobranych z ?confirm=1. Wiersze 1:1 są od razu kasowane,
  // grupowe zostają do /api/ack (albo sprzątania dostarczonych).
  app.post("/api/messages/received", { preHandler: requireAuth }, async (req) => {
    const ids = ackIds(req.body);
    releasePending(req.auth.sub, ids);
    if (ids.length) {
      await db
        .query(
          `DELETE FROM messages WHERE recipient_hash=$1 AND id = ANY($2::varchar[])
              AND delivered_at IS NOT NULL AND left(conversation_id, 2) <> 'g_'`,
          [req.auth.sub, ids],
        )
        .catch(() => {});
    }
    return { ok: true };
  });

  app.post("/api/message", { preHandler: requireAuth }, async (req, reply) => {
    const myHash = req.auth.sub;
    const { conversationId, messageId, payloadB64, recipientHash } = req.body || {};
    if (
      typeof conversationId !== "string" ||
      !conversationId ||
      typeof messageId !== "string" ||
      !MESSAGE_ID_RE.test(messageId) ||
      typeof payloadB64 !== "string" ||
      !payloadB64
    ) {
      return reply.code(400).send({ error: "Brak danych" });
    }
    if (payloadB64.length > SEALED_MAX_B64) return reply.code(413).send({ error: "Wiadomość za duża" });
    if (!b64ok(payloadB64, SEALED_MAX_B64)) return reply.code(400).send({ error: "Brak danych" });

    const kind = req.body.kind || "msg";
    const msgBytes = Buffer.from(payloadB64, "base64");
    const now = Date.now();
    const isGroup = isGroupId(conversationId);
    if (msgBytes.length > MESSAGE_MAX_BYTES) return reply.code(413).send({ error: "Wiadomość za duża" });
    if (typeof kind !== "string" || !KIND_RE.test(kind) || SERVER_ONLY_KINDS.has(kind)) {
      return reply.code(400).send({ error: "Nieprawidłowy rodzaj wiadomości" });
    }
    if (!isGroup && !isHash(recipientHash)) return reply.code(400).send({ error: "Brak recipientHash" });

    const refusal = isGroup ? await groupSendRefusal(conversationId, myHash, kind, recipientHash) : await directSendRefusal(conversationId, myHash, recipientHash);
    if (refusal) return reply.code(refusal.status).send(refusal.body);

    if (isGroup) {
      await db.query("INSERT INTO conversations(id) VALUES($1) ON CONFLICT DO NOTHING", [conversationId]);
      touchGroupDay(conversationId);
    }

    const recipients = isGroup ? await groupRecipients(conversationId, myHash, kind, recipientHash, req.body.only) : [recipientHash];

    if (!spendBudget("s:" + myHash, msgBytes.length * Math.max(1, recipients.length), SENDER_BUDGET_BYTES)) {
      return reply.code(429).send({ error: "Za dużo danych w krótkim czasie — spróbuj później", code: "queue_budget" });
    }

    const { rows: queued } = await queueMessage({
      conversationId,
      messageId,
      senderHash: myHash,
      kind,
      payload: msgBytes,
      recipients,
      isGroup,
      now,
    });

    const frame = JSON.stringify({
      type: "message",
      conversationId,
      id: messageId,
      kind,
      payloadB64,
      senderHash: myHash,
      createdAt: now,
    });
    const targets = queued.map((r) => ({ id: r.id, recipient: r.recipient_hash }));
    const live = await deliverRows(targets, frame, wakeKindFor(kind), now, isGroup);

    return { ok: true, messageId, deliveredLive: live > 0, createdAt: now };
  });

  app.post("/api/sealed", { config: perMinute(240) }, async (req, reply) => {
    const { to, ak, id, payloadB64, ik } = req.body || {};
    if (
      typeof to !== "string" ||
      !isHash(to) ||
      typeof ak !== "string" ||
      ak.length > 64 ||
      typeof id !== "string" ||
      !MESSAGE_ID_RE.test(id) ||
      !b64ok(payloadB64, SEALED_MAX_B64)
    ) {
      return reply.code(400).send({ error: "Brak danych" });
    }

    const { rows } = await db.query("SELECT ua_hash, e2e_public_key FROM users WHERE email_hash=$1", [to]);
    const expectedKey = rows[0]?.ua_hash;
    if (!expectedKey || !sameHex(expectedKey, hashAccessKey(ak))) {
      return reply.code(401).send({ error: "Brak dostępu", code: "no_access" });
    }
    const publicKey = rows[0]?.e2e_public_key;
    if (typeof ik === "string" && publicKey && keyFingerprint(publicKey) !== ik) {
      return reply.code(409).send({ error: "Nieaktualny klucz adresata", code: "stale_key" });
    }

    const ephemeral = req.body.eph === true;
    if (sealedFlood(to)) return reply.code(429).send({ error: "Za dużo wiadomości" });
    if (!ephemeral && !spendBudget("r:" + to, payloadB64.length, SEALED_BUDGET_BYTES)) {
      return reply.code(429).send({ error: "Za dużo wiadomości" });
    }

    const now = Date.now();
    const rowId = "s_" + id;
    if (ephemeral) {
      sendToUser(to, { type: "message", kind: "sealed", eph: true, id: rowId, payloadB64, createdAt: now });
      return { ok: true, createdAt: now };
    }

    // urgent:false = cicha ramka (np. potwierdzenie, klucz): budzi bez wysokiego priorytetu FCM.
    const quiet = req.body.urgent === false;
    const inserted = await db.query(
      `INSERT INTO messages(id,conversation_id,sender_hash,recipient_hash,kind,payload,created_at)
       VALUES($1,'',NULL,$2,$5,$3,$4) ON CONFLICT(id) DO NOTHING`,
      [rowId, to, Buffer.from(payloadB64, "base64"), now, quiet ? QUIET_SEALED : "sealed"],
    );
    if (!inserted.rowCount) return { ok: true, messageId: id, createdAt: now };

    const frame = { type: "message", kind: "sealed", id: rowId, payloadB64, createdAt: now };
    const live = await deliverRow(to, rowId, frame, quiet ? "quiet" : "msg", now);
    return { ok: true, messageId: id, deliveredLive: live, createdAt: now };
  });

  app.post("/api/sealed/ack", { preHandler: requireAuth }, async (req) => {
    const ids = ackIds(req.body);
    if (!ids.length) return { ok: true, deleted: 0 };
    releasePending(req.auth.sub, ids);
    const { rowCount } = await db.query("DELETE FROM messages WHERE recipient_hash=$1 AND kind IN ('sealed','sealed_q') AND id = ANY($2::varchar[])", [
      req.auth.sub,
      ids,
    ]);
    return { ok: true, deleted: rowCount };
  });

  app.post("/api/ack", { preHandler: requireAuth }, async (req, reply) => {
    const myHash = req.auth.sub;
    const { conversationId, readUpTo, silentRead, noRelay } = req.body || {};
    if (!conversationId) return reply.code(400).send({ error: "Brak conversationId" });
    const deliveredUpTo = Number.isSafeInteger(req.body.deliveredUpTo) ? req.body.deliveredUpTo : 0;
    if (!(await canUseConversation(conversationId, myHash))) {
      return reply.code(403).send({ error: "Brak dostępu do rozmowy" });
    }

    const deleted =
      deliveredUpTo &&
      (await db
        .query(
          `DELETE FROM messages WHERE recipient_hash=$1 AND conversation_id=$2 AND created_at <= $3::bigint
              AND delivered_at IS NOT NULL
       RETURNING sender_hash`,
          [myHash, conversationId, deliveredUpTo],
        )
        .catch(() => null));

    if (!noRelay && !isGroupId(conversationId)) {
      await relayDirectAck(myHash, conversationId, deliveredUpTo, silentRead ? null : readUpTo);
    } else if (!noRelay && deleted) {
      const authors = new Set(deleted.rows.map((r) => r.sender_hash).filter((h) => h && h !== myHash));
      for (const author of [...authors].slice(0, MAX_NOTIFIED_AUTHORS)) {
        if (await isBlockedBy(myHash, author)) continue;
        sendToUser(author, { type: "ack", conversationId, fromHash: myHash, deliveredUpTo });
      }
    }
    return { ok: true, deliveredUpTo, readUpTo };
  });
}

module.exports = { messageRoutes, MESSAGE_TTL_MS, purgeOldMessages, relayDirectAck };
