// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

"use strict";

const { db } = require("../db");
const { DAY_MS, directMember, groupAllows, isGroupId, isParticipant, memberCount, membership, otherMemberHashes, sendToAll } = require("../common");
const { requireAuth } = require("./auth");
const { removeMember } = require("./groups");
const { isOnlineNow, presenceOf } = require("./presence");

const MAX_TTL_MS = 365 * DAY_MS;

async function requireParticipant(req, reply) {
  if (!(await membership(req.params.id, req.auth.sub))) {
    return reply.code(403).send({ error: "Nie jesteś uczestnikiem" });
  }
}

function conversationRoutes(app) {
  app.get("/api/conversations", { preHandler: requireAuth }, async (req) => {
    const { rows } = await db.query(
      `
      SELECT
        c.id,
        CASE WHEN c.id LIKE 'g_%' THEN NULL ELSE cp2.user_hash END as other_hash,
        CASE WHEN c.id LIKE 'g_%' THEN NULL ELSE u.display_name   END as other_name,
        CASE WHEN c.id LIKE 'g_%' THEN g.avatar_url ELSE u.avatar_url END as avatar_url,
        CASE WHEN c.id LIKE 'g_%' THEN NULL ELSE u.e2e_public_key END as e2e_public_key,
        CASE WHEN c.id LIKE 'g_%' THEN NULL ELSE u.chat_privacy_mode END as chat_privacy_mode,
        (c.id NOT LIKE 'g_%' AND u.activity_hidden = true) as other_hidden,
        g.name         as group_name,
        g.avatar_color as group_avatar_color,
        -- Nieprzeczytane, czas ostatniej wiadomości i znaczki liczy telefon.
        0 as unread_count,
        NULL::bigint as last_message_at,
        NULL::bigint as delivered_up_to,
        NULL::bigint as read_up_to,
        NULL::bigint as other_delivered_up_to,
        NULL::bigint as other_read_up_to,
        (c.id LIKE 'g_%') as is_group
      FROM conversations c
      JOIN conversation_participants cp  ON cp.conversation_id = c.id AND cp.user_hash = $1
      LEFT JOIN conversation_participants cp2
        ON cp2.conversation_id = c.id AND cp2.user_hash != $1 AND c.id NOT LIKE 'g_%'
      LEFT JOIN users u                  ON u.email_hash = cp2.user_hash
      LEFT JOIN groups g                 ON g.id = c.id
    `,
      [req.auth.sub],
    );
    for (const row of rows) {
      const showPresence = !row.is_group && row.other_hash && row.other_hidden !== true;
      const activity = showPresence ? presenceOf(row.other_hash) : { hb: 0, seen: 0 };
      row.last_heartbeat_ms = activity.hb;
      row.last_seen_ms = activity.seen;
      row.is_online = showPresence ? isOnlineNow(row.other_hash) : false;
      delete row.other_hidden;
    }
    return rows;
  });

  app.post("/api/conversations/wipe", { preHandler: requireAuth }, async (req) => {
    const myHash = req.auth.sub;
    await db.query(
      `DELETE FROM messages
        WHERE recipient_hash=$1
           OR (sender_hash=$1 AND conversation_id IN
                (SELECT conversation_id FROM conversation_participants WHERE user_hash=$1))`,
      [myHash],
    );
    await db.query("DELETE FROM conversation_meta WHERE user_hash=$1", [myHash]);
    return { ok: true };
  });

  app.post("/api/conversations/delete", { preHandler: requireAuth }, async (req, reply) => {
    const myHash = req.auth.sub;
    const convId = req.body?.conversationId;
    if (!convId || typeof convId !== "string") return reply.code(400).send({ error: "Brak conversationId" });

    if (!isGroupId(convId)) {
      if (directMember(convId, myHash)) {
        await db.query("DELETE FROM messages WHERE conversation_id=$1 AND (recipient_hash=$2 OR sender_hash=$2)", [convId, myHash]);
      }
      return { ok: true };
    }

    const wasMember = await isParticipant(convId, myHash);
    await removeMember(convId, myHash);
    await db.query("DELETE FROM messages WHERE conversation_id=$1 AND recipient_hash=$2", [convId, myHash]);
    if (!wasMember) return { ok: true };

    if ((await memberCount(convId)) === 0) {
      await db.query("DELETE FROM messages WHERE conversation_id=$1", [convId]);
      await db.query("DELETE FROM conversation_meta WHERE conversation_id=$1", [convId]);
      await db.query("DELETE FROM conversations WHERE id=$1", [convId]);
      await db.query("DELETE FROM groups WHERE id=$1", [convId]);
    }
    return { ok: true };
  });

  app.get("/api/conversation/:id/ttl", { preHandler: [requireAuth, requireParticipant] }, async (req) => {
    const { rows } = await db.query("SELECT disappearing_ttl_ms, disappearing_trigger FROM conversations WHERE id=$1", [req.params.id]);
    return {
      disappearing_ttl: Number(rows[0]?.disappearing_ttl_ms || 0),
      disappearing_trigger: rows[0]?.disappearing_trigger || "read",
      server_now_ms: Date.now(),
    };
  });

  app.post("/api/conversation/:id/ttl", { preHandler: [requireAuth, requireParticipant] }, async (req, reply) => {
    const convId = req.params.id;
    if (isGroupId(convId) && !(await groupAllows(convId, req.auth.sub, "editSettings"))) {
      return reply.code(403).send({ error: "Nie możesz zmieniać ustawień grupy", code: "group_edit_forbidden" });
    }
    const ttlMs = Number(req.body?.disappearingTtlMs ?? req.body?.disappearing_ttl ?? 0);
    const trigger = String(req.body?.disappearingTrigger ?? req.body?.disappearing_trigger ?? "read");
    if (!Number.isFinite(ttlMs) || ttlMs < 0 || ttlMs > MAX_TTL_MS) {
      return reply.code(400).send({ error: "Nieprawidłowy czas" });
    }
    if (trigger !== "read" && trigger !== "received") {
      return reply.code(400).send({ error: "Nieprawidłowy wyzwalacz" });
    }

    const disappearingTtlMs = Math.round(ttlMs);
    await db.query("UPDATE conversations SET disappearing_ttl_ms=$2::bigint, disappearing_trigger=$3 WHERE id=$1", [convId, disappearingTtlMs, trigger]);

    sendToAll(await otherMemberHashes(convId, req.auth.sub), {
      type: "conversation_ttl_changed",
      conversationId: convId,
      disappearingTtlMs,
      disappearingTrigger: trigger,
    });
    return { ok: true };
  });
}

module.exports = { conversationRoutes };
