// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

"use strict";

const { accessKeyMatches, randomBase64Url, randomUuid } = require("../crypto");
const { db } = require("../db");
const {
  colorOk,
  groupAllows,
  isBlockedBy,
  isGroupBanned,
  isHash,
  isParticipant,
  knownContact,
  memberCount,
  memberHashes,
  membership,
  newChatsBlocked,
  otherMemberHashes,
  perHour,
  perMinute,
  sendToAll,
  sendToUser,
  userExists,
  withoutBlockers,
} = require("../common");
const { requireAuth } = require("./auth");
const { gcallDropMember } = require("./calls");
const { isOnlineNow, touchGroupDay } = require("./presence");
const { signalCapable } = require("./signal");

const GROUP_INVITE_RE = /^grp_[A-Za-z0-9_-]{20,40}$/;
const MAX_GROUP_MEMBERS = 1000;
const MAX_GROUP_NAME_CHARS = 1024;
const MAX_GROUP_DESCRIPTION_CHARS = 8192;
const GROUP_PERM_KEYS = ["editSettings", "sendMessages", "addMembers", "callGroup"];
const DEFAULT_GROUP_COLOR = "#5288C1";
const GROUP_AVATAR_RE = /^https:\/\/files\.sinusoide\.pl\/api\/uploads\/group_avatars\/[0-9a-f]{32}\.(jpg|png|webp|bin)(\?v=\d{1,16})?$/;
const NOT_MEMBER = { error: "Nie jesteś członkiem" };
const ADMIN_ONLY = { error: "Tylko administrator" };
const LINK_BROKEN = { error: "Link nie działa", code: "group_invite_invalid" };
const GROUP_ADMIN = [requireAuth, requireGroupAdmin];

function groupIsCommunity(group) {
  if (!group) return false;
  if (group.kind) return group.kind === "community";
  let perms = group.perms || {};
  if (typeof perms === "string") {
    try {
      perms = JSON.parse(perms);
    } catch (_) {
      perms = {};
    }
  }
  return perms.sendMessages === false;
}

function addMember(groupId, userHash) {
  return db.query("INSERT INTO conversation_participants(conversation_id,user_hash) VALUES($1,$2) ON CONFLICT DO NOTHING", [groupId, userHash]);
}

async function removeMember(groupId, userHash) {
  const member = [groupId, userHash];
  await db.query("DELETE FROM conversation_participants WHERE conversation_id=$1 AND user_hash=$2", member);
  await db.query("DELETE FROM conversation_meta WHERE conversation_id=$1 AND user_hash=$2", member);
  await gcallDropMember(groupId, userHash);
}

function groupFieldsRefusal({ name, description, avatarColor }) {
  if (name != null && (typeof name !== "string" || name.length > MAX_GROUP_NAME_CHARS)) return "Nieprawidłowa nazwa";
  if (description != null && (typeof description !== "string" || description.length > MAX_GROUP_DESCRIPTION_CHARS)) {
    return "Nieprawidłowy opis";
  }
  if (avatarColor != null && !colorOk(avatarColor)) return "Nieprawidłowy kolor";
  return null;
}

function cleanPerms(perms) {
  if (!perms || typeof perms !== "object") return null;
  const known = GROUP_PERM_KEYS.filter((key) => typeof perms[key] === "boolean");
  return known.length ? Object.fromEntries(known.map((key) => [key, perms[key]])) : null;
}

async function requireGroupAdmin(req, reply) {
  const { rows } = await db.query(
    `SELECT g.*, cp.is_admin FROM groups g
       JOIN conversation_participants cp ON cp.conversation_id = g.id AND cp.user_hash = $2
      WHERE g.id = $1`,
    [req.params.groupId, req.auth.sub],
  );
  if (!rows.length) return reply.code(403).send({ error: "Nie jesteś członkiem" });
  if (!rows[0].is_admin) return reply.code(403).send({ error: "Tylko administrator", code: "not_admin" });
  req.group = rows[0];
}

async function findGroupByInvite(code) {
  if (!GROUP_INVITE_RE.test(code)) return null;
  const { rows } = await db.query("SELECT * FROM groups WHERE invite_code=$1", [code]);
  return rows[0] && groupIsCommunity(rows[0]) ? rows[0] : null;
}

function cleanGroupAvatarUrl(url) {
  if (url === "") return "";
  if (typeof url !== "string") return undefined;
  return GROUP_AVATAR_RE.test(url) ? url : undefined;
}

function fetchGroup(groupId) {
  return db.query("SELECT * FROM groups WHERE id=$1", [groupId]).then((r) => r.rows[0]);
}

async function invitableMembers(members, myHash, accessKeys) {
  const candidates = [...new Set(members)].filter((hash) => isHash(hash) && hash !== myHash);
  // Blokady to tagi HMAC (src/blocks.js), więc odsiewa się je przed zapytaniem, a nie w SQL.
  const hashes = await withoutBlockers(candidates, myHash);
  if (!hashes.length) return [];
  const { rows } = await db.query(
    `SELECT u.email_hash, u.block_new, u.ua_hash,
            EXISTS (SELECT 1 FROM conversation_participants cp1
                      JOIN conversation_participants cp2 ON cp1.conversation_id = cp2.conversation_id
                     WHERE cp1.user_hash = $2 AND cp2.user_hash = u.email_hash
                       AND cp1.conversation_id LIKE 'g!_%' ESCAPE '!') AS shares_group
       FROM users u WHERE u.email_hash = ANY($1::varchar[])`,
    [hashes, myHash],
  );
  return rows.filter((r) => r.block_new !== true || r.shares_group || accessKeyMatches(r.ua_hash, accessKeys[r.email_hash])).map((r) => r.email_hash);
}

function groupRoutes(app) {
  app.post("/api/groups/create", { preHandler: requireAuth }, async (req, reply) => {
    const myHash = req.auth.sub;
    const { name, description, members, avatarColor, avatarUrl, aks } = req.body || {};
    if (!name || !Array.isArray(members) || !members.length) {
      return reply.code(400).send({ error: "Brak nazwy lub członków" });
    }
    const fieldsRefusal = groupFieldsRefusal(req.body);
    if (fieldsRefusal) return reply.code(400).send({ error: fieldsRefusal });
    if (new Set(members.map(String)).size >= MAX_GROUP_MEMBERS) {
      return reply.code(409).send({ error: "Za dużo członków", code: "group_full" });
    }
    const groupAvatar = cleanGroupAvatarUrl(avatarUrl) || null;
    const kind = ["community", "group", "custom"].includes(req.body.kind) ? req.body.kind : null;
    const groupDescription = description || "";
    const color = avatarColor || DEFAULT_GROUP_COLOR;

    const invited = await invitableMembers(members, myHash, aks && typeof aks === "object" ? aks : {});
    if (!invited.length) return reply.code(403).send({ error: "Nie można dodać tych osób do grupy" });

    const groupId = "g_" + randomUuid();
    const allMembers = [myHash, ...invited];
    await db.query(
      `WITH conversation AS (INSERT INTO conversations(id) VALUES($1)),
            new_group AS (
              INSERT INTO groups(id,name,description,avatar_color,created_by,created_at,avatar_url,kind)
              VALUES($1,$2,$3,$4,$5::text,$6,$7,$8))
       INSERT INTO conversation_participants(conversation_id,user_hash,is_admin)
       SELECT $1, member, member = $5 FROM unnest($9::varchar[]) AS member`,
      [groupId, name, groupDescription, color, myHash, Date.now(), groupAvatar, kind, allMembers],
    );
    touchGroupDay(groupId);

    sendToAll(invited, {
      type: "group_created",
      groupId,
      name,
      description: groupDescription,
      avatarColor: color,
      createdBy: myHash,
      members: allMembers,
    });
    return { ok: true, groupId, name, members: allMembers };
  });

  app.get("/api/groups/:groupId", { preHandler: requireAuth }, async (req, reply) => {
    const myHash = req.auth.sub;
    const { groupId } = req.params;
    const me = await membership(groupId, myHash);
    if (!me) return reply.code(403).send(NOT_MEMBER);
    const group = await fetchGroup(groupId);
    if (!group) return reply.code(404).send({ error: "Nie znaleziono" });
    touchGroupDay(groupId);

    const { rows: members } = await db.query(
      `SELECT cp.user_hash, cp.is_admin, u.display_name, u.avatar_url, u.avatar_color, u.activity_hidden
         FROM conversation_participants cp
         LEFT JOIN users u ON u.email_hash=cp.user_hash
        WHERE cp.conversation_id=$1`,
      [groupId],
    );
    const signalSet = await signalCapable(members.map((m) => m.user_hash));
    let activeCount = 0;
    for (const m of members) {
      if (m.user_hash === myHash || (m.activity_hidden !== true && isOnlineNow(m.user_hash))) activeCount++;
      m.signal = signalSet.has(m.user_hash);
    }

    const { invite_code: inviteCode, invite_created_at: _, ...publicGroup } = group;
    return {
      ...publicGroup,
      is_community: groupIsCommunity(group),
      has_invite_link: !!inviteCode,
      ...(me.is_admin ? { invite_code: inviteCode || null } : {}),
      members,
      activeCount,
      server_now_ms: Date.now(),
    };
  });

  app.post("/api/groups/:groupId/add", { preHandler: requireAuth }, async (req, reply) => {
    const myHash = req.auth.sub;
    const { groupId } = req.params;
    const { userHash, ak } = req.body || {};
    if (!isHash(userHash)) return reply.code(400).send({ error: "Brak userHash" });

    const me = await membership(groupId, myHash);
    if (!me) return reply.code(403).send(NOT_MEMBER);
    if (!(await groupAllows(groupId, myHash, "addMembers"))) {
      return reply.code(403).send({ error: "Nie możesz dodawać członków", code: "group_add_forbidden" });
    }

    if (!(await userExists(userHash))) {
      return reply.code(403).send({ error: "Nie można dodać tej osoby do grupy" });
    }
    if (await isGroupBanned(groupId, userHash)) {
      if (!me.is_admin) {
        return reply.code(403).send({ error: "Tę osobę usunął administrator", code: "group_member_banned" });
      }
      await db.query("DELETE FROM group_bans WHERE group_id=$1 AND user_hash=$2", [groupId, userHash]).catch(() => {});
    }

    if (await isBlockedBy(userHash, myHash)) {
      return reply.code(403).send({ error: "Nie można dodać tej osoby do grupy" });
    }
    if (!(await knownContact(await newChatsBlocked(userHash), userHash, myHash, ak))) {
      return reply.code(403).send({ error: "Nie można dodać tej osoby do grupy", code: "block_new" });
    }
    if ((await memberCount(groupId)) >= MAX_GROUP_MEMBERS) {
      return reply.code(409).send({ error: "Grupa jest pełna", code: "group_full" });
    }

    await addMember(groupId, userHash);

    const group = await fetchGroup(groupId);
    const members = await memberHashes(groupId);
    sendToUser(userHash, { type: "group_added", groupId, name: group?.name, avatarColor: group?.avatar_color, members });
    sendToAll(
      members.filter((h) => h !== userHash),
      { type: "group_member_added", groupId, newMember: userHash },
    );
    return { ok: true };
  });

  app.post("/api/groups/:groupId/kick", { preHandler: requireAuth }, async (req, reply) => {
    const { groupId } = req.params;
    const { userHash } = req.body || {};
    if (!isHash(userHash)) return reply.code(400).send({ error: "Brak userHash" });

    const me = await membership(groupId, req.auth.sub);
    if (!me?.is_admin) return reply.code(403).send(ADMIN_ONLY);
    const { rows } = await db.query("SELECT created_by FROM groups WHERE id=$1", [groupId]);
    if (rows[0]?.created_by === userHash) return reply.code(400).send({ error: "Nie można wyrzucić twórcy" });

    await removeMember(groupId, userHash);
    await db.query("INSERT INTO group_bans(group_id,user_hash,created_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", [groupId, userHash, Date.now()]).catch(() => {});

    sendToUser(userHash, { type: "group_kicked", groupId });
    sendToAll(await memberHashes(groupId), { type: "group_member_removed", groupId, removed: userHash });
    return { ok: true };
  });

  app.post("/api/groups/:groupId/admin", { preHandler: requireAuth }, async (req, reply) => {
    const { groupId } = req.params;
    const { userHash, makeAdmin } = req.body || {};
    if (!isHash(userHash)) return reply.code(400).send({ error: "Brak userHash" });

    const me = await membership(groupId, req.auth.sub);
    if (!me?.is_admin) return reply.code(403).send(ADMIN_ONLY);

    const isAdmin = !!makeAdmin;
    await db.query("UPDATE conversation_participants SET is_admin=$3 WHERE conversation_id=$1 AND user_hash=$2", [groupId, userHash, isAdmin]);
    sendToAll(await memberHashes(groupId), { type: "group_admin_changed", groupId, userHash, isAdmin });
    return { ok: true };
  });

  app.post("/api/groups/:groupId/settings", { preHandler: requireAuth }, async (req, reply) => {
    const myHash = req.auth.sub;
    const { groupId } = req.params;
    const { disappearingTtlMs } = req.body || {};
    const perms = cleanPerms(req.body?.perms);
    const changesTtl = Number.isSafeInteger(disappearingTtlMs) && disappearingTtlMs >= 0;
    const changesPerms = perms !== null;
    if (!changesTtl && !changesPerms) return reply.code(400).send({ error: "Brak zmian" });

    const me = await membership(groupId, myHash);
    if (!me) return reply.code(403).send({ error: "Nie jestes czlonkiem" });
    if (changesPerms && !me.is_admin) return reply.code(403).send(ADMIN_ONLY);
    if (changesTtl && !(await groupAllows(groupId, myHash, "editSettings"))) {
      return reply.code(403).send({ error: "Nie mozesz zmieniac ustawien grupy", code: "group_edit_forbidden" });
    }

    if (changesTtl) {
      await db.query("UPDATE groups SET disappearing_ttl_ms=$2 WHERE id=$1", [groupId, disappearingTtlMs]);
    }
    if (changesPerms) {
      await db.query("UPDATE groups SET perms=$2 WHERE id=$1", [groupId, JSON.stringify(perms)]);
    }
    sendToAll(await memberHashes(groupId), {
      type: "group_settings_changed",
      groupId,
      disappearingTtlMs: changesTtl ? disappearingTtlMs : undefined,
      perms: perms || undefined,
    });
    return { ok: true };
  });

  app.post("/api/groups/:groupId/leave", { preHandler: requireAuth }, async (req) => {
    const myHash = req.auth.sub;
    const { groupId } = req.params;
    if (!(await isParticipant(groupId, myHash))) return { ok: true };
    await removeMember(groupId, myHash);

    const remaining = await memberHashes(groupId);
    sendToAll(remaining, { type: "group_member_left", groupId, userHash: myHash, silent: req.body?.silent === true });
    if (!remaining.length) {
      await db.query("DELETE FROM groups WHERE id=$1", [groupId]);
      await db.query("DELETE FROM conversations WHERE id=$1", [groupId]);
      await db.query("DELETE FROM conversation_meta WHERE conversation_id=$1", [groupId]);
      await db.query("DELETE FROM group_bans WHERE group_id=$1", [groupId]).catch(() => {});
    }
    return { ok: true };
  });

  app.post("/api/groups/:groupId/update", { preHandler: requireAuth }, async (req, reply) => {
    const myHash = req.auth.sub;
    const { groupId } = req.params;
    const { name, description, avatarColor } = req.body || {};
    const avatarUrl = cleanGroupAvatarUrl(req.body?.avatarUrl);
    const fieldsRefusal = groupFieldsRefusal(req.body || {});
    if (fieldsRefusal) return reply.code(400).send({ error: fieldsRefusal });

    if (!(await membership(groupId, myHash))) return reply.code(403).send(NOT_MEMBER);
    if (!(await groupAllows(groupId, myHash, "editSettings"))) {
      return reply.code(403).send({ error: "Nie możesz zmieniać ustawień grupy", code: "group_edit_forbidden" });
    }

    await db.query(
      `UPDATE groups SET name=COALESCE($2,name), description=COALESCE($3,description),
         avatar_color=COALESCE($4,avatar_color),
         avatar_url = CASE WHEN $5::text = '' THEN NULL ELSE COALESCE($5::text, avatar_url) END
       WHERE id=$1`,
      [groupId, name, description, avatarColor, avatarUrl === undefined ? null : avatarUrl],
    );

    sendToAll(await otherMemberHashes(groupId, myHash), {
      type: "group_updated",
      groupId,
      name,
      description,
      avatarColor,
      avatarUrl,
      by: myHash,
    });
    return { ok: true };
  });

  app.post("/api/groups/:groupId/invite", { preHandler: GROUP_ADMIN, config: perHour(30) }, async (req, reply) => {
    const { group } = req;
    if (!groupIsCommunity(group)) {
      return reply.code(400).send({ error: "Link jest dostępny tylko dla społeczności", code: "not_community" });
    }

    let code = group.invite_code;
    let createdAt = Number(group.invite_created_at) || null;
    if (!code || req.body?.reset === true) {
      code = "grp_" + randomBase64Url(18);
      createdAt = Date.now();
      await db.query("UPDATE groups SET invite_code=$2, invite_created_at=$3 WHERE id=$1", [group.id, code, createdAt]);
    }
    return { ok: true, code, createdAt, memberCount: await memberCount(group.id) };
  });

  app.post("/api/groups/:groupId/invite/revoke", { preHandler: GROUP_ADMIN, config: perHour(30) }, async (req) => {
    await db.query("UPDATE groups SET invite_code=NULL, invite_created_at=NULL WHERE id=$1", [req.group.id]);
    return { ok: true };
  });

  app.get("/api/group-invite/:code", { preHandler: requireAuth, config: perMinute(30) }, async (req, reply) => {
    const myHash = req.auth.sub;
    const group = await findGroupByInvite(String(req.params.code || ""));
    if (!group || (await isGroupBanned(group.id, myHash))) return reply.code(404).send(LINK_BROKEN);

    const members = await memberHashes(group.id);
    const alreadyMember = members.includes(myHash);
    return {
      ok: true,
      name: group.name,
      description: group.description || "",
      avatarColor: group.avatar_color || DEFAULT_GROUP_COLOR,
      avatarUrl: group.avatar_url || null,
      memberCount: members.length,
      alreadyMember,
      groupId: alreadyMember ? group.id : null,
    };
  });

  app.post("/api/group-invite/join", { preHandler: requireAuth, config: perHour(20) }, async (req, reply) => {
    const myHash = req.auth.sub;
    const group = await findGroupByInvite(String(req.body?.code || ""));
    if (!group) return reply.code(404).send(LINK_BROKEN);

    const { rows: members } = await db.query("SELECT user_hash, is_admin FROM conversation_participants WHERE conversation_id=$1", [group.id]);
    const result = {
      ok: true,
      groupId: group.id,
      name: group.name,
      avatarColor: group.avatar_color || DEFAULT_GROUP_COLOR,
      avatarUrl: group.avatar_url || null,
    };
    const hashes = members.map((m) => m.user_hash);
    if (hashes.includes(myHash)) return { ...result, alreadyMember: true };

    const admins = members.filter((m) => m.is_admin).map((m) => m.user_hash);
    if ((await withoutBlockers(admins, myHash)).length < admins.length) return reply.code(404).send(LINK_BROKEN);
    if (await isGroupBanned(group.id, myHash)) return reply.code(404).send(LINK_BROKEN);
    if (members.length >= MAX_GROUP_MEMBERS) {
      return reply.code(409).send({ error: "Społeczność jest pełna", code: "group_full" });
    }

    await addMember(group.id, myHash);

    sendToUser(myHash, {
      type: "group_added",
      groupId: group.id,
      name: group.name,
      avatarColor: group.avatar_color,
      members: [...hashes, myHash],
      selfJoin: true,
    });
    sendToAll(hashes, { type: "group_member_added", groupId: group.id, newMember: myHash });
    return result;
  });
}

module.exports = { groupRoutes, removeMember };
