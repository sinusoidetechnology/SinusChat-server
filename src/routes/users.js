// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

"use strict";

const { bt } = require("../blocks");
const { REQUIRE_AUTH_PROOF } = require("../config");
const { accessKeyMatches, hashAccessKey, sameHex, sha256Hex, uploadHmacHex } = require("../crypto");
const { db } = require("../db");
const {
  b64ok,
  closeConnection,
  colorOk,
  connections,
  DAY_MS,
  HIDDEN_LOOKUP_LIMIT,
  isBlockedBy,
  isHash,
  kickSocket,
  knownContact,
  lookupAllowed,
  searchAllowed,
  sendToUser,
  sharesGroup,
  strangerLookupAllowed,
} = require("../common");
const { scrubLog } = require("../log");
const {
  ANON_DEFAULT_IDLE_SEC,
  anonPending,
  authProofKind,
  bearerToken,
  EMAIL_DEFAULT_IDLE_SEC,
  proofPredatesBoot,
  requireAuth,
  signToken,
  verifyActiveDevice,
} = require("./auth");
const { forgetPresence, isOnlineNow, presenceOf } = require("./presence");
const { ensureUserNtfyTopic, forgetPushState, wakeUser } = require("./push");
const { announceKeyChange, currentKeyOf, dropSignalKeys, signalCapable } = require("./signal");

const USER_AVATAR_RE = /^https:\/\/files\.sinusoide\.pl\/api\/uploads\/avatars\/([0-9a-f]{32}|[0-9a-f]{64})\.(jpg|png|webp|bin)(\?v=\d{1,16})?$/;
const USER_AVATAR_FILE_RE = /\/uploads\/avatars\/((?:[0-9a-f]{32}|[0-9a-f]{64})\.(?:jpg|png|webp|bin))/;
const DEVICE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_PUBLIC_KEY_CHARS = 128;
const ACCOUNT_DELETION_DELAY_MS = 14 * DAY_MS;
const SQL_NAME_RE = /^[a-z_][a-z0-9_]*$/;
const ACCOUNT_HASH_COLUMNS = [
  ["users", "email_hash"],
  ["conversation_participants", "user_hash"],
  ["conversation_meta", "user_hash"],
  ["messages", "sender_hash"],
  ["messages", "recipient_hash"],
  ["groups", "created_by"],
];
const MAX_AUTO_DELETE_SEC = 100 * 365 * 24 * 3600;
const ACCESS_KEY_BYTES = 16;
const NOT_FOUND = { error: "Nie znaleziono" };
const PROFILE_COLUMNS = `email_hash, display_name, avatar_url, avatar_color, avatar_updated_at, e2e_public_key,
  key_updated_at, chat_privacy_mode, activity_hidden, email_block, block_new, last_heartbeat_ms, last_seen_ms,
  ua_hash, profile_key_wrap, call_e2e, account_kind`;

function profileFieldsRefusal({ e2ePublicKey, avatarColor }) {
  if (e2ePublicKey != null && !b64ok(e2ePublicKey, MAX_PUBLIC_KEY_CHARS)) return "Nieprawidłowy klucz publiczny";
  if (avatarColor != null && !colorOk(avatarColor)) return "Nieprawidłowy kolor";
  return null;
}

function cleanUserAvatarUrl(url) {
  if (url === "") return "";
  if (typeof url !== "string") return undefined;
  return USER_AVATAR_RE.test(url) ? url : undefined;
}

function avatarFileOf(url) {
  const m = typeof url === "string" ? url.match(USER_AVATAR_FILE_RE) : null;
  return m ? m[1] : "";
}
async function purgeAvatarFile(hash, avatarUrl, mode = "all") {
  const file = avatarFileOf(avatarUrl);
  if (mode === "file" && !file) return false;
  const expires = String(Date.now() + 5 * 60 * 1000);
  const sig = uploadHmacHex(`purge_avatar|${hash}|${file}|${mode}|${expires}`);
  try {
    const res = await fetch("https://files.sinusoide.pl/api/upload.php", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ action: "purge_avatar", account: hash, file, mode, expires, sig }).toString(),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) console.warn("[AVATAR] kasowanie zdjęcia nieudane: HTTP", res.status);
    return res.ok;
  } catch (e) {
    console.warn("[AVATAR] kasowanie zdjęcia nieudane:", scrubLog(e.message));
    return false;
  }
}

async function withSavepoint(client, name, work) {
  await client.query(`SAVEPOINT ${name}`);
  try {
    await work();
    return true;
  } catch (_) {
    await client.query(`ROLLBACK TO SAVEPOINT ${name}`);
    return false;
  }
}

async function moveAccount(client, oldHash, newHash) {
  try {
    const { rows } = await client.query("SELECT 1 FROM users WHERE email_hash=$1", [newHash]);
    if (rows.length) return false;

    const move = (table, column) => client.query(`UPDATE ${table} SET ${column}=$1 WHERE ${column}=$2`, [newHash, oldHash]);

    await client.query("BEGIN");
    for (const [table, column] of ACCOUNT_HASH_COLUMNS) await move(table, column);
    // Blokady są zapisane jako tagi HMAC (zob. src/blocks.js), więc przenosi się tag, nie hash.
    for (const column of ["blocker_hash", "blocked_hash"]) {
      await client.query(`UPDATE blocked_users SET ${column}=$1 WHERE ${column}=$2`, [bt(newHash), bt(oldHash)]);
    }
    await withSavepoint(client, "bans", () => move("group_bans", "user_hash"));
    await withSavepoint(client, "signal", async () => {
      await move("signal_prekeys", "user_hash");
      await move("signal_keys", "user_hash");
    });
    await withSavepoint(client, "invites", async () => {
      await move("contact_invites", "owner_hash");
      await move("contact_invites", "used_by");
    });
    await withSavepoint(client, "reports", () => move("bug_reports", "user_hash"));
    await client.query("COMMIT");
    return true;
  } catch (e) {
    try {
      await client.query("ROLLBACK");
    } catch (_) {}
    throw e;
  }
}

async function clearUserReferences(client, hash) {
  const user = (await client.query("SELECT * FROM users WHERE email_hash=$1", [hash])).rows[0];
  if (!user) return;
  const { rows: refs } = await client.query(
    `SELECT kcu.table_name, kcu.column_name, pk.column_name AS ref_column, col.is_nullable
       FROM information_schema.referential_constraints rc
       JOIN information_schema.key_column_usage kcu
         ON kcu.constraint_name = rc.constraint_name AND kcu.constraint_schema = rc.constraint_schema
       JOIN information_schema.key_column_usage pk
         ON pk.constraint_name = rc.unique_constraint_name AND pk.constraint_schema = rc.unique_constraint_schema
        AND pk.ordinal_position = kcu.position_in_unique_constraint
       JOIN information_schema.columns col
         ON col.table_schema = kcu.table_schema AND col.table_name = kcu.table_name
        AND col.column_name = kcu.column_name
      WHERE pk.table_name = 'users' AND kcu.table_schema = current_schema()`,
  );
  for (const { table_name: table, column_name: column, ref_column: refColumn, is_nullable: nullable } of refs) {
    if (table === "users") continue;
    if (![table, column, refColumn].every((n) => SQL_NAME_RE.test(n))) continue;
    const value = user[refColumn];
    if (value === null || value === undefined) continue;
    await client.query("SAVEPOINT ref");
    try {
      if (nullable === "YES") {
        await client.query(`UPDATE "${table}" SET "${column}"=NULL WHERE "${column}"=$1`, [value]);
      } else {
        await client.query(`DELETE FROM "${table}" WHERE "${column}"=$1`, [value]);
      }
    } catch (e) {
      await client.query("ROLLBACK TO SAVEPOINT ref");
      console.warn("[ACCOUNT] nie wyczyszczono", table + "." + column + ":", scrubLog(e.message));
    }
  }
}

async function releaseOwnedGroups(client, hash) {
  const cleared = await withSavepoint(client, "owner", () => client.query("UPDATE groups SET created_by=NULL WHERE created_by=$1", [hash]));
  if (cleared) return;
  await client.query(
    `UPDATE groups g SET created_by = cp.user_hash
       FROM (SELECT DISTINCT ON (conversation_id) conversation_id, user_hash
               FROM conversation_participants
              WHERE user_hash <> $1
              ORDER BY conversation_id, is_admin DESC NULLS LAST) cp
      WHERE g.id = cp.conversation_id AND g.created_by = $1`,
    [hash],
  );
  await withSavepoint(client, "orphan", () => client.query("DELETE FROM groups WHERE created_by=$1", [hash]));
}

async function deleteUserData(hash) {
  forgetPresence(hash);
  forgetPushState(hash);
  let avatarUrl = null;
  try {
    const { rows } = await db.query("SELECT avatar_url FROM users WHERE email_hash=$1", [hash]);
    avatarUrl = rows[0]?.avatar_url || null;
  } catch (_) {}
  const client = await db.connect();
  const remove = (sql) => client.query(sql, [hash]);
  try {
    await client.query("BEGIN");
    await remove("DELETE FROM messages WHERE sender_hash=$1 OR recipient_hash=$1");
    await remove("DELETE FROM conversation_meta WHERE user_hash=$1");
    await remove("DELETE FROM conversation_participants WHERE user_hash=$1");
    await client.query("DELETE FROM blocked_users WHERE blocker_hash=$1 OR blocked_hash=$1", [bt(hash)]);
    await releaseOwnedGroups(client, hash);
    await withSavepoint(client, "reports", () => remove("DELETE FROM bug_reports WHERE user_hash=$1"));
    await withSavepoint(client, "invites", () => remove("DELETE FROM contact_invites WHERE owner_hash=$1"));
    await withSavepoint(client, "bans", () => remove("DELETE FROM group_bans WHERE user_hash=$1"));
    await withSavepoint(client, "signal", async () => {
      await remove("DELETE FROM signal_prekeys WHERE user_hash=$1");
      await remove("DELETE FROM signal_keys WHERE user_hash=$1");
    });
    await clearUserReferences(client, hash);
    await remove("DELETE FROM users WHERE email_hash=$1");
    await client.query("COMMIT");
    purgeAvatarFile(hash, avatarUrl, "all");
  } catch (e) {
    try {
      await client.query("ROLLBACK");
    } catch (_) {}
    throw e;
  } finally {
    client.release();
  }
}

async function deleteAccounts(rows, failureLabel) {
  let removed = 0;
  for (const { email_hash } of rows) {
    try {
      await deleteUserData(email_hash);
      closeConnection(email_hash);
      removed++;
    } catch (e) {
      console.error(`[ACCOUNT] błąd usuwania ${failureLabel} konta:`, scrubLog(e.message));
    }
  }
  return removed;
}

async function purgeScheduledAccounts() {
  try {
    const { rows } = await db.query("SELECT email_hash FROM users WHERE deletion_scheduled_at IS NOT NULL AND deletion_scheduled_at <= $1", [
      Date.now() - ACCOUNT_DELETION_DELAY_MS,
    ]);
    const removed = await deleteAccounts(rows, "zaplanowanego");
    if (removed) console.log("[ACCOUNT] usunięto zaplanowane konta:", removed);
  } catch (e) {
    console.error("[ACCOUNT] błąd przeglądu zaplanowanych usunięć:", scrubLog(e.message));
  }
}

async function purgeInactiveAccounts() {
  try {
    const { rows } = await db.query(
      `SELECT email_hash FROM users
        WHERE COALESCE(auto_delete_after_sec,0) > 0
          AND last_active_day IS NOT NULL
          AND (last_active_day::bigint + 1) * 86400000 <= $1::bigint - auto_delete_after_sec * 1000`,
      [Date.now()],
    );
    const removed = await deleteAccounts(rows, "nieużywanego");
    if (removed) console.log("[ACCOUNT] usunięto nieużywane konta:", removed);
  } catch (e) {
    console.error("[ACCOUNT] błąd przeglądu nieużywanych kont:", scrubLog(e.message));
  }
}

async function isStranger(user, hash, viewerHash, accessKey) {
  if (accessKey && user.ua_hash && sameHex(hashAccessKey(accessKey), user.ua_hash)) return false;
  const { rows } = await db.query(
    `SELECT 1 FROM conversation_participants cp1
     JOIN conversation_participants cp2 ON cp1.conversation_id = cp2.conversation_id
     WHERE cp1.user_hash = $1 AND cp2.user_hash = $2 LIMIT 1`,
    [viewerHash, hash],
  );
  return rows.length === 0;
}

function parseAutoDeleteSec(value) {
  if (value === undefined || value === null) return null;
  const seconds = Number(value);
  return Number.isFinite(seconds) && seconds >= 0 ? Math.min(Math.floor(seconds), MAX_AUTO_DELETE_SEC) : null;
}

async function currentAvatarUrl(hash) {
  try {
    const { rows } = await db.query("SELECT avatar_url FROM users WHERE email_hash=$1", [hash]);
    return rows[0]?.avatar_url || null;
  } catch (_) {
    return null;
  }
}

async function saveProfileKeyWrap(hash, wrap) {
  if (typeof wrap !== "string" || !wrap.length || wrap.length > 256) return;
  await db.query("UPDATE users SET profile_key_wrap=$2 WHERE email_hash=$1", [hash, wrap]);
}

async function saveAccessKey(hash, accessKey) {
  if (typeof accessKey !== "string" || accessKey.length > 64) return;
  const raw = Buffer.from(accessKey, "base64");
  if (raw.length !== ACCESS_KEY_BYTES) return;
  await db.query("UPDATE users SET ua_hash=$2 WHERE email_hash=$1", [hash, sha256Hex(raw)]);
}

async function accountKindOf(hash) {
  const { rows } = await db.query("SELECT account_kind FROM users WHERE email_hash=$1", [hash]);
  return rows.length ? rows[0].account_kind || "email" : null;
}

async function resolveAccountClaim(hash, existing, kind, proof) {
  const anon = anonPending.get(hash);
  if (!existing && kind === "anon" && !(anon && anon.exp > Date.now())) {
    return { error: "Dowód wygasł, zaloguj się ponownie", code: "anon_proof_expired" };
  }
  if (!existing || existing === kind) return null;
  if (kind === "anon" || proofPredatesBoot(proof)) {
    return { error: "Wymagane potwierdzenie adresu e-mail", code: "email_verification_required" };
  }
  await deleteUserData(hash);
  closeConnection(hash);
  return null;
}

async function unblockUser(myHash, hash) {
  await db.query("DELETE FROM blocked_users WHERE blocker_hash=$1 AND blocked_hash=$2", [bt(myHash), bt(hash)]);
  sendToUser(hash, { type: "unblocked", by: myHash });
}

function userRoutes(app) {
  app.post("/api/register", async (req, reply) => {
    const { emailHash, displayName, e2ePublicKey, keyUpdatedAt, avatarUrl, avatarColor, avatarUpdatedAt, deviceId, authProof } = req.body || {};
    if (!emailHash) return reply.code(400).send({ error: "Brak danych" });
    if (displayName != null && displayName !== "" && (typeof displayName !== "string" || displayName.length > 1024)) {
      return reply.code(400).send({ error: "Nieprawidłowa nazwa" });
    }
    if (!isHash(emailHash)) {
      return reply.code(400).send({ error: "Nieprawidłowy emailHash" });
    }
    const fieldsRefusal = profileFieldsRefusal(req.body);
    if (fieldsRefusal) return reply.code(400).send({ error: fieldsRefusal });
    if (deviceId != null && (typeof deviceId !== "string" || !DEVICE_ID_RE.test(deviceId))) {
      return reply.code(400).send({ error: "Nieprawidłowe urządzenie" });
    }

    const proofKind = authProofKind(authProof, emailHash);
    if (!proofKind) {
      if (REQUIRE_AUTH_PROOF) {
        return reply.code(401).send({
          error: "Wymagane potwierdzenie adresu e-mail",
          code: "email_verification_required",
        });
      }
      console.warn("[REGISTER] rejestracja bez dowodu weryfikacji e-maila");
    }

    const existingKind = await accountKindOf(emailHash);
    const accountKind = proofKind || existingKind || "email";
    const refusal = await resolveAccountClaim(emailHash, existingKind, accountKind, authProof);
    if (refusal) return reply.code(401).send(refusal);

    const oldKey = e2ePublicKey ? await currentKeyOf(emailHash) : null;
    const anon = accountKind === "anon" ? anonPending.get(emailHash) : null;

    const { rowCount } = await db.query(
      `
      INSERT INTO users(email_hash, display_name, e2e_public_key, key_updated_at, avatar_color, avatar_url,
                        avatar_updated_at, auto_delete_after_sec, account_kind, login_key, active_device_id)
      VALUES($1,COALESCE($2,''),$3,$4,COALESCE($6,'#5288C1'),$5,COALESCE($7,0),$8,$9,$10,$11)
      ON CONFLICT(email_hash) DO UPDATE SET
        display_name      = COALESCE($2, users.display_name),
        e2e_public_key    = COALESCE(EXCLUDED.e2e_public_key, users.e2e_public_key),
        key_updated_at    = COALESCE(EXCLUDED.key_updated_at, users.key_updated_at),
        avatar_color      = COALESCE(EXCLUDED.avatar_color, users.avatar_color),
        avatar_url        = COALESCE(EXCLUDED.avatar_url, users.avatar_url),
        avatar_updated_at = GREATEST(COALESCE(EXCLUDED.avatar_updated_at,0),
                                     COALESCE(users.avatar_updated_at,0)),
        active_device_id  = COALESCE(EXCLUDED.active_device_id, users.active_device_id)
      WHERE COALESCE(users.account_kind, 'email') = EXCLUDED.account_kind`,
      [
        emailHash,
        displayName || null,
        e2ePublicKey || null,
        keyUpdatedAt || null,
        cleanUserAvatarUrl(avatarUrl) || null,
        avatarColor || null,
        avatarUpdatedAt || null,
        accountKind === "anon" ? ANON_DEFAULT_IDLE_SEC : EMAIL_DEFAULT_IDLE_SEC,
        accountKind,
        anon?.loginKey || null,
        deviceId || null,
      ],
    );
    if (!rowCount) return reply.code(409).send({ error: "Konto właśnie się zmieniło, spróbuj ponownie" });
    if (anon) anonPending.delete(emailHash);

    if (e2ePublicKey && oldKey && oldKey !== e2ePublicKey) await dropSignalKeys(emailHash);
    if (e2ePublicKey) announceKeyChange(emailHash, oldKey, e2ePublicKey);
    if (deviceId) {
      const prev = connections.get(emailHash);
      if (prev && prev.deviceId !== deviceId) {
        kickSocket(prev);
        connections.delete(emailHash);
      }
      wakeUser(emailHash, "kicked").catch(() => {});
    }
    const token = signToken(emailHash, deviceId || null);
    const ntfyTopic = await ensureUserNtfyTopic(emailHash);
    let autoDeleteAfterSec = null;
    try {
      const { rows } = await db.query("SELECT auto_delete_after_sec FROM users WHERE email_hash=$1", [emailHash]);
      if (rows.length) autoDeleteAfterSec = Number(rows[0].auto_delete_after_sec || 0);
    } catch (_) {}
    return { token, userHash: emailHash, ntfyTopic, autoDeleteAfterSec };
  });

  app.get("/api/user/:hash", async (req, reply) => {
    const { hash } = req.params;
    let viewer = await verifyActiveDevice(bearerToken(req));
    if (viewer?.kicked) viewer = null;
    const proofKind = viewer ? null : authProofKind(req.headers["x-auth-proof"], hash);
    if (!viewer && !proofKind) return reply.code(401).send({ error: "Brak autoryzacji" });
    if (!isHash(hash)) return reply.code(404).send(NOT_FOUND);

    const { rows } = await db.query(`SELECT ${PROFILE_COLUMNS} FROM users WHERE email_hash=$1`, [hash]);
    const accessKey = String(req.headers["x-access-key"] || "");
    const isOwner = !viewer || viewer.sub === hash;
    const contact = isOwner || (rows.length > 0 && (accessKeyMatches(rows[0].ua_hash, accessKey) || (await sharesGroup(viewer.sub, hash))));
    if (!contact && !strangerLookupAllowed(viewer.sub, hash)) {
      return reply.code(429).send({ error: "Za dużo wyszukiwań — spróbuj później" });
    }
    if (!rows.length) return reply.code(404).send(NOT_FOUND);
    const [user] = rows;
    const accountKind = user.account_kind || "email";
    delete user.account_kind;
    if (proofKind && proofKind !== accountKind) return reply.code(404).send(NOT_FOUND);

    const isSearch = String(req.headers["x-search"]) === "true";
    if (isSearch && (user.email_block === true || accountKind === "anon")) return reply.code(404).send(NOT_FOUND);

    if (user.block_new === true && !isOwner && !(await knownContact({ uaHash: user.ua_hash }, hash, viewer.sub, accessKey))) {
      return reply.code(404).send(NOT_FOUND);
    }

    const stranger = user.email_block === true && !isOwner && (await isStranger(user, hash, viewer.sub, accessKey));
    if (stranger && !lookupAllowed("h", viewer.sub, hash, HIDDEN_LOOKUP_LIMIT)) {
      return reply.code(404).send(NOT_FOUND);
    }
    if (stranger) {
      delete user.avatar_url;
      delete user.avatar_updated_at;
    }

    const activityHidden = user.activity_hidden === true;
    const blockedByOwner = viewer ? await isBlockedBy(hash, viewer.sub) : false;
    // Obecność widzi tylko właściciel, ktoś z kluczem dostępu albo ze wspólnej grupy.
    const hidePresence = activityHidden || !viewer || blockedByOwner || stranger || !contact;
    const activity = presenceOf(hash);

    delete user.block_new;
    delete user.email_block;
    delete user.ua_hash;
    delete user.activity_hidden;
    if (!isOwner || !user.profile_key_wrap) delete user.profile_key_wrap;

    user.last_heartbeat_ms = hidePresence ? 0 : activity.hb;
    user.last_seen_ms = hidePresence ? 0 : activity.seen;
    user.is_online = isOnlineNow(hash) && !hidePresence;
    user.signal = (await signalCapable([hash])).has(hash);
    user.call_e2e = user.call_e2e === true;
    user.server_now_ms = Date.now();
    return user;
  });

  app.post("/api/user/update", { preHandler: requireAuth }, async (req, reply) => {
    const myHash = req.auth.sub;
    const {
      displayName,
      avatarUrl,
      chatPrivacyMode,
      activityHidden,
      avatarColor,
      avatarUpdatedAt,
      e2ePublicKey,
      keyUpdatedAt,
      emailBlock,
      autoDeleteAfterSec,
      blockNew,
      profileKeyWrap,
      accessKey,
    } = req.body || {};
    if (displayName != null && (typeof displayName !== "string" || displayName.length > 1024)) {
      return reply.code(400).send({ error: "Nieprawidłowa nazwa" });
    }
    const fieldsRefusal = profileFieldsRefusal(req.body || {});
    if (fieldsRefusal) return reply.code(400).send({ error: fieldsRefusal });

    const oldKey = e2ePublicKey ? await currentKeyOf(myHash) : null;

    const safeAvatar = cleanUserAvatarUrl(avatarUrl);
    const clearAvatar = safeAvatar === "";
    const newAvatar = safeAvatar || null;
    const oldAvatar = safeAvatar !== undefined ? await currentAvatarUrl(myHash) : null;

    await db.query(
      `UPDATE users SET
         display_name      = COALESCE($2, display_name),
         avatar_url        = CASE WHEN $6::boolean THEN NULL ELSE COALESCE($3, avatar_url) END,
         chat_privacy_mode = COALESCE($4, chat_privacy_mode),
         activity_hidden   = COALESCE($10, activity_hidden),
         avatar_color      = COALESCE($5, avatar_color),
         avatar_updated_at = GREATEST(COALESCE($7::bigint,0), COALESCE(avatar_updated_at,0)),
         e2e_public_key    = COALESCE($8, e2e_public_key),
         key_updated_at    = COALESCE($9::bigint, key_updated_at),
         email_block       = COALESCE($11, email_block),
         auto_delete_after_sec = COALESCE($12::bigint, auto_delete_after_sec),
         block_new         = COALESCE($13, block_new)
       WHERE email_hash=$1`,
      [
        myHash,
        displayName ?? null,
        newAvatar,
        chatPrivacyMode ?? null,
        avatarColor ?? null,
        clearAvatar,
        avatarUpdatedAt ?? null,
        e2ePublicKey ?? null,
        keyUpdatedAt ?? null,
        activityHidden ?? null,
        emailBlock ?? null,
        parseAutoDeleteSec(autoDeleteAfterSec),
        typeof blockNew === "boolean" ? blockNew : null,
      ],
    );

    if (blockNew === true) {
      await db.query("UPDATE contact_invites SET revoked=true WHERE owner_hash=$1 AND revoked=false", [myHash]).catch(() => {});
    }
    if (e2ePublicKey && oldKey && oldKey !== e2ePublicKey) await dropSignalKeys(myHash);
    if (e2ePublicKey) announceKeyChange(myHash, oldKey, e2ePublicKey);
    await saveProfileKeyWrap(myHash, profileKeyWrap);
    await saveAccessKey(myHash, accessKey);

    if (clearAvatar) {
      purgeAvatarFile(myHash, oldAvatar, "all");
    } else if (newAvatar && avatarFileOf(oldAvatar) && avatarFileOf(oldAvatar) !== avatarFileOf(newAvatar)) {
      purgeAvatarFile(myHash, oldAvatar, "file");
    }
    return { ok: true };
  });

  app.post("/api/user/change-email", { preHandler: requireAuth }, async (req, reply) => {
    const oldHash = req.auth.sub;
    const { newHash, authProof } = req.body || {};
    if ((await accountKindOf(oldHash)) === "anon") {
      return reply.code(409).send({ error: "Konto bez e-maila", code: "anon_account" });
    }
    if (!isHash(newHash)) {
      return reply.code(400).send({ error: "Brak lub nieprawidłowy newHash" });
    }

    if (authProofKind(authProof, newHash) !== "email") {
      if (REQUIRE_AUTH_PROOF) {
        return reply.code(401).send({
          error: "Wymagane potwierdzenie nowego adresu e-mail",
          code: "email_verification_required",
        });
      }
      console.warn("[CHANGE-EMAIL] zmiana adresu bez dowodu weryfikacji");
    }
    if (newHash === oldHash) {
      return reply.code(400).send({ error: "Nowy e-mail jest taki sam jak obecny" });
    }
    await resolveAccountClaim(newHash, await accountKindOf(newHash), "email", authProof);

    const client = await db.connect();
    try {
      if (!(await moveAccount(client, oldHash, newHash))) {
        return reply.code(409).send({ error: "Ten e-mail jest już w użyciu" });
      }
    } catch (e) {
      console.error("[ACCOUNT] zmiana e-maila nieudana:", scrubLog(e.message));
      return reply.code(500).send({ error: "Zmiana e-maila nie powiodła się" });
    } finally {
      client.release();
    }

    forgetPresence(oldHash);
    forgetPushState(oldHash);
    const oldSocket = connections.get(oldHash);
    if (oldSocket) {
      connections.delete(oldHash);
      try {
        oldSocket.close();
      } catch (_) {}
    }
    return { ok: true, token: signToken(newHash, req.auth.deviceId || null), userHash: newHash };
  });

  app.post("/api/user/delete-account", { preHandler: requireAuth }, async (req, reply) => {
    const myHash = req.auth.sub;
    try {
      await deleteUserData(myHash);
      closeConnection(myHash);
      return { ok: true };
    } catch (e) {
      console.error("[ACCOUNT] usunięcie konta nieudane:", scrubLog(e.message), e.table ? "| tabela: " + e.table : "", e.constraint ? "| ograniczenie: " + e.constraint : "");
      return reply.code(500).send({ error: "Usunięcie konta nie powiodło się" });
    }
  });

  app.get("/api/user/deletion", { preHandler: requireAuth }, async (req) => {
    const { rows } = await db.query("SELECT deletion_scheduled_at FROM users WHERE email_hash=$1", [req.auth.sub]);
    const scheduledAt = rows[0]?.deletion_scheduled_at ? Number(rows[0].deletion_scheduled_at) : null;
    return {
      scheduledAt,
      deleteAt: scheduledAt ? scheduledAt + ACCOUNT_DELETION_DELAY_MS : null,
      now: Date.now(),
    };
  });

  app.post("/api/user/deletion", { preHandler: requireAuth }, async (req, reply) => {
    const myHash = req.auth.sub;
    if (req.body?.cancel === true) {
      await db.query("UPDATE users SET deletion_scheduled_at=NULL WHERE email_hash=$1", [myHash]);
      return { ok: true, scheduledAt: null, deleteAt: null };
    }
    const now = Date.now();
    const { rows } = await db.query(
      `UPDATE users SET deletion_scheduled_at = COALESCE(deletion_scheduled_at, $2)
        WHERE email_hash=$1 RETURNING deletion_scheduled_at`,
      [myHash, now],
    );
    if (!rows.length) return reply.code(404).send({ error: "Nie znaleziono konta" });
    const scheduledAt = Number(rows[0].deletion_scheduled_at);
    return { ok: true, scheduledAt, deleteAt: scheduledAt + ACCOUNT_DELETION_DELAY_MS, now };
  });

  app.post("/api/user/block", { preHandler: requireAuth }, async (req, reply) => {
    const myHash = req.auth.sub;
    const { blockedHash, block } = req.body || {};
    if (!isHash(blockedHash)) return reply.code(400).send({ error: "Brak blockedHash" });
    if (block) {
      await db.query("INSERT INTO blocked_users(blocker_hash,blocked_hash,blocked_at) VALUES($1,$2,NULL) ON CONFLICT DO NOTHING", [
        bt(myHash),
        bt(blockedHash),
      ]);
    } else {
      await unblockUser(myHash, blockedHash);
    }
    return { ok: true, blocked: !!block };
  });

  app.post("/api/user/unblock", { preHandler: requireAuth }, async (req, reply) => {
    const hash = req.body?.unblockedHash || req.body?.blockedHash;
    if (!isHash(hash)) return reply.code(400).send({ error: "Brak hasha" });
    await unblockUser(req.auth.sub, hash);
    return { ok: true, blocked: false };
  });

  app.get("/api/users/search", { preHandler: requireAuth }, async (req, reply) => {
    const myHash = req.auth.sub;
    const q = String(req.query.q || "").trim();
    if (q.length < 2 || q.length > 64) return [];
    const exact = isHash(q);
    const allowed = exact ? lookupAllowed("s", myHash, q, HIDDEN_LOOKUP_LIMIT) : searchAllowed(myHash);
    if (!allowed) return reply.code(429).send({ error: "Za dużo wyszukiwań — spróbuj później" });

    const match = exact
      ? { sql: "email_hash = $1 AND COALESCE(account_kind, 'email') <> 'anon'", value: q }
      : { sql: "display_name ILIKE $1 ESCAPE '\\'", value: "%" + q.replace(/([\\%_])/g, "\\$1") + "%" };
    const { rows } = await db.query(
      `SELECT email_hash, display_name, avatar_url, e2e_public_key, key_updated_at
       FROM users WHERE ${match.sql} AND email_hash != $2
         AND COALESCE(email_block, false) = false AND COALESCE(block_new, false) = false LIMIT 10`,
      [match.value, myHash],
    );
    return rows;
  });
}

module.exports = { userRoutes, purgeScheduledAccounts, purgeInactiveAccounts };
