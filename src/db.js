// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

"use strict";

const pg = require("pg");

const { DB_URL } = require("./config");
const { uploadHmacHex } = require("./crypto");
const { scrubLog } = require("./log");

const db = new pg.Pool({
  connectionString: DB_URL,
  max: 20,
  connectionTimeoutMillis: 10_000,
  idleTimeoutMillis: 30_000,
  statement_timeout: 60_000,
  idle_in_transaction_session_timeout: 60_000,
});
db.on("error", (err) => console.error("[DB]", scrubLog(err.message)));

async function ensureSchema() {
  const stmts = [
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS chat_privacy_mode boolean DEFAULT false`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS activity_hidden   boolean DEFAULT false`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS email_block       boolean DEFAULT false`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS block_new         boolean DEFAULT false`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS ntfy_topic        varchar(64)`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS push_mode         varchar(8) DEFAULT 'ntfy'`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS fcm_token         text`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS active_device_id  varchar(128)`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS call_e2e          boolean DEFAULT false`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_heartbeat_ms bigint DEFAULT 0`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_ms      bigint DEFAULT 0`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS deletion_scheduled_at bigint`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS auto_delete_after_sec bigint DEFAULT 0`,
    `ALTER TABLE conversation_participants ADD COLUMN IF NOT EXISTS is_admin boolean DEFAULT false`,
    `UPDATE conversation_participants cp SET is_admin = true
       FROM groups g
      WHERE g.id = cp.conversation_id
        AND cp.user_hash = g.created_by
        AND cp.is_admin IS NOT TRUE`,
    `ALTER TABLE groups ADD COLUMN IF NOT EXISTS perms jsonb DEFAULT '{}'::jsonb`,
    `ALTER TABLE groups ADD COLUMN IF NOT EXISTS avatar_url text`,
    `ALTER TABLE conversations ADD COLUMN IF NOT EXISTS disappearing_ttl_ms  bigint DEFAULT 0`,
    `ALTER TABLE conversations ADD COLUMN IF NOT EXISTS disappearing_trigger varchar(16) DEFAULT 'read'`,
    `CREATE INDEX IF NOT EXISTS idx_messages_undelivered
       ON messages (created_at) WHERE delivered_at IS NULL`,
    `DROP INDEX IF EXISTS idx_messages_delivered`,
    `DROP INDEX IF EXISTS idx_groups_id`,
    `CREATE INDEX IF NOT EXISTS idx_messages_delivered_at
       ON messages (delivered_at) WHERE delivered_at IS NOT NULL`,
    `CREATE INDEX IF NOT EXISTS idx_messages_recipient_conversation
       ON messages (recipient_hash, conversation_id, created_at)`,
    `CREATE INDEX IF NOT EXISTS idx_blocked_users_blocked ON blocked_users (blocked_hash)`,
    `CREATE TABLE IF NOT EXISTS bug_reports (
       id           bigserial PRIMARY KEY,
       user_hash    varchar(64),
       email        varchar(254),
       name         varchar(100),
       topic        varchar(16)  NOT NULL DEFAULT 'other',
       description  text         NOT NULL,
       app_version  varchar(40),
       device       varchar(120),
       android      varchar(20),
       diagnostics  text,
       status       varchar(16)  NOT NULL DEFAULT 'pending',
       reply        text,
       replied_at   bigint,
       created_at   bigint       NOT NULL,
       updated_at   bigint
     )`,
    `CREATE INDEX IF NOT EXISTS idx_bug_reports_user    ON bug_reports (user_hash, created_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_bug_reports_created ON bug_reports (created_at DESC)`,
    `ALTER TABLE bug_reports ALTER COLUMN status SET DEFAULT 'pending'`,
    `UPDATE bug_reports SET status = 'pending'   WHERE status IN ('new', 'in_progress')`,
    `UPDATE bug_reports SET status = 'confirmed' WHERE status = 'resolved'`,
    `ALTER TABLE bug_reports ADD COLUMN IF NOT EXISTS decided_at bigint`,
    `ALTER TABLE bug_reports ADD COLUMN IF NOT EXISTS platform varchar(24)`,
    `CREATE TABLE IF NOT EXISTS contact_invites (
       code        varchar(48) PRIMARY KEY,
       owner_hash  varchar(64) NOT NULL,
       kind        varchar(8)  NOT NULL,
       created_at  bigint      NOT NULL,
       expires_at  bigint,
       used_at     bigint,
       used_by     varchar(64),
       revoked     boolean     NOT NULL DEFAULT false,
       use_count   integer     NOT NULL DEFAULT 0
     )`,
    `CREATE INDEX IF NOT EXISTS idx_contact_invites_owner ON contact_invites (owner_hash, kind)`,
    `ALTER TABLE groups ADD COLUMN IF NOT EXISTS kind              varchar(16)`,
    `ALTER TABLE groups ADD COLUMN IF NOT EXISTS invite_code       varchar(48)`,
    `ALTER TABLE groups ADD COLUMN IF NOT EXISTS invite_created_at bigint`,
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_invite_code ON groups (invite_code) WHERE invite_code IS NOT NULL`,
    `CREATE TABLE IF NOT EXISTS group_bans (
       group_id    varchar(64) NOT NULL,
       user_hash   varchar(64) NOT NULL,
       created_at  bigint      NOT NULL,
       PRIMARY KEY (group_id, user_hash)
     )`,
    `CREATE TABLE IF NOT EXISTS signal_keys (
       user_hash          varchar(64) PRIMARY KEY,
       identity_key       text    NOT NULL,
       registration_id    integer NOT NULL,
       signed_prekey_id   integer NOT NULL,
       signed_prekey      text    NOT NULL,
       signed_prekey_sig  text    NOT NULL,
       kyber_prekey_id    integer NOT NULL,
       kyber_prekey       text    NOT NULL,
       kyber_prekey_sig   text    NOT NULL,
       updated_at         bigint  NOT NULL
     )`,
    `CREATE TABLE IF NOT EXISTS signal_prekeys (
       user_hash  varchar(64) NOT NULL,
       key_id     integer     NOT NULL,
       pub        text        NOT NULL,
       PRIMARY KEY (user_hash, key_id)
     )`,
    `ALTER TABLE groups ALTER COLUMN name TYPE text`,
    `ALTER TABLE groups ALTER COLUMN description TYPE text`,
    `ALTER TABLE users ALTER COLUMN display_name TYPE text`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS ua_hash text`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_key_wrap text`,
    `ALTER TABLE messages ALTER COLUMN sender_hash DROP NOT NULL`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_active_day integer`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS account_kind varchar(8) DEFAULT 'email'`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS login_key text`,
    `DELETE FROM conversation_meta WHERE conversation_id NOT LIKE 'g!_%' ESCAPE '!'`,
    `ALTER TABLE groups ADD COLUMN IF NOT EXISTS last_active_day integer`,
    `UPDATE groups g SET last_active_day = COALESCE(
       (SELECT (NULLIF(MAX(cm.last_message_at), 0) / 86400000)::integer FROM conversation_meta cm WHERE cm.conversation_id = g.id),
       ((extract(epoch from now()) * 1000)::bigint / 86400000)::integer)
     WHERE g.last_active_day IS NULL`,
    `DELETE FROM conversation_meta`,
    `DELETE FROM conversation_participants WHERE conversation_id NOT LIKE 'g!_%' ESCAPE '!'`,
    `DELETE FROM conversations WHERE id NOT LIKE 'g!_%' ESCAPE '!'`,
    `UPDATE users SET last_active_day = (GREATEST(COALESCE(last_seen_ms,0), COALESCE(last_heartbeat_ms,0)) / 86400000)::integer
      WHERE last_active_day IS NULL AND GREATEST(COALESCE(last_seen_ms,0), COALESCE(last_heartbeat_ms,0)) > 0`,
    `UPDATE users SET last_active_day = ((extract(epoch from now()) * 1000)::bigint / 86400000)::integer
      WHERE last_active_day IS NULL`,
    `UPDATE users SET last_heartbeat_ms = 0, last_seen_ms = 0
      WHERE COALESCE(last_heartbeat_ms,0) <> 0 OR COALESCE(last_seen_ms,0) <> 0`,
    `CREATE TABLE IF NOT EXISTS server_flags (name varchar(64) PRIMARY KEY)`,
    `ALTER TABLE blocked_users ALTER COLUMN blocked_at DROP DEFAULT`,
    `UPDATE blocked_users SET blocked_at = NULL WHERE blocked_at IS NOT NULL`,
  ];
  let failed = 0;
  for (const sql of stmts) {
    try {
      await db.query(sql);
    } catch (e) {
      failed++;
      console.error("[SCHEMA] BŁĄD:", scrubLog(e.message), "← przy:", sql.replace(/\s+/g, " ").slice(0, 90));
    }
  }
  if (failed > 0) {
    console.error(
      `[SCHEMA] ${failed} zmian(y) schematu NIE weszło. Najczęściej: użytkownik bazy ` +
        "z DATABASE_URL nie jest właścicielem tabel. Uruchom migracja_sinuschat.sql jako postgres.",
    );
  } else {
    console.log("[SCHEMA] schemat aktualny");
  }
}

async function migrateAvatarNames() {
  try {
    const { rows } = await db.query(`SELECT email_hash, avatar_url FROM users WHERE avatar_url ~ '/uploads/avatars/[0-9a-f]{64}[.]'`);
    let moved = 0;
    for (const { email_hash, avatar_url } of rows) {
      const m = String(avatar_url).match(/\/uploads\/avatars\/([0-9a-f]{64})\.(jpg|png|webp)/);
      if (!m) continue;
      const base = uploadHmacHex("avatar|" + m[1]).slice(0, 32);
      await db.query("UPDATE users SET avatar_url=$1 WHERE email_hash=$2", [avatar_url.replace(`${m[1]}.${m[2]}`, `${base}.${m[2]}`), email_hash]);
      moved++;
    }
    if (moved) console.log("[AVATAR] nowe nazwy zdjęć profilowych:", moved);
  } catch (e) {
    console.error("[AVATAR] zmiana nazw nieudana:", scrubLog(e.message));
  }
}

module.exports = { db, ensureSchema, migrateAvatarNames };
