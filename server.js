/*
 * SinusChat — serwer
 * Copyright © 2026 Sinusoide Technology
 *
 * Ten program jest wolnym oprogramowaniem na licencji GNU Affero General Public
 * License w wersji 3 (AGPL-3.0), z tymi samymi warunkami dodatkowymi z sekcji 7
 * co aplikacja SinusChat:
 *  - licencja nie daje praw do nazw „SinusChat", „Sinia" i „Sinusoide" ani do logo;
 *    zmieniona wersja musi mieć własną nazwę (7 e),
 *  - zmieniona wersja musi być wyraźnie opisana jako zmieniona i niepochodząca
 *    od Sinusoide Technology i nie może być przedstawiana jako oficjalny serwer
 *    SinusChat (7 c),
 *  - trzeba zachować informacje o prawach autorskich i autorach (7 b),
 *  - nie wolno używać nazwy Sinusoide Technology do reklamowania zmienionych
 *    wersji ani sugerować, że je popieramy (7 d).
 *
 * Jeśli udostępniasz zmieniony serwer innym przez sieć, musisz im udostępnić jego
 * kod źródłowy (sekcja 13 AGPL-3.0). Program jest rozpowszechniany BEZ ŻADNEJ
 * GWARANCJI. Pełny tekst licencji: LICENSE i NOTICE.md, opis po polsku:
 * https://sinusoide.pl/dokumentacja.html
 *
 * English: free software under the GNU Affero General Public License version 3
 * with the same additional terms under section 7 as the SinusChat app (names and
 * marks, marking modified versions, authorship, endorsement), see NOTICE.md.
 * No warranty.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

'use strict'

const Fastify  = require('fastify')
const pg       = require('pg')
const jwt      = require('jsonwebtoken')
const crypto   = require('crypto')
const { execSync } = require('child_process')

function requiredEnv(name) {
  const v = process.env[name]
  if (!v) {
    console.error(`[FATAL] Brak zmiennej środowiskowej ${name} — nie startuję.`)
    process.exit(1)
  }
  return v
}

const PORT        = process.env.PORT || 3000
const DB_URL      = requiredEnv('DATABASE_URL')
const JWT_SECRET  = requiredEnv('JWT_SECRET')
const TURN_SECRET = requiredEnv('TURN_SECRET')
const UPLOAD_TOKEN_SECRET = requiredEnv('UPLOAD_TOKEN_SECRET')
const NTFY_BASE   = process.env.NTFY_URL || 'https://ntfy.sh'
const TURN_HOST   = process.env.TURN_HOST || 'turn.sinusoide.pl'
const PUBLIC_API_URL = (process.env.PUBLIC_API_URL || 'https://api.sinusoide.pl').replace(/\/+$/, '')
const VOICE_DIR      = '/opt/sinuschat/uploads/voice'

const FCM_SERVICE_ACCOUNT_FILE = process.env.FCM_SERVICE_ACCOUNT_FILE || ''

const AUTH_PROOF_SECRET  = process.env.AUTH_PROOF_SECRET || null
const REQUIRE_AUTH_PROOF = process.env.REQUIRE_AUTH_PROOF !== '0'

if (!AUTH_PROOF_SECRET) {
  console.error('[UWAGA] Brak AUTH_PROOF_SECRET — rejestracja i logowanie są ZABLOKOWANE, dopóki go nie ustawisz.')
} else if (!REQUIRE_AUTH_PROOF) {
  console.warn('[UWAGA] REQUIRE_AUTH_PROOF=0 — rejestracja bez dowodu z kodu e-mail jest przyjmowana. Ustaw 1 albo usuń zmienną.')
}

function verifyAuthProof(proof, emailHash) {
  if (!AUTH_PROOF_SECRET || typeof proof !== 'string') return false
  const parts = proof.split('.')
  if (parts.length !== 3) return false
  const [h, exp, sig] = parts
  if (h !== emailHash) return false
  if (!/^[0-9]{1,15}$/.test(exp) || Number(exp) < Date.now()) return false
  const expected = crypto.createHmac('sha256', AUTH_PROOF_SECRET)
    .update(`${h}.${exp}`).digest('hex')
  const a = Buffer.from(expected, 'utf8')
  const b = Buffer.from(String(sig), 'utf8')
  return a.length === b.length && crypto.timingSafeEqual(a, b)
}

const ONLINE_WINDOW_MS = 45_000

function getFreeDiskGB() {
  try {
    const out = execSync("df /opt/sinuschat --output=avail -B G | tail -1").toString().trim()
    return parseInt(out.replace('G','')) || 0
  } catch(_) { return 999 }
}
const MIN_FREE_GB = 5

const app = Fastify({
  logger: false,
  bodyLimit: 2 * 1024 * 1024,
  routerOptions: { maxParamLength: 300 }
})

app.register(require('@fastify/rate-limit'), {
  global: true,
  max: 300,
  timeWindow: '1 minute',
  keyGenerator: (req) => clientIp(req) || 'unknown',
  errorResponseBuilder: () => ({ statusCode: 429, error: 'Za dużo żądań — spróbuj za chwilę' })
})

app.register(require('@fastify/multipart'))
app.register(require('@fastify/static'), { root: '/opt/sinuschat/uploads', serve: false })

app.setErrorHandler((err, req, reply) => {
  const status = Number(err.statusCode) || (reply.statusCode >= 400 ? reply.statusCode : 500)
  if (status === 429) return reply.code(429).send({ error: 'Za dużo żądań — spróbuj za chwilę' })
  if (status >= 500) {
    const route = (req.routeOptions && req.routeOptions.url) || req.routerPath || ''
    console.error('[ERR]', req.method, route, err.message)
    return reply.code(500).send({ error: 'Błąd serwera' })
  }
  return reply.code(status).send({ error: err.message || 'Błędne żądanie' })
})

const QUEUE_BUDGET = new Map()
function spendBudget(key, bytes, limit) {
  const now = Date.now()
  const e = QUEUE_BUDGET.get(key)
  if (!e || now - e[0] > 3600_000) { QUEUE_BUDGET.set(key, [now, bytes]); return bytes <= limit }
  e[1] += bytes
  return e[1] <= limit
}
setInterval(() => {
  const now = Date.now()
  for (const [k, e] of QUEUE_BUDGET) if (now - e[0] > 3600_000) QUEUE_BUDGET.delete(k)
}, 10 * 60_000).unref()
function clientIp(req) {
  return String(req.headers['x-real-ip'] || req.ip || '').trim()
}

const HIDDEN_LOOKUP_LIMIT = 300
const DIRECT_TARGET_LIMIT = 500
const LOOKUP_WINDOW_MS = 24 * 3600_000
const LOOKUP_BUDGET = new Map()
function lookupAllowed(kind, requester, target, limit) {
  if (!requester || !target || requester === target) return true
  const key = kind + ':' + requester
  const now = Date.now()
  let e = LOOKUP_BUDGET.get(key)
  if (!e || now - e.start > LOOKUP_WINDOW_MS) { e = { start: now, seen: new Set() }; LOOKUP_BUDGET.set(key, e) }
  if (e.seen.has(target)) return true
  if (e.seen.size >= limit) return false
  e.seen.add(target)
  return true
}
setInterval(() => {
  const now = Date.now()
  for (const [k, e] of LOOKUP_BUDGET) if (now - e.start > LOOKUP_WINDOW_MS) LOOKUP_BUDGET.delete(k)
}, 10 * 60_000).unref()
const MESSAGE_MAX_BYTES   = 512 * 1024
const SENDER_BUDGET_BYTES = 200 * 1024 * 1024
const SEALED_BUDGET_BYTES = 50 * 1024 * 1024
const VOICE_BUDGET_BYTES  = 100 * 1024 * 1024
app.register(require('@fastify/cors'), { origin: true })
app.register(require('@fastify/websocket'))
app.addContentTypeParser('audio/ogg', { parseAs: 'buffer' }, (req, body, done) => done(null, body))

const db = new pg.Pool({ connectionString: DB_URL })
db.on('error', (err) => console.error('[DB]', err.message))

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
      WHERE COALESCE(last_heartbeat_ms,0) <> 0 OR COALESCE(last_seen_ms,0) <> 0`
  ]
  let failed = 0
  for (const sql of stmts) {
    try { await db.query(sql) }
    catch (e) {
      failed++
      console.error('[SCHEMA] BŁĄD:', e.message, '← przy:', sql.replace(/\s+/g, ' ').slice(0, 90))
    }
  }
  if (failed > 0) {
    console.error(`[SCHEMA] ${failed} zmian(y) schematu NIE weszło. Najczęściej: użytkownik bazy ` +
      'z DATABASE_URL nie jest właścicielem tabel. Uruchom migracja_sinuschat.sql jako postgres.')
  } else {
    console.log('[SCHEMA] schemat aktualny')
  }
}

const connections = new Map()

const pendingCallOffers = new Map()
const endedCalls = new Map()
setInterval(() => {
  const cut = Date.now() - 120_000
  for (const [k, ts] of endedCalls) if (ts < cut) endedCalls.delete(k)
}, 60_000).unref?.()
const pendingGcallRings = new Map()

const GCALL_MEMBER_TTL_MS = 60_000
const GCALL_SIGNAL_LIMIT = 200
const groupCalls = new Map()

function gcallState(gid) {
  const c = groupCalls.get(gid)
  if (!c) return { type: 'gcall_state', conversationId: gid, active: false, now: Date.now() }
  return {
    type: 'gcall_state', conversationId: gid, active: true, kind: c.kind,
    startedBy: c.startedBy, startedAt: c.startedAt, members: [...c.members.keys()], now: Date.now()
  }
}

async function gcallBroadcast(gid) {
  const state = gcallState(gid)
  try {
    const { rows } = await db.query('SELECT user_hash FROM conversation_participants WHERE conversation_id=$1', [gid])
    for (const { user_hash } of rows) sendToUser(user_hash, state)
  } catch (_) {}
}

async function gcallSendActive(userHash) {
  for (const gid of groupCalls.keys()) {
    if (await isParticipant(gid, userHash)) sendToUser(userHash, gcallState(gid))
  }
}

setInterval(() => {
  const cutoff = Date.now() - GCALL_MEMBER_TTL_MS
  for (const [gid, c] of groupCalls) {
    let changed = false
    for (const [hash, seen] of c.members) {
      if (seen < cutoff) { c.members.delete(hash); changed = true }
    }
    if (c.members.size === 0) { groupCalls.delete(gid); changed = true }
    if (changed) gcallBroadcast(gid)
  }
}, 15_000)
setInterval(() => {
  const cutoff = Date.now() - 40_000
  for (const [h, o] of pendingCallOffers) if (o.ts < cutoff) pendingCallOffers.delete(h)
  for (const [k, t] of pendingGcallRings) if (t < cutoff) pendingGcallRings.delete(k)
}, 10_000)

const CALL_ACK_TIMEOUT_MS = 4_000

const allSockets = new Set()
setInterval(() => {
  for (const ws of allSockets) {
    if (ws.heartbeatAlive === false) { try { ws.terminate() } catch (_) {} ; continue }
    ws.heartbeatAlive = false
    try { ws.ping() } catch (_) {}
  }
}, 30_000)

const MESSAGE_TTL_MS = 24 * 60 * 60 * 1000

const NOTIFIABLE_KINDS = new Set(['msg', 'group_attach'])

function baseMessageId(rowId) {
  return String(rowId).replace(/_[0-9a-f]{16}$/, '')
}

async function purgeOldMessages() {
  try {
    const now    = Date.now()
    const cutoff = now - MESSAGE_TTL_MS

    const { rows: expired } = await db.query(
      `SELECT id, conversation_id, sender_hash, kind
         FROM messages
        WHERE delivered_at IS NULL AND created_at < $1::bigint
        LIMIT 5000`,
      [cutoff]
    )
    if (!expired.length) return

    const pending = new Map()
    for (const r of expired) {
      if (!NOTIFIABLE_KINDS.has(r.kind)) continue
      const isGroup = String(r.conversation_id).startsWith('g_')
      const base    = isGroup ? baseMessageId(r.id) : r.id
      const key     = `${r.conversation_id}|${r.sender_hash}|${base}`
      const entry   = pending.get(key)
      if (entry) entry.missed++
      else pending.set(key, {
        conversationId: r.conversation_id,
        senderHash: r.sender_hash,
        baseId: base,
        isGroup,
        missed: 1
      })
    }

    for (const e of pending.values()) {
      try {
        let total = 1
        if (e.isGroup) {
          const { rows } = await db.query(
            'SELECT COUNT(*)::int AS c FROM conversation_participants WHERE conversation_id=$1 AND user_hash!=$2',
            [e.conversationId, e.senderHash]
          )
          total = rows[0]?.c ?? e.missed
        }
        const missed    = Math.min(e.missed, total)
        const delivered = Math.max(0, total - missed)

        const noticeBody = Buffer.from(JSON.stringify({
          originalId:     e.baseId,
          conversationId: e.conversationId,
          isGroup:        e.isGroup,
          total,
          delivered,
          missed,
          expiredAt:      now
        }), 'utf8')

        const noticeId = `exp_${e.baseId}`

        await db.query(
          `INSERT INTO messages(id,conversation_id,sender_hash,recipient_hash,kind,payload,created_at)
           VALUES($1,$2,$3,$4,'expiry_notice',$5,$6) ON CONFLICT(id) DO NOTHING`,
          [noticeId, e.conversationId, e.senderHash, e.senderHash, noticeBody, now]
        )

        const payloadB64 = noticeBody.toString('base64')
        const live = sendToUser(e.senderHash, {
          type: 'message', conversationId: e.conversationId, id: noticeId,
          kind: 'expiry_notice', payloadB64, senderHash: e.senderHash, createdAt: now
        })
        if (live) {
          await db.query('UPDATE messages SET delivered_at=$1 WHERE id=$2', [now, noticeId])
        }
      } catch (inner) {
        console.error('[PURGE] powiadomienie nadawcy nie powiodło się:', inner.message)
      }
    }

    const res = await db.query(
      'DELETE FROM messages WHERE id = ANY($1::varchar[])',
      [expired.map(r => r.id)]
    )
    if (res.rowCount > 0) {
      console.log(`[PURGE] usunięto ${res.rowCount} niedostarczonych, powiadomiono ${pending.size} nadawców`)
    }
  } catch (e) {
    console.error('[PURGE] błąd czyszczenia:', e.message)
  }
}
setInterval(purgeOldMessages, 60 * 60 * 1000)

function purgeOldVoice() {
  const fs = require('fs')
  try {
    if (!fs.existsSync(VOICE_DIR)) return
    const cutoff = Date.now() - MESSAGE_TTL_MS
    let removed = 0
    for (const name of fs.readdirSync(VOICE_DIR)) {
      const p = `${VOICE_DIR}/${name}`
      try {
        if (fs.statSync(p).mtimeMs < cutoff) { fs.unlinkSync(p); removed++ }
      } catch (_) {}
    }
    if (removed > 0) console.log('[PURGE] usunięto głosówek:', removed)
  } catch (e) {
    console.error('[PURGE] błąd czyszczenia głosówek:', e.message)
  }
}
setInterval(purgeOldVoice, 60 * 60 * 1000)

async function migrateAvatarNames() {
  try {
    const { rows } = await db.query(
      `SELECT email_hash, avatar_url FROM users WHERE avatar_url ~ '/uploads/avatars/[0-9a-f]{64}[.]'`)
    let moved = 0
    for (const { email_hash, avatar_url } of rows) {
      const m = String(avatar_url).match(/\/uploads\/avatars\/([0-9a-f]{64})\.(jpg|png|webp)/)
      if (!m) continue
      const base = crypto.createHmac('sha256', UPLOAD_TOKEN_SECRET).update('avatar|' + m[1]).digest('hex').slice(0, 32)
      await db.query('UPDATE users SET avatar_url=$1 WHERE email_hash=$2',
        [avatar_url.replace(`${m[1]}.${m[2]}`, `${base}.${m[2]}`), email_hash])
      moved++
    }
    if (moved) console.log('[AVATAR] nowe nazwy zdjęć profilowych:', moved)
  } catch (e) {
    console.error('[AVATAR] zmiana nazw nieudana:', e.message)
  }
}

const schemaReady = ensureSchema().then(migrateAvatarNames)
schemaReady.then(purgeOldMessages).then(purgeOldVoice)
  .then(() => setTimeout(purgeScheduledAccounts, 30_000))

const WS_MSG_LIMIT = 40
const WS_MSG_WINDOW_MS = 10_000
const WS_CONN_PER_IP = 10
const wsConnByIp = new Map()

function sendToUser(userHash, data) {
  const ws = connections.get(userHash)
  if (ws && ws.readyState === 1) {
    ws.send(JSON.stringify(data))
    return true
  }
  return false
}

async function isBlockedBy(blockerHash, blockedHash) {
  if (!blockerHash || !blockedHash) return false
  try {
    const { rows } = await db.query(
      'SELECT 1 FROM blocked_users WHERE blocker_hash=$1 AND blocked_hash=$2 LIMIT 1',
      [blockerHash, blockedHash]
    )
    return rows.length > 0
  } catch (_) { return false }
}

const GROUP_AVATAR_RE = /^https:\/\/files\.sinusoide\.pl\/api\/uploads\/group_avatars\/[0-9a-f]{32}\.(jpg|png|webp)$/
function cleanGroupAvatarUrl(url) {
  if (url === '') return ''
  if (typeof url !== 'string') return undefined
  return GROUP_AVATAR_RE.test(url) ? url : undefined
}

const USER_AVATAR_RE = /^https:\/\/files\.sinusoide\.pl\/api\/uploads\/avatars\/([0-9a-f]{32}|[0-9a-f]{64})\.(jpg|png|webp|bin)(\?v=\d{1,16})?$/
function cleanUserAvatarUrl(url) {
  if (url === '') return ''
  if (typeof url !== 'string') return undefined
  return USER_AVATAR_RE.test(url) ? url : undefined
}

async function groupAllows(groupId, userHash, key) {
  try {
    const { rows } = await db.query(
      `SELECT cp.is_admin, g.perms
         FROM conversation_participants cp
         JOIN groups g ON g.id = cp.conversation_id
        WHERE cp.conversation_id = $1 AND cp.user_hash = $2
        LIMIT 1`,
      [groupId, userHash]
    )
    if (!rows.length) return false
    if (rows[0].is_admin) return true
    let perms = rows[0].perms || {}
    if (typeof perms === 'string') { try { perms = JSON.parse(perms) } catch (_) { perms = {} } }
    return perms[key] !== false
  } catch (_) { return false }
}

function accessKeyMatches(uaHash, akB64) {
  if (!uaHash || typeof akB64 !== 'string' || !akB64 || akB64.length > 64) return false
  const got = crypto.createHash('sha256').update(Buffer.from(akB64, 'base64')).digest('hex')
  return got.length === uaHash.length && crypto.timingSafeEqual(Buffer.from(got), Buffer.from(uaHash))
}

async function sharesGroup(a, b) {
  if (!a || !b) return false
  try {
    const { rows } = await db.query(
      `SELECT 1 FROM conversation_participants cp1
       JOIN conversation_participants cp2 ON cp1.conversation_id = cp2.conversation_id
       WHERE cp1.user_hash = $1 AND cp2.user_hash = $2 AND cp1.conversation_id LIKE 'g!_%' ESCAPE '!' LIMIT 1`,
      [a, b]
    )
    return rows.length > 0
  } catch (_) { return false }
}

async function newChatsBlocked(targetHash) {
  try {
    const { rows } = await db.query('SELECT block_new, ua_hash FROM users WHERE email_hash=$1', [targetHash])
    return rows[0]?.block_new === true ? { uaHash: rows[0].ua_hash } : null
  } catch (_) { return null }
}

async function knownContact(block, targetHash, requester, akB64) {
  if (!block) return true
  if (accessKeyMatches(block.uaHash, akB64)) return true
  return await sharesGroup(requester, targetHash)
}

async function isParticipant(conversationId, userHash) {
  if (!conversationId || !userHash) return false
  try {
    const { rows } = await db.query(
      'SELECT 1 FROM conversation_participants WHERE conversation_id=$1 AND user_hash=$2 LIMIT 1',
      [conversationId, userHash]
    )
    return rows.length > 0
  } catch (_) { return false }
}

const presence = new Map()
const activeDayWritten = new Map()
function todayNumber() { return Math.floor(Date.now() / 86400000) }
function presenceOf(hash) { return presence.get(hash) || { hb: 0, seen: 0 } }
function isOnlineNow(hash) {
  const p = presence.get(hash)
  return !!p && p.hb > 0 && (Date.now() - p.hb) < ONLINE_WINDOW_MS
}
async function touchActiveDay(hash) {
  const d = todayNumber()
  if (activeDayWritten.get(hash) === d) return
  activeDayWritten.set(hash, d)
  if (activeDayWritten.size > 200000) activeDayWritten.clear()
  try {
    await db.query('UPDATE users SET last_active_day=$2 WHERE email_hash=$1 AND COALESCE(last_active_day,0) <> $2', [hash, d])
  } catch (_) {}
}
function forgetPresence(hash) { presence.delete(hash); activeDayWritten.delete(hash) }
const groupDayWritten = new Map()
async function touchGroupDay(groupId) {
  const d = todayNumber()
  if (groupDayWritten.get(groupId) === d) return
  groupDayWritten.set(groupId, d)
  if (groupDayWritten.size > 100000) groupDayWritten.clear()
  try {
    await db.query('UPDATE groups SET last_active_day=$2 WHERE id=$1 AND COALESCE(last_active_day,0) <> $2', [groupId, d])
  } catch (_) {}
}
setInterval(() => {
  const cut = Date.now() - 7 * 86400000
  for (const [h, p] of presence) if (Math.max(p.hb, p.seen) < cut) presence.delete(h)
}, 10 * 60 * 1000)

function canonicalPair(a, b) { return a < b ? `${a}_${b}` : `${b}_${a}` }
function directMember(conversationId, userHash) {
  const parts = String(conversationId || '').split('_')
  return parts.length === 2 && canonicalPair(parts[0], parts[1]) === conversationId &&
    (parts[0] === userHash || parts[1] === userHash)
}
async function canUseConversation(conversationId, userHash) {
  if (!conversationId || !userHash) return false
  if (String(conversationId).startsWith('g_')) return isParticipant(conversationId, userHash)
  return directMember(conversationId, userHash) || isParticipant(conversationId, userHash)
}

async function userExists(hash) {
  try {
    const { rows } = await db.query('SELECT 1 FROM users WHERE email_hash=$1', [String(hash)])
    return rows.length > 0
  } catch (_) { return true }
}

async function relayDirectAck(fromHash, conversationId, deliveredUpTo, readUpTo) {
  const d = Number(deliveredUpTo) || 0
  const r = Number(readUpTo) || 0
  if (!d && !r) return
  const parts = String(conversationId).split('_')
  const other = parts[0] === fromHash ? parts[1] : parts[0]
  if (!other || other === fromHash) return
  if (await isBlockedBy(fromHash, other)) return
  if (sendToUser(other, { type: 'ack', conversationId, fromHash, deliveredUpTo: d || undefined, readUpTo: r || undefined })) return
  if (!(await userExists(other))) return
  try {
    let md = d, mr = r
    const { rows } = await db.query(
      "SELECT payload FROM messages WHERE kind='ack' AND sender_hash=$1 AND recipient_hash=$2 AND conversation_id=$3 AND delivered_at IS NULL",
      [fromHash, other, conversationId])
    for (const row of rows) {
      try {
        const o = JSON.parse(row.payload.toString('utf8'))
        md = Math.max(md, Number(o.deliveredUpTo) || 0)
        mr = Math.max(mr, Number(o.readUpTo) || 0)
      } catch (_) {}
    }
    await db.query(
      "DELETE FROM messages WHERE kind='ack' AND sender_hash=$1 AND recipient_hash=$2 AND conversation_id=$3 AND delivered_at IS NULL",
      [fromHash, other, conversationId])
    await db.query(
      `INSERT INTO messages(id,conversation_id,sender_hash,recipient_hash,kind,payload,created_at)
       VALUES($1,$2,$3,$4,'ack',$5,$6) ON CONFLICT(id) DO NOTHING`,
      ['ack_' + crypto.randomUUID(), conversationId, fromHash, other,
       Buffer.from(JSON.stringify({ deliveredUpTo: md, readUpTo: mr }), 'utf8'), Date.now()])
  } catch (_) {}
}

const ADDRESSED_GROUP_KINDS = new Set(['group_key', 'group_key_request'])

async function isGroupBanned(groupId, userHash) {
  try {
    const { rows } = await db.query('SELECT 1 FROM group_bans WHERE group_id=$1 AND user_hash=$2 LIMIT 1', [groupId, userHash])
    return rows.length > 0
  } catch (_) { return false }
}

function signToken(sub, deviceId) {
  return jwt.sign({ sub, deviceId }, JWT_SECRET, { expiresIn: '30d' })
}
function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET) } catch(_) { return null }
}

async function verifyActiveDevice(token) {
  const payload = verifyToken(token)
  if (!payload) return null
  const { rows } = await db.query(
    'SELECT active_device_id FROM users WHERE email_hash=$1', [payload.sub])
  const active = rows[0]?.active_device_id
  if (!payload.deviceId) return active ? { kicked: true } : payload
  if (!active) return payload
  if (active !== payload.deviceId) return { kicked: true }
  return payload
}

async function pushViaNtfy(userHash, kind, extra) {
  let topic
  try { topic = await ensureUserNtfyTopic(userHash) }
  catch (_) { topic = ntfyTopicFor(userHash) }
  const headers = { 'Content-Type': 'text/plain' }
  if (extra?.title) headers['X-Title'] = extra.title
  if (kind === 'call') {
    headers['X-Priority'] = 'max'
    headers['X-Tags'] = 'phone'
  }
  fetch(`${NTFY_BASE}/${topic}`, {
    method: 'POST',
    headers,
    body: kind || 'msg'
  }).catch(() => {})
}

let _fcmAccount = null
let _fcmAccessToken = null
function fcmAccount() {
  if (_fcmAccount !== null) return _fcmAccount || null
  _fcmAccount = false
  if (!FCM_SERVICE_ACCOUNT_FILE) return null
  try {
    const j = JSON.parse(require('fs').readFileSync(FCM_SERVICE_ACCOUNT_FILE, 'utf8'))
    if (j.client_email && j.private_key && j.project_id) _fcmAccount = j
    else console.warn('[FCM] niekompletny plik konta usługi')
  } catch (e) { console.warn('[FCM] nie można wczytać konta usługi:', e.message) }
  return _fcmAccount || null
}
const fcmAvailable = () => !!fcmAccount()

async function fcmGetAccessToken() {
  const acc = fcmAccount()
  if (!acc) return null
  const now = Math.floor(Date.now() / 1000)
  if (_fcmAccessToken && _fcmAccessToken.exp - 60 > now) return _fcmAccessToken.token
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url')
  const unsigned = b64({ alg: 'RS256', typ: 'JWT' }) + '.' + b64({
    iss: acc.client_email,
    scope: 'https://www.googleapis.com/auth/firebase.messaging',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now, exp: now + 3600
  })
  const sig = crypto.sign('RSA-SHA256', Buffer.from(unsigned), acc.private_key).toString('base64url')
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: `${unsigned}.${sig}`
    })
  })
  if (!res.ok) { console.warn('[FCM] token OAuth:', res.status); return null }
  const j = await res.json()
  _fcmAccessToken = { token: j.access_token, exp: now + (Number(j.expires_in) || 3600) }
  return _fcmAccessToken.token
}

async function sendFcm(userHash, fcmToken, kind) {
  const acc = fcmAccount()
  if (!acc || !fcmToken) return false
  try {
    const access = await fcmGetAccessToken()
    if (!access) return false
    void kind
    const res = await fetch(`https://fcm.googleapis.com/v1/projects/${acc.project_id}/messages:send`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${access}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: {
        token: fcmToken,
        data: { w: '1' },
        android: {
          priority: 'HIGH',
          ttl: '600s',
          collapse_key: 'wake'
        }
      } })
    })
    if (res.ok) return true
    const body = await res.text().catch(() => '')
    if (res.status === 404 || body.includes('UNREGISTERED') || body.includes('INVALID_ARGUMENT')) {
      await db.query('UPDATE users SET fcm_token=NULL WHERE email_hash=$1', [userHash]).catch(() => {})
      _pushPrefCache.delete(userHash)
    } else {
      console.warn('[FCM] send:', res.status)
    }
    return false
  } catch (e) { console.warn('[FCM] send error:', e.message); return false }
}

const _pushPrefCache = new Map()
async function pushPrefFor(userHash) {
  const c = _pushPrefCache.get(userHash)
  if (c) return c
  let pref = { mode: 'ntfy', token: null }
  try {
    const { rows } = await db.query('SELECT push_mode, fcm_token FROM users WHERE email_hash=$1', [userHash])
    if (rows[0]) pref = { mode: rows[0].push_mode === 'fcm' ? 'fcm' : 'ntfy', token: rows[0].fcm_token || null }
  } catch (_) {}
  if (_pushPrefCache.size > 5000) _pushPrefCache.clear()
  _pushPrefCache.set(userHash, pref)
  return pref
}

async function wakeUser(userHash, kind, extra) {
  const pref = await pushPrefFor(userHash)
  if (pref.mode === 'fcm' && pref.token && fcmAvailable()) {
    if (await sendFcm(userHash, pref.token, kind)) return
  }
  return pushViaNtfy(userHash, kind, extra)
}

const _ntfyTopicCache = new Map()

function legacyTopicFor(userHash) {
  return 'sinuschat_' + String(userHash).substring(0, 32)
}
function ntfyTopicFor(userHash) {
  return _ntfyTopicCache.get(userHash) || legacyTopicFor(userHash)
}
async function loadNtfyTopic(userHash) {
  try {
    const { rows } = await db.query('SELECT ntfy_topic FROM users WHERE email_hash=$1', [userHash])
    if (rows[0]?.ntfy_topic) _ntfyTopicCache.set(userHash, rows[0].ntfy_topic)
  } catch (_) {}
}

async function ensureUserNtfyTopic(userHash) {
  const cached = _ntfyTopicCache.get(userHash)
  if (cached) return cached
  const { rows } = await db.query('SELECT ntfy_topic FROM users WHERE email_hash=$1', [userHash])
  let topic = rows[0]?.ntfy_topic
  if (!topic || topic === legacyTopicFor(userHash)) {
    topic = 'sinuschat_' + crypto.randomBytes(24).toString('hex')
    await db.query('UPDATE users SET ntfy_topic=$2 WHERE email_hash=$1', [userHash, topic])
  }
  _ntfyTopicCache.set(userHash, topic)
  return topic
}

app.get('/health', async () => ({ status: 'ok', ts: Date.now() }))

const OTP_EXPIRY_S   = 600
const OTP_MAX_TRIES  = 5
const OTP_REUSE_S    = 120
const OTP_MAX_TRACKED = 20000
const otpTickets = new Map()

function hmacHex(data) {
  return crypto.createHmac('sha256', AUTH_PROOF_SECRET).update(data).digest('hex')
}

function sameHex(a, b) {
  const x = Buffer.from(String(a), 'utf8')
  const y = Buffer.from(String(b), 'utf8')
  return x.length === y.length && crypto.timingSafeEqual(x, y)
}

setInterval(() => {
  const now = Math.floor(Date.now() / 1000)
  for (const [nonce, st] of otpTickets) if (st.exp < now) otpTickets.delete(nonce)
}, 60 * 1000)

app.post('/api/auth/verify', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req, reply) => {
  if (!AUTH_PROOF_SECRET) return reply.code(503).send({ success: false, error: 'Weryfikacja chwilowo niedostępna' })

  const body   = req.body || {}
  const email  = String(body.email || '').trim().toLowerCase()
  const code   = String(body.code || '').trim()
  const ticket = String(body.ticket || '').trim()
  if (!email || !code) return reply.send({ success: false, error: 'Brak danych' })

  const m = /^([0-9a-f]{16,64})\.([0-9]{1,12})\.([0-9a-f]{64})$/.exec(ticket)
  if (!m) return reply.send({ success: false, error: 'Nieprawidłowe żądanie. Wyślij kod ponownie.' })
  const [, nonce, expStr, mac] = m
  const exp = Number(expStr)
  const now = Math.floor(Date.now() / 1000)
  if (now > exp) return reply.send({ success: false, error: 'Kod wygasł. Wyślij nowy.' })
  if (exp > now + OTP_EXPIRY_S + 60) return reply.send({ success: false, error: 'Nieprawidłowe żądanie. Wyślij kod ponownie.' })

  let st = otpTickets.get(nonce)
  if (st && st.attempts >= OTP_MAX_TRIES) {
    return reply.send({ success: false, error: 'Za dużo błędnych prób. Wyślij nowy kod.' })
  }
  if (st && st.usedAt && now - st.usedAt > OTP_REUSE_S) {
    return reply.send({ success: false, error: 'Ten kod został już użyty. Wyślij nowy.' })
  }
  if (!st) {
    if (otpTickets.size >= OTP_MAX_TRACKED) {
      return reply.code(503).send({ success: false, error: 'Spróbuj za chwilę' })
    }
    st = { attempts: 0, usedAt: 0, exp }
    otpTickets.set(nonce, st)
  }

  const emailHash = crypto.createHash('sha256').update(email).digest('hex')
  const ok = /^[0-9]{4,10}$/.test(code) && sameHex(hmacHex(`otp|${emailHash}|${nonce}|${exp}|${code}`), mac)
  if (!ok) {
    st.attempts++
    return reply.send({ success: false, error: `Nieprawidłowy kod. Pozostało prób: ${Math.max(0, OTP_MAX_TRIES - st.attempts)}` })
  }

  if (!st.usedAt) st.usedAt = now
  const expiresAt = (now + 900) * 1000
  return reply.send({
    success: true,
    emailHash,
    authProof: `${emailHash}.${expiresAt}.${hmacHex(`${emailHash}.${expiresAt}`)}`,
    expiresAt
  })
})

app.post('/api/auth/transfer-proof', { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } }, async (req, reply) => {
  if (!AUTH_PROOF_SECRET) return reply.code(503).send({ error: 'Przenoszenie konta chwilowo niedostępne' })
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = auth ? await verifyActiveDevice(auth) : null
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked' })
  const emailHash = String(payload.sub || '')
  if (!/^[a-f0-9]{64}$/.test(emailHash)) return reply.code(400).send({ error: 'Nieprawidłowe konto' })
  const expiresAt = Date.now() + 900 * 1000
  return {
    authProof: `${emailHash}.${expiresAt}.${hmacHex(`${emailHash}.${expiresAt}`)}`,
    expiresAt
  }
})

async function currentKeyOf(userHash) {
  try {
    const { rows } = await db.query('SELECT e2e_public_key FROM users WHERE email_hash=$1', [userHash])
    return rows[0]?.e2e_public_key || null
  } catch (_) { return null }
}

async function announceKeyChange(userHash, oldKey, newKey) {
  if (!newKey || newKey === oldKey) return
  try {
    const { rows } = await db.query(
      `SELECT DISTINCT cp2.user_hash FROM conversation_participants cp1
         JOIN conversation_participants cp2 ON cp2.conversation_id = cp1.conversation_id
        WHERE cp1.user_hash = $1 AND cp2.user_hash <> $1`, [userHash])
    for (const { user_hash } of rows) {
      sendToUser(user_hash, { type: 'peer_key', userHash, e2ePublicKey: newKey })
    }
  } catch (_) {}
}

const ANON_POW_BITS = 20
const ANON_DEFAULT_IDLE_SEC = 548 * 24 * 3600
const EMAIL_DEFAULT_IDLE_SEC = 5 * 365 * 24 * 3600
const anonChallenges = new Map()
const loginChallenges = new Map()
const anonPending = new Map()
setInterval(() => {
  const now = Date.now()
  for (const [k, exp] of anonChallenges) if (exp < now) anonChallenges.delete(k)
  for (const [k, v] of loginChallenges) if (v.exp < now) loginChallenges.delete(k)
  for (const [k, v] of anonPending) if (v.exp < now) anonPending.delete(k)
}, 60 * 1000)

function leadingZeroBits(buf) {
  let n = 0
  for (const byte of buf) {
    if (byte === 0) { n += 8; continue }
    for (let b = 7; b >= 0; b--) { if (byte & (1 << b)) return n; n++ }
  }
  return n
}

function ed25519Verify(pubB64, message, sigB64) {
  try {
    const raw = Buffer.from(String(pubB64), 'base64')
    const sig = Buffer.from(String(sigB64), 'base64')
    if (raw.length !== 32 || sig.length !== 64) return false
    const key = crypto.createPublicKey({
      key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]),
      format: 'der', type: 'spki'
    })
    return crypto.verify(null, Buffer.from(message, 'utf8'), key, sig)
  } catch (_) { return false }
}

function issueAuthProof(hash) {
  const expiresAt = Date.now() + 900 * 1000
  return { authProof: `${hash}.${expiresAt}.${hmacHex(`${hash}.${expiresAt}`)}`, expiresAt }
}

app.post('/api/anon/challenge', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req, reply) => {
  if (!AUTH_PROOF_SECRET) return reply.code(503).send({ error: 'Chwilowo niedostępne' })
  if (anonChallenges.size > 20000) anonChallenges.clear()
  const challenge = crypto.randomBytes(16).toString('hex')
  anonChallenges.set(challenge, Date.now() + 10 * 60 * 1000)
  return { challenge, bits: ANON_POW_BITS }
})

app.post('/api/anon/register', { config: { rateLimit: { max: 5, timeWindow: '1 hour' } } }, async (req, reply) => {
  if (!AUTH_PROOF_SECRET) return reply.code(503).send({ error: 'Chwilowo niedostępne' })
  const { accountHash, loginKey, challenge, nonce } = req.body || {}
  const hash = String(accountHash || '')
  if (!/^[a-f0-9]{64}$/.test(hash)) return reply.code(400).send({ error: 'Nieprawidłowe dane' })
  if (!b64ok(loginKey, 60) || Buffer.from(String(loginKey), 'base64').length !== 32) {
    return reply.code(400).send({ error: 'Nieprawidłowe dane' })
  }
  const exp = anonChallenges.get(String(challenge || ''))
  anonChallenges.delete(String(challenge || ''))
  if (!exp || exp < Date.now()) return reply.code(400).send({ error: 'Wyzwanie wygasło', code: 'challenge_expired' })
  const n = String(nonce ?? '')
  if (!/^[0-9]{1,16}$/.test(n)) return reply.code(400).send({ error: 'Nieprawidłowe dane' })
  const digest = crypto.createHash('sha256').update(`${challenge}:${n}`).digest()
  if (leadingZeroBits(digest) < ANON_POW_BITS) return reply.code(400).send({ error: 'Nieprawidłowy dowód', code: 'bad_pow' })
  const { rows } = await db.query('SELECT 1 FROM users WHERE email_hash=$1', [hash])
  if (rows.length) return reply.code(409).send({ error: 'Konto już istnieje', code: 'exists' })
  anonPending.set(hash, { loginKey: String(loginKey), exp: Date.now() + 900 * 1000 })
  return issueAuthProof(hash)
})

app.post('/api/anon/login-challenge', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req, reply) => {
  const hash = String(req.body?.accountHash || '')
  if (!/^[a-f0-9]{64}$/.test(hash)) return reply.code(400).send({ error: 'Nieprawidłowe dane' })
  if (loginChallenges.size > 20000) loginChallenges.clear()
  const challenge = crypto.randomBytes(16).toString('hex')
  loginChallenges.set(challenge, { hash, exp: Date.now() + 5 * 60 * 1000 })
  return { challenge }
})

app.post('/api/anon/login', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req, reply) => {
  if (!AUTH_PROOF_SECRET) return reply.code(503).send({ error: 'Chwilowo niedostępne' })
  const { accountHash, challenge, signature } = req.body || {}
  const hash = String(accountHash || '')
  const ch = loginChallenges.get(String(challenge || ''))
  loginChallenges.delete(String(challenge || ''))
  const deny = () => reply.code(401).send({ error: 'Nie udało się zalogować', code: 'login_failed' })
  if (!ch || ch.exp < Date.now() || ch.hash !== hash) return deny()
  const { rows } = await db.query(
    "SELECT login_key FROM users WHERE email_hash=$1 AND account_kind='anon'", [hash])
  if (!rows.length || !rows[0].login_key) return deny()
  if (!ed25519Verify(rows[0].login_key, `SinusChat login v1|${hash}|${challenge}`, signature)) return deny()
  return issueAuthProof(hash)
})

const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/
function b64ok(s, max) { return typeof s === 'string' && s.length > 0 && s.length <= max && B64_RE.test(s) }
function signedKeyOk(k, maxPub) {
  return !!k && Number.isInteger(k.id) && k.id > 0 && k.id < 0xFFFFFF && b64ok(k.pub, maxPub) && b64ok(k.sig, 200)
}

async function signalCapable(hashes) {
  if (!hashes.length) return new Set()
  try {
    const { rows } = await db.query(
      `SELECT sk.user_hash FROM signal_keys sk JOIN users u ON u.email_hash = sk.user_hash
        WHERE sk.user_hash = ANY($1::varchar[]) AND sk.identity_key = u.e2e_public_key`, [hashes])
    return new Set(rows.map(r => r.user_hash))
  } catch (_) { return new Set() }
}

async function dropSignalKeys(userHash) {
  try {
    await db.query('DELETE FROM signal_prekeys WHERE user_hash=$1', [userHash])
    await db.query('DELETE FROM signal_keys WHERE user_hash=$1', [userHash])
  } catch (_) {}
}

app.post('/api/signal/keys', { config: { rateLimit: { max: 30, timeWindow: '1 hour' } } }, async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const b = req.body || {}
  const regId = Number(b.registrationId)
  if (!Number.isInteger(regId) || regId < 1 || regId > 16380) return reply.code(400).send({ error: 'Nieprawidłowe dane' })
  if (!signedKeyOk(b.signedPreKey, 100) || !signedKeyOk(b.kyberPreKey, 3000)) {
    return reply.code(400).send({ error: 'Nieprawidłowe klucze' })
  }
  const current = await currentKeyOf(payload.sub)
  if (!current || b.identityKey !== current) {
    return reply.code(409).send({ error: 'Klucz tożsamości się nie zgadza', code: 'identity_mismatch' })
  }
  const pre = Array.isArray(b.preKeys) ? b.preKeys.slice(0, 200) : []
  for (const p of pre) {
    if (!p || !Number.isInteger(p.id) || p.id <= 0 || p.id >= 0xFFFFFF || !b64ok(p.pub, 100)) {
      return reply.code(400).send({ error: 'Nieprawidłowe klucze' })
    }
  }

  const client = await db.connect()
  try {
    await client.query('BEGIN')
    await client.query(
      `INSERT INTO signal_keys (user_hash, identity_key, registration_id, signed_prekey_id, signed_prekey,
                                signed_prekey_sig, kyber_prekey_id, kyber_prekey, kyber_prekey_sig, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       ON CONFLICT (user_hash) DO UPDATE SET
         identity_key=EXCLUDED.identity_key, registration_id=EXCLUDED.registration_id,
         signed_prekey_id=EXCLUDED.signed_prekey_id, signed_prekey=EXCLUDED.signed_prekey,
         signed_prekey_sig=EXCLUDED.signed_prekey_sig, kyber_prekey_id=EXCLUDED.kyber_prekey_id,
         kyber_prekey=EXCLUDED.kyber_prekey, kyber_prekey_sig=EXCLUDED.kyber_prekey_sig,
         updated_at=EXCLUDED.updated_at`,
      [payload.sub, current, regId, b.signedPreKey.id, b.signedPreKey.pub, b.signedPreKey.sig,
       b.kyberPreKey.id, b.kyberPreKey.pub, b.kyberPreKey.sig, Date.now()])
    if (b.replacePreKeys === true) await client.query('DELETE FROM signal_prekeys WHERE user_hash=$1', [payload.sub])
    if (pre.length) {
      const { rows } = await client.query('SELECT COUNT(*)::int AS n FROM signal_prekeys WHERE user_hash=$1', [payload.sub])
      const take = pre.slice(0, Math.max(0, 500 - (rows[0]?.n || 0)))
      if (take.length) {
        await client.query(
          `INSERT INTO signal_prekeys (user_hash, key_id, pub)
           SELECT $1, t.k, t.p FROM unnest($2::int[], $3::text[]) AS t(k, p)
           ON CONFLICT DO NOTHING`,
          [payload.sub, take.map(p => p.id), take.map(p => p.pub)])
      }
    }
    await client.query('COMMIT')
  } catch (e) {
    try { await client.query('ROLLBACK') } catch (_) {}
    client.release()
    return reply.code(500).send({ error: 'Nie udało się zapisać kluczy' })
  }
  client.release()
  return { ok: true }
})

app.get('/api/signal/count', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  try {
    const { rows } = await db.query('SELECT identity_key, signed_prekey_id FROM signal_keys WHERE user_hash=$1', [payload.sub])
    const { rows: c } = await db.query('SELECT COUNT(*)::int AS n FROM signal_prekeys WHERE user_hash=$1', [payload.sub])
    return { count: c[0]?.n || 0, signedPreKeyId: rows[0]?.signed_prekey_id ?? -1, identityKey: rows[0]?.identity_key || '' }
  } catch (_) {
    return { count: 0, signedPreKeyId: -1, identityKey: '' }
  }
})

app.get('/api/signal/bundle/:hash', { config: { rateLimit: { max: 120, timeWindow: '1 minute' } } }, async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const hash = String(req.params.hash || '')
  if (!/^[a-f0-9]{64}$/.test(hash) || hash === payload.sub) return reply.code(404).send({ error: 'Brak kluczy' })
  if (await isBlockedBy(hash, payload.sub)) return reply.code(404).send({ error: 'Brak kluczy' })
  try {
    const { rows } = await db.query(
      `SELECT sk.*, u.email_block AS u_email_block, u.block_new AS u_block_new
         FROM signal_keys sk JOIN users u ON u.email_hash = sk.user_hash
        WHERE sk.user_hash=$1 AND sk.identity_key = u.e2e_public_key`, [hash])
    if (!rows.length) return reply.code(404).send({ error: 'Brak kluczy' })
    const k = rows[0]
    if ((k.u_email_block === true || k.u_block_new === true) &&
        !lookupAllowed('h', payload.sub, hash, HIDDEN_LOOKUP_LIMIT)) {
      return reply.code(404).send({ error: 'Brak kluczy' })
    }
    const { rows: pre } = await db.query(
      `DELETE FROM signal_prekeys WHERE (user_hash, key_id) IN (
         SELECT user_hash, key_id FROM signal_prekeys WHERE user_hash=$1 LIMIT 1 FOR UPDATE SKIP LOCKED)
       RETURNING key_id, pub`, [hash])
    return {
      registrationId: k.registration_id,
      identityKey: k.identity_key,
      signedPreKey: { id: k.signed_prekey_id, pub: k.signed_prekey, sig: k.signed_prekey_sig },
      kyberPreKey: { id: k.kyber_prekey_id, pub: k.kyber_prekey, sig: k.kyber_prekey_sig },
      preKey: pre[0] ? { id: pre[0].key_id, pub: pre[0].pub } : null
    }
  } catch (_) {
    return reply.code(404).send({ error: 'Brak kluczy' })
  }
})

app.post('/api/register', async (req, reply) => {
  const { emailHash, displayName, e2ePublicKey, keyUpdatedAt,
          avatarUrl, avatarColor, avatarUpdatedAt, deviceId, authProof } = req.body || {}
  if (!emailHash) return reply.code(400).send({ error: 'Brak danych' })
  if (displayName != null && displayName !== '' &&
      (typeof displayName !== 'string' || displayName.length > 1024)) {
    return reply.code(400).send({ error: 'Nieprawidłowa nazwa' })
  }
  if (!/^[a-f0-9]{64}$/.test(String(emailHash))) {
    return reply.code(400).send({ error: 'Nieprawidłowy emailHash' })
  }

  const proofOk = verifyAuthProof(authProof, emailHash)
  if (!proofOk) {
    if (REQUIRE_AUTH_PROOF) {
      return reply.code(401).send({
        error: 'Wymagane potwierdzenie adresu e-mail',
        code: 'email_verification_required'
      })
    }
    console.warn('[REGISTER] rejestracja bez dowodu weryfikacji e-maila')
  }

  const oldKey = e2ePublicKey ? await currentKeyOf(emailHash) : null

  await db.query(`
    INSERT INTO users(email_hash, display_name, e2e_public_key, key_updated_at,
                      avatar_color, avatar_url, avatar_updated_at, auto_delete_after_sec)
    VALUES($1,COALESCE($2,''),$3,$4,COALESCE($6,'#5288C1'),$5,COALESCE($7,0),${EMAIL_DEFAULT_IDLE_SEC})
    ON CONFLICT(email_hash) DO UPDATE SET
      display_name      = COALESCE($2, users.display_name),
      e2e_public_key    = COALESCE(EXCLUDED.e2e_public_key, users.e2e_public_key),
      key_updated_at    = COALESCE(EXCLUDED.key_updated_at, users.key_updated_at),
      avatar_color      = COALESCE(EXCLUDED.avatar_color, users.avatar_color),
      avatar_url        = COALESCE(EXCLUDED.avatar_url, users.avatar_url),
      avatar_updated_at = GREATEST(COALESCE(EXCLUDED.avatar_updated_at,0),
                                   COALESCE(users.avatar_updated_at,0))`,
    [emailHash, displayName || null, e2ePublicKey || null, keyUpdatedAt || null,
     cleanUserAvatarUrl(avatarUrl) || null, avatarColor || null, avatarUpdatedAt || null]
  )
  if (e2ePublicKey && oldKey && oldKey !== e2ePublicKey) await dropSignalKeys(emailHash)
  if (e2ePublicKey) announceKeyChange(emailHash, oldKey, e2ePublicKey)
  if (deviceId) {
    await db.query('UPDATE users SET active_device_id=$2 WHERE email_hash=$1',
      [emailHash, deviceId])
    const prev = connections.get(emailHash)
    if (prev && prev.deviceId !== deviceId) {
      try { prev.send(JSON.stringify({ type: 'device_kicked' })) } catch (_) {}
      try { prev.close() } catch (_) {}
      connections.delete(emailHash)
    }
    wakeUser(emailHash, 'kicked').catch(() => {})
  }
  const anon = anonPending.get(emailHash)
  if (anon && anon.exp > Date.now()) {
    anonPending.delete(emailHash)
    await db.query(
      "UPDATE users SET account_kind='anon', login_key=$2, auto_delete_after_sec=$3 WHERE email_hash=$1",
      [emailHash, anon.loginKey, ANON_DEFAULT_IDLE_SEC])
  }
  const token = signToken(emailHash, deviceId || null)
  const ntfyTopic = await ensureUserNtfyTopic(emailHash)
  let autoDeleteAfterSec = null
  try {
    const { rows } = await db.query('SELECT auto_delete_after_sec FROM users WHERE email_hash=$1', [emailHash])
    if (rows.length) autoDeleteAfterSec = Number(rows[0].auto_delete_after_sec || 0)
  } catch (_) {}
  return { token, userHash: emailHash, ntfyTopic, autoDeleteAfterSec }
})

app.get('/api/user/:hash', async (req, reply) => {
  const { hash } = req.params
  let payload = await verifyActiveDevice(req.headers.authorization?.replace('Bearer ', ''))
  if (payload && payload.kicked) payload = null
  if (!payload && !verifyAuthProof(String(req.headers['x-auth-proof'] || ''), String(hash))) {
    return reply.code(401).send({ error: 'Brak autoryzacji' })
  }
  const { rows } = await db.query(
    'SELECT email_hash, display_name, avatar_url, avatar_color, avatar_updated_at, e2e_public_key, key_updated_at, chat_privacy_mode, activity_hidden, email_block, block_new, last_heartbeat_ms, last_seen_ms, ua_hash, profile_key_wrap, call_e2e FROM users WHERE email_hash=$1',
    [hash]
  )
  if (!rows.length) return reply.code(404).send({ error: 'Nie znaleziono' })
  const user = rows[0]

  const now = Date.now()

  const isSearch = String(req.headers['x-search']) === 'true'
  if (user.email_block === true && isSearch) {
    return reply.code(404).send({ error: 'Nie znaleziono' })
  }

  const isOwner = !payload || payload.sub === hash
  if (user.block_new === true && !isOwner &&
      !(await knownContact({ uaHash: user.ua_hash }, hash, payload.sub, String(req.headers['x-access-key'] || '')))) {
    return reply.code(404).send({ error: 'Nie znaleziono' })
  }
  delete user.block_new
  let stranger = false
  if (user.email_block === true && payload && !isOwner) {
    const ak = String(req.headers['x-access-key'] || '')
    let shared = false
    if (ak && user.ua_hash) {
      const got = crypto.createHash('sha256').update(Buffer.from(ak, 'base64')).digest('hex')
      shared = got.length === user.ua_hash.length &&
        crypto.timingSafeEqual(Buffer.from(got), Buffer.from(user.ua_hash))
    }
    if (!shared) {
      const { rows: rel } = await db.query(
        `SELECT 1 FROM conversation_participants cp1
         JOIN conversation_participants cp2 ON cp1.conversation_id = cp2.conversation_id
         WHERE cp1.user_hash = $1 AND cp2.user_hash = $2 LIMIT 1`,
        [payload.sub, hash]
      )
      shared = rel.length > 0
    }
    stranger = !shared
  }
  if (stranger && !lookupAllowed('h', payload.sub, hash, HIDDEN_LOOKUP_LIMIT)) {
    return reply.code(404).send({ error: 'Nie znaleziono' })
  }
  if (stranger) {
    delete user.avatar_url
    delete user.avatar_updated_at
  }
  delete user.email_block
  delete user.ua_hash
  if (!isOwner || !user.profile_key_wrap) delete user.profile_key_wrap

  const pres = presenceOf(hash)
  user.last_heartbeat_ms = pres.hb
  user.last_seen_ms = pres.seen
  user.is_online = !!(isOnlineNow(hash) && !user.activity_hidden)
  user.signal = (await signalCapable([hash])).has(hash)
  user.call_e2e = user.call_e2e === true

  const blockedByOwner = payload ? await isBlockedBy(hash, payload.sub) : false

  if (user.activity_hidden === true || !payload || blockedByOwner || stranger) {
    user.last_heartbeat_ms = 0
    user.last_seen_ms = 0
    if (blockedByOwner || !payload || stranger) user.is_online = false
  }
  delete user.activity_hidden

  user.server_now_ms = now

  return user
})

app.post('/api/user/update', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  const { displayName, avatarUrl, chatPrivacyMode, activityHidden, avatarColor,
          avatarUpdatedAt, e2ePublicKey, keyUpdatedAt, emailBlock,
          autoDeleteAfterSec, blockNew } = req.body || {}
  if (displayName != null && (typeof displayName !== 'string' || displayName.length > 1024)) {
    return reply.code(400).send({ error: 'Nieprawidłowa nazwa' })
  }

  let autoDeleteSec = null
  if (autoDeleteAfterSec !== undefined && autoDeleteAfterSec !== null) {
    const n = Number(autoDeleteAfterSec)
    if (Number.isFinite(n) && n >= 0) autoDeleteSec = Math.min(Math.floor(n), 100 * 365 * 24 * 3600)
  }

  const oldKey = e2ePublicKey ? await currentKeyOf(payload.sub) : null

  const safeAvatar  = cleanUserAvatarUrl(avatarUrl)
  const avatarValue = safeAvatar === '' ? null : (safeAvatar ?? undefined)
  const clearAvatar = safeAvatar === ''
  let oldAvatar = null
  if (clearAvatar || typeof avatarValue === 'string') {
    try {
      const { rows } = await db.query('SELECT avatar_url FROM users WHERE email_hash=$1', [payload.sub])
      oldAvatar = rows[0]?.avatar_url || null
    } catch (_) {}
  }

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
    [payload.sub, displayName ?? null, clearAvatar ? null : (avatarValue ?? null),
     chatPrivacyMode ?? null, avatarColor ?? null, clearAvatar,
     avatarUpdatedAt ?? null, e2ePublicKey ?? null, keyUpdatedAt ?? null,
     activityHidden ?? null, emailBlock ?? null, autoDeleteSec,
     typeof blockNew === 'boolean' ? blockNew : null]
  )
  if (blockNew === true) {
    await db.query('UPDATE contact_invites SET revoked=true WHERE owner_hash=$1 AND revoked=false', [payload.sub]).catch(() => {})
  }
  if (e2ePublicKey && oldKey && oldKey !== e2ePublicKey) await dropSignalKeys(payload.sub)
  if (e2ePublicKey) announceKeyChange(payload.sub, oldKey, e2ePublicKey)
  const profileKeyWrap = req.body?.profileKeyWrap
  if (typeof profileKeyWrap === 'string' && profileKeyWrap.length > 0 && profileKeyWrap.length <= 256) {
    await db.query('UPDATE users SET profile_key_wrap=$2 WHERE email_hash=$1', [payload.sub, profileKeyWrap])
  }
  const accessKey = req.body?.accessKey
  if (typeof accessKey === 'string' && accessKey.length <= 64) {
    const raw = Buffer.from(accessKey, 'base64')
    if (raw.length === 16) {
      await db.query('UPDATE users SET ua_hash=$2 WHERE email_hash=$1',
        [payload.sub, crypto.createHash('sha256').update(raw).digest('hex')])
    }
  }
  if (clearAvatar) {
    purgeAvatarFile(payload.sub, oldAvatar, 'all')
  } else if (typeof avatarValue === 'string' && oldAvatar &&
             avatarFileOf(oldAvatar) && avatarFileOf(oldAvatar) !== avatarFileOf(avatarValue)) {
    purgeAvatarFile(payload.sub, oldAvatar, 'file')
  }
  return { ok: true }
})

app.post('/api/user/change-email', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const oldHash = payload.sub
  const { newHash, authProof } = req.body || {}
  try {
    const { rows } = await db.query('SELECT account_kind FROM users WHERE email_hash=$1', [oldHash])
    if (rows[0]?.account_kind === 'anon') return reply.code(409).send({ error: 'Konto bez e-maila', code: 'anon_account' })
  } catch (_) {}
  if (!newHash || typeof newHash !== 'string' || !/^[a-f0-9]{64}$/.test(newHash)) {
    return reply.code(400).send({ error: 'Brak lub nieprawidłowy newHash' })
  }

  if (!verifyAuthProof(authProof, newHash)) {
    if (REQUIRE_AUTH_PROOF) {
      return reply.code(401).send({
        error: 'Wymagane potwierdzenie nowego adresu e-mail',
        code: 'email_verification_required'
      })
    }
    console.warn('[CHANGE-EMAIL] zmiana adresu bez dowodu weryfikacji')
  }
  if (newHash === oldHash) {
    return reply.code(400).send({ error: 'Nowy e-mail jest taki sam jak obecny' })
  }

  const client = await db.connect()
  try {
    const { rows: exists } = await client.query(
      'SELECT 1 FROM users WHERE email_hash=$1', [newHash])
    if (exists.length > 0) {
      client.release()
      return reply.code(409).send({ error: 'Ten e-mail jest już w użyciu' })
    }

    await client.query('BEGIN')

    await client.query('UPDATE users SET email_hash=$1 WHERE email_hash=$2', [newHash, oldHash])
    await client.query('UPDATE conversation_participants SET user_hash=$1 WHERE user_hash=$2', [newHash, oldHash])
    await client.query('UPDATE conversation_meta SET user_hash=$1 WHERE user_hash=$2', [newHash, oldHash])
    await client.query('UPDATE messages SET sender_hash=$1 WHERE sender_hash=$2', [newHash, oldHash])
    await client.query('UPDATE messages SET recipient_hash=$1 WHERE recipient_hash=$2', [newHash, oldHash])
    await client.query('UPDATE blocked_users SET blocker_hash=$1 WHERE blocker_hash=$2', [newHash, oldHash])
    await client.query('UPDATE blocked_users SET blocked_hash=$1 WHERE blocked_hash=$2', [newHash, oldHash])
    await client.query('UPDATE groups SET created_by=$1 WHERE created_by=$2', [newHash, oldHash])
    await client.query('SAVEPOINT bans')
    try { await client.query('UPDATE group_bans SET user_hash=$1 WHERE user_hash=$2', [newHash, oldHash]) }
    catch (_) { await client.query('ROLLBACK TO SAVEPOINT bans') }
    await client.query('SAVEPOINT signal')
    try {
      await client.query('UPDATE signal_prekeys SET user_hash=$1 WHERE user_hash=$2', [newHash, oldHash])
      await client.query('UPDATE signal_keys SET user_hash=$1 WHERE user_hash=$2', [newHash, oldHash])
    } catch (_) { await client.query('ROLLBACK TO SAVEPOINT signal') }

    await client.query('COMMIT')
    client.release()

    forgetPresence(oldHash)
    const token = signToken(newHash, payload.deviceId || null)
    const prevSocket = connections.get(oldHash)
    if (prevSocket) {
      connections.delete(oldHash)
      try { prevSocket.close() } catch (_) {}
    }
    return { ok: true, token, userHash: newHash }
  } catch (e) {
    try { await client.query('ROLLBACK') } catch (_) {}
    client.release()
    app.log.error('change-email failed: ' + e.message)
    return reply.code(500).send({ error: 'Zmiana e-maila nie powiodła się' })
  }
})

const USER_AVATAR_FILE_RE = /\/uploads\/avatars\/((?:[0-9a-f]{32}|[0-9a-f]{64})\.(?:jpg|png|webp|bin))/
function avatarFileOf(url) {
  const m = typeof url === 'string' ? url.match(USER_AVATAR_FILE_RE) : null
  return m ? m[1] : ''
}
async function purgeAvatarFile(hash, avatarUrl, mode = 'all') {
  const file = avatarFileOf(avatarUrl)
  if (mode === 'file' && !file) return false
  const expires = String(Date.now() + 5 * 60 * 1000)
  const sig = crypto.createHmac('sha256', UPLOAD_TOKEN_SECRET)
    .update(`purge_avatar|${hash}|${file}|${mode}|${expires}`).digest('hex')
  try {
    const res = await fetch('https://files.sinusoide.pl/api/upload.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ action: 'purge_avatar', account: hash, file, mode, expires, sig }).toString(),
      signal: AbortSignal.timeout(15_000)
    })
    if (!res.ok) console.warn('[AVATAR] kasowanie zdjęcia nieudane: HTTP', res.status)
    return res.ok
  } catch (e) {
    console.warn('[AVATAR] kasowanie zdjęcia nieudane:', e.message)
    return false
  }
}

const SQL_NAME_RE = /^[a-z_][a-z0-9_]*$/

async function clearUserReferences(client, hash) {
  const user = (await client.query('SELECT * FROM users WHERE email_hash=$1', [hash])).rows[0]
  if (!user) return
  const { rows: refs } = await client.query(
    `SELECT kcu.table_name, kcu.column_name, pk.column_name AS ref_column, col.is_nullable
       FROM information_schema.referential_constraints rc
       JOIN information_schema.key_column_usage kcu
         ON kcu.constraint_name = rc.constraint_name AND kcu.constraint_schema = rc.constraint_schema
       JOIN information_schema.key_column_usage pk
         ON pk.constraint_name = rc.unique_constraint_name AND pk.constraint_schema = rc.unique_constraint_schema
        AND pk.ordinal_position = kcu.position_in_unique_constraint
       JOIN information_schema.columns col
         ON col.table_schema = kcu.table_schema AND col.table_name = kcu.table_name AND col.column_name = kcu.column_name
      WHERE pk.table_name = 'users' AND kcu.table_schema = current_schema()`)
  for (const r of refs) {
    if (r.table_name === 'users') continue
    if (![r.table_name, r.column_name, r.ref_column].every(n => SQL_NAME_RE.test(n))) continue
    const value = user[r.ref_column]
    if (value === null || value === undefined) continue
    await client.query('SAVEPOINT ref')
    try {
      if (r.is_nullable === 'YES') {
        await client.query(`UPDATE "${r.table_name}" SET "${r.column_name}"=NULL WHERE "${r.column_name}"=$1`, [value])
      } else {
        await client.query(`DELETE FROM "${r.table_name}" WHERE "${r.column_name}"=$1`, [value])
      }
    } catch (e) {
      await client.query('ROLLBACK TO SAVEPOINT ref')
      console.warn('[ACCOUNT] nie wyczyszczono', r.table_name + '.' + r.column_name + ':', e.message)
    }
  }
}

async function deleteUserData(hash) {
  forgetPresence(hash)
  let avatarUrl = null
  try {
    const { rows } = await db.query('SELECT avatar_url FROM users WHERE email_hash=$1', [hash])
    avatarUrl = rows[0]?.avatar_url || null
  } catch (_) {}
  const client = await db.connect()
  try {
    await client.query('BEGIN')
    await client.query('DELETE FROM messages WHERE sender_hash=$1 OR recipient_hash=$1', [hash])
    await client.query('DELETE FROM conversation_meta WHERE user_hash=$1', [hash])
    await client.query('DELETE FROM conversation_participants WHERE user_hash=$1', [hash])
    await client.query('DELETE FROM blocked_users WHERE blocker_hash=$1 OR blocked_hash=$1', [hash])
    await client.query('SAVEPOINT owner')
    try {
      await client.query('UPDATE groups SET created_by=NULL WHERE created_by=$1', [hash])
    } catch (_) {
      await client.query('ROLLBACK TO SAVEPOINT owner')
      await client.query(
        `UPDATE groups g SET created_by = cp.user_hash
           FROM (SELECT DISTINCT ON (conversation_id) conversation_id, user_hash
                   FROM conversation_participants
                  WHERE user_hash <> $1
                  ORDER BY conversation_id, is_admin DESC NULLS LAST) cp
          WHERE g.id = cp.conversation_id AND g.created_by = $1`, [hash])
      await client.query('SAVEPOINT orphan')
      try { await client.query('DELETE FROM groups WHERE created_by=$1', [hash]) }
      catch (_) { await client.query('ROLLBACK TO SAVEPOINT orphan') }
    }
    await client.query('SAVEPOINT reports')
    try { await client.query('DELETE FROM bug_reports WHERE user_hash=$1', [hash]) }
    catch (_) { await client.query('ROLLBACK TO SAVEPOINT reports') }
    await client.query('SAVEPOINT invites')
    try { await client.query('DELETE FROM contact_invites WHERE owner_hash=$1', [hash]) }
    catch (_) { await client.query('ROLLBACK TO SAVEPOINT invites') }
    await client.query('SAVEPOINT bans')
    try { await client.query('DELETE FROM group_bans WHERE user_hash=$1', [hash]) }
    catch (_) { await client.query('ROLLBACK TO SAVEPOINT bans') }
    await client.query('SAVEPOINT signal')
    try {
      await client.query('DELETE FROM signal_prekeys WHERE user_hash=$1', [hash])
      await client.query('DELETE FROM signal_keys WHERE user_hash=$1', [hash])
    } catch (_) { await client.query('ROLLBACK TO SAVEPOINT signal') }
    await clearUserReferences(client, hash)
    await client.query('DELETE FROM users WHERE email_hash=$1', [hash])
    await client.query('COMMIT')
    purgeAvatarFile(hash, avatarUrl, 'all')
  } catch (e) {
    try { await client.query('ROLLBACK') } catch (_) {}
    throw e
  } finally {
    client.release()
  }
}

app.post('/api/user/delete-account', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  try {
    await deleteUserData(payload.sub)
    const ws = connections.get(payload.sub)
    if (ws) { try { ws.close() } catch (_) {} }
    return { ok: true }
  } catch (e) {
    app.log.error('delete-account failed: ' + e.message +
      (e.table ? ' | tabela: ' + e.table : '') + (e.constraint ? ' | ograniczenie: ' + e.constraint : ''))
    return reply.code(500).send({ error: 'Usunięcie konta nie powiodło się' })
  }
})

const ACCOUNT_DELETION_DELAY_MS = 14 * 24 * 60 * 60 * 1000

app.get('/api/user/deletion', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  const { rows } = await db.query(
    'SELECT deletion_scheduled_at FROM users WHERE email_hash=$1', [payload.sub])
  const at = rows[0]?.deletion_scheduled_at ? Number(rows[0].deletion_scheduled_at) : null
  return { scheduledAt: at, deleteAt: at ? at + ACCOUNT_DELETION_DELAY_MS : null, now: Date.now() }
})

app.post('/api/user/deletion', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  if (req.body?.cancel === true) {
    await db.query('UPDATE users SET deletion_scheduled_at=NULL WHERE email_hash=$1', [payload.sub])
    return { ok: true, scheduledAt: null, deleteAt: null }
  }
  const now = Date.now()
  const { rows } = await db.query(
    `UPDATE users SET deletion_scheduled_at = COALESCE(deletion_scheduled_at, $2)
      WHERE email_hash=$1 RETURNING deletion_scheduled_at`,
    [payload.sub, now])
  if (!rows.length) return reply.code(404).send({ error: 'Nie znaleziono konta' })
  const at = Number(rows[0].deletion_scheduled_at)
  return { ok: true, scheduledAt: at, deleteAt: at + ACCOUNT_DELETION_DELAY_MS, now }
})

async function purgeScheduledAccounts() {
  try {
    const cutoff = Date.now() - ACCOUNT_DELETION_DELAY_MS
    const { rows } = await db.query(
      'SELECT email_hash FROM users WHERE deletion_scheduled_at IS NOT NULL AND deletion_scheduled_at <= $1',
      [cutoff])
    let removed = 0
    for (const { email_hash } of rows) {
      try {
        await deleteUserData(email_hash)
        const ws = connections.get(email_hash)
        if (ws) { try { ws.close() } catch (_) {} }
        removed++
      } catch (e) {
        console.error('[ACCOUNT] błąd usuwania zaplanowanego konta:', e.message)
      }
    }
    if (removed) console.log('[ACCOUNT] usunięto zaplanowane konta:', removed)
  } catch (e) {
    console.error('[ACCOUNT] błąd przeglądu zaplanowanych usunięć:', e.message)
  }
}
setInterval(purgeScheduledAccounts, 60 * 60 * 1000)

async function purgeInactiveAccounts() {
  try {
    const now = Date.now()
    const { rows } = await db.query(
      `SELECT email_hash FROM users
        WHERE COALESCE(auto_delete_after_sec,0) > 0
          AND last_active_day IS NOT NULL
          AND (last_active_day::bigint + 1) * 86400000 <= $1::bigint - auto_delete_after_sec * 1000`,
      [now])
    let removed = 0
    for (const { email_hash } of rows) {
      try {
        await deleteUserData(email_hash)
        const ws = connections.get(email_hash)
        if (ws) { try { ws.close() } catch (_) {} }
        removed++
      } catch (e) {
        console.error('[ACCOUNT] błąd usuwania nieużywanego konta:', e.message)
      }
    }
    if (removed) console.log('[ACCOUNT] usunięto nieużywane konta:', removed)
  } catch (e) {
    console.error('[ACCOUNT] błąd przeglądu nieużywanych kont:', e.message)
  }
}
setInterval(purgeInactiveAccounts, 60 * 60 * 1000)

async function purgeOldInvites() {
  try {
    await db.query(
      `DELETE FROM contact_invites
        WHERE revoked = true
           OR (kind = 'once' AND used_at IS NOT NULL AND used_at < $1)
           OR (kind = 'once' AND expires_at IS NOT NULL AND expires_at < $1)`,
      [Date.now() - 24 * 3600 * 1000])
  } catch (_) {}
}
setInterval(purgeOldInvites, 60 * 60 * 1000)

const REPORTS_ADMIN_KEY = process.env.REPORTS_ADMIN_KEY || null
const REPORT_TOPICS   = new Set(['bug', 'feature', 'other'])
const REPORT_STATUSES = new Set(['pending', 'confirmed', 'rejected'])
const REPORT_MAX_PER_DAY = 10
const REPORT_RETENTION_DAYS = 30
const REPORT_RETENTION_MS = REPORT_RETENTION_DAYS * 24 * 60 * 60 * 1000
const REPORT_RETENTION_BASE_SQL = 'GREATEST(created_at, COALESCE(replied_at, 0), COALESCE(decided_at, 0))'

if (!REPORTS_ADMIN_KEY || REPORTS_ADMIN_KEY.length < 24) {
  console.warn('[UWAGA] Brak REPORTS_ADMIN_KEY (min. 24 znaki) — panel zgłoszeń /api/reports-admin jest wyłączony. ' +
    'Zgłoszenia z aplikacji i tak się zapisują.')
}

function clip(v, max) {
  if (v === undefined || v === null) return null
  const s = String(v).replace(/\u0000/g, '').trim()
  return s ? s.slice(0, max) : null
}

const REPORTS_ADMIN_IPS = (process.env.REPORTS_ADMIN_IPS || '')
  .split(',').map(x => x.trim()).filter(Boolean)

function checkReportsAdmin(req) {
  if (!REPORTS_ADMIN_KEY || REPORTS_ADMIN_KEY.length < 24) return 'disabled'
  if (REPORTS_ADMIN_IPS.length) {
    if (!REPORTS_ADMIN_IPS.includes(clientIp(req))) return 'bad'
  }
  const given = String(req.headers['x-admin-key'] || '')
  const a = crypto.createHash('sha256').update(given).digest()
  const b = crypto.createHash('sha256').update(REPORTS_ADMIN_KEY).digest()
  return crypto.timingSafeEqual(a, b) && given.length > 0 ? 'ok' : 'bad'
}

function denyReportsAdmin(reply, state) {
  if (state === 'disabled') return reply.code(503).send({ error: 'Panel wyłączony — ustaw REPORTS_ADMIN_KEY na serwerze' })
  return reply.code(401).send({ error: 'Nieprawidłowy klucz' })
}

app.post('/api/report', { config: { rateLimit: { max: 6, timeWindow: '1 hour' } } }, async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const b = req.body || {}
  const description = clip(b.description, 4000)
  const email = clip(b.email, 254)
  const topic = REPORT_TOPICS.has(b.topic) ? b.topic : 'other'
  if (!description || description.length < 10) {
    return reply.code(400).send({ error: 'Opis jest za krótki', code: 'description_too_short' })
  }
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return reply.code(400).send({ error: 'Nieprawidłowy e-mail', code: 'invalid_email' })
  }

  const dayAgo = Date.now() - 24 * 60 * 60 * 1000
  const { rows: cnt } = await db.query(
    'SELECT count(*)::int AS n FROM bug_reports WHERE user_hash=$1 AND created_at > $2', [payload.sub, dayAgo])
  if ((cnt[0]?.n || 0) >= REPORT_MAX_PER_DAY) {
    return reply.code(429).send({ error: 'Za dużo zgłoszeń — spróbuj jutro', code: 'too_many_reports' })
  }

  const now = Date.now()
  const { rows } = await db.query(
    `INSERT INTO bug_reports (user_hash, email, name, topic, description, app_version, device, android,
                              diagnostics, status, created_at, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10,$10) RETURNING id`,
    [payload.sub, email, clip(b.name, 100), topic, description, clip(b.appVersion, 40),
     clip(b.device, 120), clip(b.android, 20), clip(b.diagnostics, 16000), now])
  console.log('[REPORT] nowe zgłoszenie #' + rows[0].id + ' (' + topic + ')')
  return { ok: true, id: Number(rows[0].id) }
})

app.get('/api/reports/mine', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  const { rows } = await db.query(
    `SELECT id, topic, description, status, reply, replied_at, created_at, (email IS NOT NULL) AS has_email,
            ${REPORT_RETENTION_BASE_SQL} AS retention_base
       FROM bug_reports WHERE user_hash=$1 ORDER BY created_at DESC LIMIT 50`, [payload.sub])
  return {
    reports: rows.map(r => ({
      id: Number(r.id), topic: r.topic, status: r.status,
      description: String(r.description || '').slice(0, 300),
      reply: r.reply || null,
      hasEmail: r.has_email === true,
      deleteAt: Number(r.retention_base) + REPORT_RETENTION_MS,
      repliedAt: r.replied_at ? Number(r.replied_at) : null,
      createdAt: Number(r.created_at)
    }))
  }
})

app.get('/api/reports-admin/list', { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } }, async (req, reply) => {
  const state = checkReportsAdmin(req)
  if (state !== 'ok') return denyReportsAdmin(reply, state)
  const status = REPORT_STATUSES.has(req.query?.status) ? req.query.status : null
  const q = clip(req.query?.q, 100)
  const params = []
  const where = []
  if (status) { params.push(status); where.push(`status = $${params.length}`) }
  if (q) {
    params.push('%' + q.replace(/[\\%_]/g, m => '\\' + m) + '%')
    where.push(`(description ILIKE $${params.length} ESCAPE '\\' OR email ILIKE $${params.length} ESCAPE '\\' OR device ILIKE $${params.length} ESCAPE '\\')`)
  }
  const { rows } = await db.query(
    `SELECT id, email, name, topic, description, app_version, device, android, diagnostics,
            status, reply, replied_at, created_at, updated_at, decided_at,
            ${REPORT_RETENTION_BASE_SQL} AS retention_base
       FROM bug_reports ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
      ORDER BY created_at DESC LIMIT 300`, params)
  const { rows: counts } = await db.query('SELECT status, count(*)::int AS n FROM bug_reports GROUP BY status')
  const stats = { pending: 0, confirmed: 0, rejected: 0 }
  for (const c of counts) if (c.status in stats) stats[c.status] = c.n
  return {
    stats,
    retentionDays: REPORT_RETENTION_DAYS,
    reports: rows.map(r => ({
      id: Number(r.id), email: r.email, name: r.name, topic: r.topic, description: r.description,
      appVersion: r.app_version, device: r.device, android: r.android, diagnostics: r.diagnostics,
      status: r.status, reply: r.reply,
      repliedAt: r.replied_at ? Number(r.replied_at) : null,
      createdAt: Number(r.created_at), updatedAt: r.updated_at ? Number(r.updated_at) : null,
      decidedAt: r.decided_at ? Number(r.decided_at) : null,
      deleteAt: Number(r.retention_base) + REPORT_RETENTION_MS
    }))
  }
})

app.get('/api/reports-admin/version', { config: { rateLimit: { max: 120, timeWindow: '1 minute' } } }, async (req, reply) => {
  const state = checkReportsAdmin(req)
  if (state !== 'ok') return denyReportsAdmin(reply, state)
  const { rows } = await db.query(
    `SELECT count(*)::int AS n,
            COALESCE(max(GREATEST(created_at, COALESCE(updated_at, 0))), 0)::bigint AS last,
            count(*) FILTER (WHERE status = 'pending')::int AS fresh
       FROM bug_reports`)
  const r = rows[0] || { n: 0, last: 0, fresh: 0 }
  return { version: r.n + ':' + r.last, total: r.n, newCount: r.fresh }
})

app.post('/api/reports-admin/:id', { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } }, async (req, reply) => {
  const state = checkReportsAdmin(req)
  if (state !== 'ok') return denyReportsAdmin(reply, state)
  const id = Number(req.params.id)
  if (!Number.isSafeInteger(id) || id <= 0) return reply.code(400).send({ error: 'Złe id' })
  const b = req.body || {}

  if (b.delete === true) {
    await db.query('DELETE FROM bug_reports WHERE id=$1', [id])
    return { ok: true, deleted: true }
  }
  const status = REPORT_STATUSES.has(b.status) ? b.status : null
  const hasReply = Object.prototype.hasOwnProperty.call(b, 'reply')
  const replyText = hasReply ? clip(b.reply, 4000) : null
  const now = Date.now()

  const { rows: before } = await db.query('SELECT user_hash, status, reply FROM bug_reports WHERE id=$1', [id])
  if (!before.length) return reply.code(404).send({ error: 'Nie ma takiego zgłoszenia' })
  const old = before[0]
  const statusChanged = status !== null && status !== old.status
  const replyChanged = hasReply && (replyText || null) !== (old.reply || null)

  await db.query(
    `UPDATE bug_reports SET
        status     = COALESCE($2, status),
        decided_at = CASE WHEN NOT $6 THEN decided_at
                          WHEN $2 IN ('confirmed', 'rejected') THEN $5::bigint
                          ELSE NULL END,
        reply      = CASE WHEN $3 THEN $4 ELSE reply END,
        replied_at = CASE WHEN $3 AND $4 IS DISTINCT FROM reply THEN
                       (CASE WHEN $4 IS NULL THEN NULL ELSE $5::bigint END)
                     ELSE replied_at END,
        updated_at = $5
      WHERE id=$1`,
    [id, status, hasReply, replyText, now, statusChanged])

  if ((statusChanged || (replyChanged && replyText)) && old.user_hash) {
    sendToUser(old.user_hash, {
      type: 'report_update', id,
      status: status || old.status,
      replied: Boolean(replyChanged && replyText)
    })
  }
  return { ok: true }
})


async function purgeOldReports() {
  try {
    const { rowCount } = await db.query(
      `DELETE FROM bug_reports WHERE ${REPORT_RETENTION_BASE_SQL} < $1`,
      [Date.now() - REPORT_RETENTION_MS])
    if (rowCount) console.log('[REPORT] usunięto zgłoszenia po ' + REPORT_RETENTION_DAYS + ' dniach od ostatniej zmiany:', rowCount)
  } catch (_) {}
}
setInterval(purgeOldReports, 60 * 60 * 1000)
setTimeout(purgeOldReports, 60 * 1000)


const INVITE_ONCE_TTL_MS = 7 * 24 * 60 * 60 * 1000
const INVITE_MAX_ACTIVE_ONCE = 20
const INVITE_CODE_RE = /^inv_[A-Za-z0-9_-]{20,40}$/

function newInviteCode() {
  return 'inv_' + crypto.randomBytes(16).toString('base64url')
}

function inviteJson(r) {
  return {
    code: r.code, kind: r.kind,
    createdAt: Number(r.created_at),
    expiresAt: r.expires_at ? Number(r.expires_at) : null,
    useCount: Number(r.use_count || 0)
  }
}

app.post('/api/invites', { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } }, async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const kind = req.body?.kind === 'multi' ? 'multi' : 'once'
  const now = Date.now()
  if (await newChatsBlocked(payload.sub)) {
    return reply.code(403).send({ error: 'Masz włączoną blokadę nowych rozmów', code: 'block_new' })
  }

  if (kind === 'multi') {
    if (req.body?.reset === true) {
      await db.query("UPDATE contact_invites SET revoked=true WHERE owner_hash=$1 AND kind='multi' AND revoked=false",
        [payload.sub])
    } else {
      const { rows } = await db.query(
        "SELECT * FROM contact_invites WHERE owner_hash=$1 AND kind='multi' AND revoked=false ORDER BY created_at DESC LIMIT 1",
        [payload.sub])
      if (rows.length) return { invite: inviteJson(rows[0]) }
    }
    const code = newInviteCode()
    const { rows } = await db.query(
      "INSERT INTO contact_invites (code, owner_hash, kind, created_at) VALUES ($1,$2,'multi',$3) RETURNING *",
      [code, payload.sub, now])
    return { invite: inviteJson(rows[0]) }
  }

  await db.query(
    "UPDATE contact_invites SET revoked=true " +
    " WHERE code IN (SELECT code FROM contact_invites " +
    "   WHERE owner_hash=$1 AND kind='once' AND revoked=false AND used_at IS NULL AND expires_at > $2 " +
    "   ORDER BY created_at DESC OFFSET $3)",
    [payload.sub, now, INVITE_MAX_ACTIVE_ONCE - 1])
  const code = newInviteCode()
  const { rows } = await db.query(
    "INSERT INTO contact_invites (code, owner_hash, kind, created_at, expires_at) VALUES ($1,$2,'once',$3,$4) RETURNING *",
    [code, payload.sub, now, now + INVITE_ONCE_TTL_MS])
  return { invite: inviteJson(rows[0]) }
})

app.post('/api/invites/preview', { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } }, async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const code = String(req.body?.code || '')
  if (!INVITE_CODE_RE.test(code)) return reply.code(404).send({ error: 'Nieprawidłowe zaproszenie', code: 'invite_invalid' })
  const { rows: found } = await db.query('SELECT * FROM contact_invites WHERE code=$1', [code])
  const inv = found[0]
  if (!inv) return reply.code(404).send({ error: 'Nieprawidłowe zaproszenie', code: 'invite_invalid' })
  if (inv.owner_hash === payload.sub) return reply.code(409).send({ error: 'To Twoje zaproszenie', code: 'invite_own' })
  if (inv.revoked) return reply.code(410).send({ error: 'Zaproszenie zostało wyłączone', code: 'invite_revoked' })
  if (inv.kind === 'once' && inv.used_at) {
    if (inv.used_by !== payload.sub) return reply.code(410).send({ error: 'Zaproszenie zostało już wykorzystane', code: 'invite_used' })
  } else if (inv.kind === 'once' && inv.expires_at && Number(inv.expires_at) < Date.now()) {
    return reply.code(410).send({ error: 'Zaproszenie wygasło', code: 'invite_expired' })
  }
  if (await isBlockedBy(inv.owner_hash, payload.sub)) {
    return reply.code(410).send({ error: 'Zaproszenie zostało wyłączone', code: 'invite_revoked' })
  }
  if (await newChatsBlocked(inv.owner_hash)) {
    return reply.code(410).send({ error: 'Zaproszenie zostało wyłączone', code: 'invite_revoked' })
  }
  const { rows: owner } = await db.query(
    'SELECT email_hash, display_name, avatar_color FROM users WHERE email_hash=$1', [inv.owner_hash])
  if (!owner.length) return reply.code(410).send({ error: 'Konto już nie istnieje', code: 'invite_owner_gone' })
  return {
    ok: true,
    hash: owner[0].email_hash,
    displayName: owner[0].display_name,
    avatarColor: owner[0].avatar_color || null
  }
})

app.post('/api/invites/redeem', { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } }, async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const code = String(req.body?.code || '')
  if (!INVITE_CODE_RE.test(code)) return reply.code(404).send({ error: 'Nieprawidłowe zaproszenie', code: 'invite_invalid' })

  const now = Date.now()
  const { rows: found } = await db.query('SELECT * FROM contact_invites WHERE code=$1', [code])
  const inv = found[0]
  if (!inv) return reply.code(404).send({ error: 'Nieprawidłowe zaproszenie', code: 'invite_invalid' })
  if (inv.owner_hash === payload.sub) return reply.code(409).send({ error: 'To Twoje zaproszenie', code: 'invite_own' })
  if (inv.revoked) return reply.code(410).send({ error: 'Zaproszenie zostało wyłączone', code: 'invite_revoked' })
  if (inv.kind === 'once' && inv.used_at) {
    if (inv.used_by !== payload.sub) return reply.code(410).send({ error: 'Zaproszenie zostało już wykorzystane', code: 'invite_used' })
  } else if (inv.kind === 'once' && inv.expires_at && Number(inv.expires_at) < now) {
    return reply.code(410).send({ error: 'Zaproszenie wygasło', code: 'invite_expired' })
  }
  if (await isBlockedBy(inv.owner_hash, payload.sub)) {
    return reply.code(410).send({ error: 'Zaproszenie zostało wyłączone', code: 'invite_revoked' })
  }
  if (await newChatsBlocked(inv.owner_hash)) {
    return reply.code(410).send({ error: 'Zaproszenie zostało wyłączone', code: 'invite_revoked' })
  }

  if (inv.kind === 'once' && !inv.used_at) {
    const { rowCount } = await db.query(
      "UPDATE contact_invites SET used_at=$2, used_by=$3, use_count=use_count+1 " +
      " WHERE code=$1 AND used_at IS NULL AND revoked=false AND (expires_at IS NULL OR expires_at >= $2)",
      [code, now, payload.sub])
    if (!rowCount) return reply.code(410).send({ error: 'Zaproszenie zostało już wykorzystane', code: 'invite_used' })
  } else if (inv.kind === 'multi') {
    await db.query('UPDATE contact_invites SET use_count=use_count+1 WHERE code=$1', [code])
  }

  const { rows: owner } = await db.query(
    'SELECT email_hash, display_name, avatar_url FROM users WHERE email_hash=$1', [inv.owner_hash])
  if (!owner.length) return reply.code(410).send({ error: 'Konto już nie istnieje', code: 'invite_owner_gone' })

  const a = payload.sub, b = inv.owner_hash
  const conversationId = a < b ? a + '_' + b : b + '_' + a
  sendToUser(inv.owner_hash, { type: 'invite_used', conversationId, byHash: payload.sub })

  return {
    ok: true, conversationId,
    hash: owner[0].email_hash,
    displayName: owner[0].display_name,
    avatarUrl: owner[0].avatar_url || null
  }
})

app.post('/api/user/ntfy-topic', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const ntfyTopic = await ensureUserNtfyTopic(payload.sub)
  return { ok: true, ntfyTopic }
})

app.get('/api/push/config', { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } }, async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  return { fcm: fcmAvailable() }
})

app.post('/api/user/push', { config: { rateLimit: { max: 30, timeWindow: '1 hour' } } }, async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const mode = req.body?.mode === 'fcm' ? 'fcm' : 'ntfy'
  let token = null
  if (mode === 'fcm') {
    if (!fcmAvailable()) return reply.code(409).send({ error: 'fcm_unavailable' })
    token = typeof req.body?.token === 'string' ? req.body.token.trim() : ''
    if (!token || token.length > 4096 || !/^[A-Za-z0-9_:\-]+$/.test(token)) {
      return reply.code(400).send({ error: 'Nieprawidłowy token' })
    }
  }
  try {
    await db.query('UPDATE users SET push_mode=$2, fcm_token=$3 WHERE email_hash=$1', [payload.sub, mode, token])
  } catch (e) {
    return reply.code(500).send({ error: 'Błąd zapisu' })
  }
  _pushPrefCache.set(payload.sub, { mode, token })
  return { ok: true, mode }
})

app.post('/api/call/reject', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const { conversationId } = req.body || {}
  if (!conversationId) return reply.code(400).send({ error: 'Brak conversationId' })
  if (!(await canUseConversation(conversationId, payload.sub))) {
    return reply.code(403).send({ error: 'Brak dostępu do rozmowy' })
  }

  const { rows } = await db.query(
    'SELECT user_hash FROM conversation_participants WHERE conversation_id=$1 AND user_hash!=$2',
    [conversationId, payload.sub]
  )
  for (const { user_hash } of rows) {
    sendToUser(user_hash, { type: 'call_reject', conversationId })
  }
  return { ok: true }
})

app.post('/api/user/block', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  const { blockedHash, block } = req.body || {}
  if (!blockedHash) return reply.code(400).send({ error: 'Brak blockedHash' })
  if (block) {
    await db.query('INSERT INTO blocked_users(blocker_hash,blocked_hash) VALUES($1,$2) ON CONFLICT DO NOTHING', [payload.sub, blockedHash])
  } else {
    await db.query('DELETE FROM blocked_users WHERE blocker_hash=$1 AND blocked_hash=$2', [payload.sub, blockedHash])
    sendToUser(blockedHash, { type: 'unblocked', by: payload.sub })
  }
  return { ok: true, blocked: !!block }
})

app.post('/api/user/unblock', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const hash = req.body?.unblockedHash || req.body?.blockedHash
  if (!hash) return reply.code(400).send({ error: 'Brak hasha' })
  await db.query('DELETE FROM blocked_users WHERE blocker_hash=$1 AND blocked_hash=$2', [payload.sub, hash])
  sendToUser(hash, { type: 'unblocked', by: payload.sub })
  return { ok: true, blocked: false }
})

app.post('/api/heartbeat', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const now = Date.now()
  if (req.body?.touchOnly === true) {
    touchActiveDay(payload.sub)
    return { ok: true, server_now_ms: now }
  }
  const hb = (req.body?.heartbeatMs > 0) ? now : 0

  const rawSeen = (req.body?.lastSeenMs !== undefined)
    ? req.body.lastSeenMs
    : req.body?.last_seen_ms

  const clearSeen = (hb === 0 && (rawSeen === 0 || rawSeen === '0'))
  const prev = presence.get(payload.sub)
  let ls
  if (hb > 0) ls = now
  else if (clearSeen) ls = 0
  else if (req.body?.heartbeatMs === 0) ls = prev ? (prev.hb > 0 ? prev.hb : prev.seen) : 0
  else ls = Math.min(Number(rawSeen) || now, now)

  const wasOnline = isOnlineNow(payload.sub)
  presence.set(payload.sub, { hb, seen: ls })
  if (hb > 0) touchActiveDay(payload.sub)

  if (wasOnline !== (hb > 0) || clearSeen) try {
    const { rows } = await db.query(
      `SELECT DISTINCT cp2.user_hash FROM conversation_participants cp1
       JOIN conversation_participants cp2 ON cp1.conversation_id = cp2.conversation_id
       WHERE cp1.user_hash = $1 AND cp2.user_hash != $1`,
      [payload.sub]
    )
    for (const { user_hash } of rows) {
      sendToUser(user_hash, { type: 'presence', senderHash: payload.sub, heartbeatMs: hb, lastSeenMs: ls })
    }
  } catch(_) {}

  return { ok: true, server_now_ms: now }
})

app.get('/api/conversations', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const { rows } = await db.query(`
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
    LEFT JOIN conversation_participants cp2 ON cp2.conversation_id = c.id AND cp2.user_hash != $1 AND c.id NOT LIKE 'g_%'
    LEFT JOIN users u                  ON u.email_hash = cp2.user_hash
    LEFT JOIN groups g                 ON g.id = c.id
  `, [payload.sub])
  for (const r of rows) {
    const show = !r.is_group && r.other_hash && r.other_hidden !== true
    const p = show ? presenceOf(r.other_hash) : { hb: 0, seen: 0 }
    r.last_heartbeat_ms = p.hb
    r.last_seen_ms = p.seen
    r.is_online = show ? isOnlineNow(r.other_hash) : false
    delete r.other_hidden
  }
  return rows
})

app.post('/api/presence', { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } }, async (req, reply) => {
  const payload = await verifyActiveDevice(req.headers.authorization?.replace('Bearer ', ''))
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  const list = Array.isArray(req.body?.hashes) ? req.body.hashes.slice(0, 200) : []
  const hashes = [...new Set(list.map(String).filter(h => /^[a-f0-9]{64}$/.test(h)))]
  if (!hashes.length) return {}
  const { rows } = await db.query(
    'SELECT email_hash, activity_hidden, email_block, block_new FROM users WHERE email_hash = ANY($1::varchar[])', [hashes])
  const out = {}
  for (const r of rows) {
    if (r.activity_hidden === true) continue
    if ((r.email_block === true || r.block_new === true) &&
        !lookupAllowed('h', payload.sub, r.email_hash, HIDDEN_LOOKUP_LIMIT)) continue
    if (await isBlockedBy(r.email_hash, payload.sub)) continue
    const p = presenceOf(r.email_hash)
    out[r.email_hash] = { online: isOnlineNow(r.email_hash), seen: p.seen || 0 }
  }
  return out
})

app.get('/api/messages/waiting', async (req, reply) => {
  const payload = await verifyActiveDevice(req.headers.authorization?.replace('Bearer ', ''))
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  const { rows } = await db.query(
    "SELECT COUNT(*)::int AS n FROM messages WHERE recipient_hash=$1 AND delivered_at IS NULL AND kind IN ('msg','group_attach','sealed')",
    [payload.sub])
  return { count: rows[0]?.n || 0 }
})

app.get('/api/messages/pending', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const { rows } = await db.query(
    `SELECT id, conversation_id, sender_hash, kind, payload, created_at
     FROM messages
     WHERE recipient_hash = $1 AND delivered_at IS NULL
     ORDER BY created_at ASC
     LIMIT 500`,
    [payload.sub]
  )
  if (!rows.length) return []

  const ids = rows.map(r => r.id)
  await db.query(
    'UPDATE messages SET delivered_at=$1 WHERE id = ANY($2::varchar[])',
    [Date.now(), ids]
  )

  return rows.map(r => ({
    id: r.id,
    conversationId: r.conversation_id,
    senderHash: r.sender_hash,
    kind: r.kind,
    payloadB64: r.payload.toString('base64'),
    createdAt: r.created_at
  }))
})

app.post('/api/message', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const { conversationId, messageId, kind, payloadB64, recipientHash } = req.body || {}
  if (!conversationId || !messageId || !payloadB64) return reply.code(400).send({ error: 'Brak danych' })

  const msgId    = messageId
  const msgBytes = Buffer.from(payloadB64, 'base64')
  const now      = Date.now()
  const isGroup  = conversationId.startsWith('g_')
  if (msgBytes.length > MESSAGE_MAX_BYTES) return reply.code(413).send({ error: 'Wiadomość za duża' })

  if (kind === 'expiry_notice') return reply.code(400).send({ error: 'Nieprawidłowy rodzaj wiadomości' })

  if (isGroup) {
    const { rows: me } = await db.query(
      'SELECT 1 FROM conversation_participants WHERE conversation_id=$1 AND user_hash=$2 LIMIT 1',
      [conversationId, payload.sub]
    )
    if (!me.length) return reply.code(403).send({ error: 'Nie jesteś członkiem tej rozmowy' })
    if (ADDRESSED_GROUP_KINDS.has(kind) &&
        !(recipientHash && await isParticipant(conversationId, String(recipientHash)))) {
      return reply.code(400).send({ error: 'Adresat nie należy do grupy' })
    }

    const CONTENT_KINDS = new Set(['msg', 'group_attach'])
    if (CONTENT_KINDS.has(kind || 'msg') && !(await groupAllows(conversationId, payload.sub, 'sendMessages'))) {
      return reply.code(403).send({ error: 'Nie można pisać na tej grupie', code: 'group_send_forbidden' })
    }
  } else if (recipientHash) {
    const pairOk = conversationId === canonicalPair(payload.sub, String(recipientHash)) ||
      ((await isParticipant(conversationId, payload.sub)) && (await isParticipant(conversationId, String(recipientHash))))
    if (!pairOk) {
      return reply.code(403).send({ error: 'Nieprawidłowa rozmowa', code: 'conversation_mismatch' })
    }
    if (!lookupAllowed('d', payload.sub, String(recipientHash), DIRECT_TARGET_LIMIT)) {
      return reply.code(429).send({ error: 'Za dużo nowych odbiorców — spróbuj jutro', code: 'too_many_recipients' })
    }
    if (!(await userExists(String(recipientHash)))) {
      return reply.code(410).send({
        error: 'To konto zostało usunięte',
        code: 'account_deleted',
        deleted: String(recipientHash)
      })
    }
    if (await isBlockedBy(recipientHash, payload.sub)) {
      return reply.code(403).send({
        error: 'Nie można wysłać wiadomości do tego odbiorcy',
        code: 'blocked_by_recipient',
        blockedBy: recipientHash
      })
    }
  }

  if (isGroup) {
    await db.query('INSERT INTO conversations(id) VALUES($1) ON CONFLICT DO NOTHING', [conversationId])
    touchGroupDay(conversationId)
  }

  let recipients = []
  if (isGroup && ADDRESSED_GROUP_KINDS.has(kind)) {
    recipients = [String(recipientHash)]
  } else if (isGroup) {
    const { rows: members } = await db.query(
      'SELECT user_hash FROM conversation_participants WHERE conversation_id=$1 AND user_hash!=$2',
      [conversationId, payload.sub]
    )
    recipients = members.map(m => m.user_hash)
  } else {
    if (!recipientHash) return reply.code(400).send({ error: 'Brak recipientHash' })
    recipients = [recipientHash]
  }

  if (isGroup && recipients.length) {
    const { rows: blockers } = await db.query(
      'SELECT blocker_hash FROM blocked_users WHERE blocked_hash=$1 AND blocker_hash = ANY($2::text[])',
      [payload.sub, recipients]
    ).catch(() => ({ rows: [] }))
    if (blockers.length) {
      const skip = new Set(blockers.map(r => r.blocker_hash))
      recipients = recipients.filter(h => !skip.has(h))
    }
  }

  if (!spendBudget('s:' + payload.sub, msgBytes.length * Math.max(1, recipients.length), SENDER_BUDGET_BYTES)) {
    return reply.code(429).send({ error: 'Za dużo danych w krótkim czasie — spróbuj później', code: 'queue_budget' })
  }

  let deliveredAny = false

  for (const rHash of recipients) {
    const rowId = isGroup ? `${msgId}_${rHash.slice(0, 16)}` : msgId

    await db.query(
      `INSERT INTO messages(id,conversation_id,sender_hash,recipient_hash,kind,payload,created_at)
       VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO NOTHING`,
      [rowId, conversationId, payload.sub, rHash, kind || 'msg', msgBytes, now]
    )

    const live = sendToUser(rHash, {
      type: 'message', conversationId, id: msgId, kind: kind || 'msg',
      payloadB64, senderHash: payload.sub, createdAt: now
    })

    if (live) {
      deliveredAny = true
      await db.query('UPDATE messages SET delivered_at=$1 WHERE id=$2', [now, rowId])
    } else {
      wakeUser(rHash, kind || 'msg').catch(() => {})
    }
  }

  return { ok: true, messageId: msgId, deliveredLive: deliveredAny, createdAt: now }
})

const SEALED_MAX_B64 = 700 * 1024
const sealedPerRecipient = new Map()
function sealedFlood(to) {
  const now = Date.now()
  const e = sealedPerRecipient.get(to)
  if (!e || now - e[0] > 60_000) { sealedPerRecipient.set(to, [now, 1]); return false }
  return ++e[1] > 600
}
setInterval(() => {
  const now = Date.now()
  for (const [k, e] of sealedPerRecipient) if (now - e[0] > 60_000) sealedPerRecipient.delete(k)
}, 5 * 60_000).unref()

app.post('/api/sealed', { config: { rateLimit: { max: 240, timeWindow: '1 minute' } } }, async (req, reply) => {
  const { to, ak, id, payloadB64, ik } = req.body || {}
  if (typeof to !== 'string' || !/^[a-f0-9]{64}$/.test(to) ||
      typeof ak !== 'string' || ak.length > 64 ||
      typeof id !== 'string' || !/^[A-Za-z0-9_~.-]{1,100}$/.test(id) ||
      typeof payloadB64 !== 'string' || !payloadB64.length || payloadB64.length > SEALED_MAX_B64) {
    return reply.code(400).send({ error: 'Brak danych' })
  }
  const { rows } = await db.query('SELECT ua_hash, e2e_public_key FROM users WHERE email_hash=$1', [to])
  const expected = rows[0]?.ua_hash
  const got = crypto.createHash('sha256').update(Buffer.from(ak, 'base64')).digest('hex')
  if (!expected || expected.length !== got.length ||
      !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(got))) {
    return reply.code(401).send({ error: 'Brak dostępu', code: 'no_access' })
  }
  const cur = rows[0]?.e2e_public_key
  if (typeof ik === 'string' && cur &&
      crypto.createHash('sha256').update(Buffer.from(cur, 'base64')).digest('hex').slice(0, 16) !== ik) {
    return reply.code(409).send({ error: 'Nieaktualny klucz adresata', code: 'stale_key' })
  }
  if (sealedFlood(to)) return reply.code(429).send({ error: 'Za dużo wiadomości' })
  if (req.body?.eph !== true && !spendBudget('r:' + to, payloadB64.length, SEALED_BUDGET_BYTES)) {
    return reply.code(429).send({ error: 'Za dużo wiadomości' })
  }

  const now = Date.now()
  if (req.body?.eph === true) {
    sendToUser(to, { type: 'message', kind: 'sealed', eph: true, id: 's_' + id, payloadB64, createdAt: now })
    return { ok: true, createdAt: now }
  }
  const rowId = 's_' + id
  const ins = await db.query(
    `INSERT INTO messages(id,conversation_id,sender_hash,recipient_hash,kind,payload,created_at)
     VALUES($1,'',NULL,$2,'sealed',$3,$4) ON CONFLICT(id) DO NOTHING`,
    [rowId, to, Buffer.from(payloadB64, 'base64'), now])
  if (!ins.rowCount) return { ok: true, messageId: id, createdAt: now }

  const live = sendToUser(to, { type: 'message', kind: 'sealed', id: rowId, payloadB64, createdAt: now })
  if (live) await db.query('UPDATE messages SET delivered_at=$1 WHERE id=$2', [now, rowId])
  else wakeUser(to, 'msg').catch(() => {})
  return { ok: true, messageId: id, deliveredLive: !!live, createdAt: now }
})

app.post('/api/sealed/ack', async (req, reply) => {
  const payload = await verifyActiveDevice(req.headers.authorization?.replace('Bearer ', ''))
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  const ids = Array.isArray(req.body?.ids)
    ? req.body.ids.filter(x => typeof x === 'string' && x.length <= 110).slice(0, 500) : []
  if (!ids.length) return { ok: true, deleted: 0 }
  const r = await db.query(
    "DELETE FROM messages WHERE recipient_hash=$1 AND kind='sealed' AND id = ANY($2::varchar[])",
    [payload.sub, ids])
  return { ok: true, deleted: r.rowCount }
})

app.post('/api/ack', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const { conversationId, deliveredUpTo, readUpTo, silentRead, noRelay } = req.body || {}
  if (!conversationId) return reply.code(400).send({ error: 'Brak conversationId' })
  if (!(await canUseConversation(conversationId, payload.sub))) {
    return reply.code(403).send({ error: 'Brak dostępu do rozmowy' })
  }

  const isGroup = String(conversationId).startsWith('g_')
  let groupAuthors = []
  if (deliveredUpTo) {
    const del = await db.query(
      'DELETE FROM messages WHERE recipient_hash=$1 AND conversation_id=$2 AND created_at <= $3::bigint RETURNING sender_hash',
      [payload.sub, conversationId, deliveredUpTo]
    ).catch(() => null)
    if (isGroup && del) groupAuthors = [...new Set(del.rows.map(r => r.sender_hash).filter(h => h && h !== payload.sub))]
  }

  if (!isGroup) {
    if (!noRelay) await relayDirectAck(payload.sub, conversationId, deliveredUpTo, silentRead ? null : readUpTo)
    return { ok: true, deliveredUpTo, readUpTo }
  }
  if (!noRelay) {
    for (const author of groupAuthors.slice(0, 50)) {
      if (await isBlockedBy(payload.sub, author)) continue
      sendToUser(author, { type: 'ack', conversationId, fromHash: payload.sub, deliveredUpTo })
    }
  }
  return { ok: true, deliveredUpTo, readUpTo }
})

app.post('/api/conversations/wipe', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  await db.query('DELETE FROM messages WHERE recipient_hash=$1 OR (sender_hash=$1 AND conversation_id IN (SELECT conversation_id FROM conversation_participants WHERE user_hash=$1))', [payload.sub])
  await db.query('DELETE FROM conversation_meta WHERE user_hash=$1', [payload.sub])
  return { ok: true }
})

app.post('/api/conversations/delete', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  const convId = req.body?.conversationId
  if (!convId || typeof convId !== 'string') return reply.code(400).send({ error: 'Brak conversationId' })

  if (!convId.startsWith('g_')) {
    if (directMember(convId, payload.sub)) {
      await db.query('DELETE FROM messages WHERE conversation_id=$1 AND (recipient_hash=$2 OR sender_hash=$2)', [convId, payload.sub])
    }
    return { ok: true }
  }

  const wasMember = await isParticipant(convId, payload.sub)
  await db.query('DELETE FROM conversation_participants WHERE conversation_id=$1 AND user_hash=$2', [convId, payload.sub])
  await db.query('DELETE FROM conversation_meta WHERE conversation_id=$1 AND user_hash=$2', [convId, payload.sub])
  await db.query('DELETE FROM messages WHERE conversation_id=$1 AND recipient_hash=$2', [convId, payload.sub])
  if (!wasMember) return { ok: true }

  const { rows } = await db.query('SELECT COUNT(*) AS c FROM conversation_participants WHERE conversation_id=$1', [convId])
  if (parseInt(rows[0]?.c || 0) === 0) {
    await db.query('DELETE FROM messages WHERE conversation_id=$1', [convId])
    await db.query('DELETE FROM conversation_meta WHERE conversation_id=$1', [convId])
    await db.query('DELETE FROM conversations WHERE id=$1', [convId])
    await db.query('DELETE FROM groups WHERE id=$1', [convId])
  }
  return { ok: true }
})

const SEARCH_LIMIT       = 20
const SEARCH_WINDOW_MS   = 10 * 60_000
const _searchHits = new Map()
setInterval(() => {
  const cutoff = Date.now() - SEARCH_WINDOW_MS
  for (const [h, arr] of _searchHits) {
    const fresh = arr.filter(t => t > cutoff)
    if (fresh.length) _searchHits.set(h, fresh)
    else _searchHits.delete(h)
  }
}, SEARCH_WINDOW_MS)

function searchAllowed(userHash) {
  const now    = Date.now()
  const cutoff = now - SEARCH_WINDOW_MS
  const hits   = (_searchHits.get(userHash) || []).filter(t => t > cutoff)
  if (hits.length >= SEARCH_LIMIT) { _searchHits.set(userHash, hits); return false }
  hits.push(now)
  _searchHits.set(userHash, hits)
  return true
}

app.get('/api/conversation/:id/ttl', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const convId = req.params.id
  const { rows: member } = await db.query(
    'SELECT 1 FROM conversation_participants WHERE conversation_id=$1 AND user_hash=$2 LIMIT 1',
    [convId, payload.sub]
  )
  if (!member.length) return reply.code(403).send({ error: 'Nie jesteś uczestnikiem' })

  const { rows } = await db.query(
    'SELECT disappearing_ttl_ms, disappearing_trigger FROM conversations WHERE id=$1', [convId])
  return {
    disappearing_ttl:     Number(rows[0]?.disappearing_ttl_ms || 0),
    disappearing_trigger: rows[0]?.disappearing_trigger || 'read',
    server_now_ms:        Date.now()
  }
})

app.post('/api/conversation/:id/ttl', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const convId = req.params.id
  const { rows: member } = await db.query(
    'SELECT 1 FROM conversation_participants WHERE conversation_id=$1 AND user_hash=$2 LIMIT 1',
    [convId, payload.sub]
  )
  if (!member.length) return reply.code(403).send({ error: 'Nie jesteś uczestnikiem' })

  const ttlMs   = Number(req.body?.disappearingTtlMs ?? req.body?.disappearing_ttl ?? 0)
  const trigger = String(req.body?.disappearingTrigger ?? req.body?.disappearing_trigger ?? 'read')
  if (!Number.isFinite(ttlMs) || ttlMs < 0 || ttlMs > 365 * 24 * 3600 * 1000) {
    return reply.code(400).send({ error: 'Nieprawidłowy czas' })
  }
  if (trigger !== 'read' && trigger !== 'received') {
    return reply.code(400).send({ error: 'Nieprawidłowy wyzwalacz' })
  }

  await db.query(
    `UPDATE conversations SET disappearing_ttl_ms=$2::bigint, disappearing_trigger=$3 WHERE id=$1`,
    [convId, Math.round(ttlMs), trigger]
  )

  const { rows: others } = await db.query(
    'SELECT user_hash FROM conversation_participants WHERE conversation_id=$1 AND user_hash!=$2',
    [convId, payload.sub]
  )
  for (const { user_hash } of others) {
    sendToUser(user_hash, {
      type: 'conversation_ttl_changed', conversationId: convId,
      disappearingTtlMs: Math.round(ttlMs), disappearingTrigger: trigger
    })
  }
  return { ok: true }
})

app.get('/api/users/search', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  const q = (req.query.q || '').trim()
  if (q.length < 2 || q.length > 64) return []

  const isExactHash = /^[a-f0-9]{64}$/.test(q)
  if (!isExactHash && !searchAllowed(payload.sub)) {
    return reply.code(429).send({ error: 'Za dużo wyszukiwań — spróbuj później' })
  }
  const like = '%' + q.replace(/([\\%_])/g, '\\$1') + '%'
  const { rows } = await db.query(
    `SELECT email_hash, display_name, avatar_url, e2e_public_key, key_updated_at
     FROM users WHERE (display_name ILIKE $1 ESCAPE '\\' OR email_hash = $2) AND email_hash != $3
       AND COALESCE(email_block, false) = false AND COALESCE(block_new, false) = false LIMIT 10`,
    [like, q, payload.sub]
  )
  return rows
})

app.get('/api/turn-credentials', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  const ttl = 3600
  const ts = Math.floor(Date.now() / 1000) + ttl
  const username = `${ts}:${payload.sub}`
  const credential = crypto.createHmac('sha1', TURN_SECRET).update(username).digest('base64')
  return {
    urls: [
      `stun:${TURN_HOST}:3478`,
      `turn:${TURN_HOST}:3478?transport=udp`,
      `turn:${TURN_HOST}:3478?transport=tcp`,
      `turns:${TURN_HOST}:5349?transport=tcp`
    ],
    username, credential, ttl
  }
})

app.get('/api/upload-token', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const phoneHash = payload.sub
  const expiry = Date.now() + 5 * 60 * 1000
  const data = `${phoneHash}.${expiry}`
  const hmac = require('crypto')
    .createHmac('sha256', UPLOAD_TOKEN_SECRET)
    .update(data)
    .digest('hex')
  return { token: `${data}.${hmac}`, expires_at: expiry }
})

app.post('/api/upload-voice', { config: { rawBody: true } }, async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  if (getFreeDiskGB() < MIN_FREE_GB) return reply.code(507).send({ error: 'Brak miejsca' })

  require('fs').mkdirSync(VOICE_DIR, { recursive: true })
  const fileName = `${crypto.randomBytes(16).toString('hex')}.ogg`
  const filePath = `${VOICE_DIR}/${fileName}`

  const body = await req.body
  if (!body) return reply.code(400).send({ error: 'Brak danych' })
  if (!spendBudget('v:' + payload.sub, body.length, VOICE_BUDGET_BYTES)) {
    return reply.code(429).send({ error: 'Za dużo głosówek w krótkim czasie — spróbuj później' })
  }
  require('fs').writeFileSync(filePath, body)

  return { ok: true, url: `${PUBLIC_API_URL}/api/voice/${fileName}` }
})

app.get('/api/voice/:filename', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  const filename = String(req.params.filename || '')
  if (!/^[A-Za-z0-9_-]{1,80}\.(ogg|opus|m4a|mp3)$/.test(filename)) {
    return reply.code(400).send({ error: 'Nieprawidłowa nazwa pliku' })
  }
  const filePath = `${VOICE_DIR}/${filename}`
  if (!require('fs').existsSync(filePath)) return reply.code(404).send({ error: 'Nie znaleziono' })
  return reply.sendFile(filename, VOICE_DIR)
})

const FILES_ORIGIN = 'https://files.sinusoide.pl/api/'
const FILES_RELAY_PATH = /^\/api\/files\/(upload\.php|auth\.php|uploads\/(?:avatars|group_avatars)\/[0-9a-f]{32,64}\.(?:jpg|png|webp|bin)|models\/translate\/(?:model|vocab|lex)\.[a-z0-9.]+\.(?:bin|spm)\.gz)$/
const FILES_RELAY_MAX = 52 * 1024 * 1024
const FILES_RELAY_SLOTS = 4
const FILES_RELAY_HEADERS = ['content-type', 'accept', 'x-file-id', 'x-upload-token', 'x-account', 'x-file-auth']
const FILES_RELAY_REPLY_HEADERS = ['content-type', 'content-disposition', 'cache-control', 'etag', 'last-modified']
const RELAY_CACHE_MAX = 128 * 1024 * 1024
const RELAY_CACHE_MS = 15 * 60 * 1000
const relayCache = new Map()
let relayCacheBytes = 0
let filesRelayBusy = 0

function relayClientTag(req) {
  const ip = clientIp(req)
  const exp = String(Date.now() + 120_000)
  const sig = crypto.createHmac('sha256', UPLOAD_TOKEN_SECRET).update(`relay|${ip}|${exp}`).digest('hex')
  return `${ip};${exp};${sig}`
}

function validUploadToken(token, account) {
  if (typeof token !== 'string' || typeof account !== 'string') return false
  const parts = token.split('.')
  if (parts.length !== 3 || parts[0] !== account) return false
  if (!/^[0-9]{1,15}$/.test(parts[1]) || Number(parts[1]) < Date.now()) return false
  const expected = Buffer.from(crypto.createHmac('sha256', UPLOAD_TOKEN_SECRET)
    .update(`${parts[0]}.${parts[1]}`).digest('hex'))
  const given = Buffer.from(parts[2])
  return expected.length === given.length && crypto.timingSafeEqual(expected, given)
}

function relayCacheKey(h) {
  const id = h['x-file-id'], acc = h['x-account'], auth = h['x-file-auth']
  if (![id, acc, auth].every(v => typeof v === 'string' && v.length > 0)) return null
  return crypto.createHash('sha256').update(`${id}|${acc}|${auth}`).digest('hex')
}

function relayCacheSweep() {
  const now = Date.now()
  for (const [k, e] of relayCache) if (e.until <= now) relayCacheDrop(k)
}
setInterval(relayCacheSweep, 60_000).unref()

function relayCacheDrop(key) {
  const e = relayCache.get(key)
  if (!e) return
  relayCache.delete(key)
  relayCacheBytes -= e.body.length
}

function relayCachePut(key, headers, body) {
  relayCacheDrop(key)
  if (body.length > RELAY_CACHE_MAX / 4) return
  relayCacheSweep()
  while (relayCacheBytes + body.length > RELAY_CACHE_MAX && relayCache.size > 0) {
    relayCacheDrop(relayCache.keys().next().value)
  }
  relayCache.set(key, { until: Date.now() + RELAY_CACHE_MS, headers, body })
  relayCacheBytes += body.length
}

app.register(async function (relay) {
  relay.removeAllContentTypeParsers()
  relay.addContentTypeParser('*', { parseAs: 'buffer', bodyLimit: FILES_RELAY_MAX }, (req, body, done) => done(null, body))

  relay.route({
    method: ['GET', 'POST'],
    url: '/api/files/*',
    bodyLimit: FILES_RELAY_MAX,
    onRequest: (req, reply, done) => {
      if (filesRelayBusy >= FILES_RELAY_SLOTS) {
        reply.code(503).send({ success: false, error: 'Serwer plików jest zajęty — spróbuj za chwilę' })
        return
      }
      filesRelayBusy++
      reply.raw.once('close', () => { filesRelayBusy-- })
      done()
    },
    handler: async (req, reply) => {
      const q = req.url.indexOf('?')
      const path = q < 0 ? req.url : req.url.slice(0, q)
      const query = q < 0 ? '' : req.url.slice(q)
      const m = path.match(FILES_RELAY_PATH)
      if (!m) return reply.code(404).send({ success: false, error: 'Nie znaleziono' })

      const model = m[1].startsWith('models/')
      if (model && req.method !== 'GET') return reply.code(405).send({ success: false, error: 'Tylko GET' })
      const download = model || (m[1] === 'upload.php' && /[?&]action=download(?:&|$)/.test(query))
      const cacheKey = download ? relayCacheKey(req.headers) : null
      if (cacheKey) {
        const hit = relayCache.get(cacheKey)
        if (hit && hit.until > Date.now() && validUploadToken(req.headers['x-upload-token'], req.headers['x-account'])) {
          return reply.code(200).headers(hit.headers).send(hit.body)
        }
      }

      try {
        const headers = { 'user-agent': 'SinusChat-Relay', 'x-sinuschat-client': relayClientTag(req) }
        for (const h of FILES_RELAY_HEADERS) if (typeof req.headers[h] === 'string') headers[h] = req.headers[h]
        const res = await fetch(FILES_ORIGIN + m[1] + query, {
          method: req.method,
          headers,
          body: req.method === 'POST' ? (Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0)) : undefined,
          redirect: 'manual',
          signal: AbortSignal.timeout(download ? 900_000 : 180_000)
        })
        const out = {}
        for (const h of FILES_RELAY_REPLY_HEADERS) {
          const v = res.headers.get(h)
          if (v) out[h] = v
        }
        const length = Number(res.headers.get('content-length') || 0)
        if (download && res.status === 200 && res.body && (!cacheKey || !length || length > RELAY_CACHE_MAX / 4)) {
          if (length > 0) out['content-length'] = String(length)
          return reply.code(res.status).headers(out).send(require('stream').Readable.fromWeb(res.body))
        }
        const body = Buffer.from(await res.arrayBuffer())
        if (cacheKey && res.status === 200 && body.length > 0) relayCachePut(cacheKey, out, body)
        return reply.code(res.status).headers(out).send(body)
      } catch (e) {
        console.warn('[FILES] przekaźnik:', e.message)
        return reply.code(502).send({ success: false, error: 'Serwer plików nie odpowiada' })
      }
    }
  })
})

app.post('/api/groups/create', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const { name, description, members, avatarColor, avatarUrl } = req.body || {}
  if (!name || !Array.isArray(members) || !members.length) return reply.code(400).send({ error: 'Brak nazwy lub członków' })
  if (new Set(members.map(String)).size >= MAX_GROUP_MEMBERS) {
    return reply.code(409).send({ error: 'Za dużo członków', code: 'group_full' })
  }
  const groupAvatar = cleanGroupAvatarUrl(avatarUrl) || null
  const kind = ['community', 'group', 'custom'].includes(req.body?.kind) ? req.body.kind : null

  const groupId = 'g_' + require('crypto').randomUUID()
  const now = Date.now()

  await db.query('INSERT INTO conversations(id) VALUES($1) ON CONFLICT DO NOTHING', [groupId])
  await db.query(
    'INSERT INTO groups(id,name,description,avatar_color,created_by,created_at,avatar_url,kind) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
    [groupId, name, description || '', avatarColor || '#5288C1', payload.sub, now, groupAvatar, kind]
  )

  const aks = (req.body?.aks && typeof req.body.aks === 'object') ? req.body.aks : {}
  const invited = []
  for (const hash of [...new Set(members)]) {
    if (hash === payload.sub) continue
    if (await isBlockedBy(hash, payload.sub)) continue
    if (!(await knownContact(await newChatsBlocked(hash), hash, payload.sub, aks[hash]))) continue
    invited.push(hash)
  }
  if (!invited.length) return reply.code(403).send({ error: 'Nie można dodać tych osób do grupy' })

  const allMembers = [...new Set([payload.sub, ...invited])]
  for (const hash of allMembers) {
    await db.query(
      'INSERT INTO conversation_participants(conversation_id,user_hash) VALUES($1,$2) ON CONFLICT DO NOTHING',
      [groupId, hash]
    )
  }
  touchGroupDay(groupId)

  await db.query(
    'UPDATE conversation_participants SET is_admin=true WHERE conversation_id=$1 AND user_hash=$2',
    [groupId, payload.sub]
  )

  const groupInfo = { type: 'group_created', groupId, name, description: description||'', avatarColor: avatarColor||'#5288C1', createdBy: payload.sub, members: allMembers }
  for (const hash of allMembers) {
    if (hash !== payload.sub) sendToUser(hash, groupInfo)
  }

  return { ok: true, groupId, name, members: allMembers }
})

app.get('/api/groups/:groupId', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const { groupId } = req.params
  const { rows: g } = await db.query('SELECT * FROM groups WHERE id=$1', [groupId])
  if (!g.length) return reply.code(404).send({ error: 'Nie znaleziono' })

  const { rows: members } = await db.query(
    'SELECT cp.user_hash, cp.is_admin, u.display_name, u.avatar_url, u.avatar_color, u.activity_hidden FROM conversation_participants cp LEFT JOIN users u ON u.email_hash=cp.user_hash WHERE cp.conversation_id=$1',
    [groupId]
  )
  if (!members.find(m => m.user_hash === payload.sub)) return reply.code(403).send({ error: 'Nie jesteś członkiem' })
  const signalSet = await signalCapable(members.map(m => m.user_hash))
  for (const m of members) m.signal = signalSet.has(m.user_hash)
  const now = Date.now()
  const activeCount = members.filter(m =>
    m.user_hash === payload.sub ||
    (m.activity_hidden !== true && isOnlineNow(m.user_hash))
  ).length
  const { invite_code, invite_created_at, ...groupRow } = g[0]
  const meAdmin = members.some(m => m.user_hash === payload.sub && m.is_admin)
  return {
    ...groupRow,
    is_community: groupIsCommunity(g[0]),
    has_invite_link: !!invite_code,
    ...(meAdmin ? { invite_code: invite_code || null } : {}),
    members, activeCount, server_now_ms: now
  }
})

app.post('/api/groups/:groupId/add', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const { groupId } = req.params
  const { userHash } = req.body || {}
  if (!userHash) return reply.code(400).send({ error: 'Brak userHash' })

  const { rows: check } = await db.query(
    'SELECT 1 FROM conversation_participants WHERE conversation_id=$1 AND user_hash=$2',
    [groupId, payload.sub]
  )
  if (!check.length) return reply.code(403).send({ error: 'Nie jesteś członkiem' })
  if (!(await groupAllows(groupId, payload.sub, 'addMembers'))) {
    return reply.code(403).send({ error: 'Nie możesz dodawać członków', code: 'group_add_forbidden' })
  }

  if (await isGroupBanned(groupId, String(userHash))) {
    const { rows: adm } = await db.query(
      'SELECT is_admin FROM conversation_participants WHERE conversation_id=$1 AND user_hash=$2', [groupId, payload.sub])
    if (!adm[0]?.is_admin) return reply.code(403).send({ error: 'Tę osobę usunął administrator', code: 'group_member_banned' })
    await db.query('DELETE FROM group_bans WHERE group_id=$1 AND user_hash=$2', [groupId, String(userHash)]).catch(() => {})
  }

  if (await isBlockedBy(userHash, payload.sub)) {
    return reply.code(403).send({ error: 'Nie można dodać tej osoby do grupy' })
  }
  if (!(await knownContact(await newChatsBlocked(String(userHash)), String(userHash), payload.sub, req.body?.ak))) {
    return reply.code(403).send({ error: 'Nie można dodać tej osoby do grupy', code: 'block_new' })
  }

  const { rows: cnt } = await db.query('SELECT COUNT(*)::int AS n FROM conversation_participants WHERE conversation_id=$1', [groupId])
  if ((cnt[0]?.n || 0) >= MAX_GROUP_MEMBERS) {
    return reply.code(409).send({ error: 'Grupa jest pełna', code: 'group_full' })
  }

  const now = Date.now()
  await db.query('INSERT INTO conversation_participants(conversation_id,user_hash) VALUES($1,$2) ON CONFLICT DO NOTHING', [groupId, userHash])

  const { rows: g } = await db.query('SELECT * FROM groups WHERE id=$1', [groupId])
  const { rows: members } = await db.query('SELECT user_hash FROM conversation_participants WHERE conversation_id=$1', [groupId])
  const memberHashes = members.map(m => m.user_hash)

  sendToUser(userHash, { type: 'group_added', groupId, name: g[0]?.name, avatarColor: g[0]?.avatar_color, members: memberHashes })
  for (const hash of memberHashes) {
    if (hash !== userHash) sendToUser(hash, { type: 'group_member_added', groupId, newMember: userHash })
  }
  return { ok: true }
})

app.post('/api/groups/:groupId/kick', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  const { groupId } = req.params
  const { userHash } = req.body || {}
  if (!userHash) return reply.code(400).send({ error: 'Brak userHash' })

  const { rows: me } = await db.query(
    'SELECT is_admin FROM conversation_participants WHERE conversation_id=$1 AND user_hash=$2',
    [groupId, payload.sub])
  if (!me.length || !me[0].is_admin) return reply.code(403).send({ error: 'Tylko administrator' })
  const { rows: g } = await db.query('SELECT created_by FROM groups WHERE id=$1', [groupId])
  if (g[0]?.created_by === userHash) return reply.code(400).send({ error: 'Nie można wyrzucić twórcy' })

  await db.query('DELETE FROM conversation_participants WHERE conversation_id=$1 AND user_hash=$2', [groupId, userHash])
  await db.query('DELETE FROM conversation_meta WHERE conversation_id=$1 AND user_hash=$2', [groupId, userHash])
  await db.query('INSERT INTO group_bans(group_id,user_hash,created_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',
    [groupId, userHash, Date.now()]).catch(() => {})

  sendToUser(userHash, { type: 'group_kicked', groupId })
  const { rows: members } = await db.query('SELECT user_hash FROM conversation_participants WHERE conversation_id=$1', [groupId])
  for (const m of members) sendToUser(m.user_hash, { type: 'group_member_removed', groupId, removed: userHash })
  return { ok: true }
})

app.post('/api/groups/:groupId/admin', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  const { groupId } = req.params
  const { userHash, makeAdmin } = req.body || {}
  if (!userHash) return reply.code(400).send({ error: 'Brak userHash' })

  const { rows: me } = await db.query(
    'SELECT is_admin FROM conversation_participants WHERE conversation_id=$1 AND user_hash=$2',
    [groupId, payload.sub])
  if (!me.length || !me[0].is_admin) return reply.code(403).send({ error: 'Tylko administrator' })

  await db.query('UPDATE conversation_participants SET is_admin=$3 WHERE conversation_id=$1 AND user_hash=$2',
    [groupId, userHash, !!makeAdmin])

  const { rows: members } = await db.query('SELECT user_hash FROM conversation_participants WHERE conversation_id=$1', [groupId])
  for (const m of members) sendToUser(m.user_hash, { type: 'group_admin_changed', groupId, userHash, isAdmin: !!makeAdmin })
  return { ok: true }
})

app.post('/api/groups/:groupId/settings', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  const { groupId } = req.params
  const { disappearingTtlMs, perms } = req.body || {}

  const { rows: me } = await db.query(
    'SELECT is_admin FROM conversation_participants WHERE conversation_id=$1 AND user_hash=$2',
    [groupId, payload.sub])
  if (!me.length) return reply.code(403).send({ error: 'Nie jestes czlonkiem' })
  if (perms && typeof perms === 'object' && !me[0].is_admin) {
    return reply.code(403).send({ error: 'Tylko administrator' })
  }
  if (typeof disappearingTtlMs === 'number' && !(await groupAllows(groupId, payload.sub, 'editSettings'))) {
    return reply.code(403).send({ error: 'Nie mozesz zmieniac ustawien grupy', code: 'group_edit_forbidden' })
  }

  if (typeof disappearingTtlMs === 'number') {
    await db.query('UPDATE groups SET disappearing_ttl_ms=$2 WHERE id=$1', [groupId, disappearingTtlMs])
  }
  if (perms && typeof perms === 'object') {
    await db.query('UPDATE groups SET perms=$2 WHERE id=$1', [groupId, JSON.stringify(perms)])
  }
  const { rows: members } = await db.query('SELECT user_hash FROM conversation_participants WHERE conversation_id=$1', [groupId])
  for (const m of members) sendToUser(m.user_hash, { type: 'group_settings_changed', groupId, disappearingTtlMs, perms })
  return { ok: true }
})

app.post('/api/groups/:groupId/leave', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const { groupId } = req.params
  const silent = req.body?.silent === true
  if (!(await isParticipant(groupId, payload.sub))) return { ok: true }
  await db.query('DELETE FROM conversation_participants WHERE conversation_id=$1 AND user_hash=$2', [groupId, payload.sub])
  await db.query('DELETE FROM conversation_meta WHERE conversation_id=$1 AND user_hash=$2', [groupId, payload.sub])

  const { rows: remaining } = await db.query('SELECT user_hash FROM conversation_participants WHERE conversation_id=$1', [groupId])
  for (const { user_hash } of remaining) {
    sendToUser(user_hash, { type: 'group_member_left', groupId, userHash: payload.sub, silent })
  }
  if (!remaining.length) {
    await db.query('DELETE FROM groups WHERE id=$1', [groupId])
    await db.query('DELETE FROM conversations WHERE id=$1', [groupId])
    await db.query('DELETE FROM conversation_meta WHERE conversation_id=$1', [groupId])
    await db.query('DELETE FROM group_bans WHERE group_id=$1', [groupId]).catch(() => {})
  }
  return { ok: true }
})

app.post('/api/groups/:groupId/update', async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const { groupId } = req.params
  const { name, description, avatarColor } = req.body || {}
  const groupAvatar = cleanGroupAvatarUrl(req.body?.avatarUrl)

  const { rows: check } = await db.query(
    'SELECT 1 FROM conversation_participants WHERE conversation_id=$1 AND user_hash=$2',
    [groupId, payload.sub]
  )
  if (!check.length) return reply.code(403).send({ error: 'Nie jesteś członkiem' })
  if (!(await groupAllows(groupId, payload.sub, 'editSettings'))) {
    return reply.code(403).send({ error: 'Nie możesz zmieniać ustawień grupy', code: 'group_edit_forbidden' })
  }

  await db.query(
    `UPDATE groups SET name=COALESCE($2,name), description=COALESCE($3,description),
       avatar_color=COALESCE($4,avatar_color),
       avatar_url = CASE WHEN $5::text = '' THEN NULL ELSE COALESCE($5::text, avatar_url) END
     WHERE id=$1`,
    [groupId, name, description, avatarColor, groupAvatar === undefined ? null : groupAvatar]
  )

  const { rows: members } = await db.query('SELECT user_hash FROM conversation_participants WHERE conversation_id=$1', [groupId])
  for (const { user_hash } of members) {
    if (user_hash !== payload.sub) sendToUser(user_hash, { type: 'group_updated', groupId, name, description, avatarColor, avatarUrl: groupAvatar, by: payload.sub })
  }
  return { ok: true }
})

const GROUP_INVITE_RE = /^grp_[A-Za-z0-9_-]{20,40}$/
const MAX_GROUP_MEMBERS = 1000

function groupIsCommunity(g) {
  if (!g) return false
  if (g.kind) return g.kind === 'community'
  let perms = g.perms || {}
  if (typeof perms === 'string') { try { perms = JSON.parse(perms) } catch (_) { perms = {} } }
  return perms.sendMessages === false
}

async function requireGroupAdmin(req, reply) {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) { reply.code(401).send({ error: 'Brak autoryzacji' }); return null }
  if (payload.kicked) { reply.code(409).send({ error: 'device_kicked', kicked: true }); return null }
  const { groupId } = req.params
  const { rows } = await db.query(
    `SELECT g.*, cp.is_admin FROM groups g
       JOIN conversation_participants cp ON cp.conversation_id = g.id AND cp.user_hash = $2
      WHERE g.id = $1`, [groupId, payload.sub])
  if (!rows.length) { reply.code(403).send({ error: 'Nie jesteś członkiem' }); return null }
  if (!rows[0].is_admin) { reply.code(403).send({ error: 'Tylko administrator', code: 'not_admin' }); return null }
  return { payload, group: rows[0] }
}

app.post('/api/groups/:groupId/invite', { config: { rateLimit: { max: 30, timeWindow: '1 hour' } } }, async (req, reply) => {
  const ctx = await requireGroupAdmin(req, reply)
  if (!ctx) return
  const { group } = ctx
  if (!groupIsCommunity(group)) return reply.code(400).send({ error: 'Link jest dostępny tylko dla społeczności', code: 'not_community' })

  let code = group.invite_code
  let createdAt = Number(group.invite_created_at) || null
  if (!code || req.body?.reset === true) {
    code = 'grp_' + crypto.randomBytes(18).toString('base64url')
    createdAt = Date.now()
    await db.query('UPDATE groups SET invite_code=$2, invite_created_at=$3 WHERE id=$1', [group.id, code, createdAt])
  }
  const { rows: cnt } = await db.query('SELECT COUNT(*)::int AS n FROM conversation_participants WHERE conversation_id=$1', [group.id])
  return { ok: true, code, createdAt, memberCount: cnt[0]?.n || 0 }
})

app.post('/api/groups/:groupId/invite/revoke', { config: { rateLimit: { max: 30, timeWindow: '1 hour' } } }, async (req, reply) => {
  const ctx = await requireGroupAdmin(req, reply)
  if (!ctx) return
  await db.query('UPDATE groups SET invite_code=NULL, invite_created_at=NULL WHERE id=$1', [ctx.group.id])
  return { ok: true }
})

async function findGroupByInvite(code) {
  if (!GROUP_INVITE_RE.test(code)) return null
  const { rows } = await db.query('SELECT * FROM groups WHERE invite_code=$1', [code])
  return rows[0] && groupIsCommunity(rows[0]) ? rows[0] : null
}

app.get('/api/group-invite/:code', { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } }, async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const g = await findGroupByInvite(String(req.params.code || ''))
  if (!g) return reply.code(404).send({ error: 'Link nie działa', code: 'group_invite_invalid' })
  if (await isGroupBanned(g.id, payload.sub)) return reply.code(404).send({ error: 'Link nie działa', code: 'group_invite_invalid' })
  const { rows: members } = await db.query('SELECT user_hash, is_admin FROM conversation_participants WHERE conversation_id=$1', [g.id])
  const alreadyMember = members.some(m => m.user_hash === payload.sub)
  return {
    ok: true,
    name: g.name,
    description: g.description || '',
    avatarColor: g.avatar_color || '#5288C1',
    avatarUrl: g.avatar_url || null,
    memberCount: members.length,
    alreadyMember,
    groupId: alreadyMember ? g.id : null
  }
})

app.post('/api/group-invite/join', { config: { rateLimit: { max: 20, timeWindow: '1 hour' } } }, async (req, reply) => {
  const auth = req.headers.authorization?.replace('Bearer ', '')
  const payload = await verifyActiveDevice(auth)
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })

  const g = await findGroupByInvite(String(req.body?.code || ''))
  if (!g) return reply.code(404).send({ error: 'Link nie działa', code: 'group_invite_invalid' })

  const { rows: members } = await db.query('SELECT user_hash, is_admin FROM conversation_participants WHERE conversation_id=$1', [g.id])
  const result = { ok: true, groupId: g.id, name: g.name, avatarColor: g.avatar_color || '#5288C1', avatarUrl: g.avatar_url || null }
  if (members.some(m => m.user_hash === payload.sub)) return { ...result, alreadyMember: true }

  for (const m of members) {
    if (m.is_admin && await isBlockedBy(m.user_hash, payload.sub)) {
      return reply.code(404).send({ error: 'Link nie działa', code: 'group_invite_invalid' })
    }
  }
  if (await isGroupBanned(g.id, payload.sub)) {
    return reply.code(404).send({ error: 'Link nie działa', code: 'group_invite_invalid' })
  }
  if (members.length >= MAX_GROUP_MEMBERS) return reply.code(409).send({ error: 'Społeczność jest pełna', code: 'group_full' })

  const now = Date.now()
  await db.query('INSERT INTO conversation_participants(conversation_id,user_hash) VALUES($1,$2) ON CONFLICT DO NOTHING', [g.id, payload.sub])

  const memberHashes = [...members.map(m => m.user_hash), payload.sub]
  sendToUser(payload.sub, { type: 'group_added', groupId: g.id, name: g.name, avatarColor: g.avatar_color, members: memberHashes, selfJoin: true })
  for (const m of members) sendToUser(m.user_hash, { type: 'group_member_added', groupId: g.id, newMember: payload.sub })
  return result
})

app.register(async function (app) {
  app.get('/ws', { websocket: true }, (socket, req) => {
    const ip = clientIp(req) || 'unknown'
    const cur = wsConnByIp.get(ip) || 0
    if (cur >= WS_CONN_PER_IP) {
      try { socket.close(1013, 'Za dużo połączeń') } catch (_) {}
      return
    }
    wsConnByIp.set(ip, cur + 1)

    let userHash = null
    let msgCount = 0
    let sigCount = 0
    let windowStart = Date.now()

  const onMessage = async (raw) => {
    try {
      const now = Date.now()
      if (now - windowStart > WS_MSG_WINDOW_MS) { windowStart = now; msgCount = 0; sigCount = 0 }

      const text = (raw && raw.data !== undefined) ? raw.data.toString() : raw.toString()
      if (text.length > 256 * 1024) return
      const msg = JSON.parse(text)
      if (msg && (msg.type === 'gcall_signal' || msg.type === 'gcall_ping')) {
        if (++sigCount > GCALL_SIGNAL_LIMIT) return
      } else if (++msgCount > WS_MSG_LIMIT) return

      if (msg.type === 'auth') {
        const payload = verifyToken(msg.token)
        if (!payload) { socket.send(JSON.stringify({ type: 'auth_error' })); return }
        userHash = payload.sub

        try {
          const { rows } = await db.query(
            'SELECT active_device_id FROM users WHERE email_hash=$1', [userHash])
          const active = rows[0]?.active_device_id
          if (active && active !== payload.deviceId) {
            socket.send(JSON.stringify({ type: 'device_kicked' }))
            try { socket.close() } catch (_) {}
            return
          }
        } catch (_) {}
        socket.deviceId = payload.deviceId || null

        const prev = connections.get(userHash)
        if (prev && prev !== socket && prev.readyState === 1) {
          try { prev.send(JSON.stringify({ type: 'device_kicked' })) } catch (_) {}
          try { prev.close() } catch (_) {}
        }

        connections.set(userHash, socket)
        socket.callAckSupported = Array.isArray(msg.caps) && msg.caps.includes('call_ack')
        socket.gcallAckSupported = Array.isArray(msg.caps) && msg.caps.includes('gcall_ack')
        if (Array.isArray(msg.caps) && msg.caps.includes('call_e2e')) {
          db.query('UPDATE users SET call_e2e=true WHERE email_hash=$1 AND call_e2e IS NOT TRUE', [userHash]).catch(() => {})
        }
        socket.send(JSON.stringify({ type: 'auth_ok', hash: userHash, userHash }))
        loadNtfyTopic(userHash)

        gcallSendActive(userHash).catch(() => {})

        const pending = pendingCallOffers.get(userHash)
        if (pending) {
          if (!socket.callAckSupported) pendingCallOffers.delete(userHash)
          if (Date.now() - pending.ts < 40_000) {
            const { ts, ...offer } = pending
            socket.send(JSON.stringify(offer))
          }
        }
        return
      }

      if (msg.type === 'call_offer_ack') {
        const p = pendingCallOffers.get(userHash)
        if (p && p.conversationId === msg.conversationId) pendingCallOffers.delete(userHash)
        return
      }

      if (!userHash) return

      if (msg.type === 'ping') { socket.send(JSON.stringify({ type: 'pong' })); return }

      if (typeof msg.type === 'string' && msg.type.startsWith('gcall_')) {
        const gid = String(msg.conversationId || '')
        if (!gid.startsWith('g_')) return
        const call = groupCalls.get(gid)
        if (msg.type === 'gcall_ack') { pendingGcallRings.delete(userHash + '|' + gid); return }
        if (msg.type === 'gcall_ping') {
          if (call && call.members.has(userHash)) { call.members.set(userHash, Date.now()); return }
          if (await isParticipant(gid, userHash)) socket.send(JSON.stringify(gcallState(gid)))
          return
        }
        if (msg.type === 'gcall_signal') {
          const to = String(msg.to || '')
          if (!call || !call.members.has(userHash) || !call.members.has(to) || to === userHash) return
          if (typeof msg.payload !== 'string' || msg.payload.length > 96 * 1024) return
          call.members.set(userHash, Date.now())
          sendToUser(to, { type: 'gcall_signal', conversationId: gid, from: userHash, payload: msg.payload })
          return
        }
        if (!(await isParticipant(gid, userHash))) return
        if (msg.type === 'gcall_query') { socket.send(JSON.stringify(gcallState(gid))); return }
        if (msg.type === 'gcall_leave') {
          if (!call || !call.members.delete(userHash)) return
          if (call.members.size === 0) groupCalls.delete(gid)
          await gcallBroadcast(gid)
          return
        }
        if (msg.type === 'gcall_start' || msg.type === 'gcall_join') {
          if (call) {
            call.members.set(userHash, Date.now())
            await gcallBroadcast(gid)
            return
          }
          if (msg.type === 'gcall_join') { socket.send(JSON.stringify(gcallState(gid))); return }
          if (!(await groupAllows(gid, userHash, 'callGroup'))) {
            socket.send(JSON.stringify({ type: 'gcall_error', conversationId: gid, reason: 'group_call_forbidden' }))
            return
          }
          const fresh = {
            kind: msg.kind === 'video' ? 'video' : 'audio',
            startedBy: userHash, startedAt: Date.now(), members: new Map([[userHash, Date.now()]])
          }
          groupCalls.set(gid, fresh)
          await gcallBroadcast(gid)
          try {
            const { rows } = await db.query(
              'SELECT user_hash FROM conversation_participants WHERE conversation_id=$1 AND user_hash!=$2', [gid, userHash])
            for (const { user_hash } of rows) {
              if (await isBlockedBy(user_hash, userHash)) continue
              const target = connections.get(user_hash)
              if (!target) { wakeUser(user_hash, 'call', { title: 'Rozmowa grupowa' }).catch(() => {}); continue }
              if (!target.gcallAckSupported) continue
              const key = user_hash + '|' + gid
              pendingGcallRings.set(key, Date.now())
              setTimeout(() => {
                if (!pendingGcallRings.delete(key)) return
                const c = groupCalls.get(gid)
                if (c !== fresh || c.members.has(user_hash)) return
                if (connections.get(user_hash) === target) {
                  connections.delete(user_hash)
                  try { target.terminate() } catch (_) {}
                }
                wakeUser(user_hash, 'call', { title: 'Rozmowa grupowa' }).catch(() => {})
              }, CALL_ACK_TIMEOUT_MS)
            }
          } catch (_) {}
          return
        }
        return
      }

      if (['call_offer','call_answer','call_ice','call_reject','call_end','call_reoffer','call_reanswer','call_screen'].includes(msg.type)) {
        const { conversationId: callConvId } = msg
        if (callConvId) {
          try {
            if (!(await canUseConversation(callConvId, userHash))) return

            if (msg.type === 'call_offer' && String(callConvId).startsWith('g_') &&
                !(await groupAllows(callConvId, userHash, 'callGroup'))) {
              sendToUser(userHash, { type: 'call_reject', conversationId: callConvId, reason: 'group_call_forbidden' })
              return
            }

            if (!String(callConvId).startsWith('g_')) {
              const endKey = `${callConvId}|${userHash}`
              if (msg.type === 'call_end' || msg.type === 'call_reject') endedCalls.set(endKey, Date.now())
              else if (msg.type === 'call_offer') endedCalls.delete(endKey)
              if (msg.type === 'call_answer') {
                const parts = String(callConvId).split('_')
                const caller = parts[0] === userHash ? parts[1] : parts[0]
                const ended = endedCalls.get(`${callConvId}|${caller}`)
                if (ended && Date.now() - ended < 120_000) {
                  sendToUser(userHash, { type: 'call_end', conversationId: callConvId, fromHash: caller, senderHash: caller, reason: 'gone' })
                  return
                }
              }
            }

            let rows
            if (String(callConvId).startsWith('g_')) {
              rows = (await db.query(
                'SELECT user_hash FROM conversation_participants WHERE conversation_id=$1 AND user_hash!=$2',
                [callConvId, userHash])).rows
            } else {
              const parts = String(callConvId).split('_')
              rows = [{ user_hash: parts[0] === userHash ? parts[1] : parts[0] }]
            }
            for (const { user_hash } of rows) {
              if (msg.type === 'call_offer' && !String(callConvId).startsWith('g_') &&
                  !lookupAllowed('d', userHash, user_hash, DIRECT_TARGET_LIMIT)) {
                sendToUser(userHash, { type: 'call_reject', conversationId: callConvId, reason: 'limit' })
                continue
              }
              if (!String(callConvId).startsWith('g_') && !(await userExists(user_hash))) {
                if (msg.type === 'call_offer') {
                  sendToUser(userHash, { type: 'call_reject', conversationId: callConvId, reason: 'account_deleted' })
                }
                continue
              }
              if (await isBlockedBy(user_hash, userHash)) continue

              if (msg.type === 'call_end' || msg.type === 'call_reject') {
                const p = pendingCallOffers.get(user_hash)
                if (p && p.conversationId === callConvId && p.fromHash === userHash) pendingCallOffers.delete(user_hash)
              }

              const relayMsg = { ...msg, fromHash: userHash, senderHash: userHash }
              const target = connections.get(user_hash)
              const live = sendToUser(user_hash, relayMsg)
              if (msg.type === 'call_end') {
                sendToUser(user_hash, { type: 'call_cancel', kind: 'call_end', conversationId: callConvId, fromHash: userHash, senderHash: userHash })
              }

              if (msg.type !== 'call_offer') continue
              pendingCallOffers.set(user_hash, { ...msg, fromHash: userHash, ts: Date.now() })

              if (!live) {
                wakeUser(user_hash, 'call', { title: 'Połączenie przychodzące' }).catch(() => {})
              } else if (target && target.callAckSupported) {
                setTimeout(() => {
                  const p = pendingCallOffers.get(user_hash)
                  if (!p || p.conversationId !== callConvId || p.fromHash !== userHash) return
                  if (connections.get(user_hash) === target) {
                    connections.delete(user_hash)
                    try { target.terminate() } catch (_) {}
                  }
                  wakeUser(user_hash, 'call', { title: 'Połączenie przychodzące' }).catch(() => {})
                }, CALL_ACK_TIMEOUT_MS)
              } else {
                pendingCallOffers.delete(user_hash)
              }
            }
          } catch(_) {}
        }
        return
      }

      if (msg.type === 'typing' || msg.type === 'typing_stop') {
        const relayType = msg.type
        if (!(await canUseConversation(msg.conversationId, userHash))) return
        if (msg.recipientHash) {
          const rcpt = String(msg.recipientHash)
          const ok = String(msg.conversationId).startsWith('g_')
            ? await isParticipant(msg.conversationId, rcpt)
            : (msg.conversationId === canonicalPair(userHash, rcpt) || await isParticipant(msg.conversationId, rcpt))
          if (!ok) return
        }
        if (msg.recipientHash) {
          if (await isBlockedBy(msg.recipientHash, userHash)) return
          sendToUser(msg.recipientHash, { type: relayType, conversationId: msg.conversationId, senderHash: userHash })
        } else if (msg.conversationId) {
          try {
            const { rows } = await db.query(
              'SELECT user_hash FROM conversation_participants WHERE conversation_id=$1 AND user_hash!=$2 LIMIT 20',
              [msg.conversationId, userHash]
            )
            for (const { user_hash } of rows) {
              if (await isBlockedBy(user_hash, userHash)) continue
              sendToUser(user_hash, { type: relayType, conversationId: msg.conversationId, senderHash: userHash })
            }
          } catch(_) {}
        }
        return
      }

      if (msg.type === 'ack') {
        const { conversationId, deliveredUpTo, readUpTo } = msg
        if (conversationId && !String(conversationId).startsWith('g_') && await canUseConversation(conversationId, userHash)) {
          await relayDirectAck(userHash, conversationId, deliveredUpTo, readUpTo)
        }
        return
      }

      if (['group_created','group_added','group_member_added','group_member_left','group_updated'].includes(msg.type)) {
        return
      }

    } catch(_) {}
  }

    socket.on('message', onMessage)
    socket.heartbeatAlive = true
    socket.on('pong', () => { socket.heartbeatAlive = true })
    allSockets.add(socket)
    socket.on('close', () => {
      allSockets.delete(socket)
      if (userHash && connections.get(userHash) === socket) connections.delete(userHash)
      const n = (wsConnByIp.get(ip) || 1) - 1
      if (n <= 0) wsConnByIp.delete(ip); else wsConnByIp.set(ip, n)
    })
  })
})

setInterval(async () => {
  try {
    const cutoff30d = Date.now() - 30 * 24 * 60 * 60 * 1000
    const { rowCount } = await db.query(
      'DELETE FROM messages WHERE delivered_at IS NULL AND created_at < $1::bigint',
      [cutoff30d]
    )
    if (rowCount > 0) console.log('[cleanup] Usunięto', rowCount, 'nieodebranych wiadomości')

    await db.query(
      'DELETE FROM messages WHERE delivered_at IS NOT NULL AND delivered_at < $1::bigint',
      [Date.now() - 60 * 60 * 1000]
    )

    const groupCutoffDay = Math.floor(Date.now() / 86400000) - 548
    await db.query(`
      DELETE FROM conversation_participants cp
      USING groups g
      WHERE g.id = cp.conversation_id
        AND g.last_active_day IS NOT NULL
        AND g.last_active_day < $1::integer
    `, [groupCutoffDay])
  } catch(e) { console.error('[cleanup]', e.message) }
}, 60 * 60 * 1000)

setInterval(() => {
  const freeGB = getFreeDiskGB()
  if (freeGB < 10) console.warn(`[DISK WARNING] Wolne miejsce: ${freeGB}GB!`)
  if (freeGB < 5)  console.error(`[DISK CRITICAL] Tylko ${freeGB}GB wolnego!`)
}, 6 * 60 * 60 * 1000)

schemaReady.finally(() => {
  app.listen({ port: PORT, host: '127.0.0.1' }, (err) => {
    if (err) { console.error(err); process.exit(1) }
    console.log(`SinusChat server running on port ${PORT}`)
  })
})
