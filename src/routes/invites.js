// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

'use strict'

const { randomBase64Url } = require('../crypto')
const { db } = require('../db')
const {
  canonicalPair, DAY_MS, isBlockedBy, newChatsBlocked, perMinute, sendToUser
} = require('../common')
const { requireAuth } = require('./auth')

const INVITE_ONCE_TTL_MS = 7 * DAY_MS
const INVITE_MAX_ACTIVE_ONCE = 20
const INVITE_CODE_RE = /^inv_[A-Za-z0-9_-]{20,40}$/
const INVALID = { error: 'Nieprawidłowe zaproszenie', code: 'invite_invalid' }
const OWN = { error: 'To Twoje zaproszenie', code: 'invite_own' }
const DISABLED = { error: 'Zaproszenie zostało wyłączone', code: 'invite_revoked' }
const USED = { error: 'Zaproszenie zostało już wykorzystane', code: 'invite_used' }
const EXPIRED = { error: 'Zaproszenie wygasło', code: 'invite_expired' }
const OWNER_GONE = { error: 'Konto już nie istnieje', code: 'invite_owner_gone' }

function newInviteCode() {
  return 'inv_' + randomBase64Url(16)
}

function inviteJson(row) {
  return {
    invite: {
      code: row.code, kind: row.kind,
      createdAt: Number(row.created_at),
      expiresAt: row.expires_at ? Number(row.expires_at) : null,
      useCount: Number(row.use_count || 0)
    }
  }
}

async function multiInvite(myHash, reset, now) {
  if (reset) {
    await db.query(
      "UPDATE contact_invites SET revoked=true WHERE owner_hash=$1 AND kind='multi' AND revoked=false", [myHash])
  } else {
    const { rows } = await db.query(
      `SELECT * FROM contact_invites WHERE owner_hash=$1 AND kind='multi' AND revoked=false
        ORDER BY created_at DESC LIMIT 1`, [myHash])
    if (rows.length) return rows[0]
  }
  const { rows } = await db.query(
    "INSERT INTO contact_invites (code, owner_hash, kind, created_at) VALUES ($1,$2,'multi',$3) RETURNING *",
    [newInviteCode(), myHash, now])
  return rows[0]
}

async function onceInvite(myHash, now) {
  await db.query(
    `UPDATE contact_invites SET revoked=true
      WHERE code IN (SELECT code FROM contact_invites
        WHERE owner_hash=$1 AND kind='once' AND revoked=false AND used_at IS NULL AND expires_at > $2
        ORDER BY created_at DESC OFFSET $3)`,
    [myHash, now, INVITE_MAX_ACTIVE_ONCE - 1])
  const { rows } = await db.query(
    `INSERT INTO contact_invites (code, owner_hash, kind, created_at, expires_at)
     VALUES ($1,$2,'once',$3,$4) RETURNING *`,
    [newInviteCode(), myHash, now, now + INVITE_ONCE_TTL_MS])
  return rows[0]
}

async function findInvite(code) {
  if (!INVITE_CODE_RE.test(code)) return null
  const { rows } = await db.query('SELECT * FROM contact_invites WHERE code=$1', [code])
  return rows[0] || null
}

async function inviteRefusal(invite, myHash) {
  if (!invite) return { status: 404, body: INVALID }
  if (invite.owner_hash === myHash) return { status: 409, body: OWN }
  if (invite.revoked) return { status: 410, body: DISABLED }
  if (invite.kind === 'once') {
    if (invite.used_at && invite.used_by !== myHash) return { status: 410, body: USED }
    if (!invite.used_at && invite.expires_at && Number(invite.expires_at) < Date.now()) {
      return { status: 410, body: EXPIRED }
    }
  }
  if (await isBlockedBy(invite.owner_hash, myHash)) return { status: 410, body: DISABLED }
  if (await newChatsBlocked(invite.owner_hash)) return { status: 410, body: DISABLED }
  return null
}

async function claimInvite(invite, myHash, now) {
  if (invite.kind === 'multi') {
    await db.query('UPDATE contact_invites SET use_count=use_count+1 WHERE code=$1', [invite.code])
    return true
  }
  if (invite.kind !== 'once' || invite.used_at) return true
  const { rowCount } = await db.query(
    `UPDATE contact_invites SET used_at=$2, used_by=$3, use_count=use_count+1
      WHERE code=$1 AND used_at IS NULL AND revoked=false AND (expires_at IS NULL OR expires_at >= $2)`,
    [invite.code, now, myHash])
  return rowCount > 0
}

function inviteRoutes(app) {
  app.post('/api/invites', { preHandler: requireAuth, config: perMinute(30) }, async (req, reply) => {
    const myHash = req.auth.sub
    if (await newChatsBlocked(myHash)) {
      return reply.code(403).send({ error: 'Masz włączoną blokadę nowych rozmów', code: 'block_new' })
    }
    const now = Date.now()
    const row = req.body?.kind === 'multi'
      ? await multiInvite(myHash, req.body?.reset === true, now)
      : await onceInvite(myHash, now)
    return inviteJson(row)
  })

  app.post('/api/invites/preview', { preHandler: requireAuth, config: perMinute(30) }, async (req, reply) => {
    const invite = await findInvite(String(req.body?.code || ''))
    const refusal = await inviteRefusal(invite, req.auth.sub)
    if (refusal) return reply.code(refusal.status).send(refusal.body)

    const { rows } = await db.query(
      'SELECT email_hash, display_name, avatar_color FROM users WHERE email_hash=$1', [invite.owner_hash])
    if (!rows.length) return reply.code(410).send(OWNER_GONE)
    const [owner] = rows
    return {
      ok: true,
      hash: owner.email_hash,
      displayName: owner.display_name,
      avatarColor: owner.avatar_color || null
    }
  })

  app.post('/api/invites/redeem', { preHandler: requireAuth, config: perMinute(30) }, async (req, reply) => {
    const myHash = req.auth.sub
    const invite = await findInvite(String(req.body?.code || ''))
    const refusal = await inviteRefusal(invite, myHash)
    if (refusal) return reply.code(refusal.status).send(refusal.body)

    if (!(await claimInvite(invite, myHash, Date.now()))) return reply.code(410).send(USED)

    const { rows } = await db.query(
      'SELECT email_hash, display_name, avatar_url FROM users WHERE email_hash=$1', [invite.owner_hash])
    if (!rows.length) return reply.code(410).send(OWNER_GONE)
    const [owner] = rows

    const conversationId = canonicalPair(myHash, invite.owner_hash)
    sendToUser(invite.owner_hash, { type: 'invite_used', conversationId, byHash: myHash })

    return {
      ok: true, conversationId,
      hash: owner.email_hash,
      displayName: owner.display_name,
      avatarUrl: owner.avatar_url || null
    }
  })
}

module.exports = { inviteRoutes }
