// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

'use strict'

const { REPORTS_ADMIN_IPS, REPORTS_ADMIN_KEY } = require('../config')
const { secretEquals } = require('../crypto')
const { db } = require('../db')
const { clientIp, clip, DAY_MS, perHour, perMinute, sendToUser } = require('../common')
const { requireAuth } = require('./auth')

const REPORT_STATUSES = new Set(['pending', 'confirmed', 'rejected'])
const REPORT_MAX_PER_DAY = 10
const REPORT_RETENTION_DAYS = 30
const REPORT_RETENTION_MS = REPORT_RETENTION_DAYS * DAY_MS
const REPORT_RETENTION_BASE_SQL = 'GREATEST(created_at, COALESCE(replied_at, 0), COALESCE(decided_at, 0))'
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

const REPORT_TOPICS = new Set(['bug', 'feature', 'other'])
// Aplikacja, z której przyszło zgłoszenie; brak lub nieznana wartość = Android (starsze wersje).
const REPORT_PLATFORMS = new Set(['SinusChatA', 'SinusChat-Desktop', 'SinusChatI'])
const DEFAULT_PLATFORM = 'SinusChatA'
// Dane kontaktowe i diagnostyka rozstrzygniętego zgłoszenia są czyszczone dobę po decyzji.
const REPORT_PERSONAL_KEEP_MS = DAY_MS

async function purgeOldReports() {
  try {
    await db.query(
      `UPDATE bug_reports SET email=NULL, name=NULL, device=NULL, android=NULL, app_version=NULL, diagnostics=NULL
        WHERE status IN ('confirmed', 'rejected') AND decided_at IS NOT NULL AND decided_at < $1
          AND (email IS NOT NULL OR name IS NOT NULL OR device IS NOT NULL OR android IS NOT NULL
               OR app_version IS NOT NULL OR diagnostics IS NOT NULL)`,
      [Date.now() - REPORT_PERSONAL_KEEP_MS])
    const { rowCount } = await db.query(
      `DELETE FROM bug_reports WHERE ${REPORT_RETENTION_BASE_SQL} < $1`,
      [Date.now() - REPORT_RETENTION_MS])
    if (rowCount) {
      console.log(`[REPORT] usunięto zgłoszenia po ${REPORT_RETENTION_DAYS} dniach od ostatniej zmiany:`, rowCount)
    }
  } catch (_) {}
}

function checkReportsAdmin(req) {
  if (!REPORTS_ADMIN_KEY || REPORTS_ADMIN_KEY.length < 24) return 'disabled'
  if (REPORTS_ADMIN_IPS.length) {
    if (!REPORTS_ADMIN_IPS.includes(clientIp(req))) return 'bad'
  }
  const given = String(req.headers['x-admin-key'] || '')
  return secretEquals(given, REPORTS_ADMIN_KEY) && given.length > 0 ? 'ok' : 'bad'
}

function denyReportsAdmin(reply, state) {
  if (state === 'disabled') {
    return reply.code(503).send({ error: 'Panel wyłączony — ustaw REPORTS_ADMIN_KEY na serwerze' })
  }
  return reply.code(401).send({ error: 'Nieprawidłowy klucz' })
}

async function requireReportsAdmin(req, reply) {
  const state = checkReportsAdmin(req)
  if (state !== 'ok') return denyReportsAdmin(reply, state)
}

const optionalNumber = (value) => (value ? Number(value) : null)
const deleteAtOf = (row) => Number(row.retention_base) + REPORT_RETENTION_MS

function ownReportJson(r) {
  return {
    id: Number(r.id), topic: r.topic, status: r.status,
    platform: r.platform || DEFAULT_PLATFORM,
    description: String(r.description || '').slice(0, 300),
    reply: r.reply || null,
    hasEmail: r.has_email === true,
    deleteAt: deleteAtOf(r),
    repliedAt: optionalNumber(r.replied_at),
    createdAt: Number(r.created_at)
  }
}

function adminReportJson(r) {
  return {
    id: Number(r.id), email: r.email, name: r.name, topic: r.topic, description: r.description,
    appVersion: r.app_version, device: r.device, android: r.android, diagnostics: r.diagnostics,
    platform: r.platform || DEFAULT_PLATFORM,
    status: r.status, reply: r.reply,
    repliedAt: optionalNumber(r.replied_at),
    createdAt: Number(r.created_at),
    updatedAt: optionalNumber(r.updated_at),
    decidedAt: optionalNumber(r.decided_at),
    deleteAt: deleteAtOf(r)
  }
}

function reportFilter(query) {
  const status = REPORT_STATUSES.has(query?.status) ? query.status : null
  const q = clip(query?.q, 100)
  const params = []
  const conditions = []
  if (status) {
    params.push(status)
    conditions.push(`status = $${params.length}`)
  }
  if (q) {
    params.push('%' + q.replace(/[\\%_]/g, m => '\\' + m) + '%')
    const pattern = `$${params.length} ESCAPE '\\'`
    conditions.push(`(description ILIKE ${pattern} OR email ILIKE ${pattern} OR device ILIKE ${pattern})`)
  }
  return { where: conditions.length ? 'WHERE ' + conditions.join(' AND ') : '', params }
}

function reportRoutes(app) {
  app.post('/api/report', { preHandler: requireAuth, config: perHour(6) }, async (req, reply) => {
    const myHash = req.auth.sub
    const b = req.body || {}
    const description = clip(b.description, 4000)
    const email = clip(b.email, 254)
    const topic = REPORT_TOPICS.has(b.topic) ? b.topic : 'other'
    const platform = REPORT_PLATFORMS.has(b.platform) ? b.platform : DEFAULT_PLATFORM
    if (!description || description.length < 10) {
      return reply.code(400).send({ error: 'Opis jest za krótki', code: 'description_too_short' })
    }
    if (email && !EMAIL_RE.test(email)) {
      return reply.code(400).send({ error: 'Nieprawidłowy e-mail', code: 'invalid_email' })
    }

    const { rows: recent } = await db.query(
      'SELECT count(*)::int AS n FROM bug_reports WHERE user_hash=$1 AND created_at > $2',
      [myHash, Date.now() - DAY_MS])
    if ((recent[0]?.n || 0) >= REPORT_MAX_PER_DAY) {
      return reply.code(429).send({ error: 'Za dużo zgłoszeń — spróbuj jutro', code: 'too_many_reports' })
    }

    const { rows } = await db.query(
      `INSERT INTO bug_reports (user_hash, email, name, topic, description, app_version, device, android,
                                diagnostics, status, created_at, updated_at, platform)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10,$10,$11) RETURNING id`,
      [myHash, email, clip(b.name, 100), topic, description, clip(b.appVersion, 40),
       clip(b.device, 120), clip(b.android, 20), clip(b.diagnostics, 16000), Date.now(), platform])
    console.log('[REPORT] nowe zgłoszenie #' + rows[0].id + ' (' + topic + ', ' + platform + ')')
    return { ok: true, id: Number(rows[0].id) }
  })

  app.get('/api/reports/mine', { preHandler: requireAuth }, async (req) => {
    const { rows } = await db.query(
      `SELECT id, topic, description, status, reply, replied_at, created_at, (email IS NOT NULL) AS has_email, platform,
              ${REPORT_RETENTION_BASE_SQL} AS retention_base
         FROM bug_reports WHERE user_hash=$1 ORDER BY created_at DESC LIMIT 50`, [req.auth.sub])
    return { reports: rows.map(ownReportJson) }
  })

  app.get('/api/reports-admin/list', { preHandler: requireReportsAdmin, config: perMinute(60) }, async (req) => {
    const { where, params } = reportFilter(req.query)
    const { rows } = await db.query(
      `SELECT id, email, name, topic, description, app_version, device, android, diagnostics, platform,
              status, reply, replied_at, created_at, updated_at, decided_at,
              ${REPORT_RETENTION_BASE_SQL} AS retention_base
         FROM bug_reports ${where}
        ORDER BY created_at DESC LIMIT 300`, params)
    const { rows: counts } = await db.query('SELECT status, count(*)::int AS n FROM bug_reports GROUP BY status')
    const stats = { pending: 0, confirmed: 0, rejected: 0 }
    for (const { status, n } of counts) if (status in stats) stats[status] = n
    return { stats, retentionDays: REPORT_RETENTION_DAYS, reports: rows.map(adminReportJson) }
  })

  app.get('/api/reports-admin/version', { preHandler: requireReportsAdmin, config: perMinute(120) }, async () => {
    const { rows } = await db.query(
      `SELECT count(*)::int AS n,
              COALESCE(max(GREATEST(created_at, COALESCE(updated_at, 0))), 0)::bigint AS last,
              count(*) FILTER (WHERE status = 'pending')::int AS fresh
         FROM bug_reports`)
    const { n, last, fresh } = rows[0] || { n: 0, last: 0, fresh: 0 }
    return { version: n + ':' + last, total: n, newCount: fresh }
  })

  app.post('/api/reports-admin/:id', { preHandler: requireReportsAdmin, config: perMinute(60) }, async (req, reply) => {
    const id = Number(req.params.id)
    if (!Number.isSafeInteger(id) || id <= 0) return reply.code(400).send({ error: 'Złe id' })
    const b = req.body || {}

    if (b.delete === true) {
      await db.query('DELETE FROM bug_reports WHERE id=$1', [id])
      return { ok: true, deleted: true }
    }
    const status = REPORT_STATUSES.has(b.status) ? b.status : null
    const hasReply = Object.hasOwn(b, 'reply')
    const replyText = hasReply ? clip(b.reply, 4000) : null

    const { rows } = await db.query('SELECT user_hash, status, reply FROM bug_reports WHERE id=$1', [id])
    if (!rows.length) return reply.code(404).send({ error: 'Nie ma takiego zgłoszenia' })
    const [old] = rows
    const statusChanged = status !== null && status !== old.status
    const replied = !!replyText && replyText !== old.reply

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
      [id, status, hasReply, replyText, Date.now(), statusChanged])

    if ((statusChanged || replied) && old.user_hash) {
      sendToUser(old.user_hash, { type: 'report_update', id, status: status || old.status, replied })
    }
    return { ok: true }
  })
}

module.exports = { reportRoutes, purgeOldReports }
