// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

"use strict";

const fs = require("fs/promises");

const { db } = require("./db");
const { DAY_MS, HOUR_MS } = require("./common");
const { scrubLog } = require("./log");
const { purgeOldMessages } = require("./routes/messages");
const { purgeOldReports } = require("./routes/reports");
const { purgeInactiveAccounts, purgeScheduledAccounts } = require("./routes/users");

// Dostarczone (i potwierdzone) wiersze kolejki leżą jeszcze chwilę, żeby /api/ack miał co skasować.
const DELIVERED_KEEP_MS = 5 * 60 * 1000;
const GB = 1024 ** 3;

async function purgeOldInvites() {
  try {
    await db.query(
      `DELETE FROM contact_invites
        WHERE revoked = true
           OR (kind = 'once' AND used_at IS NOT NULL AND used_at < $1)
           OR (kind = 'once' AND expires_at IS NOT NULL AND expires_at < $1)`,
      [Date.now() - DAY_MS],
    );
  } catch (_) {}
}

async function cleanupMessagesAndGroups() {
  try {
    const cutoff30d = Date.now() - 30 * DAY_MS;
    const { rowCount } = await db.query("DELETE FROM messages WHERE delivered_at IS NULL AND created_at < $1::bigint", [cutoff30d]);
    if (rowCount > 0) console.log("[cleanup] Usunięto", rowCount, "nieodebranych wiadomości");

    const groupCutoffDay = Math.floor(Date.now() / DAY_MS) - 548;
    await db.query(
      `
      DELETE FROM conversation_participants cp
      USING groups g
      WHERE g.id = cp.conversation_id
        AND g.last_active_day IS NOT NULL
        AND g.last_active_day < $1::integer
    `,
      [groupCutoffDay],
    );
  } catch (e) {
    console.error("[cleanup]", scrubLog(e.message));
  }
}

function purgeDeliveredMessages() {
  return db
    .query("DELETE FROM messages WHERE delivered_at IS NOT NULL AND delivered_at < $1::bigint", [Date.now() - DELIVERED_KEEP_MS])
    .catch(() => {});
}

// Serwer nie trzyma plików, więc sprawdzany jest dysk, na którym leży jego katalog roboczy.
async function getFreeDiskGB() {
  try {
    const { bavail, bsize } = await fs.statfs(process.cwd());
    return Math.floor((bavail * bsize) / GB);
  } catch (_) {
    return 999;
  }
}

async function checkDiskSpace() {
  const freeGB = await getFreeDiskGB();
  if (freeGB < 10) console.warn(`[DISK WARNING] Wolne miejsce: ${freeGB}GB!`);
  if (freeGB < 5) console.error(`[DISK CRITICAL] Tylko ${freeGB}GB wolnego!`);
}

function startJobs(schemaReady) {
  schemaReady.then(purgeOldMessages).then(() => setTimeout(purgeScheduledAccounts, 30_000));
  setTimeout(purgeOldReports, 60 * 1000);
  setInterval(purgeOldMessages, HOUR_MS);
  setInterval(purgeScheduledAccounts, HOUR_MS);
  setInterval(purgeInactiveAccounts, HOUR_MS);
  setInterval(purgeOldInvites, HOUR_MS);
  setInterval(purgeOldReports, HOUR_MS);
  setInterval(cleanupMessagesAndGroups, HOUR_MS);
  setInterval(purgeDeliveredMessages, DELIVERED_KEEP_MS);
  setInterval(checkDiskSpace, 6 * HOUR_MS);
}

module.exports = { startJobs };
