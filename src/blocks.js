// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

"use strict";

const crypto = require("crypto");

const { BLOCK_SECRET } = require("./config");
const { db } = require("./db");
const { scrubLog } = require("./log");

// Blokady w tabeli blocked_users są przechowywane jako HMAC(BLOCK_SECRET, "block|" + hash),
// więc zrzut bazy nie zdradza, kto kogo zablokował. Flaga `blocks_tagged` w server_flags mówi,
// że jednorazowa migracja jawnych wierszy już się odbyła.
const TAG_CACHE_MAX = 50_000;
const tagCache = new Map();
let blocksTagged = false;

function blockTag(hash) {
  const key = String(hash);
  let tag = tagCache.get(key);
  if (tag) return tag;
  tag = crypto.createHmac("sha256", BLOCK_SECRET).update("block|" + key).digest("hex");
  if (tagCache.size >= TAG_CACHE_MAX) tagCache.delete(tagCache.keys().next().value);
  tagCache.set(key, tag);
  return tag;
}

// Wartość zapisywana w blocked_users dla danego hasha konta (jawna, dopóki migracja nie przeszła).
function bt(hash) {
  return blocksTagged ? blockTag(hash) : String(hash);
}

// Mapa tag → hash dla listy kont, żeby wynik zapytania przełożyć z powrotem na hashe.
function tagMap(hashes) {
  return new Map(hashes.map((h) => [bt(h), h]));
}

async function migrateBlockTags() {
  let done = false;
  try {
    const { rows } = await db.query("SELECT 1 FROM server_flags WHERE name='blocks_tagged'");
    done = rows.length > 0;
  } catch (e) {
    console.error("[BLOCKS] odczyt stanu blokad nieudany:", scrubLog(e.message));
    return;
  }
  if (done && !BLOCK_SECRET) {
    console.error("[FATAL] Blokady są zaszyfrowane, a brakuje BLOCK_SECRET — nie startuję.");
    process.exit(1);
  }
  if (!BLOCK_SECRET) {
    console.warn("[UWAGA] Brak BLOCK_SECRET — blokady leżą w bazie jawnie.");
    return;
  }
  if (done) {
    blocksTagged = true;
    return;
  }
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const { rows: all } = await client.query("SELECT blocker_hash, blocked_hash FROM blocked_users");
    await client.query("DELETE FROM blocked_users");
    if (all.length) {
      await client.query(
        `INSERT INTO blocked_users(blocker_hash, blocked_hash, blocked_at)
         SELECT blocker, blocked, NULL FROM unnest($1::varchar[], $2::varchar[]) AS t(blocker, blocked)
         ON CONFLICT DO NOTHING`,
        [all.map((r) => blockTag(r.blocker_hash)), all.map((r) => blockTag(r.blocked_hash))],
      );
    }
    await client.query("INSERT INTO server_flags(name) VALUES('blocks_tagged') ON CONFLICT DO NOTHING");
    await client.query("COMMIT");
    blocksTagged = true;
    console.log("[BLOCKS] zaszyfrowano blokady:", all.length);
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("[BLOCKS] szyfrowanie blokad nieudane, zostają jawne:", scrubLog(e.message));
  } finally {
    client.release();
  }
}

module.exports = { bt, tagMap, migrateBlockTags };
