// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

"use strict";

const { db } = require("../db");
const {
  b64ok,
  contactsOf,
  HIDDEN_LOOKUP_LIMIT,
  isBlockedBy,
  isHash,
  keyIdOk,
  lookupAllowed,
  perHour,
  perMinute,
  sendToAll,
  signedKeyOk,
  spendBudget,
} = require("../common");
const { requireAuth } = require("./auth");

const PREKEYS_PER_PEER_HOURLY = 3;

async function currentKeyOf(userHash) {
  try {
    const { rows } = await db.query("SELECT e2e_public_key FROM users WHERE email_hash=$1", [userHash]);
    return rows[0]?.e2e_public_key || null;
  } catch (_) {
    return null;
  }
}

async function announceKeyChange(userHash, oldKey, newKey) {
  if (!newKey || newKey === oldKey) return;
  try {
    sendToAll(await contactsOf(userHash), { type: "peer_key", userHash, e2ePublicKey: newKey });
  } catch (_) {}
}

async function signalCapable(hashes) {
  if (!hashes.length) return new Set();
  try {
    const { rows } = await db.query(
      `SELECT sk.user_hash FROM signal_keys sk JOIN users u ON u.email_hash = sk.user_hash
        WHERE sk.user_hash = ANY($1::varchar[]) AND sk.identity_key = u.e2e_public_key`,
      [hashes],
    );
    return new Set(rows.map((r) => r.user_hash));
  } catch (_) {
    return new Set();
  }
}

async function dropSignalKeys(userHash) {
  try {
    await db.query("DELETE FROM signal_prekeys WHERE user_hash=$1", [userHash]);
    await db.query("DELETE FROM signal_keys WHERE user_hash=$1", [userHash]);
  } catch (_) {}
}

function signalRoutes(app) {
  app.post("/api/signal/keys", { preHandler: requireAuth, config: perHour(30) }, async (req, reply) => {
    const myHash = req.auth.sub;
    const b = req.body || {};
    const regId = Number(b.registrationId);
    if (!Number.isInteger(regId) || regId < 1 || regId > 16380) {
      return reply.code(400).send({ error: "Nieprawidłowe dane" });
    }
    if (!signedKeyOk(b.signedPreKey, 100) || !signedKeyOk(b.kyberPreKey, 3000)) {
      return reply.code(400).send({ error: "Nieprawidłowe klucze" });
    }
    const current = await currentKeyOf(myHash);
    if (!current || b.identityKey !== current) {
      return reply.code(409).send({ error: "Klucz tożsamości się nie zgadza", code: "identity_mismatch" });
    }
    const pre = Array.isArray(b.preKeys) ? b.preKeys.slice(0, 200) : [];
    for (const p of pre) {
      if (!p || !keyIdOk(p.id) || !b64ok(p.pub, 100)) {
        return reply.code(400).send({ error: "Nieprawidłowe klucze" });
      }
    }

    const client = await db.connect();
    try {
      await client.query("BEGIN");
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
        [myHash, current, regId, b.signedPreKey.id, b.signedPreKey.pub, b.signedPreKey.sig, b.kyberPreKey.id, b.kyberPreKey.pub, b.kyberPreKey.sig, Date.now()],
      );
      if (b.replacePreKeys === true) await client.query("DELETE FROM signal_prekeys WHERE user_hash=$1", [myHash]);
      if (pre.length) {
        const { rows } = await client.query("SELECT COUNT(*)::int AS n FROM signal_prekeys WHERE user_hash=$1", [myHash]);
        const take = pre.slice(0, Math.max(0, 500 - (rows[0]?.n || 0)));
        if (take.length) {
          await client.query(
            `INSERT INTO signal_prekeys (user_hash, key_id, pub)
             SELECT $1, t.k, t.p FROM unnest($2::int[], $3::text[]) AS t(k, p)
             ON CONFLICT DO NOTHING`,
            [myHash, take.map((p) => p.id), take.map((p) => p.pub)],
          );
        }
      }
      await client.query("COMMIT");
    } catch (e) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {}
      client.release();
      return reply.code(500).send({ error: "Nie udało się zapisać kluczy" });
    }
    client.release();
    return { ok: true };
  });

  app.get("/api/signal/count", { preHandler: requireAuth }, async (req) => {
    const myHash = req.auth.sub;
    try {
      const { rows } = await db.query("SELECT identity_key, signed_prekey_id FROM signal_keys WHERE user_hash=$1", [myHash]);
      const { rows: c } = await db.query("SELECT COUNT(*)::int AS n FROM signal_prekeys WHERE user_hash=$1", [myHash]);
      return {
        count: c[0]?.n || 0,
        signedPreKeyId: rows[0]?.signed_prekey_id ?? -1,
        identityKey: rows[0]?.identity_key || "",
      };
    } catch (_) {
      return { count: 0, signedPreKeyId: -1, identityKey: "" };
    }
  });

  app.get("/api/signal/bundle/:hash", { preHandler: requireAuth, config: perMinute(120) }, async (req, reply) => {
    const myHash = req.auth.sub;
    const hash = String(req.params.hash || "");
    if (!isHash(hash) || hash === myHash) return reply.code(404).send({ error: "Brak kluczy" });
    if (await isBlockedBy(hash, myHash)) return reply.code(404).send({ error: "Brak kluczy" });
    try {
      const { rows } = await db.query(
        `SELECT sk.*, u.email_block AS u_email_block, u.block_new AS u_block_new
           FROM signal_keys sk JOIN users u ON u.email_hash = sk.user_hash
          WHERE sk.user_hash=$1 AND sk.identity_key = u.e2e_public_key`,
        [hash],
      );
      if (!rows.length) return reply.code(404).send({ error: "Brak kluczy" });
      const k = rows[0];
      if ((k.u_email_block === true || k.u_block_new === true) && !lookupAllowed("h", myHash, hash, HIDDEN_LOOKUP_LIMIT)) {
        return reply.code(404).send({ error: "Brak kluczy" });
      }
      const mayTakePreKey = spendBudget(`p:${myHash}:${hash}`, 1, PREKEYS_PER_PEER_HOURLY);
      const { rows: pre } = !mayTakePreKey
        ? { rows: [] }
        : await db.query(
            `DELETE FROM signal_prekeys WHERE (user_hash, key_id) IN (
           SELECT user_hash, key_id FROM signal_prekeys WHERE user_hash=$1 LIMIT 1 FOR UPDATE SKIP LOCKED)
         RETURNING key_id, pub`,
            [hash],
          );
      return {
        registrationId: k.registration_id,
        identityKey: k.identity_key,
        signedPreKey: { id: k.signed_prekey_id, pub: k.signed_prekey, sig: k.signed_prekey_sig },
        kyberPreKey: { id: k.kyber_prekey_id, pub: k.kyber_prekey, sig: k.kyber_prekey_sig },
        preKey: pre[0] ? { id: pre[0].key_id, pub: pre[0].pub } : null,
      };
    } catch (_) {
      return reply.code(404).send({ error: "Brak kluczy" });
    }
  });
}

module.exports = { signalRoutes, currentKeyOf, announceKeyChange, signalCapable, dropSignalKeys };
