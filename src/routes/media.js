// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

"use strict";

const { Readable } = require("stream");

const { sameHex, sha256Hex, uploadHmacHex } = require("../crypto");
const { clientIp } = require("../common");
const { scrubLog } = require("../log");
const { requireAuth } = require("./auth");

// Głosówki trzyma wyłącznie serwer plików (hosting); ten serwer nie zapisuje już nic na dysku.
const RELAY_CACHE_MAX = 128 * 1024 * 1024;
const RELAY_CACHE_MS = 15 * 60 * 1000;
const FILES_ORIGIN = "https://files.sinusoide.pl/api/";
const FILES_RELAY_PATH = new RegExp(
  `^/api/files/(${[
    String.raw`upload\.php`,
    String.raw`auth\.php`,
    String.raw`uploads/(?:avatars|group_avatars)/[0-9a-f]{32,64}\.(?:jpg|png|webp|bin)`,
    String.raw`models/translate/(?:model|vocab|lex)\.[a-z0-9.]+\.(?:bin|spm)\.gz`,
  ].join("|")})$`,
);
const DOWNLOAD_QUERY = /[?&]action=download(?:&|$)/;
const FILES_RELAY_MAX = 52 * 1024 * 1024;
// Przy włączonym Torze aplikacja kieruje przez przekaźnik wszystkie żądania do serwera plików
// (awatary, załączniki, modele), a wielu użytkowników dzieli IP węzła wyjściowego. Limity mają
// więc tylko odciąć nadużycia, a nie zwykłe równoległe pobieranie (aplikacja nie ponawia po 503).
const FILES_RELAY_SLOTS = 64;
const FILES_RELAY_SLOTS_PER_IP = 16;
const FILES_RELAY_HEADERS = ["content-type", "accept", "x-file-id", "x-upload-token", "x-account", "x-file-auth"];
const FILES_RELAY_REPLY_HEADERS = ["content-type", "content-disposition", "cache-control", "etag", "last-modified"];
const RELAY_CACHEABLE_MAX = RELAY_CACHE_MAX / 4;
const DOWNLOAD_TIMEOUT_MS = 900_000;
const REQUEST_TIMEOUT_MS = 180_000;

function issueUploadToken(account) {
  const expiry = Date.now() + 5 * 60 * 1000;
  const data = `${account}.${expiry}`;
  return { token: `${data}.${uploadHmacHex(data)}`, expires_at: expiry };
}

function validUploadToken(token, account) {
  if (typeof token !== "string" || typeof account !== "string") return false;
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== account) return false;
  if (!/^[0-9]{1,15}$/.test(parts[1]) || Number(parts[1]) < Date.now()) return false;
  return sameHex(uploadHmacHex(`${parts[0]}.${parts[1]}`), parts[2]);
}

const relayCache = new Map();
let relayCacheBytes = 0;

function relayCacheKey(h) {
  const id = h["x-file-id"],
    acc = h["x-account"],
    auth = h["x-file-auth"];
  if (![id, acc, auth].every((v) => typeof v === "string" && v.length > 0)) return null;
  return sha256Hex(`${id}|${acc}|${auth}`);
}

function relayCacheSweep() {
  const now = Date.now();
  for (const [k, e] of relayCache) if (e.until <= now) relayCacheDrop(k);
}
setInterval(relayCacheSweep, 60_000).unref();

function relayCacheDrop(key) {
  const e = relayCache.get(key);
  if (!e) return;
  relayCache.delete(key);
  relayCacheBytes -= e.body.length;
}

function relayCachePut(key, headers, body) {
  relayCacheDrop(key);
  if (body.length > RELAY_CACHE_MAX / 4) return;
  relayCacheSweep();
  while (relayCacheBytes + body.length > RELAY_CACHE_MAX && relayCache.size > 0) {
    relayCacheDrop(relayCache.keys().next().value);
  }
  relayCache.set(key, { until: Date.now() + RELAY_CACHE_MS, headers, body });
  relayCacheBytes += body.length;
}

let filesRelayBusy = 0;
const filesRelayByIp = new Map();

const failure = (reply, status, error) => reply.code(status).send({ success: false, error });

function holdRelaySlot(req, reply, done) {
  const ip = clientIp(req);
  const held = filesRelayByIp.get(ip) || 0;
  if (filesRelayBusy >= FILES_RELAY_SLOTS || held >= FILES_RELAY_SLOTS_PER_IP) {
    failure(reply, 503, "Serwer plików jest zajęty — spróbuj za chwilę");
    return;
  }
  filesRelayBusy++;
  filesRelayByIp.set(ip, held + 1);
  reply.raw.once("close", () => {
    filesRelayBusy--;
    const left = filesRelayByIp.get(ip) - 1;
    if (left > 0) filesRelayByIp.set(ip, left);
    else filesRelayByIp.delete(ip);
  });
  done();
}

function relayClientTag(req) {
  const ip = clientIp(req);
  const exp = String(Date.now() + 120_000);
  return `${ip};${exp};${uploadHmacHex(`relay|${ip}|${exp}`)}`;
}

function forwardedHeaders(req) {
  const headers = { "user-agent": "SinusChat-Relay", "x-sinuschat-client": relayClientTag(req) };
  for (const name of FILES_RELAY_HEADERS) {
    if (typeof req.headers[name] === "string") headers[name] = req.headers[name];
  }
  return headers;
}

function returnedHeaders(res) {
  const headers = {};
  for (const name of FILES_RELAY_REPLY_HEADERS) {
    const value = res.headers.get(name);
    if (value) headers[name] = value;
  }
  return headers;
}

function cachedDownload(cacheKey, req) {
  if (!cacheKey) return null;
  const hit = relayCache.get(cacheKey);
  const fresh = hit && hit.until > Date.now();
  return fresh && validUploadToken(req.headers["x-upload-token"], req.headers["x-account"]) ? hit : null;
}

async function relayToFilesServer(req, reply) {
  const [path, query] = splitUrl(req.url);
  const match = path.match(FILES_RELAY_PATH);
  if (!match) return failure(reply, 404, "Nie znaleziono");
  const target = match[1];

  const isModel = target.startsWith("models/");
  if (isModel && req.method !== "GET") return failure(reply, 405, "Tylko GET");
  const isDownload = isModel || (target === "upload.php" && DOWNLOAD_QUERY.test(query));
  const cacheKey = isDownload ? relayCacheKey(req.headers) : null;

  const hit = cachedDownload(cacheKey, req);
  if (hit) return reply.code(200).headers(hit.headers).send(hit.body);

  try {
    const res = await fetch(FILES_ORIGIN + target + query, {
      method: req.method,
      headers: forwardedHeaders(req),
      body: req.method === "POST" ? (Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0)) : undefined,
      redirect: "manual",
      signal: AbortSignal.timeout(isDownload ? DOWNLOAD_TIMEOUT_MS : REQUEST_TIMEOUT_MS),
    });
    const headers = returnedHeaders(res);
    const length = Number(res.headers.get("content-length") || 0);
    const cacheable = cacheKey && length && length <= RELAY_CACHEABLE_MAX;
    if (isDownload && res.status === 200 && res.body && !cacheable) {
      if (length > 0) headers["content-length"] = String(length);
      return reply.code(res.status).headers(headers).send(Readable.fromWeb(res.body));
    }
    const body = Buffer.from(await res.arrayBuffer());
    if (cacheKey && res.status === 200 && body.length > 0) relayCachePut(cacheKey, headers, body);
    return reply.code(res.status).headers(headers).send(body);
  } catch (e) {
    console.warn("[FILES] przekaźnik:", scrubLog(e.message));
    return failure(reply, 502, "Serwer plików nie odpowiada");
  }
}

function splitUrl(url) {
  const q = url.indexOf("?");
  return q < 0 ? [url, ""] : [url.slice(0, q), url.slice(q)];
}

function mediaRoutes(app) {
  app.get("/api/upload-token", { preHandler: requireAuth }, async (req) => {
    return issueUploadToken(req.auth.sub);
  });
}

async function filesRelayRoutes(relay) {
  relay.removeAllContentTypeParsers();
  relay.addContentTypeParser("*", { parseAs: "buffer", bodyLimit: FILES_RELAY_MAX }, (req, body, done) => {
    done(null, body);
  });

  relay.route({
    method: ["GET", "POST"],
    url: "/api/files/*",
    bodyLimit: FILES_RELAY_MAX,
    onRequest: holdRelaySlot,
    handler: relayToFilesServer,
  });
}

module.exports = { mediaRoutes, filesRelayRoutes };
