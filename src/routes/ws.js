// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

"use strict";

const { db } = require("../db");
const {
  allSockets,
  canonicalPair,
  canUseConversation,
  clientIp,
  connections,
  failProbes,
  isBlockedBy,
  isGroupId,
  isHash,
  isParticipant,
  onWsPong,
  sendJson,
  sendToAll,
  sendToUser,
  WS_OPEN,
  withoutBlockers,
} = require("../common");
const { verifyActiveDevice } = require("./auth");
const { CALL_OFFER_TTL_MS, GCALL_SIGNAL_LIMIT, gcallSendActive, handleCall, handleGroupCall, pendingCallOffers } = require("./calls");
const { relayDirectAck } = require("./messages");
const { loadNtfyTopic } = require("./push");

const TYPING_MAX_RECIPIENTS = 20;
const WS_MSG_LIMIT = 40;
const WS_MSG_WINDOW_MS = 10_000;
const WS_MAX_FRAME_BYTES = 256 * 1024;
const WS_FRAMES_HARD_LIMIT = 1000;
const WS_AUTH_TIMEOUT_MS = 15_000;
const WS_CONN_PER_IP = 10;
const CALL_SIGNALS = new Set(["call_offer", "call_answer", "call_ice", "call_reject", "call_end", "call_reoffer", "call_reanswer", "call_screen"]);
const GCALL_KEEPALIVES = new Set(["gcall_signal", "gcall_ping"]);
// auth_ok niesie czas startu serwera (klient po restarcie wie, że ma dociągnąć kolejkę)
// oraz listę możliwości serwera.
const SERVER_BOOT = Date.now();
const SERVER_CAPS = ["group_sealed"];

async function authenticate(session, token) {
  session.authorizing = true;
  try {
    return await verifyActiveDevice(token);
  } catch (_) {
    try {
      session.socket.close(1011);
    } catch (_) {}
    return undefined;
  } finally {
    session.authorizing = false;
  }
}

async function handleAuth(session, msg) {
  const { socket } = session;
  if (session.userHash || session.authorizing) return;
  const payload = await authenticate(session, msg.token);
  if (payload === undefined) return;
  if (!payload) {
    sendJson(socket, { type: "auth_error" });
    return;
  }
  if (payload.kicked) {
    sendJson(socket, { type: "device_kicked" });
    try {
      socket.close();
    } catch (_) {}
    return;
  }
  if (socket.readyState !== WS_OPEN) return;

  const userHash = (session.userHash = payload.sub);
  clearTimeout(session.authTimer);
  socket.deviceId = payload.deviceId || null;
  socket.userHash = userHash;

  // Niepotwierdzone ramki poprzedniego gniazda wracają do kolejki (bez budzenia — konto właśnie się łączy).
  const prev = connections.get(userHash);
  if (prev && prev !== socket) await failProbes(prev, false);
  if (socket.readyState !== WS_OPEN) return;
  const holder = connections.get(userHash);
  if (holder && holder !== socket && holder.readyState === WS_OPEN) {
    const sameDevice = !!socket.deviceId && holder.deviceId === socket.deviceId;
    // To samo urządzenie otworzyło już nowsze gniazdo: to starsze ustępuje, a nie wyrzuca nowego.
    if (sameDevice && (holder.openedAt || 0) > socket.openedAt) {
      try {
        socket.close(1000, "superseded");
      } catch (_) {}
      return;
    }
    if (!sameDevice) {
      try {
        sendJson(holder, { type: "device_kicked" });
      } catch (_) {}
    }
    try {
      holder.close();
    } catch (_) {}
  }

  connections.set(userHash, socket);
  const caps = Array.isArray(msg.caps) ? msg.caps : [];
  socket.callAckSupported = caps.includes("call_ack");
  socket.gcallAckSupported = caps.includes("gcall_ack");
  if (caps.includes("call_e2e")) {
    db.query("UPDATE users SET call_e2e=true WHERE email_hash=$1 AND call_e2e IS NOT TRUE", [userHash]).catch(() => {});
  }
  sendJson(socket, { type: "auth_ok", hash: userHash, userHash, boot: SERVER_BOOT, caps: SERVER_CAPS });
  loadNtfyTopic(userHash);

  gcallSendActive(userHash).catch(() => {});

  const pending = pendingCallOffers.get(userHash);
  if (pending) {
    if (!socket.callAckSupported) pendingCallOffers.delete(userHash);
    if (Date.now() - pending.ts < CALL_OFFER_TTL_MS) {
      const { ts, ...offer } = pending;
      sendJson(socket, offer);
    }
  }
}

async function canReceiveTyping(conversationId, senderHash, recipient) {
  if (!isGroupId(conversationId) && conversationId === canonicalPair(senderHash, recipient)) return true;
  return isParticipant(conversationId, recipient);
}

async function notifyMembers(conversationId, senderHash, signal) {
  const { rows } = await db.query(
    `SELECT user_hash FROM conversation_participants
      WHERE conversation_id=$1 AND user_hash!=$2 LIMIT ${TYPING_MAX_RECIPIENTS}`,
    [conversationId, senderHash],
  );
  sendToAll(
    await withoutBlockers(
      rows.map((r) => r.user_hash),
      senderHash,
    ),
    signal,
  );
}

async function handleTyping({ userHash }, msg) {
  const { type, conversationId, recipientHash } = msg;
  if (!(await canUseConversation(conversationId, userHash))) return;
  const signal = { type, conversationId, senderHash: userHash };

  if (recipientHash) {
    if (!isHash(recipientHash) || !(await canReceiveTyping(conversationId, userHash, recipientHash))) return;
    if (await isBlockedBy(recipientHash, userHash)) return;
    sendToUser(recipientHash, signal);
    return;
  }
  try {
    await notifyMembers(conversationId, userHash, signal);
  } catch (_) {}
}

const wsConnByIp = new Map();

function ackCallOffer(userHash, msg) {
  const offer = pendingCallOffers.get(userHash);
  if (offer && offer.conversationId === msg.conversationId) pendingCallOffers.delete(userHash);
}

async function relayAck(userHash, { conversationId, deliveredUpTo, readUpTo }) {
  if (conversationId && !isGroupId(conversationId) && (await canUseConversation(conversationId, userHash))) {
    await relayDirectAck(userHash, conversationId, deliveredUpTo, readUpTo);
  }
}

async function dispatch(session, msg) {
  if (msg.type === "auth") return handleAuth(session, msg);
  if (!session.userHash) return;

  if (msg.type === "call_offer_ack") return ackCallOffer(session.userHash, msg);
  if (msg.type === "ping") return sendJson(session.socket, { type: "pong" });
  if (msg.type === "bg") return setBackground(session.socket, msg.on === true);
  if (typeof msg.type === "string" && msg.type.startsWith("gcall_")) return handleGroupCall(session, msg);
  if (CALL_SIGNALS.has(msg.type)) return handleCall(session, msg);
  if (msg.type === "typing" || msg.type === "typing_stop") return handleTyping(session, msg);
  if (msg.type === "ack") return relayAck(session.userHash, msg);
}

// Aplikacja w tle zgłasza {type:"bg", on:true}: serwer pinguje ją rzadziej (zob. BG_PING_EVERY).
function setBackground(socket, on) {
  socket.background = on;
  socket.heartbeatAlive = true;
  socket.pingTick = 0;
}

function createFloodGuard() {
  let frames = 0;
  let messages = 0;
  let signals = 0;
  let windowStart = Date.now();

  return {
    tick() {
      const now = Date.now();
      if (now - windowStart <= WS_MSG_WINDOW_MS) return;
      windowStart = now;
      frames = 0;
      messages = 0;
      signals = 0;
    },
    overloaded() {
      return ++frames > WS_FRAMES_HARD_LIMIT;
    },
    allows(msg) {
      if (msg && GCALL_KEEPALIVES.has(msg.type)) return ++signals <= GCALL_SIGNAL_LIMIT;
      return ++messages <= WS_MSG_LIMIT;
    },
  };
}

function releaseIpSlot(ip) {
  const remaining = (wsConnByIp.get(ip) || 1) - 1;
  if (remaining <= 0) wsConnByIp.delete(ip);
  else wsConnByIp.set(ip, remaining);
}

async function wsRoutes(app) {
  app.get("/ws", { websocket: true }, (socket, req) => {
    const ip = clientIp(req) || "unknown";
    const connectionsFromIp = wsConnByIp.get(ip) || 0;
    if (connectionsFromIp >= WS_CONN_PER_IP) {
      try {
        socket.close(1013, "Za dużo połączeń");
      } catch (_) {}
      return;
    }
    wsConnByIp.set(ip, connectionsFromIp + 1);
    socket.openedAt = Date.now();

    const session = { socket, userHash: null, authorizing: false, authTimer: null };
    const floodGuard = createFloodGuard();
    session.authTimer = setTimeout(() => socket.terminate(), WS_AUTH_TIMEOUT_MS);

    socket.on("message", async (raw) => {
      try {
        floodGuard.tick();
        if (floodGuard.overloaded()) {
          socket.terminate();
          return;
        }
        const text = raw && raw.data !== undefined ? raw.data.toString() : raw.toString();
        const msg = JSON.parse(text);
        if (floodGuard.allows(msg)) await dispatch(session, msg);
      } catch (_) {}
    });

    socket.heartbeatAlive = true;
    socket.on("pong", (data) => onWsPong(socket, data));
    allSockets.add(socket);

    socket.on("close", () => {
      clearTimeout(session.authTimer);
      allSockets.delete(socket);
      failProbes(socket, true);
      if (session.userHash && connections.get(session.userHash) === socket) connections.delete(session.userHash);
      releaseIpSlot(ip);
    });
  });
}

module.exports = { wsRoutes, WS_MAX_FRAME_BYTES };
