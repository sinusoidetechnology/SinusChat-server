// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

"use strict";

const Fastify = require("fastify");

const { clientIp } = require("./common");
const { scrubLog } = require("./log");
const { authRoutes, bearerToken, verifyToken } = require("./routes/auth");
const { callRoutes } = require("./routes/calls");
const { conversationRoutes } = require("./routes/conversations");
const { groupRoutes } = require("./routes/groups");
const { inviteRoutes } = require("./routes/invites");
const { filesRelayRoutes, mediaRoutes } = require("./routes/media");
const { messageRoutes } = require("./routes/messages");
const { presenceRoutes } = require("./routes/presence");
const { pushRoutes } = require("./routes/push");
const { reportRoutes } = require("./routes/reports");
const { signalRoutes } = require("./routes/signal");
const { userRoutes } = require("./routes/users");
const { WS_MAX_FRAME_BYTES, wsRoutes } = require("./routes/ws");

const API_ROUTERS = [
  authRoutes,
  userRoutes,
  signalRoutes,
  messageRoutes,
  conversationRoutes,
  groupRoutes,
  inviteRoutes,
  callRoutes,
  presenceRoutes,
  pushRoutes,
  reportRoutes,
  mediaRoutes,
];

const USER_LIMIT_PER_MINUTE = 600;
const IP_LIMIT_PER_MINUTE = 300;
const RATE_LIMIT_TRACKED_KEYS = 100_000;

function rateLimitKey(req) {
  const token = bearerToken(req);
  const sub = token && verifyToken(token)?.sub;
  return sub ? `u:${sub}` : `ip:${clientIp(req) || "unknown"}`;
}

function buildApp() {
  const app = Fastify({
    logger: false,
    bodyLimit: 2 * 1024 * 1024,
    requestTimeout: 600_000,
    routerOptions: { maxParamLength: 300 },
  });

  app.decorateRequest("auth", null);
  app.decorateRequest("group", null);

  app.register(require("@fastify/rate-limit"), {
    global: true,
    max: (req, key) => (key.startsWith("u:") ? USER_LIMIT_PER_MINUTE : IP_LIMIT_PER_MINUTE),
    timeWindow: "1 minute",
    keyGenerator: rateLimitKey,
    cache: RATE_LIMIT_TRACKED_KEYS,
    errorResponseBuilder: () => ({ statusCode: 429, error: "Za dużo żądań — spróbuj za chwilę" }),
  });

  app.setErrorHandler((err, req, reply) => {
    const status = Number(err.statusCode) || (reply.statusCode >= 400 ? reply.statusCode : 500);
    if (status === 429) return reply.code(429).send({ error: "Za dużo żądań — spróbuj za chwilę" });
    if (status >= 500) {
      const route = (req.routeOptions && req.routeOptions.url) || req.routerPath || "";
      console.error("[ERR]", req.method, route, scrubLog(err.message));
      return reply.code(500).send({ error: "Błąd serwera" });
    }
    return reply.code(status).send({ error: err.message || "Błędne żądanie" });
  });

  app.addHook("onSend", async (req, reply, payload) => {
    reply.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    reply.header("X-Content-Type-Options", "nosniff");
    if (!reply.hasHeader("content-security-policy")) {
      reply.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
    }
    return payload;
  });

  app.register(require("@fastify/cors"), { origin: true });
  app.register(require("@fastify/websocket"), { options: { maxPayload: WS_MAX_FRAME_BYTES } });

  app.register(async (health) => {
    health.get("/health", { config: { rateLimit: false } }, async () => ({ status: "ok", ts: Date.now() }));
  });
  for (const routes of API_ROUTERS) app.register(routes);

  app.register(filesRelayRoutes);
  app.register(wsRoutes);

  return app;
}

module.exports = { buildApp };
