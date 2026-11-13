# SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

ARG NODE_IMAGE=node:24-alpine

# 1. Install deps
FROM ${NODE_IMAGE} AS deps
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --omit=dev --ignore-scripts --no-audit --no-fund

# 2. Build runtime image
FROM ${NODE_IMAGE} AS runtime

LABEL org.opencontainers.image.title="sinuschat-server" \
      org.opencontainers.image.description="SinusChat messenger server" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.vendor="Sinusoide Technology"

RUN apk upgrade --no-cache \
 && apk add --no-cache tini \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
           /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
           /opt/yarn* /usr/local/bin/yarn /usr/local/bin/yarnpkg

WORKDIR /app

# Pliki aplikacji należą do root:root (tylko do odczytu dla użytkownika node)
COPY --from=deps /app/node_modules ./node_modules
COPY package.json server.js LICENSE NOTICE.md ./
COPY src ./src

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    NODE_OPTIONS="--disable-proto=delete"

USER node:node
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/health',{signal:AbortSignal.timeout(4000)}).then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "server.js"]