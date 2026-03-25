# ── Build stage ───────────────────────────────────────────────────────────────
FROM node:20-alpine AS build

WORKDIR /app

# Install dependencies (including devDeps for TypeScript compilation)
COPY package*.json ./
RUN npm ci

# Copy source and compile
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# Build the web UI if present
COPY web/ ./web/
RUN cd web && npm ci 2>/dev/null && npm run build 2>/dev/null || true

# Remove devDependencies before copying to the runtime image
RUN npm prune --omit=dev

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM node:20-alpine AS runtime

WORKDIR /app

# Security: run as non-root user
RUN addgroup -g 1001 scanner && adduser -u 1001 -G scanner -s /bin/sh -D scanner

# Copy compiled output and production node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json

# Copy web UI build if it exists
COPY --from=build /app/web/dist ./web/dist 2>/dev/null || true

ENV NODE_ENV=production

# Expose the server port (default 3001; overridable via PORT env var)
EXPOSE 3001

# Health check — waits up to 30s for the server to become ready
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://localhost:${PORT:-3001}/health || exit 1

USER scanner

# Start the Express server
CMD ["node", "dist/server.js"]
