FROM node:22-alpine3.20 AS deps

RUN apk add --no-cache libc6-compat
RUN corepack enable && corepack prepare pnpm@latest --activate

WORKDIR /app

COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile


FROM node:22-alpine3.20 AS builder

RUN apk add --no-cache libc6-compat
RUN corepack enable && corepack prepare pnpm@latest --activate

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build-time env vars (baked into the bundle)
ARG NEXT_PUBLIC_BASE_URL=http://localhost:5005
ARG NEXT_PUBLIC_SIGN=
ARG SITE_URL=http://localhost:3000
ENV NEXT_PUBLIC_BASE_URL=${NEXT_PUBLIC_BASE_URL}
ENV NEXT_PUBLIC_SIGN=${NEXT_PUBLIC_SIGN}
ENV SITE_URL=${SITE_URL}
ENV NEXT_TELEMETRY_DISABLED=1

RUN pnpm run build


FROM node:22-alpine3.20 AS runner

WORKDIR /app

RUN apk add --no-cache dumb-init openssl

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

RUN corepack enable && corepack prepare pnpm@latest --activate

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

COPY --from=builder /app/public ./public

RUN mkdir -p .next && chown -R nextjs:nodejs .next

COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

ENTRYPOINT ["dumb-init", "--"]

CMD ["node", "server.js"]
