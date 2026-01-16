FROM node:20-slim

# 1. Install OpenSSL (Required for Prisma)
RUN apt-get update -y && apt-get install -y openssl procps

WORKDIR /app

RUN corepack enable

COPY . .

RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm config set store-dir /pnpm/store && \
    pnpm config set enable-pre-post-scripts true && \
    pnpm install

RUN pnpm -r build

RUN pnpm prisma generate

EXPOSE 1100

CMD /bin/sh -c "pnpm prisma migrate dev && pnpm start"