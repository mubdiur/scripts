FROM node:20-slim

RUN apt-get update -y && apt-get install -y openssl

WORKDIR /app

RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./

COPY packages ./packages
COPY . .

RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm config set store-dir /pnpm/store && \
    pnpm config set dangerouslyAllowAllBuilds true && \
    pnpm install

RUN pnpm prisma generate

EXPOSE 1100

CMD ["pnpm", "start"]


