FROM node:lts-trixie-slim
WORKDIR /app
RUN corepack enable

COPY package.json pnpm-lock.yaml ./
RUN pnpm config set enable-pre-post-scripts true && pnpm install

COPY . .
ENV NODE_OPTIONS="--max-old-space-size=4096"
RUN pnpm run build

EXPOSE 1100
CMD ["pnpm", "run", "start"]

