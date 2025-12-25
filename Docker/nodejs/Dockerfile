FROM node:22-alpine
WORKDIR /app
RUN corepack enable

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --ignore-scripts=false

COPY . .
ENV NODE_OPTIONS="--max-old-space-size=4096"
RUN pnpm run build

EXPOSE 1100
CMD ["pnpm", "run", "start"]
