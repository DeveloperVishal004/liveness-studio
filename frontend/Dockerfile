# Hosted DEMO of Liveness Studio: static files only. No camera feed, no engine, no /api calls, nothing stored server-side.
# Build:  docker build -t liveness-studio-demo frontend
# Run:    docker run --rm -p 127.0.0.1:8080:8080 liveness-studio-demo     (then open http://127.0.0.1:8080)
FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
# Vite 8 needs Node 20.19+ (hence node:22). Its native bundler is an optional dependency that npm sometimes skips when the
# lockfile was made on another platform, so fall back to a fresh install for this platform.
RUN npm ci --no-audit --no-fund || (rm -rf node_modules && npm install --no-audit --no-fund)
COPY . .
RUN npm run build:demo

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist-demo /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
