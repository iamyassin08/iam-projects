# ---- 1. Build the React frontend ----
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# ---- 2. Build the Go API (stdlib only, static binary) ----
FROM golang:1.24-alpine AS api
WORKDIR /src
COPY server/go.mod ./
COPY server/*.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /iam-server .

# ---- 3. Small runtime image ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget && adduser -D -u 10001 app && mkdir -p /data && chown app /data
WORKDIR /app
COPY --from=api /iam-server /app/iam-server
COPY --from=web /web/dist /app/web
ENV PORT=8080 STATIC_DIR=/app/web DATA_PATH=/data/iam.json
USER app
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:8080/api/health || exit 1
CMD ["/app/iam-server"]
