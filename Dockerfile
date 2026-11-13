# ---- 1. Build the React frontend ----
FROM node:22-alpine AS web
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# pages embed the automation scripts and the Keycloak realm (../backend/scripts, ../backend/keycloak)
COPY backend/scripts/ /src/backend/scripts/
COPY backend/keycloak/ /src/backend/keycloak/
RUN npm run build

# ---- 2. Build the Go API (stdlib only, static binary) ----
FROM golang:1.24-alpine AS api
WORKDIR /src
COPY backend/go.mod ./
COPY backend/*.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /iam-server .

# ---- 3. Small runtime image ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget && adduser -D -u 10001 app && mkdir -p /data && chown app /data
WORKDIR /app
COPY --from=api /iam-server /app/iam-server
COPY --from=web /src/frontend/dist /app/web
ENV PORT=8080 STATIC_DIR=/app/web DATA_PATH=/data/iam.json
USER app
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:8080/api/health || exit 1
CMD ["/app/iam-server"]
