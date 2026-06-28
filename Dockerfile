# syntax=docker/dockerfile:1.7

FROM node:20-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.25-alpine AS go
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/dist ./internal/api/web_dist
# BPF .o objects are pre-compiled and committed — no clang/go generate needed.
RUN CGO_ENABLED=0 go build \
    -ldflags "-X main.Version=$(git describe --tags --always 2>/dev/null || echo dev)" \
    -o /out/vakta ./cmd/vakta

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=go /out/vakta /usr/local/bin/vakta
USER 0:0
ENTRYPOINT ["/usr/local/bin/vakta"]
CMD ["agent", "--config", "/etc/vakta/config.yaml"]
