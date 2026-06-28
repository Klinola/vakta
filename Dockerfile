# syntax=docker/dockerfile:1.7

FROM node:20-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.25-alpine AS go
RUN apk add --no-cache clang llvm libelf-dev linux-headers musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/dist ./internal/api/web_dist
RUN CGO_ENABLED=0 go generate ./internal/probe/... \
 && CGO_ENABLED=0 go build -ldflags "-X main.Version=$(git describe --tags --always 2>/dev/null || echo dev)" -o /out/vakta ./cmd/vakta

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=go /out/vakta /usr/local/bin/vakta
USER 0:0
ENTRYPOINT ["/usr/local/bin/vakta"]
CMD ["agent", "--config", "/etc/vakta/config.yaml"]
