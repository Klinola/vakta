.PHONY: web build test

web:
	cd web && npm ci && npm run build
	rm -rf internal/api/web_dist/*
	mkdir -p internal/api/web_dist
	cp -r web/dist/* internal/api/web_dist/

build: web
	CGO_ENABLED=0 go build -o bin/vakta ./cmd/vakta

test:
	CGO_ENABLED=0 go test ./...
