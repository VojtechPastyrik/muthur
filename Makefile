.PHONY: proto proto-check dev build docker lint test helm-lint

proto:
	protoc --go_out=. --go_opt=paths=source_relative proto/alert.proto

# Fail if alert.proto has drifted from the shared contract hash (see
# scripts/check-proto-sync.sh). Keep muthur and muthur-collector in lockstep.
proto-check:
	./scripts/check-proto-sync.sh

dev:
	go run ./cmd/muthur

build:
	CGO_ENABLED=0 go build -ldflags="-w -s" -trimpath -o bin/muthur ./cmd/muthur

docker:
	docker build -t muthur:local .

lint:
	golangci-lint run ./...

test:
	go test ./... -v -race

helm-lint:
	helm lint helm/muthur
