.PHONY: proto dev build docker lint test helm-lint

proto:
	protoc --go_out=. --go_opt=paths=source_relative proto/alert.proto

dev:
	go run ./cmd/central

build:
	CGO_ENABLED=0 go build -ldflags="-w -s" -trimpath -o bin/central ./cmd/central

docker:
	docker build -t muthur-central:local .

lint:
	golangci-lint run ./...

test:
	go test ./... -v -race

helm-lint:
	helm lint helm/muthur-central
