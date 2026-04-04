# Contributing

## Development setup

```bash
# Install dependencies
go mod download

# Generate protobuf (required before building)
make proto

# Run tests
make test

# Lint
make lint

# Lint Helm chart
make helm-lint
```

## PR guidelines

- Run `make test` and `make lint` before submitting
- Keep commits focused and descriptive
- No secrets in commits — use `.env` for local dev (it's gitignored)
- Proto changes must be synced with muthur-collector

## Project structure

- `cmd/central/` — entry point
- `internal/` — all business logic
- `proto/` — shared protobuf schema
- `helm/` — Helm chart source (synced to charts repo via CI)
