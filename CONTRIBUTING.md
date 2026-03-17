# Contributing to hip-sdk-go

Thank you for your interest in contributing to the Human Identity Protocol Go SDK.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/hip-sdk-go.git`
3. Create a branch: `git checkout -b your-feature`
4. Make your changes
5. Run tests: `go test ./... -count=1`
6. Commit and push
7. Open a pull request

## Development

Requirements: Go 1.24+

```bash
# Run tests
go test ./... -v -count=1

# Run linter
go vet ./...
gofmt -d .
```

## Guidelines

- Write idiomatic Go. Follow [Effective Go](https://go.dev/doc/effective_go)
- Add tests for new functionality
- Keep the API surface small — this SDK should be simple to use
- No external dependencies beyond the Go standard library and `github.com/google/uuid`
- All cryptographic operations use Go's standard `crypto` package

## Pull Requests

- One concern per PR
- Include tests
- Update README if the public API changes
- Describe what changed and why

## Reporting Issues

Open an issue at https://github.com/nellcorp/hip-sdk-go/issues

## Security

If you discover a security vulnerability, please report it responsibly. See [SECURITY.md](SECURITY.md).
