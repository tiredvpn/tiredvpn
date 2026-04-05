# Contributing to TiredVPN

## Reporting Issues

- Use [GitHub Issues](https://github.com/tiredvpn/tiredvpn/issues) for bugs and feature requests
- Include: OS, Go version, steps to reproduce, expected vs actual behavior
- For security issues, see [SECURITY.md](SECURITY.md)

## Development Setup

```bash
git clone https://github.com/tiredvpn/tiredvpn.git
cd tiredvpn
go build ./cmd/tiredvpn/
go test ./internal/...
```

Requires Go 1.24+.

## Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Write tests for new functionality
4. Ensure `go test ./internal/...` passes
5. Run `gofmt -s -w .` before committing
6. Submit a PR with a clear description

## Code Style

- Follow standard Go conventions
- Use `gofmt` for formatting
- Keep functions focused and testable
- Write meaningful commit messages: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`

## Code of Conduct

By participating, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).
