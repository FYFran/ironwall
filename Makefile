.PHONY: build test clean lint install

APP_NAME := ironwall
BUILD_DIR := build
GO := go

# Build for current platform
build:
	$(GO) build -o $(BUILD_DIR)/$(APP_NAME) ./cmd/ironwall

# Build for all platforms
build-all:
	GOOS=linux   GOARCH=amd64 $(GO) build -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64   ./cmd/ironwall
	GOOS=linux   GOARCH=arm64 $(GO) build -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64   ./cmd/ironwall
	GOOS=darwin  GOARCH=amd64 $(GO) build -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64  ./cmd/ironwall
	GOOS=darwin  GOARCH=arm64 $(GO) build -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64  ./cmd/ironwall
	GOOS=windows GOARCH=amd64 $(GO) build -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe ./cmd/ironwall

# Run tests
test:
	$(GO) test ./... -v -count=1

# Run with race detector
test-race:
	$(GO) test ./... -race -count=1

# Format code
fmt:
	$(GO) fmt ./...

# Run linter (requires golangci-lint)
lint:
	golangci-lint run ./...

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Install to $GOPATH/bin
install:
	$(GO) install ./cmd/ironwall

# Run ironwall against testdata
smoke:
	$(GO) run ./cmd/ironwall scan ./testdata/go-vuln --format markdown

# Quick smoke test
smoke-quick:
	$(GO) run ./cmd/ironwall quick ./testdata/go-vuln

# Update dependencies
deps:
	$(GO) get -u ./...
	$(GO) mod tidy
