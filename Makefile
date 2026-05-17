BINARY     := zeek-bzar-ocsf
VERSION    := 1.0.0
BUILD_DIR  := ./build
CMD_DIR    := ./cmd
LDFLAGS    := -ldflags "-X main.version=$(VERSION) -s -w"

.PHONY: all build clean install uninstall test lint fmt deps

all: build

## Build the binary
build:
	@echo "Building $(BINARY) v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) $(CMD_DIR)/main.go
	@echo "Binary: $(BUILD_DIR)/$(BINARY)"

## Build for Linux amd64 (for cross-compilation)
build-linux:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64 $(CMD_DIR)/main.go

## Run tests
test:
	go test ./... -v -count=1

## Run tests with race detector
test-race:
	go test ./... -race -count=1

## Download dependencies
deps:
	go mod download
	go mod tidy

## Format code
fmt:
	gofmt -s -w .

## Run linter (requires golangci-lint)
lint:
	golangci-lint run ./...

## Install service (requires root)
install: build
	@echo "Installing $(BINARY)..."
	$(BUILD_DIR)/$(BINARY) install --binary $(BUILD_DIR)/$(BINARY) --config configs/config.yaml

## Uninstall service (requires root)
uninstall:
	@echo "Uninstalling $(BINARY)..."
	$(BUILD_DIR)/$(BINARY) uninstall

## Uninstall and remove config files
purge:
	@echo "Purging $(BINARY)..."
	$(BUILD_DIR)/$(BINARY) uninstall --purge

## Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

## Show help
help:
	@echo "zeek-bzar-ocsf Makefile targets:"
	@echo ""
	@echo "  make build        - Build binary"
	@echo "  make build-linux  - Cross-compile for Linux amd64"
	@echo "  make test         - Run tests"
	@echo "  make test-race    - Run tests with race detector"
	@echo "  make deps         - Download and tidy dependencies"
	@echo "  make fmt          - Format source code"
	@echo "  make lint         - Run linter"
	@echo "  make install      - Install as systemd service (root)"
	@echo "  make uninstall    - Remove systemd service (root)"
	@echo "  make purge        - Remove service and config (root)"
	@echo "  make clean        - Remove build artifacts"
