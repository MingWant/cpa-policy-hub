.PHONY: help fmt test build-linux build-darwin build-windows build-all clean

PLUGIN_NAME := cpa-policy-hub
DIST_DIR := dist

help:
	@echo "Targets:"
	@echo "  fmt           Format Go code"
	@echo "  test          Run Go tests/build checks"
	@echo "  build-linux   Build Linux amd64 .so"
	@echo "  build-darwin  Build macOS arm64 .dylib"
	@echo "  build-windows Build Windows amd64 .dll"
	@echo "  build-all     Build common local artifacts"
	@echo "  clean         Remove build outputs"

fmt:
	gofmt -w main.go

test:
	go test ./...

build-linux:
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -buildmode=c-shared -trimpath -ldflags="-s -w" -o $(DIST_DIR)/$(PLUGIN_NAME).so .

build-darwin:
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -buildmode=c-shared -trimpath -ldflags="-s -w" -o $(DIST_DIR)/$(PLUGIN_NAME).dylib .

build-windows:
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -buildmode=c-shared -trimpath -ldflags="-s -w" -o $(DIST_DIR)/$(PLUGIN_NAME).dll .

build-all: build-linux build-darwin build-windows

clean:
	rm -rf $(DIST_DIR) build bin
