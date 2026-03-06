# List targets
default:
    @just --list

# Build the binary for the current platform
build:
    @mkdir -p build
    go build -o build/hyperhash .

# Remove build artifacts
clean:
    rm -f build/*
    rm -f hyperhash-*.zip

# Build for a specific OS/architecture and package into a zip
# Usage: just dist linux amd64
dist GOOS GOARCH:
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
    BINARY=build/hyperhash
    if [ "{{GOOS}}" = "windows" ]; then
        BINARY=build/hyperhash.exe
    fi
    GOOS={{GOOS}} GOARCH={{GOARCH}} go build -o "${BINARY}" .
    ZIP_NAME="hyperhash-${VERSION}-{{GOOS}}-{{GOARCH}}.zip"
    zip "${ZIP_NAME}" "${BINARY}" README.md LICENSE.txt
    rm -f "${BINARY}"
    echo "Created ${ZIP_NAME}"
