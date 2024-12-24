#!/bin/bash

# Build script for the Go application
# Usage: ./build.sh <platform>

# Enable strict error handling
set -euo pipefail

# Configuration
APP_NAME="xray-knife"
BUILD_DIR="build"
SOURCE_FILE="main.go"

# Common build configuration
BUILD_TAGS="with_gvisor,with_quic,with_wireguard,with_ech,with_utls,with_clash_api,with_grpc"
LDFLAGS="-s -w"
GOARCH_DEFAULT="amd64"

# Verify source file exists
if [ ! -f "$SOURCE_FILE" ]; then
    echo "Error: Source file '$SOURCE_FILE' not found."
    exit 1
fi

# Create build directory if it doesn't exist
mkdir -p "$BUILD_DIR"

# Build function
build_app() {
    local platform=$1
    local output_name=$2
    local goos=$3
    local goarch=${4:-$GOARCH_DEFAULT}  # Default to GOARCH_DEFAULT if not provided

    echo "Building for $platform..."

    # Set environment variables for cross-compilation
    GOOS=$goos GOARCH=$goarch go build \
        -tags="$BUILD_TAGS" \
        -ldflags="$LDFLAGS" \
        -trimpath \
        -o "$BUILD_DIR/$output_name" \
        "$SOURCE_FILE"

    echo "✓ Build successful: $BUILD_DIR/$output_name"
}

# Process command-line argument
case "${1:-}" in
    "macos"|"darwin")
        build_app "macOS" "$APP_NAME" "darwin"
        ;;
    "win"|"windows")
        build_app "Windows" "${APP_NAME}.exe" "windows"
        ;;
    "linux")
        build_app "Linux" "$APP_NAME" "linux"
        ;;
    "all")
        build_app "macOS" "$APP_NAME" "darwin"
        build_app "Windows" "${APP_NAME}.exe" "windows"
        build_app "Linux" "${APP_NAME}_linux" "linux"
        ;;
    *)
        echo "Error: Invalid or missing platform argument."
        echo "Usage: $0 <platform>"
        echo "Available platforms:"
        echo "  - macos (or darwin)"
        echo "  - win (or windows)"
        echo "  - linux"
        echo "  - all (builds for all platforms)"
        exit 1
        ;;
esac
