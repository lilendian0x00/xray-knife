#!/bin/bash
# Build script for the Go application
# Usage: ./build.sh <platform>
#
# Available platforms:
#   - macos (or darwin)
#   - win (or windows)
#   - linux
#   - all (builds for all platforms concurrently)

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

# Ensure source file exists
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
    local goarch=${4:-$GOARCH_DEFAULT}  # Default architecture if not provided

    echo "Starting build for $platform..."
    GOOS=$goos GOARCH=$goarch go build \
        -tags="$BUILD_TAGS" \
        -ldflags="$LDFLAGS" \
        -trimpath \
        -o "$BUILD_DIR/$output_name" \
        "$SOURCE_FILE"
    echo "✓ Build successful: $BUILD_DIR/$output_name"
}

# Ensure a platform argument is provided
if [ $# -lt 1 ]; then
    echo "Error: Missing platform argument."
    echo "Usage: $0 <platform>"
    exit 1
fi

# Process command-line argument
case "$1" in
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
        echo "Building for all platforms concurrently..."

        # Launch each build in the background
        build_app "macOS" "$APP_NAME" "darwin" &
        pid_darwin=$!
        build_app "Windows" "${APP_NAME}.exe" "windows" &
        pid_windows=$!
        build_app "Linux" "${APP_NAME}_linux" "linux" &
        pid_linux=$!

        # Wait for all builds and capture exit statuses
        exit_status=0

        wait "$pid_darwin" || { echo "Build failed for macOS"; exit_status=1; }
        wait "$pid_windows" || { echo "Build failed for Windows"; exit_status=1; }
        wait "$pid_linux" || { echo "Build failed for Linux"; exit_status=1; }

        if [ $exit_status -ne 0 ]; then
            echo "One or more builds failed."
            exit 1
        else
            echo "✓ All builds completed successfully!"
        fi
        ;;
    *)
        echo "Error: Invalid or missing platform argument."
        echo "Usage: $0 <platform>"
        echo "Available platforms:"
        echo "  - macos (or darwin)"
        echo "  - win (or windows)"
        echo "  - linux"
        echo "  - all (builds for all platforms concurrently)"
        exit 1
        ;;
esac
