#!/bin/bash
# Build script for the Go application
# Usage: ./build.sh <platform>
#
# Available platforms (OS):
#   - macos (or darwin)
#   - win (or windows)
#   - linux
#   - all (builds for all platforms concurrently)
#
# Optional second argument for architecture: <arch> (amd64, arm64, armv7).
# Defaults to amd64. armv7 is Linux-only.

# Enable strict error handling
set -euo pipefail

# Configuration
APP_NAME="xray-knife"
BUILD_DIR="build"
SOURCE_FILE="main.go"

# Common build configuration
BUILD_TAGS="with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_grpc"

# Stamp the version into the binary so `xray-knife -V` reports what it was
# actually built from. Override with VERSION=... ./build.sh
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
MODULE_PATH="github.com/lilendian0x00/xray-knife/v11"
LDFLAGS="-s -w -X ${MODULE_PATH}/cmd.version=${VERSION#v}"
# GOARCH_DEFAULT is set in build_app based on argument or default

# Ensure source file exists
if [ ! -f "$SOURCE_FILE" ]; then
    echo "Error: Source file '$SOURCE_FILE' not found."
    exit 1
fi

# Refresh the compressed embedded frontend once, before any parallel builds.
# Generate for the host even if the caller exports cross-compilation targets.
GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go generate ./web

# Create build directory if it doesn't exist
mkdir -p "$BUILD_DIR"

# Build function
build_app() {
    local platform=$1
    local output_name=$2
    local target_goos=$3
    local target_goarch=$4
    # GOARM only means anything for GOARCH=arm; Go ignores it elsewhere, so an
    # empty value is safe for every other target.
    local target_goarm=${5:-}

    echo "Starting build for $platform ($target_goos/$target_goarch${target_goarm:+v$target_goarm})..."
    GOOS=$target_goos GOARCH=$target_goarch GOARM=$target_goarm go build \
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
    echo "Usage: $0 <platform> [amd64|arm64|armv7]"
    exit 1
fi

# Determine architecture: use $2 if provided, otherwise default to amd64
arch_arg=${2:-"amd64"}

# Map the architecture label to a GOARCH/GOARM pair. GOARCH=arm on its own is
# ambiguous — v5, v6 and v7 differ only by GOARM — so the label carries the
# version and names the output accordingly. armv7 is hard-float (VFPv3), which
# is what plain GOARM=7 means.
case "$arch_arg" in
    "amd64"|"arm64")
        goarch="$arch_arg"
        goarm=""
        ;;
    "armv7")
        goarch="arm"
        goarm="7"
        ;;
    *)
        echo "Error: Invalid architecture '$arch_arg'. Supported: amd64, arm64, armv7."
        echo "Usage: $0 <platform> [amd64|arm64|armv7]"
        exit 1
        ;;
esac

# 32-bit ARM is Linux-only here: Go has no darwin/arm target at all, and
# windows/arm is outside the release matrix.
if [ "$arch_arg" = "armv7" ] && [ "$1" != "linux" ] && [ "$1" != "all" ]; then
    echo "Error: armv7 is only supported on linux (got '$1')."
    exit 1
fi


# Process command-line argument
case "$1" in
    "macos"|"darwin")
        build_app "macOS" "${APP_NAME}_darwin_${arch_arg}" "darwin" "$goarch" "$goarm"
        ;;
    "win"|"windows")
        build_app "Windows" "${APP_NAME}_windows_${arch_arg}.exe" "windows" "$goarch" "$goarm"
        ;;
    "linux")
        build_app "Linux" "${APP_NAME}_linux_${arch_arg}" "linux" "$goarch" "$goarm"
        ;;
    "all")
        echo "Building for all supported OS/architecture combinations concurrently..."

        # Launch each build in the background
        # For 'all', we build for both amd64 and arm64 for each OS
        pids=()
        build_app "macOS (amd64)" "${APP_NAME}_darwin_amd64" "darwin" "amd64" & pids+=($!)
        build_app "macOS (arm64)" "${APP_NAME}_darwin_arm64" "darwin" "arm64" & pids+=($!)
        build_app "Windows (amd64)" "${APP_NAME}_windows_amd64.exe" "windows" "amd64" & pids+=($!)
        build_app "Windows (arm64)" "${APP_NAME}_windows_arm64.exe" "windows" "arm64" & pids+=($!)
        build_app "Linux (amd64)" "${APP_NAME}_linux_amd64" "linux" "amd64" & pids+=($!)
        build_app "Linux (arm64)" "${APP_NAME}_linux_arm64" "linux" "arm64" & pids+=($!)
        build_app "Linux (armv7)" "${APP_NAME}_linux_armv7" "linux" "arm" "7" & pids+=($!)

        # Wait for all builds and capture exit statuses
        exit_status=0
        for pid in "${pids[@]}"; do
            wait "$pid" || { echo "A build failed (PID: $pid)"; exit_status=1; }
        done

        if [ $exit_status -ne 0 ]; then
            echo "One or more builds failed."
            exit 1
        else
            echo "✓ All builds completed successfully!"
        fi
        ;;
    *)
        echo "Error: Invalid or missing platform argument."
        echo "Usage: $0 <platform> [amd64|arm64|armv7]"
        echo "Available platforms (OS):"
        echo "  - macos (or darwin)"
        echo "  - win (or windows)"
        echo "  - linux"
        echo "  - all (builds for all OS/arch combinations concurrently)"
        echo "Available architectures: amd64, arm64, armv7 (defaults to amd64; armv7 is Linux-only)"
        exit 1
        ;;
esac