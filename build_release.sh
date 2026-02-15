#!/bin/bash

# Define version
VERSION="v1.0.0" 

OUTPUT_DIR="bin"
mkdir -p "$OUTPUT_DIR"
# rm -f "$OUTPUT_DIR"/* # Don't remove if we want to keep what we have, but better to start clean. Let's keep cleaning.
rm -f "$OUTPUT_DIR"/*

echo "Building release binaries..."

build() {
  local GOOS=$1
  local GOARCH=$2
  local EXT=$3
  local OUT="$OUTPUT_DIR/icmptunnel-${GOOS}-${GOARCH}${EXT}"
  
  echo "Building for ${GOOS}/${GOARCH}..."
  if CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="-s -w" -o "$OUT" .; then
    echo "  -> Success: $OUT"
  else
    echo "  -> FAILED: ${GOOS}/${GOARCH}"
  fi
}

# Linux
build linux amd64 ""
build linux 386 ""
build linux arm64 ""
build linux arm ""
build linux mips ""
build linux mipsle ""

# Darwin (macOS)
build darwin amd64 ""
build darwin arm64 ""

# Windows
build windows amd64 ".exe"
build windows 386 ".exe"

echo "Build process finished."
ls -lh "$OUTPUT_DIR"

