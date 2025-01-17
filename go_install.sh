#!/bin/bash

TEMP_DIR="/tmp/go_install"
INSTALL_DIR="/usr/local"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    armv8*|aarch64) ARCH="arm64" ;;
    armv7*) ARCH="armv6l" ;;
esac
GO_ARCH="${OS}-${ARCH}"
echo "Detected architecture: $GO_ARCH"

echo "Fetching the latest Go version..."
LATEST_VERSION=$(curl -s https://go.dev/dl/ | grep -o 'go[0-9]\+\.[0-9]\+\(\.[0-9]\+\)\?' | head -1)

if [[ -z "$LATEST_VERSION" ]]; then
    echo "Failed to fetch the latest Go version. Please check your internet connection."
    exit 1
fi

echo "Latest version found: $LATEST_VERSION"

GO_TAR="${LATEST_VERSION}.${GO_ARCH}.tar.gz"
GO_URL="https://go.dev/dl/${GO_TAR}"

echo "Downloading ${GO_TAR}..."
mkdir -p "$TEMP_DIR"
curl -Lo "$TEMP_DIR/$GO_TAR" "$GO_URL"
if [[ $? -ne 0 ]]; then
    echo "Failed to download Go. Please check the URL or your connection."
    exit 1
fi

echo "Removing any previous Go installation..."
sudo rm -rf "$INSTALL_DIR/go"

echo "Extracting Go archive..."
sudo tar -C "$INSTALL_DIR" -xzf "$TEMP_DIR/$GO_TAR"
if [[ $? -ne 0 ]]; then
    echo "Failed to extract the Go archive."
    exit 1
fi

PROFILE_FILE="$HOME/.bashrc"
if ! grep -q "export PATH=\$PATH:/usr/local/go/bin" "$PROFILE_FILE"; then
    echo "Adding Go to PATH..."
    echo 'export PATH=$PATH:/usr/local/go/bin' >> "$PROFILE_FILE"
    source "$PROFILE_FILE"
fi

echo "Verifying Go installation..."
if command -v go &> /dev/null; then
    echo "Go installed successfully: $(go version)"
else
    echo "Go installation failed."
    exit 1
fi

echo "Cleaning up..."
rm -rf "$TEMP_DIR"