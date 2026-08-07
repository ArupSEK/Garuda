#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

case "$(uname -m)" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

HTTPX_VERSION="1.9.0"
NUCLEI_VERSION="3.11.0"
NAABU_VERSION="2.6.1"
DNSX_VERSION="1.3.0"
GOWITNESS_VERSION="3.1.1"
NUCLEI_TEMPLATES_COMMIT="83234ce456da3e90dda86dfbc5e605e64a846df3"
TESTSSL_COMMIT="97763a411c525720a5f9bd9d2cded416b10f210a"
INSTALL_ROOT="${GARUDA_INSTALL_ROOT:-/opt/garuda}"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TEMP_DIR"' EXIT

$SUDO apt-get update
$SUDO apt-get install -y --no-install-recommends \
  ca-certificates chromium curl git nmap openssl python3 python3-pip python3-venv unzip

python3 -c 'import sys; assert sys.version_info >= (3, 12), "Python 3.12 or newer is required"'

install_projectdiscovery() {
  local tool="$1" version="$2" checksum_file="$3" destination="$4"
  local asset="${tool}_${version}_linux_${ARCH}.zip"
  local release="https://github.com/projectdiscovery/${tool}/releases/download/v${version}"
  curl --http1.1 --retry 5 --retry-all-errors --connect-timeout 30 \
    -fsSLo "$TEMP_DIR/$asset" "$release/$asset"
  curl --http1.1 --retry 5 --retry-all-errors --connect-timeout 30 \
    -fsSLo "$TEMP_DIR/$checksum_file" "$release/$checksum_file"
  (
    cd "$TEMP_DIR"
    grep -F "  $asset" "$checksum_file" | sha256sum -c -
  )
  rm -rf -- "$TEMP_DIR/$tool"
  mkdir -p "$TEMP_DIR/$tool"
  unzip -q "$TEMP_DIR/$asset" -d "$TEMP_DIR/$tool"
  $SUDO install -m 0755 "$TEMP_DIR/$tool/$tool" "/usr/local/bin/$destination"
}

install_projectdiscovery httpx "$HTTPX_VERSION" "httpx_${HTTPX_VERSION}_checksums.txt" httpx-pd
install_projectdiscovery nuclei "$NUCLEI_VERSION" "nuclei_${NUCLEI_VERSION}_checksums.txt" nuclei
install_projectdiscovery naabu "$NAABU_VERSION" naabu-checksums.txt naabu
install_projectdiscovery dnsx "$DNSX_VERSION" "dnsx_${DNSX_VERSION}_checksums.txt" dnsx

case "$ARCH" in
  amd64) GOWITNESS_SHA256="57b3188e24782c27fdf72493ce599537efd3187d03b80f8afe733c72d68c5517" ;;
  arm64) GOWITNESS_SHA256="a24284b4df4ea94a34edc55232b5d102555dcd01c73b1eb950ac4e304f753784" ;;
esac
GOWITNESS_ASSET="gowitness-${GOWITNESS_VERSION}-linux-${ARCH}"
curl --http1.1 --retry 5 --retry-all-errors --connect-timeout 30 \
  -fsSLo "$TEMP_DIR/$GOWITNESS_ASSET" \
  "https://github.com/sensepost/gowitness/releases/download/${GOWITNESS_VERSION}/${GOWITNESS_ASSET}"
echo "$GOWITNESS_SHA256  $TEMP_DIR/$GOWITNESS_ASSET" | sha256sum -c -
$SUDO install -m 0755 "$TEMP_DIR/$GOWITNESS_ASSET" /usr/local/bin/gowitness

curl --http1.1 --retry 5 --retry-all-errors --connect-timeout 30 \
  -fsSLo "$TEMP_DIR/nuclei-templates.tar.gz" \
  "https://github.com/projectdiscovery/nuclei-templates/archive/${NUCLEI_TEMPLATES_COMMIT}.tar.gz"
curl --http1.1 --retry 5 --retry-all-errors --connect-timeout 30 \
  -fsSLo "$TEMP_DIR/testssl.tar.gz" \
  "https://github.com/testssl/testssl.sh/archive/${TESTSSL_COMMIT}.tar.gz"
$SUDO mkdir -p \
  "$INSTALL_ROOT/nuclei-templates-$NUCLEI_TEMPLATES_COMMIT" \
  "$INSTALL_ROOT/testssl-$TESTSSL_COMMIT"
$SUDO tar -xzf "$TEMP_DIR/nuclei-templates.tar.gz" --strip-components=1 \
  -C "$INSTALL_ROOT/nuclei-templates-$NUCLEI_TEMPLATES_COMMIT"
$SUDO tar -xzf "$TEMP_DIR/testssl.tar.gz" --strip-components=1 \
  -C "$INSTALL_ROOT/testssl-$TESTSSL_COMMIT"
$SUDO ln -sfn \
  "$INSTALL_ROOT/nuclei-templates-$NUCLEI_TEMPLATES_COMMIT" \
  "$INSTALL_ROOT/nuclei-templates"
$SUDO ln -sfn "$INSTALL_ROOT/testssl-$TESTSSL_COMMIT/testssl.sh" /usr/local/bin/testssl.sh

python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev,pdf]'

echo "Installed the pinned Garuda scanner suite."
echo "Set NUCLEI_TEMPLATES_PATH=$INSTALL_ROOT/nuclei-templates in .env for native runs."
./scripts/check_dependencies.sh
