#!/usr/bin/env bash
set -euo pipefail

REPO="9star-academy/secctl"
BIN_NAME="secctl"
INSTALL_DIR="/usr/local/bin"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "错误: 不支持的架构 $ARCH"; exit 1 ;;
esac
case "$OS" in linux|darwin) ;; *) echo "错误: 不支持的操作系统 $OS"; exit 1 ;; esac

TAG="${SECCTL_VERSION:-}"
if [ -z "$TAG" ]; then
  TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -nE 's/.*"tag_name": *"([^"]+)".*/\1/p')"
fi
if [[ ! "$TAG" =~ ^v[0-9][a-zA-Z0-9._-]*$ ]]; then
  echo "错误: 无法获取有效发布版本，请检查 GitHub 连接或设置 SECCTL_VERSION" >&2
  exit 1
fi
FILE="${BIN_NAME}-${OS}-${ARCH}"
BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "==> 下载并校验 ${BIN_NAME} ${TAG} (${OS}/${ARCH})..."
curl -fsSL "${BASE_URL}/${FILE}" -o "${TMP_DIR}/${FILE}"
curl -fsSL "${BASE_URL}/SHA256SUMS" -o "${TMP_DIR}/SHA256SUMS"
EXPECTED="$(awk -v name="$FILE" '$2 == name {print $1}' "${TMP_DIR}/SHA256SUMS")"
if [[ ! "$EXPECTED" =~ ^[a-fA-F0-9]{64}$ ]]; then
  echo "错误: 发布文件缺少有效 SHA256，停止安装" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "${TMP_DIR}/${FILE}" | awk '{print $1}')"
else
  ACTUAL="$(shasum -a 256 "${TMP_DIR}/${FILE}" | awk '{print $1}')"
fi
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "错误: SHA256 校验失败，停止安装" >&2
  exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
  mkdir -p "$INSTALL_DIR"
  install -m 0755 "${TMP_DIR}/${FILE}" "${INSTALL_DIR}/${BIN_NAME}"
else
  sudo mkdir -p "$INSTALL_DIR"
  sudo install -m 0755 "${TMP_DIR}/${FILE}" "${INSTALL_DIR}/${BIN_NAME}"
fi
echo "✔ 安装成功。运行 secctl --help。"
