#!/usr/bin/env bash
set -euo pipefail
TASK_DIR="$(mktemp -d)"
trap 'rm -rf "$TASK_DIR"' EXIT
mkdir -p "$TASK_DIR/bin" "$TASK_DIR/fixtures"
printf 'fixture binary\n' > "$TASK_DIR/fixtures/secctl-linux-amd64"
if command -v sha256sum >/dev/null 2>&1; then
  HASH="$(sha256sum "$TASK_DIR/fixtures/secctl-linux-amd64" | awk '{print $1}')"
else
  HASH="$(shasum -a 256 "$TASK_DIR/fixtures/secctl-linux-amd64" | awk '{print $1}')"
fi
printf '%s  secctl-linux-amd64\n' "$HASH" > "$TASK_DIR/fixtures/SHA256SUMS"
cat > "$TASK_DIR/bin/uname" <<'SH'
#!/usr/bin/env bash
if [ "$1" = -s ]; then echo Linux; else echo x86_64; fi
SH
cat > "$TASK_DIR/bin/id" <<'SH'
#!/usr/bin/env bash
echo 1000
SH
cat > "$TASK_DIR/bin/curl" <<'SH'
#!/usr/bin/env bash
URL=""
OUT=""
while [ "$#" -gt 0 ]; do
 case "$1" in
  -o) OUT="$2"; shift 2 ;;
  https://*) URL="$1"; shift ;;
  *) shift ;;
 esac
done
if [ -z "$OUT" ]; then printf '{"tag_name": "v9.9.9"}\n'; else cp "$MOCK_FIXTURES/${URL##*/}" "$OUT"; fi
SH
cat > "$TASK_DIR/bin/sudo" <<'SH'
#!/usr/bin/env bash
case "$1" in
 mkdir) exit 0 ;;
 install) shift 3; cp "$1" "$MOCK_INSTALLED" ;;
 *) exit 99 ;;
esac
SH
chmod +x "$TASK_DIR/bin/"*
export PATH="$TASK_DIR/bin:$PATH" MOCK_FIXTURES="$TASK_DIR/fixtures" MOCK_INSTALLED="$TASK_DIR/installed"
INSTALL_SCRIPT="$(cd "$(dirname "$0")" && pwd)/install.sh"
bash "$INSTALL_SCRIPT" > "$TASK_DIR/good.log"
cmp "$MOCK_INSTALLED" "$TASK_DIR/fixtures/secctl-linux-amd64"
rm "$MOCK_INSTALLED"
printf 'tampered\n' >> "$TASK_DIR/fixtures/secctl-linux-amd64"
if bash "$INSTALL_SCRIPT" > "$TASK_DIR/bad.log" 2>&1; then echo 'FAIL: checksum mismatch accepted'; exit 1; fi
if [ -e "$MOCK_INSTALLED" ]; then echo 'FAIL: installed after mismatch'; exit 1; fi
printf '' > "$TASK_DIR/fixtures/SHA256SUMS"
if bash "$INSTALL_SCRIPT" > "$TASK_DIR/missing.log" 2>&1; then echo 'FAIL: missing checksum accepted'; exit 1; fi
echo 'PASS: installer accepts matching SHA256 and rejects tampering/missing checksums without system writes'
