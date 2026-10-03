#!/usr/bin/env bash
# 打发布包：Linux 源码包 + Windows 便携子集包 + 校验和。
# 只打包，不发布；发布由 gh release 完成。
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="$(python3 -c "import sys; sys.path.insert(0,'src'); from vigil.version import __version__; print(__version__)")"
OUT="dist"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
rm -rf "$OUT"; mkdir -p "$OUT"

echo "==> 打 Linux 源码包 vigil-guard-${VERSION}-linux"
L="$STAGE/vigil-guard-${VERSION}"
mkdir -p "$L"
cp -a src tests docs tools scripts examples packaging install.sh \
      pyproject.toml README.md CHANGELOG.md LICENSE DISCLAIMER.md \
      SECURITY.md CONTRIBUTING.md .gitignore "$L/" 2>/dev/null || true
find "$L" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
tar -czf "$OUT/vigil-guard-${VERSION}-linux.tar.gz" -C "$STAGE" "vigil-guard-${VERSION}"

echo "==> 校验和"
( cd "$OUT" && sha256sum ./*.tar.gz > SHA256SUMS.txt )
ls -lh "$OUT"
