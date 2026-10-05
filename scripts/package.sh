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
      dashboard \
      pyproject.toml README.md CHANGELOG.md LICENSE DISCLAIMER.md \
      SECURITY.md CONTRIBUTING.md .gitignore "$L/" 2>/dev/null || true

# 工作树里有**只属于这一台机器**的文件 —— 操作员自己的禁止清单
# (tools/source-forbid.txt，里面逐条写着本机域名与名字)、dashboard/config.json
# (写着真实域名与坐标)、以及各种缓存。它们都被 .gitignore 忽略，原因正是
# 「绝不出现在包里」；`cp -a` 会把它们一起抄进来。**忽略规则本身就是过滤器**，
# 所以这里按忽略规则清一遍：审计只看仓库根，包里漏出去的东西它看不到。
if git rev-parse --git-dir >/dev/null 2>&1; then
  while IFS= read -r -d '' f; do
    rel="${f#"$L"/}"
    if git check-ignore -q -- "$rel"; then rm -f "$f"; fi
  done < <(find "$L" -type f -print0)
fi
find "$L" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

# 最后一道：本地专属文件一个都不许留在包里，否则直接失败而不是发布。
for junk in tools/source-forbid.txt dashboard/config.json; do
  if [ -e "$L/$junk" ]; then
    echo "打包中止：本地专属文件混进了发布包：$junk" >&2
    exit 1
  fi
done
tar -czf "$OUT/vigil-guard-${VERSION}-linux.tar.gz" -C "$STAGE" "vigil-guard-${VERSION}"

echo "==> 校验和"
( cd "$OUT" && sha256sum ./*.tar.gz > SHA256SUMS.txt )
ls -lh "$OUT"
