#!/bin/sh
# Build the distributable install package.
#
#   scripts/package.sh [output-dir]
#
# Produces a tar.gz containing exactly what `install.sh` needs, plus a
# SHA256 file and a file manifest. Deliberately not a wheel: the install path
# for this project is "unpack, run install.sh", and it has to work on a host
# with no pip, no network, and a system Python. A wheel would add a build
# dependency to the one thing that is supposed to have none.
#
# The tree is copied rather than archived in place so that build artefacts,
# caches and local state can never end up inside the package -- shipping
# somebody's secrets.json in a tarball is the classic way this goes wrong.
set -eu
cd "$(dirname "$0")/.."

OUT=${1:-/Ai_Results}
NAME=vigil-guard
VERSION=$(sed -n 's/^__version__ *= *"\(.*\)"/\1/p' src/vigil/version.py)
STAGE=$(mktemp -d)
TOP="$STAGE/$NAME-$VERSION"

echo "打包 $NAME $VERSION -> $OUT"
mkdir -p "$TOP" "$OUT"

# Everything a source install needs, and nothing else.
cp -a install.sh LICENSE README.md DISCLAIMER.md INTRODUCTION.md \
   RELEASE-NOTES.md RETROSPECTIVE.md \
   pyproject.toml \
   .gitignore "$TOP/"
cp -a src "$TOP/src"
cp -a docs "$TOP/docs" 2>/dev/null || true
cp -a examples "$TOP/examples" 2>/dev/null || true
cp -a scripts "$TOP/scripts" 2>/dev/null || true
cp -a tests "$TOP/tests" 2>/dev/null || true

# Strip anything that must never ship.
find "$TOP" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$TOP" -name '*.pyc' -delete 2>/dev/null || true
find "$TOP" -name '*.pyo' -delete 2>/dev/null || true
find "$TOP" -name '.DS_Store' -delete 2>/dev/null || true
rm -f "$TOP"/config.json "$TOP"/secrets.json 2>/dev/null || true
rm -rf "$TOP"/.git 2>/dev/null || true

# Refuse to ship anything that looks like a credential.
if grep -rIl --exclude='*.pyc' -E 're_[A-Za-z0-9]{20,}' "$TOP" 2>/dev/null \
        | grep -v 'providers/resend.py' | grep -q .; then
    echo "拒绝打包：发现疑似密钥" >&2
    grep -rIl --exclude='*.pyc' -E 're_[A-Za-z0-9]{20,}' "$TOP" >&2
    exit 1
fi

TAR="$OUT/$NAME-$VERSION.tar.gz"
tar -czf "$TAR" -C "$STAGE" "$NAME-$VERSION"
rm -rf "$STAGE"

( cd "$OUT" && sha256sum "$(basename "$TAR")" > "$(basename "$TAR").sha256" )
tar -tzf "$TAR" | sed "s|^$NAME-$VERSION/||" | grep -v '/$' | sort > "$OUT/$NAME-$VERSION.manifest"

printf '\n  %s\n  %s\n  %s\n' \
    "$TAR" \
    "$TAR.sha256" \
    "$OUT/$NAME-$VERSION.manifest"
printf '\n  大小 %s，文件 %s 个\n' \
    "$(du -h "$TAR" | cut -f1)" "$(wc -l < "$OUT/$NAME-$VERSION.manifest")"
