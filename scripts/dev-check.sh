#!/bin/sh
# Everything CI would run, runnable by hand.
#
#   scripts/dev-check.sh
#
# No network, no services, nothing to install: the promise of this project is
# that a locked-down host can run it, and the same has to be true of its
# checks.
set -eu
cd "$(dirname "$0")/.."

fail=0
say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

say "Python 语法"
python3 -m compileall -q src tests >/dev/null && echo "  ok"

say "单元测试"
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' || fail=1

say "零第三方依赖"
if python3 - <<'PY'
import sys
sys.path.insert(0, 'src')
from vigil.core import paths  # noqa: F401
PY
then echo "  ok"; else echo "  失败：导入 src/vigil 需要第三方包"; fail=1; fi

say "不内嵌本机信息"
PYTHONPATH=src python3 -m unittest tests.test_vigil.TestNoHardcodedHostData \
    tests.test_vigil.TestPackaging || fail=1

say "网关前端脚本语法"
if command -v node >/dev/null 2>&1; then
    # `.js` matters: node refuses to parse a file whose extension it does not
    # recognise, and a check that fails without setting `fail` is worse than
    # no check at all -- it reads as a pass.
    tmp=$(mktemp --suffix=.js)
    sed -n '/^<script nonce/,/^<\/script>/p' \
        src/vigil/gates/templates/verify.php.tmpl | sed '1d;$d' > "$tmp"
    if node --check "$tmp"; then
        echo "  ok"
    else
        echo "  网关前端脚本语法错误"
        fail=1
    fi
    rm -f "$tmp"
else
    echo "  跳过（本机没有 node）"
fi

say "PHP 模板语法"
# The templates need PHP 7.4 or newer. A control panel often puts an older
# build first on PATH -- this host has 5.6 there -- and linting the templates
# with it reports a wall of syntax errors that are really just an old parser.
php_bin=""
for cand in php php8.2 php8.1 php8.0 php7.4 \
            /www/server/php/82/bin/php /usr/local/bin/php; do
    have=$(command -v "$cand" 2>/dev/null || true)
    [ -n "$have" ] || continue
    ver=$("$have" -r 'echo PHP_VERSION_ID;' 2>/dev/null || echo 0)
    if [ "$ver" -ge 70400 ] 2>/dev/null; then php_bin="$have"; break; fi
done
if [ -n "$php_bin" ]; then
    for f in src/vigil/gates/templates/*.php.tmpl \
             src/vigil/gates/templates/lib/*.php.tmpl; do
        "$php_bin" -l "$f" >/dev/null || { echo "  $f 语法错误"; fail=1; }
    done
    echo "  ok（$php_bin，$("$php_bin" -r 'echo PHP_VERSION;')）"
else
    echo "  跳过（没有 PHP >= 7.4；模板要求 7.4+）"
fi

say "Lua 网关语法"
if command -v luac >/dev/null 2>&1; then
    luac -p src/vigil/gates/templates/gate.lua.tmpl && echo "  ok"
else
    echo "  跳过（本机没有 luac）"
fi

if [ "$fail" -ne 0 ]; then
    printf '\n\033[31m有检查未通过\033[0m\n'
    exit 1
fi
printf '\n\033[32m全部通过\033[0m\n'
