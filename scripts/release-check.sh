#!/bin/sh
# 发布前的关卡。任何一步失败就停下，不推 tag、不发 release。
#
#   scripts/release-check.sh            全部检查
#   scripts/release-check.sh --allow-flaky   允许「首轮失败、复跑通过」的情况通过
#
# 为什么要有这个东西：v2.3.0 第一次发布时，全套测试 4 项失败、源码审计 1 项违规，
# 而当时的发布命令没有关卡 —— tag 和 release 照样推出去了。**红构建被发出去，
# 是流程问题，不是运气问题。**
#
# 为什么先跑一遍再挑失败项复跑：这个项目里出现过「首轮失败、接着两次都通过」的
# 间歇性失败。对这种情况，**不该悄悄放过，也不该凭一次复跑就宣布没事** ——
# 脚本会把 FLAKY 显著地打出来，并要求显式加 --allow-flaky 才继续。
# 把它藏起来是最糟的处理方式：它会以「偶尔抽风」的形式留在项目里。
set -u
cd "$(dirname "$0")/.."

ALLOW_FLAKY=0
[ "${1:-}" = "--allow-flaky" ] && ALLOW_FLAKY=1
fail=0
say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

say "Python 语法"
python3 -m compileall -q src tests >/dev/null && echo "  ok" || { echo "  失败"; exit 1; }

say "单元测试"
LOG=$(mktemp)
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' >"$LOG" 2>&1
if [ $? -eq 0 ]; then
    grep -E '^(Ran |OK)' "$LOG" | sed 's/^/  /'
else
    grep -E '^(Ran |FAILED)' "$LOG" | sed 's/^/  /'
    grep -E '^(FAIL|ERROR):' "$LOG" | sed 's/^/    /'
    # unittest 的失败行长这样：`FAIL: test_x (mod.Cls)`，而复跑需要的是
    # `mod.Cls.test_x`。第一版用 sed 提取，写成了基本正则（`(A|B)` 在 BRE 里
    # 不是交替），结果提取出空 ID、复跑退化成「再跑一遍全套」，
    # FLAKY 那条分支永远不会触发 —— 关卡自己的 bug，是测试它时才发现的。
    IDS=$(grep -E '^(FAIL|ERROR):' "$LOG" | python3 -c "
import re, sys
out = []
for line in sys.stdin:
    m = re.match(r'^(?:FAIL|ERROR): (\\S+) \\((.+)\\)', line.strip())
    if not m:
        continue
    method, owner = m.group(1), m.group(2)
    out.append(owner if owner.endswith('.' + method) else owner + '.' + method)
print(' '.join(sorted(set(out))))
")
    echo "  → 复跑失败项，判断是真失败还是间歇性失败：$IDS"
    # 复跑要给 `tests` 也加上导入路径：显式点名 `mod.Cls.method` 时，
    # unittest 需要能 import 那个模块，而 tests/ 不在默认路径上。
    # 第一版漏了这点，复跑直接 ImportError，被误判成「真失败」。
    # shellcheck disable=SC2086
    PYTHONPATH="src:tests" python3 -m unittest $IDS >"$LOG.retry" 2>&1
    if [ $? -eq 0 ]; then
        printf '\n  \033[1m!! FLAKY !! 首轮失败、复跑通过：%s\033[0m\n' "$IDS"
        echo "  这不是「没事」：间歇性失败会以「偶尔抽风」的形式留在项目里。"
        echo "  请定位根因（多半是依赖了宿主机负载/时间/网络）。"
        [ "$ALLOW_FLAKY" -eq 1 ] || { fail=1; }
    else
        echo "  真失败（复跑同样失败）"; fail=1
    fi
fi
rm -f "$LOG" "$LOG.retry"

say "源码审计（不得含宿主机信息）"
N=$(PYTHONPATH=src python3 -c "from vigil.core import sourceaudit; print(len(sourceaudit.scan('.')))")
echo "  违规 $N 处"
[ "$N" = "0" ] || fail=1

[ "$fail" -eq 0 ] || { printf '\n\033[1m关卡未通过，禁止发布。\033[0m\n'; exit 1; }

say "打包"
./scripts/package.sh >/dev/null 2>&1 && ls -1 dist | sed 's/^/  /'
echo
echo "关卡通过，可以发布。"
