#!/usr/bin/env python3
"""AstrBot's shell tool must refuse commands that would stop AstrBot itself.

Twice now the agent has talked itself out of existence:

  2026-10-04 14:53   pkill -f "astrbot"        matched its own command line
  2026-10-04 23:48   systemctl stop astrbot    stopped, and never restarted

`Restart=always` rescues neither: a SIGTERM to the main process and a
deliberate stop are both "clean" endings to systemd, so the unit stayed down.
The guard lives in the tool so the agent is refused with a reason it can read,
instead of silently taking the service with it.
"""
import sys

SHELL_TOOL = ("/opt/astrbot/tools/astrbot/lib/python3.12/site-packages/astrbot/"
              "core/tools/computer_tools/shell.py")

BLOCKED = [
    'systemctl stop astrbot 2>&1; sleep 1; systemctl is-active astrbot',
    'systemctl restart astrbot',
    'systemctl kill astrbot',
    'systemctl stop astrbot.service',
    'service astrbot stop',
    'pkill -f "astrbot" 2>/dev/null; sleep 1; echo done',
    "pkill -f 'astrbot'",
    'pkill -f astrbot',
    'killall astrbot',
]
ALLOWED = [
    'systemctl status astrbot',
    'systemctl restart nginx',
    'journalctl -u astrbot -n 20',
    'ls /root/astrbot/data',
    'cat /opt/astrbot/config.json',
    'grep -rn "wake_prefix" /opt/astrbot/',
]


def main() -> int:
    try:
        src = open(SHELL_TOOL, encoding="utf-8").read()
    except OSError as exc:
        print("读取工具源码失败：%s" % exc)
        return 1
    if "_SELF_STOP_PATTERNS" not in src:
        print("FAIL: 自我保护逻辑不存在（升级可能覆盖了它，需要重新打补丁）")
        return 1

    ns = {}
    start = src.index("_SELF_STOP_PATTERNS")
    end = src.index("@builtin_tool(config=_COMPUTER_RUNTIME_TOOL_CONFIG)")
    exec(src[start:end], ns)                            # noqa: S102
    reject = ns["_reject_self_stop"]

    failed = 0
    for cmd in BLOCKED:
        got = reject(cmd)
        if not got:
            failed += 1
            print("  ✗ 未拦截：%s" % cmd[:60])
    for cmd in ALLOWED:
        got = reject(cmd)
        if got:
            failed += 1
            print("  ✗ 误拦：%s" % cmd[:60])
    print("  拦截用例 %d 个，放行用例 %d 个" % (len(BLOCKED), len(ALLOWED)))
    print("PASS: 自杀命令全部拦截，正常运维命令放行" if not failed
          else "FAIL: %d 项不符合预期" % failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
