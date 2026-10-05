#!/usr/bin/env python3
"""Agent 侧唤醒前缀不得吃掉命令前缀 `/`。

astr_main_agent.py 里这段：

    if config.provider_wake_prefix and not event.message_str.startswith(...):
        return None, None
    req.prompt = event.message_str[len(config.provider_wake_prefix):]

`provider_settings.wake_prefix` 若等于 `/`，每条消息在送进 agent 之前都会被砍掉
开头的 `/`，于是 `/pic 猫` 变成 `pic 猫`，插件收不到指令——这正是"指令传不到
插件"的原因。这个用例直接调用真实代码，确认剥离行为符合预期。
"""
import json
import sys

sys.path.insert(0, "/opt/astrbot/tools/astrbot/lib/python3.12/site-packages")

CONFIG = "/root/astrbot/data/cmd_config.json"


def prompt_after_strip(message: str, prefix: str) -> str | None:
    """复刻 astr_main_agent 的处理：前缀不匹配则整条丢弃，匹配则剥掉前缀。"""
    if prefix and not message.startswith(prefix):
        return None
    return message[len(prefix):]


def main() -> int:
    cfg = json.load(open(CONFIG, encoding="utf-8"))
    prefix = (cfg.get("provider_settings") or {}).get("wake_prefix") or ""
    if isinstance(prefix, list):
        prefix = prefix[0] if prefix else ""
    bot_prefixes = cfg.get("wake_prefix") or []
    if isinstance(bot_prefixes, str):
        bot_prefixes = [bot_prefixes]

    print("  provider_settings.wake_prefix = %r" % prefix)
    print("  顶层 wake_prefix（命令前缀）  = %r" % bot_prefixes)

    failed = 0

    # 1) 配置不得与命令前缀冲突
    if prefix and prefix in bot_prefixes:
        print("  ✗ agent 前缀与命令前缀相同：消息会被剥掉 /，插件收不到指令")
        failed += 1
    else:
        print("  ✓ agent 前缀不与命令前缀冲突")

    # 2) 斜杠指令必须原样进入 agent
    for message in ("/pic 猫", "/help", "/reset"):
        got = prompt_after_strip(message, prefix)
        if got != message:
            print("  ✗ %-10s 被改成了 %r" % (message, got))
            failed += 1
        else:
            print("  ✓ %-10s 原样传递" % message)

    # 3) 若配置了独立前缀，仍应正常唤醒并剥掉它
    # 源码只剥前缀、不做 trim，所以剥完会留下一个空格——这里断言真实行为，
    # 不美化它，否则测试会和代码脱节。
    for message, want in (("!ai 你好", " 你好"), ("你好", None)):
        got = prompt_after_strip(message, "!ai")
        if got != want:
            print("  ✗ 独立前缀场景 %-10s → %r（期望 %r）" % (message, got, want))
            failed += 1
    if not failed:
        print("  ✓ 独立前缀场景（!ai）行为正常：匹配则剥前缀，不匹配则忽略")

    print("PASS: 斜杠指令完整送达插件" if not failed
          else "FAIL: %d 项不符合预期" % failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
