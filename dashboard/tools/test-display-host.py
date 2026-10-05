#!/usr/bin/env python3
"""界面显示的域名必须是给人看的原文，不是 punycode。

同一个域名有两种写法：ASCII（punycode）是证书、vhost 与 Host 头必须的
形式，给人看则是一串乱码。PUBLIC_HOST 保持 ASCII，DISPLAY_HOST 是它的
Unicode 形式（或配置里的 display_name），面板顶栏与页面标题用后者。
具体域名来自 config.json，这个文件里没有任何一个。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import settings  # noqa: E402


def main() -> int:
    failed = 0
    ascii_host = settings.PUBLIC_HOST
    display = settings.DISPLAY_HOST

    print("  PUBLIC_HOST  = %s  ← 证书 / vhost / Host 头" % ascii_host)
    print("  DISPLAY_HOST = %s  ← 界面显示" % display)

    if "xn--" in ascii_host:
        if "xn--" in display:
            print("  ✗ DISPLAY_HOST 仍是 punycode")
            failed += 1
        else:
            print("  ✓ DISPLAY_HOST 已解码为中文")
    else:
        print("  · 配置里本就没有 punycode，跳过解码检查")

    # 必须能解回同一个域名，否则证书与显示就对不上了
    try:
        back = display.encode("idna").decode("ascii")
    except (UnicodeError, ValueError) as exc:
        print("  ✗ DISPLAY_HOST 无法解回 ASCII：%s" % exc)
        failed += 1
    else:
        if back == ascii_host:
            print("  ✓ 与 PUBLIC_HOST 是同一个域名（可逆）")
        else:
            print("  ✗ 解回后不一致：%s" % back)
            failed += 1

    # 站点列表里的名字同样要本地化，否则「站点开关」页满屏 xn--
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from backend import sites as sites_mod
        listing = sites_mod.sites.list_sites()
    except Exception as exc:                            # noqa: BLE001
        print("  · 跳过站点名检查（%s）" % exc)
        listing = []
    if listing:
        raw_left = [s for s in listing if "xn--" in (s.get("primary") or "")]
        if raw_left:
            print("  ✗ 仍有 %d 个站点的显示名是 punycode：%s"
                  % (len(raw_left), raw_left[0]["primary"]))
            failed += 1
        else:
            print("  ✓ %d 个站点的显示名已本地化" % len(listing))
        keep_key = all("xn--" in (s.get("key") or "") or "." in (s.get("key") or "")
                       for s in listing)
        if keep_key:
            print("  ✓ key 保持 ASCII（切换站点靠它匹配 vhost 文件）")
        else:
            print("  ✗ key 被改动，站点切换会匹配不到文件")
            failed += 1

    print("PASS: 显示域名已本地化" if not failed else "FAIL: %d 项不符合预期" % failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
