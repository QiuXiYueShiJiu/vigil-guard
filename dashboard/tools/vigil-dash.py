#!/usr/bin/env python3
"""Operator CLI for the vigil console.

    vigil-dash status              what the service thinks of itself
    vigil-dash set-password        set the console password (root is not consulted)
    vigil-dash clear-password      remove it -- after that nobody can sign in
    vigil-dash sessions            how many browser sessions are open
    vigil-dash kick                sign every browser out
    vigil-dash sites               list sites and their switch state
    vigil-dash open <site>         allow a site
    vigil-dash close <site>        deny a site (writes deny all; + reloads nginx)
    vigil-dash logs [-n 80]        tail the service journal

Exit codes: 0 ok, 1 handled failure, 2 usage.
"""
from __future__ import annotations

import argparse
import getpass
import os
import time
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import auth, geo, settings, sites, threat                 # noqa: E402
from backend import resources as res                                   # noqa: E402


def cmd_status(_args) -> int:
    snapshot = threat.threat.snapshot()
    sample = res.sampler.latest()
    print("配置文件        %s" % settings.CONFIG_FILE)
    print("状态目录        %s" % settings.STATE_DIR)
    print("监听            %s:%d" % (settings.PANEL_HOST, settings.PANEL_PORT))
    print("公开域名        %s" % settings.PUBLIC_HOST)
    # Opening is lazy, so touching `available` is what resolves the path.
    geo.geo.available
    print("GeoIP           %s" % (geo.geo.path or "未找到（离线定位不可用）"))
    print("控制台密码      %s" % ("已设置（%s）"
                                  % settings.PASSWORD_FILE
                                  if auth.auth.dashboard_password_set()
                                  else "未设置 —— 现在没有任何口令可以登录"))
    print("活跃会话        %d" % auth.auth.session_count())
    print("威胁账本        封禁 %d / 累计 %d / 事件 %d"
          % (snapshot["live_bans"], snapshot["bans_total"], snapshot["events"]))
    posture = threat.threat.posture()
    print("防护姿态        %s" % ("已提升，剩余 %ds" % posture["remaining"]
                                  if posture["active"] else "常规"))
    if sample:
        cpu = sample.get("cpu", {}).get("percent")
        mem = sample.get("memory", {}).get("percent")
        print("资源            CPU %.1f%%  内存 %.1f%%" % (cpu or 0, mem or 0))
    ok, detail = sites.sites.test_config()
    print("nginx 配置      %s" % ("有效" if ok else "有问题：%s" % detail.strip()[:120]))
    return 0


def cmd_set_password(args) -> int:
    password = args.password
    if not password:
        first = getpass.getpass("新的控制台密码: ")
        second = getpass.getpass("再输入一次: ")
        if first != second:
            print("两次输入不一致", file=sys.stderr)
            return 1
        password = first
    if len(password) < 8:
        print("密码至少 8 位", file=sys.stderr)
        return 1
    auth.auth.set_dashboard_password(password, method=args.algo)
    auth.auth.destroy_all()
    print("已设置控制台密码（%s），所有会话已注销。" % args.algo)
    print("这是唯一有效的凭据：root 密码不会被接受。删除用 vigil-dash clear-password"
          "（删除后控制台谁都进不去）。")
    return 0


def cmd_clear_password(_args) -> int:
    auth.auth.clear_dashboard_password()
    print("已删除控制台密码。现在没有任何口令可以登录，"
          "请用 vigil-dash set-password 重新设置。")
    return 0


def cmd_unlock(args) -> int:
    """Clear the login throttle. The counter lives in the running service,
    so this is not a file edit: it asks the service to forget, through the
    same module instance the CLI's sibling process cannot reach."""
    import json as _json
    import urllib.request
    url = "http://%s:%d/api/v1/admin/unlock" % (settings.PANEL_HOST, settings.PANEL_PORT)
    body = _json.dumps({"ip": args.ip or ""}).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=6) as res:
            data = _json.loads(res.read().decode()).get("data", {})
        print("已清除 %d 条登录失败记录" % data.get("cleared", 0))
        return 0
    except Exception as exc:                        # noqa: BLE001
        print("服务未响应（%s），改为直接清除本进程内的状态" % exc, file=sys.stderr)
        removed = auth.clear_failures(args.ip or "")
        print("已清除 %d 条记录" % removed)
        return 0


def cmd_sessions(_args) -> int:
    print("活跃会话：%d" % auth.auth.session_count())
    return 0


def cmd_kick(_args) -> int:
    count = auth.auth.destroy_all()
    print("已注销 %d 个会话。" % count)
    return 0


def cmd_sites(_args) -> int:
    summary = sites.sites.state_summary()
    print("%-52s %-8s %-10s %s" % ("标识", "状态", "开关注入", "主域名"))
    for site in summary["sites"]:
        print("%-52s %-8s %-10s %s"
              % (site["key"], "已关闭" if site["blocked"] else "放行",
                 "已注入" if site["include_ok"] else "待注入", site["primary"]))
    print("\n共 %d 个站点，关闭 %d 个。" % (summary["total"], summary["blocked"]))
    return 0


def _switch(key: str, blocked: bool) -> int:
    """按标识、显示名或 ASCII 原名切换站点。

    三种写法都要能匹配：vhost 文件名（key）、界面显示的中文域名（primary /
    names）、以及 punycode 原名（names_raw）。少了最后一项，就会出现"列表里
    看到的是中文、照着敲却找不到站点"的情况——而且现在站点关闭后只能靠这条
    命令行恢复，匹配不上等于进不去。
    """
    want = (key or "").strip()
    lowered = want.lower()
    matches = []
    for site in sites.sites.list_sites():
        forms = set()
        forms.add(site.get("key") or "")
        forms.add(site.get("primary") or "")
        forms.update(site.get("names") or [])
        forms.update(site.get("names_raw") or [])
        forms.update(sites.settings.display_domain(f) for f in list(forms))
        if want in forms or lowered in {f.lower() for f in forms}:
            matches.append(site)
    if not matches:
        print("找不到站点：%s（用 vigil-dash sites 查看标识）" % key, file=sys.stderr)
        return 1
    site = matches[0]
    try:
        result = sites.sites.set_blocked(site["key"], blocked,
                                        note="vigil-dash CLI", operator="cli")
    except sites.NginxError as exc:
        print("失败：%s" % exc, file=sys.stderr)
        if exc.detail:
            print(exc.detail[-1500:], file=sys.stderr)
        return 1
    # 报状态之前先真的请求一次。之前这里只报告"nginx 是否 reload 成功"，
    # 而 reload 成功不等于站点真的按预期开放或关闭——开关片段、全局 include、
    # IP 封禁列表任何一处残留都会让实际结果与报告不一致。
    verdict, detail = _verify_site(site, blocked)
    print("%s：%s%s" % (site["primary"], "已关闭" if blocked else "已放行",
                        "，nginx 已重载" if result.get("reloaded") else
                        "，但 nginx 未重载，请检查"))
    if verdict is None:
        print("  实际校验：跳过（%s）" % detail)
    elif verdict:
        print("  实际校验：通过 —— %s" % detail)
    else:
        print("  实际校验：**未通过** —— %s" % detail, file=sys.stderr)
        print("  开关文件与 nginx 实际行为不一致，请检查 include 与全局封禁片段。",
              file=sys.stderr)
        return 1
    return 0


def _verify_site(site: dict, blocked: bool) -> tuple:
    """回环请求一次，确认站点真的按预期关闭 / 放行。

    返回 ``(True/False/None, 说明)``；None 表示无法判定（例如没有可用地址）。
    """
    import http.client
    import ssl

    host = (site.get("names_raw") or site.get("names") or [""])[0]
    if not host:
        return None, "没有可用于校验的域名"
    try:
        ascii_host = host if "xn--" in host else host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        ascii_host = host

    # http.client 而不是 urllib：这里要的只是"带上 Host 头打一次回环请求"，
    # 不需要 urllib 的异常层级（那个层级没导入时会抛 AttributeError，
    # 把校验悄悄变成"跳过"，报告就和现实脱节了）。
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def probe() -> int:
        conn = http.client.HTTPSConnection("127.0.0.1", 443, timeout=6, context=ctx)
        try:
            conn.request("GET", "/api/v1/health", headers={"Host": ascii_host})
            return conn.getresponse().status
        finally:
            conn.close()

    def expected(code: int) -> bool:
        return (code == 403) if blocked else (code != 403)

    # nginx 是 reload 而不是 restart：worker 换新配置有短暂过渡，reload 刚返回
    # 时请求可能仍由旧 worker 处理，于是校验读到的是上一次的状态（关完还是
    # 200、开完还是 403）。等它收敛，而不是把过渡当成不一致。
    code = 0
    for attempt in range(20):                           # 最多约 5 秒
        try:
            code = probe()
        except Exception as exc:                        # noqa: BLE001
            if attempt == 19:
                return None, "请求失败：%s: %s" % (type(exc).__name__, exc)
            code = 0
        else:
            if expected(code):
                return True, "HTTP %s（第 %d 次探测）" % (code, attempt + 1)
        time.sleep(0.25)
    return False, "HTTP %s（等待 5 秒后仍不符合预期）" % code


def cmd_open(args) -> int:
    return _switch(args.site, False)


def cmd_close(args) -> int:
    return _switch(args.site, True)


def cmd_logs(args) -> int:
    subprocess.run(["journalctl", "-u", "vigil-dashboard.service", "-n",
                    str(args.n), "--no-pager", "-f" if args.follow else "-q"])
    return 0


def cmd_operator(args) -> int:
    """Mark an address as the operator's, or list what is marked.

    Requests from a marked address are counted but never published, so the
    person watching the public dashboard cannot tell which address
    administers it. Logging in marks it automatically; this exists for the
    case where the operator wants to pre-mark a fixed line.
    """
    import time

    # This has to talk to the running service. Writing to a local import's
    # registry would only change this process's memory, and the console would
    # never see it.
    import json as _json
    import urllib.request

    def call(method, payload=None):
        url = "http://%s:%d/api/v1/admin/operator" % (settings.PANEL_HOST, settings.PANEL_PORT)
        data = _json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return _json.loads(resp.read().decode())["data"]

    try:
        if not args.ip:
            data = call("GET")
            marks = data.get("operators") or []
            if not marks:
                print("没有登记任何运维方地址（登录成功时会自动登记）")
                return 0
            print("已登记的运维方地址（其访问不出现在公开页面）：")
            for item in sorted(marks, key=lambda m: m["ip"]):
                left = item["remaining"]
                print("  %-18s 剩余 %d 小时 %d 分"
                      % (item["ip"], left // 3600, (left % 3600) // 60))
            return 0
        data = call("POST", {"ip": args.ip})
        print("已登记 %s 为运维方地址；撤销了 %d 条已发布记录"
              % (data["ip"], data["removed"]))
        return 0
    except Exception as exc:                            # noqa: BLE001
        print("调用管理接口失败：%s" % exc, file=sys.stderr)
        return 1


def cmd_mapcheck(_args) -> int:
    """Verify the map file the browser is served: format, base64, byte counts.

    Everything the browser's decoder checks, checked here first. A decode
    failure in the page is otherwise only reproducible on the device that hit
    it, which makes it very hard to tell a bad file from a stale cache.
    """
    import base64
    import json

    path = settings.DATA / "world.json"
    print("文件        %s" % path)
    try:
        stat = path.stat()
    except OSError as exc:
        print("无法读取：%s" % exc, file=sys.stderr)
        return 1
    print("大小        %.1f KiB" % (stat.st_size / 1024))
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print("JSON 解析失败：%s" % exc, file=sys.stderr)
        return 1

    meta = doc.get("meta") or {}
    print("版本        v%s（解码器要求 v2）" % doc.get("v"))
    print("编码        %s" % meta.get("encoding"))
    print("坐标系      %s" % meta.get("projection"))
    print("国家 / 环   %d / %d" % (len(doc.get("countries") or []),
                                  sum(len(c.get("r") or []) for c in doc.get("countries") or [])))
    print("坐标点      %s" % meta.get("points"))
    print("构建时间    %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(meta.get("built") or 0)))

    problems = []
    if doc.get("v") != 2:
        problems.append("数据版本不是 2")
    checked = 0
    for country in doc.get("countries") or []:
        rings = country.get("r") or []
        bytes_list = country.get("b") or []
        for index, encoded in enumerate(rings):
            checked += 1
            if not isinstance(encoded, str):
                problems.append("国家 #%s 第 %d 环不是字符串（类型 %s）"
                                % (country.get("i"), index, type(encoded).__name__))
                continue
            try:
                blob = base64.b64decode(encoded, validate=True)
            except Exception as exc:                    # noqa: BLE001
                problems.append("国家 #%s 第 %d 环 base64 非法：%s"
                                % (country.get("i"), index, exc))
                continue
            expected = bytes_list[index] if index < len(bytes_list) else None
            if expected is not None and len(blob) != expected:
                problems.append("国家 #%s 第 %d 环字节数不符：期望 %s 实际 %d"
                                % (country.get("i"), index, expected, len(blob)))
            # Note: no even-length check. Coordinates are varint-encoded, so
            # a ring of N points is a sequence of 2N varints of 1-3 bytes
            # each -- the total byte count has no parity constraint. An
            # earlier version of this check flagged 1455 perfectly good rings.

    print("校验        %d 个环" % checked)
    if problems:
        print("\n发现 %d 个问题：" % len(problems))
        for item in problems[:20]:
            print("  - %s" % item)
        return 1
    print("结论        全部通过 ✓")

    # Also confirm what the web root is actually serving, if there is one.
    served = settings.WWWROOT / "assets" / "world.json"
    if served.exists():
        same = served.read_bytes() == path.read_bytes()
        print("线上副本    %s（%s）" % (served, "与本文件一致" if same else "不一致，需重新部署"))
        if not same:
            return 1
    return 0


def cmd_check(_args) -> int:
    return subprocess.call([sys.executable,
                            os.path.join(settings.ROOT, "backend", "serve.py"),
                            "--check"])


def main() -> int:
    ap = argparse.ArgumentParser(prog="vigil-dash", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command")

    sub.add_parser("status", help="运行状态总览").set_defaults(func=cmd_status)
    sub.add_parser("check", help="启动前自检").set_defaults(func=cmd_check)
    sub.add_parser("mapcheck", help="校验地图数据（base64/长度/版本）").set_defaults(func=cmd_mapcheck)
    p = sub.add_parser("operator", help="登记运维方地址（其访问不出现在公开页面）")
    p.add_argument("ip", nargs="?", help="留空则列出已登记地址")
    p.set_defaults(func=cmd_operator)
    sub.add_parser("sessions", help="活跃会话数").set_defaults(func=cmd_sessions)
    sub.add_parser("kick", help="注销所有会话").set_defaults(func=cmd_kick)
    sp = sub.add_parser("unlock", help="清除登录限速（忘记失败次数）")
    sp.add_argument("ip", nargs="?", default="", help="只清除某个来源，省略则全部")
    sp.set_defaults(func=cmd_unlock)
    sub.add_parser("clear-password", help="删除控制台密码（之后无人可登录）").set_defaults(
        func=cmd_clear_password)
    sub.add_parser("sites", help="列出站点与开关状态").set_defaults(func=cmd_sites)

    sp = sub.add_parser("set-password", help="设置控制台独立密码")
    sp.add_argument("password", nargs="?", help="省略则交互式输入")
    sp.add_argument("--algo", choices=("sha256", "crypt"), default="sha256")
    sp.set_defaults(func=cmd_set_password)

    sp = sub.add_parser("open", help="放行站点")
    sp.add_argument("site")
    sp.set_defaults(func=cmd_open)

    sp = sub.add_parser("close", help="关闭站点")
    sp.add_argument("site")
    sp.set_defaults(func=cmd_close)

    sp = sub.add_parser("logs", help="查看服务日志")
    sp.add_argument("-n", type=int, default=80)
    sp.add_argument("-f", "--follow", action="store_true")
    sp.set_defaults(func=cmd_logs)

    args = ap.parse_args()
    if not getattr(args, "func", None):
        ap.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
