#!/usr/bin/env python3
"""X-Vigil-Token 必须携带**会话 token**，不是 CSRF 值。

服务端 `_require_admin` 比对的是：

    header = X-Vigil-Token;  token = 从 cookie 解析出来的会话 token
    if not header or not hmac.compare_digest(header, token): 403

而前端曾经把头设成登录时拿到的 `csrf`（`sha256("csrf" + token)[:32]`），
两者不同值，于是**登录成功、下一个请求就 403「会话校验失败」**。
管理接口测试没发现它，是因为那个脚本自己从 Set-Cookie 里抠出了 token。

这个用例断言服务端契约：登录返回会话 token；用它访问受保护接口通过；
用 csrf 冒充则被拒。

账号与密码**不在源码里**：这是别人会看到的仓库，写进一个真实账号就等于
发布它。运行时从环境变量取：

    VIGIL_DASH_TEST_ACCOUNT=... VIGIL_DASH_TEST_PASSWORD=... \
        python3 tools/test-auth-token.py

没设就跳过（退出码 2），不会假装通过。
"""
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("VIGIL_DASH_TEST_BASE", "http://127.0.0.1:9310/api/v1")
ACCOUNT = os.environ.get("VIGIL_DASH_TEST_ACCOUNT", "")
PASSWORD = os.environ.get("VIGIL_DASH_TEST_PASSWORD", "")


class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, path, method="GET", body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(BASE + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with self.opener.open(req, timeout=8) as resp:
                raw = resp.read().decode()
                status = resp.status
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode()
            status = exc.code
        try:
            return status, json.loads(raw)
        except ValueError:
            return status, {}


def main() -> int:
    if not ACCOUNT or not PASSWORD:
        print("  · 跳过：未设置 VIGIL_DASH_TEST_ACCOUNT / VIGIL_DASH_TEST_PASSWORD")
        print("    例：VIGIL_DASH_TEST_ACCOUNT=op VIGIL_DASH_TEST_PASSWORD=... \\")
        print("            python3 tools/test-auth-token.py")
        return 2
    client = Client()
    failed = 0

    status, payload = client.call("/login", "POST",
                                  {"account": ACCOUNT, "password": PASSWORD})
    if status != 200 or not payload.get("ok"):
        print("  ✗ 登录失败：HTTP %s %s" % (status, payload))
        return 1
    data = payload["data"]
    token = data.get("token") or ""
    csrf = data.get("csrf") or ""
    print("  登录成功，返回 token=%s… csrf=%s…" % (token[:8], csrf[:8]))

    if not token:
        print("  ✗ 登录响应没有返回会话 token（X-Vigil-Token 将无值可用）")
        failed += 1
    else:
        print("  ✓ 登录响应包含会话 token")

    status, payload = client.call("/session")
    got = (payload.get("data") or {}).get("token") or ""
    if got == token:
        print("  ✓ /session 也返回同一个 token（刷新后可恢复）")
    else:
        print("  ✗ /session 未返回可恢复的 token：%r" % got[:12])
        failed += 1

    status, _ = client.call("/sites", headers={"X-Vigil-Token": token})
    if status == 200:
        print("  ✓ 会话 token 通过受保护接口校验")
    else:
        print("  ✗ 会话 token 被拒：HTTP %s" % status)
        failed += 1

    status, _ = client.call("/sites", headers={"X-Vigil-Token": csrf})
    if status == 403:
        print("  ✓ csrf 值冒充会话 token 被拒（403）")
    else:
        print("  ✗ csrf 值竟然通过了：HTTP %s" % status)
        failed += 1

    status, _ = client.call("/sites", headers={"X-Vigil-Token": "bogus"})
    if status == 403:
        print("  ✓ 伪造 token 被拒（403）")
    else:
        print("  ✗ 伪造 token 竟然通过：HTTP %s" % status)
        failed += 1

    print("PASS: 会话 token 契约正确" if not failed
          else "FAIL: %d 项不符合预期" % failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
