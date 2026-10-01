#!/usr/bin/env python3
"""敏感文件规则接线校验器 —— 可单独运行，也可作为网页后端。

它回答一个问题：**每个会读磁盘的 `^~ 前缀` 里，敏感文件拒绝规则还在不在？**

为什么值得单独做一个工具：

`location ^~ /xxx/` 会让 nginx 跳过同级所有正则 location。所以那套「备份 / 点文件 /
源码不许下载」的规则必须在每个这样前缀里再挂一次。这条 include 只能写在站点自己的
配置里，而在面板接管的机器上，那个文件属于面板 —— 实测中它被本程序之外的进程改写，
include 随之消失，该子树的文件重新变成可被公网下载。

**最危险的地方**：规则文件本身一直在，所以「检查文件在不在」的监控会一路报 OK。
本工具查的是「有没有真的接进去」。

它不做任何修改，只读配置并回答。要修就用 `vigil exposure install` 或 `vigil update`。

用法：

    ./exposure_check.py                 # 人类可读
    ./exposure_check.py --json          # 机器可读
    ./exposure_check.py --root /etc/nginx/conf.d
    ./exposure_check.py --serve --port 8791          # 起一个只读 JSON 接口
    ./exposure_check.py --serve --token 一串密钥      # 对外时必须带 token

设计取舍：校验逻辑与 vigil 共用同一份实现（`vigil.guards.exposure`），
不在这里复制一遍 —— 两份实现会漂移，而「扫描说干净、服务器却在往外发」
正是这个项目反复踩过的坑。因此本机需要有 vigil（`install.sh` 装好后即可）。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

# --------------------------------------------------------------------------
# 找到 vigil 的实现。本机安装路径优先，其次是同仓库的 src/。
# --------------------------------------------------------------------------
def _load_exposure():
    here = Path(__file__).resolve()
    candidates = [
        os.environ.get("VIGIL_LIB", ""),
        "/usr/local/lib/vigil",
        str(here.parents[2] / "src"),          # 仓库内直接跑
        str(here.parents[1].parent / "src"),
    ]
    for cand in candidates:
        if cand and (Path(cand) / "vigil" / "guards" / "exposure.py").is_file():
            if cand not in sys.path:
                sys.path.insert(0, cand)
            break
    try:
        from vigil.guards import exposure
        return exposure
    except ImportError:
        sys.stderr.write(
            "找不到 vigil 的实现。\n"
            "  它要么装在本机（/usr/local/lib/vigil），要么用 VIGIL_LIB 指到 src 目录。\n"
            "  安装：仓库根目录执行 sudo ./install.sh\n")
        raise SystemExit(2)


# --------------------------------------------------------------------------
# 校验
# --------------------------------------------------------------------------
def check(root=None) -> dict:
    """返回一次校验结果。只读，绝不修改任何文件。"""
    exposure = _load_exposure()
    started = time.time()
    sites, holes = [], []

    for conf in exposure.site_confs(root):
        ext = conf.parent
        managed = any((ext / name).is_file() for name in (
            "zz-exposure-deny.conf", "vigil-deny.conf", "vigil-hygiene.conf",
            "vigil-lure.conf", "vigil-decoy.conf"))
        try:
            text = conf.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            sites.append({"conf": conf.name, "error": str(exc)})
            continue
        if "location ^~" not in text:
            continue
        audit = exposure.audit_conf(text)
        serving = [b for b in audit["prefixes"] if b["serves"]]
        if not serving and not managed:
            continue
        uncovered = [b["prefix"] for b in audit["uncovered"]]
        entry = {
            "conf": conf.name,
            "managed": managed,
            "rules_file": (ext / "zz-exposure-deny.conf").is_file(),
            "file_serving_prefixes": [b["prefix"] for b in serving],
            "holes": uncovered,
            "ok": not uncovered,
        }
        sites.append(entry)
        for prefix in uncovered:
            holes.append({"conf": conf.name, "prefix": prefix})

    return {
        "ok": not holes,
        "checked_sites": len(sites),
        "holes": holes,
        "sites": sites,
        "summary": ("所有 `^~` 前缀都已挂上敏感文件拒绝规则"
                    if not holes else
                    "%d 个 `^~` 前缀没有挂规则，其下文件可被公网下载" % len(holes)),
        "fix": "" if not holes else
               "vigil exposure install（或 vigil update 会自动补回）",
        "elapsed_ms": int((time.time() - started) * 1000),
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }


# --------------------------------------------------------------------------
# 网页后端：只读 JSON 接口
# --------------------------------------------------------------------------
PAGE = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>敏感文件规则接线校验</title><style>
:root{color-scheme:light dark}
body{margin:0;padding:26px;font:15px/1.6 -apple-system,BlinkMacSystemFont,
 "Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;background:#0e1420;color:#e6eefb}
h1{margin:0 0 4px;font-size:19px}p.sub{margin:0 0 18px;color:#8fa2bf;font-size:13px}
button{padding:9px 16px;font-size:14px;font-weight:600;color:#fff;border:0;border-radius:9px;
 background:linear-gradient(135deg,#4f9dff,#7d6bff);cursor:pointer}
button:disabled{background:#33405a;cursor:progress}
.ok{color:#7fe3a8}.bad{color:#ff8f9a}
table{width:100%;border-collapse:collapse;margin-top:16px;font-size:14px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid #1e2a44}
th{color:#8fa2bf;font-weight:600;font-size:12.5px}
code{font-family:ui-monospace,Consolas,monospace;color:#b3a6ff}
.badge{display:inline-block;padding:1px 8px;border-radius:20px;font-size:12px}
.b-ok{background:#12301f;color:#7fe3a8}.b-bad{background:#3a1620;color:#ff8f9a}
</style></head><body>
<h1>敏感文件规则接线校验</h1>
<p class="sub">检查每个会读磁盘的 <code>^~</code> 前缀里，敏感文件拒绝规则是否还挂着。
只读，不修改任何配置。</p>
<button id="go">开始校验</button> <span id="state" class="sub"></span>
<div id="out"></div>
<script>
async function run(){
  var go=document.getElementById('go'), st=document.getElementById('state'),
      out=document.getElementById('out');
  go.disabled=true; st.textContent='校验中…'; out.textContent='';
  try{
    var r=await fetch('api/check',{headers:{'Accept':'application/json'}});
    var d=await r.json();
    st.innerHTML = d.ok ? '<span class="ok">✔ '+d.summary+'</span>'
                        : '<span class="bad">✘ '+d.summary+'</span>';
    var h='<table><tr><th>站点配置</th><th>规则文件</th><th>^~ 前缀</th><th>状态</th></tr>';
    (d.sites||[]).forEach(function(s){
      h+='<tr><td>'+s.conf+'</td><td>'+(s.rules_file?'在':'<span class="bad">缺</span>')+'</td>'
        +'<td>'+(s.file_serving_prefixes||[]).map(function(p){return '<code>'+p+'</code>';}).join(' ')||'—'
        +'</td><td>'+(s.ok?'<span class="badge b-ok">已挂规则</span>'
                         :'<span class="badge b-bad">未覆盖</span>')+'</td></tr>';
    });
    h+='</table>';
    if(!d.ok && d.fix){h+='<p class="sub">修复：<code>'+d.fix+'</code></p>';}
    out.innerHTML=h;
  }catch(e){ st.innerHTML='<span class="bad">请求失败：'+e+'</span>'; }
  finally{ go.disabled=false; }
}
document.getElementById('go').onclick=run; run();
</script></body></html>
"""


def serve(bind: str, port: int, token: str, allow_origin: str) -> int:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse, parse_qs

    class Handler(BaseHTTPRequestHandler):
        server_version = "vigil-exposure-check"

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if allow_origin:
                self.send_header("Access-Control-Allow-Origin", allow_origin)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, code: int, payload: dict) -> None:
            self._send(code, json.dumps(payload, ensure_ascii=False).encode(),
                       "application/json; charset=utf-8")

        def _authorised(self, query) -> bool:
            if not token:
                return True
            given = (self.headers.get("X-Vigil-Token")
                     or (query.get("token") or [""])[0])
            import hmac
            return hmac.compare_digest(str(given), token)

        def do_GET(self) -> None:                        # noqa: N802
            url = urlparse(self.path)
            query = parse_qs(url.query)
            if url.path in ("/healthz", "/health"):
                self._send(200, b"ok\n", "text/plain; charset=utf-8")
                return
            if not self._authorised(query):
                self._json(401, {"ok": False, "error": "unauthorised"})
                return
            if url.path in ("/", "/index.html", "/check"):
                self._send(200, PAGE.encode("utf-8"),
                           "text/html; charset=utf-8")
                return
            if url.path in ("/api/check", "/api/check/"):
                try:
                    self._json(200, check())
                except SystemExit:
                    self._json(500, {"ok": False,
                                     "error": "vigil 未安装或找不到实现"})
                except Exception as exc:                 # noqa: BLE001
                    self._json(500, {"ok": False, "error": str(exc)})
                return
            self._json(404, {"ok": False, "error": "not found"})

        do_HEAD = do_GET

        def log_message(self, fmt, *args):               # 静音默认日志
            pass

    srv = ThreadingHTTPServer((bind, port), Handler)
    print("vigil-exposure-check 监听 http://%s:%d" % (bind, port))
    print("  页面   /            接口  /api/check      存活  /healthz")
    if bind not in ("127.0.0.1", "::1", "localhost"):
        print("  ⚠ 绑定在非本机地址。若要对公网开放，请务必设 --token，"
              "并放在带 TLS 的反向代理后面。")
    if token:
        print("  token 已启用（X-Vigil-Token 头，或 ?token=…）")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="校验 nginx `^~` 前缀里的敏感文件拒绝规则是否还挂着（只读）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--root", default="",
                    help="只检查这个目录（默认：自动探测常见 nginx 配置目录）")
    ap.add_argument("--serve", action="store_true", help="作为网页后端运行")
    ap.add_argument("--bind", default="127.0.0.1", help="监听地址（默认仅本机）")
    ap.add_argument("--port", type=int, default=8791, help="监听端口（默认 8791）")
    ap.add_argument("--token", default="",
                    help="共享密钥；对外提供服务时必须设置")
    ap.add_argument("--allow-origin", default="",
                    help="需要跨域时填来源（如 https://panel.example.com）")
    args = ap.parse_args(argv)

    if args.serve:
        return serve(args.bind, args.port, args.token, args.allow_origin)

    result = check(args.root or None)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["ok"] else 1

    print("敏感文件规则接线校验")
    print("─" * 62)
    for site in result["sites"]:
        if site.get("error"):
            print("  ! %-28s 读取失败：%s" % (site["conf"], site["error"]))
            continue
        mark = "✔" if site["ok"] else "✘"
        print("  %s %-28s 规则文件 %s" % (mark, site["conf"],
                                          "在" if site["rules_file"] else "缺"))
        for prefix in site["file_serving_prefixes"]:
            flag = "未覆盖" if prefix in site["holes"] else "已挂规则"
            print("      %-22s %s" % (prefix, flag))
    print("─" * 62)
    print(("✔ " if result["ok"] else "✘ ") + result["summary"])
    if not result["ok"]:
        print("  修复：" + result["fix"])
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
