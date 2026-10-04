"""The status page, as one self-contained document.

No external CSS, fonts, or scripts: this page has to render on a host with no
outbound network, and a page whose styling depends on a CDN is a page that
looks broken exactly when someone is trying to find out whether the host is
broken. Everything is inline and everything is generated here.

Every host-specific value shown is passed in at render time. Nothing about a
particular machine is written into this file -- the same rule the rest of the
package follows, for the same reason.
"""
from __future__ import annotations

import html

CSS = """
:root{--bg:#0e1621;--fg:#dbe6f2;--mut:#8ba0b8;--card:#18222f;--acc:#6fa8d6;
      --ok:#4caf7d;--warn:#d9a441;--bad:#d96a6a;--line:#243244}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
     font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",
     "Microsoft YaHei",sans-serif}
.wrap{max-width:880px;margin:0 auto;padding:24px 16px 64px}
header{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;margin-bottom:4px}
h1{font-size:19px;margin:0}
.sub{color:var(--mut);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));
      gap:12px;margin:18px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
      padding:13px 14px}
.card h2{font-size:13px;margin:0 0 8px;color:var(--mut);font-weight:600}
.big{font-size:22px;font-weight:650}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
table{width:100%;border-collapse:collapse;font-size:13px}
td{padding:4px 0;border-bottom:1px solid var(--line);vertical-align:top}
td:first-child{color:var(--mut);width:42%}
form{display:grid;gap:9px;margin-top:8px}
input,textarea,button{font:inherit;color:var(--fg);background:#111a26;
      border:1px solid var(--line);border-radius:8px;padding:9px 11px;width:100%}
button{background:var(--acc);color:#0b1420;border:0;font-weight:650;cursor:pointer}
button.ghost{background:transparent;color:var(--mut);border:1px solid var(--line)}
.note{color:var(--mut);font-size:12px;margin-top:6px}
.flash{padding:9px 11px;border-radius:8px;margin:12px 0;font-size:13px}
.flash.ok{background:rgba(76,175,125,.13);border:1px solid rgba(76,175,125,.35)}
.flash.bad{background:rgba(217,106,106,.13);border:1px solid rgba(217,106,106,.35)}
footer{color:var(--mut);font-size:12px;margin-top:26px;border-top:1px solid var(--line);
       padding-top:12px}
a{color:var(--acc)}
"""


def _esc(v) -> str:
    return html.escape(str(v if v is not None else ""))


def login_page(*, title: str, error: str = "", csrf: str = "") -> str:
    flash = ('<div class="flash bad">%s</div>' % _esc(error)) if error else ""
    return """<!doctype html><html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>%s</title>
<style>%s</style></head><body><div class="wrap">
<h1>%s</h1>
<p class="sub">这个页面的账号与密码由本机使用者用命令行设置，程序不自带默认凭据。</p>
%s
<div class="card" style="max-width:360px;margin-top:16px">
<form method="post" action="/login">
<input type="hidden" name="csrf" value="%s">
<input name="username" placeholder="账号" autocomplete="username" required>
<input name="password" type="password" placeholder="密码"
       autocomplete="current-password" required>
<button type="submit">登录</button>
</form></div>
<footer>vigil</footer>
</div></body></html>""" % (_esc(title), CSS, _esc(title), flash, _esc(csrf))


def status_page(*, title: str, host: dict, cards: list, tables: list,
                flash: str = "", flash_ok: bool = True, csrf: str = "",
                feedback: list = None) -> str:
    flash_html = ""
    if flash:
        flash_html = '<div class="flash %s">%s</div>' % (
            "ok" if flash_ok else "bad", _esc(flash))

    card_html = "".join(
        '<div class="card"><h2>%s</h2><div class="big %s">%s</div>%s</div>'
        % (_esc(c.get("title")), _esc(c.get("cls") or ""), _esc(c.get("value")),
           ('<div class="note">%s</div>' % _esc(c["note"])) if c.get("note") else "")
        for c in cards)

    table_html = ""
    for t in tables:
        rows = "".join("<tr><td>%s</td><td>%s</td></tr>" % (_esc(k), _esc(v))
                       for k, v in t.get("rows", []))
        table_html += ('<div class="card" style="margin-top:12px"><h2>%s</h2>'
                       '<table>%s</table></div>' % (_esc(t.get("title")), rows))

    fb_rows = ""
    for f in (feedback or [])[:20]:
        fb_rows += ("<tr><td>%s</td><td>%s</td></tr>"
                    % (_esc(f.get("at_text")), _esc(f.get("text"))[:400]))

    return """<!doctype html><html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>%s</title>
<style>%s</style></head><body><div class="wrap">
<header><h1>%s</h1><span class="sub">%s</span></header>
<p class="sub">本页数据实时读取本机状态；主机名、域名等信息在运行时获取，程序内不含任何主机信息。</p>
%s
<div class="grid">%s</div>
%s
<div class="card" style="margin-top:16px"><h2>反馈</h2>
<form method="post" action="/feedback">
<input type="hidden" name="csrf" value="%s">
<textarea name="text" rows="4" placeholder="写下你遇到的问题或建议（会记录在本机，并通知维护者）"
          required></textarea>
<button type="submit">提交反馈</button>
</form>
<div class="note">反馈会写入本机日志并进入告警通道；不要填写密码或密钥。</div>
%s
</div>
<footer>vigil · <a href="/logout">退出登录</a></footer>
</div></body></html>""" % (
        _esc(title), CSS, _esc(title), _esc(host.get("subtitle", "")), flash_html,
        card_html, table_html, _esc(csrf),
        ('<table style="margin-top:10px">%s</table>' % fb_rows) if fb_rows else "")
