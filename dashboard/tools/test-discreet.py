"""Feed events straight into the hub: no log tailing in the loop.

Normal traffic is published without its address, so the tests identify it by
the same opaque token the service derives (`sha1(ip)[:10]`) -- computing it
here is the point: nothing in the payload can be traced back by accident.

The fixture addresses come from the RFC 5737 documentation ranges on purpose:
this repository must not carry somebody's real address, and a documentation
address is guaranteed never to be a real visitor. The service would normally
refuse to publish one (see store.ingest -- a packet never really comes from
there), so the GeoIP layer is stubbed to report them as ordinary public
addresses. This test is about the *discreet path* filter, not about the geo
database, and the stub keeps those two concerns apart.
"""
import hashlib
import os
import sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from types import SimpleNamespace
from backend import store, geo, threat

# Stub before anything is ingested: documentation ranges would otherwise be
# classified `special` and dropped before the publish decisions run.
store.geo.geo.lookup = lambda ip, *a, **k: {
    "kind": "public", "lat": 1.0, "lon": 2.0, "cc": "ZZ", "co": "Fixture"}

class Sub:
    def __init__(self): self.items = []
    def push(self, item): self.items.append(item)
    def drain(self, n=0): out, self.items = self.items, []; return out

hub = store.hub
sub = Sub()
token = 'test-discreet'
hub._subs[token] = sub

now = time.time()
cases = [
    ('192.0.2.1', '/dsh-whale/wait.json', 0),
    ('192.0.2.2', '/dsh-whale/last-turn.json', 0),
    ('192.0.2.3', '/api/v1/stream', 0),
    ('192.0.2.4', '/api/session/prompt', 0),
    ('192.0.2.5', '/plugins/events', 0),
    ('192.0.2.6', '/blog/hello', 1),        # 应发布
    ('192.0.2.7', '/index.html', 1),        # 应发布
]
for ip, path, _ in cases:
    hub.ingest(SimpleNamespace(ip=ip, ts=now, method='GET', path=path,
                              status=200, site='test', ua='x'))
hub._subs.pop(token, None)

def token_of(ip):
    return hashlib.sha1(ip.encode('utf-8', 'replace')).hexdigest()[:10]

published = {}
for item in sub.items:
    published.setdefault(item.get('ip') or token_of(item.get('id', '')), []).append(item.get('p'))
# 普通来源的 token 直接用 id；攻击来源用真实地址
for item in sub.items:
    key = item.get('ip') or item.get('id')
    published.setdefault(key, []).append(item.get('p'))

print('推送给浏览器的事件：')
ok = True
for ip, path, expect in cases:
    got = published.get(ip) or published.get(token_of(ip))
    if expect and not got:
        print('  ✗ %-15s %-28s 应发布但被隐藏' % (ip, path)); ok = False
    elif not expect and got:
        print('  ✗ %-15s %-28s 应隐藏但发布了' % (ip, path)); ok = False
    else:
        print('  ✓ %-15s %-28s %s' % (ip, path, '已发布' if expect else '已隐藏'))

# 计数仍然包含被隐藏的请求
snap = hub.snapshot()
print('\n总数仍计入隐藏请求：total=%d' % snap['traffic']['total'])
print('历史记录里是否残留敏感路径：', [
    e.get('p') for e in (snap.get('history') or [])
    if e.get('p') and threat.threat.is_discreet_path(e['p'])
] or '无 ✓')

# 分类器对路径的判断
for path, want in (('/dsh-whale/wait.json', True), ('/api/v1/state', True),
                   ('/wp-login.php', False), ('/blog/hello', False),
                   ('/index.html', False)):
    got = threat.threat.is_discreet_path(path)
    flag = '✓' if got == want else '✗'
    if got != want: ok = False
    print('  %s is_discreet_path(%-24s) = %s' % (flag, path, got))

print('\n' + ('PASS: 私密路径只计数不发布' if ok else 'FAIL'))
sys.exit(0 if ok else 1)
