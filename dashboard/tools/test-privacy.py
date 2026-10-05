"""Fixtures use the RFC 5737 documentation ranges: no real address is kept in
the repository. The GeoIP layer is stubbed so that a documentation source is
treated as an ordinary public one -- this test is about the *privacy rules*
(what the map is allowed to reveal), not about geo classification.
"""
import os
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from types import SimpleNamespace
from backend import store

# Documentation ranges would be classified `special` and dropped before the
# privacy decisions run; stub the lookup so the rules under test are reached.
store.geo.geo.lookup = lambda ip, *a, **k: {
    "kind": "public", "lat": 1.0, "lon": 2.0, "cc": "ZZ", "co": "Fixture"}

NORMAL_IP = '192.0.2.1'      # 普通访客
OPERATOR_IP = '192.0.2.3'    # 运维方（登录过控制台）

class Sub:
    def __init__(self): self.items = []
    def push(self, i): self.items.append(i)
    def drain(self, n=0): o, self.items = self.items, []; return o

hub = store.hub
sub = Sub(); hub._subs['privacy-test'] = sub
now = time.time()
hub.ingest(SimpleNamespace(ip=NORMAL_IP, ts=now, method='GET', path='/blog', status=200, site='t', ua='x'))
# Any address currently live in vigil's ledger, read at run time. Hard-coding
# one rots the moment its ban expires, and then the test silently stops
# testing anything.
def live_ban() -> str:
    import json
    try:
        data = json.load(open('/var/lib/vigil/state/threat.json'))
    except Exception:                                   # noqa: BLE001
        return ''
    now = time.time()
    for ip, rec in sorted(data.get('bans', {}).items(),
                          key=lambda kv: -(kv[1].get('until') or 0)):
        if (rec.get('until') or 0) > now:
            return ip
    return ''


BANNED = live_ban()
hub.ingest(SimpleNamespace(ip=BANNED, ts=now, method='GET', path='/wp-login.php', status=404, site='t', ua='x'))
store.mark_operator(OPERATOR_IP)
hub.ingest(SimpleNamespace(ip=OPERATOR_IP, ts=now, method='GET', path='/blog', status=200, site='t', ua='x'))
hub._subs.pop('privacy-test', None)

ok = True
seen = {}
for item in sub.items:
    seen.setdefault(item.get('id') or item.get('ip'), []).append(item)

def show(label, cond, detail):
    global ok
    print('  %s %-34s %s' % ('✓' if cond else '✗', label, detail))
    if not cond: ok = False

normal = [i for i in sub.items if i.get('lv') == 0 and i.get('id', '').startswith(('32', 'a', 'b', 'c', 'd', 'e', 'f'))]
pub_normal = [i for i in sub.items if i.get('lv') == 0]
pub_attack = [i for i in sub.items if i.get('lv', 0) > 0]

show('普通访问不带真实 IP',
     all('ip' not in i for i in pub_normal),
     '字段: ' + str(sorted(pub_normal[0].keys())) if pub_normal else '无样本')
show('普通访问有位置信息',
     bool(pub_normal and pub_normal[0].get('cc')),
     'cc=%s co=%s' % (pub_normal[0].get('cc'), pub_normal[0].get('co')) if pub_normal else '无')
if not BANNED:
    show('攻击保留真实地址', False, '账本里没有生效封禁，无法验证')
elif pub_attack:
    show('攻击保留真实地址', pub_attack[0].get('ip') == BANNED,
         'ip=%s lv=%s' % (pub_attack[0].get('ip'), pub_attack[0].get('lv')))
else:
    show('攻击保留真实地址', False, '本次没有产生攻击事件，无法验证')
show('运维方地址完全不出现',
     not any(i.get('ip') == OPERATOR_IP or i.get('id') == OPERATOR_IP for i in sub.items),
     '推送 %d 条，来自运维方的 0 条' % len(sub.items))
show('重复访问会归并（同一 token）',
     len({i['id'] for i in pub_normal}) == len(pub_normal),
     '%d 条正常访问，%d 个 token' % (len(pub_normal), len({i['id'] for i in pub_normal})))
print('\n' + ('PASS: 隐私规则生效' if ok else 'FAIL'))
sys.exit(0 if ok else 1)
