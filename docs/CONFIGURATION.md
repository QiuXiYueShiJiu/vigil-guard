# 配置

## 两个文件，故意的

```sh
sudo vigil config path
# /etc/vigil/config.json     0640  可以放心贴进工单
# /etc/vigil/secrets.json    0600  密钥都在这里
```

告警密钥、SMTP 授权码、IMAP 密码统一进 `secrets.json`。`config.json` 里对应
位置留空。这样做的原因很实际：**配置文件是被复制粘贴到聊天窗口和工单里的那个文件**。
`vigil config export` 默认不包含密钥，`--include-secrets` 才带上。

```sh
sudo vigil config export > backup.json
sudo vigil config import backup.json
sudo vigil config validate
```

## 改配置

```sh
sudo vigil config get threat.ssh.max_failures
sudo vigil config set threat.ssh.max_failures 8
sudo vigil config set checks.disk.paths '["/", "/data"]'   # JSON 值
```

## 结构

配置是一棵树，点号路径寻址。缺键不是错误 —— 读取时永远先合并默认值，
所以升级新增的字段在旧配置文件上直接可用。

```jsonc
{
  "hostname": "",              // 留空则用系统主机名
  "mail":       { /* 见 MAIL.md */ },
  "threat":     { /* 实时风控与自动封禁 */ },
  "loadshed":   { /* 高负载时限流 */ },
  "checks":     { /* 安全巡检项 */ },
  "malware":    { /* 恶意文件扫描 */ },
  "gate":       { /* 登录界面防护，见 GATE.md */ },
  "auditd":     { /* 内核审计规则 */ },
  "logging":    { "level": "INFO", "keep_days": 30 }
}
```

完整字段见 `examples/config.typical.json`，或读
`src/vigil/core/config.py` 里的 `DEFAULTS`（那是唯一权威）。

## 白名单：最容易把自己锁在外面的一项

`threat.whitelist` 里的地址**永远不会被封禁**。默认只有回环地址。

```sh
sudo vigil threat whitelist add 203.0.113.10
sudo vigil threat whitelist
```

> 如果你的管理 IP 是运营商动态分配的，把它加进白名单等于没加 —— 换个网段就失效了。
> 这种情况下靠的是「先确认能登录，再收紧」，而不是靠白名单。

## sitemap：不抢站长自己的那一份

`vigil lure install` 会往站点 include 目录写一段 nginx 片段，让 `/sitemap.xml`
返回一份「列出诱饵路径的假 sitemap」，把扫描器引到诱饵端点上。

但 `location = /sitemap.xml` 是精确匹配，会**盖住站长自己放在 webroot 的 sitemap** ——
文件还在，只是永远送不出去，从外面完全看不出来。所以默认行为是：**站点自己有
sitemap 就不发诱饵 sitemap**，把这一面留给站长。

```sh
# 三档，默认 auto
sudo vigil config set threat.lure.sitemap auto     # 站点有就不发（默认）
sudo vigil config set threat.lure.sitemap always   # 照发，明确接受覆盖站长文件
sudo vigil config set threat.lure.sitemap never    # 从不发
```

`vigil lure status` 会说明当前是谁在提供 sitemap，以及金丝雀是否被请求过。

> 诱导面本身不靠 sitemap：`robots.txt` 里那一段（`Disallow:` 一串诱饵路径 + 金丝雀）
> 是独立的，跟这个开关无关，而它才是自动化流量最先读的地方。

## 自修正：它被允许做什么

`vigil evolve` 默认**关闭**。开启后它会读本机真实流量、采纳新的诱饵路径，
并把每次改动写进台账、改前发邮件、改后上报。

```sh
sudo vigil config set evolve.enabled true          # 打开循环
sudo vigil config set evolve.allow_code_edits true # 允许改源码（默认关，需先设 source_root）
sudo vigil config set evolve.source_root /path/to/vigil-guard
sudo vigil config set evolve.report_url https://你的收集端/evolve/report.php
```

资源上限一律按**可用量的比例**给，不写死绝对值：

| 键 | 默认 | 含义 |
|---|---|---|
| `evolve.memory_pct` | 5.0 | 只取**可用**内存的这个百分比 |
| `evolve.memory_floor_mb` | 96 | 可用内存低于此值就不开工 |
| `evolve.load_ratio` | 0.7 | 负载超过 `核数 × 此值` 就不开工 |
| `evolve.time_budget` | 120 | 单次运行的墙钟上限（秒） |
| `evolve.min_hits` / `min_ips` | 8 / 3 | 证据门槛：命中次数 / 独立来源数 |
| `evolve.max_per_run` / `max_adopted` | 5 / 200 | 单次与累计采纳上限 |
| `evolve.max_code_edits_per_day` | 3 | 每日源码自改次数上限 |
| `evolve.max_patch_lines` | 40 | 单次补丁行数上限 |
| `evolve.report_enabled` / `report_url` | true / 空 | 上报开关与地址；留空则只写本地台账 |

`vigil evolve status` 看现状，`scan` 只看证据，`plan` 看它打算做什么，
`apply` 执行（`--dry-run` 预演），`rollback <id>` 撤销，`watchdog` 检查它有没有失控。

## 配置校验

`vigil config validate` 会指出真正会让告警发不出去的问题：没有渠道、没有收件人、
没有发件地址、白名单是空的。它不会因为风格问题报错。
