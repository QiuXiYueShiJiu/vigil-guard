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
  "alerts":     { /* 告警节奏与迟滞，见下文 */ },
  "threat":     { /* 实时风控与自动封禁；可疑进程自动响应也在这里 */ },
  "bouncer":    { /* nginx 侧封禁（顶层，不在 threat 下） */ },
  "evolve":     { /* 自修正（顶层，不在 threat 下） */ },
  "loadshed":   { /* 高负载时限流 */ },
  "checks":     { /* 安全巡检项：阈值、自检、可用性 */ },
  "malware":    { /* 恶意文件扫描 */ },
  "gate":       { /* 登录界面防护，见 GATE.md */ },
  "auditd":     { /* 内核审计规则 */ },
  "logging":    { "level": "INFO", "keep_days": 30 }
}
```

完整字段见 `examples/config.typical.json`，或读
`src/vigil/core/config.py` 里的 `DEFAULTS`（那是唯一权威）。

### 展示出来的键必须真的有人读

一个「看起来能配、实际没人读」的键，比缺一个键**更坏**：它让人以为配上了。
v3.3.0 修掉了这类错位 —— 包括一个展示为 `netblock.digest_min_items`、实际读取
`mail.digest_min_items` 的键，`bouncer` / `evolve` 两段的整体错位（它们属于
**顶层**，不属于 `threat`），以及 29 处把 schema 内的键误标成「扩展键」的标注。

现在有一条从真实的「键被读取」日志出发的**双向**测试：既不虚报扩展键，也不隐藏
schema 键；另有一项扫描「整个源码从未提到过的 `DEFAULTS` 叶子键」。

## 告警节奏与迟滞

告警的默认目标是**少而准**：普通事件攒批发，严重事件立刻发，没发生变化的持续
异常按间隔提醒，而不是每轮巡检都重发一封一模一样的信。

| 键 | 默认 | 含义 |
|---|---|---|
| `mail.digest_min_items` | 5 | 普通事件攒够这么多条就发一次 |
| `mail.digest_max_wait` | 1800 | 条数不够时，最老一条最多等这么多秒 |
| `alerts.renotify_seconds` | 21600（6 小时） | 同一个**未变化**的异常最多这么久重复提醒一次 |
| `alerts.recovery_quiet_seconds` | 600 | 恢复后这么久内再次变坏不重复告警 |

- **严重事件（`SEV_CRIT`）与带 `immediate` 的事件不受攒批约束**，立即发出；
  被压住的普通事件**不会丢**：条数够、时间到、或强制刷新（退出 / 积压补发）
  都会发出。
- `renotify_seconds` 只压「完全没变」的重复信：**新增异常项、严重度上升、异常
  内容变化会立即发**。比对时会把 detail 里的数字（CPU%、PID 这类每轮都变的
  部分）折叠掉，否则指纹每轮都不同，比原来还勤。
- 迟滞期间异常**仍然**写进 `vigil health` 与 history，退出码仍为 1 ——
  **迟滞不会让真实问题消失**，窗口一过异常仍在就照常告警。
- 旧字段 `cooldown[id]` 的语义已被纠正：它原本表达的是「多久重复一次」而不是
  「多久内不重复」，于是超时即重发。现在由 `alerts.renotify_seconds` 取代。

```sh
sudo vigil config set mail.digest_min_items 10          # 攒更多条再发
sudo vigil config set mail.digest_max_wait 3600         # 最多等 1 小时
sudo vigil config set alerts.renotify_seconds 3600      # 未变化的异常每小时最多重提一次
sudo vigil config set alerts.recovery_quiet_seconds 0   # 0 表示关闭抖动迟滞
```

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

训练与验证：`vigil evolve train`（自监督，标签来自本机处置结果）、
`vigil evolve train --bulk`（加大语料并报告对未见族类的识别能力）、
`vigil evolve novel`（用整族未见过命名习惯考它）、
`vigil evolve outcomes`（回看自己的改动有没有用）。
完整设计见 [EVOLVE.md](EVOLVE.md)。

## 可疑进程的自动响应（默认关闭）

这是本程序里唯一会**动别的进程**的功能：默认关闭，打开后默认只做**可逆的**
`SIGSTOP`，并且会自动撤销。完整设计、置信判据、永不处置清单与证据落盘见
[AUTORESPONSE.md](AUTORESPONSE.md)。

```sh
sudo vigil config set threat.autoresponse.enabled true    # 显式决定
sudo vigil autoresponse status           # 暂停 / 观察了哪些进程，依据是什么
sudo vigil autoresponse resume --all     # 一键恢复（功能关闭时也能用）
sudo vigil autoresponse log              # 处置台账：何时、依据什么、何时恢复
```

| 键 | 默认 | 含义 |
|---|---|---|
| `threat.autoresponse.enabled` | `false` | 总开关。**默认关闭** |
| `threat.autoresponse.action` | `stop` | `stop` = `SIGSTOP`（可逆）；`terminate` = 按 `terminate_signal` |
| `threat.autoresponse.observe_seconds` | 120 | 判定成立后先观察这么久，期间出现豁免证据即放弃 |
| `threat.autoresponse.resume_window_seconds` | 600 | 暂停后继续观察这么久，证据被推翻就自动恢复 |
| `threat.autoresponse.after_observe` | `hold` | 恢复观察窗结束后：`hold` 保持暂停等操作者；`terminate` 升级为终止信号 |
| `threat.autoresponse.terminate_signal` | `SIGTERM` | 直接终止时用的信号；`SIGKILL` 不可挽回，需显式配置 |
| `threat.autoresponse.max_per_hour` | 2 | 每小时最多处置几个（上限 10） |
| `threat.autoresponse.allowlist` | `[]` | 允许清单：命中的进程**永不处置** |
| `threat.autoresponse.evidence_dir` | 空 | 留空则用 `/var/lib/vigil/state/autoresponse-evidence` |

> `threat.autoresponse.allowlist` 与 `checks.process_anomaly.whitelist` 是两件事：
> 后者只影响**报告**，前者是**硬豁免**，会写进「永不处置」清单。

## 程序自身完整性：自动重建与归因

`checks.self_integrity.paths` 是自检对象（安装时会填入本程序生成物，也可以自己
加）。发现变化时先**归因**，再决定报什么、动不动手。

| 键 | 默认 | 含义 |
|---|---|---|
| `checks.self_integrity.paths` | `[]` | 额外的自检路径 |
| `checks.self_integrity.auto_recover` | `true` | 本程序**生成物**被删 / 被改时自动重新生成、复检并报告 |
| `checks.self_integrity.heal_window_seconds` | 1800 | 同一路径的重建限频窗口 |
| `checks.self_integrity.heal_max_attempts` | 3 | 窗口内最多重建几次，超过只报警（防「重建→又被删」的循环） |
| `checks.self_integrity.attribution_window_seconds` | 86400 | 台账记录必须新近到这个程度，才能为一次改动背书 |
| `checks.self_integrity.deploy_window_seconds` | 900 | `vigil update` 写 `deploy.json` 前后多久算「部署」 |

- **自动重建只动本程序生成的文件。** 本程序源码**绝不**自动还原（静默回滚会掩盖
  真实入侵），操作者的文件**绝不**触碰 —— 只报告并给出手工命令。
- 归因判据是**哈希**：台账里的改动后哈希 == 当前哈希 → 自修正；有记录但哈希不符
  → CRIT；无记录但落在部署窗口内 → 部署；其余 → CRIT。
- 台账是**链式 HMAC**（密钥在 `secrets.json`，`0600`）。链断了就**所有**改动都
  按未归因处理，并报出断点。边界见 [EVOLVE.md](EVOLVE.md)。

```sh
sudo vigil config set checks.self_integrity.auto_recover false            # 只报告，不自动重建
sudo vigil config set checks.self_integrity.attribution_window_seconds 3600
sudo vigil config set checks.self_integrity.heal_max_attempts 1
```

## 判定智能化：别把正常当异常

三条修正，判据全部落在**结构性特征**上，而不是名字或单一比例。

### 内存阈值按机器规模

`checks.memory` 同时看**比例**与**绝对量**：只看比例在小内存机器上是常态误报 ——
一台 2 GB 的机器跑一次构建就会掉到 20% 以下，而它一切正常。

| 键 | 默认 | 含义 |
|---|---|---|
| `checks.memory.warn_available_pct` | 20 | 可用内存比例低于它**且**低于绝对下限才报；默认值在小机器上自动放宽（≤4 GB → 16%，≤2 GB → 12%） |
| `checks.memory.crit_available_pct` | 10 | 严重线，同样按机器规模放宽 |
| `checks.memory.warn_available_mb` | 0 | 绝对下限（MB）。**0 = 按总内存缩放**：取约 8%，同时不小于「总内存 5%、下限 256 MB、上限 3277 MB」那一档 |
| `checks.memory.crit_available_mb` | 0 | 同上，取约 3%，同档的一半 |

**操作者显式写下的值绝不被改写**：只要 `warn_available_mb` / `crit_available_mb`
是正数，它就完全替代自动缩放出来的下限，连那条「总量上限」也不再参与 —— 你已经
告诉我们你的工作负载需要多少，再去猜一遍只会让这个键变得没用。

### 高占用按类别判断

`checks.process_anomaly.cpu_warn`（默认 80）本身**不是**可疑特征：编译、测试、扫描
必然如此。降级依据是结构性的（属于某个 systemd 单元 / 可执行文件由包管理器提供
**且**不是在跑内联代码 / 持有控制终端或父进程是交互式 shell / 命令行指向已登记的
工作目录）。**光凭进程名叫 `node`、`python3` 不降级** —— `node -e <payload>` 正是
要继续报的形状。

| 键 | 默认 | 含义 |
|---|---|---|
| `checks.process_anomaly.whitelist` | `[]` | 额外豁免的进程模式。只影响**报告**，不是永不处置清单 |
| `checks.process_anomaly.build_dirs` | `[]` | 构建 / 测试目录；命令行指向这里的进程自动降级。空表示只用站点根目录与结构判据 |

### 可用性检查理解认证闸门

站点装了登录闸门时，`401` / `403` / `302 → 验证页`都是**设计行为**，不再报故障。
但闸门站点**连验证页都打不开**（5xx / 超时）照常报 CRIT —— 一个发不出自己验证页的
闸门，比一个坏站点更值得慌。没配域名时这个检查直接跳过（会依次回退到
`gate.*.domain`）：

```sh
sudo vigil config set checks.site_availability.domain status.example.com
sudo vigil config set checks.site_availability.port 443
```

## 配置校验

`vigil config validate` 会指出真正会让告警发不出去的问题：没有渠道、没有收件人、
没有发件地址、白名单是空的。它不会因为风格问题报错。
