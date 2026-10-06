# 可疑进程的自动响应

`vigil autoresponse` —— 本程序里**唯一会去动别的进程**的功能。

绝大多数安全组件止步于「报告」：发现有问题的进程，写进日志、发封邮件，然后等
人来处理。这个功能往前多走了一步 —— 于是**护栏比功能本身重要**。一次误判的
自动处置会直接把服务器搞挂，那比放过一个攻击者严重得多。所有默认值都是按这个
取舍选的。

> 一句话：**宁可漏处置，也绝不误杀。**

## 默认关闭，而且必须显式打开

`threat.autoresponse.enabled` 默认是 `false`。关闭时这个功能**不动任何进程**；
唯一还会跑的是「自动化工具链消解」（见下文），因为它只会让报告变少，永远不会
导致某个进程收到信号。

```sh
sudo vigil config set threat.autoresponse.enabled true    # 显式决定
sudo vigil autoresponse status                            # 先看看它现在打算做什么
```

打开它意味着允许本程序暂停这台机器上的任意进程（永不处置清单之外的），这应该
是一次明确的决定，而不是一个默认值。

## 默认只做可逆的 `SIGSTOP`

| `threat.autoresponse.action` | 含义 |
|---|---|
| `stop`（**默认**） | 发 `SIGSTOP`：进程被暂停，**全部状态、内存与证据保留**，随时可以 `SIGCONT` 继续 |
| `terminate` | 按 `terminate_signal`（默认 `SIGTERM`）终止。**不可逆**，需要显式配置 |

选可逆动作只是第一步；**「可撤销」必须真的有人去撤，否则等于没有**。所以暂停
之后继续观察：

1. **观察期**（`observe_seconds`，默认 120 秒）：判定成立后先不动手，这段窗口内
   一旦出现任何豁免证据就放弃 —— 一瞬的可疑形状不足以动手，要求特征在时间上持续。
2. **动手**：信号发出**之前**，先发一封高优先级告警、先把证据写盘。
3. **恢复观察窗**（`resume_window_seconds`，默认 600 秒）：暂停之后每轮重新评估。
   出现**肯定性豁免证据**（归属某个 systemd 单元 / 位于受信发行布局 / 命中允许
   清单 / 可执行文件由包管理器提供 / 发现它其实是本程序自己人）就自动 `SIGCONT`
   并记一条「已撤销」。
   **读失败不恢复**：「读不到」不等于「它没问题」，因为 `/proc` 忙一下就把内存马
   放走，是和「只报不修」同一类的错误。
4. **恢复观察窗结束之后**（`after_observe`）：`hold`（**默认**）保持暂停、只报告、
   等操作者决定；`terminate` 升级为 `terminate_signal`。

## 高置信才动手：两个**来源不同**的信号

只报告、不处置，是绝大多数调用走到的地方（`DECISION_REPORT`）。要拿到
`DECISION_RESPOND`，以下条件必须同时成立（`procresponse.HIGH_RULE`）：

> 可执行文件已被删除且磁盘上不存在（独立信号 A）
> **且**持有到非环回地址的已建立连接（独立信号 B，与 A 来源不同）
> **且**不属于任何 systemd 单元
> **且**不在浏览器 / 自动化发行布局内
> **且**不在允许清单里

为什么是这两类，而不是「从临时目录运行」：

- 仅仅「可执行文件已被删除」很常见而且通常无害（一次包升级就会这样）；
- 仅仅「从临时目录运行」是误报工厂（构建工具、浏览器发行包、安装器）；
- 两者**各自一类**，再加上一条**活的对外连接**，这个形状就不再能用日常运维解释。

「从临时目录运行」这个信号被**刻意移出**了高置信规则 —— 它和「路径看着奇怪」
属于同一类证据，而浏览器下载恰好就在临时目录里。把它留在规则里，就得靠自动化
豁免去补偿一个本来就不该在那儿的信号。

判定与实际动作之间还会有两次复核，因为事实会变：

- **动作前复读**：重新读一次进程信息与连接，确认第二个信号此刻仍然成立 ——
  「五分钟前有过连接」不能用来为现在的动作背书；
- **豁免复读**：`exempt_reason()` 会被调用两次（分类时一次、发信号前一次），
  身份、cgroup、允许清单、可执行文件都可能在这中间变化。

### 动手前先固化证据

证据先写盘再动手（默认目录 `/var/lib/vigil/state/autoresponse-evidence`）。
内存马一旦被杀，证据就跟着消失；**写不下去就拒绝处置** —— 没有证据的处置等于
不可追溯的破坏。证据包括：可执行文件哈希（通过 `/proc/<pid>/exe` 读，这是给一个
已被删除的二进制算哈希的唯一办法）、命令行、父进程链、对外连接、cgroup 单元。

## 永不处置（硬编码）

以下进程无论置信度多高都不会被处置。这不是配置项，是代码里的硬判断：

| 对象 | 原因 |
|---|---|
| **PID 1** | `init`。信号它是把整台机器拖下水 |
| **内核线程** | 没有用户态映像，由内核持有（`kworker/0:1`、`ksoftirqd/0` 这类带修饰的名字也认） |
| **本程序自己的进程树** | 走真实的 `ppid` 链判断，不认 `comm` —— 每个守护进程在 `ps` 里都叫 `python3`，而「把自己杀掉」是自动化最丢人的故障 |
| **systemd 单元管理的进程** | 重启策略、依赖关系与审计都在单元一侧，绕过它处置会与 systemd 打架 |
| **允许清单内的进程** | 操作者的显式豁免（`threat.autoresponse.allowlist`），硬豁免 |
| **浏览器 / 自动化工具链** | 按纯结构判定（发行布局目录名 + 浏览器或 helper 文件名），只从报告与处置路径里拿掉，**绝不进入自动处置** |
| **不同 PID 命名空间的进程** | 通常是容器。在那个命名空间里发信号，可能落到同号的**无关**进程上 —— 这是「信号打错人」的唯一直通路径 |
| 可执行文件由系统包管理器提供 | 安装包里的程序被暂停，症状会出现在完全无关的地方 |
| 可执行文件位于受信发行布局内 | 同上，按路径结构判断 |

判定「内核线程」时有一个刻意收紧的地方：空的 `/proc/<pid>/exe` 本身**不算**
证据（权限不足读不到、二进制被删除后也读成空）。要求的是「没有用户态映像
**且**没有命令行」或「父进程是 `kthreadd`」—— 否则一个已被删除的载荷会被
当成内核线程放过去，那是这个模块能犯的最坏的假阴性。

## 身份绑定：防 PID 复用

进程标识记为 `(pid, 启动时间, exe 设备号 + inode, exe 路径)`。动作之前复读一次，
**任一项不一致就放弃**：PID 会被复用，`SIGCONT`/`SIGTERM` 打到一个恰好拿到同号
的无关进程上，是另一种形式的破坏。撤销（`resume`）时同样复核 —— 不一致就照发，
但会明确告诉你「pid 已被复用，恢复的可能不是原进程」。

## 限频与告警

- **每小时上限**：默认 2 个，配置上限 10（`max_per_hour` 会被夹到 10）。超过就
  只报告并说明已达上限。
- **每次动作一封告警**：`SEV_CRIT`、在立即通道上、**不去重**。理由是它不是「某个
  持续状态」而是一个**事件** —— 从用户抱怨「服务卡住了」才知道有进程被暂停，
  已经太晚了。告警正文里直接给出撤销方式（`kill -CONT <pid>`）与误判处理办法。
- **已处置的进程从后续判定中排除**，否则每一轮都会重新判一次同一个进程，信号
  会一直发下去。

## 命令

```sh
sudo vigil autoresponse status           # 暂停 / 观察中的进程、依据、剩余观察时间
sudo vigil autoresponse resume --all     # 撤销全部：发 SIGCONT 让它们继续跑
sudo vigil autoresponse resume 1234 5678 # 撤销指定的几个
sudo vigil autoresponse log --limit 50   # 处置台账：判定、动作、撤销，逐条可追溯
```

`resume` 只发 `SIGCONT`，不「顺便修好」任何东西，而且**刻意不需要功能处于开启
状态** —— 把功能关掉不应该把已经暂停的进程留在那里冻着。人的决定立刻覆盖自动
判定，不用改配置、不用重启任何东西。

## 配置

| 键 | 默认 | 含义 |
|---|---|---|
| `threat.autoresponse.enabled` | `false` | 总开关。**默认关闭** |
| `threat.autoresponse.action` | `stop` | `stop` = `SIGSTOP`（可逆）；`terminate` = 按 `terminate_signal` |
| `threat.autoresponse.observe_seconds` | 120 | 判定成立后先观察这么久，期间出现豁免即放弃 |
| `threat.autoresponse.resume_window_seconds` | 600 | 暂停后继续观察这么久，证据被推翻就自动恢复 |
| `threat.autoresponse.after_observe` | `hold` | 恢复观察窗结束后：`hold` 保持暂停等操作者；`terminate` 升级 |
| `threat.autoresponse.terminate_signal` | `SIGTERM` | 直接终止时用的信号；`SIGKILL` 不可挽回，需显式配置 |
| `threat.autoresponse.max_per_hour` | 2 | 每小时最多处置几个（上限 10） |
| `threat.autoresponse.allowlist` | `[]` | 操作者允许清单：命中的进程**永不处置** |
| `threat.autoresponse.evidence_dir` | 空 | 留空则用 `/var/lib/vigil/state/autoresponse-evidence` |

> `threat.autoresponse.allowlist` 和 `checks.process_anomaly.whitelist` 是两件事：
> 后者只影响**报告**，前者是**硬豁免**，会写进「永不处置」清单。

```sh
# 误判过一次之后，最省事的做法是把这个进程豁免掉，而不是关掉整个功能
sudo vigil config set threat.autoresponse.allowlist '["/usr/local/bin/my-worker"]'
sudo vigil config set threat.autoresponse.enabled false    # 或者整个关掉
sudo vigil autoresponse resume --all                       # 已经暂停的别忘了放回来
```

## 状态与文件

| 路径 | 内容 |
|---|---|
| `/var/lib/vigil/state/health.json` | `autoresponse` 段：暂停中 / 观察中的进程记录 |
| `/var/lib/vigil/state/autoresponse.jsonl` | 只增处置台账（判定、动作、撤销），`vigil autoresponse log` 读它 |
| `/var/lib/vigil/state/autoresponse-evidence/` | 每次动作前固化的证据（默认目录） |

它由巡检进程（`vigil-healthd`）在**已有的**可疑进程候选上执行，不新增常驻进程：
候选本来就在那里，处置放在这里不需要再多一个会挂的东西。

## 相关文档

- [ARCHITECTURE.md](ARCHITECTURE.md) —— 进程模型与模块分工
- [CONFIGURATION.md](CONFIGURATION.md) —— 配置文件的组织与全部配置项
- [FAQ.md](FAQ.md) —— 误判了怎么办
