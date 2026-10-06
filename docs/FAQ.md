# 常见问题

## 会不会把我自己锁在外面？

**会，如果不配白名单的话。** 这是这个工具最可能造成的实际损失，请务必先做：

```bash
vigil threat allow <你自己的管理地址>
vigil threat list          # 确认白名单里有你
```

已经进不去了怎么办（面板/SSH 还能用的情况下）：

```bash
vigil threat unban <你的地址>       # 解封
vigil gate reset-holds --all        # 解开登录闸门的所有封禁
vigil bouncer clear                 # 清掉 nginx 侧的封禁
```

真的完全进不去，就从云厂商的控制台/VNC 进去，或让服务商协助。

## 误封了正常用户怎么办？

先解封，再找原因，不要直接关掉整个能力：

```bash
vigil threat unban 203.0.113.7      # 先恢复对方访问
vigil threat list                   # 看当前还有谁被封
vigil learn status                  # 看自学习是不是采纳了过于宽泛的特征
```

如果是某个特征造成的批量误封，用它对应的 `vigil <能力> status` 查看，并考虑把
该特征降级或加进白名单，而不是把整个能力删掉。

## 会不会拖慢机器？

设计目标是单核 1 GB 内存可用。它不在请求路径上做重活：请求侧的判断交给 nginx，
Python 侧主要处理日志与巡检。如果确实发现负载异常，可以先关掉负载最相关的能力：

```bash
vigil loadshed status     # 它会自动、可逆地降压
vigil threat status       # 看检测频率
```

## 告警邮件太多 / 太少怎么办？

默认策略是「普通事件攒批、严重事件立即发、未变化的持续异常每 6 小时才重提」。
节奏都在配置里，不用关掉整个告警通道：

```bash
sudo vigil config set mail.digest_min_items 10          # 普通事件攒更多条再发
sudo vigil config set mail.digest_max_wait 3600         # 最多等 1 小时
sudo vigil config set alerts.renotify_seconds 3600      # 未变化的异常每小时最多重提一次
sudo vigil config set alerts.recovery_quiet_seconds 0   # 0 表示关闭恢复抖动迟滞
```

严重事件（爆破成功、熔断、白名单命中、程序自身完整性…）与带 `immediate` 的
事件**永远立即发**，不受这些值影响；被压住的普通事件也不会丢。

调大这些值只改变**发信的节奏**，不会让异常消失：迟滞期间的异常仍然写进
`vigil health` 与 history，退出码仍为 1。想主动看现状随时 `vigil health`。

## 怎么只启用一部分能力？

每个能力都是独立的，互不依赖：

```bash
vigil hygiene status && vigil hygiene install     # 只要请求卫生
vigil shield status  && vigil shield install      # 只要 Web 层防护
```

`vigil install` 只是帮你把这些串起来；单独装某一项完全没问题。

## 怎么彻底卸载？

```bash
vigil uninstall          # 移除它写入的配置与服务
vigil service stop       # 如果还有残留的服务
```

它会在 `/var/lib/vigil-backup`（可用 `VIGIL_BACKUP_DIR` 改）留一份改动前的备份，
确认不需要后可以自行删除。

## 升级出问题怎么回滚？

```bash
vigil rollback           # 回到上一次更新之前
```

每次更新都会先把被替换的文件备份下来，所以回滚是可用的 —— 但仍建议在低峰期升级。

## 人机验证的图出不来怎么办？

默认情况下**图片是内联进页面的**（`data:` URI），不依赖任何后续请求，所以出现空白一般是别的原因：

- 浏览器把内联图片拦了（极少见，某些企业策略会）
- 服务端 GD 扩展缺失

页面会在 3 秒内自动切到**文字验证码**；也可以直接访问带 `?fallback=text` 的入口。
文字验证码的图片同样是服务端渲染并内联的，不依赖第二次请求。

## nginx 报 `limit_req ... uses the ... key while previously it used ...`，reload 一直失败？

这是**共享内存限流 zone 被同名换了 key**，也是极少数 `reload` 永远修不好的
nginx 配置错误。阴的地方在于 **`nginx -t` 反而通过**：它是全新解析，只看到一个
定义。于是配置检查说没问题，此后**每一次 `reload` 都以 `[emerg]` 失败**，
只有完整重启能恢复 —— 而完整重启会断掉所有连接。**给共享内存 zone 换 key
属于需要维护窗口的操作。**

本程序不会替你写出这种配置：写入前检测到同名换 key 就**拒绝**（不写任何文件、
不退役旧文件），并报出 zone 名与前后 key；真的遇到 nginx 的该 `[emerg]` 时，
它也会译成「**仅靠 reload 无法生效，需要完整重启 nginx**」。

处理方式（这份配置本程序不替你写）：

```bash
# 1) 要保留原 zone 名：在维护窗口手工改 key，然后完整重启而不是 reload
sudo systemctl restart nginx        # 会中断现有连接

# 2) 或者换一个新的 zone 名，并同步更新所有引用它的 limit_req / limit_conn
```

先完整重启、再重跑原来的操作没有帮助：只要新旧定义同名不同 key，本程序仍会拒绝。
设计原因见 [ARCHITECTURE.md](ARCHITECTURE.md)。

## 自动化测试的浏览器被判成可疑进程怎么办？

「从临时目录运行」是内存马的特征，但 Playwright / Puppeteer 这类工具会把浏览器
发行包解压到临时目录再执行，形状上完全一样。现在的豁免是**结构性**的，三条
同时成立才降级，且只针对「从临时目录运行」这一分支：

- 可执行文件名属已知浏览器（`chrome`、`chromium`、`headless_shell`、`firefox`…）；
- 路径里有浏览器发行布局目录名（`chromium-<版本>`、`chrome-linux64`、`browsers`、
  `ms-playwright`…）；
- 祖先链（最多 6 层、含自身）里存在受信自动化运行时（node / python / java /
  playwright / chromedriver / electron…）。shell 会被跳过，但**绝不受信**。

降级时进程仍列在检查结果的 OK 详情里，**不是静默忽略**；**可执行文件已被删除
的进程永不豁免**。已知残留：浏览器自带的 crashpad helper 按设计比浏览器活得久、
会被 reparent，祖先链里确实没有受信运行时了，**可能仍被判可疑**。要消除它必须
放宽某条判据（不再要求运行时祖先），会削弱检测，所以没有做 —— 看到它时知道是
什么即可。

## 有个进程被 vigil 暂停了（`ps` 里是 `T`），怎么回事？

先看它做了什么，再决定放不放：

```bash
vigil autoresponse status        # 暂停 / 观察了哪些进程、依据什么证据、还剩多久
vigil autoresponse log           # 处置台账：判定 → 动作 → 是否撤销
vigil autoresponse resume --all  # 一键恢复（发 SIGCONT）
```

这个能力**默认关闭**；打开后默认只做**可逆的** `SIGSTOP`（保留全部状态与证据），
而且会持续重新评估：一旦出现肯定性豁免证据（归属某个 systemd 单元、位于受信发行
布局、命中允许清单、可执行文件由包管理器提供、发现是本程序自己人）就自动恢复。
自己发 `kill -CONT <pid>` 也可以。

判定需要**两个来源不同的信号**（默认是「可执行文件已被删除」**且**「持有到可路由
地址的已建立连接」），而且要避开一整份**永不处置清单** —— PID 1、内核线程、本程序
自己的进程树、systemd 单元管理的进程、允许清单内的、自动化工具链、不同 PID 命名
空间的容器进程。动手之前还会复读身份并复核证据，任一项变了就放弃。

误判过一次，最省事的处理是豁免那个进程，而不是关掉整个功能：

```bash
sudo vigil config set threat.autoresponse.allowlist '["/usr/local/bin/my-worker"]'
sudo vigil config set threat.autoresponse.enabled false    # 或者整个关掉
vigil autoresponse resume --all                            # 已经暂停的别忘了放回来
```

完整设计见 [AUTORESPONSE.md](AUTORESPONSE.md)。

## 完整性检查说文件被改了，怎么知道是自己改的还是别人改的？

它先**归因**，再给结论，判据是**哈希**：

- 台账里的「改动后哈希」**等于**当前文件哈希 → 报「自修正（已记录）」，并指名是
  哪一条台账；
- 有该文件的记录但哈希**不符** → CRIT，报出期望与实际哈希；
- 无记录，但改动落在 `vigil update` 的部署窗口内 → 报「部署」；
- 其余 → CRIT，未归因。

台账是链式 HMAC（密钥在 `secrets.json`，`0600`），所以「我在台账里加一行说明是我
改的」这条路走不通：链会断，而**链断时所有改动都按未归因处理**并报出断点。记录还
必须新近（默认 24 小时窗口）—— 三个月前的一次自修正不能为今天的改动背书。

**它也有明确证明不了的东西**：链只能证明「已加链的记录没有被改写 / 删除 / 重排」，
证明不了「没有旧格式（无 MAC）的行被追加」。这条边界写在代码里，也写在
[EVOLVE.md](EVOLVE.md) 里。

如果被删 / 被改的是**本程序生成的配置**，它会自己重新生成、复检并与基线哈希比对；
本程序源码与操作者的文件永不自动还原，只报告。

## 小内存机器老是报内存不足 / 编译时 CPU 高就被报可疑？

两者都按**结构性判据**收敛过：

- **内存**：比例之外，还要「可用内存绝对值低于按总内存缩放出的下限」同时成立。
  默认比例阈值在小机器上会自动放宽（≤4 GB → 16%，≤2 GB → 12%）；那条绝对下限在
  大机器上才是真正起作用的一条 —— 64 GB 上的 17%（11 GB 可用）因此不会被报。
  你显式写下的 MB 下限**绝不被改写**。
- **高 CPU**：编译、测试、扫描必然高占用。属于 systemd 单元、可执行文件由包管理器
  提供且不是在跑内联代码、持有控制终端或父进程是交互式 shell、命令行指向已登记的
  工作目录 —— 命中任一条就降级。但**光凭进程名叫 `node`、`python3` 不降级**。

```bash
sudo vigil config set checks.memory.warn_available_mb 512   # 按自己的工作负载定死下限
sudo vigil config set checks.process_anomaly.build_dirs '["/srv/build"]'
```

细节与全部键见 [CONFIGURATION.md](CONFIGURATION.md)。

## 为什么不用 fail2ban / CrowdSec？

它们很好，本项目也不打算取代它们。区别在于关注点：

- fail2ban / CrowdSec 擅长**从日志里认 IP 并封禁**，生态成熟、规则丰富。
- 本项目把「登录闸门 + 敏感文件暴露扫描 + 诱饵 + 审计归因 + 自检」放在一起，
  并且**每个能力都带自检**，回答的是「装好的东西到底有没有在工作」。

两者可以并存。如果你已经有 CrowdSec，完全可以只使用本项目的闸门与暴露扫描。

## 日志在哪？

```bash
vigil service logs          # 程序日志
vigil audit status          # 内核审计规则
vigil status                # 一眼看完当前状态
```

## 密码/凭据忘了怎么办？

凭据以 bcrypt 摘要保存，无法还原。删掉凭据文件后重新 `vigil install` 即可重设：

```bash
vigil config path           # 找到凭据文件位置
```

## 能不能管多台机器？

当前设计是**单机**的：它读写本机防火墙、本机 nginx、本机审计规则。多机场景请用
配置管理工具统一分发，或考虑成熟的集中式方案。

## 自修正循环会不会把服务器改坏？

不会改它不该改的东西，而且**能退回去**：

- 能自动改的只有「诱饵路径」这类**行为数据**，且有硬门槛（≥8 次命中且 ≥3 个独立来源）。
- 改**源码**默认关闭；打开后也只能动唯一一个被许可的文件，并受单一锚点、行数上限、
  每日上限、改前备份、**测试不过自动还原**五重约束。
- 另有一份 `CRITICAL_FILES` 禁碰清单（封禁决策、审计链、上报脱敏、配置、邮件通道、
  以及它**自己**的边界代码）—— 许可表可以被编辑，这份锁不会。
- 每次改动**先发邮件**再落笔，改完写只增台账，`vigil evolve rollback <id>` 逐条撤销。
- 资源占用按**可用量的比例**给，可用内存不足、负载过高就直接不开工。

## 它凭什么说自己「会学习」？

标签不是人标的，是本机**已经发生的处置结果**：命中过诱饵、或随后被封禁的请求是
正样本，被正常服务的是负样本。它用这些样本来改进下一步判断 —— 这叫自监督。

而且能力是被**验证**过的，不是被声明的：`vigil evolve novel` 会把整族未见过的
命名习惯排除在训练之外再来考它，并同时给出正常路径的对照组与误报数 ——
只看「认出多少攻击」没有意义，一个把什么都判成攻击的模型也能拿 100%。
