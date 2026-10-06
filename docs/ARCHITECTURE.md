# 架构

## 目录

```
src/vigil/
  cli.py            argparse 命令树（菜单分组在 COMMAND_GROUPS）
  ui.py             终端输出：表格、面板、彩色/无色、中英
  i18n.py           中英文案表
  core/             与业务无关的地基
    paths.py        所有路径的唯一来源，环境变量可覆盖（便于测试）
    state.py        原子写 + flock + 深合并；Store 是带点号寻址的 JSON 文档
    shell.py        永远 stdin=DEVNULL、永远带超时
    config.py       DEFAULTS schema、密钥分离、导入导出
    detect.py       环境探测（结果缓存，见下）
    installer.py    部署、systemd 单元、atomic write
  mail/             告警子系统
    message.py      数据结构（Alert/Message/Section）
    render.py       纯文本 + HTML，先转义再上标记
    router.py       按收件人降级、去重、额度
    queue.py        序号、额度、去重、积压、日志
    providers/      8 类渠道，注册表式
    commandd.py     IMAP 回信指令
  guards/           防护能力
    threat.py       实时风控与自动封禁
    loadshed.py     高负载限流
    health.py       巡检调度
    logind.py       登录事件（SSH + 网关）
    checks/         36 个巡检项，ASCII id
  gates/            登录界面防护
    spec.py         配置模型 + 从实时安装回读
    installer.py    渲染模板、原子写、PHP 冒烟测试
    scenes.py       图库扫描、黑名单
    providers.py    公开图库取图
    templates/      Lua / PHP / nginx 模板
```

## 为什么零依赖

目标环境常常是一台装不上包、也连不上 PyPI 的机器。所以：

- HTTP 用 `urllib`，不是 `requests`
- 图片头自己解析（`gates/scenes.py`），不是 Pillow
- 锁用 `fcntl.flock`，不是 `filelock`

代价是要多写一点代码。收益是 `git clone && ./install.sh` 在任何有 CPython 的
Linux 上都能跑通，不需要先解决一个包管理问题才能开始解决安全问题。

`TestPackaging.test_only_standard_library_is_imported` 会遍历 `src/` 下每一行
import 来守住它。

## 进程模型

| 单元 | 干什么 | 周期 |
|---|---|---|
| `vigil-threatd` | 实时风控：读日志、判违规、封禁、发告警 | 常驻 |
| `vigil-healthd` | 安全巡检：跑检查项、汇总、发告警 | 常驻 |

登录界面防护**没有**常驻进程。它在 nginx 的请求路径上（Lua），
状态放在文件里。少一个会挂的进程，就少一种「防护本身变成故障源」的方式。

## 环境探测是缓存的

`detect.full()` 会去 shell 出 nginx、systemctl、php-fpm，还会**真的开一条
TCP 到 25 端口**判断能不能直连发信。一次约 8 秒。

它被安装器、`doctor`、`GateSpec.for_kind` 反复调用。没有缓存时，一条命令
绝大部分时间都花在重复探测同样的东西上 —— 测试套件因此跑不完。
`detect.full()` 和 `detect.port25_open()` 都带缓存，`refresh=True` 可强制重探。

## 状态写入

日志会被 OOM killer 杀掉、会被 `systemctl restart`、会被操作者在凌晨三点手动重启。
**写了一半的状态文件永远不能被读到**，所以：

- 所有写入都是「同目录临时文件 → fsync → `os.replace`」
- 状态目录用 `flock` 做单写者互斥，进程被 SIGKILL 时内核会释放锁
- 读取永远先合并默认值，旧版本写的状态不会让新版本崩

## 安全上的几个刻意选择

- **失败即拒绝。** 票据解析出错、字段形状不对、绑定哈希缺失，一律当作无效。
- **审计 `-w` 绑的是 inode。** `mv` 覆盖可以绕过文件监视，所以关键路径要监视**目录**。
  另外 `augenrules` 遇到一个不存在的 `-w` 目标会**丢弃其后全部规则** —— 这个坑很安静。
- **不内嵌本机信息。** 仓库里没有 IP、域名、邮箱、主机名。
  `TestNoHardcodedHostData` 会扫源码和文档。
- **审计先解码再匹配。** `core/sourceaudit.py` 在比对规则前，先把
  `\uXXXX` / `\UXXXXXXXX` / `\xXX` 三种转义**解码一次**再匹配。原因是一个真实
  账号名曾以 `"\u0061\u0064\u006d\u0069\u006e"` 这类形式同时躲过人工 grep、本地
  禁止清单的字面量规则和所有形状规则 —— 三者都在比对原始字节。只解这三种、
  只解一次，正常代码里的 `"\n"`、`"\t"`、正则 `\d` 不受影响；`"\\uXXXX"`
  （被引用的转义字面量）因负向后顾也不会被误解码；代理区与越界码位原样保留。
- **可疑进程的判据是结构性的。** 「从临时目录运行」是内存马的特征，但浏览器
  自动化工具链会把 Chromium 发行包解压到临时目录再执行。豁免要求三条**同时**
  成立：可执行文件名属已知浏览器 × 路径含浏览器发行布局目录名
  （`chromium-<版本>`、`chrome-linux64`、`browsers`、`ms-playwright`…）×
  祖先链（最多 6 层、含自身）里存在受信自动化运行时。shell 会被**跳过但绝不受
  信** —— `bash -c <payload>` 正是该继续告警的形状；**可执行文件已被删除的进程
  永不豁免**。已知残留：浏览器自带的 crashpad helper 按设计比浏览器活得久、
  会被 reparent，祖先链里确实没有受信运行时了，可能仍被判可疑 —— 放宽这条
  判据会削弱检测，所以没有做。

## 运行期换不掉的共享内存 zone

`limit_req_zone` / `limit_conn_zone` 在 nginx 首次载入时于共享内存里创建，并
**绑定它的 key 表达式**。同名 zone 换一个 key 时：

- `nginx -t` **通过** —— 全新解析只看到一个定义；
- 但从写入那一刻起，**每一次 `reload` 都以 `[emerg]` 失败**，报
  `limit_req "X" uses the "Y" key while previously it used the "Z" key`，
  **只有完整重启（`systemctl restart nginx`）能恢复** —— 而完整重启会断掉所有
  连接。操作者看到的现象就是「nginx 挂了」。

所以 `gates/shield.py` 在**写入前**就读出当前与将被退役的 zone 定义，同名不同
key 时**直接拒绝写入**（不写任何文件、不退役旧文件、也不产生 `.retired-*`）。
为什么不改名绕开：真实站点的 `limit_req` / `limit_conn` 引用的正是这些历史
zone 名，改名会让它们 `nginx -t` 失败；保留一个同名同 key 的过渡定义则让那些
站点继续走旧 key（白名单豁免永远到不了它们）—— 策略在两个 zone 之间悄悄分裂。
拒绝是唯一不留半套策略的做法。

遇到该 `[emerg]` 时（`limit_req` / `limit_req_zone` / `limit_conn` /
`limit_conn_zone` 都覆盖），程序把它译成「**仅靠 reload 无法生效，需要完整重启
nginx**」，并报出 zone 名与前后 key，而不是丢一句 nginx 原文。运维步骤见
[FAQ.md](FAQ.md)。

## 自修正循环（`evolve/`）

| 模块 | 职责 |
|---|---|
| `budget.py` | 资源闸门：按**可用量**的固定比例计算预算，不满足就不开工 |
| `score.py` | 在线逻辑回归：哈希特征 + 逐步 SGD，决策可逐条读回 |
| `corpus.py` | 按**族类**组织的训练语料，以及「整族留出」的泛化测试 |
| `train.py` | 自监督标签（来自本机处置结果）、批量训练、结果回看 |
| `ledger.py` | 只增台账与备份：改动前先写下来，才谈得上回滚 |
| `report.py` | 上报（脱敏 + 服务端二次校验）与改前邮件 |
| `__init__.py` | 证据 → 提案 → 闸门 → 应用/回滚 → 闭环；关键文件禁碰清单 |

设计取舍见 [EVOLVE.md](EVOLVE.md)。
