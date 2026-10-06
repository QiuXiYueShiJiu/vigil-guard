# 安装

## 环境要求

| 项目 | 要求 | 说明 |
|---|---|---|
| 操作系统 | Linux（systemd） | 其他 init 需要自行写单元文件 |
| Python | **3.8+**，仅标准库 | 没有 `pip install` 这一步 |
| 权限 | root | 要写 iptables、auditd、系统服务 |
| 可选 | PHP 7.4+ / GD | 只有装登录界面防护时才需要 |
| 可选 | nginx（带 lua 模块） | 同上，用于请求期拦截 |

**零第三方依赖**是硬约束，不是偏好：目标环境常常是台装不上包、也连不上 PyPI 的机器。
`tests/test_vigil.py::TestPackaging` 会遍历 `src/` 下每个 `import` 来守住这条线。

## 安装

```sh
git clone <仓库地址> vigil && cd vigil
sudo ./install.sh
sudo vigil doctor          # 环境自检：这台机器支持哪些能力
sudo vigil status          # 现在是否一切正常
```

`install.sh` 只做三件事：把 `src/vigil` 复制到 `/usr/local/lib/vigil`、写一个
`/usr/local/bin/vigil` 启动器、把 systemd 单元装上。它**不**碰 nginx、不碰面板、
不改防火墙 —— 那些都要你显式跑 `vigil gate install` / `vigil threat enable`。

## 内置管理后台（可选，`dashboard/`）

仓库自带一个**完整的管理后台**（实时态势地图 + 管理控制台）。
**`install.sh` 不会装它** —— 它要全盘文件权限和自己的 vhost，装它应该是一次
明确的决定：

```sh
cp dashboard/config.example.json dashboard/config.json   # 填 public_host 与坐标
sudo bash dashboard/deploy/install.sh
```

**部署前必须把 `dashboard/config.json` 填好**：

- `public_host` 还是模板里的占位值时，脚本**直接拒绝安装**，不会把一个连不上的
  站点发出去；域名、webroot、显示名与地图坐标全部来自这个文件，源码里没有真实值。
- 控制台账号来自 `console_account`（默认 `vigil`），**口令要用
  `vigil-dash set-password` 单独设置** —— 没设口令就谁都进不去控制台。

页面本身由 **nginx 直接静态提供**，只有 `/api/` 反代到 `127.0.0.1:9310` 的
Python 服务 —— 静态资源、gzip 与 TLS 都在 nginx 上，进程只回答接口。这意味着
**改完前端要重新执行一次 `bash dashboard/deploy/install.sh`**（幂等：重算资源
内容哈希并替换文件），重启服务不会更新静态页面。本文档只说明它做什么，不代替
你执行。

它动的东西：

| 路径 | 内容 |
|---|---|
| `/etc/systemd/system/vigil-dashboard.service` | 独立进程，默认只监听 `127.0.0.1:9310` |
| `<config 里的 webroot>` | 静态页面与内容哈希资源（默认 `/www/wwwroot/<public_host>`） |
| `/var/lib/vigil-dashboard` | 会话、审计日志、控制台口令派生值 |
| `/www/server/nginx/conf/vigil-dashboard-sites/` | 站点开关片段（它自己的目录） |
| `<面板 vhost 目录>/<public_host>.conf` 等 | 反代站点、封闭名单、证书校验目录 |
| `/usr/local/bin/vigil-cert-sync` | 证书同步钩子（**已存在则不覆盖**） |

它和 `vigil web` 那个最小状态页是两回事，分工见 [WEB.md](WEB.md)。
没有专门的卸载命令：删掉上面这些文件与服务即可 —— 脚本全程只按自己的命名
写文件，不会碰别人的 vhost。

## 升级

```sh
git pull
sudo vigil update
```

`vigil update` 从当前源码目录重新部署，并重启常驻守护进程。配置、状态、
已签发的会话都不受影响。

### 升级之后：自己生成的东西会自己补回来

`vigil update` 会重装程序本体，并在部署窗口内改动**包内文件** —— 这些改动会被
归因为「部署」，而不是 CRIT。此后如果发现**本程序生成的配置**（登录网关的
nginx 片段与 Lua 配置、防护片段…）被删或被改，自检会**自动重新生成**、复检
（独立重算期望内容并与基线哈希比对）并报告做了什么。

**只在生成物上**：本程序源码与操作者的文件**永不**自动还原 —— 静默回滚会掩盖
真实入侵，报告必须留给人看。改动落在 `vigil update` 的部署窗口内会被归因为
「部署」，本程序自己的自修正按台账哈希归因，其余一律 CRIT。写入前还会过一遍
「限流区同名换 key」的检查，避免自动恢复把 v3.2.3 修掉的那类事故引回来。细节见
[ARCHITECTURE.md](ARCHITECTURE.md)，归因判据与它的边界见 [EVOLVE.md](EVOLVE.md)。

升级前后建议各跑一次 `vigil health`：升级前是基准，升级后能立刻看出哪些改动是
这次部署带来的。

## 这台机器上它动了什么

| 路径 | 内容 |
|---|---|
| `/usr/local/lib/vigil` | 程序本体 |
| `/usr/local/bin/vigil` | 启动器 |
| `/etc/vigil/config.json` | 配置 |
| `/etc/vigil/secrets.json` | 密钥（0600，与配置分开） |
| `/var/lib/vigil` | 状态：封禁记录、邮件队列、序号 |
| `/var/log/vigil` | 日志 |
| `/etc/systemd/system/vigil-*.service` | 常驻进程 |

登录界面防护装到哪里，由 `--state-dir` / `--webroot` 决定，默认见
[GATE.md](GATE.md)。

## 卸载

```sh
sudo vigil uninstall                # 停服务、删程序；保留配置、状态与日志
sudo vigil uninstall --keep-logs    # 再加删配置与状态，只留 /var/log/vigil
sudo vigil uninstall --purge        # 全部删除，不可恢复
sudo vigil uninstall --dry-run      # 只打印将要做什么
```

**三种方式都会撤回本程序生成的网页配置**（诱饵、诱导面、请求卫生、登录网关、
状态页反代），只按本程序命名的文件匹配，不会碰站点自己的 vhost。

撤回是**可逆**的：脚本先把文件移到隔离区并摘掉相关的 `include` 行，跑 `nginx -t`，
通过才真正删除；**不通过就把文件和 include 行一起搬回**。这样即使撤回逻辑本身出错，
站点也不会因为一次卸载而无法重载。

### 不会覆盖，也不会删除别人的 vhost

`vigil web install --domain <域名>` 的目标文件若已存在、又不带本程序生成的标记
（首行 `# >>> vigil web (generated; do not edit) >>>` 与结尾 `# <<< vigil web <<<`），
它会**拒绝写入**，报出该文件路径，并提示用什么方式才覆盖：

```sh
sudo vigil web install --domain status.example.com          # 别人的 vhost → 拒绝并给出路径
sudo vigil web install --domain status.example.com --force  # 明确接受覆盖
```

反过来，`vigil web uninstall` **绝不删除**不是本程序生成的配置：文件名
`<域名>.conf` 是面板也会用的命名，所以只认标记、不认文件名 —— 不是自己写的就
跳过并列出，由你自行确认后手动处理。

### 已经写进系统的防护要显式撤销

卸载**不会**自动撤销已经写进系统的防护（iptables 规则、auditd 规则、nginx 接线）。
那些是显式安装的，也要显式撤销：

```sh
sudo vigil gate uninstall bt_panel
sudo vigil threat disable
sudo vigil audit disable
```
