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

## 升级

```sh
git pull
sudo vigil update
```

`vigil update` 从当前源码目录重新部署，并重启常驻守护进程。配置、状态、
已签发的会话都不受影响。

## 卸载

```sh
sudo vigil uninstall              # 停服务、删代码，保留配置与状态
sudo vigil uninstall --purge      # 连配置、状态、日志一起删（不可恢复）
sudo vigil uninstall --dry-run    # 只打印将要做什么
```

卸载**不会**自动撤销已经写进系统的防护（iptables 规则、auditd 规则、nginx 接线）。
那些是显式安装的，也要显式撤销：

```sh
sudo vigil gate uninstall bt_panel
sudo vigil threat disable
sudo vigil audit disable
```

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
```

**三种方式都会撤回本程序生成的网页配置**（诱饵、诱导面、请求卫生、登录网关、
状态页反代），只按本程序命名的文件匹配，不会碰站点自己的 vhost。

撤回是**可逆**的：脚本先把文件移到隔离区并摘掉相关的 `include` 行，跑 `nginx -t`，
通过才真正删除；**不通过就把文件和 include 行一起搬回**。这样即使撤回逻辑本身出错，
站点也不会因为一次卸载而无法重载。
