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
