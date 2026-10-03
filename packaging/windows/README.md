# vigil-agent for Windows

`vigil-guard` 的核心是 nginx 诱饵、ipset/iptables 封禁、systemd 与 auditd ——
**这些在 Windows 上都不存在**。把一个跑不起来的完整移植叫「Windows 版」是骗人，
所以这里只装**在 Windows 上确实成立、确实有用**的那一半。

## 这里有什么

`vigil-agent.ps1` —— 纯 PowerShell，无第三方模块，无需安装服务，可以全文读完再跑：

| 能力 | 说明 |
|---|---|
| 文件完整性基线 | 对指定目录递归取 SHA-256，建立基线并检出新增 / 修改 / 删除 |
| 上报 | 用与 Linux 端**同一套脱敏规则**发到同一个收集端（主机身份不上传） |
| 资源上限 | 没有 cgroup 配额，改用**开工前让路**：可用内存低于下限、或可分预算过小就不跑 |
| 台账 | 每次运行追加一行 JSONL 到 `%ProgramData%\vigil\ledger.jsonl` |

## 这里没有什么（以及为什么）

- **诱饵 / 蜜罐**：依赖 nginx 的 `location`，Windows 上换成 IIS 重写规则是另一套东西，没做。
- **自动封禁**：依赖 ipset/iptables。Windows 防火墙规则可以用 PowerShell 写，但那需要
  对「封谁、封多久、怎么回滚」做完整设计，不是随手加两行该做的事。
- **登录闸门 / 验证码**：与面板和 nginx 强绑定。
- **自修正循环**：那一套依赖本项目的 Python 包与测试闸门，随 Linux 发行版提供。

## 用法

```powershell
# 建基线并立刻退出
.\vigil-agent.ps1 -Paths 'C:\inetpub','C:\ProgramData\ssh' -Once

# 常驻（建议用计划任务以 SYSTEM 身份在开机时启动）
.\vigil-agent.ps1 -Loop -IntervalSeconds 900 `
    -ReportUrl 'https://你的收集端/evolve/report.php' `
    -MemoryFloorMB 384
```

以 SYSTEM 跑之前请先通读脚本；这也是本项目对 Linux 侧安装脚本的同一要求。
