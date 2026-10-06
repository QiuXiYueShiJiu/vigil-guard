# 文档索引

| 文档 | 讲什么 |
|---|---|
| [INSTALL.md](INSTALL.md) | 安装、升级、卸载，以及它到底改了系统里的什么；不会覆盖别人的 vhost |
| [CONFIGURATION.md](CONFIGURATION.md) | 配置文件的组织、密钥分离、导入导出、告警节奏与迟滞 |
| [WEB.md](WEB.md) | 状态页与内置管理后台：两个页面的分工、交互逻辑、安全取舍 |
| [../dashboard/README.md](../dashboard/README.md) | 内置管理后台：部署（`dashboard/deploy/install.sh`）、配置项与安全边界 |
| [EVOLVE.md](EVOLVE.md) | 自修正：边界、自监督训练、泛化验证、关键文件禁碰 |
| [MAIL.md](MAIL.md) | 告警通道：8 类渠道、21 个 SMTP 预设、自建域名、攒批与降级 |
| [GATE.md](GATE.md) | 登录界面防护：宝塔面板与独立登录页，含「接入已有配置」 |
| [ARCHITECTURE.md](ARCHITECTURE.md) | 代码结构、进程模型、为什么零依赖、共享内存 zone 的运行期约束 |
| [../tools/exposure-check/README.md](../tools/exposure-check/README.md) | 独立校验器：检查 `^~` 前缀里规则还在不在，可当网页后端调用 |
| [FAQ.md](FAQ.md) | 常见问题：误封了怎么办、`nginx reload` 一直失败、怎么只装一部分 |

想快速上手直接看仓库根的 `README.md`；这里放的是分主题的细节。
