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
