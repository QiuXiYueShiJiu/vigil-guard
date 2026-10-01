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
  "threat":     { /* 实时风控与自动封禁 */ },
  "loadshed":   { /* 高负载时限流 */ },
  "checks":     { /* 安全巡检项 */ },
  "malware":    { /* 恶意文件扫描 */ },
  "gate":       { /* 登录界面防护，见 GATE.md */ },
  "auditd":     { /* 内核审计规则 */ },
  "logging":    { "level": "INFO", "keep_days": 30 }
}
```

完整字段见 `examples/config.typical.json`，或读
`src/vigil/core/config.py` 里的 `DEFAULTS`（那是唯一权威）。

## 白名单：最容易把自己锁在外面的一项

`threat.whitelist` 里的地址**永远不会被封禁**。默认只有回环地址。

```sh
sudo vigil threat whitelist add 203.0.113.10
sudo vigil threat whitelist
```

> 如果你的管理 IP 是运营商动态分配的，把它加进白名单等于没加 —— 换个网段就失效了。
> 这种情况下靠的是「先确认能登录，再收紧」，而不是靠白名单。

## 配置校验

`vigil config validate` 会指出真正会让告警发不出去的问题：没有渠道、没有收件人、
没有发件地址、白名单是空的。它不会因为风格问题报错。
