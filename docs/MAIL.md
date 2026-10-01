# 告警通道

## 一条告警的旅程

```
事件 → 渲染（纯文本 + HTML）→ 编号 → 额度检查 → 去重 → 逐收件人降级投递
                                              ↘ 全部失败 → 进积压队列，定时补发
```

- **按收件人降级**，不是按告警：A 收件人在 QQ 上、B 收件人在 Outlook 上，就该走不同通道。
- **编号**：每封邮件一个递增序号（`#000172`），写进正文和 HTML 顶部。回信引用时能对上号。
- **去重**：同一个条件在窗口期（`mail.dedupe_window`，默认 900 秒）内只发一次；
  但命令回执永不dedupe（`allow_dedupe=False`），因为那是一次性的对话。
- **额度**：`mail.daily_quota`（默认 100，按 UTC 日重置）。存在的意义是拦住
  「告警风暴把计量额度烧光」，不是替服务商执行限额。
- **积压**：所有通道都失败时落到 `/var/lib/vigil/mail/overflow/`，
  由摘要任务在通道恢复后补发。补发前会先 `rename` 抢占文件，两个并发任务不会重发同一封。

## 支持的渠道

```sh
vigil mail providers
```

| ID | 类型 | 适用 |
|---|---|---|
| `resend` | HTTPS API | 有自有域名，不要运维 MTA，最省事 |
| `sendgrid` / `mailgun` / `brevo` | HTTPS API | 同类替代 |
| `aliyun` | HTTPS API | 国内可达性最好 |
| `smtp` | SMTP | 21 个预设：QQ、163、Gmail、Outlook、企业微信、阿里云… |
| `sendmail` | 本机 MTA | 已经跑着 postfix/exim 的机器 |
| `webhook` | HTTP POST | 钉钉 / 企业微信 / Slack / 飞书群机器人 |

```sh
sudo vigil mail setup                    # 交互式，推荐
sudo vigil mail setup --provider smtp    # 直接指定
```

## 发件域名：最容易踩的坑

自建域名的关键在于 **SPF/DKIM 对齐**。用免费邮箱（QQ/163/Gmail/Outlook）的地址当
发件人时，它**不会**用你的域名做 DKIM 签名，于是 `From` 和信封发件人不一致，
绝大多数收件方会直接判为垃圾邮件 —— 现象是「日志说投递成功，收件箱里没有」。

两条正确做法：

1. 用 API 渠道（Resend 等），按提示在 DNS 加 SPF + DKIM 记录。
   ```sh
   sudo vigil mail domain          # 打印需要添加的 DNS 记录
   sudo vigil mail domain --verify
   ```
2. 或者让 `From` 就是那个免费邮箱本身，不要伪造自有域名。

> API 密钥如果只有 *发送* 权限，就读不了账户/域名接口。这不是配置错了，
> `vigil mail status` 会如实说明「密钥为发送专用权限，读不到域名状态」，
> 而不是报一个吓人的 401。

## 自检

```sh
sudo vigil mail status     # 渠道、收件人、额度、连通性、待处理问题
sudo vigil mail test       # 真的发一封，这是唯一可信的验证
sudo vigil mail quota
sudo vigil mail sender     # 主机显示名 / 发件人显示名 / 发件地址
```

`mail test` 返回成功只代表服务商收下了。最终确认请**看收件箱**，
并检查垃圾邮件目录 —— 免费邮箱对自建域名发件人尤其敏感。

## 收件人

```sh
sudo vigil mail recipient add ops@example.com
sudo vigil mail recipient add oncall@example.com --login-only
sudo vigil mail recipient list
```

两类收件人分开：`recipients`（告警）与 `login_recipients`（登录通知）。
后者留空则回落到前者。
