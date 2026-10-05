# 运维手册

## 静态资源与缓存

样式与脚本按**内容哈希**命名（`base.473aabce73.css`），HTML 在部署时被改写
指向哈希名，因此可以安全地设 `max-age=31536000, immutable`：文件一变，
URL 就变，浏览器不可能拿到旧版本。

> 这里踩过一个坑：第一版哈希重写循环拿**改名后**的文件名去匹配 HTML，
> 只替换成功了一个 `favicon.svg`，所有 CSS/JS 仍指向旧名（旧名文件已删），
> 表现就是"改了页面完全没生效"。现在 `install.sh` 用
> 原始名 -> 哈希名 的映射来改写，并在最后 `verify_html` 逐个检查 HTML 里
> 引用的资源是否真的存在，**缺一个就直接报错退出**，不会再静默发布坏页面。

`world.json` 是固定路径（页面按名字取），所以给它 `max-age=300`；
它自己 `meta.built` 里也带构建时间。

## 部署 / 更新

```bash
# 在 vigil-guard 仓库根目录执行（本目录即 dashboard/）
bash dashboard/deploy/install.sh                         # 全量（代码+静态+systemd+nginx）
bash dashboard/deploy/install.sh --no-nginx              # 只更新代码与静态资源
bash dashboard/deploy/install.sh --host status.example.com --site-name "状态页"
```

**域名、webroot、显示名都来自 `dashboard/config.json`**（可用上面的参数写入，
`config.example.json` 是模板）。脚本里没有任何一个真实域名：`public_host`
还是占位值 `status.example.com` 时它会直接报错停下，不会把一个连不上的站点
发出去。

脚本是幂等的：重复跑不会重复加配置。它会

1. 读 `config.json`，并把 `deploy/nginx-vigil.conf`、`deploy/vigil-dashboard.service`
   两份模板按这台机器的域名/目录渲染出来；
2. 清掉 `__pycache__`；
3. 把 `frontend/` 发布到配置里的 webroot（默认 `/www/wwwroot/<public_host>`），
   并把 `backend/data/world.json` 一起放到 `assets/`（同时生成 `.gz`，
   nginx 用 `gzip_static` 直接发预压缩文件）；
4. 建好 `/var/lib/vigil-dashboard`、站点开关目录、缺省片段；
5. 安装并启动 systemd 单元，随后接口自检；
6. 写入 vhost、`nginx -t` 通过才 reload。

**失败即停**：`nginx -t` 不通过时脚本不会 reload，并打印校验输出。

`server_lat` / `server_lon` 未配置时会打一条显眼的告警：地图会把流星画到
几内亚湾（只影响画线起点，不影响采集与封禁）。**没有任何默认坐标** ——
一台机器的经纬度就是这类仓库不该带的信息。

## 证书

首次由 certbot 签发（webroot 模式，HTTP-01）：

```bash
HOST="$(python3 -c 'import sys; sys.path.insert(0, "dashboard"); \
    from backend import settings; print(settings.PUBLIC_HOST)')"
certbot certonly --webroot -w /www/wwwroot \
  -d "$HOST" \
  --email admin@example.com --agree-tos --no-eff-email --non-interactive
/usr/local/bin/vigil-cert-sync          # 拷进宝塔证书目录并 reload nginx
```

`vigil-cert-sync` 由 `install.sh` 安装（`deploy/certbot-hook.sh` 渲染而成，
域名烘进脚本里 —— certbot 从 cron 调它时没有安装脚本的环境变量）。已经存在
同名文件时不会覆盖。


为什么是拷贝而不是软链：`/etc/letsencrypt/{live,archive}` 是 0700 root，
nginx 以 `www` 身份跑，跟不进软链。

续期：`/etc/cron.d/certbot-vigil` 每 12 小时跑一次 `certbot -q renew`，
带 `--deploy-hook /usr/local/bin/vigil-cert-sync`，续期成功后自动同步并
reload。手动验证：

```bash
certbot renew --cert-name status.example.com --dry-run   # 换成自己的域名
```

> 本机没有 pip（`python3 -m pip` 不存在，也没有 ensurepip），certbot 是
> apt 装的 `python3-certbot`；该包只装库不装 `/usr/bin/certbot`，所以
> `/usr/local/bin/certbot` 是一个两行的 wrapper，直接调
> `certbot._internal.main:main`。

## 站点开关

```bash
vigil-dash sites                       # 看标识与状态
vigil-dash close status.example.com     # 关掉某个站点，写 deny all; 后 reload
vigil-dash open  status.example.com     # 放行
```

管理页上的开关走同一套代码。它做四件事：注入 `include`（若缺）、写片段、
`nginx -t`、reload。任何一步失败都会把片段与 `include` 还原。

vhost 备份在同目录 `*.vigildash.<时间戳>`，最多留 5 份。

## AstrBot：`/` 指令传不到插件

**症状**：agent 说要把 `/指令` 转给插件，插件却收不到。

**原因**：`provider_settings.wake_prefix` 被设成了 `'/'`，和顶层 `wake_prefix`
（命令前缀）撞在一起。`astr_main_agent.py` 里：

```python
req.prompt = event.message_str[len(config.provider_wake_prefix):]
```

于是每条消息在进入 agent 之前都被砍掉开头的 `/`，`/pic 猫` 变成 `pic 猫`，
插件自然不认。注意 `agent_request.py` 里那段"自动去重"**救不了这种情况**：
它只在 provider 前缀以 bot 前缀开头时剥掉 bot 前缀，而这里是两者完全相同，
结果只是把 provider 前缀剥成了空串——`astr_main_agent` 读的是另一份配置，
剥前缀的逻辑照旧执行。

**修法**：`provider_settings.wake_prefix` 设为 `''`。命令前缀 `/` 归插件系统，
agent 侧不需要额外唤醒词，这样消息原样进入 agent，插件拿到完整 `/指令`。

回归用例：`tools/test-astrbot-prefix.py`（断言 `/pic`、`/help`、`/reset` 原样传递，
且配置不再与命令前缀冲突）。

## AstrBot 会把自己关掉（已两次）

这个 agent 有 shell 权限，自己把自己停掉过两次：

| 时间 | 它执行的命令 | 后果 |
|---|---|---|
| 2026-10-04 14:53 | `pkill -f "astrbot"` | `-f` 匹配到自己的命令行，主进程被 TERM |
| 2026-10-04 23:48 | `systemctl stop astrbot` | 停掉后没有重启，服务躺了 |

**`Restart=always` 两种情况都救不了**：被 TERM 与主动 stop 在 systemd 眼里都是
「正常结束」。第一次已经改成 `Restart=always` 了，第二次依然失效。

现在在**工具入口**拦掉（`core/tools/computer_tools/shell.py`）：

```python
_SELF_STOP_PATTERNS = ("systemctl stop astrbot", "pkill -f astrbot", …)
```

命中就返回一段说明，让 agent 知道"这条命令会带走你自己"，改为重载插件或报告问题。
`systemctl status astrbot`、`journalctl -u astrbot` 这类只读命令照常放行，
`systemctl restart nginx` 等别的服务也不受影响。

回归用例：`tools/test-astrbot-guard.py`（9 个拦截 + 6 个放行）。
⚠️ 升级 AstrBot 会覆盖 `shell.py`，用例会因此失败——那正是提醒你重新打补丁。

另外 `provider_settings.wake_prefix` 会被配置面板写成数组 `['/']`，而代码按字符串用，
导致启动即崩。已在 `agent_request.py` 里兼容两种类型，配置怎么改都不会再崩。

## 服务自愈策略

**所有常驻服务都应为 `Restart=always`。** `Restart=on-failure` 看起来更"保守"，
但它**不会**在进程收到 SIGTERM 后重启——systemd 把被 TERM 杀掉视为「正常停止」。

真实案例（2026-10-04）：AstrBot 的 agent 调用自己的 shell 工具执行

```
pkill -f "astrbot" 2>/dev/null; sleep 1; echo done
```

它想重启插件，结果 `-f` 匹配到了自己的完整命令行，把自己杀了。因为单元里写的是
`Restart=on-failure`，服务躺了 12 分钟，后台页面一直 502。

修复：`/etc/systemd/system/astrbot.service` 改为 `Restart=always`。
验证方式就是 `kill -TERM` 主进程，然后确认 PID 变了。

同类风险：任何"用 `pkill -f <自己的名字>`"的自动化都可能自杀，
包括本控制台自己的文件管理器（它能改 systemd 单元）。控制台不会主动这么做，
但如果你在文件管理器里编辑单元文件，记得 `systemctl daemon-reload`。

## 排障

| 症状 | 看什么 |
|---|---|
| 地图没有线条 | `journalctl -u vigil-dashboard -n 50`；采集器每分钟打印消费事件数，`poll failed` 会带异常 |
| 地图画成一条横带 | 投影坏了。跑 `python3 tools/render-map.py --preset world -o /tmp/w.png` 看一眼；`projectionY(84)` 必须 ≈ -1 |
| 后台页面 502 | 先看被代理的那个服务是否在跑：`systemctl status astrbot`。502 说明 nginx 活着、上游死了；401 是登录网关，正常 |
| 正常客户端被标红 | 速率判据。确认它的路径是否属于"定时轮询"：是的话加进 `threat._QUIET_PATHS`（backend/threat.py）。绝对阈值在 `config.json` 的 `attack_rate` / `pressure_rate` / `rate_outlier_factor` |
| 地图上全是 127.0.0.1 | 正常，本机请求不画；真机来源看 `/api/v1/state` 的 `traffic.local` 与外网计数 |
| 管理页保存不了 | 会话过期（15 分钟内无操作不会过期，但 7 天会）；重新登录。403 且提示「会话校验失败」说明 `X-Vigil-Token` 没带上 |
| nginx 起不来 | `nginx -t`；如果指向 `vigil-dashboard-sites/*.conf`，删掉那个片段文件即可恢复 |
| 站点开关点了没反应 | 该站点 server 块里的 `include` 被宝塔改写删掉了；再点一次会自动补 |

## 性能

- 首屏 gzip 约 299 KiB（其中地图 270 KiB），比球面版本少一半；页面先渲染数据、
  地图异步加载，互不阻塞；
- nginx 必须带 `gzip_proxied any`：`gzip on` 默认**不压缩代理响应**，
  这就是早期 `/api/v1/state` 87 KiB 明文传输的原因；
- 采集线程 700 ms 轮询，空闲时只做 `stat`，几毫秒；
- 单次最多处理 400 条日志行（`max_events_per_poll`），防止日志暴涨时打满 CPU；
- GeoIP 结果按 IP 缓存（默认 2 万条 LRU），命中不查库；
- 地图每帧最多 240 条流星，掉帧时自动降频；
- SSE 每浏览器一个长连接，订阅队列有上限，慢客户端丢事件而不是拖垮服务。
