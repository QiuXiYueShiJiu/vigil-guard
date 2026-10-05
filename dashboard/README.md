# 内置管理后台（vigil console）

`vigil-guard` 自带的**完整管理后台**：一个实时态势主页 + 一个需要登录的
管理控制台。它随仓库一起发布，装在 `dashboard/` 下，是一个**独立的
Python 进程**（默认 `127.0.0.1:9310`），由本机已有的 Web 服务反代对外 ——
和 `vigil web` 那个「只监听回环、只显示状态」的最小状态页不是同一个东西，
两者的分工见仓库根目录的 [`../docs/WEB.md`](../docs/WEB.md)。

- **主页**（游客免登录）：置顶一张平面世界地图，实时显示各地对服务器的
  访问。每个来源都是一颗**流星**：亮头从来源飞向主机，拖一条渐变的尾巴，
  来源处的点随流星远离而淡出，抵达主机时扩散一圈波纹。正常访问绿色、
  攻击红色、高压攻击深红。下面是 CPU / 内存 / 硬盘 / 网络与实时事件流。
- **管理页**（需登录）：站点一键放行或关闭、各后台快捷入口、全盘文件管理
  （浏览 / 读写 / 上传 / 下载）、操作审计。

两页共用一套**暖白 · 灰 · 淡橘**配色：

| 用途 | 色值 |
|---|---|
| 页面底色 | `#f7f3ed` 暖白（顶部淡橘光晕） |
| 卡片 / 面板 | `#ffffff` 纯白 |
| 文字 / 次级 / 弱化 | `#2f2a25` / `#615751` / `#948a7f` |
| 分割线 / 边框 | `#ebe3d9` / `#dbd0c2` |
| 强调色（按钮、链接、选中） | `#d2762e` |
| 地图海洋（三段渐变） | `#f7ecdc` → `#fbf5ee` → `#fffdfa` |
| 地图陆地（渐变） | `#efe6d7` → `#e2d4c1` |
| 海岸浅滩柔光 / 海岸线 | `#f6e8d4` / `#96806a` |
| 主机信标 | `#c2682a`，标签只写地址 |
| 正常访问 | `#3a7a52` 森林绿 |
| 攻击 / 高压攻击 | `#d04030` / `#841e18` |

除强调色外只有两个饱和色（访问绿、攻击红），其余全是暖灰 —— 数据本身
才是页面上最显眼的东西。

---

## 1. 部署

**域名、webroot、显示名、地图坐标全部来自 `config.json`，源码里一个都
没有。** 这是硬要求：这个仓库会公开发布，写死一个真实域名就等于把某台
机器的身份一起发出去。

```bash
cd /path/to/vigil-guard          # 仓库根目录
cp dashboard/config.example.json dashboard/config.json
$EDITOR dashboard/config.json    # 至少填 public_host / server_lat / server_lon

# 幂等安装：代码、静态资源、systemd 单元、nginx vhost、证书钩子
sudo bash dashboard/deploy/install.sh
# 也可以不改文件、直接由参数写入 config.json：
sudo bash dashboard/deploy/install.sh --host status.example.com --site-name "状态页"
```

`public_host` 还是占位值 `status.example.com` 时，`install.sh` 会**直接报错
停下** —— 域名是这个控制台的 Host 校验、证书路径与 vhost 的共同来源，装错
等于发布一个连不上的站点。`server_lat` / `server_lon` 不填会打一条显眼的
告警（地图会把流星画到几内亚湾）。

安装后：

| 入口 | 地址 | 权限 |
|---|---|---|
| 实时态势主页 | `https://<public_host>/` | 游客免登录 |
| 管理控制台 | `https://<public_host>/admin.html` | 管理员登录 |

**登录账号与密码都不在源码里，也没有默认值。** 服务端只保存 PBKDF2 派生值
（`/var/lib/vigil-dashboard/dashboard-password.json`，0600）：

```bash
vigil-dash set-password          # 交互式输入
vigil-dash clear-password        # 回到「没有账号，谁都进不去」的状态
```

## 2. 结构

```
dashboard/
├── backend/                  Python 3.10，仅用标准库
│   ├── serve.py              入口：日志采集线程 + 资源采样线程 + HTTP 服务
│   ├── settings.py           全部路径与可调项（config.json 覆盖；无宿主机默认值）
│   ├── tailer.py             跟踪 /www/wwwlogs/*.log，容忍两种日志格式
│   ├── store.py              事件总线：GeoIP、威胁分级、滚动历史、SSE 扇出
│   ├── threat.py             读 vigil 的威胁账本（/var/lib/vigil/state/threat.json）
│   ├── geo.py                离线 GeoLite2 查询（复用面板自带的 mmdb）
│   ├── sysinfo.py            /proc 与 /sys 资源采集
│   ├── resources.py          资源采样线程与短期历史
│   ├── auth.py               会话与口令校验（只有派生值）
│   ├── fs.py                 文件管理（含 deny/read-only 策略）
│   ├── sites.py              nginx 站点开关
│   ├── audit.py              追加式审计日志
│   ├── app.py                HTTP 路由、SSE、鉴权
│   ├── data/world.json       地图数据（由 tools/build-map.py 生成）
│   └── vendor/maxminddb/     纯 Python MaxMind 读取器（Apache-2.0）
├── frontend/                 无构建步骤：原生 ES 模块
│   ├── index.html            主页
│   ├── admin.html            管理页（标题里的显示名由后台接口注入）
│   └── assets/               core.js / map.js / home.js / admin.js / selfcheck.js / *.css
├── deploy/
│   ├── install.sh            幂等安装/更新（先读 config.json，再渲染下面两份模板）
│   ├── vigil-dashboard.service   systemd 单元模板（__DASHBOARD_DIR__）
│   ├── nginx-vigil.conf          vhost 模板（__PUBLIC_HOST__ / __WEBROOT__）
│   └── certbot-hook.sh           证书同步到面板目录 + reload nginx
├── tools/
│   ├── build-map.py          从 Natural Earth 生成 world.json
│   ├── render-map.py         离线渲染一帧地图（无浏览器时验证投影）
│   ├── unit-tests.py         单元测试
│   ├── selftest.py           分类端到端测试（写日志 → 读接口）
│   ├── test-admin-api.py     管理接口端到端测试
│   ├── attack-report.py      本机攻击历史报告（默认写到 /var/lib，不进仓库）
│   ├── dom-stub.mjs          用真实 HTML 搭的 DOM 桩，sim/ 下的检查靠它
│   ├── sim/                  无浏览器的前端检查（CSS 覆盖、移动端、投影、性能）
│   └── vigil-dash.py         运维 CLI（安装为 /usr/local/bin/vigil-dash）
├── config.example.json       配置模板
└── docs/                     设计说明与坑记录
```

## 3. 数据流

```
nginx access logs ─┐
                   ├─► tailer.py ─► store.EventHub ─┬─► SSE /api/v1/stream ─► 浏览器地图
vigil threat.json ─┘   (700ms 轮询)   │             └─► /api/v1/state（首屏快照）
/proc /sys ────────► resources.py ────┴─► SSE resources（每 2 秒）
```

**访问分级**（`threat.py` 判断，不做二次猜测）：

| 等级 | 颜色 | 判据 |
|---|---|---|
| 0 正常 | 绿 | 其余全部 |
| 1 攻击 | 红 | vigil 当前已封禁该 IP，或诱饵命中 / 可疑行为累计 ≥3 次 |
| 2 高压攻击 | 黑（红边） | 封禁原因含漏洞利用 / webshell / 命令执行等，或短时速率 ≥12 次/秒 |

分级只依据 vigil 的账本与实测速率。**宁可漏报也不把普通访客画成攻击者**，
所以没有「看起来像扫描器」这类猜测。

## 4. 运维

```bash
vigil-dash status              # 运行状态、GeoIP、会话数、nginx 配置
vigil-dash sites               # 站点与开关状态
vigil-dash close <站点>        # 关闭站点（写 deny all; + nginx -t + reload）
vigil-dash open  <站点>        # 放行站点
vigil-dash set-password        # 设置独立控制台密码
vigil-dash kick                # 注销所有登录会话
vigil-dash logs -f             # 看服务日志

systemctl status vigil-dashboard
bash dashboard/deploy/install.sh      # 重新部署（幂等）
```

站点开关实现：控制台在 `/www/server/nginx/conf/vigil-dashboard-sites/<站点>.conf`
写一份片段，并在该站点的 server 块里注入一行 `include`。关闭 = 片段写
`deny all;`，放行 = 片段清空。**每次改动都先跑 `nginx -t`，不通过就回滚**
片段与 include，绝不会把 nginx 弄成起不来的状态。

## 5. 地图

- 数据：Natural Earth 1:10m Admin 0 Countries 的 **CHN 世界观**版本（台湾是
  中国的一部分，无「中华民国」条目，边界符合中国官方立场），公有领域。
- 投影：canvas 2D 上的正射投影球面，中心对准视图经纬度，
  见 [docs/map-projection.md](docs/map-projection.md)。
- 预生成：`python3 tools/build-map.py`（需要 `.geojson`，见脚本注释）；
  产物 `backend/data/world.json` 约 1.33 MiB，gzip 后约 565 KiB。
- 离线校验：`python3 tools/render-map.py --preset asia -o /tmp/x.png`
  用纯标准库把同一套投影数学渲染成 PNG，无需浏览器。
- **手势已停用**：拖拽 / 捏合 / 滚轮缩放**全部关掉**，操作收敛到
  `#zoom-in` / `#zoom-out` 两个按钮（开关在 `frontend/assets/map.js` 的
  `GESTURES_ENABLED`）。这是交互设计上的取舍，不是 bug 修复 —— 手势在
  地图上的表现不过关，先收敛到按钮。配套地 `home.css` 里地图容器的
  `touch-action` 必须是 `pan-x pan-y`：留 `none` 的话，关掉手势会连页面
  本身的滚动一起拖不动。

## 6. 安全

- 后端只监听 `127.0.0.1:9310`，公网流量一律经 nginx。
- Host 头必须是 `public_host`（或其子域 / `extra_hosts` 里列出的），
  否则拒绝 —— 挡掉针对回环监听的 DNS-rebinding。
- 管理接口需要会话；每个写操作还要在 `X-Vigil-Token` 里回显会话令牌
  （Cookie 之外的第二道校验），上传接口同样要求，缺令牌直接 403。
- 会话 Cookie 由 nginx 补 `Secure` 标记（`proxy_cookie_flags`）：服务端到
  nginx 走明文回环，若在服务端就加 `Secure`，行为良好的客户端会拒绝发送。
- 文件管理：
  - 全盘可读写（按需求），但 `deny_paths` 保护 `/etc/shadow`、`/proc`、
    `/sys`、`/root/.ssh`、面板数据库等；`readonly_paths` 保护
    `/usr`、`/boot`、`/www/server/panel` 等；
  - 所有路径先 `realpath` 再校验，符号链接无法越界；
  - 删除需要服务端为**该路径**签发的确认令牌（300 秒有效），重放或误点无效；
  - 覆盖写自动在同目录留 `.vigilbak.<时间戳>`（最多 5 份）。
- 全部写操作记入 `/var/lib/vigil-dashboard/audit.jsonl`，管理页可直接查。
- 登录失败按 IP 限速（15 分钟内 8 次）。

## 7. 已知边界

- 服务以 root 运行（要改 vhost、做全盘文件管理、读面板的 mmdb）。
  这是需求决定的，缓解手段是上面的鉴权与策略，不是沙箱。
- 面板若重新保存某个站点，可能把它 server 块里控制台注入的那行
  `include` 删掉；下次切换该站点时会自动补回（管理页会显示「待注入」）。
- 实时地图只画公网来源。本机与保留地址（127.x、内网、RFC 5737 测试段）
  计入统计但不画流星，否则面板自己的健康检查会把地图刷满。
- `vigil --json` 在部分子命令上不可用，控制台因此直接读
  `/var/lib/vigil/state/threat.json`，而不是调用 CLI。
- 源码里**没有任何**真实域名、IP、邮箱或站点名。这条由 vigil-guard 的
  发布关卡 `src/vigil/core/sourceaudit.py` 强制检查；`tools/` 下的测试
  夹具一律用 RFC 5737 文档段地址，需要「真实公网地址」的用例在
  `store.geo.geo.lookup` 上打桩。
