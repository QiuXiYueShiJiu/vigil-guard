# 登录界面防护

在管理界面之前加一层人机验证。两种形态：

| 类型 | 用途 | 凭据 |
|---|---|---|
| `bt_panel` | 宝塔面板 / aaPanel 人机验证 | 不存账号密码，真正的登录仍由面板完成 |
| `login` | 独立登录页（人机验证 + 账号密码） | bcrypt 哈希，可反代为只监听本机的服务 |

```sh
sudo vigil gate list
sudo vigil gate detect                 # 读出已安装网关的全部参数
sudo vigil gate install login
sudo vigil gate reconfigure login --port 4400 --no-https
sudo vigil gate status
sudo vigil gate test login             # 端到端自检
```

## 多个实例

`login` 类型可以装任意多个**互相独立**的实例。`--name` 指定实例名，名字决定它
的状态目录（`/www/server/<名字>-gate`）、网页目录（`/www/wwwroot/<名字>-gate`）、
会话 Cookie、nginx 接线文件和配置键（`gate.<名字>`）。省略 `--name` 时落到默认
实例 `login`，也就是历史安装的 `/www/server/dsh-gate` 与 `gate.dsh_gate`——
老安装因此原样继续工作，不需要迁移。

```sh
# 给某个只监听本机的服务加一层仅人机验证的网关
sudo vigil gate install login --name astrbot \
    --domain gate.example.com --upstream http://127.0.0.1:6185 \
    --port 4400 --https --no-password

sudo vigil gate list                                   # 所有实例一眼看清
sudo vigil gate status      --name astrbot
sudo vigil gate detect      --name astrbot
sudo vigil gate reconfigure login --name astrbot --password '新密码'
sudo vigil gate repair      login --name astrbot
sudo vigil gate holds       --name astrbot
sudo vigil gate uninstall   login --name astrbot
```

每个实例各占一个监听端口和一组限流区。`--port` 若已被别的实例占用，命令会
直接报错，而**不会**去改那个实例。`bt_panel` 天然只有一个面板，固定为单实例，
不接受 `--name`。

## 接入已有配置（不改动任何文件）

已经有一套网关配置在跑，不想重建会话、不想重置密码：

```sh
sudo vigil gate adopt login      # 只读，只把参数读进 vigils 的配置
sudo vigil gate repair login     # 只重新接线 nginx，不重建网关文件
```

`adopt` 是只读的。`repair` 用于面板点过「修复 nginx」之后接线丢失的情况。

## 刷新重验证：`strict_nav` 的三种取值

这是最容易配错的一项，因为它取决于被保护的是哪类应用。

| 值 | 行为 | 适用 |
|---|---|---|
| `0` | 会话有效期内导航一律放行 | 只想挡一层，不想打扰 |
| `1` | **每次导航**都要一次性票据，F5 必重验 | 单页应用（SPA）。站内跳转走 XHR，不受影响 |
| `2` | **只有重新加载**才重验；跳到别的页面放行 | 传统多页应用，比如宝塔面板 |

原因：多页应用里每一次点击都是一次导航。对它用 `1`，面板会变成每点一下就
弹一次验证，实际上不可用。`2` 通过比较「本次导航的目标是否就是当前所在的页面」
来区分 F5 和点击 —— 请求本身没有这个标志位，`Sec-Fetch-Mode` 对两者都是 `navigate`。

```sh
sudo vigil gate reconfigure login    --strict-nav          # SPA
sudo vigil gate reconfigure bt_panel --reload-nav --nav-cookie btnav
```

开了严格模式就必须有 `--nav-cookie`，否则一次性票据无处存放，等于没开。

## 画面

验证码是**拖动拼图**，两种画面，每次出题随机：

```sh
sudo vigil gate scene show
sudo vigil gate scene set auto|art|image
sudo vigil gate scene providers        # 可以从哪些公开图库取图
sudo vigil gate scene fetch wallhaven -n 24 --preset character
sudo vigil gate scene review           # 生成带编号的对照表
sudo vigil gate scene block <id>       # 拉黑不合适的
```

- `art` —— 程序生成的 Q 版二次元风景图，五个场景（晴空 / 樱风 / 黄昏 / 星夜 / 青岚）。
  始终可用，永远是对的尺寸。
- `image` —— 取自你自己指定的目录。
- `auto` —— 约 1:1，且**连续同类不超过两张**。图库按主题均匀抽取，不按各主题的张数加权。

> **导出的包不附带任何图片。** 这不只是体积问题：图片属于安装它的人，
> 而且一个把装饰品打包进去的安全工具，会随着时间推移变得难以维护。
>
> **公开图库的授权差别很大。** `openverse` 是 CC0/公有领域，可以再分发；
> `wallhaven` / `konachan` 是第三方同人作品，**仅限自用，不要再分发**。
> 取图时会记录出处、作者与授权到 `credits.json`。
>
> **自动筛选识别不出**真人照片、文字水印、极端主义符号和擦边内容。
> 取完图请务必跑一遍 `vigil gate scene review` 人工过目 —— 这一步不能省。

## 它动了哪些文件

| 路径 | 内容 |
|---|---|
| `<state-dir>/` | `gate.lua`、`policy.conf`、`config.php`、`lib/gate-lib.php`、`sessions/`、`logs/auth.log` |
| `<webroot>/` | `verify.php`、`captcha.php`、`logout.php` |
| nginx | 一个 server 作用域的 include 片段，外加限流 zone 定义 |

所有写入都是原子的（临时文件 + `fsync` + `os.replace`），所以并发请求
要么看到旧文件要么看到新文件，不会读到写了一半的配置。

## Web 层防护（`vigil shield`）

`gate` 保护的是**管理入口**。`vigil shield` 保护的是**其余所有东西**：
按 User-Agent 拒掉那些整天在找漏洞的工具，并给单个地址的请求速率与并发封顶。

```sh
sudo vigil shield status
sudo vigil shield install      # 写入 + nginx -t 验证 + 重载
sudo vigil shield uninstall
```

它作用于 nginx 的 `http{}`，所以**影响这台机器上的每一个站点** —— 这也是它
和 `gate` 分开的原因。每次改动都会先用 `nginx -t` 验证，失败自动全量回滚；
写新配置、验证、再退役旧文件，中间没有「两者都不生效」的窗口。

> **变量名为什么沿用 `dsh_*`。** 旧版加固文件定义的同名 map 与限流区被线上
> 站点配置直接引用（`if ($dsh_bad_agent) { return 403; }` 等）。删掉它，
> nginx 会因为 `unknown "dsh_bad_agent" variable` **直接拒绝加载** —— 那不是
> 少了一层防护，而是整台机器的网站全挂。所以定义搬进本系统，名字保留。
