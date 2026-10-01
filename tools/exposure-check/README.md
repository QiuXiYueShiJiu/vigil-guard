# 敏感文件规则接线校验器（exposure-check）

一个**只读**的小工具，回答一个问题：

> 每个会读磁盘的 `^~ 前缀` 里，敏感文件拒绝规则还在不在？

它可以当命令行用，也可以当**网页后端**用 —— 后者是为了把它挂到自己的面板/仪表盘页面上，
点一下就知道有没有问题。

---

## 为什么需要单独做一个

`location ^~ /xxx/` 会让 nginx **跳过同级所有正则 location**。所以那套
「备份 / 点文件 / 源码不许下载」的规则，必须在每个这样的前缀里**再挂一次**。

这条 `include` 只能写在站点自己的配置里，而在面板接管的机器上，**那个文件属于面板**。
实测中它被本程序之外的进程改写，`include` 随之消失，该子树里的文件重新变成可被公网下载
（一个真实的 3KB `.gitignore` 又变回可下载）。

**最危险的地方在于**：规则文件本身一直在，所以任何「检查文件在不在」的监控都会一路报 OK。
本工具查的是「有没有真的接进去」。

---

## 环境要求

| 项目 | 要求 |
|---|---|
| Python | 3.8+（只用标准库） |
| vigil | 需要装好（本工具与它共用同一份校验实现，不复制逻辑） |
| 权限 | 能读 nginx 配置即可；**不需要 root**，也不会修改任何文件 |

> 为什么不把校验逻辑抄一份进来：两份实现一定会漂移，而「扫描说干净、服务器却在往外发」
> 正是这个项目反复踩过的坑。所以它调用 `vigil.guards.exposure`，找不到就明确报错并告诉你怎么装。

---

## 命令行用法

```bash
./exposure_check.py                    # 人类可读
./exposure_check.py --json             # 机器可读
./exposure_check.py --root /etc/nginx/conf.d    # 只查指定目录
```

退出码：`0` = 全部已挂规则，`1` = 有未覆盖前缀，`2` = 找不到 vigil。

输出示例：

```
敏感文件规则接线校验
──────────────────────────────────────────────────────────────
  ✔ zz-function.conf             规则文件 在
      /function/             已挂规则
──────────────────────────────────────────────────────────────
✔ 所有 `^~` 前缀都已挂上敏感文件拒绝规则
```

---

## 作为网页后端

```bash
./exposure_check.py --serve --port 8791                 # 仅本机可访问（默认）
./exposure_check.py --serve --bind 0.0.0.0 --port 8791 --token "$(openssl rand -hex 16)"
```

| 路径 | 说明 |
|---|---|
| `GET /` | 自带页面，点一下按钮就出结果（无需额外文件） |
| `GET /api/check` | 校验结果（JSON） |
| `GET /healthz` | 存活探测，恒返回 `200 ok` |

### 接口返回

```json
{
  "ok": false,
  "checked_sites": 4,
  "holes": [{"conf": "zz-function.conf", "prefix": "/function/"}],
  "sites": [{
    "conf": "zz-function.conf",
    "managed": true,
    "rules_file": true,
    "file_serving_prefixes": ["/function/"],
    "holes": ["/function/"],
    "ok": false
  }],
  "summary": "1 个 `^~` 前缀没有挂规则，其下文件可被公网下载",
  "fix": "vigil exposure install（或 vigil update 会自动补回）",
  "elapsed_ms": 3,
  "checked_at": "2026-10-01T12:00:00+0800"
}
```

`ok` 为 `false` 时 `holes` 列出具体是哪个配置文件的哪个前缀。

### 带 token 调用

```bash
curl -s -H "X-Vigil-Token: $TOKEN" http://127.0.0.1:8791/api/check | jq .ok
curl -s "http://127.0.0.1:8791/api/check?token=$TOKEN" | jq .summary
```

---

## 在已有的站点后面接一个子路径

如果你已经有 nginx 站点，想用 `https://你的域名/tools/exposure/` 访问，
把请求转给本服务即可（页面里的 `fetch('api/check')` 是相对路径，所以子路径直接能用）：

```nginx
location ^~ /tools/exposure/ {
    proxy_pass http://127.0.0.1:8791/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    # 这个页面会显示你的站点配置文件名，按需要加一层访问控制
    # auth_basic "restricted";
    # auth_basic_user_file /etc/nginx/.htpasswd;
}
```

> ⚠️ 注意：**不要**把 `/tools/exposure/` 放在你已有的 `^~` 前缀规则之下却忘了规则覆盖 ——
> 这正是本工具在查的问题。用一个独立的 `location` 前缀最省心。

---

## 常驻运行

```bash
sudo cp vigil-exposure-check.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vigil-exposure-check
systemctl status vigil-exposure-check
```

单元默认把服务绑在 `127.0.0.1:8791`，并以低权限运行。若要在局域网内直接访问，
改 `ExecStart` 里的 `--bind`/`--token`，并**务必**配上 TLS 反向代理。

---

## 安全须知

- 本工具**只读**：它不写任何配置，也不需要 root。
- 输出里包含**配置文件名与 `^~` 前缀**（不包含绝对路径）。这些信息对攻击者价值不高，
  但足以告诉你"站点结构"，所以**不要裸奔在公网**：默认只监听 `127.0.0.1`，
  对外开放时请用 `--token` + TLS 反向代理，或加 `auth_basic`。
- 需要跨域（页面与服务不同源）时用 `--allow-origin https://你的页面来源`，
  不要图省事写 `*`，除非那个接口确实无需保密。
- 发现 `ok: false` 时，**用 `vigil exposure install` 或 `vigil update` 修复**，
  不要手工编辑面板接管的配置文件 —— 它随时可能被面板再改写一次。

---

## 相关

- 修复与自检：[`vigil exposure`](../../docs/GATE.md) / `vigil exposure status`
- 完整巡检：`vigil health run`（含同名检查项 `exposure_prefix_rules`，发现即发告警邮件）
- 为什么这样设计：[../../CHANGELOG.md](../../CHANGELOG.md) 的 v1.0.1
