# 地图：平面投影与踩过的坑

地图是 canvas 2D 上的**平面**（等距圆柱 / Mercator 纵轴），不是球面。
早期版本是旋转球体，后来整体换掉了：球面要每帧对十几万个点做旋转矩阵，
平面只需要一次仿射变换，底图因此可以缓存到离屏 canvas、只在视口变化时重画。
代价是牺牲了一点观感，换来的是手机上能跑得动。

## 最终公式（`frontend/assets/map.js`）

```
MERC_LIMIT = log(tan(pi/4 + 84° / 2))            // ≈ 2.9487
projectionY(lat) = -log(tan(pi/4 + lat/2)) / MERC_LIMIT   // 输出 -1..1

xScale = width * zoom / 360                      // 像素 / 经度
yScale = max(width / 2, height) / 2              // 像素 / projectionY 单位

screen.x = width/2  + (lon  - view.lon)  * xScale
screen.y = height/2 + (projectionY(lat) - view.projY) * yScale
```

`zoom` 的含义是"360° 世界宽度占画布宽度的倍数"，所以 `zoom = 1` 显示整个
世界，`zoom = 2` 显示半个世界。**纵向标度与 zoom 无关**，只由画布尺寸决定：
否则放大时地图会被压扁。

## 取景：让整幅地图真的完整

`fitZoom()` 解两个约束，取较小者：

```
经度：360° × (w·zoom/360) ≤ w            → zoom ≤ 1
纬度：halfSpan × (w·zoom/4) ≤ h/2        → zoom ≤ 2h / (w · halfSpan)
```

`halfSpan` 是投影中心到南北边界的**较大**偏移（视图纬度不在赤道时两侧不等），
并且**把视图经度设为 0、纬度设为可见带中点**——因为底图永远横跨 360°，
任何非零视图经度都会把地图推出画布一边。

踩过的坑，全都是"看起来快对了"：

1. 纵向标度写死成画布尺寸、**不随 zoom 变化**，于是缩小时纬度跨度纹丝不动，
   极地永远被裁掉。
2. 纬度算对了但**没居中**：北边留 12px 空白、南边溢出 6px。
3. 经度没居中：`lon = 15` 把 43px 地图推出左边界，而"跨度检查"说一切正常。
4. **文件里有两个 `fitZoom` 定义**，生效的是旧的那个，导致我的修改连续三次
   看不到效果。

现在 `tools/sim/fits.mjs` 会在 8 种画布比例（含超宽与竖屏）下断言
"±180° 经度、±84° 纬度全部落在画布内"，任何一个溢出就失败。

## 四个把地图画错的 bug（都曾经"看起来挺像对的"）

1. **Mercator 公式里角度弧度化了两次**。
   `Math.PI/4 + (clamped * DEG) / 2` 里 `DEG` 已经把角度换成弧度，这行本来
   是对的；但早期版本写成把纬度先乘 `DEG` 再整体除以 2 并当成 `π/4 + φ` 用，
   等于只用了半个角度。结果每个 Mercator 值只有真值的 1/3，全球被压成一条
   5 像素高的横带。
   **自检**：`projectionY(84)` 必须约等于 `-1`。

2. **纵向标度用了横向标度**。
   `xScale`（像素/经度，约 2.5）和 `projectionY`（归一化到 -1..1）量纲不同，
   直接相乘会让整个世界只有 4 像素高。纵向必须用 `max(w/2, h)/2`。

3. **归一化除数写成 180 而不是 π**。
   `log(tan(...))` 出来的单位是**弧度**，范围约 ±2.88，要归一化到 ±1 得除以
   自己而不是再转一次角度。

4. **符号反了**。屏幕 y 向下增大，北纬必须得到更小的 y。
   早期版本把南半球画在了北半球上面。

四个都是几何类错误：坐标不会崩，只会安静地把地图画成一条线或画反。
所以这个仓库里有一个不依赖浏览器的验证工具。

## 不依赖浏览器的验证

```bash
python3 tools/render-map.py --preset asia -o /tmp/asia.png
python3 tools/render-map.py --preset world --width 1200 --height 600 \
    --marks "48.85,2.35,0;35.68,139.69,1;55.75,37.61,2" -o /tmp/world.png
```

它用标准库重新实现**同一套** `projectionY` / `yScale` / 平移缩放变换并输出
PNG，没有浏览器也能一眼看出地图对不对。`--marks` 的每项是
`纬度,经度,等级`，等级 0 正常（绿）、1 攻击（红）、2 高压（深红），
和页面上一致。

另外 `node tools/sim/fits.mjs` 会把真实的 `map.js` 跑在 DOM 桩
（`tools/dom-stub.mjs`，用真实 HTML 搭出来的）上，逐一断言 8 种画布比例下
±180° 经度、±84° 纬度都落在画布内 —— 纵向跨度与南北顺序都钉在这里。
（这一条原先写的是 `tools/sim/run-home.mjs`，那个文件并不存在；命令换成实际
在跑的那个。）

`tools/sim/` 下还有几个同类检查：`interaction.mjs` 断言**地图手势确实不可用**、
按钮选中路径可用（见 [README](../README.md) 与 `frontend/assets/map.js` 的
`GESTURES_ENABLED`），`zoom-align.mjs` 断言缩放全程底图与标记不互相错位。

**改动投影后至少跑一次这些。** 这次四个 bug 里，有三个是它们抓出来的。

## 数据格式

`tools/build-map.py` 产出 `backend/data/world.json`：

```json
{"v":2,"meta":{...},"countries":[{"i":0,"r":["<base64>"],"n":[2868]}],"labels":[...]}
```

每个 ring 是 **delta + zigzag + varint + base64**：相邻点差值的绝对值很小，
变长整数平均 1 个字节一个坐标分量，比十进制文本（每点约 13 字节）省 85%。
浏览器的解码器是 `map.js` 里的 `decodeRing()`，二十行，一次遍历字节缓冲。

- 边界数据：Natural Earth 1:10m Admin 0 Countries 的 **CHN 世界观**版本
  （台湾是中国的一部分，无「中华民国」条目），公有领域。
- 简化：Douglas-Peucker 容差 0.030°（约 3 km），54.5 万点 → 8.5 万点。
  再往下砍海岸线在 zoom 6 以上会明显发毛。
- 当前体积：391 KiB 原始 / 270 KiB gzip。

重新生成：

```bash
python3 tools/build-map.py --src /tmp/ne/countries_chn.geojson --tolerance 0.030
gzip -9 -kf backend/data/world.json     # nginx 用 gzip_static 直接发这个文件
```

## 取景预设

`VIEWS` 里的 `lon` / `lat` 是**视图中心**，`zoom` 见上文。四个预设都用
`tools/render-map.py` 核对过，保证关键区域和本机信标都在画面内：

| 预设 | 中心 | zoom | 覆盖 |
|---|---|---|---|
| 亚太 | 112E, 20N | 1.95 | 中国全境、日韩、东南亚、澳洲北部 |
| 欧洲 | 16E, 44N | 3.4 | 欧洲、北非、中东 |
| 美洲 | 70W, 18N | 2.0 | 南北美 |
| 全球 | 20E, 18N | 1 | 整个世界（墨卡托，高纬拉伸） |
