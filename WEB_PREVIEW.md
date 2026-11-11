# HGhub Web 预览 —— 实时调前端用

给 HGhub 加了一层纯浏览器构建，右侧栏 / 浏览器里就能跑起来，改完代码热更新、立刻看到效果。
方便你看着我调 UI。

## 怎么开

```powershell
cd D:\工作区\HGhub_patched
pnpm dev
```

然后打开 **http://127.0.0.1:1420/web.html**（或 `pnpm web:dev` 自动开浏览器）。

在 DSH 右侧栏里看：
1. 点右上角侧栏展开箭头，点「浏览器」卡片
2. 地址栏输入 `http://127.0.0.1:1420/web.html`
3. 拖宽侧栏到 ~600px 以上（太窄会切到窄布局）

## 已验证

在 Edge 内核里实测（640px 与 900px 两种宽度）：

- 首页榜单：10 部剧，标题/热力值正常
- 封面：10 张全部解码成功（`/hg/img` 服务端 AES-128-CBC 解密）
- 视频：`<video>` 元素就绪，HLS 播放列表 + `crypt.key` + 分片全部 200，画面在走
- 详情：21 集列表、评分、简介、作者
- 搜索 / 排行榜 / 分类

## 架构

桌面端靠 Rust 做协议和媒体，浏览器里没有这些，所以补了三层：

```
src/web/edge.ts      dx150-edge-v1 协议的 WebCrypto 实现
                     ECDH P-256 → HKDF-SHA256 → AES-256-GCM 帧
                     与 src-tauri/src/edge_crypto.rs 逐字节等价

src/web/bridge.ts    invoke 桥：把 30+ 个 Tauri 命令映射成 fetch 实现
                     还补了 __TAURI_INTERNALS__.metadata，否则 @tauri-apps/api/window
                     在模块加载时就读 currentWindow.label，直接白屏

vite.hgweb.ts        dev server 中间件（仅开发期）
                     /api-proxy?u=<url>  同源反代，绕开站点不回 CORS 头
                     /hg/img?u=          封面 AES 解密
                     /hg/hls?u=          m3u8 改写分片/密钥指向 /hg/seg
                     /hg/seg?u=          分片与密钥透传
```

`src/main.web.tsx` 先 `installWebBridge()` 再挂 App，业务代码一行没改。

## 改了什么（相对桌面构建）

| 文件 | 改动 |
| --- | --- |
| `src/api.ts` | `LOCAL` 在 Web 构建下改成 `/hg` |
| `src/App.tsx` | 视口 < 560px 时自动收起左侧 rail（否则内容被挤成一条） |
| `vite.config.ts` | 挂 `hgMediaProxy()`；绑 `127.0.0.1`（默认只听 ::1，Windows 上 `localhost` 会连不上）；忽略编辑器临时目录（否则 chokidar EBUSY 直接崩） |
| `package.json` | 加 `web:dev` 脚本 |

其余全是新增文件。

## 线路说明（重要）

站点域名一直在换，今天（2026-11-11 凌晨）的实测：

| 域名 | 状态 |
| --- | --- |
| `huangguoai.com` | 不通 |
| `huangguoai.ai` | `/api/*` 返回 nginx 404 |
| `huangguoai.io` | DNS 解析到 0.0.0.0，挂了 |
| `thu.gitiecgad.cc`（跳板） | ECONNRESET，挂了 |
| `00b4b.adihsppe.cc` | **可用**（当日镜像） |

所以 `bridge.ts` 里做了自动发现：候选并发探测 hello，谁先通过用谁，结果缓存 10 分钟。
候选来源 = 上次成功的 + 跳板 301 + 发布页 `publish.js` + 固定线路兜底。

**跳板全挂时手动切线路**：浏览器控制台执行
```js
localStorage.setItem("hghub_web_base", "https://00b4b.adihsppe.cc"); location.reload();
```

## 已知边界

- 只 DEV 模式：`vite build` 出来的是给 Tauri 的，`outDir` 也是 `dist`。要独立部署 web 版得另配一个 build target（现有 `web.html` + `main.web.tsx` 可直接用，加个 `--mode web` 即可）。
- 代理只在 dev server 里：生产 web 版需要一台真后端来终止 CORS 和做媒体解密。
- 登录态存 localStorage，刷新保留；切线路会清登录（与桌面端一致）。
- 桌面 / 安卓构建不受影响：`isWebBuild` 判定基于 `window.__HGHUB_WEB__`，原生里不存在。
