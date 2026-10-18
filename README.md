# comfyui-jwt-auth

ComfyUI 访问守卫插件：**内网直连 + 其他来源 JWT 登录**。

- 免登录：`127.0.0.1` / `::1`（本机回环）、`192.168.0.0/16`（局域网 IPv4）
- **需登录：其他一切来源**（所有公网 IPv6/4G/5G/家宽 IPv6、10.x、172.16.x 等）→ 登录页（用户名+密码）→ JWT Cookie（记住我 7 天 / 默认 12 小时）
- 诊断：`GET /jwt-whoami`（免登录）显示访问者 IP / 是否豁免 / 命中规则，排查"为什么没弹登录"一步到位
- API / WebSocket 未认证返回 401；页面请求跳转登录页；带防爆破（5 次失败/5 分钟窗口）；被要求登录的请求会记服务端日志
- 已登录（cookie 有效）访问 `/jwt-login` 会 302 回画布（`next` 参数决定目标）；`/jwt-login?force=1` 强制显示登录页（换账号逃生口）；`/jwt-logout` 登出始终可用

## 安装

1. 把本目录放到 `ComfyUI/custom_nodes/comfyui-jwt-auth/`（或运行技能 `comfyui-jwt-auth` 的 `scripts/install.sh`）
2. 确保环境里有 `PyJWT`（`pip install PyJWT`；本机环境已自带）
3. 编辑本目录 `config.json`（可写明文 `password`，启动后自动转 pbkdf2 哈希）
4. 重启 ComfyUI。服务监听须包含 IPv4 与 IPv6（推荐 `--listen 0.0.0.0,::`；⚠️ 只写 `::` 在新版 Python 下是 v6-only，IPv4 会断）

## 配置项（config.json）

| 键 | 说明 | 本部署值 |
|---|---|---|
| `enabled` | 总开关 | true |
| `username` / `password` | 登录凭据（password 明文会在启动时自动转为 `password_hash`） | - |
| `trusted_networks` | 免登录网段（CIDR 列表） | 127.0.0.0/8, ::1/128, 192.168.0.0/16 |
| `trust_local_ipv6_prefix` | 动态信任本机公网 IPv6 的 /64（家宽前缀） | false |
| `remember_ttl_hours` | “记住我”有效期 | 168（7 天） |
| `short_ttl_hours` | 不勾选记住我时的有效期 | 12 |
| `max_failures` / `failure_window_minutes` | 防爆破限速 | 5 / 5 |

配置修改后**无需重启**（mtime 热重载）。改到把自己锁住也别怕：`127.0.0.1` 永久豁免。

## 安全说明

- 密码以 pbkdf2-sha256（20 万次迭代）哈希存储；JWT 使用 HS256 + 独立随机密钥
- 登录页为纯内联 HTML/CSS/JS，无外部依赖（公网环境不因 CDN 拖慢）
- HTTP 明文场景下 cookie 可能被网络嗅探；如需要，可再加 TLS（反向代理或自签）