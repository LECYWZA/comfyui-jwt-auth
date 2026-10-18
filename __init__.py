"""
comfyui-jwt-auth — ComfyUI 访问守卫插件（IP 白名单 + JWT 登录）

- 回环 / 局域网 / 同一家宽 IPv6 前缀：直接访问，无需登录
- 其他来源（公网 IPv6 等）：跳转登录页，用户名+密码签发的 JWT 凭据（默认 7 天）
- 安装：把本目录放进 ComfyUI 的 custom_nodes/ 并重启；配置见同目录 config.json
- 详细说明见 README.md（本插件同时由技能 comfyui-jwt-auth 维护/分发）
"""

import hashlib
import hmac
import html
import ipaddress
import json
import logging
import os
import secrets
import time
from urllib.parse import quote

import jwt  # PyJWT
from aiohttp import web
from server import PromptServer

log = logging.getLogger("comfyui-jwt-auth")

PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(PLUGIN_DIR, "config.json")
COOKIE_NAME = "comfy_jwt"

PBKDF2_ITERATIONS = 200_000

DEFAULT_TRUSTED_NETWORKS = [
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
]

PUBLIC_PATHS = {"/jwt-login", "/jwt-login/", "/jwt-logout", "/jwt-logout/", "/jwt-whoami", "/favicon.ico"}


# --------------------------------------------------------------------------- #
# 配置
# --------------------------------------------------------------------------- #

def _default_config():
    return {
        "enabled": True,
        "username": "admin",
        "password": "",          # 可写明文；启动时自动转成 password_hash 并移除
        "password_hash": "",
        "jwt_secret": "",
        "trusted_networks": list(DEFAULT_TRUSTED_NETWORKS),
        "trust_local_ipv6_prefix": True,   # 动态放行本机所在的公网 IPv6 /64（家里设备）
        "remember_ttl_hours": 168,         # 记住我 = 7 天
        "short_ttl_hours": 12,             # 不勾选记住我 = 12 小时
        "max_failures": 5,
        "failure_window_minutes": 5,
    }


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return f"pbkdf2${PBKDF2_ITERATIONS}${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iters, salt, hashval = str(stored).split("$")
        if scheme != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(dk.hex(), hashval)
    except Exception:
        return False


class _ConfigStore:
    """带 mtime 热重载的配置读取；明文密码自动转哈希。"""

    def __init__(self):
        self._mtime = None
        self._data = None

    def load(self):
        try:
            mtime = os.path.getmtime(CONFIG_PATH)
        except OSError:
            mtime = None

        if self._data is not None and mtime == self._mtime:
            return self._data

        if mtime is None:
            data = _default_config()
            try:
                with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                mtime = os.path.getmtime(CONFIG_PATH)
                log.info("[comfyui-jwt-auth] 已生成默认配置（注意：未设置密码时插件不启用）：%s", CONFIG_PATH)
            except OSError:
                pass
        else:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                raw = json.load(f)
            if not isinstance(raw, dict):
                raise ValueError("config.json 必须是 JSON 对象")
            data = {**_default_config(), **raw}

        changed = False
        if not data.get("jwt_secret"):
            data["jwt_secret"] = secrets.token_hex(32)
            changed = True
        if data.get("password"):
            data["password_hash"] = hash_password(str(data.pop("password")))
            changed = True
        if changed and mtime is not None:
            try:
                tmp = CONFIG_PATH + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                os.replace(tmp, CONFIG_PATH)
                mtime = os.path.getmtime(CONFIG_PATH)
                log.info("[comfyui-jwt-auth] 配置已更新（明文密码已转哈希 / 已生成密钥）")
            except OSError as exc:
                log.warning("[comfyui-jwt-auth] 配置写回失败：%s", exc)

        self._data = data
        self._mtime = mtime
        return data


config_store = _ConfigStore()


# --------------------------------------------------------------------------- #
# IP 信任判定
# --------------------------------------------------------------------------- #

_local_prefix_cache = {"ts": 0.0, "nets": []}
_net_cache = {"key": None, "nets": []}


def _local_global_v6_prefixes():
    """本机公网 IPv6 的 /64 前缀（家宽前缀；家里设备走这个前缀 → 视为局域网）。"""
    now = time.time()
    if now - _local_prefix_cache["ts"] < 300:
        return _local_prefix_cache["nets"]
    nets = []
    try:
        with open("/proc/net/if_inet6", encoding="ascii") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 6:
                    continue
                addr_hex, _idx, _plen, scope_hex, _flags, _name = parts[:6]
                if scope_hex != "00":   # 只取 global
                    continue
                addr = ipaddress.IPv6Address(int(addr_hex, 16))
                if addr.is_loopback or addr.is_link_local:
                    continue
                nets.append(ipaddress.ip_network(f"{addr}/64", strict=False))
    except Exception:
        pass
    _local_prefix_cache.update(ts=now, nets=nets)
    return nets


def _get_networks(cfg):
    key = (tuple(cfg.get("trusted_networks") or []), bool(cfg.get("trust_local_ipv6_prefix", True)))
    if _net_cache["key"] == key:
        return _net_cache["nets"]
    nets = []
    for cidr in cfg.get("trusted_networks") or []:
        try:
            nets.append(ipaddress.ip_network(str(cidr), strict=False))
        except ValueError:
            log.warning("[comfyui-jwt-auth] 忽略非法网段：%r", cidr)
    if cfg.get("trust_local_ipv6_prefix", True):
        nets.extend(_local_global_v6_prefixes())
    _net_cache.update(key=key, nets=nets)
    return nets


def is_trusted_ip(ip_str: str, cfg) -> bool:
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    for net in _get_networks(cfg):
        try:
            if ip.version == net.version and ip in net:
                return True
        except TypeError:
            continue
    return False


# --------------------------------------------------------------------------- #
# JWT
# --------------------------------------------------------------------------- #

def issue_token(cfg, remember: bool):
    ttl_hours = int(cfg["remember_ttl_hours"] if remember else cfg["short_ttl_hours"])
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": cfg.get("username", ""),
            "iss": "comfyui-jwt-auth",
            "iat": now,
            "exp": now + ttl_hours * 3600,
        },
        cfg["jwt_secret"],
        algorithm="HS256",
    )
    return token, ttl_hours * 3600


def verify_token(token: str, cfg) -> bool:
    try:
        jwt.decode(
            token,
            cfg["jwt_secret"],
            algorithms=["HS256"],
            options={"require": ["exp", "sub"]},
        )
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# 防爆破（内存计数）
# --------------------------------------------------------------------------- #

_failures = {}


def _recent_failures(ip, window_seconds, cfg):
    now = time.time()
    lst = [t for t in _failures.get(ip, []) if now - t < window_seconds]
    if lst:
        _failures[ip] = lst
    else:
        _failures.pop(ip, None)
    return lst


def is_locked(ip, cfg) -> bool:
    window = int(cfg.get("failure_window_minutes", 5)) * 60
    return len(_recent_failures(ip, window, cfg)) >= int(cfg.get("max_failures", 5))


def record_failure(ip, cfg):
    window = int(cfg.get("failure_window_minutes", 5)) * 60
    lst = _recent_failures(ip, window, cfg)
    lst.append(time.time())
    _failures[ip] = lst


def clear_failures(ip):
    _failures.pop(ip, None)


# --------------------------------------------------------------------------- #
# 请求工具
# --------------------------------------------------------------------------- #

def _is_navigation(request) -> bool:
    mode = request.headers.get("Sec-Fetch-Mode", "")
    if mode == "navigate":
        return True
    if mode in ("cors", "no-cors", "same-origin"):
        return False
    accept = request.headers.get("Accept", "")
    return ("text/html" in accept) and ("application/json" not in accept)


def _safe_next(raw) -> str:
    if not raw:
        return "/"
    s = str(raw)
    if not s.startswith("/") or s.startswith("//"):
        return "/"
    return s


# --------------------------------------------------------------------------- #
# 登录页（内联 HTML/CSS/JS，无外部资源）
# --------------------------------------------------------------------------- #

_LOGIN_PAGE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ComfyUI · 访问验证</title>
<style>
  :root{
    --bg:#0a0c14; --card:rgba(19,22,36,.84); --line:rgba(148,163,255,.16);
    --txt:#e8eaf4; --muted:#8d94ad; --err:#ff6b81;
    --accent1:#7c5cff; --accent2:#e0559c;
  }
  *{box-sizing:border-box; margin:0; padding:0}
  html,body{height:100%}
  body{
    font-family:system-ui,-apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;
    background:var(--bg); color:var(--txt);
    display:flex; align-items:center; justify-content:center;
    padding:24px; overflow:hidden;
  }
  body::before{
    content:""; position:fixed; inset:0; z-index:0; pointer-events:none;
    background:
      radial-gradient(520px 380px at 18% 12%, rgba(124,92,255,.20), transparent 62%),
      radial-gradient(560px 420px at 84% 26%, rgba(224,85,156,.16), transparent 60%),
      radial-gradient(480px 420px at 55% 92%, rgba(45,212,191,.10), transparent 62%),
      linear-gradient(180deg,#0a0c14 0%,#0d101d 55%,#0a0c14 100%);
  }
  body::after{
    content:""; position:fixed; inset:0; z-index:0; pointer-events:none; opacity:.5;
    background-image:
      linear-gradient(rgba(148,163,255,.05) 1px, transparent 1px),
      linear-gradient(90deg, rgba(148,163,255,.05) 1px, transparent 1px);
    background-size:44px 44px;
    mask-image:radial-gradient(620px 520px at 50% 42%, #000 30%, transparent 78%);
    -webkit-mask-image:radial-gradient(620px 520px at 50% 42%, #000 30%, transparent 78%);
  }
  .card{
    position:relative; z-index:1; width:min(400px,100%);
    background:var(--card); border:1px solid var(--line); border-radius:18px;
    padding:38px 34px 30px;
    box-shadow:0 28px 80px rgba(0,0,0,.58), inset 0 1px 0 rgba(255,255,255,.05);
    backdrop-filter:blur(14px); -webkit-backdrop-filter:blur(14px);
    animation:rise .45s cubic-bezier(.2,.7,.3,1) both;
  }
  .card::before{
    content:""; position:absolute; top:0; left:14%; right:14%; height:2px; border-radius:2px;
    background:linear-gradient(90deg, transparent, var(--accent1), var(--accent2), transparent);
    opacity:.9;
  }
  @keyframes rise{from{opacity:0; transform:translateY(14px)} to{opacity:1; transform:none}}
  .brand{display:flex; align-items:center; gap:12px; margin-bottom:22px}
  .glyph{position:relative; width:40px; height:40px; border-radius:11px;
    background:linear-gradient(135deg, rgba(124,92,255,.22), rgba(224,85,156,.18));
    border:1px solid var(--line); display:grid; place-items:center}
  .glyph i{position:absolute; width:9px; height:9px; border-radius:2.5px}
  .glyph i:nth-child(1){background:#7c5cff; top:9px; left:9px}
  .glyph i:nth-child(2){background:#a855f7; top:9px; right:9px}
  .glyph i:nth-child(3){background:#e0559c; bottom:9px; left:9px}
  .glyph i:nth-child(4){background:#2dd4bf; bottom:9px; right:9px}
  .brand b{font-size:19px; font-weight:650; letter-spacing:.2px}
  .brand small{display:block; font-size:12px; color:var(--muted); margin-top:2px; letter-spacing:.4px}
  h1{font-size:17px; font-weight:600; margin-bottom:6px}
  .sub{font-size:12.5px; color:var(--muted); margin-bottom:22px; line-height:1.5}
  .error{
    display:flex; align-items:center; gap:9px;
    background:rgba(255,107,129,.10); border:1px solid rgba(255,107,129,.32);
    color:#ffc2cb; font-size:13px; border-radius:10px; padding:10px 12px; margin-bottom:16px;
    animation:shake .32s ease;
  }
  @keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-5px)}75%{transform:translateX(5px)}}
  .error svg{flex:none}
  .field{display:block; margin-bottom:14px}
  .field span{display:block; font-size:12.5px; color:var(--muted); margin-bottom:7px}
  .field input{
    width:100%; height:46px; padding:0 14px; font-size:14.5px; color:var(--txt);
    background:rgba(8,10,18,.72); border:1px solid var(--line); border-radius:11px; outline:none;
    transition:border-color .16s ease, box-shadow .16s ease, background .16s ease;
  }
  .field input:hover{border-color:rgba(148,163,255,.30)}
  .field input:focus{border-color:rgba(124,92,255,.85); box-shadow:0 0 0 3.5px rgba(124,92,255,.18)}
  .pw{position:relative}
  .pw input{padding-right:46px}
  .eye{
    position:absolute; right:6px; top:50%; transform:translateY(-50%);
    width:36px; height:36px; display:grid; place-items:center; cursor:pointer;
    background:none; border:none; color:var(--muted); border-radius:9px;
  }
  .eye:hover{color:var(--txt); background:rgba(148,163,255,.08)}
  .remember{display:flex; align-items:center; gap:10px; margin:16px 0 20px; cursor:pointer; user-select:none}
  .remember input{display:none}
  .remember .track{
    width:38px; height:22px; border-radius:20px; background:rgba(148,163,255,.16);
    position:relative; transition:background .18s ease; flex:none;
  }
  .remember .track::after{
    content:""; position:absolute; top:3px; left:3px; width:16px; height:16px; border-radius:50%;
    background:#aab1c9; transition:transform .18s ease, background .18s ease;
  }
  .remember input:checked + .track{background:linear-gradient(135deg,var(--accent1),var(--accent2))}
  .remember input:checked + .track::after{transform:translateX(16px); background:#fff}
  .remember em{font-style:normal; font-size:13px; color:var(--muted)}
  .remember em b{color:var(--txt); font-weight:550}
  .submit{
    width:100%; height:46px; border:none; border-radius:11px; cursor:pointer;
    font-size:15px; font-weight:600; color:#fff; letter-spacing:2px;
    background:linear-gradient(135deg,var(--accent1),var(--accent2));
    box-shadow:0 10px 26px rgba(124,92,255,.30);
    transition:transform .15s ease, box-shadow .15s ease, filter .15s ease;
  }
  .submit:hover{transform:translateY(-1px); box-shadow:0 14px 32px rgba(124,92,255,.40); filter:brightness(1.06)}
  .submit:active{transform:translateY(0)}
  .submit:disabled{opacity:.75; cursor:default; transform:none}
  .spin{display:inline-block; width:15px; height:15px; margin-right:8px; vertical-align:-2px;
    border:2px solid rgba(255,255,255,.4); border-top-color:#fff; border-radius:50%;
    animation:rot .7s linear infinite}
  @keyframes rot{to{transform:rotate(360deg)}}
  .foot{margin-top:22px; text-align:center; font-size:11.5px; color:var(--muted); line-height:1.7}
  .foot b{color:#aeb5cc; font-weight:550}
  @media (max-width:480px){
    body{padding:16px}
    .card{padding:30px 22px 24px; border-radius:16px}
  }
</style>
</head>
<body>
  <main class="card">
    <div class="brand">
      <div class="glyph"><i></i><i></i><i></i><i></i></div>
      <div><b>ComfyUI</b><small>Access Guard · JWT</small></div>
    </div>
    <h1>访问验证</h1>
    <p class="sub">你正从外部网络访问此服务，请登录后继续。</p>
    {{ERROR}}
    <form method="post" action="/jwt-login" autocomplete="on">
      <input type="hidden" name="next" value="{{NEXT}}">
      <label class="field"><span>用户名</span>
        <input name="username" value="{{USERNAME}}" autocomplete="username" autocapitalize="off" spellcheck="false" required autofocus>
      </label>
      <label class="field"><span>密码</span>
        <div class="pw">
          <input type="password" name="password" autocomplete="current-password" required>
          <button type="button" class="eye" tabindex="-1" aria-label="显示/隐藏密码" onclick="togglePw(this)">
            <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M1 12s4-7.5 11-7.5S23 12 23 12s-4 7.5-11 7.5S1 12 1 12z"/><circle cx="12" cy="12" r="3.2"/>
            </svg>
          </button>
        </div>
      </label>
      <label class="remember"><input type="checkbox" name="remember" checked><span class="track"></span>
        <em>记住我 · <b>7 天内免登录</b></em></label>
      <button class="submit" type="submit" id="submitBtn"><span id="submitLabel">登 录</span></button>
    </form>
    <p class="foot"><b>内网设备免登录</b> · 仅公网访问需要验证<br>凭据经由 JWT 签发，有效期可配置</p>
  </main>
<script>
  function togglePw(btn){
    var input = btn.parentElement.querySelector('input');
    input.type = input.type === 'password' ? 'text' : 'password';
    btn.style.color = input.type === 'text' ? 'var(--txt)' : '';
  }
  (function(){
    var userInput = document.querySelector('input[name=username]');
    try{
      var saved = localStorage.getItem('cj_user');
      if (saved && !userInput.value) userInput.value = saved;
    }catch(e){}
    var form = document.querySelector('form');
    form.addEventListener('submit', function(){
      try{ localStorage.setItem('cj_user', userInput.value); }catch(e){}
      var btn = document.getElementById('submitBtn');
      btn.disabled = true;
      document.getElementById('submitLabel').innerHTML = '<span class="spin"></span>验证中…';
    });
  })();
</script>
</body>
</html>
"""


def render_login_page(cfg, error: str = "", next_url: str = "/", username: str = ""):
    if error:
        err_html = (
            '<div class="error">'
            '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/>'
            '<line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
            f"<span>{html.escape(error)}</span></div>"
        )
    else:
        err_html = ""
    return (
        _LOGIN_PAGE
        .replace("{{ERROR}}", err_html)
        .replace("{{NEXT}}", html.escape(next_url, quote=True))
        .replace("{{USERNAME}}", html.escape(username, quote=True))
    )


# --------------------------------------------------------------------------- #
# 中间件 & 路由
# --------------------------------------------------------------------------- #

def _make_middleware(cfg_store):
    @web.middleware
    async def jwt_auth_middleware(request: web.Request, handler):
        try:
            cfg = cfg_store.load()
        except Exception:
            log.exception("[comfyui-jwt-auth] 配置读取失败，本次请求放行")
            return await handler(request)

        if not cfg.get("enabled", True) or not cfg.get("password_hash"):
            return await handler(request)
        if request.path in PUBLIC_PATHS:
            return await handler(request)

        ip = request.remote or ""
        if is_trusted_ip(ip, cfg):
            return await handler(request)

        token = request.cookies.get(COOKIE_NAME)
        if token and verify_token(token, cfg):
            return await handler(request)

        if _is_navigation(request):
            log.info("[comfyui-jwt-auth] 要求登录 ip=%s path=%s", ip, request.path)
            nxt = request.rel_url.path_qs
            raise web.HTTPFound("/jwt-login?next=" + quote(nxt, safe=""))
        log.debug("[comfyui-jwt-auth] 未认证请求 ip=%s path=%s", ip, request.path)
        raise web.HTTPUnauthorized(
            text="401 Unauthorized (comfyui-jwt-auth)",
            content_type="text/plain",
            headers={"WWW-Authenticate": 'Cookie realm="comfyui"'},
        )

    return jwt_auth_middleware


def _register_routes(routes):
    @routes.get("/jwt-whoami")
    async def jwt_whoami(request: web.Request):
        cfg = config_store.load()
        ip = request.remote or ""
        trusted = is_trusted_ip(ip, cfg)
        matched = ""
        try:
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
                ip_obj = ip_obj.ipv4_mapped
            for net in _get_networks(cfg):
                if ip_obj.version == net.version and ip_obj in net:
                    matched = str(net)
                    break
        except ValueError:
            pass
        token_ok = False
        token = request.cookies.get(COOKIE_NAME)
        if token:
            token_ok = verify_token(token, cfg)
        enabled = bool(cfg.get("enabled", True)) and bool(cfg.get("password_hash"))
        info = {
            "enabled": enabled,
            "ip": ip,
            "trusted_no_login": trusted,
            "matched_rule": matched,
            "has_valid_token": token_ok,
            "needs_login": enabled and not (trusted or token_ok),
        }
        if _is_navigation(request) or "text/html" in request.headers.get("Accept", ""):
            rows = []
            for k, v in info.items():
                cls = ""
                if k in ("trusted_no_login",):
                    cls = " class='ok'" if v else " class='no'"
                if k == "needs_login":
                    cls = " class='no'" if v else " class='ok'"
                rows.append(f"<div class='row'><span>{html.escape(k)}</span><b{cls}>{html.escape(str(v))}</b></div>")
            page = (
                "<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>"
                "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                "<title>ComfyUI · 访问诊断</title><style>"
                "body{font-family:system-ui,'PingFang SC','Microsoft YaHei',sans-serif;background:#0a0c14;color:#e8eaf4;"
                "display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}"
                ".card{background:rgba(19,22,36,.85);border:1px solid rgba(148,163,255,.16);border-radius:16px;"
                "padding:26px 28px;width:min(440px,100%);box-shadow:0 24px 70px rgba(0,0,0,.55)}"
                "h1{font-size:16px;margin:0 0 4px}p{color:#8d94ad;font-size:12.5px;margin:0 0 18px}"
                ".row{display:flex;justify-content:space-between;gap:12px;padding:10px 2px;"
                "border-bottom:1px solid rgba(148,163,255,.10);font-size:13.5px}"
                ".row span{color:#8d94ad}.row b{font-weight:550;word-break:break-all;text-align:right}"
                ".ok{color:#5eead4}.no{color:#ffb4c0}</style></head><body><div class='card'>"
                "<h1>ComfyUI · 访问诊断</h1><p>当前访问者来源与鉴权判定（此页免登录）</p>"
                + "".join(rows) +
                "</div></body></html>"
            )
            return web.Response(text=page, content_type="text/html", headers={"Cache-Control": "no-store"})
        return web.json_response(info, headers={"Cache-Control": "no-store"})

    @routes.get("/jwt-login")
    async def jwt_login_page(request: web.Request):
        cfg = config_store.load()
        nxt = _safe_next(request.query.get("next"))
        force = str(request.query.get("force", "")).lower() in ("1", "true", "yes", "on")
        token = request.cookies.get(COOKIE_NAME)
        if not force and token and verify_token(token, cfg):
            raise web.HTTPFound(nxt)
        return web.Response(
            text=render_login_page(cfg, next_url=nxt),
            content_type="text/html",
            headers={"Cache-Control": "no-store"},
        )

    @routes.post("/jwt-login")
    async def jwt_login_submit(request: web.Request):
        cfg = config_store.load()
        form = await request.post()
        username = str(form.get("username") or "").strip()
        password = str(form.get("password") or "")
        remember = form.get("remember") == "on"
        nxt = _safe_next(form.get("next"))
        ip = request.remote or ""

        if is_locked(ip, cfg):
            return web.Response(
                text=render_login_page(cfg, error="尝试次数过多，请稍后再试", next_url=nxt, username=username),
                content_type="text/html",
                status=429,
                headers={"Cache-Control": "no-store"},
            )

        user_ok = hmac.compare_digest(username, str(cfg.get("username", "")))
        pass_ok = verify_password(password, str(cfg.get("password_hash", "")))
        if user_ok and pass_ok:
            clear_failures(ip)
            token, ttl = issue_token(cfg, remember)
            resp = web.HTTPFound(nxt)
            resp.set_cookie(
                COOKIE_NAME, token,
                max_age=ttl, httponly=True, samesite="Lax", path="/",
            )
            log.info("[comfyui-jwt-auth] 登录成功 ip=%s remember=%s ttl=%ss", ip, remember, ttl)
            return resp

        record_failure(ip, cfg)
        log.info("[comfyui-jwt-auth] 登录失败 ip=%s user=%r", ip, username)
        return web.Response(
            text=render_login_page(cfg, error="用户名或密码错误", next_url=nxt, username=username),
            content_type="text/html",
            status=401,
            headers={"Cache-Control": "no-store"},
        )

    @routes.get("/jwt-logout")
    @routes.post("/jwt-logout")
    async def jwt_logout(_request: web.Request):
        resp = web.HTTPFound("/jwt-login")
        resp.del_cookie(COOKIE_NAME, path="/")
        resp.headers["Cache-Control"] = "no-store"
        return resp


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #

def _install():
    try:
        cfg = config_store.load()
    except Exception:
        log.exception("[comfyui-jwt-auth] 初始化失败（连配置都读不了），以放行模式运行")
        return

    app = getattr(PromptServer.instance, "app", None)
    if app is None:
        log.warning("[comfyui-jwt-auth] PromptServer.instance.app 不存在，跳过（是否加载时机过早？）")
        return

    try:
        app.middlewares.append(_make_middleware(config_store))
    except AttributeError:
        app._middlewares.append(_make_middleware(config_store))

    _register_routes(PromptServer.instance.routes)

    enabled = bool(cfg.get("enabled", True)) and bool(cfg.get("password_hash"))
    if enabled:
        nets = ", ".join(str(n) for n in _get_networks(cfg))
        log.info("[comfyui-jwt-auth] 已启用。免登录来源：loopback/未列出=需登录；信任网段：%s", nets)
    else:
        log.warning("[comfyui-jwt-auth] 未启用（enabled=false 或缺少密码，编辑 %s 后无需重启即生效）", CONFIG_PATH)


_install()

NODE_CLASS_MAPPINGS = {}
NODE_DISPLAY_NAME_MAPPINGS = {}