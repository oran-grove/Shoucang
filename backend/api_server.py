# -*- coding: utf-8 -*-
"""
守藏 — 统一 FastAPI 后端
============================
提供 REST API + 前端静态文件服务。
由 main.py 一键启动。

所有数据库访问通过 database 模块统一接口，不直接连接数据库。

告警数据以 traffic_log 表为唯一数据源。
"""

import hashlib
import json
import logging
import os
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, model_validator

from config.shared_config import PROJECT_ROOT as _PROJECT_ROOT
_FRONTEND_ROOT = _PROJECT_ROOT / "frontend"

from config import get_config, reset_config, save_config_dict

logger = logging.getLogger("UnifiedBackend")

# ---- 系统性能采样（后台线程，避免阻塞异步事件循环）----
_perf_lock = threading.Lock()
_perf_cache = {
    "cpu": "0.0",
    "ram": "0.0",
    "up": "--",
    "down": "--",
    "updated": 0.0,
}
_PERF_INTERVAL = 2.0


def _perf_sampler():
    """后台线程：采集系统 CPU/RAM/网络速率"""
    import psutil
    while True:
        try:
            cpu = psutil.cpu_percent(interval=None)
            ram = psutil.virtual_memory().percent
            net_start = psutil.net_io_counters()
            time.sleep(1)
            net_end = psutil.net_io_counters()
            up_speed = (net_end.bytes_sent - net_start.bytes_sent) / 1024
            down_speed = (net_end.bytes_recv - net_start.bytes_recv) / 1024
            with _perf_lock:
                _perf_cache["cpu"] = f"{cpu:.1f}"
                _perf_cache["ram"] = f"{ram:.1f}"
                _perf_cache["up"] = f"{up_speed:.1f} KB/s" if up_speed < 1024 else f"{up_speed/1024:.1f} MB/s"
                _perf_cache["down"] = f"{down_speed:.1f} KB/s" if down_speed < 1024 else f"{down_speed/1024:.1f} MB/s"
                _perf_cache["updated"] = time.time()
        except Exception:
            pass
        time.sleep(_PERF_INTERVAL)


_perf_thread = threading.Thread(target=_perf_sampler, daemon=True)
_perf_thread.start()

# ---- FastAPI 应用实例 ----
app = FastAPI(title="守藏 API", version="3.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_should_serve_static = False
_server_instance = None

# ============================================================================
# WebUI 鉴权 — 密码哈希 / JWT / 中间件
# ============================================================================

_SCRYPT_N = 16384
_SCRYPT_R = 8
_SCRYPT_P = 1


def _hash_password(password: str) -> str:
    """stdlib scrypt 哈希密码，返回 'hexhash:hexsalt'。"""
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return h.hex() + ":" + salt.hex()


def _verify_password(password: str, stored: str) -> bool:
    """验证密码，常量时间比较。"""
    try:
        h_hex, s_hex = stored.split(":", 1)
        target = bytes.fromhex(h_hex)
        salt = bytes.fromhex(s_hex)
        actual = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
        return secrets.compare_digest(actual, target)
    except Exception:
        return False


def _create_token(username: str, secret: str, expiry_hours: int) -> str:
    """签发 JWT access token。"""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(hours=expiry_hours),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def _verify_token(token: str, secret: str) -> dict | None:
    """验证 JWT，有效返回 payload，无效/过期返回 None。"""
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


def _token_from_request(request: Request) -> str | None:
    """从 Authorization header 或 Cookie 中提取 token。"""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.cookies.get("token")


def _ensure_auth_config():
    """首次启动：自动生成 jwt_secret 和默认管理员密码哈希，持久化到 config_user.json。"""
    cfg = get_config().webui_auth
    changed = {}
    first_run = not cfg.admin_password_hash
    if not cfg.jwt_secret:
        changed["jwt_secret"] = secrets.token_urlsafe(32)
    if first_run:
        changed["admin_password_hash"] = _hash_password("admin123")
    if changed:
        save_config_dict({"webui_auth": changed})

    logger.info("=" * 60)
    logger.info("🔐 WebUI 管理员登录凭据")
    logger.info(f"   用户名: {cfg.admin_user}")
    if first_run:
        logger.info("   密码:   admin123 (首次启动默认密码，请尽快修改)")
    else:
        logger.info("   密码:   (已设置，若遗忘请编辑 config/config_user.json")
        logger.info("          删除 webui_auth.admin_password_hash 后重启将重置为 admin123)")
    logger.info("=" * 60)


# ---- HTTP 鉴权中间件 ----
_PUBLIC_PATHS = {
    "/", "/index.html", "/favicon.ico",
    "/api/auth/login", "/api/alert", "/api/health", "/api/status",
}
_PUBLIC_PREFIXES = ("/lib/", "/css/", "/js/", "/images/", "/error/", "/page/")


@app.middleware("http")
async def _auth_middleware(request: Request, call_next):
    path = request.url.path
    # 放行：白名单精确路径、静态资源前缀、OPTIONS 预检、静态 JSON 文件
    if path in _PUBLIC_PATHS or request.method == "OPTIONS":
        return await call_next(request)
    if path.startswith(_PUBLIC_PREFIXES):
        return await call_next(request)
    if path.startswith("/api/") and path.endswith(".json"):
        return await call_next(request)

    # 鉴权
    token = _token_from_request(request)
    if not token:
        return JSONResponse({"code": 401, "msg": "未登录"}, status_code=401)
    payload = _verify_token(token, get_config().webui_auth.jwt_secret)
    if payload is None:
        return JSONResponse({"code": 401, "msg": "登录已过期"}, status_code=401)
    request.state.username = payload["sub"]
    return await call_next(request)


# ============================================================================
# 统一数据转换：traffic_log 行 → 前端响应（中文字段）
# ============================================================================

# ai_verdict → 人类可读
_VERDICT_MAP = {2: "恶意", 1: "可疑", 0: "安全", None: "未分析"}
_LEVEL_MAP = {"high": "高危", "medium": "中危", "low": "低危"}
_VERDICT_TO_LEVEL = {2: "high", 1: "medium", 0: "low"}


def _fmt_bytes(b: int) -> str:
    if b is None:
        b = 0
    if b >= 1048576:
        return f"{b / 1048576:.1f} MB"
    if b >= 1024:
        return f"{b / 1024:.1f} KB"
    return f"{b} B"


def _enrich_traffic_row(row: dict) -> dict:
    """将 traffic_log 数据库行补充为前端友好的格式。

    保留原始英文字段以确保现有 JS 代码兼容，
    同时增加中文显示字段。
    """
    av_raw = row.get("ai_verdict")
    av: Optional[int] = int(av_raw) if av_raw is not None else None

    # 威胁等级
    level_key = _VERDICT_TO_LEVEL.get(av, "medium") if av is not None else "medium"
    row["threat_level"] = level_key
    row["threat_level_text"] = _LEVEL_MAP.get(level_key, "中危")

    # 判定结果
    row["verdict_text"] = _VERDICT_MAP.get(av, "未分析") if av is not None else "未分析"

    # 处理状态：区分 AI 分析阶段 vs 管理员处理阶段
    ai_done = row.get("ai_analyzed")
    is_blocked = row.get("is_blocked")
    if is_blocked:
        row["status_text"] = "已拉黑"
    elif not ai_done:
        row["status_text"] = "等待 AI 分析"
    else:
        row["status_text"] = "待管理员处理"

    # 流量大小格式化
    row["traffic_size_text"] = _fmt_bytes(row.get("accumulated_bytes") or 0)

    # 拦截状态
    row["block_text"] = "已拦截" if row.get("is_blocked") else "未拦截"

    # AI 分析理由（截断显示）
    reasoning = row.get("ai_reasoning", "") or ""
    row["ai_reasoning"] = reasoning

    # 原因摘要
    parts = []
    emp = row.get("employee", "")
    dept = row.get("department", "")
    if emp:
        parts.append(emp)
    if dept and dept != emp:
        parts.append(f"({dept})")
    if row.get("dst_ip"):
        target = row["dst_ip"]
        country = row.get("country", "")
        if country:
            target = f"{target}[{country}]"
        parts.append(f"→ {target}")
    if row.get("dst_port"):
        parts.append(f":{row['dst_port']}")
    if not parts:
        parts.append(row.get("src_ip", ""))
    row["reason"] = " ".join(parts)

    return row


# ============================================================================
# Database 模块统一调用接口
# ============================================================================
def _db(module_name: str, func_name: str, *args, **kwargs):
    """通用的 database 模块调用包装器"""
    import importlib
    try:
        mod = importlib.import_module(f"database.{module_name}")
        fn = getattr(mod, func_name)
        return fn(*args, **kwargs)
    except Exception as e:
        logger.error(f"database.{module_name}.{func_name} 调用失败: {e}")
        raise


# ============================================================================
# 内存告警缓冲区（仅用于 P4 控制面实时推送的暂存）
# ============================================================================
_alerts_lock = threading.Lock()
_alerts_buffer: list = []
_MAX_ALERTS = 200
_ALERT_TTL_SECONDS = 1800
_alert_id_counter = 0


def push_alert(ip: str, label: str, details: Optional[dict] = None,
               source: str = ""):
    """外部模块调用：推送告警到前端。"""
    global _alert_id_counter
    details = details or {}

    threat_level = (
        details.get("severity")
        or details.get("threat_level")
        or "medium"
    )
    if threat_level in ("critical",):
        threat_level = "high"
    elif threat_level not in ("high", "medium", "low"):
        threat_level = "medium"

    with _alerts_lock:
        for a in _alerts_buffer:
            if a["ip"] == ip and a["label"] == label:
                a["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                return

        _alert_id_counter += 1
        _alerts_buffer.insert(0, {
            "id": _alert_id_counter,
            "ip": ip,
            "label": label,
            "threat_level": threat_level,
            "source": source or "系统",
            "details": details,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
        if len(_alerts_buffer) > _MAX_ALERTS:
            _alerts_buffer.pop()


def dismiss_alert_by_id(alert_id: int) -> bool:
    with _alerts_lock:
        for i, a in enumerate(_alerts_buffer):
            if a["id"] == alert_id:
                _alerts_buffer.pop(i)
                return True
    return False


def dismiss_alerts_for_ip(ip: str) -> int:
    removed = 0
    with _alerts_lock:
        kept = []
        for a in _alerts_buffer:
            if a["ip"] == ip:
                removed += 1
            else:
                kept.append(a)
        _alerts_buffer[:] = kept
    return removed


def _expire_stale_alerts() -> int:
    cutoff = datetime.now()
    removed = 0
    with _alerts_lock:
        kept = []
        for a in _alerts_buffer:
            try:
                ts = datetime.strptime(a["timestamp"], "%Y-%m-%d %H:%M:%S")
                if (cutoff - ts).total_seconds() > _ALERT_TTL_SECONDS:
                    removed += 1
                else:
                    kept.append(a)
            except Exception:
                kept.append(a)
        _alerts_buffer[:] = kept
    return removed


def _start_alert_expiry_thread() -> threading.Thread:
    def _expiry_loop():
        while True:
            time.sleep(60)
            try:
                n = _expire_stale_alerts()
                if n > 0:
                    logger.debug(f"告警自动过期: {n} 条")
            except Exception:
                pass
    t = threading.Thread(target=_expiry_loop, daemon=True)
    t.start()
    return t


# ---- Pydantic 模型 ----
class AlertData(BaseModel):
    ip: str
    label: str
    details: Optional[dict] = None


class DismissRequest(BaseModel):
    alert_id: int = 0
    ip: str = ""


class BackendTestRequest(BaseModel):
    backend: str


class ConfigSaveRequest(BaseModel):
    config: dict



class BlacklistAddRequest(BaseModel):
    ip: str
    threat_level: str = "高"
    reason: Optional[str] = "手动添加"
    port: Optional[int] = None
    attack_type: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _empty_str_to_none(cls, data: dict) -> dict:
        """将空字符串转为 None，避免 Optional[int] 字段校验失败。"""
        if isinstance(data, dict):
            for key in ("port",):
                if data.get(key) in (None, ""):
                    data[key] = None
        return data


class WhitelistAddRequest(BaseModel):
    ip: str
    reason: Optional[str] = "手动添加"
    port: Optional[int] = None
    trust_level: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _empty_str_to_none(cls, data: dict) -> dict:
        """将空字符串转为 None，避免 Optional[int] 字段校验失败。"""
        if isinstance(data, dict):
            for key in ("port",):
                if data.get(key) in (None, ""):
                    data[key] = None
        return data


class TrafficAction(BaseModel):
    event: str
    id: int = 0
    reason: Optional[str] = None


class EmployeeAddRequest(BaseModel):
    number: str
    ip: str
    department: str
    name: str


# ============================================================================
# API: 系统初始化
# ============================================================================
@app.get("/api/init")
async def api_init():
    return JSONResponse({
        "code": 0,
        "msg": "系统就绪",
        "data": {
            "systemName": "守藏",
            "version": "3.1.0",
        }
    })


# ============================================================================
# API: 管理员鉴权
# ============================================================================

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
async def api_auth_login(payload: LoginRequest):
    cfg = get_config().webui_auth
    if payload.username != cfg.admin_user:
        return JSONResponse({"code": 1, "msg": "用户名或密码错误"}, status_code=401)
    if not _verify_password(payload.password, cfg.admin_password_hash):
        return JSONResponse({"code": 1, "msg": "用户名或密码错误"}, status_code=401)
    token = _create_token(payload.username, cfg.jwt_secret, cfg.jwt_expiry_hours)
    resp = JSONResponse({
        "code": 0,
        "msg": "登录成功",
        "data": {
            "token": token,
            "username": payload.username,
            "expires_in": cfg.jwt_expiry_hours * 3600,
        }
    })
    # ponytail: Cookie 让 iframe 子页面也能自动携带 token，无需逐页修改
    resp.set_cookie(
        key="token", value=token,
        max_age=cfg.jwt_expiry_hours * 3600,
        httponly=True, samesite="lax",
    )
    return resp


@app.get("/api/auth/status")
async def api_auth_status(request: Request):
    """检查当前登录状态。"""
    token = _token_from_request(request)
    if not token:
        return JSONResponse({"code": 0, "data": {"authenticated": False}})
    payload = _verify_token(token, get_config().webui_auth.jwt_secret)
    if payload is None:
        return JSONResponse({"code": 0, "data": {"authenticated": False}})
    return JSONResponse({"code": 0, "data": {"authenticated": True, "username": payload["sub"]}})


class UpdateAccountRequest(BaseModel):
    username: str = ""
    current_password: str = ""
    new_password: str = ""
    jwt_expiry_hours: int = 0


@app.post("/api/auth/update-account")
async def api_auth_update_account(payload: UpdateAccountRequest):
    """更新账户设置（用户名 / 密码 / 登录有效期）。中间件已鉴权。"""
    cfg = get_config().webui_auth
    updates = {}

    if payload.username and payload.username != cfg.admin_user:
        updates["admin_user"] = payload.username

    if payload.new_password:
        if not _verify_password(payload.current_password, cfg.admin_password_hash):
            return JSONResponse({"code": 1, "msg": "当前密码错误"}, status_code=400)
        updates["admin_password_hash"] = _hash_password(payload.new_password)

    if payload.jwt_expiry_hours > 0:
        updates["jwt_expiry_hours"] = payload.jwt_expiry_hours

    if updates:
        save_config_dict({"webui_auth": updates})
        logger.info("[鉴权] 账户设置已更新: %s", list(updates.keys()))
        return JSONResponse({"code": 0, "msg": "账户设置已保存"})
    return JSONResponse({"code": 0, "msg": "无变更"})


# ============================================================================
# API: 配置管理
# ============================================================================
@app.get("/api/config")
async def api_get_config():
    return JSONResponse({"code": 0, "data": get_config().to_dict()})


@app.post("/api/config")
async def api_save_config(payload: ConfigSaveRequest):
    try:
        save_config_dict(payload.config)
        return JSONResponse({"code": 0, "msg": "保存成功"})
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


_SUPPORTED_BACKENDS = {"deepseek", "openai", "lmstudio"}


class BackendSaveRequest(BaseModel):
    backend: str
    api_key: str = ""
    model_name: str = ""
    api_base: str = ""
    temperature: float = 0.3
    max_tokens: int = 2048
    timeout: float = 60.0
    max_retries: int = 3


@app.post("/api/config/backend")
async def api_config_backend_save(payload: BackendSaveRequest):
    """保存单个后端的配置到 config_user.json"""
    backend_key = payload.backend.lower()
    if backend_key not in _SUPPORTED_BACKENDS:
        return JSONResponse(
            {"code": 1, "msg": f"不支持的后端: {payload.backend}"}, status_code=400,
        )

    # 将前端扁平的 payload 转换为 config 的嵌套结构
    backend_fields = {}
    for f in ("api_key", "model_name", "api_base", "temperature",
              "max_tokens", "timeout", "max_retries"):
        val = getattr(payload, f, None)
        if val:
            backend_fields[f] = val

    updates = {"backends": {backend_key: backend_fields}}

    try:
        save_config_dict(updates)
        return JSONResponse({"code": 0, "msg": f"后端 '{payload.backend}' 配置已保存"})
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


@app.post("/api/config/backend/test")
async def api_config_backend_test(payload: BackendTestRequest):
    backend_key = payload.backend.lower()
    if backend_key not in _SUPPORTED_BACKENDS:
        return JSONResponse(
            {"code": 1, "msg": f"不支持的后端: {payload.backend}"}, status_code=400,
        )

    app_config = get_config()
    backend_cfg = getattr(app_config.backends, backend_key, None)

    if backend_cfg is None or not backend_cfg.api_key:
        return JSONResponse(
            {"code": 1, "msg": f"后端 '{payload.backend}' 未配置 API 密钥"}, status_code=400,
        )

    try:
        backend = _build_backend_for_test(backend_key, backend_cfg)
    except ValueError as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=400)

    try:
        await backend.chat(
            system_prompt="",
            user_prompt="ping",
            model=backend_cfg.model_name,
            max_tokens=1,
        )
        return JSONResponse({"code": 0, "msg": f"后端 '{payload.backend}' 连接成功"})
    except RuntimeError as e:
        return JSONResponse({"code": 1, "msg": f"连接失败: {str(e)[:300]}"}, status_code=502)
    except Exception as e:
        return JSONResponse({"code": 1, "msg": f"连接测试异常: {str(e)}"}, status_code=500)
    finally:
        await _close_backend(backend)


def _build_backend_for_test(backend_key: str, cfg):
    from multi_agent_system.backends.openai_backend import OpenAIBackend
    from multi_agent_system.backends.deepseek_backend import DeepSeekBackend
    from multi_agent_system.backends.lmstudio_backend import LMStudioBackend

    if backend_key == "deepseek":
        return DeepSeekBackend(
            api_key=cfg.api_key,
            api_base=cfg.api_base or "https://api.deepseek.com",
            timeout=cfg.timeout,
            max_retries=cfg.max_retries,
            default_model=cfg.model_name or "deepseek-v4-flash",
            default_thinking_enabled=getattr(cfg, "thinking_enabled", None),
            default_reasoning_effort=getattr(cfg, "reasoning_effort", None),
            include_reasoning=getattr(cfg, "include_reasoning", False),
        )
    elif backend_key == "openai":
        return OpenAIBackend(
            api_base=cfg.api_base or "https://api.openai.com/v1",
            api_key=cfg.api_key,
            timeout=cfg.timeout,
            max_retries=cfg.max_retries,
            default_model=cfg.model_name or "gpt-4o-mini",
        )
    elif backend_key == "lmstudio":
        return LMStudioBackend(
            api_base=cfg.api_base or "http://localhost:1234/v1",
            api_key=cfg.api_key or "lm-studio",
            timeout=cfg.timeout,
            max_retries=cfg.max_retries,
            default_model=cfg.model_name or "local-model",
            auto_load=False,
        )
    else:
        raise ValueError(f"不支持的后端: {backend_key}")


async def _close_backend(backend) -> None:
    try:
        if hasattr(backend, "aclose"):
            await backend.aclose()
        elif hasattr(backend, "close"):
            backend.close()
    except Exception:
        pass


class ConfigResetRequest(BaseModel):
    sections: Optional[list[str]] = None  # None/空 = 全量重置


@app.post("/api/config/reset")
async def api_config_reset(payload: ConfigResetRequest = ConfigResetRequest()):
    try:
        if payload.sections:
            reset_config(*payload.sections)
            return JSONResponse(
                {"code": 0, "msg": f"已重置配置节: {', '.join(payload.sections)}"}
            )
        else:
            reset_config()
            return JSONResponse({"code": 0, "msg": "已恢复默认配置"})
    except ValueError as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


@app.get("/api/config/database")
async def api_config_database_get():
    """返回当前数据库配置（用于 WebUI 表单预填）。"""
    db = get_config("database")
    return JSONResponse({
        "code": 0,
        "data": {
            "host": db.host,
            "port": db.port,
            "user": db.user,
            "password": db.password,
            "database": db.database,
            "charset": db.charset,
        }
    })


@app.post("/api/config/database")
async def api_config_database_save(request: Request):
    """保存数据库配置到 config_user.json。"""
    try:
        body = await request.json()
        save_config_dict({"database": body})
        return JSONResponse({"code": 0, "msg": "数据库配置已保存"})
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


# ============================================================================
# API: 员工管理
# ============================================================================
@app.get("/api/menus")
async def api_menus():
    menu_path = _FRONTEND_ROOT / "api" / "menus.json"
    if menu_path.exists():
        return JSONResponse(json.loads(menu_path.read_text(encoding="utf-8")))
    return JSONResponse({"code": 0, "data": []})


@app.get("/api/employees")
async def api_employees_get(
    page: int = Query(1),
    limit: int = Query(15),
    number: str = Query(""),
    ip: str = Query(""),
    department: str = Query(""),
    name: str = Query(""),
):
    try:
        filters = {}
        for k in ("number", "ip", "department", "name"):
            v = locals().get(k, "")
            if v:
                filters[k] = v
        total, rows = _db("lists_manager", "get_employees", filters, page, limit)
        return JSONResponse({"code": 0, "data": rows, "count": total})
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


@app.post("/api/employees")
async def api_employee_add(payload: EmployeeAddRequest):
    try:
        _db("lists_manager", "add_employee",
            payload.number, payload.ip, payload.department, payload.name)
        return JSONResponse({"code": 0, "msg": "添加成功"})
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


@app.put("/api/employees/{emp_id}")
async def api_employee_update(emp_id: int, payload: EmployeeAddRequest):
    try:
        _db("lists_manager", "update_employee",
            emp_id, number=payload.number, ip=payload.ip,
            department=payload.department, name=payload.name)
        return JSONResponse({"code": 0, "msg": "更新成功"})
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


@app.delete("/api/employees/{emp_id}")
async def api_employee_delete(emp_id: int):
    try:
        _db("lists_manager", "delete_employee", emp_id)
        return JSONResponse({"code": 0, "msg": "删除成功"})
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


@app.get("/api/ip_map")
async def api_ip_map_get():
    try:
        data = _db("lists_manager", "get_ip_dept_map")
        return JSONResponse({"code": 0, "data": data})
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


# ============================================================================
# API: 黑白名单管理
# ============================================================================
@app.get("/api/blacklist")
async def api_blacklist_get(
    page: int = Query(1),
    limit: int = Query(10),
):
    try:
        result = _db("lists_manager", "get_blacklist_detailed", page, limit)
        return JSONResponse({"code": 0, "data": result["rows"], "count": result["total"]})
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


@app.post("/api/blacklist")
async def api_blacklist_add(payload: BlacklistAddRequest):
    try:
        _db("lists_manager", "add_to_db_blacklist",
            ip=payload.ip,
            threat_level=payload.threat_level,
            reason=payload.reason or "手动添加",
            port=payload.port,
            attack_type=payload.attack_type,
        )
        return JSONResponse({"code": 0, "msg": f"已拉黑 {payload.ip}"})
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


@app.delete("/api/blacklist/{item_id}")
async def api_blacklist_delete(item_id: int):
    try:
        ok = _db("lists_manager", "remove_from_blacklist", item_id)
        if ok:
            return JSONResponse({"code": 0, "msg": "删除成功"})
        return JSONResponse({"code": 1, "msg": "删除失败"}, status_code=500)
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


@app.get("/api/whitelist")
async def api_whitelist_get(
    page: int = Query(1),
    limit: int = Query(10),
):
    try:
        result = _db("lists_manager", "get_whitelist_detailed", page, limit)
        return JSONResponse({"code": 0, "data": result["rows"], "count": result["total"]})
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


@app.post("/api/whitelist")
async def api_whitelist_add(payload: WhitelistAddRequest):
    try:
        _db("lists_manager", "add_to_db_whitelist",
            ip=payload.ip,
            reason=payload.reason or "手动添加",
            port=payload.port,
            trust_level=payload.trust_level,
        )
        return JSONResponse({"code": 0, "msg": f"已加白 {payload.ip}"})
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


@app.delete("/api/whitelist/{item_id}")
async def api_whitelist_delete(item_id: int):
    try:
        ok = _db("lists_manager", "remove_from_whitelist", item_id)
        if ok:
            return JSONResponse({"code": 0, "msg": "删除成功"})
        return JSONResponse({"code": 1, "msg": "删除失败"}, status_code=500)
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


# ============================================================================
# API: 流量事件 — 统一数据源 (traffic_log 表)
# ============================================================================
@app.get("/api/traffic")
async def api_traffic_get():
    """获取流量事件列表（数据库为唯一数据源）。"""
    data = []
    try:
        rows = _db("lists_manager", "get_traffic_logs", 200, 0)
        for row in rows:
            if isinstance(row.get("packet_time"), datetime):
                row["packet_time"] = row["packet_time"].strftime("%Y-%m-%d %H:%M:%S")
            _enrich_traffic_row(row)
            data.append(row)
    except Exception as e:
        logger.warning(f"查询 traffic_log 失败: {e}")

    return JSONResponse({"code": 0, "data": {"data": data}})


@app.post("/api/traffic")
async def api_traffic_action(payload: TrafficAction):
    """处理可疑事件（忽视 / 拉黑）"""
    action = payload.event
    item_id = payload.id
    reason = payload.reason or "手动操作"

    logger.info(f"流量事件操作: action={action}, id={item_id}")

    target_ip = None
    ai_verdict = "unknown"
    ai_confidence = 0.0

    if item_id:
        try:
            rows = _db("lists_manager", "get_traffic_logs", 200, 0)
            for row in rows:
                if row.get("id") == item_id:
                    target_ip = row.get("src_ip")
                    ai_verdict = row.get("ai_verdict", "unknown") or "unknown"
                    break
        except Exception:
            pass

    if action == "拉黑" and target_ip:
        try:
            from p4_controller.add_ip import add_to_blacklist as _p4_block
            ok = _p4_block(target_ip, source="frontend", reason=reason)
            if not ok:
                logger.warning(f"P4 拉黑 {target_ip} 返回失败（交换机可能未连接）")
        except Exception as e:
            logger.error(f"P4 硬件拉黑异常: {e}")

    if action == "忽视" and target_ip:
        # 忽视 → 从黑名单中删除该 IP
        try:
            from database import remove_from_blacklist
            detailed = _db("lists_manager", "get_blacklist_detailed", 1, 10000)
            for row in detailed.get("rows", []):
                if row.get("ip_address") == target_ip:
                    remove_from_blacklist(row["id"])
                    logger.info(f"已从数据库黑名单移除 {target_ip} (id={row['id']})")
                    break
        except Exception as e:
            logger.error(f"数据库黑名单移除异常: {e}")

    if item_id:
        try:
            _db("lists_manager", "update_traffic_action", item_id, action)
        except Exception:
            pass

    if target_ip:
        n = dismiss_alerts_for_ip(target_ip)
        if n > 0:
            logger.info(f"已移除 {target_ip} 的 {n} 条告警")

    _record_to_memory_from_admin(item_id, action, reason, target_ip,
                                 ai_verdict, ai_confidence)

    return JSONResponse({"code": 0, "msg": f"操作成功: {action}"})


# ============================================================================
# API: 告警管理（向后兼容 — 重定向到统一 traffic 端点）
# ============================================================================
@app.get("/api/alerts")
async def api_alerts_get():
    """获取告警列表 — 数据库为唯一数据源。"""
    data = []
    try:
        rows = _db("lists_manager", "get_traffic_logs", 200, 0)
        for row in rows:
            if isinstance(row.get("packet_time"), datetime):
                row["packet_time"] = row["packet_time"].strftime("%Y-%m-%d %H:%M:%S")
            _enrich_traffic_row(row)
            data.append(row)
    except Exception as e:
        logger.warning(f"查询 traffic_log 失败: {e}")

    return JSONResponse({"code": 0, "count": len(data), "data": data})


@app.post("/api/alert")
async def api_alert_receive(payload: AlertData):
    """接收实时告警推送（P4 控制面）"""
    source = "AI研判" if (payload.label and "[L3-研判]" in payload.label) else "P4控制面"
    push_alert(payload.ip, payload.label, payload.details, source=source)
    return JSONResponse({"status": "ok"})


@app.post("/api/alert/dismiss")
async def api_alert_dismiss(payload: DismissRequest):
    """移除告警（忽视操作）"""
    dismissed_count = 0
    if payload.alert_id:
        ok = dismiss_alert_by_id(payload.alert_id)
        dismissed_count = 1 if ok else 0
    elif payload.ip:
        dismissed_count = dismiss_alerts_for_ip(payload.ip)
    else:
        return JSONResponse({"code": 1, "msg": "请提供 alert_id 或 ip"}, status_code=400)

    target_ip = payload.ip or ""
    if target_ip and dismissed_count > 0:
        # 从黑名单中移除
        try:
            from database import remove_from_blacklist
            detailed = _db("lists_manager", "get_blacklist_detailed", 1, 10000)
            for row in detailed.get("rows", []):
                if row.get("ip_address") == target_ip:
                    remove_from_blacklist(row["id"])
                    logger.info(f"已从数据库黑名单移除 {target_ip} (id={row['id']})")
                    break
        except Exception as e:
            logger.error(f"数据库黑名单移除异常: {e}")

        # 记录到智能体记忆
        _record_to_memory_from_admin(
            item_id=0, action="忽视", reason="首页告警忽略",
            target_ip=target_ip, ai_verdict="unknown", ai_confidence=0.0,
        )

    return JSONResponse({"code": 0, "msg": f"已移除 {dismissed_count} 条告警"})


# ============================================================================
# API: 清理缓存 & 健康检查 & 系统状态
# ============================================================================
@app.post("/api/clear")
async def api_clear():
    with _alerts_lock:
        _alerts_buffer.clear()
    return JSONResponse({"code": 1, "msg": "服务端清理缓存成功"})


@app.get("/api/health")
async def api_health():
    return JSONResponse({"status": "ok", "version": "3.1.0"})


@app.get("/api/status")
async def api_status():
    with _perf_lock:
        cpu = _perf_cache["cpu"]
        ram = _perf_cache["ram"]
        up = _perf_cache["up"]
        down = _perf_cache["down"]
    return JSONResponse({"code": 0, "data": {"cpu": cpu, "ram": ram, "up": up, "down": down}})


# ============================================================================
# 管理员反馈 → 记忆系统
# ============================================================================
def _record_to_memory_from_admin(item_id, action, reason, target_ip,
                                 ai_verdict, ai_confidence):
    try:
        from multi_agent_system.memory import get_store
        store = get_store()
        store.record_feedback(
            traffic_id=item_id,
            ai_verdict=str(ai_verdict) if ai_verdict else "unknown",
            ai_confidence=float(ai_confidence) if ai_confidence else 0.0,
            ai_reasoning="",
            ai_threat_type="",
            admins_action=action,
            admin_note=reason or "",
            ai_correct=(action == "拉黑"),
            src_ip=target_ip or "",
            dst_ip="",
            department="",
            protocol="",
        )
    except Exception as e:
        logger.warning(f"写入反馈记忆失败: {e}")


# ============================================================================
# 启动 & 静态文件
# ============================================================================
@app.on_event("startup")
async def startup():
    global _should_serve_static
    if _FRONTEND_ROOT.exists() and (_FRONTEND_ROOT / "index.html").exists():
        _should_serve_static = True
        logger.info(f"✅ 前端静态文件目录已就绪: {_FRONTEND_ROOT}")
    else:
        _should_serve_static = False
        logger.warning(f"⚠️ 前端静态文件目录未找到: {_FRONTEND_ROOT}")

    _ensure_auth_config()
    _start_alert_expiry_thread()
    logger.info("✅ 告警自动过期线程已启动 (TTL=%ds)", _ALERT_TTL_SECONDS)


if _FRONTEND_ROOT.exists():
    _static_dirs_check = ["lib", "css", "js", "images", "error"]
    _mounted_any = False
    for _d in _static_dirs_check:
        _p = _FRONTEND_ROOT / _d
        if _p.exists() and _p.is_dir():
            try:
                app.mount(f"/{_d}", StaticFiles(directory=str(_p)), name=f"static_{_d}")
                _mounted_any = True
            except Exception:
                pass
    if _mounted_any:
        logger.info("✅ 静态资源目录挂载完成")


@app.get("/favicon.ico")
async def favicon():
    favicon_path = _FRONTEND_ROOT / "images" / "favicon.ico"
    if favicon_path.exists():
        return FileResponse(str(favicon_path))
    raise HTTPException(status_code=404)


@app.get("/")
@app.get("/index.html")
async def index():
    if not _should_serve_static:
        return HTMLResponse("<h2>前端文件未找到</h2>", status_code=404)
    return FileResponse(str(_FRONTEND_ROOT / "index.html"))


@app.get("/page/{filename:path}")
async def serve_page(filename: str):
    if not _should_serve_static:
        return HTMLResponse("<h2>前端文件未找到</h2>", status_code=404)
    file_path = _FRONTEND_ROOT / "page" / filename
    if file_path.exists() and file_path.is_file():
        return FileResponse(str(file_path))
    raise HTTPException(status_code=404)


@app.get("/api/{filename:path}")
async def serve_api_json(filename: str):
    file_path = _FRONTEND_ROOT / "api" / filename
    if file_path.exists() and file_path.is_file():
        return FileResponse(str(file_path))
    return JSONResponse({"code": 0, "data": []})


@app.get("/page/table/{filename:path}")
async def serve_table_page(filename: str):
    if not _should_serve_static:
        return HTMLResponse("<h2>前端文件未找到</h2>", status_code=404)
    file_path = _FRONTEND_ROOT / "page" / "table" / filename
    if file_path.exists() and file_path.is_file():
        return FileResponse(str(file_path))
    raise HTTPException(status_code=404)


# ============================================================================
# 服务器入口
# ============================================================================
def start_backend(port: int = 8080):
    import uvicorn
    global _server_instance

    config = uvicorn.Config(
        app="backend.api_server:app",
        host="0.0.0.0",
        port=port,
        log_level="warning",
        loop="asyncio",
        reload=False,
    )
    _server_instance = uvicorn.Server(config)
    _srv = _server_instance  # 局部捕获，消除 Optional 类型歧义

    def _run():
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_srv.serve())

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    logger.info("✅ 后端服务已启动: http://0.0.0.0:%d", port)
    return _server_instance


def stop_backend():
    global _server_instance
    if _server_instance:
        _server_instance.should_exit = True
        logger.info("后端服务已停止")


if __name__ == "__main__":
    start_backend()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_backend()
