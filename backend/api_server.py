# -*- coding: utf-8 -*-
"""
守藏 — 统一 FastAPI 后端
============================
提供 REST API + 前端静态文件服务。
由 main.py 一键启动。

所有数据库访问通过 database 模块统一接口，不直接连接数据库。

API 端点映射：
  GET    /api/init           → 系统初始化信息
  GET    /api/config          → 读取用户配置
  POST   /api/config          → 保存用户配置
  POST   /api/config/backend  → 保存后端大模型配置
  POST   /api/config/reset    → 重置默认配置
  GET    /api/employees       → 员工列表查询
  POST   /api/employees       → 新增员工
  PUT    /api/employees/{id}  → 编辑员工
  DELETE /api/employees/{id}  → 删除员工
  GET    /api/blacklist       → 黑名单列表
  POST   /api/blacklist       → 加入黑名单
  DELETE /api/blacklist/{id}  → 移除黑名单
  GET    /api/whitelist       → 白名单列表
  POST   /api/whitelist       → 加入白名单
  DELETE /api/whitelist/{id}  → 移除白名单
  GET    /api/traffic         → 流量/可疑事件列表
  POST   /api/traffic         → 处理可疑事件（拉黑/忽视）
  GET    /api/alerts          → 告警列表
  POST   /api/alert           → 接收实时告警
  POST   /api/clear           → 清理缓存
  GET    /api/menus           → 菜单权限数据
  GET    /api/ip_map          → IP-部门映射
  GET    /api/status          → 系统状态 (CPU/RAM/网络)
  GET    /api/health          → 健康检查
"""

import json
import logging
import os
import threading
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ---- 路径配置 ----
from config.shared_config import PROJECT_ROOT as _PROJECT_ROOT
_FRONTEND_ROOT = _PROJECT_ROOT / "frontend"

# ---- 配置管理（通过 config 模块）----
from config import get_config, reset_config, save_config_dict

logger = logging.getLogger("UnifiedBackend")

# ---- 系统性能采样（后台线程，避免阻塞异步事件循环）----
_perf_lock = threading.Lock()
_perf_cache = {
    "cpu": 0.0,
    "ram": 0.0,
    "up_bytes": 0,   # 真实吞吐率 (bytes/s)
    "down_bytes": 0,
}
_last_net = None     # (bytes_sent, bytes_recv, timestamp)
_perf_running = True


def _perf_sampler(interval: float = 2.0):
    """后台线程：周期性采样 CPU / RAM / 网络吞吐率"""
    import time as _time
    global _last_net, _perf_running

    # 预热 psutil CPU 采样（第一次调用总是 0）
    try:
        import psutil
        psutil.cpu_percent(interval=0.1)
    except Exception:
        pass

    while _perf_running:
        try:
            import psutil

            # CPU / RAM — 瞬时快照
            cpu = round(psutil.cpu_percent(interval=0.0), 1)
            mem = psutil.virtual_memory()
            ram = round(mem.percent, 1)

            # 网络吞吐率 — 差分计算
            net = psutil.net_io_counters()
            now = _time.monotonic()
            if _last_net is not None:
                prev_sent, prev_recv, prev_time = _last_net
                delta = now - prev_time
                if delta > 1e-6:
                    up_bytes = int((net.bytes_sent - prev_sent) / delta)
                    down_bytes = int((net.bytes_recv - prev_recv) / delta)
                else:
                    up_bytes = 0
                    down_bytes = 0
            else:
                up_bytes = 0
                down_bytes = 0
            _last_net = (net.bytes_sent, net.bytes_recv, now)

            with _perf_lock:
                _perf_cache["cpu"] = cpu
                _perf_cache["ram"] = ram
                _perf_cache["up_bytes"] = up_bytes
                _perf_cache["down_bytes"] = down_bytes
        except Exception:
            pass

        _time.sleep(interval)


_perf_thread = threading.Thread(target=_perf_sampler, daemon=True, name="PerfSampler")
_perf_thread.start()

# ---- FastAPI 应用 ----
app = FastAPI(title="守藏API", version="3.0.0", docs_url=None, redoc_url=None)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# 数据模型
# ============================================================================
class ConfigSaveRequest(BaseModel):
    database: Optional[dict] = None
    backends: Optional[dict] = None
    screening: Optional[dict] = None
    backtrack: Optional[dict] = None
    adjudication: Optional[dict] = None
    feedback: Optional[dict] = None
    live_scan: Optional[dict] = None
    geoip: Optional[dict] = None


class BackendConfigSave(BaseModel):
    backend: str
    api_key: Optional[str] = None
    model_name: Optional[str] = None
    api_base: Optional[str] = None
    auto_load: Optional[bool] = None
    context_length: Optional[int] = None
    flash_attention: Optional[bool] = None


class EmployeeCreate(BaseModel):
    number: str
    ip: str
    department: str
    name: str


class EmployeeUpdate(BaseModel):
    number: Optional[str] = None
    ip: Optional[str] = None
    department: Optional[str] = None
    name: Optional[str] = None


class BlacklistAdd(BaseModel):
    ip: str
    reason: Optional[str] = "手动添加"


class WhitelistAdd(BaseModel):
    ip: str
    reason: Optional[str] = "手动添加"


class AlertData(BaseModel):
    ip: str
    label: str
    details: Optional[dict] = None


class TrafficAction(BaseModel):
    event: str  # "忽视" or "拉黑"
    reason: str
    id: Optional[int] = None


class BlacklistItem(BaseModel):
    id: int


# ============================================================================
# 内存告警缓冲区（接收 P4 控制面的实时告警）
# ============================================================================
_alerts_lock = threading.Lock()
_alerts_buffer: list = []  # 最近告警
_MAX_ALERTS = 200


def push_alert(ip: str, label: str, details: Optional[dict] = None):
    """外部模块调用：推送告警到前端"""
    with _alerts_lock:
        _alerts_buffer.insert(
            0,
            {
                "id": len(_alerts_buffer) + 1,
                "ip": ip,
                "label": label,
                "details": details or {},
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
        )
        if len(_alerts_buffer) > _MAX_ALERTS:
            _alerts_buffer.pop()


# ============================================================================
# Database 模块统一调用接口
# ============================================================================
def _db(module_name: str, func_name: str, *args, **kwargs):
    """
    通用数据库模块调用包装。
    所有数据库操作必须通过 database 模块，禁止直接连接数据库。
    """
    try:
        import importlib
        mod = importlib.import_module(f"database.{module_name}")
        func = getattr(mod, func_name)
        return func(*args, **kwargs)
    except Exception as e:
        logger.error(f"[数据库] {module_name}.{func_name} 调用失败: {e}")
        raise


# ============================================================================
# API: 系统初始化
# ============================================================================
@app.get("/api/init")
async def api_init():
    """返回系统初始化信息：homeInfo, logoInfo, menuInfo"""
    init_file = _FRONTEND_ROOT / "api" / "init.json"
    if init_file.exists():
        return JSONResponse(json.loads(init_file.read_text(encoding="utf-8")))
    return JSONResponse(
        {
            "homeInfo": {"title": "首页", "href": "page/welcome-1.html"},
            "logoInfo": {
                "title": "守藏",
                "image": "images/logo.png",
                "href": "",
            },
            "menuInfo": [],
        }
    )


# ============================================================================
# API: 配置管理
# ============================================================================
@app.get("/api/config")
async def api_get_config():
    """获取当前用户配置"""
    config = get_config().to_dict()
    return JSONResponse({"code": 0, "data": config})


@app.post("/api/config")
async def api_save_config(payload: ConfigSaveRequest):
    """保存用户配置（部分更新）"""
    config = get_config().to_dict()
    data = payload.model_dump(exclude_none=True)

    for section, fields in data.items():
        if isinstance(fields, dict) and section in config:
            for key, value in fields.items():
                if key in config[section]:
                    orig_type = type(config[section][key])
                    try:
                        if orig_type == bool:
                            config[section][key] = bool(value)
                        elif orig_type == int:
                            config[section][key] = int(value)
                        elif orig_type == float:
                            config[section][key] = float(value)
                        else:
                            config[section][key] = str(value)
                    except (ValueError, TypeError):
                        config[section][key] = value

    save_config_dict(config)
    return JSONResponse({"code": 0, "msg": "保存成功"})


@app.post("/api/config/backend")
async def api_save_backend_config(payload: BackendConfigSave):
    """单独保存某个后端的 API 密钥 / 模型配置"""
    config = get_config().to_dict()
    if "backends" not in config:
        config["backends"] = {}

    backend_name = payload.backend
    if backend_name not in config["backends"]:
        config["backends"][backend_name] = {}

    update_data = payload.model_dump(exclude_none=True)
    update_data.pop("backend", None)

    for key, value in update_data.items():
        if key in ("auto_load", "flash_attention"):
            config["backends"][backend_name][key] = bool(value)
        elif key == "context_length":
            config["backends"][backend_name][key] = int(value) if value else 4096
        elif key == "api_base":
            config["backends"][backend_name]["api_base"] = str(value)
        elif key == "api_key":
            config["backends"][backend_name]["api_key"] = str(value)
        elif key == "model_name":
            config["backends"][backend_name]["model_name"] = str(value)
        else:
            config["backends"][backend_name][key] = value

    save_config_dict(config)
    return JSONResponse({"code": 0, "msg": f"后端 '{backend_name}' 配置已保存"})


class BackendTestRequest(BaseModel):
    backend: str


# 前端后端名称 → 配置节名称
_SUPPORTED_BACKENDS = {"deepseek", "openai", "lmstudio"}


@app.post("/api/config/backend/test")
async def api_config_backend_test(payload: BackendTestRequest):
    """测试指定后端的连接性 — 复用多智能体系统的后端类进行真实推理测试。"""
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

    # 使用与 Orchestrator._init_backends() 完全相同的后端实例化逻辑
    try:
        backend = _build_backend_for_test(backend_key, backend_cfg)
    except ValueError as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=400)

    # 发送最小推理请求，验证完整的请求→响应链路
    try:
        await backend.chat(
            system_prompt="",
            user_prompt="ping",
            model=backend_cfg.model_name,
            max_tokens=1,
        )
        return JSONResponse({"code": 0, "msg": f"后端 '{payload.backend}' 连接成功"})
    except RuntimeError as e:
        msg = str(e)[:300]
        return JSONResponse({"code": 1, "msg": f"连接失败: {msg}"}, status_code=502)
    except Exception as e:
        return JSONResponse({"code": 1, "msg": f"连接测试异常: {str(e)}"}, status_code=500)
    finally:
        await _close_backend(backend)


def _build_backend_for_test(backend_key: str, cfg):
    """为连通性测试构建后端实例（与 Orchestrator._init_backends() 逻辑一致）。"""
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
            auto_load=False,  # 测试时不触发自动加载
        )
    else:
        raise ValueError(f"不支持的后端: {backend_key}")


async def _close_backend(backend) -> None:
    """安全关闭后端连接。"""
    try:
        if hasattr(backend, "aclose"):
            await backend.aclose()
        elif hasattr(backend, "close"):
            backend.close()
    except Exception:
        pass


@app.post("/api/config/reset")
async def api_config_reset():
    """重置为默认配置 — 直接删除 config_user.json"""
    reset_config()
    return JSONResponse({"code": 0, "msg": "已恢复默认配置"})


# ============================================================================
# API: 数据库配置
# ============================================================================
class DatabaseConfigSave(BaseModel):
    host: str = "localhost"
    port: int = 3306
    user: str = "root"
    password: str = ""


@app.get("/api/config/database")
async def api_get_database_config():
    """获取数据库配置（预填当前值）"""
    config = get_config().to_dict()
    db = config.get("database", {})
    return JSONResponse({
        "code": 0,
        "data": {
            "host": db.get("host", "localhost"),
            "port": db.get("port", 3306),
            "user": db.get("user", "root"),
            "password": db.get("password", ""),
        }
    })


@app.post("/api/config/database")
async def api_save_database_config(payload: DatabaseConfigSave):
    """保存数据库配置"""
    config = get_config().to_dict()
    if "database" not in config:
        config["database"] = {}
    config["database"].update(payload.model_dump(exclude_none=True))
    save_config_dict(config)
    return JSONResponse({"code": 0, "msg": "数据库配置已保存，重启后生效"})

# ============================================================================
# API: 菜单/权限
# ============================================================================
@app.get("/api/menus")
async def api_menus():
    menus_file = _FRONTEND_ROOT / "api" / "menus.json"
    if menus_file.exists():
        return JSONResponse(json.loads(menus_file.read_text(encoding="utf-8")))
    return JSONResponse({"code": 0, "count": 0, "data": []})


# ============================================================================
# API: 员工管理（→ database.lists_manager）
# ============================================================================
@app.get("/api/employees")
async def api_employees(
    number: Optional[str] = None,
    ip: Optional[str] = None,
    department: Optional[str] = None,
    name: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(15, ge=1, le=200),
):
    """
    员工列表查询 — 通过 database 模块统一接口
    支持按字段过滤 + 分页
    """
    filters = {}
    if number:
        filters["number"] = number
    if ip:
        filters["ip"] = ip
    if department:
        filters["department"] = department
    if name:
        filters["name"] = name

    try:
        total, rows = _db("lists_manager", "get_employees", filters, page, limit)
        return JSONResponse({"code": 0, "count": total, "data": rows})
    except Exception as e:
        logger.error(f"查询员工列表失败: {e}")
        # 数据库不可用时从内存映射降级
        try:
            raw = _db("lists_manager", "get_ip_dept_map")
            data = []
            for ip_addr, (emp_name, dept) in raw.items():
                data.append(
                    {"number": "", "ip": ip_addr, "department": dept, "name": emp_name}
                )
            total = len(data)
            start = (page - 1) * limit
            end = start + limit
            paged = data[start:end]
            return JSONResponse({"code": 0, "count": total, "data": paged})
        except Exception:
            return JSONResponse({"code": 1, "msg": str(e), "count": 0, "data": []})


@app.post("/api/employees")
async def api_employee_create(emp: EmployeeCreate):
    """新增员工"""
    try:
        ok = _db("lists_manager", "add_employee",
                 emp.number, emp.ip, emp.department, emp.name)
        if ok:
            return JSONResponse({"code": 0, "msg": "添加成功"})
        return JSONResponse({"code": 1, "msg": "添加失败"}, status_code=500)
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


@app.put("/api/employees/{emp_id}")
async def api_employee_update(emp_id: int, emp: EmployeeUpdate):
    """编辑员工"""
    data = emp.model_dump(exclude_none=True)
    if not data:
        return JSONResponse({"code": 1, "msg": "无更新字段"}, status_code=400)
    try:
        ok = _db("lists_manager", "update_employee", emp_id, **data)
        if ok:
            return JSONResponse({"code": 0, "msg": "更新成功"})
        return JSONResponse({"code": 1, "msg": "更新失败"}, status_code=500)
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


@app.delete("/api/employees/{emp_id}")
async def api_employee_delete(emp_id: int):
    """删除员工"""
    try:
        ok = _db("lists_manager", "delete_employee", emp_id)
        if ok:
            return JSONResponse({"code": 0, "msg": "删除成功"})
        return JSONResponse({"code": 1, "msg": "删除失败"}, status_code=500)
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


# ============================================================================
# API: IP映射（→ database.lists_manager）
# ============================================================================
@app.get("/api/ip_map")
async def api_ip_map():
    """返回完整 IP-部门映射"""
    try:
        # 优先从数据库明细查询
        total, rows = _db("lists_manager", "get_employees", {}, 1, 10000)
        return JSONResponse({"code": 0, "data": rows})
    except Exception:
        try:
            raw = _db("lists_manager", "get_ip_dept_map")
            data = []
            for ip_addr, (emp_name, dept) in raw.items():
                data.append(
                    {
                        "id": 0,
                        "number": "",
                        "ip": ip_addr,
                        "department": dept,
                        "name": emp_name,
                    }
                )
            return JSONResponse({"code": 0, "data": data})
        except Exception as e:
            return JSONResponse({"code": 1, "msg": str(e), "data": []})


# ============================================================================
# API: 黑名单管理（→ database.lists_manager）
# ============================================================================
@app.get("/api/blacklist")
async def api_blacklist_get():
    """查询黑名单列表 — 通过 database 模块统一接口"""
    try:
        rows = _db("lists_manager", "get_blacklist_detailed")
        return JSONResponse({"code": 0, "count": len(rows), "data": rows})
    except Exception as e:
        logger.error(f"查询黑名单失败: {e}")
        # 降级：从内存集合返回
        try:
            bl = _db("lists_manager", "get_blacklist")
            data = [
                {
                    "id": i,
                    "ip_address": ip,
                    "threat_level": "高",
                    "reason": "系统自动",
                    "port": None,
                    "attack_type": None,
                }
                for i, ip in enumerate(sorted(bl))
            ]
            return JSONResponse({"code": 0, "count": len(data), "data": data})
        except Exception:
            return JSONResponse({"code": 0, "count": 0, "data": []})


@app.post("/api/blacklist")
async def api_blacklist_add(payload: BlacklistAdd):
    """加入黑名单 — DB 写入（由 add_ip.add_to_blacklist 统一完成，P4 尽力下发）"""
    target_ip = payload.ip

    try:
        from p4_controller.add_ip import add_to_blacklist as _p4_block
        _p4_block(target_ip, source="frontend", reason=payload.reason or "手动添加")
    except Exception as e:
        logger.error(f"拉黑异常: {e}")
        return JSONResponse({"code": 1, "msg": f"拉黑失败: {e}"}, status_code=500)

    return JSONResponse({"code": 0, "msg": f"已成功拉黑 {target_ip}"})


@app.delete("/api/blacklist/{item_id}")
async def api_blacklist_delete(item_id: int):
    """移除黑名单"""
    try:
        ok = _db("lists_manager", "remove_from_blacklist", item_id)
        if ok:
            return JSONResponse({"code": 0, "msg": "删除成功"})
        return JSONResponse({"code": 1, "msg": "删除失败"}, status_code=500)
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


# ============================================================================
# API: 白名单管理（→ database.lists_manager）
# ============================================================================
@app.get("/api/whitelist")
async def api_whitelist_get():
    """查询白名单列表 — 通过 database 模块统一接口"""
    try:
        rows = _db("lists_manager", "get_whitelist_detailed")
        return JSONResponse({"code": 0, "count": len(rows), "data": rows})
    except Exception as e:
        logger.error(f"查询白名单失败: {e}")
        try:
            wl = _db("lists_manager", "get_whitelist")
            data = [
                {
                    "id": i,
                    "ip_address": ip,
                    "reason": "",
                    "port": None,
                    "trust_level": "trust",
                }
                for i, ip in enumerate(sorted(wl))
            ]
            return JSONResponse({"code": 0, "count": len(data), "data": data})
        except Exception:
            return JSONResponse({"code": 0, "count": 0, "data": []})


@app.post("/api/whitelist")
async def api_whitelist_add(payload: WhitelistAdd):
    """加入白名单 — P4 流表 + 数据库写入（由 add_ip.add_to_whitelist 统一完成）"""
    target_ip = payload.ip

    try:
        from p4_controller.add_ip import add_to_whitelist as _p4_unblock
        if not _p4_unblock(target_ip, source="frontend", reason=payload.reason or "手动添加"):
            return JSONResponse({"code": 1, "msg": f"加白 {target_ip} 失败（P4 交换机可能未连接）"}, status_code=500)
    except Exception as e:
        logger.error(f"P4 解封异常: {e}")
        return JSONResponse({"code": 1, "msg": f"加白失败: {e}"}, status_code=500)

    return JSONResponse({"code": 0, "msg": f"已加白 {target_ip}"})


@app.delete("/api/whitelist/{item_id}")
async def api_whitelist_delete(item_id: int):
    """移除白名单"""
    try:
        ok = _db("lists_manager", "remove_from_whitelist", item_id)
        if ok:
            return JSONResponse({"code": 0, "msg": "删除成功"})
        return JSONResponse({"code": 1, "msg": "删除失败"}, status_code=500)
    except Exception as e:
        return JSONResponse({"code": 1, "msg": str(e)}, status_code=500)


# ============================================================================
# API: 流量/可疑事件管理（→ database.lists_manager）
# ============================================================================
@app.get("/api/traffic")
async def api_traffic_get():
    """获取可疑流量列表 — 通过 database 模块统一接口"""
    data = []
    try:
        rows = _db("lists_manager", "get_traffic_logs", 200, 0)
        for row in rows:
            if isinstance(row.get("packet_time"), datetime):
                row["packet_time"] = row["packet_time"].strftime("%Y-%m-%d %H:%M:%S")
            data.append(row)
    except Exception as e:
        logger.warning(f"查询 traffic_log 失败: {e}")

    # 如果没有数据库数据，从告警缓冲区填充
    if not data:
        with _alerts_lock:
            for alert in list(_alerts_buffer):
                data.append(
                    {
                        "id": alert.get("id"),
                        "src_ip": alert.get("ip"),
                        "dst_ip": "",
                        "src_port": "",
                        "dst_port": "",
                        "department": "",
                        "protocol": "",
                        "packet_time": alert.get("timestamp", ""),
                        "traffic_size": 0,
                        "is_blocked": 0,
                        "entropy": 0,
                    }
                )

    return JSONResponse({"code": 0, "data": {"data": data}})


@app.post("/api/traffic")
async def api_traffic_action(payload: TrafficAction):
    """处理可疑事件（忽视 / 拉黑）"""
    action = payload.event
    item_id = payload.id
    reason = payload.reason or "手动操作"

    logger.info(f"流量事件操作: action={action}, id={item_id}, reason={reason}")

    target_ip = None

    ai_verdict = "unknown"
    ai_confidence = 0.0
    if action == "拉黑" and item_id:
        # 找到该事件的源 IP 和 AI 判定信息
        try:
            rows = _db("lists_manager", "get_traffic_logs", 200, 0)
            for row in rows:
                if row.get("id") == item_id:
                    target_ip = row.get("src_ip")
                    ai_verdict = row.get("ai_verdict", "unknown") or "unknown"
                    break
        except Exception:
            pass

        if target_ip:
            # P4 硬件拉黑 + 数据库写入（由 add_ip.add_to_blacklist 统一完成）
            try:
                from p4_controller.add_ip import add_to_blacklist as _p4_block
                ok = _p4_block(target_ip, source="frontend", reason=reason)
                if not ok:
                    logger.warning(f"P4 拉黑 {target_ip} 返回失败（交换机可能未连接）")
            except Exception as e:
                logger.error(f"P4 硬件拉黑异常: {e}")

    # 更新流量记录的拦截状态
    if item_id:
        try:
            _db("lists_manager", "update_traffic_action", item_id, action)
        except Exception:
            pass

    # -- 写入多智能体记忆系统 (自适应 Tier 0) --
    _record_to_memory_from_admin(item_id, action, reason, target_ip,
                                 ai_verdict, ai_confidence)

    return JSONResponse({"code": 0, "msg": f"操作成功: {action}"})


# ============================================================================
# API: 告警管理
# ============================================================================
@app.get("/api/alerts")
async def api_alerts_get():
    """获取告警列表"""
    with _alerts_lock:
        return JSONResponse(
            {"code": 0, "count": len(_alerts_buffer), "data": list(_alerts_buffer)}
        )


@app.post("/api/alert")
async def api_alert_receive(payload: AlertData):
    """接收实时告警推送"""
    push_alert(payload.ip, payload.label, payload.details)
    return JSONResponse({"status": "ok"})


# ============================================================================
# API: 清理缓存
# ============================================================================
@app.post("/api/clear")
async def api_clear():
    """清理服务端缓存"""
    with _alerts_lock:
        _alerts_buffer.clear()
    return JSONResponse({"code": 1, "msg": "服务端清理缓存成功"})


# ============================================================================
# API: 健康检查
# ============================================================================
@app.get("/api/health")
async def api_health():
    return JSONResponse({"status": "ok", "version": "3.0.0"})


# ============================================================================
# API: 系统状态（CPU / RAM / 网络速率）
# ============================================================================
@app.get("/api/status")
async def api_status():
    """返回系统资源使用情况（非阻塞），供 welcome-1.html 仪表盘使用"""
    with _perf_lock:
        cpu = _perf_cache["cpu"]
        ram = _perf_cache["ram"]
        up_bytes = _perf_cache["up_bytes"]
        down_bytes = _perf_cache["down_bytes"]

    # 检查 psutil 是否可用（_perf_sampler 静默失败时 cache 全为 0）
    try:
        import psutil
        _psutil_ok = True
    except ImportError:
        _psutil_ok = False

    if not _psutil_ok:
        return JSONResponse(
            {
                "cpu": cpu,
                "ram": ram,
                "up": "不可用",
                "down": "不可用",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "note": "psutil 未安装，系统状态不可用",
            }
        )

    def fmt_bytes(b: float) -> str:
        if b >= 1073741824:
            return f"{b / 1073741824:.2f} GB/s"
        if b >= 1048576:
            return f"{b / 1048576:.2f} MB/s"
        if b >= 1024:
            return f"{b / 1024:.1f} KB/s"
        return f"{int(b)} B/s"

    return JSONResponse(
        {
            "cpu": cpu,
            "ram": ram,
            "up": fmt_bytes(up_bytes),
            "down": fmt_bytes(down_bytes),
            "up_bytes": up_bytes,
            "down_bytes": down_bytes,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    )


# ============================================================================
# 前端静态文件 + SPA fallback
# ============================================================================
_should_serve_static = False


@app.on_event("startup")
async def startup():
    global _should_serve_static
    if _FRONTEND_ROOT.exists() and (_FRONTEND_ROOT / "index.html").exists():
        _should_serve_static = True
        logger.info(f"✅ 前端静态文件目录已就绪: {_FRONTEND_ROOT}")
    else:
        _should_serve_static = False
        logger.warning(f"⚠️ 前端静态文件目录未找到: {_FRONTEND_ROOT}")


# 挂载静态资源目录
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
        return FileResponse(favicon_path)
    raise HTTPException(404)


@app.get("/")
@app.get("/index.html")
async def index_page():
    index_path = _FRONTEND_ROOT / "index.html"
    if index_path.exists():
        return HTMLResponse(index_path.read_text(encoding="utf-8"))
    raise HTTPException(404)


@app.get("/page/{filename:path}")
async def serve_page(filename: str):
    file_path = _FRONTEND_ROOT / "page" / filename
    if file_path.exists() and file_path.is_file():
        content_type = "text/html" if filename.endswith(".html") else None
        if content_type:
            return HTMLResponse(file_path.read_text(encoding="utf-8"))
        return FileResponse(file_path)
    raise HTTPException(404)


@app.get("/api/{filename:path}")
async def serve_api_file(filename: str):
    """为旧的直接 API 文件访问提供降级（如 init.json 等）"""
    file_path = _FRONTEND_ROOT / "api" / filename
    if file_path.exists() and file_path.is_file():
        if filename.endswith(".json"):
            return JSONResponse(json.loads(file_path.read_text(encoding="utf-8")))
        return FileResponse(file_path)
    raise HTTPException(404)


@app.get("/page/table/{filename:path}")
async def serve_table_page(filename: str):
    file_path = _FRONTEND_ROOT / "page" / "table" / filename
    if file_path.exists() and file_path.is_file():
        if filename.endswith(".html"):
            return HTMLResponse(file_path.read_text(encoding="utf-8"))
        return FileResponse(file_path)
    raise HTTPException(404)


# ============================================================================
# 启动函数（main.py 调用）
# ============================================================================
_server_instance = None


def start(host: str = "0.0.0.0", port: int = 8080, **kwargs):
    """
    启动 FastAPI 后端服务器（同步阻塞）。
    由 main.py 在独立线程或进程中调用。
    """
    import uvicorn

    global _server_instance

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
        **kwargs,
    )
    _server_instance = uvicorn.Server(config)
    _server_instance.run()


def _record_to_memory_from_admin(
    traffic_id: Optional[int], action: str, reason: str, target_ip: Optional[str],
    ai_verdict: str = "unknown", ai_confidence: float = 0.0,
) -> None:
    """将管理员操作写入多智能体记忆系统"""
    try:
        from multi_agent_system.memory import get_store

        # 推断 AI 是否正确（基于管理员动作）
        # 拉黑 → 管理员确认有异常；忽视 → 管理员认为是误报
        ai_correct = action == "拉黑"

        get_store().record_feedback(
            ai_verdict=ai_verdict,
            ai_confidence=ai_confidence,
            admins_action=action,
            ai_correct=ai_correct,
            admin_note=reason,
            src_ip=target_ip or "",
            traffic_id=traffic_id,
        )
    except Exception:
        pass  # 记忆系统不可用不影响 API 响应


def start_in_thread(host: str = "0.0.0.0", port: int = 8080):
    """在后台线程中启动 FastAPI"""
    t = threading.Thread(
        target=start,
        args=(host, port),
        kwargs={"log_config": None},
        daemon=True,
        name="UnifiedBackend",
    )
    t.start()
    return t


# ============================================================================
# 直接运行入口
# ============================================================================
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    logger.info(f"启动统一后端服务器 http://0.0.0.0:8080")
    logger.info(f"前端根目录: {_FRONTEND_ROOT}")
    start(host="0.0.0.0", port=8080)