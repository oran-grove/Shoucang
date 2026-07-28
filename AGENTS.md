# AGENTS.md — 守藏 — 基于P4的异构多智能体反泄密平台

## Setup

```bash
# uv（推荐）
uv sync
uv run python main.py

# pip（备选）
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# MySQL（首次运行前必须执行）
# 默认连接参数见 config/config_default.json 的 "database" 节
# 团队成员在 config_user.json 的 "database"."password" 中设置自己的密码
mysql -u root -p -e "source database/create_database.sql"
```

No CI, no linter, no typechecker, no test framework in this repo. Don't try to run any.

## Start the system

```bash
python main.py                          # 全量启动（四层 + WebUI）
python main.py --dry-run                # 仅打印配置，不实际启动
python main.py --no-llm                 # 跳过 AI 智能体（仅 P4 + 数据网关 + 前端）
python main.py --no-live-scan           # 跳过逐条分析扫描
python main.py --no-p4                  # 跳过 P4 控制器
python main.py --no-data-gateway        # 跳过数据网关（UDP :9999 + MySQL 写入）
python main.py --no-frontend            # 跳过 WebUI 后端
python main.py --frontend-port 3000     # 修改 WebUI 端口（默认 8080）
python main.py --update-geoip-now       # 启动时强制更新 GeoIP 数据库
```

## WebUI 鉴权

首次启动自动生成 `jwt_secret` 和默认管理员密码，输出到控制台：

```
用户名: admin
密码:   admin123（首次启动默认密码，请尽快修改）
```

**鉴权架构：**
- **密码哈希**：stdlib `hashlib.scrypt`（N=16384, r=8, p=1），自动加盐，存储格式 `hexhash:hexsalt`。
- **Token**：JWT HS256，签发时写入 `httponly` + `samesite=lax` Cookie，前端 JavaScript 不可读。
- **HTTP 中间件**：白名单路径放行（`/api/auth/login`、`/api/alert`、`/api/health`、`/api/status`、静态资源前缀、`/api/*.json`），其余 `/api/*` 路由验证 Cookie 中的 JWT。无 Token 返回 401 `"未登录"`，过期返回 401 `"登录已过期"`。
- **账户管理**：WebUI 右上角「管理员 → 账户管理」可修改用户名、密码和登录有效期。对应 API：`POST /api/auth/update-account`。
- **登录 API**：`POST /api/auth/login`（公开）。Token 不在响应 body 中返回给前端，仅通过 Set-Cookie 传输。
- **忘记密码**：删除 `config_user.json` 中 `webui_auth.admin_password_hash`，重启后密码重置为 `admin123`。

相关代码：`backend/api_server.py` 第 95-197 行（`_hash_password`、`_verify_password`、`_create_token`、`_verify_token`、`_auth_middleware`、`_ensure_auth_config`）。

## Architecture (4-layer system)

```
main.py ── single entrypoint, starts all layers + health check + GeoIP thread
  ├── Layer 1: P4 hardware controller     → Flask :5000
  ├── Layer 2: Multi-agent system         → internal (async LLM pipeline)
  ├── Layer 3: Data gateway               → UDP :9999
  └── WebUI backend                       → FastAPI :8080
```

| Layer | What | Port | Key modules |
|---|---|---|---|
| Layer 1 | P4 hardware controller | **5000** (Flask) | `p4_controller/control.py` (Flask + pynng + Thrift) |
| Layer 2 | Multi-agent system | internal | `multi_agent_system/orchestrator.py` (3-tier LLM) |
| Layer 3 | Data gateway | **9999** (UDP) | `data_gateway/data_bridge.py` (dual-buffer + GeoIP + MySQL) |
| WebUI | Dashboard + REST API + Auth | **8080** (FastAPI) | `backend/api_server.py` (FastAPI + JWT + LayUI static) |

Supporting components (not numbered layers):
- **LiveScanOrchestrator** — `multi_agent_system/orchestrators/live_scan_orchestrator.py`: polls `traffic_log` for unanalyzed rows, feeds them through the 3-tier pipeline, persists verdicts. Dual-mode: timer-triggered (default 10min idle poll) + chain consumption (runs until queue is empty). Checkpoint persisted to `.live_scan_checkpoint.json`.
- **Batch writers** — `database/writer.py`: three `queue.Queue`-backed daemon threads for batch INSERT (traffic data), batch UPDATE (verdict results), and batch DELETE (safe traffic cleanup). Configurable batch size and flush interval in `config/shared_config.py`.
- **Memory / pattern system** — `multi_agent_system/memory/`: pattern cards, clustering, evolution, and weekly extraction. Patterns feed into L1 Screening as prompt context. Data persisted under `memory/data/` (SQLite `feedback.db` + JSON pattern cards in `active/`, `retired/`, `shadow/`).

**Flask and FastAPI coexist** — not unified. Flask handles P4 control (:5000), FastAPI handles WebUI/REST + JWT auth (:8080).
**Frontend is pure static** (HTML/CSS/JS/LayUI) — FastAPI serves it from `frontend/`. No build step.
**`main.py` is the single entrypoint** — starts all layers, health check, GeoIP thread, and graceful shutdown in correct order.

### 3-Tier multi-agent pipeline (`multi_agent_system/orchestrator.py`)

- **L1 Screening** (`agents/screening_agent.py`) — Fast classification via LLM; `dangerous`→alert, `safe`→discard, `suspicious`→L2. Uses dual thresholds: `confidence_threshold_dangerous` (0.85) and `confidence_threshold_suspicious` (0.50). Injects pattern context from memory system. Retries up to 3 times on parse failure.
- **L2 Backtrack** (`agents/backtrack_agent.py`) — Queries DB for similar historical records within lookback windows ([0.5h, 24h, 168h, 720h, 2160h]), LLM filters by relevance via auto-numbered reverse selection. New records accumulate across windows.
- **L3 Adjudication** (`agents/adjudication_agent.py`) — Final verdict with full historical context. `safe`→discard, `dangerous`→alert, `suspicious`→extend window and loop back to L2. Severity levels: critical/high/medium/low/info.
- **Feedback** (`agents/feedback_agent.py`) — Handles admin feedback, suggests rule/threshold adjustments, learns patterns from confirmed cases.

### Cross-layer feedback loops
- **Multi-agent → P4**: Interception rules pushed to P4 switch flow tables
- **Multi-agent → WebUI**: High-severity alerts pushed to dashboard via `push_alert()`
- **WebUI → P4**: Blacklist/whitelist actions invoke `p4_controller.add_ip`
- **WebUI → Agents**: Config changes via dashboard write to `config_user.json`

## Configuration

Two-layer JSON merge: `config/config_default.json` ← overridden by `config/config_user.json`. Config is cached in memory as typed dataclass structs via `config/store.py:ConfigStore`.

- **Use `config` module functions exclusively** to read/write config. Sub-modules must never read JSON files directly.
- `get_config(*sections)` — request specific config structs. `get_config()` returns `FullConfig` (with `.to_dict()` for JSON serialization — this is the single serialization path, also used by `ConfigStore.save()`).
- `save_config(**structs)` — save typed structs. `save_config_dict(updates)` for WebUI partial updates.
- `reset_config()` — delete user config, reload defaults.
- `config/schema.py` — dataclass structs: `DatabaseConfig`, `BackendsConfig`, `LLMBackendConfig`, `ScreeningAgentConfig`, `BacktrackAgentConfig`, `AdjudicationAgentConfig`, `FeedbackAgentConfig`, `LiveScanConfig`, `GeoipConfig`, `WebuiAuthConfig`, `FullConfig`. `FullConfig.to_dict()` is the canonical serialization.
- `config/store.py` — ConfigStore singleton + public API functions. Save path delegates to `self.get().to_dict()`.
- `config/loader.py` — internal helpers only (`_deep_merge`, `_compute_delta`, `_validate`, `_coerce_types`). Not imported by other modules.
- `config/shared_config.py` — system constants (project root, batch write params, GeoIP paths, config file paths).
- `config/config_user.json` is in `.gitignore` (contains API keys and password hash). The `config_default.json` is committed as the template.

## Database

- **MySQL is the sole data source.** All DB access must go through `database/` module interfaces.
- `database/connection.py` — `db_connect()` and `db_cursor()` context manager (always `DictCursor`). Connection params obtained via `get_config("database")` → `DatabaseConfig`. Team members set their password in `config_user.json` under `"database"."password"`.
- `database/lists_manager.py` — blacklist/whitelist/IP-dept-map CRUD, memory-cached with `threading.RLock()`, auto-refreshes on write. Also handles employee CRUD, traffic log queries, and multi-agent specific queries (`get_unanalyzed_traffic`, `get_similar_flows_by_src_ip`).
- `database/writer.py` — three batch writers using `queue.Queue` (max 10000 items each):
  - `start_db_writer()` → `_store_batch()`: batch INSERT into `traffic_log`
  - `start_verdict_writer()` → `_update_verdict_batch()`: batch UPDATE `ai_analyzed`/`ai_verdict` on `traffic_log`
  - `start_deletion_writer()` → `_delete_safe_batch()`: batch DELETE safe traffic from `traffic_log`
- The backend (`api_server.py`) imports from `database.lists_manager` directly (explicit imports at module top, no dynamic dispatch).

## Key source files

| Path | Role |
|---|---|
| `main.py` | Single entrypoint — starts all layers, health check, signal handlers |
| `config/store.py` | ConfigStore singleton — `get_config()`, `save_config()`, `save_config_dict()`, `reset_config()` |
| `config/schema.py` | Dataclass structs — `FullConfig` (with canonical `.to_dict()`), `DatabaseConfig`, `BackendsConfig`, agent configs, `BackendType`, `WebuiAuthConfig` |
| `config/loader.py` | Internal helpers only — `_deep_merge`, `_compute_delta`, `_validate`, `_coerce_types` |
| `config/shared_config.py` | System-level constants — project root, config file paths, batch params, GeoIP constants |
| `multi_agent_system/orchestrator.py` | Core 3-tier pipeline — `Orchestrator.analyze_flow()` |
| `multi_agent_system/orchestrators/live_scan_orchestrator.py` | Background scanner — polls DB, feeds pipeline, persists verdicts |
| `multi_agent_system/core/agent.py` | `BaseAgent` — `call_llm()`, `extract_json_from_response()` (3-stage: json → json5 → nested-quote repair) |
| `multi_agent_system/core/message.py` | Data types — `FlowEvent`, `ThreatVerdict`, `TrafficVerdict`, `SeverityLevel`, utility functions `fmt_window()`, `get_pattern_context()` |
| `backend/api_server.py` | FastAPI app — REST endpoints, JWT auth middleware, static serving, alert buffer, perf sampler |
| `data_gateway/data_bridge.py` | Dual-buffer event-driven listener, P4 hex parser, GeoIP enrichment, queue→DB |
| `database/lists_manager.py` | Memory-cached blacklist/whitelist/IP-dept/employee CRUD + traffic queries |
| `database/writer.py` | Batch INSERT/UPDATE/DELETE writer threads |
| `p4_controller/control.py` | Flask app + pynng listener + Thrift telemetry |
| `p4_controller/add_ip.py` | Thrift-based P4 flow table injection (direct BMv2 RPC) |
| `p4_controller/analyzer.py` | 21-dimension feature analysis + threat scoring engine |
| `p4_controller/data_packer.py` | P4 register data packing / dual-buffer cold-hot pool swap |

## Coding conventions

- **Imports**: `p4_controller/` modules use `try: from . import` for dual-mode (package vs standalone). Expect `ImportError` fallbacks.
- **Database access**: Always through `database/` module — never raw `pymysql` calls elsewhere. Use `db_cursor()` context manager.
- **Config access**: Always through `config` module (`get_config`, `save_config`) — never read JSON directly.
- **Thread safety**: `threading.RLock()` for memory caches, `threading.Event()` for shutdown signals, `queue.Queue` for producer-consumer.
- **Graceful shutdown**: All layers use `threading.Event` (`shutdown_requested`) + signal handlers. Main loop waits on the event with timeout.
- **Logging**: Module-level `logging.getLogger(__name__)` throughout. `main.py` configures `logging.basicConfig()` once at startup.
- **Naming**: `_` prefix for module-internal functions/variables. `_global_state` dict in `main.py` holds all runtime component references.
- **Error handling**: LLM call failures → raise `RuntimeError` (caught by LiveScanOrchestrator, record kept for next poll cycle). DB errors → log warning, return empty/False. Import errors in optional deps → degrade gracefully (e.g. `maxminddb`).
- **Async/sync**: Core pipeline is async (`analyze_flow()`). All real callers use `await`. No sync wrapper methods exist.

## Key constraints

- **Don't hardcode LLM prompts or API keys** — they live in `config/config_default.json` under each agent's `system_prompt` field.
- **GeoIP** (`GeoLite2-City.mmdb`) auto-updates from CDN every 168h. The `maxminddb` package is optional — modules degrade gracefully if absent.
- **Windows-specific**: `main.py` calls `ctypes.windll.kernel32.SetConsoleMode` for ANSI color support. This is safe to leave as-is.
- **Flask + FastAPI coexistence**: Both run in daemon threads, not unified. Flask serves :5000 (P4 control), FastAPI serves :8080 (WebUI + JWT auth).
- **No build/bundle step**: Frontend is pure static files served directly. The `frontend/lib/` directory contains vendored LayUI 2.6.3, jQuery 3.4.1, Font Awesome 4.7.
- **Frontend auth guard**: `index.html` checks `localStorage.loggedIn` and redirects to `page/login.html` if missing. The real security is the JWT Cookie middleware — all `/api/*` routes are protected unless explicitly whitelisted.
- **P4 controller is Thrift-based** (not SSH). `add_ip.py` uses Apache Thrift RPC on `127.0.0.1:9100` to inject flow table rules into BMv2 directly.

## Git workflow

- Branch: `main` (trunk-based)
- Merge commits are the norm (no squash-only policy observed)
- Remote: `git@github.com:OranPhoenix/Shoucang.git`

## Tips for AI agents

- **Startup order matters in `main.py`**: Config loads first (via `get_config()`), then DB lists, then verdict writer + deletion writer, then backend, then data gateway, then P4 controller, then multi-agent system (async), then health check thread, then GeoIP thread, then evolution loop. Config MUST be loaded before any database imports because `db_connect()` calls `get_config("database")`.
- **Auth is auto-provisioned on first run**: `_ensure_auth_config()` generates `jwt_secret` and default password hash if empty, persists to `config_user.json`. Both fields are committed as empty strings in `config_default.json`.
- **Config changes require restart**: `save_config()` / `save_config_dict()` write to `config_user.json` and refresh the in-memory cache, but running components (orchestrator, agents) won't pick up changes until next `main.py` launch. Exception: `webui_auth` changes take effect immediately for new login sessions.
- **Testing individual layers**: Use the `--no-*` flags to isolate. `--no-llm --no-live-scan --no-p4 --no-data-gateway` leaves just the FastAPI frontend.
- **LLM backend selection**: Each agent can use a different backend (configured via `backend` string field: `"deepseek"`, `"openai"`, `"lmstudio"`). If an agent's specified backend lacks an API key, the orchestrator falls back to the first available backend.
- **The `database/` module is the only DB interface**: If you need a new query, add it to `lists_manager.py` or `writer.py`, and expose it via `database/__init__.py`. The backend imports functions directly — no dynamic dispatch.
- **P4 controller import fragility**: The `try: from . import` pattern in `p4_controller/control.py` is intentional for standalone testing. Don't "fix" it to absolute imports.
- **Memory pattern data**: `multi_agent_system/memory/data/` contains runtime artifacts (SQLite `feedback.db`, JSON pattern cards in `active/`, `retired/`, `shadow/`). These are gitignored — don't commit them.
- **Shared utility functions**: `fmt_window()` and `get_pattern_context()` live in `core/message.py` and are reused by multiple agents and the orchestrator. Don't duplicate these.
- **Config serialization**: `FullConfig.to_dict()` in `schema.py` is the single canonical serialization path. Both `api_server.py` (API response) and `ConfigStore.save()` (file persistence) use it. Don't add a second serialization function.
