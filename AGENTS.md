# AGENTS.md — 守藏 — 基于P4的异构多智能体反泄密平台

## Setup

```bash
# Virtual env (.venv/ already exists)
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# MySQL (required before first run)
# Default credentials in config/config_default.json under the "database" section
# Team members: set your own password in config_user.json under "database"."password"
mysql -u root -p -e "source database/create_database.sql"
```

No CI, no linter, no typechecker, no test framework in this repo. Don't try to run any.

## Start the system

```bash
python main.py                          # Full stack (all 4 layers + WebUI)
python main.py --dry-run                # Print config only, don't start
python main.py --no-llm                 # Skip AI agents (P4 + data-labeling + frontend only)
python main.py --no-live-scan           # Skip live-scan orchestrator
python main.py --no-p4                  # Skip P4 controller
python main.py --no-flow-data           # Skip UDP flow-data processor
python main.py --no-frontend            # Skip WebUI backend
python main.py --frontend-port 3000     # Change WebUI port (default 8080)
python main.py --update-geoip-now       # Force GeoIP DB update on startup
```

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
| Layer 3 | Data gateway | **9999** (UDP) | `data_gateway/data_bridge.py` (UDP + GeoIP + MySQL) |
| WebUI | Dashboard + REST API | **8080** (FastAPI) | `backend/api_server.py` (FastAPI + LayUI static) |

Supporting components (not numbered layers):
- **LiveScanOrchestrator** — `multi_agent_system/orchestrators/live_scan_orchestrator.py`: polls `traffic_log` for unanalyzed rows, feeds them through the 3-tier pipeline, persists verdicts. Dual-mode: timer-triggered (default 10min idle poll) + chain consumption (runs until queue is empty). Checkpoint persisted to `.live_scan_checkpoint.json`.
- **Batch writers** — `database/writer.py`: two `queue.Queue`-backed daemon threads for batch INSERT (traffic data) and batch UPDATE (verdict results). Configurable batch size and flush interval in `config/shared_config.py`.
- **Memory / pattern system** — `multi_agent_system/memory/`: pattern cards, clustering, evolution, and weekly extraction. Patterns feed into L1 Screening as prompt context. Data persisted under `memory/data/patterns/{active,retired,shadow}/`.

**Flask and FastAPI coexist** — not unified. Flask handles P4 control (:5000), FastAPI handles WebUI/REST (:8080).
**Frontend is pure static** (HTML/CSS/JS/LayUI) — FastAPI serves it from `frontend/`. No build step.
**`main.py` is the single entrypoint** — starts all layers, health check, GeoIP thread, and graceful shutdown in correct order.

### 3-Tier multi-agent pipeline (`multi_agent_system/orchestrator.py`)

- **L1 Screening** (`agents/screening_agent.py`) — Fast classification via LLM; `dangerous`→alert, `safe`→discard, `suspicious`→L2. Uses dual thresholds: `confidence_threshold_dangerous` (0.85) and `confidence_threshold_suspicious` (0.50).
- **L2 Backtrack** (`agents/backtrack_agent.py`) — Queries DB for similar historical records within lookback windows ([0.5h, 24h, 168h, 720h, 2160h]), LLM filters by relevance. New records accumulate across windows.
- **L3 Adjudication** (`agents/adjudication_agent.py`) — Final verdict with full historical context. `safe`→discard, `dangerous`→alert, `suspicious`→extend window (up to `max_backtrack_count`).
- **Feedback** (`agents/feedback_agent.py`) — Handles admin feedback, suggests rule/threshold adjustments.

### Cross-layer feedback loops
- **Multi-agent → P4**: Interception rules pushed to P4 switch flow tables
- **Multi-agent → WebUI**: High-severity alerts pushed to dashboard via `push_alert()`
- **WebUI → P4**: Blacklist/whitelist actions invoke `p4_controller.add_ip`
- **WebUI → Agents**: Config changes via dashboard write to `config_user.json`

## Configuration

Two-layer JSON merge: `config/config_default.json` ← overridden by `config/config_user.json`.

- **ALWAYS use `config/loader.py`** to read/write config. Sub-modules must never read JSON files directly.
- `config/schema.py` — dataclass definitions for all config objects (`BackendType`, `LLMBackendConfig`, `ScreeningAgentConfig`, `DatabaseConfig`, etc.)
- `config/active.py` — runtime singleton `set_active_config()` / `get_active_config()`, set by `main.py` on startup.
- `config/shared_config.py` — project root, batch write params, config file paths, GeoIP constants. DB credentials managed via config JSON files.
- `multi_agent_system/config.py` is a **compatibility redirect** to `config/schema.py` — new code should import directly from `config`.
- DeepSeek V4-specific settings: `thinking_enabled`, `reasoning_effort`, `include_reasoning` in the `deepseek` backend block.
- `config/config_user.json` is in `.gitignore` (contains API keys). The `config_default.json` is committed as the template.

## Database

- **MySQL is the sole data source.** All DB access must go through `database/` module interfaces.
- `database/connection.py` — `db_connect()` and `db_cursor()` context manager (always `DictCursor`). DB password comes from `config.shared_config.DB_CONFIG["password"]`, injected by `main.py` at startup (reading from `config_user.json` → `database.password`). Team members set their own password in `config_user.json` under `"database"."password"`.
- `database/lists_manager.py` — blacklist/whitelist/IP-dept-map CRUD, memory-cached with `threading.RLock()`, auto-refreshes on write.
- `database/writer.py` — two batch writers using `queue.Queue` (max 10000 items each):
  - `start_db_writer()` → `_store_batch()`: batch INSERT into `traffic_log`
  - `start_verdict_writer()` → `_update_verdict_batch()`: batch UPDATE `ai_analyzed`/`ai_verdict` on `traffic_log`
- The backend (`api_server.py`) uses `importlib.import_module(f"database.{module_name}")` for dynamic DB calls — don't break this pattern.

## Key source files

| Path | Role |
|---|---|
| `main.py` | Single entrypoint — starts all layers, health check, signal handlers |
| `config/loader.py` | Config reading/writing/validation — `load_config()`, `save_config_dict()`, `reset_user_config()` |
| `config/schema.py` | Dataclass config models — `OrchestratorConfig`, agent configs, `BackendType`, `DatabaseConfig` |
| `config/shared_config.py` | System-level constants — project root, paths, batch params, GeoIP constants |
| `multi_agent_system/orchestrator.py` | Core 3-tier pipeline — `Orchestrator.analyze_flow()` |
| `multi_agent_system/orchestrators/live_scan_orchestrator.py` | Background scanner — polls DB, feeds pipeline |
| `multi_agent_system/core/agent.py` | `BaseAgent` — `call_llm()`, `extract_json_from_response()`, `call_llm_sync()` |
| `multi_agent_system/core/message.py` | Data types — `FlowEvent`, `ThreatVerdict`, `TrafficVerdict`, `SeverityLevel` |
| `backend/api_server.py` | FastAPI app — REST endpoints, static serving, alert buffer, perf sampler |
| `data_gateway/data_bridge.py` | UDP :9999 listener, P4 hex parser, GeoIP enrichment, queue→DB |
| `database/lists_manager.py` | Memory-cached blacklist/whitelist/IP-dept CRUD |
| `database/writer.py` | Batch INSERT/UPDATE writer threads |
| `p4_controller/control.py` | Flask app + pynng listener + Thrift telemetry |
| `p4_controller/add_ip.py` | SSH-based P4 flow table injection |
| `p4_controller/analyzer.py` | P4 feature extraction / rule matching |
| `p4_controller/data_packer.py` | P4 register data packing / merged flow tables |

## Coding conventions

- **Imports**: `p4_controller/` modules use `try: from . import` for dual-mode (package vs standalone). Expect `ImportError` fallbacks.
- **Database access**: Always through `database/` module — never raw `pymysql` calls elsewhere. Use `db_cursor()` context manager.
- **Config access**: Always through `config/loader.py` or `config/active.py` — never read JSON directly.
- **Thread safety**: `threading.RLock()` for memory caches, `threading.Event()` for shutdown signals, `queue.Queue` for producer-consumer.
- **Graceful shutdown**: All layers use `threading.Event` (`shutdown_requested`) + signal handlers. Main loop waits on the event with timeout.
- **Logging**: Module-level `logging.getLogger(__name__)` throughout. `main.py` configures `logging.basicConfig()` once at startup.
- **Naming**: `_` prefix for module-internal functions/variables. `_global_state` dict in `main.py` holds all runtime component references.
- **Error handling**: LLM call failures → fallback verdict (usually `suspicious`). DB errors → log warning, return empty/False. Import errors in optional deps → degrade gracefully (e.g. `maxminddb`).
- **Async/sync**: Core pipeline is async (`analyze_flow()`). `analyze_flow_sync()` wrapper uses `asyncio.run()` when no event loop is running.

## Key constraints

- **Don't hardcode LLM prompts or API keys** — they live in `config/config_default.json` under each agent's `system_prompt` field.
- **GeoIP** (`GeoLite2-City.mmdb`) auto-updates from CDN every 168h. The `maxminddb` package is optional — modules degrade gracefully if absent.
- **Windows-specific**: `main.py` calls `ctypes.windll.kernel32.SetConsoleMode` for ANSI color support. This is safe to leave as-is.
- **Flask + FastAPI coexistence**: Both run in daemon threads, not unified. Flask serves :5000 (P4 control), FastAPI serves :8080 (WebUI).
- **No build/bundle step**: Frontend is pure static files served directly. The `frontend/lib/` directory contains vendored LayUI, jQuery, Font Awesome, and ECharts.

## Git workflow

- Branch: `main` (trunk-based)
- Merge commits are the norm (no squash-only policy observed)
- Remote: `git@github.com:OranPhoenix/Shoucang.git`
- Feature branches merged via PR (`OranPhoenix-优化系统策略`, `suifeng`)

## Tips for AI agents

- **Startup order matters in `main.py`**: DB lists load first, then verdict writer, then backend, then P4 controller, then multi-agent system (async), then data gateway, then GeoIP thread, then health check loop. The multi-agent system depends on the backend being up for alert callbacks.
- **Config changes require restart**: There's no hot-reload. The frontend writes to `config_user.json`, which takes effect on next `main.py` launch.
- **Testing individual layers**: Use the `--no-*` flags to isolate. `--no-llm --no-live-scan --no-p4 --no-flow-data` leaves just the FastAPI frontend.
- **LLM backend selection**: Each agent can use a different backend. If an agent's specified backend lacks an API key, the orchestrator falls back to the first available backend.
- **The `database/` module is the only DB interface**: If you need a new query, add it to `lists_manager.py` or `writer.py`, and expose it via `database/__init__.py`. The backend uses `importlib` to call these dynamically.
- **P4 controller import fragility**: The `try: from . import` pattern in `p4_controller/control.py` is intentional for standalone testing. Don't "fix" it to absolute imports.
- **Memory pattern data**: `multi_agent_system/memory/data/` contains runtime artifacts (SQLite WAL files for feedback, JSON patterns). These are gitignored — don't commit them.
- **`crash.txt`**: Present in repo root — likely a crash dump artifact. Don't modify or delete without asking.
