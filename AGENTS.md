# AGENTS.md — 守藏 — 基于P4的异构多智能体反泄密平台

## Setup

```bash
# Virtual env (.venv/ already exists)
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# MySQL (required before first run)
# credentials: root / 0918 @ localhost:3306 → insider_threat_db
mysql -u root -p -e "source database/create_database.sql"
```

No CI, no linter, no typechecker, no test framework in this repo. Don't try to run any.

## Start the system

```bash
python main.py                          # Full stack (all 4 layers + WebUI)
python main.py --dry-run                # Print config only, don't start
python main.py --no-llm                 # Skip AI agents (P4 + data-labeling + frontend only)
python main.py --no-slow-brain          # Skip slow-brain layer only
python main.py --no-live-scan           # Skip live-scan orchestrator
python main.py --no-p4                  # Skip P4 controller
python main.py --no-flow-data          # Skip UDP flow-data processor
python main.py --no-frontend            # Skip WebUI backend
python main.py --frontend-port 3000     # Change WebUI port (default 8080)
python main.py --update-geoip-now       # Force GeoIP DB update on startup
```

## Architecture (4-layer system)

| Layer | What | Port | Tech |
|---|---|---|---|
| Layer 1 | P4 hardware controller | **5000** (Flask) | Flask + pynng + Thrift |
| Layer 2 | Multi-agent system (slow brain) | internal | LLM orchestration + live scan + deep analysis |
| Layer 3 | Data labeling (flow-data) | **9999** (UDP) | FlowProcessor + GeoIP + MySQL batching |
| Layer 4 | WebUI + config management | **8080** (FastAPI) | FastAPI + LayUI (static frontend) |

Supporting components (not numbered layers):
- **FlowProcessor** — UDP :9999 listener, GeoIP enrichment, batch writes to MySQL
- **KnowledgeBase** — in-memory rule engine (`multi_agent_system/core/knowledge.py`), thread-safe blacklist/whitelist/greylist with TTL auto-cleanup

**Flask and FastAPI coexist** — not unified. Flask handles P4 control (:5000), FastAPI handles WebUI/REST (:8080).
**Frontend is pure static** (HTML/CSS/JS/LayUI) — FastAPI serves it from `frontend/`. No build step.
**`main.py` is the single entrypoint** — starts all layers, health check, and GeoIP thread in correct order.

### Cross-layer feedback
- **Multi-agent system → P4**: Interception rules pushed to P4 switch flow tables
- **Multi-agent system → WebUI**: High-severity alerts pushed to dashboard
- **WebUI → P4**: Blacklist/whitelist actions from the dashboard directly invoke `p4_controller.add_ip`
- **WebUI → Agents**: Config changes via dashboard write to `config_user.json`, affecting all agents on reload

## Configuration

Two-layer JSON merge: `config/config_default.json` → overridden by `config/config_user.json`.

- **ALWAYS use `config/loader.py`** to read/write config. Sub-modules must never read JSON files directly.
- `config/shared_config.py` holds DB credentials, project root, batch write params, and config file paths.
- `multi_agent_system/config.py` is a **compatibility redirect** to `config/schema.py` — new code should import directly from `config`.
- DeepSeek V4-specific settings: `thinking_enabled`, `reasoning_effort`, `include_reasoning` in the `deepseek` backend block.

## Database

- **MySQL is the sole data source.** All DB access must go through `database/` module interfaces.
- `database/lists_manager.py` — blacklist/whitelist/IP-dept-map CRUD (memory-cached, thread-safe)
- `database/writer.py` — batch writer with `queue.Queue` (zero-copy dict pass)
- The backend (`api_server.py`) uses `importlib.import_module(f"database.{module_name}")` for dynamic DB calls — don't break this pattern.

## Key constraints

- **Don't hardcode LLM prompts or API keys** — they live in `config/config_default.json` under each agent's `system_prompt` field.
- **P4 controller modules** use `try: from . import` for dual-mode import (package vs standalone). Expect ImportError fallbacks.
- **GeoIP** (`GeoLite2-City.mmdb`) auto-updates from `cdn.jsdelivr.net` every 168h. The `maxminddb` package is optional — modules degrade gracefully if absent.
- **Windows-specific**: `main.py` calls `ctypes.windll.kernel32.SetConsoleMode` for ANSI color support. This is safe to leave as-is.
