# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Quick reference

`AGENTS.md` is the canonical source for setup, startup commands, and the 4-layer architecture diagram. Read it first. This file covers architectural details that `AGENTS.md` does not.

## Multi-agent analysis pipeline (慢脑 / slow brain)

The core data flow for the multi-agent system is a fixed 5-stage pipeline in `multi_agent_system/orchestrator.py:Orchestrator.analyze_flow()`:

```
FlowEvent → [1] DetectionAgent → [2] CorrelationAgent → [3] JudgmentAgent → [4] Rule auto-generation → [5] FeedbackAgent
```

- **Stage 1 (Detection)** runs always. Returns `TrafficVerdict.SAFE` / `SUSPICIOUS` / `MALICIOUS`. SAFE short-circuits the pipeline — no further stages.
- **Stage 2 (Correlation)** only triggers for SUSPICIOUS/MALICIOUS. Uses a time-windowed buffer (`correlation_window_minutes`), only processes a group when `min_records_to_correlate` is exceeded.
- **Stage 3 (Judgment)** takes both detection and correlation results, produces the final `ThreatVerdict`.
- **Stage 4** auto-generates a blacklist `RuleEntry` if confidence ≥ `knowledge_base.confidence_threshold_block` and verdict is MALICIOUS.
- **Stage 5 (Feedback)** records the verdict for admin review.

Each agent gets its **own** backend, model, and system prompt — heterogeneous by design. The orchestrator `_init_agents()` maps each agent to its configured `BackendType` and provides graceful degradation if the specified backend is unavailable.

## Backend abstraction

Three backend implementations in `multi_agent_system/backends/`:

| File | Backend | Notes |
|---|---|---|
| `openai_backend.py` | `OpenAIBackend` | Generic OpenAI-compatible API (GPT-4o, etc.) |
| `lmstudio_backend.py` | `LMStudioBackend` | Local LM Studio; adds model load/unload/list management API on a separate `/api/v1/models` endpoint. Supports `auto_load` (load model on first call if not ready). |
| `deepseek_backend.py` | `DeepSeekBackend` | Extends OpenAI; adds `thinking_enabled`, `reasoning_effort`, `include_reasoning` headers. Longer timeout defaults (120s vs 60s). |

All backends extend `BaseLLMBackend` from `backends/base.py`. The `Orchestrator._init_backends()` creates them from typed `LLMBackendConfig` objects. If an `api_key` is empty for cloud backends (OpenAI/DeepSeek), that backend is skipped with a warning.

## Config architecture

Two-layer JSON merge in `config/loader.py`:

```
config/config_default.json  (canonical, all fields)
    ↓ deep-merged with
config/config_user.json     (override only fields that differ)
    ↓
OrchestratorConfig          (typed dataclass, used by all agents)
```

Key design rules:
- `config_default.json` is the reference — every field must exist here. `config_user.json` only needs overrides.
- Keys starting with `_` in user config are metadata/comments that do NOT merge.
- `config/schema.py` defines all dataclass types. `BackendType` is a `StrEnum` with `OPENAI`, `LMSTUDIO`, `DEEPSEEK`.
- `multi_agent_system/config.py` is a **compatibility redirect** to `config/schema.py`. New code must import from `config` directly.
- `config/loader.py` provides both typed (`load_config()` → `OrchestratorConfig`) and dict-level (`load_config_dict()`) access. The dict path exists for `backend/api_server.py` which serves config to the frontend without needing dataclass types.
- Convenience builders: `quick_all_local()` and `quick_all_deepseek()` for single-backend setups.

`config/shared_config.py` holds environment-level constants (DB credentials, project root, batch write params). These are plain module-level values, not JSON-managed.

## Threading and async model

The system uses a **mixed threading + asyncio** model:

- `main.py` runs an asyncio event loop (`asyncio.run(async_main)`). All layer startup is async.
- **Flask** (P4 controller, port 5000) runs in a daemon thread — Flask is synchronous/blocking.
- **FastAPI** (WebUI, port 8080) runs in a daemon thread via `uvicorn`. `backend/api_server.py` uses `start_in_thread()` which runs the uvicorn server in a thread.
- **UDP listener** (ColdTableProcessor, port 9999) runs in a daemon thread with blocking `socket.recvfrom()`.
- **Multi-agent system** runs async inside the main event loop. `Orchestrator` is async-first but provides `*_sync()` wrappers that handle event-loop creation for sync callers.
- **Slow brain** background loop is an `asyncio.Task` created in the main loop.
- Graceful shutdown uses a `threading.Event` (`shutdown_requested`) that all components check.

When adding new components, follow this pattern: long-running I/O that doesn't need async → daemon thread. LLM calls and agent orchestration → async in the main loop.

## P4 controller module organization

`p4_controller/` uses a **dual-mode import pattern** — it can run as a package (`python -m p4_controller.control`) or standalone:

```python
try:
    from . import data_packer  # package mode
except ImportError:
    import data_packer         # standalone mode
```

The controller has a 100-second telemetry timer (`p4_controller/timer.py`) that SSH-pulls P4 switch registers and resets them. In `main.py`, the timer is patched via `_patch_control_timer()` because the callback is not bound at import time.

`p4_controller/add_ip.py` is the single entry point for IP-level blacklist/whitelist operations — both the Flask API and the WebUI backend call into it.

## Database module contract

`database/` is the **sole database access layer**. No other module may open a MySQL connection directly.

- `database/writer.py` — batch writer using `queue.Queue`. Other modules call `store_packet(row_dict)` and the writer thread flushes batches at `DB_WRITE_BATCH_SIZE` or `DB_WRITE_FLUSH_INTERVAL` seconds.
- `database/lists_manager.py` — in-memory cached blacklist/whitelist/IP-dept-map with thread-safe read via `threading.Lock`. Cache is loaded once at startup (`load_lists_from_db()`) and must be manually refreshed after writes (`reload_lists_after_change()`).
- `database/__init__.py` re-exports everything — other modules import from `database`, never from sub-modules directly.
- `backend/api_server.py` uses dynamic imports for DB calls: `importlib.import_module(f"database.{module_name}")` — do not break this pattern.

## Frontend architecture

Frontend is pure static HTML/CSS/JS served by FastAPI from `frontend/`. Uses LayUI as the UI framework. No build step, no bundler.

- `frontend/index.html` — main entry page
- `frontend/page/*.html` — individual pages (blacklist, whitelist, settings, traffic table, dashboard, etc.)
- `frontend/api/*.json` — mock API responses for local frontend development (init, menus, table data, etc.)
- Frontend expects JSON API from `/api/*` endpoints defined in `backend/api_server.py`
- All dynamic data flows through REST calls to the FastAPI backend — the frontend never reads config files or connects to the database directly

## GeoIP module

`GeoLite2-City.mmdb` is stored in `data_labeling/`. Auto-updates every 168h (7 days) from jsDelivr CDN. `update_geoip_db()` downloads a gzipped copy and decompresses it. The `maxminddb` package is optional — the cold table processor degrades gracefully if it's not installed.

## P4 program

`p4_program/data_platform.txt` contains the P4 program source that runs on the BMv2 switch. It defines IPv4/TCP/UDP header parsing and custom metadata extraction (entropy, packet sizes, flow features). This is compiled separately (outside this repo's toolchain) and loaded onto the P4 switch. The Python controller communicates with the switch via pynng (IPC) and Thrift (management plane).
