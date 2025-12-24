# Repository Guidelines

## Project Structure & Module Organization
- **acs_manager/**: Core code. Subpackages: `container/` (ACS API client, IP discovery), `management/` (lifecycle + SSH tunnels), `webui/` (FastAPI app, templates/static), `config/` (config loader/store), `capture/` (stub sniffer).
- **config/**: Example settings in `config/examples/settings.example.yaml`; runtime config in `config/local/settings.yaml`.
- **logs/**: Runtime logs by date.
- **main.py**: Entry point wiring config, managers, and Web UI.

## Build, Test, and Development Commands
- `pip install -r requirements.txt` — install deps (uses `ruamel.yaml` to preserve YAML comments).
- `python main.py --config config/local/settings.yaml --log-level INFO` — run Web UI and tunnel manager.
- (Windows) ensure venv: `.\.venv\Scripts\activate` before running commands.
- No formal test suite; validate by hitting Web UI (`/ui/login`, `/ui/dashboard`) and API endpoints.

## Coding Style & Naming Conventions
- Python 3.12+, 4-space indent, prefer type hints.
- Config keys are snake_case; container identity uses `name` as the unique key.
- HTTP routes use FastAPI defaults; static routes named `static`.
- Avoid removing YAML comments; use provided loader/store to persist configs.
- Commit messages follow short, imperative prefixes (e.g., `feat:`, `fix:`, `chore:`).

## Testing Guidelines
- No automated tests yet. For changes: at minimum run `python main.py` and verify:
  - Web UI loads under configured `root_path`.
  - Tunnel commands include configured `-L`/`-R` from `forwards`/`reverse_forwards`.
  - Config edits via `/ui/config` keep global `acs` fields and compact per-container `acs` (`container_name`, `service_type`).

## Commit & Pull Request Guidelines
- Use concise, imperative commit messages (`feat: add multi-container manager`).
- PRs should describe scope, configuration changes, and manual verification steps (e.g., `python main.py`, screenshots of dashboard/tunnel status).
- Avoid pushing secrets: real cookies, passwords, or private keys should stay local; use example values in commits.

## Security & Configuration Tips
- Global `acs` stores shared credentials/cookies; per-container `acs` only keeps `container_name`/`service_type`.
- `forwards` and `reverse_forwards` are explicit; formats: `{"local": 8080, "remote": 80}` or `"8080:80[:mid]"` (double SSH requires `mid`).
- Keep `webui.auth` enabled in shared environments; rotate `secret_key` when deploying.
- Avoid committing real `config/local/settings.yaml`; rely on `config/examples/settings.example.yaml` for templates.
