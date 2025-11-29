# ACS Manager

Monitor the ACS web console, detect when long-running containers shut down, restart them, capture the refreshed container IP from the web terminal, and assemble the SSH/jump host command to reconnect with port forwarding.

## Features
- Packet capture stub for ACS web console traffic; hook up DevTools/mitmproxy/playwright to feed events.
- Management controller placeholder to restart the container and track last-seen IP/restart timestamps.
- SSH command builder that supports jump hosts (`-J`) and multiple `-L` forwards.
- FastAPI-based Web UI exposing health and current state.
- Simple YAML/JSON configuration loader and runnable entrypoint.

## Project layout
```
.
©À©¤ acs_manager/
©¦  ©À©¤ capture/          # Sniffer stub for ACS traffic -> extracts container IP
©¦  ©À©¤ management/       # Container lifecycle + SSH orchestration
©¦  ©À©¤ webui/            # FastAPI app exposing health/state
©¦  ©¸©¤ config/           # Config loader utilities
©À©¤ config/
©¦  ©¸©¤ settings.example.yaml   # Sample configuration
©À©¤ main.py              # Entrypoint: ties capture, manager, web UI
©À©¤ requirements.txt     # Minimal dependencies
©¸©¤ README.md            # This file
```

## Quick start
1. Python 3.11+ recommended. Create a virtual environment (optional):
   ```bash
   python -m venv .venv
   .\.venv\Scripts\activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Copy and edit the config:
   ```bash
   copy config\settings.example.yaml config\settings.yaml
   ```
   Fill in ACS credentials/URLs, the target container name, and SSH details.
4. Run the manager (logs to stdout):
   ```bash
   python main.py --config config/settings.yaml --log-level DEBUG
   ```
5. Web UI (served by the same process): visit `http://localhost:8000/health` and `http://localhost:8000/state`.

## Configuration (settings.example.yaml)
- `acs.base_url`: ACS web console base URL.
- `acs.login_user` / `acs.login_password`: credentials for automation or API use.
- `acs.container_name`: identifier for the container to restart.
- `acs.shutdown_hours`: expected auto-shutdown window (360h default).
- `acs.terminal_selector`: DOM selector for the embedded terminal (for automation).
- `capture.request_filters` / `capture.response_keywords`: strings to help you filter relevant network events.
- `ssh.bastion_host` / `ssh.bastion_user`: jump host info (omit for direct SSH).
- `ssh.target_user`: user for the container host.
- `ssh.identity_file`: private key path used by SSH.
- `ssh.forwards`: list of `{local, remote}` port forward specs.
- `webui.host` / `webui.port`: bind address for the FastAPI server.
- `logging.level`: default log verbosity.

## How it is intended to work
1. `PacketSniffer` attaches to ACS web console traffic (you wire in the actual capture mechanism) and sends parsed events to `handle_event`, which extracts container IPs.
2. When the ACS container stops after ~360 hours, implement restart logic in `ContainerManager.restart_container` (browser automation/API call).
3. Once a new IP is seen, `ContainerManager` stores it and builds the SSH command with jump host + `-L` forwards so you can reconnect.
4. The FastAPI endpoints expose health and current state for lightweight monitoring.

## Notes / next steps
- Implement real capture using DevTools, playwright, or mitmproxy to push events into `PacketSniffer.handle_event`.
- Implement ACS restart + terminal scraping inside `ContainerManager.restart_container` and the capture layer.
- Add tests and error handling once the concrete ACS integration is known.
