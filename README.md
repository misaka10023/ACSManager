# ACS Manager

Monitor the ACS web console, detect when long-running containers shut down, restart them, capture the refreshed container IP from the web terminal, and assemble the SSH/jump host command to reconnect with port forwarding.

## Features
- Packet capture stub for ACS web console traffic; hook up DevTools/mitmproxy/playwright to feed events.
- Management controller keeps an SSH tunnel alive for port forwarding (direct / `-J` / double-ssh), restarts on disconnect, and cleans up before re-establishing.
- Web UI for remote config edits, viewing state, tailing logs, and fetching container IP.
- Logging goes to `logs/YYYY-MM-DD.log` plus console.
- ConfigStore with atomic YAML/JSON read/write so the app and Web UI share the latest settings.

## Project layout
- acs_manager/
  - capture/  (sniffer stub for ACS traffic -> extracts container IP)
  - management/  (container lifecycle + SSH orchestration)
  - webui/  (FastAPI app exposing health/state/config)
  - config/  (config loader and ConfigStore)
- config/settings.example.yaml  (sample configuration)
- main.py  (entrypoint tying capture, manager, web UI)
- requirements.txt  (dependencies)
- README.md

## Quick start
1) Python 3.11+ recommended. Create a virtual environment (optional):
   ```bash
   python -m venv .venv
   .\.venv\Scripts\activate
   ```
2) Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3) Copy and edit the config:
   ```bash
   copy config\settings.example.yaml config\settings.yaml
   ```
   Fill in ACS credentials/URLs, session cookie, container/bastion IPs, and SSH details.
4) Run the manager (logs to stdout):
   ```bash
   python main.py --config config/settings.yaml --log-level DEBUG
   ```
5) Web UI (served by the same process): visit `http://localhost:8000/health`, `/state`, and `/config`.

## Runtime configuration & Web UI
- GET `/config?reload=true` returns the latest YAML/JSON from disk (reloaded each request by default).
- PATCH `/config` with a JSON object to shallow-merge updates and persist to disk atomically.
- PUT `/config` with a JSON object to replace the config entirely.
- GET `/state` shows runtime state; GET `/container-ip` returns captured or fallback IP; GET `/logs?lines=200` tails the latest log file.
- ContainerManager, PacketSniffer, and Web UI all read/write via ConfigStore, so updates go through the config module. If you change ACS base URL, restart the process so the sniffer uses the new target; SSH-related changes take effect immediately for newly built commands.
- Web UI scope: remote config edits, runtime state, tunnel/log visibility, and container IP retrieval.

Example (update jump host):
```bash
curl -X PATCH http://localhost:8000/config \
  -H "Content-Type: application/json" \
  -d "{\"ssh\":{\"bastion_host\":\"bastion.example.com\"}}"
```

SSH mode examples:
- jump (`ssh.mode=jump`): `ssh -J bastion@203.0.113.10 target@<container_ip>`
- double (`ssh.mode=double`): `ssh bastion@203.0.113.10 "ssh -p 22 -L 7890:localhost:7890 target@<container_ip>"`
- config-style analogy: 
  ```
  Host container
      HostName <container_ip>
      User target
      ProxyJump bastion@203.0.113.10
      IdentityFile ~/.ssh/id_rsa
  ```

## Logging
- Location: `logs/YYYY-MM-DD.log` (auto-created on startup) plus console output.
- Web UI: GET `/logs?lines=200` to tail the latest log.

## Configuration (settings.example.yaml)
- `acs.base_url`: ACS web console base URL.
- `acs.session_cookie`: GV_JSESSIONID cookie string to keep the session alive.
- `acs.login_user` / `acs.login_password`: credentials for automation or API use.
- `acs.container_name`: identifier for the container to restart.
- `acs.container_task_name`: task/alias name used when starting the container (e.g., E2SRLF).
- `acs.container_ip_hint`: initial container IP hint before capture detects a new one.
- `acs.shutdown_hours`: expected auto-shutdown window (360h default).
- `acs.terminal_selector`: DOM selector for the embedded terminal (for automation).
- Capture filters are hard-coded in code; no capture.* config is required.
- `ssh.mode`: `direct` | `jump` (-J) | `double` (two-hop ssh through bastion).
- `ssh.remote_server_ip` or `ssh.bastion_host`: jump host / remote server IP for double SSH.
- `ssh.port`: SSH port for the outer/default connection.
- `ssh.container_port`: inner hop port when `mode=double` (falls back to `ssh.port` if omitted).
- `ssh.target_user`: user for the container host.
- `ssh.password_login` + `ssh.password`: optional password auth (not injected into ssh CLI; use automation).
- `ssh.identity_file`: private key path used by SSH (for key-based auth).
- `ssh.container_ip`: fallback container IP if capture has not yet updated state.
- `ssh.local_open_port` / `ssh.container_open_port`: default local/container ports for a single forward when `forwards` is empty.
- `ssh.forwards`: list of `{local, remote}` port forward specs (remote = container port).
- `webui.host` / `webui.port`: bind address for the FastAPI server.
- `logging.level`: default log verbosity.

## How it is intended to work
1) `PacketSniffer` attaches to ACS web console traffic (you wire in the actual capture mechanism) and sends parsed events to `handle_event`, which extracts container IPs.
2) When the ACS container stops after ~360 hours, implement restart logic in `ContainerManager.restart_container` (browser automation/API call).
3) Once a new IP is seen, `ContainerManager` stores it and builds the SSH command with jump host + `-L` forwards so you can reconnect.
4) The FastAPI endpoints expose health, current state, and live config for lightweight monitoring.

## Notes / next steps
- Capture rules will be hard-coded later; no capture-related config is needed now.
- Implement ACS restart + terminal scraping inside `ContainerManager.restart_container` and the capture layer.
- Add tests and error handling once the concrete ACS integration is known.
