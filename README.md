# ACS Manager

> 通过监控 ACS Web 控制台 / API，自动保持远程容器运行、维护 SSH 端口转发隧道，并提供一个 Web UI 方便查看状态和修改配置。

典型场景：ACS 上的容器每 ~360 小时自动关闭，重启后容器 IP 会变化。ACS Manager 负责：

- 轮询 ACS API，在接近超时时缩短检查间隔，容器停止时调用重启接口；  
- 解析最新容器 IP，更新本地状态；  
- 基于配置自动拼出直连 / `-J` / 双层 SSH 隧道命令，保持端口转发在线；  
- 提供 Web UI：查看健康状态、容器 IP、隧道状态、配置和运行日志。

---

## 功能一览

- **多容器支持**
  - `containers` 列表为每个容器提供独立的 ACS/SSH 配置（端口、登录方式、转发规则、fallback IP 等）。
  - 后台为每个容器维护独立的生命周期监控与 SSH 隧道；仪表盘可列出全部容器并执行刷新 IP / 启停/重启隧道。
- **ACS API 客户端 (`acs_manager.container.client.ContainerClient`)**
  - 使用配置中的 Base64 公钥对密码做 RSA 加密，调用 `/login/loginAuth.action` 登录 ACS。
  - 支持配置中直接复用 `JSESSIONID` / `GV_JSESSIONID`（`acs.cookies` 不为空时跳过登录）。
  - 调用 `/sothisai/api/instance-service/task`、`/sothisai/api/instance-service/related-tasks`、`/sothisai/api/instance/{id}/container-monitor`、`/sothisai/api/instance-service/{id}/run-ips` 查询任务列表、容器状态和 IP；当 related-tasks 不返回数据时会尝试 `/sothisai/api/instance-service/{id}/detail` 作为兜底获取最新记录/IP 线索。
  - 登录成功后会自动把最新 cookies 写回配置文件（`acs.cookies`），方便后续复用；解析到新 IP 时会写回对应容器的 `ssh.container_ip` 作为下次的兜底。

- **容器生命周期 + SSH 隧道管理 (`acs_manager.management.controller.ContainerManager`)**
  - 根据 `acs.container_name` 查找 ACS 任务，使用 restart API 在容器停止时自动重启。
  - 解析 `startTime` + `timeoutLimit`，接近自动停止时间前加快轮询频率。
  - 维护 SSH 隧道，支持三种模式：
    - `direct`：直连容器 `ssh target_user@container_ip`；
    - `jump`：通过 `-J` 跳板 `ssh -J bastion_user@bastion_host target_user@container_ip`；
    - `double`：双层 ssh，通过跳板上的中间端口实现反向转发（适合代理端口转发等场景）。
  - 自动处理端口占用：
    - 本地：检测监听端口，若被同一用户的 ssh 进程占用，自动强杀并重试。
    - 远端：在跳板 / 容器侧通过 `netstat` / `ss` / `fuser` 尝试清理占用容器端口和中间端口（不依赖 sudo 密码）。
  - 支持：正向转发（`ssh.forwards` -> `-L local:remote`），反向转发（`ssh.reverse_forwards` + `ssh.intermediate_port` -> `-R` 链路）。

- **抓包 / IP 发现 (`acs_manager.capture.sniffer.PacketSniffer`)**
  - 目前是一个 stub：你可以将浏览器 DevTools、mitmproxy、Playwright 等输出的网络事件转发给 `handle_event()`。
  - 内部有一个简单的 IP 提取逻辑。发现新 IP 时会调用 `ContainerManager.handle_new_ip()`，更新状态并按需重启隧道。

- **Web UI + JSON API (`acs_manager.webui.app`)**
  - JSON API：
    - `GET /health`：健康状态；
    - `GET /state`：容器/隧道运行状态；
    - `GET /config` / `PATCH /config` / `PUT /config`：配置读取与保存；
    - `GET /container-ip`：当前容器 IP；
    - `GET /logs`：日志尾部。
  - HTML UI：
    - `GET /ui` / `/ui/dashboard`：Dashboard；
    - `GET /ui/config`：配置编辑页；
    - `GET /ui/logs`：日志查看页。
  - UI 使用 Jinja2 模板 + 一点点原生 JS，通过上述 JSON API 动态获取数据。
  - 修改关键配置（ACS URL、账号、SSH 端口 / IP 等）后，会自动重新登录 ACS（刷新 cookies）并重启 SSH 隧道，使新配置立即生效。

- **配置管理 (`acs_manager.config`)**
  - 支持 YAML / JSON；使用 `ConfigStore` 做线程安全缓存和原子写入。
  - Web UI 与主程序通过同一个 `ConfigStore` 协同，始终操作同一份配置文件。

- **日志**
  - 日志写入：`logs/YYYY-MM-DD.log` + 控制台输出。
  - `/logs?lines=N` 提供最近 N 行日志，供 Web UI 做“tail -f” 展示。

---

## 项目结构

- `acs_manager/`
  - `capture/`：抓包 / 事件适配层（目前为 stub）。
  - `config/`：配置加载与持久化（YAML/JSON + ConfigStore）。
  - `container/`：ACS API 客户端（登录 / 容器 IP / 重启）。
  - `management/`：容器生命周期监控 + SSH 隧道管理。
  - `webui/`：FastAPI App，包含 JSON API 和 HTML UI。
  - `__init__.py`：包初始化。
- `config/examples/settings.example.yaml`：示例配置文件（带中文注释）。
- `config/local/settings.yaml`：实际运行配置（首次运行自动生成）。
- `logs/`：按日期命名的日志文件。
- `main.py`：入口脚本，串联配置、容器管理和 Web UI。
- `requirements.txt`：依赖列表。

---

## 快速开始

### 1. 环境准备

建议使用 Python 3.11+：

```bash
python -m venv .venv
.\.venv\Scripts\activate   # Windows
# 或 source .venv/bin/activate  # Linux/macOS

pip install -r requirements.txt
```

### 2. 配置文件

首次运行若 `config/local/settings.yaml` 不存在，程序会自动：

1. 从 `config/examples/settings.example.yaml` 复制出模板；  
2. 打印一条错误日志提示“已生成配置文件，请填写配置后重新运行”；  
3. 直接退出。

你也可以手动复制：

```bash
copy config\examples\settings.example.yaml config\local\settings.yaml
```

然后编辑 `config/local/settings.yaml`，至少需要配置：

- ACS 基础信息：`acs.base_url`、`acs.api_prefix`、`acs.login_user`、`acs.login_password`、`acs.public_key`；
- 可选 cookies：`acs.cookies.JSESSIONID` / `acs.cookies.GV_JSESSIONID`；
- 要监控/重启的容器名称：`acs.container_name`；
- SSH 模式和目标：`ssh.mode`、`ssh.bastion_host/remote_server_ip`、`ssh.target_user`、`ssh.port` 等；
- 端口转发：`ssh.local_open_port`、`ssh.container_open_port`、`ssh.forwards`、`ssh.reverse_forwards`、`ssh.intermediate_port`；
- Web UI：`webui.host`、`webui.port`；
- 日志等级：`logging.level`。

### 3. 启动

```bash
python main.py --config config/local/settings.yaml --log-level INFO
```

启动后：

- Web UI：
  - Dashboard：`http://localhost:8000/ui` 或 `/ui/dashboard`
  - Config：`http://localhost:8000/ui/config`
  - Logs：`http://localhost:8000/ui/logs`
- JSON API 仍可直接访问：`/health`、`/state`、`/config`、`/container-ip`、`/logs`。

---

## Web UI 详情

### Dashboard `/ui/dashboard`

- **健康状态**
  - 调用 `GET /health`，展示 `status` 字段（OK / 其它）。

- **容器 IP**
  - 调用 `GET /container-ip`，返回示例：
    ```json
    {
      "ip": "173.0.106.2",
      "container_ip": "173.0.106.2",
      "source": "captured | api | fallback | unknown",
      "updated_at": "2025-12-01T10:00:00.123456"
    }
    ```
  - source 含义：
    - `captured`：通过抓包/事件捕获；
    - `api`：调用 ACS API 获取；
    - `fallback`：使用配置中 `ssh.container_ip`；
    - `unknown`：无法获取 IP。

- **隧道状态**
  - 调用 `GET /state`，展示 `ContainerManager.snapshot()`：
    - `container_ip`、`tunnel_status`（running/stopped/error）、`last_restart`、`tunnel_last_exit`；
    - `container_status`（Running/Stopped/...）、`container_start_time` 等。

- **最近日志**
  - 调用 `GET /logs?lines=200`，显示最新日志的 200 行尾部内容。

Dashboard 页面会定期通过 JS 自动刷新健康状态 / 状态 / IP；点击“刷新”按钮可更新日志。

### 配置编辑 `/ui/config`

- 页面加载时，会将当前完整配置以 JSON 形式预填进文本框。
- 按钮：
  - “重新载入”：`GET /config?reload=true`，重新读盘填入文本框。
  - “保存配置”：解析文本框 JSON，调用 `PUT /config` 覆盖配置文件。
- 保存成功/失败会在下方以绿色/红色提示。

**关键配置变更的自动应用：**

保存配置后，应用会自动比较旧配置和新配置中这些字段：

- `acs.*`：`base_url`、`api_prefix`、`login_user`、`login_password`、`public_key`；
- `ssh.*`：`mode`、`remote_server_ip`、`bastion_host`、`bastion_user`、`target_user`、`port`、`container_port`、`local_open_port`、`container_open_port`、`forwards`、`reverse_forwards`、`intermediate_port`。

如果 `acs.*` 有变化：

- 会自动调用 `ContainerClient.login()` 重新登录 ACS，并把新的 cookies 持久化到配置（`acs.cookies`）。

如果 `ssh.*` 有变化：

- 会自动调用 `ContainerManager.restart_tunnel()` 重启 SSH 隧道，让新的 URL/IP/端口配置立即生效。

### 日志查看 `/ui/logs`

- 控制：
  - “自动刷新”勾选（默认开启）；
  - 刷新间隔选择（2s / 5s / 10s）；
  - “刷新”按钮。
- 主区域：
  - 固定高度、可滚动的日志窗口，显示 `GET /logs?lines=N` 返回的文本。
  - 自动刷新开启时，会轮询 `/logs` 并将滚动条保持在底部（类似 `tail -f`）。

---

## JSON API

### `GET /health`

```json
{ "status": "ok" }
```

用于基础健康检查。

### `GET /state`

返回当前管理状态，例如：

```json
{
  "container_ip": "173.0.106.2",
  "last_restart": "2025-12-01T10:00:00.123456",
  "last_seen": "2025-12-01T10:05:00.654321",
  "tunnel_status": "running",
  "tunnel_last_exit": null,
  "container_status": "Running",
  "container_start_time": "2025-12-01 02:00:00"
}
```

### `GET /config?reload=true`

读取当前配置（从磁盘重载），返回完整 JSON。

### `PATCH /config`

以浅合并方式更新配置部分字段：

```bash
curl -X PATCH http://localhost:8000/config \
  -H "Content-Type: application/json" \
  -d "{\"ssh\":{\"bastion_host\":\"bastion.example.com\"}}"
```

写入后会自动触发关键配置变更检查，必要时重新登录 / 重启隧道。

### `PUT /config`

整体替换配置，同样会触发关键配置变更逻辑。

### `GET /container-ip`

如上所述，返回当前容器 IP 与来源。

### `GET /logs?lines=N`

返回最近 N 行日志：

```json
{
  "file": "logs/2025-12-01.log",
  "lines": 200,
  "content": ["[... line1]", "[... line2]", "..."]
}
```

---

## 配置字段要点（`config/examples/settings.example.yaml`）

这里只列关键字段，更详细的中文注释见示例文件本身。

### 多容器配置

- 推荐使用 `containers` 列表，每个元素包含独立的 `acs` 与 `ssh` 段（参见 `config/examples/settings.example.yaml`）；容器的 `name` 既是唯一标识也是展示名称。
- 每个容器都可以配置自己的端口、转发、登录方式、fallback `ssh.container_ip`；发现新 IP 时会写回对应容器的 `ssh.container_ip` 便于下次直连。
- 若老配置仍是单一 `acs`/`ssh` 段，会自动视为一个容器。
- `acs.service_type`：`container`（默认）或 `notebook`。`notebook` 仅使用 detail 接口，无法通过 API 解析 IP，必须填好对应容器的 `ssh.container_ip` 才能启隧道。

### `acs` 段

- `base_url`：ACS 控制台基础地址（含协议+端口）。
- `api_prefix`：ACS API 前缀（通常为 `/sothisai`）。
- `login_user` / `login_password` / `user_type` / `public_key`：登录相关。
- `verify_ssl`：自签名证书时可设为 `false`。
- `cookies`：预置 cookies；自动登录成功后会被最新值覆盖。
- `container_name`：容器/任务名称，例如 `Instances_2511296089`。请在“容器服务”界面创建容器，其他入口创建的实例通过上述 API 通常无法查询到容器 IP。

### `ssh` 段

- `mode`：`direct` / `jump` / `double`。
- `remote_server_ip` / `bastion_host` / `bastion_user`：跳板机信息。
- `target_user`：容器宿主机用户。
- `port` / `container_port`：外层/内层 SSH 端口。
- `local_open_port` / `container_open_port`：默认用来做单个端口转发（例如本地代理→容器代理端口）。
- `forwards`：正向本地端口转发列表（`-L`）。
- `reverse_forwards`：反向端口转发列表（`-R`），double 模式需配合 `intermediate_port`。
- `intermediate_port`：double 模式下在跳板上使用的中转端口。

### `webui` / `logging`

- `webui.host` / `webui.port`：Web UI 监听地址/端口。
- `logging.level`：日志级别（如 `INFO` / `DEBUG`）。

---

## 工作流程简述

1. 启动时加载配置，初始化 `ContainerManager`、`PacketSniffer` 和 Web UI。
2. `ContainerManager.monitor_container()` 轮询 ACS：
   - 更新容器状态与 IP；
   - 在超时前 10 分钟内加快轮询；
   - 容器停止时调用重启 API。
3. `PacketSniffer`（如果已接入）发现新 IP 时调用 `handle_new_ip()`，更新 IP 并在必要时重启隧道。
4. `maintain_tunnel()` 持续确保 SSH 隧道在线，异常退出会自动重启。
5. Web UI 和 JSON API 提供运行时状态、日志和配置编辑能力；保存配置会触发自动登录和隧道重启，使关键变更立即生效。

---

此 README 描述的是当前代码中已有的行为与约定，后续如对 ACS API、抓包方式或 SSH 策略做进一步扩展，可在此基础上继续迭代。*** End Patch
```} to=functions.apply_patch  మూఋassistant to=functions.apply_patch니스 to=functions.apply_patch>taggerеннолетassistant to=functions.apply_patch !***}assistant to=functions.apply_patch.Renderer Rawಕ to=functions.apply_patch  Onojson## Test Input Reasoning (json input) to=functions.apply_patch  Assertions to=functions.apply_patchInолжassistant to=functions.apply_patch ***!
