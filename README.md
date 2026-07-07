# ACS Manager

ACS Manager 用于管理 ACS 上会周期性停止、重启后 IP 会变化的远程容器或 Notebook 任务。它会监控任务状态、解析最新 IP、维护 SSH 端口转发，并提供网页界面查看状态、编辑配置和触发容器任务。

## 功能一览

- 多容器管理
- 生命周期维护
- IP 自动更新
- SSH 隧道维护
- 容器任务
- 网页界面

## 项目结构

- `main.py`：程序入口，加载配置、启动网页界面和后台监控。
- `acs_manager/container/`：ACS 登录、任务查询、IP 发现、重启/重建接口客户端。
- `acs_manager/management/`：容器生命周期、SSH 隧道和任务运行管理。
- `acs_manager/webui/`：网页服务、页面模板和静态资源。
- `acs_manager/config/`：配置加载、写回、版本迁移和运行态存储。
- `config/examples/settings.example.yaml`：带中文注释的示例配置。
- `config/local/settings.yaml`：本地运行配置，默认不提交。
- `state/runtime_state.yaml`：运行态数据，例如重建次数和任务执行状态，默认不提交。
- `logs/`：运行日志目录，默认不提交。

## 快速开始

创建虚拟环境并安装依赖：

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

首次运行：

```bash
python main.py --config config/local/settings.yaml --log-level INFO
```

如果 `config/local/settings.yaml` 不存在，程序会从 `config/examples/settings.example.yaml` 复制模板，提示填写配置后退出。填写完成后再次运行即可。

也可以手动复制配置：

```bash
copy config\examples\settings.example.yaml config\local\settings.yaml
```

启动后默认访问：

- 仪表盘：`http://localhost:8000/ui/dashboard`
- 配置页：`http://localhost:8000/ui/config`
- 日志页：`http://localhost:8000/ui/logs`

如果配置了 `webui.root_path: "/acsmanager"`，访问路径应加上前缀，例如 `http://localhost:8000/acsmanager/ui/dashboard`。

## 配置要点

配置文件推荐使用 `containers` 列表管理多个容器。全局 `acs` 保存 ACS 登录信息和 Cookie，容器级 `acs` 只保存当前容器对应的 `container_name` 和 `service_type`。

最少需要填写：

- `acs.base_url`：ACS 控制台地址，例如 `http://192.168.10.200:6080`。
- `acs.api_prefix`：通常为 `/sothisai`。
- `acs.login_user`、`acs.login_password`、`acs.public_key`：自动登录所需信息。
- `containers[].name`：本项目内的唯一标识，也是网页界面的展示名。
- `containers[].acs.container_name`：ACS 中实际任务名。
- `containers[].acs.service_type`：`container` 或 `notebook`。
- `containers[].ssh`：SSH 登录、跳板、端口和转发配置。

`service_type` 的区别：

- `container` 使用 `instance-service` 相关 ACS 接口。
- `notebook` 使用 `/api/notebook/task` 相关 ACS 接口。
- 两种模式的 SSH 隧道、任务执行和网页展示逻辑共用。

重启策略：

- `restart`：只重启原任务。
- `recreate`：只新建任务，名称格式为 `容器名称_次数_时间戳`。
- `none`：不自动重启或重建，手动“重启容器”操作也会跳过。
- 三种策略严格区分，失败时不会自动切换到另一种策略。

端口转发：

- `forwards` 对应 SSH `-L`。
- `remote_dynamic_forwards` 对应 OpenSSH 远端动态转发 `-R [bind:]port`，用于在容器侧监听 SOCKS4/5 代理端口。例如 `{"bind":"127.0.0.1","remote":17890}` 会生成 `-R 127.0.0.1:17890`。
- `reverse_forwards` 对应 SSH `-R`。
- 只有配置了对应列表才会拼接对应参数。
- 容器程序需要显式使用 SOCKS 代理，例如 `ALL_PROXY=socks5h://127.0.0.1:17890`；不会自动透明代理所有网络。

容器任务：

- `trigger: manual`：只允许手动触发。
- `trigger: auto_on_start`：容器进入运行状态后自动触发。
- `runner.type` 支持 `shell`、`screen`、`tmux`、`nohup`。
- 常驻服务建议使用 `screen` 或 `tmux`，一次性训练任务可使用 `nohup` 或 `shell`。
- `screen`/`tmux` 模式需要容器内已安装对应命令；任务退出后会保留可 attach 的会话，并通过运行标记判断命令是否仍在执行。
- `mode: ensure_running` 只支持 `screen` 或 `tmux`，监控循环会持续检查运行标记，命令退出后会自动重新拉起。
- 同一容器内启用的 `screen`/`tmux` 任务不能共用同一个 session；`auto_on_start` 不支持 `shell` runner。

## 网页界面

仪表盘用于查看所有容器的状态、IP、剩余时间、隧道状态和最近任务执行结果。可以刷新 IP、重启容器、重启隧道、手动执行任务，也可以触发项目更新。

配置页采用多容器工作台模式：左侧选择容器，右侧编辑当前容器。支持新增、复制、删除、排序、任务下拉选择、端口转发表格编辑和未保存提示。

日志页显示当前日志文件尾部内容，支持自动刷新。

## 常用数据接口

- `GET /health`：健康检查。
- `GET /state`：当前运行状态。
- `GET /containers`：所有容器概览。
- `GET /container-ip`：当前容器 IP，兼容旧接口。
- `GET /config`、`PATCH /config`、`PUT /config`：配置读写。
- `GET /config/global`、`PATCH /config/global`：全局配置读写。
- `GET /config/containers`：容器配置列表。
- `GET/PATCH/DELETE /config/containers/{id}`：单容器配置读写和删除。
- `POST /config/containers`：新增容器。
- `POST /config/containers/{id}/clone`：复制容器。
- `POST /config/containers/reorder`：调整容器顺序。
- `POST /containers/{id}/refresh-ip`：刷新容器 IP。
- `POST /containers/{id}/restart-container`：按策略重启、重建或跳过容器操作。
- `POST /containers/{id}/tasks/{task_id}/run`：手动执行容器任务。
- `GET /logs?lines=N`：读取最近 N 行日志。
- `POST /update`：检查 Git 更新，存在新版本时拉取并重启；本地工作区有未提交改动时会失败。

## 部署说明

直接本机访问时，使用 `webui.host` 和 `webui.port` 对应地址。默认 `webui.host` 为 `127.0.0.1`。

如果将 `webui.host` 绑定到 `0.0.0.0`、局域网 IP 或公网 IP，必须启用 `webui.auth`；否则受保护的 UI/API 会返回 403，避免配置写入和任务执行接口暴露到网络。

如果通过 Nginx 反向代理到子路径，建议同时配置：

```yaml
webui:
  root_path: "/acsmanager"
```

Nginx 需要保留路径前缀转发到后端，示例：

```nginx
location /acsmanager/ {
    proxy_pass http://127.0.0.1:18000;
    proxy_redirect off;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

如果使用 FRP 映射端口，先确认本地 `http://localhost:8000/acsmanager/ui/dashboard` 正常，再检查公网 Nginx 到 FRP 端口的转发。
