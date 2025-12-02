from __future__ import annotations

import asyncio
import datetime as dt
import getpass
import logging
import os
import subprocess
from asyncio.subprocess import Process
from typing import Any, Dict, List, Optional

import psutil

from acs_manager.config.store import ConfigStore
from acs_manager.container.client import ContainerClient

logger = logging.getLogger(__name__)


class ContainerManager:
    """澶勭悊 ACS 瀹瑰櫒鐢熷懡鍛ㄦ湡銆両P 璺熻釜涓?SSH 闅ч亾缁存姢銆?""

    def __init__(self, store: ConfigStore, container_client: Optional[ContainerClient] = None) -> None:
        self.store = store
        self.container_client = container_client or ContainerClient(store)
        self.state: Dict[str, Any] = {
            "container_ip": None,
            "next_shutdown": None,
            "remaining_seconds": None,
            "timeout_limit": None,
            "last_restart": None,
            "last_seen": None,
            "tunnel_status": "stopped",
            "tunnel_last_exit": None,
            "container_status": None,
            "container_start_time": None,
        }
        self._tunnel_process: Optional[Process] = None
        self._proc_lock = asyncio.Lock()
        self._stop_requested = False
        self._tunnel_started_once = False
        self._tunnel_failure_count = 0

    async def handle_new_ip(self, ip: str) -> None:
        """鎹曡幏鍒版柊 IP 鏃舵洿鏂扮姸鎬侊紱IP 鐪熷彉鍖栦笖宸插缓绔嬭繃闅ч亾鎵嶉噸鍚€?""
        old_ip = self.state.get("container_ip")
        self.state["last_seen"] = dt.datetime.now()

        # IP 鏈彉涓旈毀閬撳凡璺戣繃锛氫粎褰撳績璺筹紝閬垮厤閲嶅閲嶅惎
        if old_ip == ip and self._tunnel_started_once:
            logger.debug("瀹瑰櫒 IP 鏈彉鍖?%s)锛屼粎鏇存柊 last_seen銆?, ip)
            return

        self.state["container_ip"] = ip

        # 棣栨鎷垮埌 IP锛氳 maintain_tunnel 鎵ц绗竴娆″惎鍔紝涓嶆姠瀹冪殑娴佺▼
        if not self._tunnel_started_once:
            logger.info("瀹瑰櫒 IP 棣栨鎹曡幏涓?%s锛岀瓑寰呴毀閬撳垵濮嬪寲銆?, ip)
            return

        # IP 鐪熷彉鍖栵細閲嶅惎闅ч亾
        logger.info("瀹瑰櫒 IP 鏇存柊涓?%s锛堟棫鍊? %s锛夛紝閲嶅惎闅ч亾銆?, ip, old_ip)
        await self.restart_tunnel()

    def update_container_status(self, status: Optional[str], start_time: Optional[str]) -> None:
        self.state["container_status"] = status
        self.state["container_start_time"] = start_time

    def resolve_container_ip(self, *, force_login: bool = True) -> Optional[str]:
        """鍦?IP 涓嶆槑鏃堕€氳繃 API 鑷姩鑾峰彇銆?""
        name = self._acs_cfg(reload=True).get("container_name")
        if not name:
            logger.warning("鏈厤缃?acs.container_name锛屾棤娉曡嚜鍔ㄨ幏鍙?IP銆?)
            return None
        if force_login:
            try:
                self.container_client.login()
            except Exception as exc:  # pragma: no cover - 缃戠粶寮傚父
                logger.error("鑷姩鐧诲綍浠ヨ幏鍙栧鍣?IP 澶辫触: %s", exc)
                return None
        try:
            info = self.container_client.get_container_instance_info_by_name(name)
        except Exception as exc:  # pragma: no cover - 缃戠粶寮傚父
            logger.error("閫氳繃 API 鑾峰彇瀹瑰櫒 %s 淇℃伅澶辫触: %s", name, exc)
            return None
        if info and info.get("instanceIp"):
            ip = info["instanceIp"]
            self.state["container_ip"] = ip
            self.state["last_seen"] = dt.datetime.now()
            logger.info("閫氳繃 API 鑷姩鑾峰彇瀹瑰櫒 IP: %s", ip)
            return ip
        logger.warning("鏃犳硶閫氳繃 API 鑾峰彇瀹瑰櫒 %s 鐨?IP銆?, name)
        return None

    async def ensure_running(self) -> None:
        """鎹曡幏鍒板叧闂椂璋冪敤锛岀珛鍗冲皾璇曢噸鍚€?""
        await self.restart_container()
    async def prepare_on_start(self, poll_interval: int = 10) -> None:
        """\
        å¯åŠ¨æµç¨‹ä¸­çš„å®¹å™¨çŠ¶æ€é¢„æ£€æŸ¥ï¼š
        - é¡ºä¾¿ç™»å½•ç¡®ä¿ç½‘é¡µ cookie æœ‰æ•ˆ
        - æ£€æŸ¥å®¹å™¨çŠ¶æ€ï¼š
          - Waiting ï¼šæŽ’é˜Ÿï¼Œç­‰å¾…æŽ’é˜Ÿç»“æŸï¼Œå‘¨æœŸé‡è¯•
          - Running ï¼šç›´æŽ¥ç»§ç»­åŽç»­å¯åŠ¨æµç¨‹
          - Stopped/Terminated/Failed ç­‰ï¼šå°è¯•è°ƒç”¨é‡å¯æŽ¥å£ï¼Œç„¶åŽç­‰å¾…è‡³ Running
        """
        acs_cfg = self._acs_cfg(reload=True)
        name = acs_cfg.get("container_name")
        if not name:
            logger.info("æœªé…ç½® acs.container_nameï¼Œè·³è¿‡å¯åŠ¨å‰çš„å®¹å™¨çŠ¶æ€æ£€æŸ¥ã€?")
            return

        # ä¼˜å…ˆç™»å½•ä¸€æ¬¡ï¼Œç¡®ä¿ cookie å¯ç”¨
        try:
            self.container_client.login()
        except Exception as exc:  # pragma: no cover - ç½‘ç»œå¼‚å¸¸
            logger.error("å¯åŠ¨æµç¨‹ç™»å½• ACS å¤±è´¥ï¼Œè·³è¿‡é¢„æ£€ï¼š%s", exc)
            return

        stop_statuses = {"terminated", "stopped", "stop", "failed"}
        waiting_statuses = {"waiting"}

        while not self._stop_requested:
            try:
                info = self.container_client.get_container_instance_info_by_name(name)
            except Exception as exc:  # pragma: no cover - ç½‘ç»œ/API å¼‚å¸¸
                logger.error("å¯åŠ¨å‰èŽ·å–å®¹å™¨ %s çŠ¶æ€å¤±è´¥ï¼š%s", name, exc)
                await asyncio.sleep(poll_interval)
                continue

            if not info:
                logger.warning("å¯åŠ¨å‰æœªæ‰¾åˆ°å®¹å™¨ %s ï¼Œç­‰å¾…å†?è¯•ã€?", name)
                await asyncio.sleep(poll_interval)
                continue

            status = info.get("status")
            start_time_str = info.get("startTime") or info.get("createTime")
            self.update_container_status(status, start_time_str)
            ip = info.get("instanceIp")
            if ip:
                await self.handle_new_ip(ip)

            status_norm = (status or "").lower()
            if status_norm in waiting_statuses:
                logger.info("å¯åŠ¨å‰å®¹å™¨ %s çŠ¶æ€ Waitingï¼ˆæŽ’é˜Ÿï¼‰ï¼Œç­‰å¾…è°ƒåº¦ã€?", name)
                await asyncio.sleep(poll_interval)
                continue

            if status_norm in stop_statuses:
                logger.warning("å¯åŠ¨å‰å®¹å™¨ %s çŠ¶æ€ %s ï¼Œå°è¯•é‡å¯å®¹å™¨ã€?", name, status)
                await self.restart_container()
                # ç»™ ACS ä¸€ç‚¹æ—¶é—´æ‹–æœº
                await asyncio.sleep(poll_interval)
                continue

            # è®¤ä¸ºå·²ç»åœ¨è¿è¡Œæˆ–æ­£åœ¨éƒ¨ç½²ï¼Œä¸é˜»æŒåŽç»­æµç¨‹
            logger.info("å¯åŠ¨å‰å®¹å™¨ %s çŠ¶æ€ %s ï¼Œç»§ç»­åŽç»­å¯åŠ¨æµç¨‹ã€?", name, status or "æœªçŸ¥")
            break

    async def restart_container(self) -> None:
        """璋冪敤 ACS 閲嶅惎鎺ュ彛銆?""
        acs_cfg = self._acs_cfg(reload=True)
        name = acs_cfg.get("container_name")
        if not name:
            logger.error("鏈厤缃?acs.container_name锛屾棤娉曢噸鍚€?)
            return

        try:
            task = self.container_client.find_instance_by_name(name)
        except Exception as exc:
            logger.error("鏌ヨ瀹瑰櫒 %s 澶辫触锛屾棤娉曢噸鍚? %s", name, exc)
            return
        if not task:
            logger.error("鏈壘鍒板鍣?%s锛屾棤娉曢噸鍚€?, name)
            return
        task_id = task.get("instanceServiceId") or task.get("id")
        if not task_id:
            logger.error("瀹瑰櫒 %s 缂哄皯 instanceServiceId锛屾棤娉曢噸鍚€?, name)
            return

        logger.warning("灏濊瘯閲嶅惎瀹瑰櫒 %s (task id: %s)", name, task_id)
        try:
            resp = self.container_client.restart_task(task_id)
        except Exception as exc:
            logger.error("璋冪敤閲嶅惎鎺ュ彛澶辫触: %s", exc)
            return
        if str(resp.get("code")) == "0":
            logger.info("閲嶅惎璇锋眰鎴愬姛: %s", resp)
            self.state["last_restart"] = dt.datetime.now()
            self._stop_requested = True
        else:
            logger.error("閲嶅惎璇锋眰澶辫触: %s", resp)

    def _parse_start_time(self, value: Optional[str]) -> Optional[dt.datetime]:
        if not value:
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                return dt.datetime.strptime(value, fmt)
            except ValueError:
                continue
        return None

    def _parse_remaining_time_str(self, value: Optional[str]) -> Optional[int]:
        """
        瑙ｆ瀽 ACS 鎻愪緵鐨?remainingTime 鏂囨湰锛屼緥濡?\"14d 23h 48m\"锛岃繑鍥炵鏁般€?        """
        if not value:
            return None
        text = str(value).strip()
        if not text:
            return None
        total = 0
        for part in text.split():
            part = part.strip()
            try:
                if part.endswith("d"):
                    total += int(part[:-1]) * 24 * 3600
                elif part.endswith("h"):
                    total += int(part[:-1]) * 3600
                elif part.endswith("m"):
                    total += int(part[:-1]) * 60
            except ValueError:
                continue
        return total or None

    async def monitor_container(self, *, pre_shutdown_minutes: int = 10, slow_interval: int = 300, fast_interval: int = 30) -> None:
        """
        鍛ㄦ湡妫€鏌ュ鍣ㄧ姸鎬侊紱鎺ヨ繎瓒呮椂鏃剁缉鐭鏌ラ棿闅旓紝鍋滄鏃剁珛鍗抽噸鍚€?        """
        acs_cfg = self._acs_cfg(reload=True)
        name = acs_cfg.get("container_name")
        if not name:
            logger.warning("鏈厤缃?acs.container_name锛岀洃鎺ч€€鍑恒€?)
            return

        while not self._stop_requested:
            interval = slow_interval
            try:
                try:
                    info = self.container_client.get_container_instance_info_by_name(name)
                except Exception as exc:
                    # 濡傛灉鏄璇佸け璐ワ紝灏濊瘯閲嶆柊鐧诲綍涓€娆?                    try:
                        if hasattr(exc, "response") and getattr(exc.response, "status_code", None) == 401:  # type: ignore[attr-defined]
                            self.container_client.login()
                            info = self.container_client.get_container_instance_info_by_name(name)
                        else:
                            raise
                    except Exception:
                        raise
                if info:
                    status = info.get("status")
                    start_time_str = info.get("startTime") or info.get("createTime")
                    self.update_container_status(status, start_time_str)
                    ip = info.get("instanceIp")
                    if ip:
                        await self.handle_new_ip(ip)

                    # 浣跨敤 startTime + timeoutLimit 璁＄畻棰勮鑷姩鍋滄鏃堕棿鍜屽墿浣欐椂闂?                    start_dt = self._parse_start_time(start_time_str)
                    timeout_str = info.get("timeoutLimit")
                    now = dt.datetime.now()
                    if start_dt and timeout_str:
                        try:
                            # 璁板綍褰撳墠浣跨敤鐨勮秴鏃舵椂闂撮厤缃紝鏂逛究 WebUI 灞曠ず
                            self.state["timeout_limit"] = timeout_str
                            hours, minutes, seconds = timeout_str.split(":")
                            delta = dt.timedelta(hours=int(hours), minutes=int(minutes), seconds=int(seconds))
                            next_shutdown = start_dt + delta
                            self.state["next_shutdown"] = next_shutdown.strftime("%Y-%m-%d %H:%M:%S")
                            remaining = (next_shutdown - now).total_seconds()
                            remaining_sec = int(remaining) if remaining > 0 else 0
                            self.state["remaining_seconds"] = remaining_sec
                            # 鐢熸垚浜虹被鍙鐨勫墿浣欐椂闂村瓧绗︿覆
                            if remaining_sec > 0:
                                days = remaining_sec // 86400
                                hours_left = (remaining_sec % 86400) // 3600
                                mins_left = (remaining_sec % 3600) // 60
                                parts = []
                                if days > 0:
                                    parts.append(f"{days} 澶?)
                                if hours_left > 0:
                                    parts.append(f"{hours_left} 灏忔椂")
                                if mins_left > 0 or not parts:
                                    parts.append(f"{mins_left} 鍒嗛挓")
                                self.state["remaining_time_str"] = " ".join(parts)
                            else:
                                self.state["remaining_time_str"] = "0 鍒嗛挓"
                            # 鎺ヨ繎鍋滄鏃堕棿锛屼娇鐢ㄥ揩閫熻疆璇?                            threshold = next_shutdown - dt.timedelta(minutes=pre_shutdown_minutes)
                            interval = fast_interval if now >= threshold else slow_interval
                        except Exception:
                            self.state["next_shutdown"] = None
                            self.state["remaining_seconds"] = None
                            self.state["remaining_time_str"] = None
                            self.state["timeout_limit"] = None
                            interval = slow_interval
                    else:
                        self.state["next_shutdown"] = None
                        self.state["remaining_seconds"] = None
                        self.state["remaining_time_str"] = None
                        self.state["timeout_limit"] = None

                    status_norm = (status or "").lower()
                    stop_statuses = {"terminated", "stopped", "stop", "failed"}
                    waiting_statuses = {"waiting"}

                    # Waiting 瑙嗕负鎺掗槦鐘舵€侊紝涓嶈Е鍙戦噸鍚紝浣嗗彲浠ヨ€冭檻鍔犲揩杞
                    if status_norm in waiting_statuses:
                        logger.info("瀹瑰櫒 %s 褰撳墠鐘舵€佷负 Waiting锛堟帓闃燂級锛岀瓑寰呰皟搴︺€?, name)
                        interval = min(interval, fast_interval)

                    if status_norm in stop_statuses:
                        logger.warning("瀹瑰櫒 %s 鐘舵€佷负 %s锛岃Е鍙戦噸鍚€?, name, status)
                        await self.restart_container()
                        break
                else:
                    logger.warning("瀹瑰櫒 %s 鏈壘鍒帮紝灏嗗揩閫熼噸璇曘€?, name)
                    interval = fast_interval
            except Exception as exc:  # pragma: no cover - 缃戠粶/API 寮傚父
                logger.error("鐩戞帶寰幆寮傚父: %s", exc)
                interval = fast_interval

            await asyncio.sleep(interval)

    def build_ssh_command(self, *, reload_config: bool = True) -> List[str]:
        """
        缁勮 ssh 鍛戒护锛?        - direct锛氱洿杩炲鍣?        - jump锛氫娇鐢?-J 璺虫澘
        - double锛氬弻灞?ssh锛堝灞傚埌璺虫澘锛屽唴灞傚埌瀹瑰櫒锛?        """
        ssh_cfg = self._ssh_cfg(reload=reload_config)
        acs_cfg = self._acs_cfg(reload=reload_config)

        target_ip = self.state.get("container_ip") or ssh_cfg.get("container_ip")
        if not target_ip:
            target_ip = self.resolve_container_ip()
        if not target_ip:
            raise ValueError("瀹瑰櫒 IP 鏈煡锛屽皻鏈崟鑾锋垨閰嶇疆銆?)

        mode = (ssh_cfg.get("mode") or "jump").lower()
        target_user = ssh_cfg.get("target_user", "root")
        bastion_host = ssh_cfg.get("bastion_host") or ssh_cfg.get("remote_server_ip")
        bastion_user = ssh_cfg.get("bastion_user") or target_user
        ssh_port = ssh_cfg.get("port")
        password_login = ssh_cfg.get("password_login")
        password = ssh_cfg.get("password")
        forwards = ssh_cfg.get("forwards", [])
        local_open_port = ssh_cfg.get("local_open_port")
        container_open_port = ssh_cfg.get("container_open_port")

        def add_forwards(
            base: List[str],
            remote_host: str = "localhost",
            *,
            default_remote: bool = False,
        ) -> None:
            """
            榛樿杞彂锛堟棤鑷畾涔?forwards锛変娇鐢ㄨ繙绋嬭浆鍙?-R锛屼护瀹瑰櫒绔彛鍙锛?            鏄惧紡 forwards 鍒楄〃浠嶆寜 -L 琛屼负锛堟湰鍦?-> 杩滅锛夈€?            """
            if forwards:
                for spec in forwards:
                    local = spec.get("local")
                    remote = spec.get("remote")
                    if local and remote:
                        base.extend(["-L", f"{local}:{remote_host}:{remote}"])
                return
            if default_remote and local_open_port and container_open_port:
                base.extend(["-R", f"{container_open_port}:localhost:{local_open_port}"])

        def add_port(base: List[str], port_value: Any) -> None:
            if port_value:
                base.extend(["-p", str(port_value)])

        known_hosts = "NUL" if os.name == "nt" else "/dev/null"
        keepalive = [
            "-o",
            "ServerAliveInterval=60",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            f"UserKnownHostsFile={known_hosts}",
            "-o",
            f"GlobalKnownHostsFile={known_hosts}",
        ]

        if mode == "double":
            if not bastion_host:
                raise ValueError("double 妯″紡闇€瑕?ssh.bastion_host 鎴?ssh.remote_server_ip銆?)
            revs = self._reverse_specs(ssh_cfg)
            if any(spec.get("mid") is None for spec in revs):
                raise ValueError("double 妯″紡鐨勫弽鍚戣浆鍙戦渶瑕?intermediate_port 鎴栨瘡鏉?reverse_forwards.intermediate銆?)

            outer: List[str] = ["ssh", "-T"] + keepalive
            add_port(outer, ssh_port)
            # 鏈湴姝ｅ悜杞彂锛堝鏈夛級鍦ㄥ灞傛墽琛?            add_forwards(outer, default_remote=False)
            # 澶栧眰璐熻矗灏嗘湰鍦扮鍙ｆ毚闇插埌璺虫澘鐨勪腑闂寸鍙?            for spec in revs:
                outer.extend(["-R", f"{spec['mid']}:localhost:{spec['local']}"])
            outer.append(f"{bastion_user}@{bastion_host}")
            # 鍐呭眰淇濇寔杩炴帴骞跺湪瀹瑰櫒渚ф墦寮€鍙嶅悜杞彂
            inner: List[str] = ["ssh", "-T", "-N"] + keepalive
            add_port(inner, ssh_cfg.get("container_port") or ssh_port)
            # 鍐呭眰灏嗗鍣ㄧ鍙ｆ寚鍚戣烦鏉夸腑闂寸鍙?            for spec in revs:
                inner.extend(["-R", f"{spec['remote']}:localhost:{spec['mid']}"])
            inner.append(f"{target_user}@{target_ip}")
            outer.append(" ".join(inner))
            cmd = outer
        else:
            cmd: List[str] = ["ssh", "-T", "-N"] + keepalive
            add_port(cmd, ssh_port)
            if mode == "jump":
                if not bastion_host:
                    raise ValueError("jump 妯″紡闇€瑕?ssh.bastion_host 鎴?ssh.remote_server_ip銆?)
                cmd.extend(["-J", f"{bastion_user}@{bastion_host}"])
            add_forwards(cmd, default_remote=False)
            cmd.append(f"{target_user}@{target_ip}")

        if password_login and password:
            logger.info("妫€娴嬪埌瀵嗙爜鐧诲綍鏍囪锛岃纭繚鑷姩鍖栧畨鍏ㄥ鐞嗗瘑鐮佽緭鍏ャ€?)
        return cmd

    def build_tunnel_command(self) -> List[str]:
        """鐢熸垚甯︾鍙ｈ浆鍙戠殑 ssh 闅ч亾鍛戒护銆?""
        base = self.build_ssh_command()
        mode = (self._ssh_cfg(reload=False).get("mode") or "jump").lower()
        # double 妯″紡闇€瑕佸湪璺虫澘鏈烘墽琛屽唴灞?ssh 鍛戒护锛屼笉鑳藉湪澶栧眰鍔?-N
        if mode == "double":
            return base
        return ["ssh", "-o", "ExitOnForwardFailure=yes", "-N"] + base[1:]

    def _forward_ports(self, ssh_cfg: Dict[str, Any]) -> List[int]:
        """
        鏀堕泦闇€瑕佹湰鍦扮洃鍚殑绔彛锛堜粎閽堝 -L 姝ｅ悜杞彂锛夈€?        鍙嶅悜杞彂 -R 涓嶅湪鏈湴缁戝畾绔彛锛屼笉闇€瑕佹娴嬪崰鐢ㄣ€?        """
        ports: List[int] = []
        forwards = ssh_cfg.get("forwards") or []
        for spec in forwards:
            local = spec.get("local")
            if local:
                ports.append(int(local))
        return ports

    def _ports_available(self, ports: List[int]) -> bool:
        """灏濊瘯缁戝畾绔彛浠ユ鏌ュ崰鐢ㄣ€?""
        import socket

        for p in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("127.0.0.1", p))
                except OSError:
                    logger.error("鏈湴绔彛 %s 宸茶鍗犵敤锛屽皾璇曡嚜鍔ㄦ竻鐞嗗悗閲嶈瘯銆?, p)
                    return False
        return True

    def _kill_ssh_on_ports(self, ports: List[int]) -> None:
        """寮烘潃鍗犵敤绔彛鐨勫綋鍓嶇敤鎴?ssh 杩涚▼銆?""
        current_user = getpass.getuser()
        targets: List[int] = []
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr and conn.laddr.port in ports and conn.status == psutil.CONN_LISTEN:
                if conn.pid is None:
                    continue
                try:
                    proc = psutil.Process(conn.pid)
                    if "ssh" in proc.name().lower() and proc.username() == current_user:
                        targets.append(proc.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        for pid in targets:
            try:
                proc = psutil.Process(pid)
                logger.warning("寮哄埗缁撴潫鍗犵敤绔彛鐨?ssh 杩涚▼ pid=%s", pid)
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except psutil.TimeoutExpired:
                    proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _remote_kill_ports_on_host(
        self,
        *,
        host: str,
        user: str,
        ports: List[int],
        ssh_port: Optional[int],
        jump: Optional[str] = None,
        allow_sudo: bool = True,
    ) -> None:
        """鍦ㄨ繙绔富鏈轰笂寮烘潃鍗犵敤鎸囧畾绔彛鐨勮繘绋嬶紙浼樺厛浣跨敤 netstat锛屽繀瑕佹椂 sudo锛夈€?""
        if not host or not user or not ports:
            return
        cmd = ["ssh", "-T"]
        if jump:
            cmd += ["-J", jump]
        if ssh_port:
            cmd += ["-p", str(ssh_port)]
        cmd.append(f"{user}@{host}")
        cmd += ["bash", "-s"]
        plist = " ".join(str(p) for p in ports)
        script = """
if command -v sudo >/dev/null 2>&1 && {use_sudo}; then PREF="sudo -n"; else PREF=""; fi
for p in {plist}; do
  if command -v netstat >/dev/null 2>&1; then
    $PREF netstat -tnlp 2>/dev/null | awk -v port=":$p" '$4 ~ port"$" {{for(i=1;i<=NF;i++){{if($i~"/"){{split($i,a,"/"); print a[1]}}}}}}' | xargs -r $PREF kill -9
  elif command -v ss >/dev/null 2>&1; then
    $PREF ss -ltnp | awk -F'pid=' '$0 ~ /:$p/ {{print $2}}' | awk '{{print $1}}' | tr -d ',' | xargs -r $PREF kill -9
  fi
  if command -v fuser >/dev/null 2>&1; then
    $PREF fuser -k ${{p}}/tcp
  fi
done
""".format(plist=plist, use_sudo="true" if allow_sudo else "false")
        try:
            res = subprocess.run(
                cmd,
                input=script.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=8,
                check=False,
            )
            out = res.stdout.decode(errors="ignore").strip()
            err = res.stderr.decode(errors="ignore").strip()
            if res.returncode != 0:
                logger.debug("杩滅绔彛娓呯悊杩斿洖鐮?%s", res.returncode)
                if err:
                    logger.debug("杩滅绔彛娓呯悊 stderr: %s", err)
            elif out:
                logger.debug("杩滅绔彛娓呯悊杈撳嚭: %s", out)
        except Exception as exc:
            logger.info("杩滅绔彛娓呯悊澶辫触: %s", exc)
            return

    def _remote_cleanup_ports(self, ports: List[int]) -> None:
        """灏濊瘯鍦ㄨ烦鏉?瀹瑰櫒涓婃竻鐞嗗崰鐢ㄥ悓绔彛鐨勮繘绋嬨€?""
        ssh_cfg = self._ssh_cfg(reload=True)
        mode = (ssh_cfg.get("mode") or "jump").lower()
        bastion_host = ssh_cfg.get("bastion_host") or ssh_cfg.get("remote_server_ip")
        bastion_user = ssh_cfg.get("bastion_user") or ssh_cfg.get("target_user") or "root"
        target_user = ssh_cfg.get("target_user") or "root"
        ssh_port = ssh_cfg.get("port")
        container_port = ssh_cfg.get("container_port") or ssh_port
        target_ip = self.state.get("container_ip") or ssh_cfg.get("container_ip")

        if bastion_host:
            self._remote_kill_ports_on_host(
                host=bastion_host,
                user=bastion_user,
                ports=ports,
                ssh_port=ssh_port,
                jump=None,
            )
        if target_ip:
            jump = f"{bastion_user}@{bastion_host}" if bastion_host and mode in {"jump", "double"} else None
            self._remote_kill_ports_on_host(
                host=target_ip,
                user=target_user,
                ports=ports,
                ssh_port=container_port,
                jump=jump,
            )

    def _reverse_cleanup_ports(self, remote_ports: List[int], intermediate_ports: List[int], ssh_cfg: Dict[str, Any], target_ip: Optional[str]) -> None:
        """鍙嶅悜杞彂绔彛娓呯悊锛氳烦鏉跨敤涓棿绔彛锛屽鍣ㄧ敤杩滅绔彛銆?""
        mode = (ssh_cfg.get("mode") or "jump").lower()
        bastion_host = ssh_cfg.get("bastion_host") or ssh_cfg.get("remote_server_ip")
        bastion_user = ssh_cfg.get("bastion_user") or ssh_cfg.get("target_user") or "root"
        target_user = ssh_cfg.get("target_user") or "root"
        ssh_port = ssh_cfg.get("port")
        container_port = ssh_cfg.get("container_port") or ssh_port

        if bastion_host and intermediate_ports:
            self._remote_kill_ports_on_host(
                host=bastion_host,
                user=bastion_user,
                ports=intermediate_ports,
                ssh_port=ssh_port,
                jump=None,
                allow_sudo=False,
            )
        if target_ip and remote_ports:
            jump = f"{bastion_user}@{bastion_host}" if bastion_host and mode in {"jump", "double"} else None
            self._remote_kill_ports_on_host(
                host=target_ip,
                user=target_user,
                ports=remote_ports,
                ssh_port=container_port,
                jump=jump,
                allow_sudo=True,
            )

    def _reverse_specs(self, ssh_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        鏋勯€犲弽鍚戣浆鍙戣鏍硷細
        - reverse_forwards 鍒楄〃椤癸細local(鏈湴)->remote(瀹瑰櫒)锛屽彲閫?intermediate(璺虫澘)
        - 鑻?reverse_forwards 涓虹┖锛屽垯榛樿浣跨敤 container_open_port/local_open_port
        """
        local_open_port = ssh_cfg.get("local_open_port")
        container_open_port = ssh_cfg.get("container_open_port")
        intermediate_port = ssh_cfg.get("intermediate_port")
        revs = ssh_cfg.get("reverse_forwards") or []
        specs: List[Dict[str, Any]] = []
        if not revs and local_open_port and container_open_port:
            revs = [{"local": local_open_port, "remote": container_open_port}]
        for spec in revs:
            local = spec.get("local")
            remote = spec.get("remote")
            mid = spec.get("intermediate") or intermediate_port
            specs.append({"local": int(local), "remote": int(remote), "mid": int(mid) if mid else None})
        return specs

    async def _ensure_ports_free(self, ports: List[int], retries: int = 3, delay: float = 1.0) -> bool:
        """鍦ㄩ毀閬撻噸杩炴椂锛岄噸璇曢噴鏀剧鍙ｅ悗鍐嶅惎鍔ㄣ€?""
        for attempt in range(retries):
            if self._ports_available(ports):
                return True
            await self.stop_tunnel()
            self._kill_ssh_on_ports(ports)
            self._remote_cleanup_ports(ports)
            if attempt < retries - 1:
                await asyncio.sleep(delay)
        return self._ports_available(ports)

    async def start_tunnel(self) -> None:
        """鍚姩 SSH 闅ч亾锛堣嫢鏈繍琛岋級銆?""
        async with self._proc_lock:
            if self._tunnel_process and self._tunnel_process.returncode is None:
                return
            try:
                ssh_cfg = self._ssh_cfg(reload=True)
                target_ip = self.state.get("container_ip") or ssh_cfg.get("container_ip")
                if not target_ip:
                    try:
                        self.container_client.login()
                    except Exception as exc:
                        logger.error("鑾峰彇瀹瑰櫒 IP 鍓嶇櫥褰曞け璐? %s", exc)
                    target_ip = self.state.get("container_ip") or self.resolve_container_ip(force_login=False) or self.resolve_container_ip(force_login=True)
                    if not target_ip:
                        raise ValueError("瀹瑰櫒 IP 鏈煡锛屾棤娉曞惎鍔ㄩ毀閬撱€?)
                reverse_specs = self._reverse_specs(ssh_cfg)
                ports = self._forward_ports(ssh_cfg)
                # 杩滅▼鍙嶅悜杞彂绔彛棰勬竻鐞嗭紙瀹瑰櫒绔?& 璺虫澘涓棿绔彛锛?                remote_ports = [spec["remote"] for spec in reverse_specs if spec.get("remote")]
                intermediate_ports = [spec["mid"] for spec in reverse_specs if spec.get("mid")]
                if reverse_specs:
                    logger.info("灏濊瘯娓呯悊杩滅绔彛: container=%s, intermediate=%s", remote_ports, intermediate_ports)
                    self._reverse_cleanup_ports(remote_ports, intermediate_ports, ssh_cfg, target_ip)
                    # 鐭殏鍋滈】璁╄繙绔竻鐞嗗畬鎴?                    await asyncio.sleep(1.0)
                # 姣忔鍚姩鍓嶉兘纭繚绔彛鍙敤锛屽苟灏濊瘯娓呯悊鍚岀敤鎴风殑 ssh 鍗犵敤
                if ports and not await self._ensure_ports_free(ports):
                    self.state["tunnel_status"] = "error"
                    return
                cmd = self.build_tunnel_command()
            except Exception as exc:
                logger.error("鏃犳硶鏋勫缓闅ч亾鍛戒护: %s", exc)
                self.state["tunnel_status"] = "error"
                return

            logger.info("鍚姩 SSH 闅ч亾: %s", " ".join(cmd))
            proc = await asyncio.create_subprocess_exec(*cmd)
            self._tunnel_process = proc
            self.state["tunnel_status"] = "running"
            self._tunnel_started_once = True

    async def stop_tunnel(self) -> None:
        """鍋滄闅ч亾骞舵竻鐞嗙姸鎬併€?""
        async with self._proc_lock:
            proc = self._tunnel_process
            if not proc:
                return
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    proc.kill()
            self.state["tunnel_last_exit"] = dt.datetime.now()
            self.state["tunnel_status"] = "stopped"
            self._tunnel_process = None

    async def restart_tunnel(self) -> None:
        """閲嶅惎闅ч亾浠ュ埛鏂拌浆鍙戝苟娓呯悊绔彛銆?""
        await self.stop_tunnel()
        await self.start_tunnel()

    async def maintain_tunnel(self) -> None:
        """淇濇寔闅ч亾瀛樻椿锛屽紓甯搁€€鍑哄悗鑷姩閲嶅惎銆?""
        while not self._stop_requested:
            await self.start_tunnel()
            proc = self._tunnel_process
            if proc is None:
                await asyncio.sleep(3)
                continue
            try:
                rc = await proc.wait()
                if rc == 0:
                    self._tunnel_failure_count = 0
                    logger.info("SSH 闅ч亾姝ｅ父閫€鍑恒€?)
                else:
                    self._tunnel_failure_count += 1
                    logger.warning("SSH 闅ч亾閫€鍑虹爜 %s锛涚◢鍚庨噸鍚€傦紙杩炵画澶辫触娆℃暟锛?s锛?, rc, self._tunnel_failure_count)
                    # 澶氭澶辫触鍚庡皾璇曢噸鏂板埛鏂板鍣?IP锛屽啀閲嶈瘯闅ч亾
                    if self._tunnel_failure_count >= 3:
                        name = self._acs_cfg(reload=True).get("container_name")
                        logger.warning("SSH 闅ч亾杩炵画澶辫触 >=3 娆★紝灏濊瘯閫氳繃 API 鍒锋柊瀹瑰櫒 IP锛堝鍣細%s锛夈€?, name)
                        self.resolve_container_ip(force_login=True)
                        self._tunnel_failure_count = 0
            except Exception as exc:  # pragma: no cover - 瀛愯繘绋嬪紓甯?                logger.error("SSH 闅ч亾宕╂簝: %s", exc)
            finally:
                await self.stop_tunnel()
            await asyncio.sleep(3)

    async def shutdown(self) -> None:
        """閫氱煡寰幆閫€鍑哄苟鍏抽棴闅ч亾銆?""
        self._stop_requested = True
        await self.stop_tunnel()

    def snapshot(self) -> Dict[str, Any]:
        """鑾峰彇褰撳墠鐘舵€侊紙渚?Web UI 灞曠ず锛夈€?""
        return dict(self.state)

    def _acs_cfg(self, *, reload: bool = False) -> Dict[str, Any]:
        return self.store.get_section("acs", default={}, reload=reload)

    def _ssh_cfg(self, *, reload: bool = False) -> Dict[str, Any]:
        return self.store.get_section("ssh", default={}, reload=reload)
