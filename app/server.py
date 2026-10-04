# -*- coding: utf-8 -*-
"""
监控编排 + HTTP API 服务

· 后台线程按周期刷新进程快照与系统制品
· 数字签名校验在独立线程增量执行（首次较慢，之后命中缓存）
· 对高危进程追加深度扫描（加载模块 → 白加黑 / IOC DLL）
· 通过 stdlib ThreadingHTTPServer 暴露 JSON API 与静态页面
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import sys
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import collector
import integrity
import iocs
import paths
import whitelist
import rules
import winapi

# 兼容 PyInstaller 单文件打包后的资源路径
if getattr(sys, "frozen", False):
    APP_DIR = os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))), "app")
    PROGRAM_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
    PROGRAM_DIR = paths.PROGRAM_DIR

# WORKSPACE = 运行期数据目录（用户可写），**不是**程序目录。
# 分离原因见 paths.py：程序目录会被收紧为仅管理员可写，运行期数据必须另放。
WORKSPACE = paths.DATA_DIR
WEB_DIR = os.path.join(APP_DIR, "web")
REPORT_DIR = paths.REPORT_DIR

# ---------------------------------------------------------------- 接口防护
# ⚠️ 安全：本地 HTTP 服务必须防跨站请求伪造（CSRF）。
# 审计发现：初版对 POST 不做任何来源校验，任何网页都能用
#     fetch('http://127.0.0.1:8787/api/kill', {method:'POST', mode:'no-cors',
#           body: JSON.stringify({pid: 1234})})
# 这种「简单请求」（Content-Type: text/plain，不触发预检）把请求送到服务端，
# 而服务端照单全收 —— 实测可成功终止任意进程，也就能调用 /api/shutdown 关停监视器。
# 对一个「反木马工具」来说这是致命的：恶意软件或钓鱼页面可以直接把它关掉。
#
# 四层校验（见 Handler._guard）：
#   1. 每次启动生成随机令牌，前端通过 <meta> 拿到，POST 必须带 X-Yinhu-Token 头。
#      自定义头会强制浏览器发预检请求，跨域预检必然失败 → 请求根本发不出来。
#   2. Origin 头必须同源（浏览器跨域请求必带 Origin）。
#   3. Host 头必须是回环地址（防 DNS 重绑定）。
#   4. Content-Type 必须是 application/json（挡掉表单与 text/plain 提交）。
#
# 2026-10-04 加固（详见《优化说明.md》对抗测试记录）：
#   · 令牌比较改为常数时间（hmac.compare_digest）；
#   · 请求体超限/非法一律 400（初版超限后仍继续执行 /api/shutdown）；
#   · /api/kill 显式拒绝结束监视器自身；
#   · /api/shutdown 延迟 0.3s 关停，保证响应送达（初版连接被重置）；
#   · /static/ 路径穿越改为 realpath 前缀锚定（初版 startswith 可被
#     「web 前缀兄弟目录」绕过，实测读到了越界文件）；
#   · /api/ping 增加实例密钥（instance.secret），启动器的单实例探测
#     不再能被"伪造 ping 响应"欺骗（初版 APP_ID 是源码常量，人人可伪造）。
#   · 令牌对本地同权限进程仍然是可见的（它就在首页 HTML 里）——这是用户态
#     工具的固有上限，见 README 第九节，这里只保证"远程网页"打不进来。
SESSION_TOKEN = secrets.token_urlsafe(24)
MAX_BODY = 256 * 1024
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
PROTECTED_PIDS = {0, 4}      # System Idle / System，绝不允许通过接口结束

APP_ID = "yinhu-sentinel"
PORT_RANGE = range(8787, 8817)


def _load_instance_secret(workspace: str) -> str:
    """实例密钥：首次运行时生成并落盘，用于 /api/ping 的实例身份验证。"""
    p = os.path.join(workspace, "instance.secret")
    try:
        with open(p, "r", encoding="ascii") as f:
            s = f.read().strip()
        if s:
            return s
    except Exception:
        pass
    s = secrets.token_urlsafe(24)
    try:
        with open(p, "w", encoding="ascii") as f:
            f.write(s)
    except Exception:
        pass
    return s


INSTANCE_SECRET = _load_instance_secret(WORKSPACE)


class Monitor:
    def __init__(self, proc_interval: float = 3.0, artifact_interval: float = 180.0):
        self.lock = threading.RLock()
        self.proc_interval = proc_interval
        self.artifact_interval = artifact_interval

        self.procs: list[dict] = []
        self.artifacts: dict = {}
        self.artifact_findings: list[dict] = []
        self.sig_cache: dict[str, dict] = {}
        self.pending_sig: set[str] = set()
        self.deep_done: set[tuple] = set()
        self._deep_retry: dict[tuple, int] = {}   # 深度扫描"等签名结果"的重试计数
        self.alerts: list[dict] = []
        self.known: dict[int, float] = {}       # pid -> create_time（用于识别新进程）
        self.first_seen_at = time.time()
        self.last_scan = 0.0
        self.last_artifact_scan = 0.0
        self.scan_ms = 0
        self.scan_count = 0
        self.running = True
        self.status = "初始化中"
        self.artifact_busy = False
        self.sig_busy = False
        self._running_jobs: set[str] = set()
        self.bind_addr = "127.0.0.1:?"
        self.integrity: dict = {}
        self.last_integrity = 0.0
        self.integrity_interval = 300.0
        self.artifact_whitelisted = 0

        # 先把已知项文件建出来，再做完整性校验。
        # whitelist.json 位于 app/ 下、被基线覆盖；若首次启动时它还不存在，
        # 校验会报 removed → 界面显示"程序文件已被改动"（实测踩过）。
        try:
            whitelist.load()
        except Exception:
            pass

    # ------------------------------------------------------------ 主循环
    def start(self):
        threading.Thread(target=self._loop, daemon=True, name="scan-loop").start()
        threading.Thread(target=self._sig_worker, daemon=True, name="sig-worker").start()

    def _loop(self):
        # 首轮：制品 + 进程 + 完整性
        self._safe(self.check_integrity)
        self._safe(self.scan_artifacts)
        self._safe(self.scan_processes)
        while self.running:
            t0 = time.time()
            self._safe(self.scan_processes)
            if time.time() - self.last_artifact_scan > self.artifact_interval:
                self._spawn_once("artifact", self.scan_artifacts)
            if time.time() - self.last_integrity > self.integrity_interval:
                self._spawn_once("integrity", self.check_integrity)
            time.sleep(max(0.2, self.proc_interval - (time.time() - t0)))

    def _refresh_integrity_baseline(self) -> list[str] | None:
        """界面合法增删已知项后刷新基线 —— **只接受 whitelist.json 的差异**。

        ⚠️ 这里曾经是全量重建（把 app/ 下所有文件的哈希重算一遍整体覆盖），
        那是个严重的漏洞：攻击者改掉 rules.py（删检测规则）后，
        用户只要对**任何一条无关告警**点一次"加入已知项"，
        篡改就被写进新基线、告警消失 —— 触发动作完全日常，用户毫不知情。

        现在的语义：除 whitelist.json 之外的任何差异（改动 / 新增 / 缺失）
        都**拒绝刷新**，保留完整性告警，并把差异清单返回给调用方展示。
        全量重建只保留给界面上那个显式按钮（用户明确知道自己在做什么）。

        返回 None 表示刷新成功；返回非空列表表示被拒绝，内容是差异文件。
        """
        try:
            cur = integrity.collect_manifest(APP_DIR, self._integrity_extras())
            base = integrity.load_baseline(WORKSPACE)
            if not base:
                # 没有基线（首次运行）→ 正常建立
                integrity.save_baseline(WORKSPACE, cur, app_dir=APP_DIR,
                                            note="界面修改已知项后自动刷新")
                self._integrity_alerted = False
                self.check_integrity()
                return None

            old = base.get("files", {}) or {}
            removed = sorted(k for k in old if k not in cur)
            if removed:
                return ["（缺失）" + r for r in removed]
            changed = sorted(k for k in cur if k in old and cur[k] != old[k])
            added = sorted(k for k in cur if k not in old)
            unexpected = [k for k in changed + added if k != "whitelist.json"]
            if unexpected:
                return unexpected

            integrity.save_baseline(WORKSPACE, cur, app_dir=APP_DIR,
                                            note="界面修改已知项后自动刷新")
            self._integrity_alerted = False
            self.check_integrity()
            return None
        except Exception:
            return ["（内部错误）基线刷新失败"]

    @staticmethod
    def _integrity_extras() -> list[str]:
        """完整性校验要覆盖的「app/ 之外」的文件。

        为什么必须包含 python_path.txt：启动器会执行它里面写的解释器路径，
        而它原先不在基线覆盖范围内 —— 能写项目根目录的人改掉它，
        用户下次双击启动器就执行了攻击者的程序（且监视器根本不会启动，
        自检告警永远不出现）。把它纳入基线后，改动会触发「程序文件已被改动」。
        """
        extra: list[str] = []
        if getattr(sys, "frozen", False):
            extra.append(sys.executable)
        # 启动器会执行 python_path.txt 里写的解释器 —— 必须纳入基线，
        # 否则改掉它就能让启动器执行攻击者的程序，且监视器根本不会启动。
        if os.path.isfile(paths.PYTHON_PATH_FILE):
            extra.append(paths.PYTHON_PATH_FILE)
        # whitelist.json 移到了数据目录，不再被 app/ 遍历覆盖，需显式加入
        if os.path.isfile(whitelist.WHITELIST_FILE):
            extra.append(whitelist.WHITELIST_FILE)
        return extra

    def check_integrity(self):
        """校验程序自身文件是否被改动。结果会出现在界面的「安全状态」里。"""
        res = integrity.verify(APP_DIR, WORKSPACE, self._integrity_extras())
        with self.lock:
            self.integrity = res
            self.last_integrity = time.time()
            # 加固：基线文件被删除（baseline_lost）与文件被改动（changed）同等告警 ——
            # 初版会把"基线没了"当成首次运行，静默重建基线，攻击者只需删一个文件
            # 就能让完整性告警永远哑火。
            if res.get("status") in ("changed", "baseline_lost") and \
                    not getattr(self, "_integrity_alerted", False):
                self._integrity_alerted = True
                self.alerts.insert(0, {
                    "time": time.strftime("%H:%M:%S"),
                    "ts": time.time(),
                    "level": "critical",
                    "score": 100,
                    "name": "本程序文件完整性异常",
                    "pid": 0,
                    "exe": "、".join((res.get("changed") or [])[:3])
                           or (res.get("status_zh") or "见安全状态"),
                    "rules": [{"id": "SELF", "title": "程序文件已被改动/基线丢失",
                               "severity": "critical",
                               "evidence": "被修改：" + "、".join(res.get("changed") or [])
                                           + "\n新增：" + "、".join(res.get("added") or [])
                                           + "\n缺失：" + "、".join(res.get("removed") or [])
                                           + ("\n基线状态：" + res.get("status_zh", "")
                                              if res.get("status") == "baseline_lost" else "")}],
                    "text": "本程序文件与首次运行时的基线不一致，检测规则可能已被篡改",
                })
                del self.alerts[200:]

    def accept_integrity(self):
        """用户确认改动是自己做的 → 重建基线。"""
        extra = [sys.executable] if getattr(sys, "frozen", False) else []
        m = integrity.collect_manifest(APP_DIR, extra)
        integrity.save_baseline(WORKSPACE, m, app_dir=APP_DIR,
                                        note="用户从界面确认并重建")
        integrity.save_sentinel(WORKSPACE, m, APP_DIR)
        self._integrity_alerted = False
        self.check_integrity()
        return True

    def _spawn_once(self, name: str, fn):
        """单飞守卫：同一类后台任务同时只允许一个实例在跑。
        初版无条件起线程，若某轮耗时超过间隔就会堆积（审计中曾观察到并发叠加）。"""
        with self.lock:
            if name in self._running_jobs:
                return False
            self._running_jobs.add(name)

        def _run():
            try:
                self._safe(fn)
            finally:
                with self.lock:
                    self._running_jobs.discard(name)
        threading.Thread(target=_run, daemon=True, name=f"job-{name}").start()
        return True

    @staticmethod
    def _safe(fn, *a, **kw):
        try:
            return fn(*a, **kw)
        except Exception:
            traceback.print_exc()
            return None

    # ------------------------------------------------------------ 采集
    def scan_processes(self):
        t0 = time.time()
        procs = collector.collect_processes(self.sig_cache)
        with self.lock:
            self.procs = procs
            for p in procs:
                exe = p.get("exe")
                if exe and exe.lower() not in self.sig_cache:
                    self.pending_sig.add(exe)
            self._score_all()
            self._detect_new_processes()
            self.last_scan = time.time()
            self.scan_ms = int((time.time() - t0) * 1000)
            self.scan_count += 1
            self.status = "运行中"
        self._spawn_once("deep", self._deep_scan_cycle)

    def scan_artifacts(self):
        self.artifact_busy = True
        try:
            art = collector.collect_artifacts()
            with self.lock:
                self.artifacts = art
                self._queue_artifact_binaries(art)
                self._score_artifacts()
                self.last_artifact_scan = time.time()
                self._alert_artifacts(self.artifact_findings)
        finally:
            self.artifact_busy = False

    def _queue_artifact_binaries(self, art: dict):
        """把服务 / 驱动 / 计划任务 / 启动项引用的二进制纳入签名校验队列。
        没有这一步，S004、R005 这类"随机命名 + 未签名"的组合规则就无从判断。"""
        cands: list[str] = []
        for s in art.get("services", []):
            cands.append(rules.bin_from_binpath(s.get("binpath", "")))
        for d in art.get("drivers", []):
            cands.append(d.get("path", ""))
        for t in art.get("tasks", []):
            for a in t.get("actions", []):
                cands.append(os.path.expandvars(a.get("exec", "") or ""))
        for f in art.get("startup", []):
            cands.append(f.get("path", ""))
        for c in cands:
            if c and os.path.isfile(c) and c.lower() not in self.sig_cache:
                self.pending_sig.add(c)

    def _score_artifacts(self):
        art = self.artifacts or {}
        af = (rules.rules_tasks(art) +
              rules.rules_services(art, self.sig_cache) +
              rules.rules_drivers(art) +
              rules.rules_hosts(art) +
              rules.rules_registry(art, self.sig_cache) +
              rules.rules_filesystem(art))
        # 已知项过滤（制品类：任务/服务/驱动/hosts/注册表/文件系统）
        wl = whitelist.load()
        kept, suppressed = [], 0
        for item in af:
            fs, dropped = whitelist.filter_findings(item.get("findings", []), item, wl)
            if dropped:
                suppressed += len(dropped)
                if not fs:
                    continue                      # 全部被忽略 → 不再显示该项
                item = {**item, "findings": fs, "whitelisted": len(dropped)}
                item["score"], item["level"] = rules.score_findings(fs)
            kept.append(item)
        kept.sort(key=lambda x: -x["score"])
        self.artifact_findings = kept
        self.artifact_whitelisted = suppressed

    def _deep_scan_cycle(self, limit: int = 4):
        """对高危进程追加深度扫描（加载模块检查）。"""
        with self.lock:
            targets = [p for p in self.procs
                       if p.get("level") in ("critical", "high")
                       and (p["pid"], p.get("create_time")) not in self.deep_done][:limit]
            ctx = self._ctx()
        if not targets:
            return
        changed = False
        for p in targets:
            key = (p["pid"], p.get("create_time"))
            try:
                extra, pending = rules.deep_scan_process(p, ctx)
            except Exception:
                extra, pending = [], []
            with self.lock:
                if pending:
                    # 有模块尚未做签名校验：排队校验，本轮不定罪，等签名批次完成后再复查。
                    self.pending_sig.update(mp for mp in pending
                                            if mp.lower() not in self.sig_cache)
                    retries = self._deep_retry.get(key, 0) + 1
                    self._deep_retry[key] = retries
                    if retries < 4:
                        continue
                    # 重试耗尽（签名一直校验不出来）：按可疑处理，避免无限等待形成盲区
                    try:
                        extra, _ = rules.deep_scan_process(p, ctx, treat_unknown_as_bad=True)
                    except Exception:
                        pass
                self.deep_done.add(key)
                if extra:
                    p.setdefault("findings", []).extend(extra)
                    p["score"], p["level"] = rules.score_findings(p["findings"])
                    changed = True
        if changed:
            with self.lock:
                self.procs.sort(key=lambda x: -x["score"])

    # ------------------------------------------------------------ 评分
    def _ctx(self) -> dict:
        return {
            "by_pid": {p["pid"]: p for p in self.procs},
            "sig_cache": self.sig_cache,
            "artifacts": getattr(self, "artifacts", {}),
            "self_pid": os.getpid(),      # 用于排除本工具自己拉起的辅助进程
        }

    def _score_all(self):
        ctx = self._ctx()
        wl = whitelist.load()
        for p in self.procs:
            try:
                fs = rules.rules_process(p, ctx)
            except Exception:
                fs = []
            # 保留深度扫描已追加的规则
            for old in p.get("findings", []) or []:
                if old.get("rule_id", "").startswith("X") and old not in fs:
                    fs.append(old)
            # 已知项过滤：只忽略"规则号 + 匹配条件 + 守卫哈希"三者都命中的告警
            fs, dropped = whitelist.filter_findings(fs, p, wl)
            p["findings"] = fs
            p["whitelisted"] = len(dropped)
            p["score"], p["level"] = rules.score_findings(fs)
        self.procs.sort(key=lambda x: (-x["score"], x["name"].lower()))

    def _detect_new_processes(self):
        now_ids = {}
        for p in self.procs:
            now_ids[p["pid"]] = p.get("create_time") or 0
            ct = p.get("create_time") or 0
            prev = self.known.get(p["pid"])
            if prev is None and p["level"] in ("critical", "high") and ct > self.first_seen_at - 1:
                self._push_alert(p)
        self.known = now_ids

    def _push_alert(self, p: dict):
        top = sorted(p.get("findings", []), key=lambda f: -f["weight"])[:3]
        self.alerts.insert(0, {
            "time": time.strftime("%H:%M:%S"),
            "ts": time.time(),
            "level": p["level"],
            "score": p["score"],
            "name": p["name"],
            "pid": p["pid"],
            "exe": p.get("exe", ""),
            "rules": [{"id": f["rule_id"], "title": f["title"],
                       "severity": f["severity"], "evidence": f["evidence"]} for f in top],
            "text": f"新增{p['level']}级进程：{p['name']} (PID {p['pid']}) · " +
                    "；".join(f["title"] for f in top),
        })
        del self.alerts[200:]

    def _alert_artifacts(self, af: list[dict]):
        for a in af:
            if a["level"] not in ("critical", "high"):
                continue
            if any(x.get("artifact_id") == a["id"] for x in self.alerts[:80]):
                continue
            self.alerts.insert(0, {
                "time": time.strftime("%H:%M:%S"),
                "ts": time.time(),
                "level": a["level"],
                "score": a["score"],
                "name": a["title"],
                "pid": 0,
                "exe": a.get("subtitle", ""),
                "artifact_id": a["id"],
                "artifact_kind": a["kind"],
                "rules": [{"id": f["rule_id"], "title": f["title"],
                           "severity": f["severity"], "evidence": f["evidence"]}
                          for f in a["findings"][:3]],
                "text": f"[{a['kind']}] {a['title']} · " +
                        "；".join(f["title"] for f in a["findings"][:2]),
            })
        del self.alerts[200:]

    # ------------------------------------------------------------ 签名线程
    def _sig_worker(self):
        while self.running:
            batch = []
            with self.lock:
                while self.pending_sig and len(batch) < 50:
                    p = self.pending_sig.pop()
                    if p.lower() not in self.sig_cache:
                        batch.append(p)
            if not batch:
                time.sleep(1.5)
                continue
            self.sig_busy = True
            try:
                res = winapi.verify_signatures(batch)
                with self.lock:
                    self.sig_cache.update(res)
                    for p in batch:
                        if p.lower() not in self.sig_cache:
                            self.sig_cache[p.lower()] = {
                                "status": "UnknownError", "status_zh": "校验失败",
                                "kind": "unknown", "signer": "", "cn": "", "notafter": "",
                            }
                    self._score_all()
                    if self.artifacts:
                        self._score_artifacts()
            except Exception:
                traceback.print_exc()
            finally:
                self.sig_busy = False

    # ------------------------------------------------------------ 状态输出
    def state(self) -> dict:
        with self.lock:
            levels = {"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0}
            for p in self.procs:
                levels[p.get("level", "clean")] = levels.get(p.get("level", "clean"), 0) + 1
            conns = sum(len(p.get("connections") or []) for p in self.procs)
            art = getattr(self, "artifacts", {}) or {}
            af = getattr(self, "artifact_findings", []) or []
            art_levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for a in af:
                if a["level"] in art_levels:
                    art_levels[a["level"]] += 1
            return {
                "summary": {
                    "total": len(self.procs),
                    "levels": levels,
                    "connections": conns,
                    "artifact_findings": len(af),
                    "whitelisted": (sum(p.get("whitelisted", 0) for p in self.procs)
                                    + getattr(self, "artifact_whitelisted", 0)),
                    "artifact_levels": art_levels,
                    "tasks": len(art.get("tasks", [])),
                    "services": len(art.get("services", [])),
                    "drivers": len(art.get("drivers", [])),
                    "hosts_entries": len(art.get("hosts", [])),
                    "scan_ms": self.scan_ms,
                    "scan_count": self.scan_count,
                    "last_scan": self.last_scan,
                    "uptime": round(time.time() - self.first_seen_at, 0),
                    "admin": winapi.is_admin(),
                    "status": self.status,
                    "sig_pending": len(self.pending_sig),
                    "artifact_busy": self.artifact_busy,
                    "sig_busy": self.sig_busy,
                    "defender_accessible": bool((art.get("defender") or {}).get("accessible")),
                    "ioc_version": iocs.IOC_VERSION,
                },
                "security": {
                    "bind": self.bind_addr,
                    "loopback_only": self.bind_addr.startswith("127.0.0.1"),
                    "token_enabled": True,
                    "post_guards": ["会话令牌 X-Yinhu-Token", "Origin 同源校验",
                                    "Host 回环校验（防 DNS 重绑定）",
                                    "Content-Type 必须为 application/json"],
                    "egress": "无 —— 只监听回环地址，不发起任何外部网络连接",
                    "data_leaves_machine": False,
                    "integrity": self.integrity or {"status": "pending",
                                                    "status_zh": "校验中…"},
                    "ioc_version": iocs.IOC_VERSION,
                    "ioc_sources": iocs.IOC_SOURCES,
                    "rule_count": len(_RULE_DOC),
                },
                                # 已知项随 state 一起下发：前端 poll() 会整体替换 STATE，
                # 单独 fetch 挂在 STATE 上的字段会被下一轮冲掉（实测踩过）。
                "whitelist": whitelist.listing(),
"processes": self.procs,
                "artifacts": af,
                "alerts": self.alerts[:100],
            }

    def process_detail(self, pid: int) -> dict:
        with self.lock:
            proc = next((p for p in self.procs if p["pid"] == pid), None)
        if not proc:
            return {"error": "进程不存在"}
        detail = collector.enrich_process(pid)
        hashes = {}
        exe = proc.get("exe")
        if exe and os.path.isfile(exe):
            hashes = {
                "md5": collector.file_hash(exe, "md5"),
                "sha256": collector.file_hash(exe, "sha256"),
                "magic": collector.file_magic(exe),
                "size": os.path.getsize(exe),
                "mtime": time.strftime("%Y-%m-%d %H:%M:%S",
                                       time.localtime(os.path.getmtime(exe))),
            }
        # 父进程链
        chain = []
        cur = proc
        seen = set()
        for _ in range(8):
            if not cur or cur["pid"] in seen:
                break
            seen.add(cur["pid"])
            chain.append({"pid": cur["pid"], "name": cur.get("name", ""),
                          "exe": cur.get("exe", "")})
            ppid = cur.get("ppid")
            if not ppid or ppid == cur["pid"]:
                break
            with self.lock:
                cur = next((p for p in self.procs if p["pid"] == ppid), None)
        return {"process": proc, "detail": detail, "hashes": hashes, "chain": chain}


# ================================================================
# HTTP 服务
# ================================================================

class Handler(BaseHTTPRequestHandler):
    monitor: Monitor = None
    server_version = "YinhuSentinel/1.0"

    def log_message(self, fmt, *args):    # 静音访问日志
        pass

    # ---------------- 工具 ----------------
    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if ctype.startswith("text/html"):
            # 加固：本地页面也加 CSP，即使将来前端出现注入点也无法执行外部脚本。
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self'; "
                             "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                             "connect-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _file(self, path: str):
        # 加固：路径穿越校验 —— 初版 startswith(WEB_DIR) 会被
        # 「web 前缀兄弟目录」（如 app\web2\…）绕过（活体攻击 L5 实测读到了越界文件）。
        # 改为 realpath + 分隔符锚定；realpath 同时解析 junction/symlink。
        try:
            real = os.path.realpath(path)
            real_web = os.path.realpath(WEB_DIR)
            if not (real == real_web or real.startswith(real_web + os.sep)):
                self._send(403, b"forbidden", "text/plain; charset=utf-8")
                return
        except Exception:
            self._send(403, b"forbidden", "text/plain; charset=utf-8")
            return
        if not os.path.isfile(real):
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
            ".json": "application/json; charset=utf-8",
        }.get(os.path.splitext(real)[1].lower(), "application/octet-stream")
        with open(real, "rb") as f:
            data = f.read()
        # index.html 里注入本次会话的令牌（跨域页面读不到它 —— 没有 CORS 头）
        if ctype.startswith("text/html"):
            data = data.replace(b"__YINHU_TOKEN__", SESSION_TOKEN.encode("ascii"))
        self._send(200, data, ctype)

    def _body(self) -> dict | None:
        """解析 JSON 请求体。缺失 / 非法 / 超限一律返回 None（调用方必须拒绝）。"""
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > MAX_BODY:
                return None
            data = json.loads(self.rfile.read(n).decode("utf-8"))
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    def _guard(self) -> bool:
        """POST 请求的四层来源校验。任一层不过直接 403。"""
        # compare_digest 对含非 ASCII 的字符串抛 TypeError。
        # 失败关闭没问题，但语义应是 403（令牌不对）而不是 500（服务端出错）。
        try:
            token_ok = hmac.compare_digest(self.headers.get("X-Yinhu-Token") or "",
                                           SESSION_TOKEN)
        except TypeError:
            token_ok = False
        if not token_ok:
            self._json({"ok": False, "msg": "拒绝：访问令牌缺失或不正确"}, 403)
            return False
        origin = self.headers.get("Origin")
        if origin:
            o = urlparse(origin)
            if o.hostname not in ALLOWED_HOSTS:
                self._json({"ok": False, "msg": "拒绝：请求来源不被允许"}, 403)
                return False
        host = (self.headers.get("Host") or "").split(":")[0].strip("[]")
        if host and host not in ALLOWED_HOSTS:
            self._json({"ok": False, "msg": "拒绝：Host 不被允许"}, 403)
            return False
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            self._json({"ok": False, "msg": "拒绝：Content-Type 必须为 application/json"}, 403)
            return False
        return True

    # ---------------- 路由 ----------------
    def do_GET(self):
        u = urlparse(self.path)
        p = u.path
        q = parse_qs(u.query)
        m = self.monitor
        if p in ("/", "/index.html"):
            self._file(os.path.join(WEB_DIR, "index.html"))
        elif p.startswith("/static/"):
            rel = p[len("/static/"):]
            # 穿越校验在 _file 内完成（realpath 前缀锚定），这里只做拼接
            self._file(os.path.normpath(os.path.join(WEB_DIR, rel)))
        elif p == "/api/state":
            self._json(m.state())
        elif p == "/api/detail":
            try:
                pid = int(q.get("pid", ["0"])[0])
            except Exception:
                pid = 0
            self._json(m.process_detail(pid))
        elif p == "/api/rules":
            self._json(rule_catalog())
        elif p == "/api/iocs":
            self._json(ioc_catalog())
        elif p == "/api/whitelist":
            self._json(whitelist.listing())
        elif p == "/api/ping":
            # 供启动时探测"是否已有实例在运行"，避免重复双击开出多个监视器。
            # 加固：携带实例密钥，启动器只认带正确密钥的响应（见 main.find_running_instance）。
            self._json({"app": APP_ID, "version": iocs.IOC_VERSION,
                        "pid": os.getpid(), "secret": INSTANCE_SECRET})
        else:
            self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self):
        # 兜底：任何处理分支抛异常时，返回 JSON 错误而不是空响应。
        # 空响应在客户端看来只是"连接被重置"，极难定位（本工具开发时就踩过一次）。
        try:
            self._do_post()
        except Exception as e:
            traceback.print_exc()
            try:
                self._json({"ok": False, "msg": f"服务端处理异常：{type(e).__name__}: {e}"}, 500)
            except Exception:
                pass

    def _do_post(self):
        u = urlparse(self.path)
        p = u.path
        m = self.monitor
        if not self._guard():
            return
        body = self._body()
        if body is None:
            # 加固：请求体缺失/非法/超限一律 400，绝不在这种情况下执行写操作
            self._json({"ok": False, "msg": "拒绝：请求体缺失、无效或超过 256 KB 上限"}, 400)
            return
        if p == "/api/scan":
            threading.Thread(target=m._safe, args=(m.scan_processes,), daemon=True).start()
            threading.Thread(target=m._safe, args=(m.scan_artifacts,), daemon=True).start()
            self._json({"ok": True, "msg": "已触发全量重扫"})
        elif p == "/api/kill":
            try:
                pid = int(body.get("pid") or 0)
            except Exception:
                pid = 0
            if pid in PROTECTED_PIDS or pid <= 4 or pid == os.getpid():
                self._json({"ok": False, "msg": f"拒绝：PID {pid} 属受保护的系统进程或监视器自身"})
                return
            ok, msg = winapi.kill_process(pid) if pid else (False, "无效 PID")
            self._json({"ok": ok, "msg": msg})
        elif p == "/api/open":
            ok, msg = winapi.open_in_explorer(body.get("path") or "")
            self._json({"ok": ok, "msg": msg})
        elif p == "/api/export":
            try:
                path = export_report(m)
                self._json({"ok": True, "path": path,
                            "msg": f"报告已生成：{path}"})
            except Exception as e:
                self._json({"ok": False, "msg": f"导出失败：{e}"})
        elif p == "/api/integrity/accept":
            m.accept_integrity()
            self._json({"ok": True, "msg": "已按当前文件重建完整性基线"})
        elif p == "/api/whitelist/suggest":
            pid = int(body.get("pid") or 0)
            rid = str(body.get("rule_id") or "")
            subj, fnd = None, None
            for x in m.procs:
                if x["pid"] == pid:
                    subj = x
                    for f in x.get("findings", []):
                        if f.get("rule_id") == rid:
                            fnd = f
                            break
                    break
            if subj is None:
                for a in m.artifact_findings:
                    if str(a.get("id")) == str(body.get("artifact_id") or ""):
                        subj = a
                        for f in a.get("findings", []):
                            if f.get("rule_id") == rid:
                                fnd = f
                                break
                        break
            if not subj or not fnd:
                self._json({"ok": False, "msg": "未找到对应的告警对象"})
                return
            self._json({"ok": True, "suggest": whitelist.suggest(subj, fnd)})
        elif p == "/api/whitelist/add":
            rid = str(body.get("rule_id") or "")
            m2 = body.get("match") or {}
            mtype = str(m2.get("type") or "rule_only")
            mvalue = str(m2.get("value") or "")

            # 入参校验：否则可以构造"全量豁免"条目 ——
            # 例如 exe_path_prefix + 空 value（"任意路径".startswith("") 恒真）
            # 会让某条规则对所有进程永久失效。
            known_rules = {r[0] for r in _RULE_DOC}
            if rid not in known_rules:
                self._json({"ok": False, "msg": f"未知规则号：{rid or '(空)'}"}, 400)
                return
            if mtype not in whitelist.MATCH_TYPES:
                self._json({"ok": False,
                            "msg": f"不支持的匹配方式：{mtype}"}, 400)
                return
            if mtype != "rule_only" and not mvalue.strip():
                self._json({"ok": False,
                            "msg": "匹配条件不能为空——空值会让该规则对所有对象失效"}, 400)
                return

            e = whitelist.add(rid, mtype, mvalue,
                              str((body.get("guard") or {}).get("file") or ""),
                              str(body.get("note") or ""))
            blocked = m._refresh_integrity_baseline()
            if blocked:
                self._json({"ok": True, "entry": e, "integrity_refresh": "blocked",
                            "changed_files": blocked,
                            "msg": "已加入已知项；但完整性基线刷新被拒绝——"
                                   "检测到其它程序文件与基线不一致，请先在「安全状态」中处理"})
            else:
                self._json({"ok": True, "entry": e,
                            "msg": "已加入已知项，该告警不再显示"})
        elif p == "/api/whitelist/remove":
            ok = whitelist.remove(str(body.get("id") or ""))
            blocked = m._refresh_integrity_baseline()
            if blocked:
                self._json({"ok": ok, "integrity_refresh": "blocked",
                            "changed_files": blocked,
                            "msg": "已移除；但完整性基线刷新被拒绝——"
                                   "检测到其它程序文件与基线不一致，请先在「安全状态」中处理"})
            else:
                self._json({"ok": ok, "msg": "已移除" if ok else "未找到该条目"})
        elif p == "/api/shutdown":
            self._json({"ok": True, "msg": "监视器正在退出"})
            # 加固：延迟 0.3s 再关停，保证响应送达（初版立即 shutdown，
            # 实测客户端收到连接重置而不是响应）
            threading.Timer(0.3, self.server.shutdown).start()
        else:
            self._send(404, b"not found", "text/plain; charset=utf-8")


# ================================================================
# 规则 / IOC 目录（供界面展示）
# ================================================================

_RULE_DOC = [
    ("P001", "伪装系统进程", "critical", "进程名是系统进程名但不在系统目录"),
    ("P002", "父进程异常（PPID 欺骗）", "high", "系统进程由非系统目录的程序拉起"),
    ("P002B", "系统父进程下的非常规子进程", "high", "未签名程序挂在系统父进程名下（银狐伪造进程树）"),
    ("P003", "数字签名伪造（摘要校验失败）", "critical", "内嵌签名但文件摘要不符"),
    ("P004", "使用被滥用/伪造的签名主体", "critical", "签名主体命中银狐滥用名单"),
    ("P005", "未签名程序持有对外连接", "medium", "无签名 + ESTABLISHED 外联"),
    ("P006", "程序运行于用户可写目录", "medium", "Users\\Public / ProgramData / Temp 等"),
    ("P007", "随机化程序名", "medium", "5–12 位大小写混杂、非英文单词"),
    ("P008", "可执行文件伪装扩展名", "high", "运行中进程的扩展名非可执行类型"),
    ("P009", "命令行写入 Defender 排除项", "critical", "Add-MpPreference -ExclusionPath"),
    ("P010", "命令行内存加载 / 下载执行", "high", "IEX / DownloadString / FromBase64String"),
    ("P010B", "命令行使用 Base64 编码执行", "medium", "-EncodedCommand（正规运维也常用，故权重较低）"),
    ("P011", "命令行静默绕过 PowerShell 策略", "medium", "-ExecutionPolicy Bypass + 隐藏/无配置/脚本文件"),
    ("P012", "命令行注册 SYSTEM 级计划任务", "high", "Register-ScheduledTask -Xml / schtasks /ru system"),
    ("P013", "命令行破坏系统恢复/日志/防火墙", "high", "vssadmin delete shadows / wevtutil cl"),
    ("P014", "命令行终止安全软件进程", "critical", "taskkill 目标为安全软件"),
    ("P015", "命令行写入注册表启动项", "high", "reg add ...\\Run"),
    ("P016", "连接已知银狐 C2", "critical", "IP 命中公开 C2 清单"),
    ("P017", "未签名程序连接银狐常用非标端口", "high", "18300 / 7000 / 8001 等（仅未签名进程）"),
    ("P018", "命中银狐传播/C2 域名", "critical", "域名命中公开 IOC"),
    ("P019", "非常规进程直连公共 DNS", "medium", "疑似 DoH 隐蔽信道"),
    ("P020", "进程名命中银狐 IOC", "critical", "文件名命中公开样本清单"),
    ("P021", "进程路径命中银狐 IOC 目录特征", "critical", "Users\\Public\\<随机>\\ 等"),
    ("P022", "运行于 Program Files 下的随机目录", "high", "Program Files (x86)\\<随机名>\\"),
    ("P024", "程序位于开机启动目录", "high", "Startup 目录"),
    ("P025", "非常规程序监听端口", "high", "无签名 + 用户目录 + LISTEN"),
    ("T001", "计划任务名命中银狐 IOC", "critical", "任务名字面命中"),
    ("T002", "冒用系统更新任务名", "critical", "MicrosoftEdgeUpdateTask* 但目标非官方目录"),
    ("T003", "隐藏的高频计划任务指向非常规目录", "high", "Hidden + ≤30min + 用户目录/随机目录"),
    ("T004", "计划任务执行目标位于非常规目录", "high", "Users\\Public / ProgramData / 随机目录"),
    ("T005", "计划任务名为长英文语句", "medium", "AI 批量生成的废话任务名"),
    ("T008", "计划任务以隐藏方式执行脚本且目标在用户可写位置", "high",
     "powershell/cmd/wscript + 隐藏窗口标志 + 脚本或工作目录在用户可写目录"),
    ("T006", "高权限计划任务指向非常规目录", "high", "Highest + 非常规目录"),
    ("T007", "任务存放于系统任务路径但名称非系统组件", "medium", "\\Microsoft\\Windows\\AppID\\"),
    ("S001", "服务二进制命中银狐 IOC", "critical", "文件名命中"),
    ("S002", "服务二进制位于用户可写目录", "high", "非常规服务路径"),
    ("S003", "服务指向伪装扩展名文件", "high", ".jpg/.dat/.db 等"),
    ("S004", "服务指向随机命名程序", "medium", "随机名服务二进制"),
    ("D001", "加载了已知易受攻击驱动", "critical", "BYOVD 驱动名单"),
    ("D002", "驱动文件名命中银狐 IOC", "critical", "文件名命中"),
    ("D003", "驱动文件位于用户可写目录", "high", "非 System32\\drivers"),
    ("D004", "驱动文件伪装扩展名", "critical", "ranchserv.jpg 类"),
    ("H001", "安全厂商域名被劫持到回环地址", "critical", "hosts 劫持"),
    ("H002", "hosts 存在指向回环地址的条目", "medium", "需人工核对"),
    ("R001", "Defender 排除项包含大范围系统目录", "critical", "C:\\Users / C:\\ProgramData 等"),
    ("R002", "Defender 排除了银狐相关进程", "critical", "xwizard.exe / wuauclt.exe"),
    ("R003", "存在银狐专用注册表键", "critical", "HKLM\\SOFTWARE\\JDBCC"),
    ("R004", "注册表启动项指向用户可写目录", "high", "Run 键异常路径"),
    ("R004B", "注册表启动项命中银狐路径 IOC", "critical", "Run 键值命中公开路径特征（如 Adobe\\h<数字>.ini）"),
    ("R005", "开机启动目录存在可疑文件", "high", "随机名 / 伪装扩展名"),
    ("F001", "发现伪装扩展名的可执行文件", "critical", "扩展名与 PE 头不符"),
    ("F002", "发现银狐 IOC 文件名", "critical", "文件名命中"),
    ("F003", "发现银狐组合落地目录", "critical", "edge.xml + edge.jpg + 随机 exe"),
    ("X001", "加载银狐 IOC 模块", "critical", "内存模块命中"),
    ("X002", "加载伪装扩展名的可执行模块", "critical", "内存中 PE 伪装"),
    ("X003", "疑似白加黑侧加载", "high", "进程目录下的未签名 DLL"),
]


def rule_catalog() -> list[dict]:
    return [{"rule_id": r, "title": t, "severity": s,
             "severity_zh": rules.SEVERITY_ZH[s], "desc": d}
            for r, t, s, d in _RULE_DOC]


def ioc_catalog() -> dict:
    import iocs
    return {
        "version": iocs.IOC_VERSION,
        "sources": iocs.IOC_SOURCES,
        "domains": iocs.MALICIOUS_DOMAINS,
        "ips": iocs.MALICIOUS_IPS,
        "ports": iocs.SUSPICIOUS_PORTS,
        "filenames": iocs.MALICIOUS_FILENAMES,
        "task_names": iocs.MALICIOUS_TASK_NAMES,
        "drivers": iocs.VULNERABLE_DRIVERS,
        "signers": iocs.ABUSED_SIGNERS,
        "hosts_targets": iocs.HOSTS_HIJACK_DOMAINS,
        "reg_keys": iocs.MALICIOUS_REG_KEYS,
    }


# ================================================================
# 报告导出
# ================================================================

def export_report(m: Monitor) -> str:
    import iocs
    os.makedirs(REPORT_DIR, exist_ok=True)
    st = m.state()
    s = st["summary"]
    ts = time.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(REPORT_DIR, f"银狐排查报告-{ts}.html")

    def esc(x):
        return (str(x).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

    rows = []
    for p in st["processes"]:
        if p["level"] == "clean":
            continue
        rows.append(
            "<tr>"
            f"<td class='sev {p['level']}'>{rules.SEVERITY_ZH.get(p['level'],'')}</td>"
            f"<td>{p['score']}</td><td>{p['pid']}</td><td>{esc(p['name'])}</td>"
            f"<td class='path'>{esc(p['exe'])}</td>"
            f"<td>{esc(rules.sig_label(p))}</td>"
            f"<td>{esc('；'.join(f['title'] for f in p['findings']))}</td>"
            "</tr>")
    arows = []
    for a in st["artifacts"]:
        arows.append(
            "<tr>"
            f"<td class='sev {a['level']}'>{rules.SEVERITY_ZH.get(a['level'],'')}</td>"
            f"<td>{a['score']}</td><td>{esc(a['kind'])}</td><td>{esc(a['title'])}</td>"
            f"<td class='path'>{esc(a.get('subtitle',''))}</td>"
            f"<td>{esc('；'.join(f['title'] for f in a['findings']))}</td>"
            "</tr>")

    detail_blocks = []
    for p in st["processes"]:
        if p["level"] not in ("critical", "high"):
            continue
        items = "".join(
            f"<li><b>[{f['rule_id']}] {esc(f['title'])}</b>"
            f"<div class='ev'>{esc(f['evidence'])}</div>"
            f"<div class='ad'>{esc(f['advice'])}</div></li>"
            for f in p["findings"])
        detail_blocks.append(
            f"<div class='card'><h3>{esc(p['name'])} <span class='pid'>PID {p['pid']}</span>"
            f"<span class='sev {p['level']}'>{rules.SEVERITY_ZH.get(p['level'],'')} · {p['score']}分</span></h3>"
            f"<div class='path'>{esc(p['exe'])}</div>"
            f"<div class='path'>命令行：{esc(p['cmdline_str'][:300])}</div>"
            f"<ul>{items}</ul></div>")

    html = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>银狐进程排查报告 {ts}</title>
<style>
 body{{background:#0b1220;color:#dbe6f3;font:14px/1.7 "Microsoft YaHei",system-ui,sans-serif;
   margin:0;padding:32px 40px}}
 h1{{font-size:22px;margin:0 0 4px}} h2{{font-size:16px;margin:28px 0 10px;
   border-left:3px solid #3b82f6;padding-left:10px}}
 h3{{font-size:15px;margin:0 0 6px;display:flex;gap:10px;align-items:center}}
 .meta{{color:#7d8fa9;font-size:13px;margin-bottom:18px}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0}}
 .kpi{{background:#121c2e;border:1px solid #1e2d45;border-radius:10px;padding:12px 14px}}
 .kpi b{{display:block;font-size:24px;color:#e8f0fb}} .kpi span{{color:#7d8fa9;font-size:12px}}
 table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}}
 th,td{{border-bottom:1px solid #1c2942;padding:7px 8px;text-align:left;vertical-align:top}}
 th{{background:#101a2b;color:#8fa6c4;font-weight:600}}
 .path{{font-family:Consolas,monospace;font-size:12px;color:#9db4d0;word-break:break-all}}
 .sev{{font-weight:700;white-space:nowrap}}
 .sev.critical{{color:#ff5c5c}} .sev.high{{color:#ffa53d}}
 .sev.medium{{color:#ffd666}} .sev.low{{color:#63b3ff}}
 .card{{background:#111b2c;border:1px solid #1e2d45;border-radius:10px;
   padding:14px 16px;margin:10px 0}}
 .card ul{{margin:8px 0 0;padding-left:18px}} .card li{{margin-bottom:10px}}
 .ev{{color:#9db4d0;font-size:12.5px;white-space:pre-wrap;margin:2px 0}}
 .ad{{color:#6fbf8b;font-size:12.5px;margin-top:2px}}
 .pid{{color:#7d8fa9;font-size:12px;font-weight:400}}
 footer{{margin-top:32px;color:#5d6f88;font-size:12px;border-top:1px solid #1c2942;padding-top:12px}}
</style></head><body>
<h1>银狐（SilverFox）木马 · 主机排查报告</h1>
<div class="meta">生成时间 {time.strftime('%Y-%m-%d %H:%M:%S')} ·
 主机 {os.environ.get('COMPUTERNAME','')} ·
 用户 {os.environ.get('USERNAME','')} ·
 管理员权限：{'是' if s['admin'] else '否'} ·
 已扫描 {s['scan_count']} 轮 · IOC 版本 {iocs.IOC_VERSION}</div>

<div class="grid">
 <div class="kpi"><b>{s['total']}</b><span>进程总数</span></div>
 <div class="kpi"><b style="color:#ff5c5c">{s['levels']['critical']}</b><span>严重进程</span></div>
 <div class="kpi"><b style="color:#ffa53d">{s['levels']['high']}</b><span>高危进程</span></div>
 <div class="kpi"><b>{s['artifact_findings']}</b><span>系统制品异常</span></div>
 <div class="kpi"><b>{s['connections']}</b><span>网络连接</span></div>
</div>

<h2>一、结论摘要</h2>
<p>{'<b style="color:#ff5c5c">发现严重风险项，高度疑似银狐木马活动，请立即处置。</b>'
   if (s['levels']['critical'] or s['artifact_levels']['critical'])
   else ('<b style="color:#ffa53d">存在高危异常项，建议逐条核查。</b>'
   if (s['levels']['high'] or s['artifact_levels']['high'])
   else '本轮扫描未发现银狐相关高风险特征。注意：本工具基于行为特征，不能替代杀毒软件全盘扫描。')}</p>

<h2>二、异常进程（按风险分排序）</h2>
<table><tr><th>等级</th><th>评分</th><th>PID</th><th>名称</th><th>路径</th>
<th>签名</th><th>命中规则</th></tr>{''.join(rows) or '<tr><td colspan="7">无</td></tr>'}</table>

<h2>三、系统制品异常（计划任务 / 服务 / 驱动 / hosts / 注册表 / 文件）</h2>
<table><tr><th>等级</th><th>评分</th><th>类型</th><th>对象</th><th>位置</th>
<th>命中规则</th></tr>{''.join(arows) or '<tr><td colspan="6">无</td></tr>'}</table>

<h2>四、高危进程详情与处置建议</h2>
{''.join(detail_blocks) or '<p>无</p>'}

<footer>本报告由「银狐进程监视器」自动生成。检测规则依据 CNCERT/天融信、FreeBuf、火绒安全实验室、
先知社区等公开技术报告编制；IOC 会随木马迭代失效，请定期更新。<br>
本工具为行为检测辅助工具，无法覆盖纯内存执行、内核级隐藏等场景，不能替代专业 EDR 与杀毒软件。</footer>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


# ================================================================
# 启动
# ================================================================

def serve(host: str = "127.0.0.1", port: int = 8787,
          proc_interval: float = 3.0, artifact_interval: float = 180.0) -> ThreadingHTTPServer:
    m = Monitor(proc_interval=proc_interval, artifact_interval=artifact_interval)
    m.bind_addr = f"{host}:{port}"
    m.start()
    Handler.monitor = m
    srv = ThreadingHTTPServer((host, port), Handler)
    return srv, m


def main():
    srv, m = serve()
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    print(f"[银狐进程监视器] 服务已启动：{url}")
    webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
