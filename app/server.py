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

import auditlog
import collector
import integrity
import iocs
import netmon
import paths
import watch
import whitelist
import rules
import version
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
    # 进程扫描间隔默认值。
    # 2026-10-07 由 3.0 降到 1.0 —— 用户反馈"扫描速度太慢"。
    # 依据：实测单轮进程扫描 180–215 ms，3 秒一轮时**每轮有约 2.8 秒是空的**；
    # 改成 1 秒后每秒都有一次新快照，单核占用约 18%（原来约 9%），
    # 短命进程的漏报窗口也从 3 秒缩到 1 秒。
    # 想更激进可以用 --proc-interval 0.2（循环下限，约等于背靠背连续扫描）。
    PROC_INTERVAL_DEFAULT = 1.0

    def __init__(self, proc_interval: float = PROC_INTERVAL_DEFAULT,
                 artifact_interval: float = 180.0,
                 net_interval: float = netmon.DEFAULT_SAMPLE_INTERVAL,
                 net_duration: float = netmon.DEFAULT_DURATION,
                 net_enabled: bool = True):
        self.lock = threading.RLock()
        self.proc_interval = proc_interval
        self.artifact_interval = artifact_interval
        self.net_enabled = net_enabled
        self.net_duration = float(net_duration)

        self.procs: list[dict] = []
        self.artifacts: dict = {}
        self.artifact_findings: list[dict] = []
        self.sig_cache: dict[str, dict] = {}
        # F-006：签名校验的连续失败次数（path -> 次数）。
        # 失败结果**不进 sig_cache**（否则本会话永不重试），改用这个可恢复的计数：
        # 3 次以内下一轮自动重试，超过后不再重试但会在界面上显示出来。
        self._sig_failed: dict[str, int] = {}
        self.pending_sig: set[str] = set()
        self.deep_done: set[tuple] = set()
        # 白加黑模块扫描结论的持久化存储：key=(pid, create_time) -> 结论字典。
        # 进程扫描每轮会重建全新的 proc 字典（见 scan_processes），深扫追加在旧对象上的
        # X 系列 findings 会在下一轮被冲掉；这里把结论单独固化，供 _score_all 与 netmon
        # 跨轮复用，使网络页的「白加黑侧加载」信号稳定不闪烁。
        self.mod_scan: dict[tuple, dict] = {}
        self._deep_retry: dict[tuple, int] = {}   # 深度扫描"等签名结果"的复查次数
        # 深度扫描时"因模块尚未完成签名校验而挂起"的进程：key -> {待验模块路径}。
        # ⚠️ 这是"先验签后定罪"能真正成立的**唯一**依据（2026-10-08 修复）。
        #    在此之前，代码靠 `_deep_retry` 计时（重试 4 次 ≈ 4 秒）来猜"验完了没有"，
        #    而首次运行签名队列积压 647 个文件、按实测 297 ms/文件需要约 3 分钟 ——
        #    计时器必然先到期，于是把 48 个**已正确签名**的同目录 DLL
        #    （Edge / 微信 / <workspace> / 网易 UU / Intel DSA）全部定罪成白加黑，
        #    界面上"一片爆红"。改为由 _sig_worker 在签名结果到达时释放复查。
        self._deep_pending: dict[tuple, set[str]] = {}
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

        # ---- 网络心跳检测引擎 ----
        # ⚠️ 锁序约定（防死锁，改动时务必遵守）：
        #     netmon 线程可能在持 netmon.lock 时通过告警回调去拿 self.lock，
        #     因此**任何持有 self.lock 的地方都不得再去取 netmon.lock**。
        #     具体地：state() 先取 netmon 快照再进 self.lock；
        #     scan_processes() 在释放 self.lock 之后才推送进程索引。
        self.netmon = netmon.NetMonitor(sample_interval=net_interval) if net_enabled else None
        if self.netmon is not None:
            self.netmon.alert_sink = self._net_alert

        # 先把已知项文件建出来，再做完整性校验。
        # whitelist.json 位于 app/ 下、被基线覆盖；若首次启动时它还不存在，
        # 校验会报 removed → 界面显示"程序文件已被改动"（实测踩过）。
        try:
            whitelist.load()
        except Exception:
            pass

        # ---- 受监控文件 / 目录（2026-10-07 新增，见 watch.py）----
        # 与 integrity 的分工：integrity 管"我这个工具被动了"，
        # watch 管"用户指定的文件/目录被动了"。
        self.watch_interval = 60.0          # 监控目标每 60 秒比一次
        self.last_watch = 0.0
        self.watch_result: dict = {"findings": [], "targets": [], "stats": {}}
        # 去重键：同一条差异（同一个文件、同一种变化、同一个新哈希）
        # 只告警一次 —— 否则每 60 秒就往时间线塞一条，把真告警挤出去。
        self._watch_seen: set[str] = set()
        self.watch_busy = False
        self._last_beep = 0.0

    # ------------------------------------------------------------ 主循环
    def start(self):
        # 先把历史上发生过的「程序被改动 / 受监控文件被改动」读回时间线。
        # 为什么：告警原本只活在内存里，重启就没了 —— 而用户看到可疑情况时的
        # 第一反应常常就是"重启一下看看"，那一下正好把唯一的证据擦掉。
        # 有了日志文件，重启后取证链是连续的（README 反面清单第 5 条）。
        self._restore_alerts_from_log()
        auditlog.write("startup", "info", "监视器启动",
                       f"版本 {version.VERSION}  数据目录 {paths.DATA_DIR}")
        threading.Thread(target=self._loop, daemon=True, name="scan-loop").start()
        threading.Thread(target=self._sig_worker, daemon=True, name="sig-worker").start()
        # 「打开时自动扫描」：启动即开始一轮网络观测，无需用户点任何按钮。
        if self.netmon is not None:
            self.netmon.start()
            self.netmon.start_session(self.net_duration, auto=True)

    def _restore_alerts_from_log(self):
        """把安全类历史事件还原成时间线条目（只还原"重要且低频"的那几类）。

        ⚠️ 只还原安全事件，**不还原进程告警** —— 进程告警数量大且时效性强，
        把昨天的几百条搬回今天的界面，只会让人对时间线脱敏。
        """
        KINDS = {"integrity", "watch", "whitelist"}
        try:
            recs = auditlog.tail(400)
        except Exception:
            return
        restored = []
        for r in recs:
            if r.get("kind") not in KINDS:
                continue
            restored.append({
                "time": (r.get("time") or "")[-8:],
                "ts": r.get("ts") or 0,
                "level": r.get("level") or "medium",
                "score": 100 if r.get("level") == "critical" else 60,
                "name": r.get("title") or "历史安全事件",
                "pid": 0,
                "exe": r.get("detail") or "",
                "from_log": True,          # 界面据此标注「来自日志（重启前）」
                "rules": [{"id": "LOG", "title": r.get("title") or "",
                           "severity": r.get("level") or "medium",
                           "evidence": r.get("detail") or ""}],
                "text": "（重启前的记录，来自本地安全日志）" + (r.get("detail") or ""),
            })
        restored.sort(key=lambda x: x.get("ts") or 0, reverse=True)
        with self.lock:
            self.alerts.extend(restored[:80])
            self.alerts.sort(key=lambda x: x.get("ts") or 0, reverse=True)
            self.alerts_from_log = len(restored[:80])

    def _loop(self):
        # 首轮顺序（2026-10-07 调整）：完整性 → **进程** → 系统痕迹（后台）
        #
        # 原来顺序是 完整性 → 系统痕迹 → 进程。而界面窗口要等到
        # summary.scan_count >= 1 才弹出（见 main._open_when_ready），
        # 于是用户必须先等"系统痕迹扫完"（本机实测约 5.6 秒，含一次
        # PowerShell 启动）才能看到窗口 —— 这就是"打开程序要等好久"的来源。
        # 改成先扫进程：冷启动单轮约 2.5 秒（首次枚举进程句柄的一次性开销），
        # 窗口 3 秒内就有数据；系统痕迹与签名校验都改后台补齐，不阻塞首屏。
        self._safe(self.check_integrity)
        self._safe(self.scan_processes)
        self._spawn_once("artifact", self.scan_artifacts)
        while self.running:
            t0 = time.time()
            self._safe(self.scan_processes)
            if time.time() - self.last_artifact_scan > self.artifact_interval:
                self._spawn_once("artifact", self.scan_artifacts)
            if time.time() - self.last_integrity > self.integrity_interval:
                self._spawn_once("integrity", self.check_integrity)
            if time.time() - self.last_watch > self.watch_interval:
                self._spawn_once("watch", self.check_watch)
            time.sleep(max(0.2, self.proc_interval - (time.time() - t0)))

    # ------------------------------------------------------------ 受监控文件
    def check_watch(self, force_full: bool = False):
        """比对受监控的文件 / 目录，把差异写进告警时间线。

        ⚠️ 与自检同一个道理：**"变了"不等于"被攻击"**。
        用户自己改了自己的文档也会命中。所以：
          · 告警文案必须写清"这是你指定的监控目标发生了变化"，
            而不是含糊地说"检测到威胁"；
          · 提供「确认是我改的」按钮重建基线（/api/watch/accept）；
          · 同一处改动只报一次，避免刷屏（刷屏本身就是一种掩盖）。
        """
        self.watch_busy = True
        try:
            res = watch.verify(force_full=force_full)
            with self.lock:
                self.watch_result = res
                self.last_watch = time.time()
                fresh = []
                for f in res.get("findings") or []:
                    sig = watch.signature(f)
                    if sig in self._watch_seen:
                        continue
                    self._watch_seen.add(sig)
                    fresh.append(f)
                del self.alerts[400:]      # 先腾空间，再插新告警（防被自己截掉）
                for f in fresh[:20]:
                    self._push_watch_alert(f)
                # 去重集合不能无限增长
                if len(self._watch_seen) > 4000:
                    self._watch_seen = set(list(self._watch_seen)[-2000:])
        finally:
            self.watch_busy = False

    def _push_watch_alert(self, f: dict):
        kind_zh = {"changed": "被修改", "added": "新增", "removed": "被删除"}.get(
            f.get("kind"), f.get("kind"))
        title = f"受监控文件{kind_zh}"
        detail = f"{f.get('full_path')}"
        # 一律给「中危」，**刻意不给 critical**：
        # 用户自己编辑文档、软件自动更新都会命中这条规则，
        # 一次正常的文档保存就顶格告警的话，用户三天内就会对告警脱敏 ——
        # 那正是本工具最想避免的事（README 第 4 节的四条通用原则之一：
        # 弱信号必须叠加上下文，强规则才可以独立成立）。
        level = "medium"
        self.alerts.insert(0, {
            "time": time.strftime("%H:%M:%S"),
            "ts": time.time(),
            "level": level,
            "score": 45.0,
            "name": f"{title}：{f.get('label') or ''}",
            "pid": 0,
            "exe": f.get("full_path") or "",
            "watch": True,
            "rules": [{
                "id": "W001", "title": title, "severity": level,
                "evidence": (f"监控目标：{f.get('path')}\n"
                             f"相对路径：{f.get('file')}\n"
                             f"变化：{kind_zh}\n"
                             f"哈希前 16 位：{f.get('old') or '(无)'} → {f.get('new') or '(无)'}"),
                "advice": "如果这次变化是你自己造成的（编辑、更新、整理文件），"
                          "在「规则与 IOC → 安全状态」里点一次「确认，重建监控基线」即可消除。"
                          "如果不是你做的，先别急着重启或清理，先导出报告留证。",
            }],
            "text": f"[文件监控] {f.get('label') or ''} {kind_zh}：{f.get('file')}",
        })
        auditlog.write("watch", level, title, detail,
                       extra={"target": f.get("path"), "file": f.get("file"),
                              "change": f.get("kind")})
        self._notify()

    def accept_watch(self) -> dict:
        """用户确认"这些变化是我做的" → 重建监控基线，并把去重表清空。"""
        watch.rebuild()
        with self.lock:
            self._watch_seen.clear()
        self.check_watch(force_full=True)
        auditlog.write("watch", "info", "受监控基线已重建（用户确认）",
                       f"当前监控目标数：{len(watch.listing().get('targets') or [])}")
        return {"ok": True, "msg": "已重建监控基线"}
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
            # 基线按安装分文件（F-015），所以这里不再需要"属于别的程序目录就丢弃"
            # 那套逻辑 —— 冲突从命名上就不存在了。
            base = integrity.load_baseline(WORKSPACE, APP_DIR)
            if not base:
                # 基线不存在 = 两种可能，**必须区分**：
                #   · 首次运行      → 正常建立
                #   · 基线被人删除  → 告警，**绝不重建**
                # 重建等于替攻击者抹痕：他只需删掉基线文件，然后等用户对
                # 任何一条**无关**告警点一次"加入已知项"，篡改就被写进新基线、
                # 完整性告警从此永远不出现 —— 触发动作完全日常，用户毫不知情。
                # （红队 F-002，实测 2/2；这恰是 integrity.py 注释里声称已堵住的那条路。）
                if integrity.sentinel_belongs_here(
                        integrity.load_sentinel(APP_DIR), APP_DIR):
                    self._integrity_alerted = False   # 让下一轮 check_integrity 重新告警
                    self.check_integrity()
                    # 返回非空 → 端点回 integrity_refresh="blocked" → 界面明示
                    # "已加入已知项，但基线刷新被拒绝"。刻意让用户知道
                    # "你刚才那个动作没能洗掉告警"。
                    return ["（完整性基线丢失，已拒绝刷新基线）"]
                integrity.save_baseline(WORKSPACE, cur, app_dir=APP_DIR,
                                            note="首次运行建立基线")
                integrity.save_sentinel(WORKSPACE, cur, APP_DIR)
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

        ⚠️ **覆盖范围不在这里决定** —— 一律走 integrity.default_extras()。
        这里保留成薄封装只是因为历史上被多处引用。

        原先这里是一份内联实现，而 main.py --verify-only 与 accept_integrity
        各写了另一份（都漏了 python_path.txt / whitelist.json）——
        结果是**健康安装上 --verify-only 也报「程序文件已被改动」并 exit 2**，
        而且重建基线用的弱清单怎么点都消不掉。详见 integrity.default_extras()。
        """
        return integrity.default_extras()

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
                # ⚠️ 去重：时间线里已经有同类（SELF）告警就不再插。
                # 为什么必须去重：_refresh_integrity_baseline 在"基线丢失 +
                # 用户点加入已知项"时会复位 _integrity_alerted 并重新校验
                # （否则那一瞬间删掉基线就永远不会告警）。但如果没有这道去重，
                # 反复点"加入已知项"就会把时间线刷满同类告警 ——
                # **刷屏本身就是一种掩盖手段**，会把别的告警挤出去。
                _dup = any((a.get("rules") or [{}])[0].get("id") == "SELF"
                           for a in self.alerts)
                if not _dup:
                    self.alerts.insert(0, {
                        "time": time.strftime("%H:%M:%S"),
                        "ts": time.time(),
                        "level": "critical",
                        "score": 100,
                        "name": "本程序文件完整性异常",
                        "pid": 0,
                        "exe": "、".join((res.get("changed") or [])[:3])
                               or (res.get("status_zh") or "见安全状态"),
                        "rules": [{
                            "id": "SELF", "title": "程序文件已被改动/基线丢失",
                            "severity": "critical",
                            "evidence": "被修改：" + "、".join(res.get("changed") or [])
                                        + "\n新增：" + "、".join(res.get("added") or [])
                                        + "\n缺失：" + "、".join(res.get("removed") or [])
                                        + ("\n基线状态：" + res.get("status_zh", "")
                                           if res.get("status") == "baseline_lost" else "")}],
                        "text": "本程序文件与首次运行时的基线不一致，检测规则可能已被篡改",
                    })
                    del self.alerts[200:]
                    # 留痕 + 发声：这两件事原本都没有。
                    # 不留痕 → 重启就查不到"什么时候被改的"；
                    # 不发声 → 用户没盯着界面时就错过了（顶栏变红只在看着时才有效）。
                    auditlog.write(
                        "integrity", "critical", "程序文件完整性异常",
                        f"状态：{res.get('status_zh')}｜被修改：{'、'.join(res.get('changed') or []) or '无'}"
                        f"｜新增：{'、'.join(res.get('added') or []) or '无'}"
                        f"｜缺失：{'、'.join(res.get('removed') or []) or '无'}",
                        extra={"status": res.get("status")})
                    self._notify()

    def accept_integrity(self):
        """用户确认改动是自己做的 → 重建基线。"""
        # ⚠️ 与运行期、--verify-only 用同一份覆盖范围，否则重建出来的基线
        #    与运行期比对口径不一致 → 告警消不掉（实测过）
        extra = integrity.default_extras()
        m = integrity.collect_manifest(APP_DIR, extra)
        integrity.save_baseline(WORKSPACE, m, app_dir=APP_DIR,
                                        note="用户从界面确认并重建")
        integrity.save_sentinel(WORKSPACE, m, APP_DIR)
        self._integrity_alerted = False
        auditlog.write("integrity", "info", "完整性基线已重建（用户确认）",
                       f"共 {len(m)} 个文件")
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

    def _notify(self):
        """安全告警发声提示。

        为什么要它：顶栏变红**只在用户正看着界面时才有效**，
        而这类工具恰恰是"挂在后台等出事"的。声音是唯一能穿透"没在看"的通道。

        三条约束（都是踩过的常识）：
          · 用 stdlib 的 winsound.MessageBeep，不引入任何依赖、不做网络通知；
          · 5 秒节流 —— 一次批量改动可能产生几十条告警，
            不做节流就会变成机关枪，用户第一反应是把工具关掉；
          · 全程 try 包住 —— 没有声卡 / 远程会话静音时也必须照常告警，
            发不出声不能影响检测本身。
        """
        now = time.time()
        if now - getattr(self, "_last_beep", 0.0) < 5.0:
            return
        self._last_beep = now
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONHAND)
        except Exception:
            pass

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
        # ⚠️ 必须在锁外推送：netmon.update_proc_index 要拿 netmon.lock，
        #    在 self.lock 内取它就是反向锁序（见 Monitor.__init__ 的锁序约定）。
        if self.netmon is not None:
            self.netmon.update_proc_index({p["pid"]: p for p in procs})
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
            # 无论有没有被过滤，都用最终 findings 重算一次 score/level。
            # 原先只在 dropped 非空时才重算，于是"没被过滤"的项依赖 rules_* 事先
            # 算好的值 —— 一旦某个 rules_* 分支忘了算，界面就又是 undefined。
            # 统一在出口处重算，让"每个制品项都带 score/level"成为出口不变式。
            item = {**item, "findings": fs, "whitelisted": len(dropped)}
            item["score"], item["level"] = rules.score_findings(fs)
            kept.append(item)
        kept.sort(key=lambda x: -(x.get("score") or 0.0))
        self.artifact_findings = kept
        self.artifact_whitelisted = suppressed

    @staticmethod
    def _has_external_conn(p: dict) -> bool:
        # 判断进程是否握有「对外（非回环）的 ESTABLISHED 连接」。
        # 用于拓宽深度扫描的覆盖范围：银狐「白加黑」的核心是外观正常的进程
        # （签名有效、名字合法）从自身目录加载恶意 DLL —— 这类进程在进程行为评分里
        # 往往是 clean，不会被原「只扫 critical/high」的逻辑覆盖。把它们也纳入模块扫描，
        # 才能在网络页暴露其白加黑本质。仅当进程确实在对外通信时才值得付出扫描开销。
        for c in (p.get("connections") or []):
            rip = c.get("rip") or ""
            if rip and c.get("status") == "ESTABLISHED" and not rules.is_loopback_ip(rip):
                return True
        return False

    def _deep_scan_cycle(self, limit: int = 4):
        # 对高危进程、以及持有对外连接的进程追加深度扫描（加载模块检查）。
        with self.lock:
            targets = [p for p in self.procs
                       if (p.get("level") in ("critical", "high")
                           or self._has_external_conn(p))
                       and (p["pid"], p.get("create_time")) not in self.deep_done][:limit]
            ctx = self._ctx()
            # 回收已退出进程的待复查登记，避免 _deep_pending 无界增长
            live = {(p["pid"], p.get("create_time")) for p in self.procs}
            for k in [k for k in self._deep_pending if k not in live]:
                self._deep_pending.pop(k, None)
        if not targets:
            return
        changed = False
        for p in targets:
            key = (p["pid"], p.get("create_time"))
            try:
                extra, pending = rules.deep_scan_process(p, ctx)
            except Exception:
                traceback.print_exc()
                extra, pending = [], []
            with self.lock:
                # 无论有没有待验模块，本轮都算"扫过了"。
                # ⚠️ 不能因为"还有模块在等校验"就 continue —— 每轮只有 4 个名额，
                #    一个模块验不出来的进程会长期霸占名额，把其它进程活活饿死。
                #    复查由 _sig_worker 在签名结果到达时驱动（见那里的 _deep_pending 释放）。
                self.deep_done.add(key)
                # 签名校验连续失败 3 次以上的模块不再排队（F-006），也不再等待它。
                pending = [mp for mp in pending
                           if self._sig_failed.get(mp.lower(), 0) < 3]
                if pending:
                    self.pending_sig.update(mp for mp in pending
                                            if mp.lower() not in self.sig_cache)
                    self._deep_pending[key] = set(pending)
                # 复查轮（_deep_retry > 0）即使结论为空也必须写回 mod_scan：
                # 上一轮"等待校验"时留下的结论必须被清掉，否则误报会永久粘住。
                if extra or self._deep_retry.get(key, 0) > 0:
                    p.setdefault("findings", []).extend(extra)
                    p["score"], p["level"] = rules.score_findings(p["findings"])
                    self._store_mod_scan(key, extra)
                    changed = True
        if changed:
            with self.lock:
                self.procs.sort(key=lambda x: -(x.get("score") or 0.0))

    def _store_mod_scan(self, key: tuple, extra: list[dict]):
        # 把深度扫描的 X 系列模块结论固化进 self.mod_scan，跨进程扫描轮次保留。
        # 进程扫描每轮重建全新 proc 字典（见 scan_processes），旧对象上的 X findings 会丢失；
        # 这里单独存一份，使：① _score_all 能把 X 结论重新并回进程评分；
        # ② netmon 的 _analyze_flow 能稳定读到白加黑信号，网络页不闪烁。
        ioc = any(f.get("rule_id") == "X001" for f in extra)
        disguised = any(f.get("rule_id") == "X002" for f in extra)
        sideload = any(f.get("rule_id") == "X003" for f in extra)
        sevs = [f.get("severity") for f in extra]
        level = ("critical" if "critical" in sevs
                 else "high" if "high" in sevs
                 else "medium" if "medium" in sevs else "low")
        if ioc:
            summary = "加载银狐 IOC 模块"
        elif disguised:
            summary = "加载伪装扩展名的可执行模块"
        elif sideload:
            summary = "疑似白加黑侧加载（同目录未签名 DLL）"
        else:
            summary = ""
        # ⚠️ 必须**整条拷贝**，不能只挑几个字段。
        #    2026-10-08 实测缺陷：这里原先白名单式地只保留
        #    rule_id / title / severity / severity_zh / evidence / advice 六个键，
        #    **漏掉了 weight**（以及 category / category_zh）。
        #    这些残缺 finding 会在 _score_all 里被并回进程的 findings 列表，
        #    再交给 rules.score_findings() —— 后者读 f["weight"] 直接抛 KeyError，
        #    而异常从 _score_all 的 for 循环中逃逸，**其后所有进程不再被评分**。
        #    实测后果：276 个进程中 156 个没有 score/level，界面「风险」列显示
        #    undefined、标签页计数恒为 0，服务端每轮扫描（1 秒）打印一次 traceback。
        #    凡是"存一份供后续复用"的结构，字段集必须与生产它的 finding() 一致；
        #    这里直接用 dict(f) 整条复制，从根上避免再次漏字段。
        self.mod_scan[key] = {
            "ioc": ioc, "disguised": disguised, "sideload": sideload,
            "level": level, "summary": summary,
            "findings": [dict(f) for f in extra],
        }
        # 控制体积：只保留最近 512 条，越早的越不重要。
        if len(self.mod_scan) > 512:
            excess = len(self.mod_scan) - 512
            old_keys = sorted(self.mod_scan.keys(),
                              key=lambda k: (k[1] if len(k) > 1 else 0))[:excess]
            for k in old_keys:
                self.mod_scan.pop(k, None)

    # ------------------------------------------------------------ 评分
    def _ctx(self) -> dict:
        return {
            "by_pid": {p["pid"]: p for p in self.procs},
            "sig_cache": self.sig_cache,
            "artifacts": getattr(self, "artifacts", {}),
            "self_pid": os.getpid(),      # 用于排除本工具自己拉起的辅助进程
            # 本工具拉起的子进程登记表（pid → 创建时间）。
            # 只靠"父进程 == 自己"不够 —— venv 启动器与 MSIX 应用执行别名
            # 都会让 ppid 不等于本进程，详见 rules.is_own_aux_process。
            "own_children": winapi.own_child_create_times(),
        }

    def _score_all(self):
        ctx = self._ctx()
        wl = whitelist.load()
        for p in self.procs:
            # ⚠️ 逐进程隔离（2026-10-08 加固）。
            #    原先只有 rules_process 被 try 包住，后面几步（并回 mod_scan 结论、
            #    已知项过滤、score_findings）裸奔 —— 其中任何一步抛异常，都会
            #    跳出整个 for 循环，**导致该进程之后的所有进程永远拿不到 score/level**，
            #    界面直接显示 undefined。实测就是这么发生的（详见 _store_mod_scan 注释）。
            #    现在把每个进程的处理整体隔离，并在任何失败下写入兜底值：
            #    评分是显示层的基础设施，宁可某个进程显示为"正常"，
            #    也不能让整张表失去可读性。
            try:
                try:
                    fs = rules.rules_process(p, ctx)
                except Exception:
                    traceback.print_exc()
                    fs = []
                # 保留深度扫描的 X 系列模块结论（白加黑侧加载 / IOC 模块 / 伪装模块）。
                # 这些结论由 _deep_scan_cycle 固化在 self.mod_scan，跨进程扫描轮次保留 ——
                # 否则每轮重建 proc 字典会把它们冲掉，网络页的「白加黑」信号会闪烁。
                mod = self.mod_scan.get((p["pid"], p.get("create_time")))
                if mod:
                    for f in mod["findings"]:
                        if f not in fs:
                            fs.append(f)
                # 已知项过滤：只忽略"规则号 + 匹配条件 + 守卫哈希"三者都命中的告警
                fs, dropped = whitelist.filter_findings(fs, p, wl)
                p["findings"] = fs
                p["whitelisted"] = len(dropped)
                p["score"], p["level"] = rules.score_findings(fs)
            except Exception:
                traceback.print_exc()
                p.setdefault("findings", [])
                p.setdefault("whitelisted", 0)
                p["score"], p["level"] = 0.0, "clean"
        # 排序键同样必须容错：任何进程缺 score/name 都不能让排序整体失败。
        self.procs.sort(key=lambda x: (-(x.get("score") or 0.0),
                                       (x.get("name") or "").lower()))

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
        # 排序键用 .get 兜底：告警推送发生在扫描线程里，一条畸形 finding
        # 不该让告警时间线整体停摆（同 _score_all 的加固理由）。
        top = sorted(p.get("findings", []), key=lambda f: -(f.get("weight") or 0))[:3]
        self.alerts.insert(0, {
            "time": time.strftime("%H:%M:%S"),
            "ts": time.time(),
            "level": p["level"],
            "score": p["score"],
            "name": p["name"],
            "pid": p["pid"],
            # 记下父进程与自身 PID：排查"本工具把自己的辅助进程报成高危"这类
            # 误报时，这两项是唯一能定位根因的线索（实测靠它定位过）。
            "ppid": p.get("ppid") or 0,
            "parent": p.get("parent_name") or "",
            "self_pid": os.getpid(),
            "exe": p.get("exe", ""),
            "rules": [{"id": f["rule_id"], "title": f["title"],
                       "severity": f["severity"], "evidence": f["evidence"],
                       # advice 必须一起带上：像"这条其实可能是本工具自己的同类进程"
                       # 这类关键提示就写在 advice 里，而用户最先看到的就是告警时间线。
                       # 初版只带 evidence，导致提示只在进程详情里出现、在最需要的地方缺席。
                       "advice": f.get("advice", "")} for f in top],
            "text": f"新增{p.get('level') or 'clean'}级进程：{display_proc_name(p)} (PID {p['pid']}) · " +
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

    def _net_alert(self, f: dict):
        """网络引擎检出高危流量 → 写入告警时间线。

        由 netmon 线程回调，**调用时不得持有 netmon.lock**（见锁序约定）。
        """
        top = sorted(f.get("findings") or [], key=lambda x: -(x.get("weight") or 0))[:3]
        self.alerts.insert(0, {
            "time": time.strftime("%H:%M:%S"),
            "ts": time.time(),
            "level": f["level"],
            "score": f["score"],
            "name": f"{f['name']} → {f['rip']}:{f['rport']}",
            "pid": f["pid"],
            "exe": f.get("exe", ""),
            "net_key": f["key"],
            "net": True,
            "rules": [{"id": x["rule_id"], "title": x["title"],
                       "severity": x["severity"], "evidence": x["evidence"],
                       "advice": x.get("advice", "")} for x in top],
            "text": f"[网络] {f['verdict']} · " + "；".join(x["title"] for x in top[:2]),
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
                            # ⚠️ 失败结果**不写进 sig_cache**，只累加失败计数。
                            # 旧写法把失败固化成 kind="unknown" 缓存起来，而重新入队的
                            # 条件是 `exe not in sig_cache` → 本会话永不重试；
                            # 且 rules.UNTRUSTED_KINDS 不含 unknown → 所有签名门控规则
                            # 对这些文件长期跳过。一次瞬时故障 = 永久盲区（红队 F-006）。
                            # 改成可恢复：失败 3 次内自动重试，超过后不再重试但**计数可见**。
                            k = p.lower()
                            self._sig_failed[k] = self._sig_failed.get(k, 0) + 1
                    for p in batch:
                        if p.lower() in self.sig_cache:
                            self._sig_failed.pop(p.lower(), None)

                    # ★ 关键：把"因模块尚未校验而挂起的深度扫描"放行复查。
                    #   这是"先验签后定罪"能真正成立的唯一依据（2026-10-08 修复）。
                    #   没有这一步，就只能靠计时器猜"验完了没有"—— 实测猜错的代价是
                    #   Edge / 微信 / <workspace> / 网易 UU / Intel DSA 这 5 个正规软件
                    #   被判 critical（它们那 48 个同目录 DLL 逐个复验**全部签名有效**，
                    #   只是还排在 647 个文件的校验队列里没轮到）。
                    #   放行方式：把进程从 deep_done 里移除，下一轮 _deep_scan_cycle
                    #   就会带着"已填好的 sig_cache"重新扫描它，从而得出正确结论。
                    for _k, _mods in list(self._deep_pending.items()):
                        _left = {m for m in _mods
                                 if m.lower() not in self.sig_cache
                                 and self._sig_failed.get(m.lower(), 0) < 3}
                        if _left:
                            self._deep_pending[_k] = _left      # 还有模块没验完，继续等
                        else:
                            self._deep_pending.pop(_k, None)
                            _n = self._deep_retry.get(_k, 0) + 1
                            self._deep_retry[_k] = _n
                            if _n <= 3:                          # 复查次数上限，防死循环
                                self.deep_done.discard(_k)

                    self._score_all()
                    if self.artifacts:
                        self._score_artifacts()
            except Exception:
                traceback.print_exc()
            finally:
                self.sig_busy = False

    # ------------------------------------------------------------ 状态输出
    def state(self) -> dict:
        # 先取网络快照再进 self.lock —— 锁序要求，不能反过来（见 __init__ 的约定）。
        net = self.netmon.snapshot() if self.netmon is not None else None
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
                    # F-008：本次**没取到**的制品小节。
                    # 必须让"没查到"与"没取到"分得开 —— 否则报告与界面显示
                    # "未发现异常"，而实际上那几类根本没采集到，属假阴性。
                    "artifact_unavailable": list(art.get("_unavailable") or []),
                    "scan_ms": self.scan_ms,
                    "scan_count": self.scan_count,
                    "last_scan": self.last_scan,
                    "uptime": round(time.time() - self.first_seen_at, 0),
                    "admin": winapi.is_admin(),
                    "status": self.status,
                    "sig_pending": len(self.pending_sig),
                    # F-006：签名校验已重试到上限、不再重试的文件数。
                    # 让"坏了"不再看起来像"正忙" —— 否则用户只会看到 sig_pending 一直不为 0。
                    "sig_failed": sum(1 for v in self._sig_failed.values() if v >= 3),
                    # F-007：本轮有多少进程因**历史慢读**被跳过命令行。
                    # 这个数原先根本不存在，导致"命令行类规则对本会话失明"完全不可见。
                    "cmdline_denied": sum(1 for p in self.procs
                                          if p.get("cmdline_denied")),
                    "artifact_busy": self.artifact_busy,
                    "sig_busy": self.sig_busy,
                    "defender_accessible": bool((art.get("defender") or {}).get("accessible")),
                    "ioc_version": iocs.IOC_VERSION,
                    # ---- 受监控文件 / 目录（2026-10-07）----
                    "watch_findings": len((self.watch_result or {}).get("findings") or []),
                    "watch_busy": bool(getattr(self, "watch_busy", False)),
                    # 重启后从本地安全日志还原的条目数。让它可见，
                    # 用户才会知道"时间线里这几条是重启前的记录，不是刚发生的"。
                    "alerts_from_log": getattr(self, "alerts_from_log", 0),
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
                    # 数据目录若退到程序目录（用户可写），基线就落在能被改写的位置，
                    # 自检形同虚设 —— 必须让界面看得见，而不是静默降级。
                    "data_dir": paths.DATA_DIR,
                    "data_on_program_dir": bool(
                        paths.describe().get("on_program_dir")),
                    # 版本号必须下发到界面：本机存在多份副本时，
                    # "我看到的是哪一版"是排查一切问题的第一步。
                    "app_version": version.VERSION,
                    "app_version_line": version.version_line(),
                    "app_build": version.BUILD,
                    "net_enabled": self.netmon is not None,
                    "net_estats": bool(net and net.get("estats")),
                    "net_sample_interval": (net or {}).get("sample_interval"),
                    # 自身辅助进程排除的可观测性：把"本进程 PID"和"已登记的辅助子进程数"
                    # 显示出来，用户与开发者都能据此核对"工具会不会误报自己"。
                    "self_pid": os.getpid(),
                    "own_children": len(winapi.own_child_create_times()),
                },
                                # 已知项随 state 一起下发：前端 poll() 会整体替换 STATE，
                # 单独 fetch 挂在 STATE 上的字段会被下一轮冲掉（实测踩过）。
                "whitelist": whitelist.listing(),
                # ⚠️ 必须随 state 一起下发：前端 poll() 是整体替换 STATE，
                #    任何"单独 fetch 后挂在 STATE 上"的字段都会被下一轮冲掉（实测踩过）。
                "watch": watch.listing(),
                "watch_state": self.watch_result or {"findings": [], "targets": [], "stats": {}},
                "auditlog": auditlog.stats(),
                "net": net,
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
        self.send_header("Access-Control-Allow-Origin", "null")
        self.send_header(
            "Set-Cookie",
            "yinhu-token=" + SESSION_TOKEN +
            "; Path=/; SameSite=Strict; Max-Age=86400")
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
        # 令牌不再注入静态 HTML（红队 F-01）：改由 _send 里的
        # Set-Cookie(SameSite=Strict) 下发，避免被任意能读首页的本地进程直接 grep 到。
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

    def _guard_origin_host(self) -> bool:
        """**与方法无关**的来源校验：Origin 同源 + Host 回环（防 DNS 重绑定）。

        ⚠️ 这里**不检查令牌**。GET 是界面每 2 秒轮询（/api/state）与启动器探测
        （main.find_running_instance / _open_when_ready，都是裸 urllib）在用的 ——
        给 GET 加令牌这两条会全部 403，界面直接停摆。
        GET 要的是"数据别被别的站点读走"，令牌层对同用户进程本来也不构成屏障。

        ⚠️ Host 切分必须正确处理 IPv6：`[::1]:8787` 按 split(":")[0] 会切成 "[",
        再 strip("[]") 变成空串 → 校验被整个跳过（红队 F-005 指出的旧写法）。
        """
        origin = self.headers.get("Origin")
        if origin:
            if urlparse(origin).hostname not in ALLOWED_HOSTS:
                self._json({"ok": False, "msg": "拒绝：请求来源不被允许"}, 403)
                return False
        _addr = getattr(self.server, "server_address", None)
        my_port = _addr[1] if isinstance(_addr, (tuple, list)) and len(_addr) >= 2 else None

        def _host_ok(hostval: str) -> bool:
            h = (hostval or "").strip()
            if not h:
                return False
            if h.startswith("["):                       # [::1]:8787
                host = h.split("]")[0].lstrip("[").lower()
                port = (h.split("]", 1)[1].lstrip(":") or "")
            elif h.count(":") == 1:                     # 127.0.0.1:8787
                host, port = h.rsplit(":", 1)
                host = host.lower()
            else:                                       # 裸主机名或畸形值
                host, port = h.lower(), ""
            if host not in ALLOWED_HOSTS:
                return False
            if my_port is not None and port:
                try:
                    if int(port) != int(my_port):
                        return False
                except ValueError:
                    return False
            return True

        origin = self.headers.get("Origin")
        if origin:
            op = urlparse(origin)
            oval = (f"{op.hostname}:{op.port}" if op.port
                    else (op.hostname or ""))
            if not _host_ok(oval):
                self._json({"ok": False, "msg": "拒绝：请求来源不被允许"}, 403)
                return False
        h = (self.headers.get("Host") or "").strip()
        if h and not _host_ok(h):
            self._json({"ok": False, "msg": "拒绝：Host 不被允许"}, 403)
            return False
        return True

    def _guard(self) -> bool:
        """POST 来源校验：会话令牌（X-Yinhu-Token 头 或 SameSite Cookie）
        + Origin/Host 同源（含端口）+ Content-Type。任一层不过直接 403。"""
        req_tok = self.headers.get("X-Yinhu-Token") or ""
        cookie_tok = ""
        for _p in (self.headers.get("Cookie") or "").split(";"):
            _k, _, _v = _p.partition("=")
            if _k.strip() == "yinhu-token":
                cookie_tok = _v.strip()
                break
        try:
            token_ok = (hmac.compare_digest(req_tok, SESSION_TOKEN) or
                        hmac.compare_digest(cookie_tok, SESSION_TOKEN))
        except TypeError:
            token_ok = False
        if not token_ok:
            self._json({"ok": False, "msg": "拒绝：访问令牌缺失或不正确"}, 403)
            return False
        if not self._guard_origin_host():
            return False
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            self._json({"ok": False, "msg": "拒绝：Content-Type 必须为 application/json"}, 403)
            return False
        return True

    # ---------------- 路由 ----------------
    def do_GET(self):
        # GET 也要过来源校验（Origin 同源 + Host 回环），但**不加令牌**。
        # 不加之前：伪造 `Host: evil.example.com` 的 GET 全部 200，
        # 一次 /api/state 就吐出进程清单 / 完整命令行 / 路径 / 哈希 / 白名单，
        # 且 GET / 返回的 HTML 里会话令牌已被替换成真实值（红队 F-005，实测 2/2）。
        if not self._guard_origin_host():
            return
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
        elif p == "/api/watch":
            out = watch.listing()
            out["state"] = getattr(self.monitor, "watch_result", {}) or {}
            out["log"] = auditlog.stats()
            self._json(out)
        elif p == "/api/net/flow":
            if m.netmon is None:
                self._json({"error": "网络检测未启用"})
            else:
                key = q.get("key", [""])[0]
                if not netmon.parse_flow_key(key):
                    self._json({"error": "非法的流量标识"}, 400)
                else:
                    self._json(m.netmon.flow_detail(key))
        elif p == "/api/ping":
            # 供启动时探测"是否已有实例在运行"，避免重复双击开出多个监视器。
            # 加固：携带实例密钥，启动器只认带正确密钥的响应（见 main.find_running_instance）。
            self._json({"app": APP_ID, "version": iocs.IOC_VERSION,
                        "pid": os.getpid(), "secret": INSTANCE_SECRET})
        else:
            self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_OPTIONS(self):
        # 显式拒绝跨源预检（红队 F-04 补充）：本服务仅允许同站点同源的 GET/POST，
        # 不接受跨源请求。浏览器跨源非简单请求会先发 OPTIONS 预检，这里直接 405
        # + ACAO:null，杜绝任何误放行。
        self.send_response(405)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Allow", "GET, POST")
        self.send_header("Access-Control-Allow-Origin", "null")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

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
        # ---------------- 受监控文件 / 目录（2026-10-07）----------------
        elif p == "/api/watch/add":
            ok, msg, t = watch.add(str(body.get("path") or ""),
                                   bool(body.get("recursive", True)),
                                   str(body.get("label") or ""))
            if ok:
                # 加完目标必须立刻建基线：否则下一轮比对会把"整个目标都是新增"
                # 报成几百条 added 告警 —— 用户第一次用就会被自己的界面吓到。
                try:
                    watch.rebuild()
                except Exception:
                    pass
                m.check_watch(force_full=True)
                auditlog.write("config", "info", "新增受监控路径",
                               f"{t.get('path')}（递归={'是' if t.get('recursive') else '否'}）")
            self._json({"ok": ok, "msg": msg, "target": t})
        elif p == "/api/watch/remove":
            ok, msg = watch.remove(str(body.get("id") or ""))
            if ok:
                m.check_watch(force_full=True)
                auditlog.write("config", "info", "移除受监控路径",
                               str(body.get("id") or ""))
            self._json({"ok": ok, "msg": msg})
        elif p == "/api/watch/accept":
            self._json(m.accept_watch())
        elif p == "/api/watch/check":
            threading.Thread(target=m._safe, args=(m.check_watch, True),
                             daemon=True).start()
            self._json({"ok": True, "msg": "已触发监控目标全量复核"})
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
            # ⚠️ 默认值**不能**回落到 rule_only —— 那等于"不写类型就全量豁免"
            mtype = str(m2.get("type") or "")
            mvalue = str(m2.get("value") or "")
            guard_file = str((body.get("guard") or {}).get("file") or "")

            # 入参校验：否则可以构造"全量豁免"条目 ——
            # 例如 exe_path_prefix + 空 value（"任意路径".startswith("") 恒真）
            # 会让某条规则对所有进程永久失效。
            known_rules = {r[0] for r in _RULE_DOC}
            if rid not in known_rules:
                self._json({"ok": False, "msg": f"未知规则号：{rid or '(空)'}"}, 400)
                return
            # ① 禁止「按规则号全量豁免」——这是把一条规则对所有对象关掉的后门
            if mtype == "rule_only":
                self._json({"ok": False,
                            "msg": "不支持按规则号全量豁免：请给出限定到具体对象的匹配条件"},
                           400)
                return
            if mtype not in whitelist.MATCH_TYPES:
                self._json({"ok": False,
                            "msg": f"不支持的匹配方式：{mtype or '(空)'}"}, 400)
                return
            # ② 所有类型都必须给非空匹配值（空值会让 "" in x / startswith("") 恒真）
            if not mvalue.strip():
                self._json({"ok": False,
                            "msg": "匹配条件不能为空——空值会让该规则对所有对象失效"}, 400)
                return
            # ③ 必须指明对象，并断言「这条条目只命中这一个对象」。
            #    这是**结构性**防线：即使前面几条被绕过，
            #    一条会命中多个对象的条目也进不来，"一条 entry 关掉整条规则"
            #    在数据层面不再可能。红队报告 §2.1.3 的推荐做法。
            scope_pid = body.get("pid")
            scope_aid = str(body.get("artifact_id") or "")
            if scope_pid is None and not scope_aid:
                self._json({"ok": False,
                            "msg": "必须指明这条已知项针对哪个对象（pid 或 artifact_id）"},
                           400)
                return
            cand = {"rule_id": rid,
                    "match": {"type": mtype, "value": mvalue},
                    "guard": {"file": guard_file,
                              "sha256": whitelist._sha256(guard_file) if guard_file else ""}}
            hits = []
            for x in m.procs:
                for f in x.get("findings", []):
                    if whitelist.entry_matches(cand, f, x):
                        hits.append(f"{x.get('name')}(pid {x.get('pid')})")
            for a in m.artifact_findings:
                for f in a.get("findings", []):
                    if whitelist.entry_matches(cand, f, a):
                        hits.append(f"{a.get('title')}({a.get('id')})")
            if len(hits) > 1:
                shown = "、".join(hits[:5]) + ("…" if len(hits) > 5 else "")
                self._json({"ok": False,
                            "msg": f"这条已知项会同时命中 {len(hits)} 个对象（{shown}）——"
                                   f"请把匹配条件收窄到只针对你要忽略的那一个"}, 400)
                return

            # ④ 匹配值还要"够具体"：非空不等于够窄 ——
            #    exe_path_prefix + "C:\" 或 cmdline_contains + "a" 依然一网打尽。
            #    放在对象断言之后：先告诉用户"要限定到哪个对象"，再说"值太宽"，
            #    提示顺序才符合排查顺序。
            broad = _match_too_broad(mtype, mvalue)
            if broad:
                self._json({"ok": False, "msg": broad}, 400)
                return

            try:
                e = whitelist.add(rid, mtype, mvalue, guard_file,
                                  str(body.get("note") or ""))
            except ValueError as ex:
                # 已知项文件损坏时拒绝写入 —— 否则会把空表覆盖上去，
                # 用户的已知项全部永久丢失（红队 F-017）。
                self._json({"ok": False, "msg": str(ex)}, 409)
                return
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
            try:
                ok = whitelist.remove(str(body.get("id") or ""))
            except ValueError as ex:
                self._json({"ok": False, "msg": str(ex)}, 409)
                return
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
        elif p in ("/api/net/start", "/api/net/duration", "/api/net/stop"):
            if m.netmon is None:
                self._json({"ok": False, "msg": "网络检测未启用（启动时用了 --no-net）"})
                return
            try:
                dur = float(body.get("duration") or netmon.DEFAULT_DURATION)
            except Exception:
                dur = float(netmon.DEFAULT_DURATION)
            if p == "/api/net/start":
                m.netmon.start_session(dur)
                self._json({"ok": True, "msg": f"已开始一轮 {netmon.fmt_duration(dur)} 的网络观测"})
            elif p == "/api/net/duration":
                r = m.netmon.set_duration(dur)
                # F-003：非法入参（非数字 / NaN / 无穷）明确回 400 ——
                # 旧写法会把它静默钳成边界值并回"已改为 0.0 秒"，
                # 说的和做的不一样，排查时最费时间。
                if r.get("bad"):
                    self._json({"ok": False, "msg": r.get("msg") or "观测时长不合法"}, 400)
                    return
                if r.get("finalized"):
                    msg = f"观测时长已改为 {netmon.fmt_duration(dur)}，已到时间，本轮结算完成"
                elif r.get("restarted"):
                    msg = f"已按 {netmon.fmt_duration(dur)} 重新开始一轮观测"
                else:
                    msg = f"观测时长已改为 {netmon.fmt_duration(dur)}"
                self._json({"ok": True, "msg": msg, **r})
            else:
                self._json(m.netmon.stop_session())
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
    ("N001", "外联呈现周期性心跳", "high",
     "连接建立或数据突发的间隔高度规律（低抖动）—— C2 心跳的典型时间特征"),
    ("N002", "连接已知银狐 C2 地址（网络会话层）", "critical",
     "会话期间实测到与公开披露 C2 的活动连接"),
    ("N003", "规律性外联 + 进程本身已判高风险", "critical",
     "网络规律性与进程行为两条独立证据同时指向同一目标"),
    ("N004", "未签名程序连接银狐常用非标端口", "high",
     "会话期间实测到未签名进程连向 18300 / 7000 / 8001 等端口"),
    ("N005", "高风险进程持有对外连接", "high",
     "进程行为已判 critical/high，且确实保持着公网连接"),
]

# 规则号 → 规则名（报告里还原网络行的判定依据用，见 _flow_rules_text）。
# ⚠️ 必须在这里（_RULE_DOC 之后）**直接定义**，不能在文件前部先写个空字典占位 ——
#    那样会被这个赋值顺序覆盖掉，运行时报 NameError / 拿到空表。
_RULE_TITLE = {rid: title for rid, title, _sev, _desc in _RULE_DOC}


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

# ================================================================
# 排查报告
# ================================================================
# ⚠️ 报告的核心约束：**顶部所有数字必须与下方表格逐行对应**。
#    初版把顶部 KPI 的计数直接取自 summary，而表格行是另外循环出来的，
#    两边口径不同（KPI 只按"进程"分等级，表格却还列了系统痕迹）——
#    于是同一份报告上写着「高危 0」，下面却列出一堆「高危」行。
#    这类自相矛盾比少报更伤可信度：试用者会立刻不再相信任何数字。
#    现在计数与表格行都由 report_buckets() 产出，改一处即同时改两处。

_KIND_ZH = {
    "task": "计划任务", "service": "系统服务", "driver": "内核驱动",
    "hosts": "hosts 文件", "registry": "注册表", "file": "文件特征",
}
_LEVELS = ("critical", "high", "medium", "low")
# 规则号 → 规则名（_RULE_TITLE）在文件后部、_RULE_DOC 之后构建，
# 报告里网络行只有 finding_ids，靠它还原成可读文字。


def _tally(items) -> dict:
    c = {k: 0 for k in _LEVELS}
    c["clean"] = 0
    for it in items:
        lv = (it or {}).get("level") or "clean"
        c[lv] = c.get(lv, 0) + 1
    return c


def report_buckets(st: dict) -> dict:
    """报告里三张表的**行**与**计数** —— 全报告唯一的数字来源。

    网络部分有两类行：
      · `nets`  有规则命中的（计入风险等级）
      · `watch` 规律性 ≥55 但无旁证命中的「观察项」（只展示，不计入风险）
    分开计数并在标题里写明，避免"看着像告警、其实不算风险"的误读。
    """
    procs = [p for p in (st.get("processes") or []) if (p.get("level") or "clean") != "clean"]
    arts = list(st.get("artifacts") or [])
    flows = ((st.get("net") or {}).get("flows") or [])
    nets = [f for f in flows if (f.get("level") or "clean") != "clean"]
    watch = [f for f in flows
             if (f.get("level") or "clean") == "clean" and (f.get("regularity") or 0) >= 55]

    c_proc, c_art, c_net = _tally(procs), _tally(arts), _tally(nets)
    c_all = {k: c_proc[k] + c_art[k] + c_net[k] for k in _LEVELS}
    return {
        "procs": procs, "arts": arts, "nets": nets, "watch": watch,
        "c_proc": c_proc, "c_art": c_art, "c_net": c_net, "c_all": c_all,
        "rows": len(procs) + len(arts) + len(nets),
        "need_action": c_all["critical"] + c_all["high"],
    }


def _flow_rules_text(f: dict) -> str:
    """网络行的「判定依据」文案：优先用规则号 + 规则名，否则退回判决语。

    ⚠️ **绝不能直接访问 `f['findings']`** —— 下发给前端的网络流量是精简结构
    （`netmon._slim_flow`），里面**没有** findings，只有 `finding_ids`。
    报告初版直接取了 `f['findings']`，于是只要存在"规律性观察项"或"可疑外联"，
    导出就会 `KeyError('findings')` 整个失败（实测踩过，用户报的就是这个）。
    """
    ids = f.get("finding_ids") or []
    if ids:
        return "；".join(
            (f"[{i}] {_RULE_TITLE[i]}" if _RULE_TITLE.get(i) else f"[{i}]") for i in ids)
    return f.get("verdict") or ""


def _match_too_broad(mtype: str, value: str) -> str:
    """匹配值是否宽到"一网打尽"。返回错误说明；够具体则返回空串。

    ⚠️ 这是**启发式下限，不是安全边界**。真正的结构性防线是调用点里
    「这条 entry 只命中一个对象」的断言 —— 两者叠加使用：

      · 对象断言挡住"现在就已经命中多个对象"的条目；
      · 具体性下限挡住"现在只命中一个、但宽到能放行**将来**出现的对象"的条目。

    只做前者会漏：`exe_path_prefix = "C:\\"` 在当前快照里可能只命中一个对象
    （因为该规则此刻只有一个对象命中），但它把整个 C 盘都放行了 ——
    以后任何落在 C 盘的同类对象都会被静默忽略。红队 §2.1.3 指的就是这个残留。
    """
    v = (value or "").strip()
    if mtype == "exe_path_prefix":
        # 至少要到「盘符:\目录\子目录」这一级
        segs = [x for x in v.replace("/", "\\").split("\\")
                if x and not x.endswith(":")]
        if len(segs) < 2:
            return (f"路径前缀太宽（{v}）——至少给到「盘符:\\目录\\子目录」，"
                    f"否则等于把这一整片目录都放行")
    elif mtype in ("cmdline_contains", "subject_text_contains"):
        if len(v) < 8:
            return f"匹配文本太短（{v}）——至少 8 个字符，否则会命中大量无关对象"
    return ""


_ARTIFACT_SECTION_ZH = {
    "tasks": "计划任务", "drivers": "内核驱动", "run_keys": "注册表启动项",
    "defender": "Defender 排除项", "suspicious_reg": "可疑注册表键",
}


def display_proc_name(p: dict) -> str:
    """取进程的**可显示**名称。

    受保护的内核/驱动宿主进程（如 PID 312）系统会拒绝读取 name，
    psutil 返回空串。直接渲染就会在表格与报告里留下一格空白 ——
    用户无法判断"这行是什么"，也不知道空白代表"读不到"而非"程序有问题"。
    这里统一兜底成一句明确说明，与界面上的 name_unreadable 词条对应。
    """
    nm = (p or {}).get("name") or ""
    if nm:
        return nm
    pid = (p or {}).get("pid")
    return f"（进程名不可读 · PID {pid}）" if pid else "（进程名不可读）"


def build_report_html(st: dict) -> str:
    """由一份 state 快照生成 HTML 报告。

    纯函数（只读 st、不碰文件系统）—— 这样可以用合成数据做回归测试，
    专门盯住"顶部数字与下方表格不一致"这类问题。
    """
    import iocs

    s = st["summary"]
    b = report_buckets(st)
    ca, cp, car, cn = b["c_all"], b["c_proc"], b["c_art"], b["c_net"]
    net = st.get("net") or {}
    ns = net.get("summary") or {}
    nses = net.get("session") or {}

    def esc(x):
        return (str(x).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

    # ---- 结论：与上方计数同源，且覆盖"只有中危/低危"的情况
    #（初版只在 critical/high 时才有话说，于是"有中危"也会显示"未发现高风险特征"）
    if ca["critical"]:
        concl = ('<b style="color:#ff5c5c">发现严重风险项，高度疑似银狐木马活动，'
                 '请立即断网并处置。</b>')
    elif ca["high"]:
        concl = '<b style="color:#ffa53d">存在高危异常项，建议逐条核查。</b>'
    elif ca["medium"]:
        concl = ('<b style="color:#ffd666">存在若干中危可疑项，建议核对后决定是否处置。</b>')
    elif ca["low"]:
        concl = '<b style="color:#63b3ff">仅有低危观察项，通常无需处置。</b>'
    else:
        concl = ('本轮扫描未发现银狐相关风险特征。注意：本工具基于行为特征，'
                 '不能替代杀毒软件全盘扫描。')

    # ---- 未取到的制品小节（F-008）
    # "没查到"和"没取到"必须分开写。合并成一句"未发现异常"就是假阴性 ——
    # 用户会以为那几类查过了、是干净的，实际上根本没采集到。
    _unav = list(s.get("artifact_unavailable") or [])
    _unav_html = ""
    if _unav:
        _names = "、".join(_ARTIFACT_SECTION_ZH.get(k, k) for k in _unav)
        _unav_html = (f'<div class="warnbox">⚠ 本次有 <b>{len(_unav)}</b> 类系统痕迹'
                      f'<b>未取到</b>：{_names}。<br>这几类<b>没有结论</b>，'
                      f'不等于没有异常 —— 请重新扫描或检查权限。</div>')

    # ---- 二、异常进程
    rows = []
    for p in b["procs"]:
        # 一律用 .get + 兜底：报告是"事后取证"的载体，不能因为某个字段缺失
        # 而生成出带 undefined/KeyError 的报告（KeyError 会让整个导出直接失败）。
        _lv = p.get("level") or "clean"
        rows.append(
            "<tr>"
            f"<td class='sev {_lv}'>{rules.SEVERITY_ZH.get(_lv,'')}</td>"
            f"<td>{p.get('score') or 0}</td><td>{p.get('pid')}</td>"
            f"<td>{esc(display_proc_name(p))}</td>"
            f"<td class='path'>{esc(p.get('exe') or '')}</td>"
            f"<td>{esc(rules.sig_label(p))}</td>"
            f"<td>{esc('；'.join(f['title'] for f in p.get('findings') or []))}</td>"
            "</tr>")

    # ---- 三、系统痕迹
    arows = []
    for a in b["arts"]:
        kind = _KIND_ZH.get(a.get("kind", ""), a.get("kind", ""))
        arows.append(
            "<tr>"
            f"<td class='sev {a.get('level') or 'clean'}'>{rules.SEVERITY_ZH.get(a.get('level') or 'clean','')}</td>"
            f"<td>{a.get('score') or 0}</td><td>{esc(kind)}</td><td>{esc(a.get('title') or '')}</td>"
            f"<td class='path'>{esc(a.get('subtitle',''))}</td>"
            f"<td>{esc('；'.join(f['title'] for f in a.get('findings') or []))}</td>"
            "</tr>")

    # ---- 四、网络外联
    nrows = []
    for f in (b["nets"] + b["watch"]):
        lv = f.get("level") or "clean"
        badge = (rules.SEVERITY_ZH.get(lv, "") if lv != "clean" else "观察")
        cls = lv if lv != "clean" else "watch"
        nrows.append(
            "<tr>"
            f"<td class='sev {cls}'>{badge}</td>"
            f"<td>{float(f.get('score') or 0):.0f}</td>"
            f"<td>{esc(f['regularity'] if f['regularity'] is not None else '不可评估')}</td>"
            f"<td>{esc(f['avg_interval'] if f['avg_interval'] is not None else '—')}</td>"
            f"<td>{f['pid']}</td><td>{esc(f['name'])}</td>"
            f"<td class='path'>{esc(f['rip'])}:{f['rport']}</td>"
            f"<td>{esc(f['ip_scope_zh'])}</td>"
            f"<td>{esc(_flow_rules_text(f))}</td>"
            "</tr>")

    net_html = ""
    if net:
        estats_txt = ("可用 —— 已启用每连接字节统计，可识别长连接上的周期性数据心跳"
                      if net.get("estats") else
                      "不可用 —— " + esc(net.get("estats_note") or "未启用") +
                      "；本次仅依据连接建立事件判定，长连接型心跳可能漏检")
        net_html = f"""
<h2>四、网络外联与心跳规律性 —— 可疑 {len(b['nets'])} 项 / 规律性观察 {len(b['watch'])} 项</h2>
<div class="meta">观测 {esc(nses.get('duration', 0))} 秒 ·
 采样周期 {esc(net.get('sample_interval'))} 秒 ·
 活动连接 {esc(net.get('live_conns', 0))} 条 ·
 流量条目 {esc(ns.get('flows', 0))} 个 ·
 其中可评估规律性 {esc(ns.get('evaluated', 0))} 个 ·
 规律性 ≥85 的 {esc(ns.get('high_reg', 0))} 个<br>
 字节统计（estats）：{estats_txt}</div>
<p><b>「观察」是什么意思</b>：规律性 ≥55 但没有旁证（进程可信、目标端点也不可疑）的外联，
只作为时序观察展示，<b>不计入风险等级</b>。软件更新检查、遥测上报同样极其规律，
只凭"像机器打拍子"就告警会让这一页失去意义。</p>
<table><tr><th>等级</th><th>风险分</th><th>规律性</th><th>平均周期(s)</th>
<th>PID</th><th>进程</th><th>远端</th><th>地址归属</th><th>判定依据</th></tr>
{''.join(nrows) or '<tr><td colspan="9">未发现规律性异常或可疑的网络外联</td></tr>'}</table>
"""
    else:
        net_html = ("<h2>四、网络外联与心跳规律性</h2>"
                    "<p>本次未启用网络检测。</p>")

    # ---- 五、高危项详情（进程 + 系统痕迹，与上面的计数同源）
    # ⚠️ 这里的每一项都必须用 .get 取：报告是"事后取证"的载体，
    #    它的正确性不能依赖"上游一定填好了 findings/level/score"。
    #    2026-10-08 回归用例实测：进程缺 findings 键时 p["findings"] 抛 KeyError，
    #    整个导出直接失败 —— 而用户点"导出报告"往往正是为了留证据。
    detail_blocks = []
    for p in b["procs"]:
        if (p.get("level") or "clean") not in ("critical", "high"):
            continue
        items = "".join(
            f"<li><b>[{esc(f.get('rule_id') or '')}] {esc(f.get('title') or '')}</b>"
            f"<div class='ev'>{esc(f.get('evidence') or '')}</div>"
            f"<div class='ad'>{esc(f.get('advice') or '')}</div></li>"
            for f in (p.get("findings") or []))
        _plv = p.get("level") or "clean"
        detail_blocks.append(
            f"<div class='card'><h3>{esc(display_proc_name(p))} <span class='pid'>进程 · PID {p.get('pid')}</span>"
            f"<span class='sev {_plv}'>{rules.SEVERITY_ZH.get(_plv,'')} · {p.get('score') or 0}分</span></h3>"
            f"<div class='path'>{esc(p.get('exe') or '')}</div>"
            f"<div class='path'>命令行：{esc((p.get('cmdline_str') or '')[:300])}</div>"
            f"<ul>{items}</ul></div>")
    for a in b["arts"]:
        if (a.get("level") or "clean") not in ("critical", "high"):
            continue
        items = "".join(
            f"<li><b>[{esc(f.get('rule_id') or '')}] {esc(f.get('title') or '')}</b>"
            f"<div class='ev'>{esc(f.get('evidence') or '')}</div>"
            f"<div class='ad'>{esc(f.get('advice') or '')}</div></li>"
            for f in (a.get("findings") or []))
        kind = _KIND_ZH.get(a.get("kind", ""), a.get("kind", ""))
        _alv = a.get("level") or "clean"
        detail_blocks.append(
            f"<div class='card'><h3>{esc(a.get('title') or '')} <span class='pid'>系统痕迹 · {esc(kind)}</span>"
            f"<span class='sev {_alv}'>{rules.SEVERITY_ZH.get(_alv,'')} · {a.get('score') or 0}分</span></h3>"
            f"<div class='path'>{esc(a.get('subtitle',''))}</div>"
            f"<ul>{items}</ul></div>")

    ts = time.strftime("%Y%m%d-%H%M%S")
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
 .warnbox{{margin:12px 0;padding:10px 14px;border-radius:6px;font-size:13px;line-height:1.7;color:#ffd666;background:rgba(255,166,61,.10);border-left:3px solid #ffa53d}}
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
 .sev.watch{{color:#7d8fa9}}
 .tally td,.tally th{{text-align:center}} .tally td:first-child,.tally th:first-child{{text-align:left}}
 .tally tr.sum td{{border-top:2px solid #2b3d5c;font-weight:700;background:#101a2b}}
 .note{{color:#7d8fa9;font-size:12.5px;background:#101a2b;border-left:2px solid #2b3d5c;
   padding:9px 12px;border-radius:6px}}
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
 已扫描 {s['scan_count']} 轮 · IOC 版本 {iocs.IOC_VERSION} · 程序版本 {version.VERSION}</div>

<div class="grid">
 <div class="kpi"><b>{s['total']}</b><span>进程总数</span></div>
 <div class="kpi"><b>{b['rows']}</b><span>异常项合计</span></div>
 <div class="kpi"><b style="color:#ff5c5c">{ca['critical']}</b><span>严重项</span></div>
 <div class="kpi"><b style="color:#ffa53d">{ca['high']}</b><span>高危项</span></div>
 <div class="kpi"><b>{s['connections']}</b><span>网络连接</span></div>
 <div class="kpi"><b>{len(b['watch'])}</b><span>规律性观察项</span></div>
</div>

<h2>一、结论摘要</h2>
<p>{concl}</p>
{_unav_html}

<p><b>本报告共列出 {b['rows']} 项异常</b>（其中需优先处置的严重+高危共
<b>{b['need_action']}</b> 项），按类别分布如下：</p>
<table class="tally">
<tr><th>类别</th><th>严重</th><th>高危</th><th>中危</th><th>低危</th><th>合计</th></tr>
<tr><td>异常进程</td><td>{cp['critical']}</td><td>{cp['high']}</td>
    <td>{cp['medium']}</td><td>{cp['low']}</td><td>{len(b['procs'])}</td></tr>
<tr><td>系统痕迹</td><td>{car['critical']}</td><td>{car['high']}</td>
    <td>{car['medium']}</td><td>{car['low']}</td><td>{len(b['arts'])}</td></tr>
<tr><td>网络外联</td><td>{cn['critical']}</td><td>{cn['high']}</td>
    <td>{cn['medium']}</td><td>{cn['low']}</td><td>{len(b['nets'])}</td></tr>
<tr class="sum"><td>合计</td><td>{ca['critical']}</td><td>{ca['high']}</td>
    <td>{ca['medium']}</td><td>{ca['low']}</td><td>{b['rows']}</td></tr>
</table>
<p class="note"><b>口径说明</b>：本表数字与下方各表格<b>逐行对应</b> ——
"异常进程"对应第二节、"系统痕迹"对应第三节、"网络外联"对应第四节。
三者是<b>三类不同的对象</b>（运行中的进程 / 系统里的持久化与落地痕迹 / 网络连接），
所以各自的等级计数分开列，不能只看其中一栏就下结论。</p>

<h2>二、异常进程 —— {len(b['procs'])} 项</h2>
<table><tr><th>等级</th><th>评分</th><th>PID</th><th>名称</th><th>路径</th>
<th>签名</th><th>命中规则</th></tr>{''.join(rows) or '<tr><td colspan="7">无</td></tr>'}</table>

<h2>三、系统痕迹异常 —— {len(b['arts'])} 项</h2>
<p class="note"><b>「系统痕迹」指什么</b>：木马除了"正在运行的进程"之外，
还会在系统里留下需要长期存在的东西 —— 计划任务、系统服务、内核驱动、
hosts 文件改动、注册表启动项与 Defender 排除项、以及磁盘上落地的伪装文件。
它们的特点是<b>进程被杀掉之后依然存在</b>，所以必须单独查、单独清。
本工具把这一类统一叫"系统痕迹"（也叫系统制品 / 制品）。</p>
<table><tr><th>等级</th><th>评分</th><th>类型</th><th>对象</th><th>位置</th>
<th>命中规则</th></tr>{''.join(arows) or '<tr><td colspan="6">无</td></tr>'}</table>

{net_html}

<h2>五、高危项详情与处置建议 —— {b['need_action']} 项</h2>
{''.join(detail_blocks) or '<p>无严重 / 高危项。</p>'}

<footer>本报告由「银狐进程监视器」自动生成。检测规则依据 CNCERT/天融信、FreeBuf、火绒安全实验室、
先知社区等公开技术报告编制；IOC 会随木马迭代失效，请定期更新。<br>
本工具为行为检测辅助工具，无法覆盖纯内存执行、内核级隐藏等场景，不能替代专业 EDR 与杀毒软件。
网络章节的规律性判定基于本机连接表与 TCP 统计计数器，<b>不抓包、不解密、不发起任何网络请求</b>。</footer>
</body></html>"""
    return html


def export_report(m: Monitor) -> str:
    os.makedirs(REPORT_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(REPORT_DIR, f"银狐排查报告-{ts}.html")
    html = build_report_html(m.state())
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


# ================================================================
# 启动
# ================================================================

def serve(host: str = "127.0.0.1", port: int = 8787,
          proc_interval: float = 3.0, artifact_interval: float = 180.0,
          net_interval: float = netmon.DEFAULT_SAMPLE_INTERVAL,
          net_duration: float = netmon.DEFAULT_DURATION,
          net_enabled: bool = True) -> ThreadingHTTPServer:
    m = Monitor(proc_interval=proc_interval, artifact_interval=artifact_interval,
                net_interval=net_interval, net_duration=net_duration,
                net_enabled=net_enabled)
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
