# -*- coding: utf-8 -*-
"""
网络心跳规律性引擎 —— 从"银狐的最终目的是连上 C2"这个事实出发的反向检测。

## 为什么盯"规律性"

C2 要活着，就必须**周期性**地向控制端报到（心跳 / beacon）。这是它的生存必需，
不是可选特征。而"周期性"在时间序列上留下的是**极低的抖动**：

    银狐心跳     : 60.0s, 60.4s, 59.8s, 60.1s   → 变异系数 CV ≈ 0.004
    浏览器/CDN   : 0.3s, 12s, 1.1s, 47s, 0.8s   → CV ≈ 1.4
    软件更新检查  : 300s, 300s, 300s（同样很规律 —— 所以规律性本身不足以定罪）

所以本引擎的输出是**两个独立的维度**，绝不混为一谈：

  · **规律性（0–100）** —— 纯时序指标。回答"这个外联有多像机器在打拍子"。
  · **风险分（0–100）** —— 由规则判定，回答"这件事有多可疑"。

用户界面把两者分列显示、各自高亮。规律性高但进程可信、端点正常的流量
（例如 Windows 遥测）会出现在"规律"维度里，但不会进入风险告警 —— 这是刻意的：
把系统自身的遥测刷成高危，用户三天内就会对告警脱敏，工具就废了。

## 两条互相补充的证据流

1. **连接建立事件**（TCP）—— 覆盖"连上→发数据→断开→再连"的心跳。
   银狐的短连接型回连、部分 C2 框架的 poll 模式都属于此类。

2. **数据突发事件**（TCP，依赖 netapi.estats）—— 覆盖**长连接上的心跳**。
   这条更关键：银狐常见的持久 C2 是一条一直挂着的 TCP 连接，
   连接表上永远是"存在"，只有字节计数才看得出"每 60 秒推一小段数据"。
   实测（本机）：某连接 25 秒内只在 t=6 出了 1414 字节、t=7 进了 333 字节，
   其余时刻计数完全不动 —— 这就是心跳在字节序列上的样子。

## 明确的观测边界（写在代码里，也写在界面上）

- **采样精度**：默认 1 秒一次。间隔短于采样周期的行为会发生混叠，
  本引擎对"中位间隔 < 4×采样周期"的结果标记 `resolution_limited` 并降权。
- **不抓包、不解密**：只看连接表与 TCP 栈计数器，看不到载荷内容，
  因此"规律性高"只是**行为特征**，不能证明那是 C2。
- **UDP 无远端**：UDP 表只有本地端口，无法关联远端，只做端口清点，不参与规律性判定。
- **非管理员**：读不到字节计数，自动退化为"仅连接建立事件"模式，界面会明确标注。
- **零外联**：本模块不做 DNS 解析、不打开 socket、不发起任何网络请求。

## 会话模型

一次「检测会话」= 一段固定长度的观测窗口。滑块决定窗口长度，可随时拖动调整
（拖长会延长当前会话，拖短到已过时间之下则立即结算）。打开程序时自动开始一轮。
"""

from __future__ import annotations

import ipaddress
import os
import threading
import time
import traceback

import psutil

import iocs
import netapi
import rules

# ================================================================
# 参数
# ================================================================

DEFAULT_SAMPLE_INTERVAL = 1.0        # 采样周期（秒）
DURATION_STOPS = [30, 60, 120, 180, 300, 600, 900]
DEFAULT_DURATION = 120

MAX_FLOWS = 1500                     # 流量表上限（防内存无限增长）
MAX_CONNS = 2000                     # 连接实例表上限
MAX_EVENTS = 800                     # 每个流的单类事件上限
MERGE_FACTOR = 1.6                   # 事件合并窗口 = MERGE_FACTOR × 采样周期
MIN_INTERVALS = 3                    # 至少 3 个间隔才评估规律性
REG_EMIT_MIN = 55                    # 规律性低于此值不产生规则命中
CV_SCALE = 0.16                      # 规律性曲线尺度：CV=0.16 时得 50 分
HISTORY_KEEP = 5

# 采样周期下限：低于此值收益有限但 CPU 明显上升
MIN_SAMPLE_INTERVAL = 0.4

# ---------------------------------------------------------------- 端口分类
# 常见且低风险的服务端口（连这些端口不构成任何加分）
COMMON_PORTS = {
    22, 25, 53, 80, 110, 123, 143, 389, 443, 465, 587, 636, 853,
    993, 995, 1080, 1194, 1900, 2049, 3478, 3479, 5060, 5061, 5222,
    5228, 5353, 5672, 8080, 8443, 9418, 8883,
}
# 常被远控 / 横向移动滥用的端口（本身是正常服务，但对外发起值得注意）
ABUSED_PORTS = {
    23, 135, 137, 138, 139, 445, 1433, 1521, 3306, 3389,
    4444, 5432, 5900, 5985, 5986, 6379, 9200, 11211, 27017,
}

SCOPE_ZH = {
    "public": "公网", "private": "内网", "cgnat": "运营商级 NAT",
    "loopback": "回环", "linklocal": "链路本地", "multicast": "组播",
    "unspecified": "未指定", "unknown": "未知",
}

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


# ================================================================
# 小工具
# ================================================================

def ip_scope(ip: str) -> str:
    """地址归属分类。不依赖 Python 版本对 is_private 的定义差异，显式判断 CGNAT。"""
    s = (ip or "").strip()
    if not s:
        return "unknown"
    if s.lower().startswith("::ffff:"):
        s = s[7:]
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return "unknown"
    if a.is_loopback:
        return "loopback"
    if a.is_multicast:
        return "multicast"
    if a.is_unspecified:
        return "unspecified"
    if a.is_link_local:
        return "linklocal"
    if a.version == 4 and a in _CGNAT:
        return "cgnat"
    if a.is_private:
        return "private"
    return "public"


def port_class(rport: int) -> str:
    if rport in iocs.SUSPICIOUS_PORTS:
        return "silverfox"          # 银狐公开报告点名的 C2 端口段
    if rport in ABUSED_PORTS:
        return "abused"
    if rport in COMMON_PORTS:
        return "common"
    return "nonstandard"


def fmt_duration(sec: float) -> str:
    sec = max(0.0, float(sec or 0))
    if sec < 90:
        return f"{sec:.1f} 秒"
    if sec < 3600:
        return f"{sec / 60:.1f} 分钟"
    return f"{sec / 3600:.1f} 小时"


# ================================================================
# 规律性分析（纯函数，便于单测）
# ================================================================

def merge_events(times: list[float], window: float) -> list[float]:
    """把窗口内相邻的事件合并成一个。

    为什么必须合并：
      · 一次心跳可能在两个采样点各产生一次字节增量（先发后收）——
        不合并就会凭空多出一个"1 秒间隔"，把规律性算歪；
      · 浏览器之类会在同一瞬间开好几条连接，它们应当算作**一个**事件。
    """
    out: list[float] = []
    for t in sorted(times):
        if out and (t - out[-1]) <= window:
            continue
        out.append(t)
    return out


def analyze_intervals(times: list[float], merge_window: float) -> dict | None:
    """对事件时刻序列做规律性分析。

    返回 None 表示样本不足以给出结论（**宁可说"测不出"，也不给假精度**）。

    指标：
      mean/median  平均与中位间隔
      cv           变异系数 σ/μ —— 抖动大小的标准度量
      mad_ratio    中位绝对偏差 / 中位数 —— 对离群值稳健的离散度
      regularity   0–100 规律性得分（主输出）
      jitter_pct   抖动百分比（= CV×100，与 Cobalt Strike 的 jitter 同量纲）
    """
    if len(times) < 2:
        return None
    merged = merge_events(times, merge_window)
    if len(merged) < MIN_INTERVALS + 1:
        return None
    d = [merged[i + 1] - merged[i] for i in range(len(merged) - 1)]
    d = [x for x in d if x >= 0.15]          # 丢掉采样抖动造成的近零间隔
    n = len(d)
    if n < MIN_INTERVALS:
        return None

    mean = sum(d) / n
    if mean <= 0:
        return None
    var = sum((x - mean) ** 2 for x in d) / n
    sd = var ** 0.5
    cv = sd / mean

    ds = sorted(d)
    med = ds[n // 2] if n % 2 else (ds[n // 2 - 1] + ds[n // 2]) / 2
    devs = sorted(abs(x - med) for x in d)
    mad = devs[n // 2] if n % 2 else (devs[n // 2 - 1] + devs[n // 2]) / 2
    mad_ratio = (mad / med) if med else 0.0

    # 规律性曲线：CV=0 → 100；CV=0.16 → 50；CV=0.32 → 20；CV≥0.6 → <6
    reg = 100.0 / (1.0 + (cv / CV_SCALE) ** 2.2)

    return {
        "n": n,
        "events": len(merged),
        "mean": round(mean, 3),
        "median": round(med, 3),
        "sd": round(sd, 3),
        "cv": round(cv, 4),
        "mad_ratio": round(mad_ratio, 4),
        "min": round(ds[0], 3),
        "max": round(ds[-1], 3),
        "regularity": round(reg, 1),
        "jitter_pct": round(cv * 100, 1),
        "confidence": round(min(1.0, n / 6.0), 3),
        "times": [round(t, 3) for t in merged],
        "intervals": [round(x, 3) for x in d],
    }


# ================================================================
# 端点风险
# ================================================================

def endpoint_risk(rip: str, rport: int) -> tuple[float, list[str]]:
    """远端端点本身的可疑度（0–100）与理由列表。"""
    if rip in iocs.MALICIOUS_IPS:
        return 100.0, [f"{rip} 命中公开披露的银狐 C2 地址清单"]

    pts = 0.0
    why: list[str] = []
    pc = port_class(rport)
    if pc == "silverfox":
        pts += 55
        why.append(f"端口 {rport} 属银狐公开报告点名的 C2 端口段")
    elif pc == "abused":
        pts += 22
        why.append(f"端口 {rport} 常被远控/横向移动滥用")
    elif pc == "nonstandard":
        pts += 16
        why.append(f"端口 {rport} 非标准服务端口")

    sc = ip_scope(rip)
    if sc == "public":
        pts += 6
    elif sc in ("private", "cgnat", "linklocal"):
        pts -= 12
        why.append("目标位于内网")

    return max(0.0, min(100.0, pts)), why


# ================================================================
# 数据结构
# ================================================================

class _Conn:
    """一条具体的 TCP 连接实例（四元组含本地端口）。"""
    __slots__ = ("key", "flow_key", "pid", "proto", "lip", "lport", "rip", "rport",
                 "first_seen", "last_seen", "last_out", "last_in", "enabled",
                 "reset_count")

    def __init__(self, c: dict, now: float):
        self.key = (c["pid"], c["proto"], c["lip"], c["lport"], c["rip"], c["rport"])
        self.flow_key = flow_key_of(c["pid"], c["proto"], c["rip"], c["rport"])
        self.pid = c["pid"]
        self.proto = c["proto"]
        self.lip = c["lip"]
        self.lport = c["lport"]
        self.rip = c["rip"]
        self.rport = c["rport"]
        self.first_seen = now
        self.last_seen = now
        self.last_out = -1
        self.last_in = -1
        self.enabled = False
        self.reset_count = 0


class _Flow:
    """按 (PID, 协议, 远端IP, 远端端口) 聚合的流量。"""
    __slots__ = ("key", "pid", "proto", "rip", "rport", "first_seen", "last_seen",
                 "conn_events", "byte_events", "byte_amounts", "pre_existing",
                 "durations", "idle_ticks", "active_ticks", "bytes_out", "bytes_in",
                 "instances", "resets")

    def __init__(self, key: str, pid: int, proto: str, rip: str, rport: int, now: float):
        self.key = key
        self.pid = pid
        self.proto = proto
        self.rip = rip
        self.rport = rport
        self.first_seen = now
        self.last_seen = now
        self.conn_events: list[float] = []
        self.byte_events: list[float] = []
        self.byte_amounts: list[int] = []
        self.pre_existing = False
        self.durations: list[float] = []
        self.idle_ticks = 0
        self.active_ticks = 0
        self.bytes_out = 0
        self.bytes_in = 0
        self.instances = 0
        self.resets = 0


def flow_key_of(pid: int, proto: str, rip: str, rport: int) -> str:
    return f"{pid}|{proto}|{rip}|{rport}"


def parse_flow_key(key: str) -> tuple[int, str, str, int] | None:
    parts = (key or "").split("|")
    if len(parts) != 4:
        return None
    try:
        return int(parts[0]), parts[1], parts[2], int(parts[3])
    except ValueError:
        return None


# ================================================================
# 引擎
# ================================================================

class NetMonitor:
    def __init__(self, sample_interval: float = DEFAULT_SAMPLE_INTERVAL):
        self.lock = threading.RLock()
        self.sample_interval = max(MIN_SAMPLE_INTERVAL, float(sample_interval))

        self.conns: dict[tuple, _Conn] = {}
        self.flows: dict[str, _Flow] = {}
        self.udp_by_pid: dict[int, list[int]] = {}

        self._proc_index: dict[int, dict] = {}
        self._name_cache: dict[int, tuple[str, str]] = {}

        self.session: dict | None = None
        self.history: list[dict] = []
        self._alerted: set[str] = set()

        self.running = True
        self.tick = 0
        self.sample_ms = 0
        self.last_error = ""
        self.estats_ok = False
        self.estats_note = ""
        self.estats_fail_streak = 0
        # F-011：退避重试的下次允许时间。旧逻辑里失败计数**只增不减**，
        # 三次瞬时失败就把字节证据流关到本次会话结束 —— 而"长连接上的心跳"
        # 恰恰只能靠字节计数发现，等于永久漏检。改成失败可退避重试、
        # 成功即清零，并把降级原因说清楚（不再一律甩给"权限"）。
        self.estats_retry_after = 0.0
        self._results: list[dict] = []
        self._result_tick = -1
        self._result_at = 0.0
        self._live_count = 0
        self.started_at = time.time()

    # ------------------------------------------------------------ 生命周期
    def start(self):
        self.estats_ok = netapi.available()
        if not self.estats_ok:
            self.estats_note = f"采集接口不可用：{netapi.load_error()}"
        threading.Thread(target=self._loop, daemon=True, name="net-loop").start()

    def stop(self):
        self.running = False

    def update_proc_index(self, index: dict[int, dict]):
        """由进程扫描线程推送 pid → 进程对象，用于联合判定。"""
        with self.lock:
            self._proc_index = index

    # ------------------------------------------------------------ 会话
    def start_session(self, duration: float, auto: bool = False) -> dict:
        duration = float(duration or DEFAULT_DURATION)
        duration = max(5.0, min(7200.0, duration))
        with self.lock:
            now = time.monotonic()
            self.conns.clear()
            self.flows.clear()
            self.udp_by_pid.clear()
            self._alerted.clear()
            self._results = []
            self._result_tick = -1
            self.session = {
                "id": int(time.time()),
                "started_mono": now,
                "started_at": time.time(),
                "duration": duration,
                "phase": "collecting",
                "auto": bool(auto),
                "finished_at": 0.0,
                "tick_at_start": self.tick,
            }
            return {"ok": True, "duration": duration}

    def stop_session(self) -> dict:
        with self.lock:
            if not self.session:
                return {"ok": False, "msg": "当前没有进行中的检测"}
        # 在锁外结算：_finalize → _recompute → 告警回调会去拿 Monitor 的锁，
        # 若此时仍持有 netmon.lock，就形成 netmon.lock → monitor.lock 的嵌套。
        # 而 Monitor.state() 是反过来的顺序（先取 netmon 快照再进自己的锁），
        # 两者一旦交叉就是死锁。这里统一保证"告警回调不在锁内触发"。
        self._finalize()
        return {"ok": True, "msg": "检测已停止并结算"}

    def set_duration(self, duration: float) -> dict:
        """滑块调整：直接改变当前会话的目标长度。

        拖长 → 会话继续收集；拖短到已过时长之下 → 立即结算。
        """
        # F-003：非有限值（NaN / inf）必须**明确拒绝**，不能静默钳成边界值。
        # 旧写法 max(5.0, min(7200.0, nan)) 在 CPython 上会得到 7200.0，
        # 但返回消息用的是原值 —— 于是接口回"已改为 0.0 秒"而实际是 7200 秒，
        # 用户和日志都对不上。这类"说得和做的不一样"比报错更难查。
        try:
            duration = float(duration)
        except (TypeError, ValueError):
            return {"ok": False, "bad": True, "msg": "观测时长必须是数字"}
        if not math.isfinite(duration):
            return {"ok": False, "bad": True, "msg": "观测时长必须是有限数字（不接受 NaN / 无穷）"}
        duration = max(5.0, min(7200.0, duration))
        with self.lock:
            if not self.session or self.session["phase"] != "collecting":
                restart = True
            else:
                restart = False
                self.session["duration"] = duration
                elapsed = time.monotonic() - self.session["started_mono"]
                expired = elapsed >= duration
        if restart:
            self.start_session(duration)
            return {"ok": True, "duration": duration, "restarted": True}
        if expired:
            self._finalize()          # 同上：锁外结算
            return {"ok": True, "duration": duration, "finalized": True}
        return {"ok": True, "duration": duration}

    def _finalize(self):
        s = self.session
        if not s:
            return
        s["phase"] = "done"
        s["finished_at"] = time.time()
        self._recompute(force=True)
        top = [f for f in self._results if f["level"] in ("critical", "high")][:5]
        self.history.insert(0, {
            "id": s["id"],
            "started_at": time.strftime("%H:%M:%S", time.localtime(s["started_at"])),
            "duration": s["duration"],
            "flows": len(self._results),
            "regular": sum(1 for f in self._results if (f.get("regularity") or 0) >= 70),
            "critical": sum(1 for f in self._results if f["level"] == "critical"),
            "high": sum(1 for f in self._results if f["level"] == "high"),
            "top": [{"name": f["name"], "rip": f["rip"], "rport": f["rport"],
                     "regularity": f.get("regularity")} for f in top],
        })
        del self.history[HISTORY_KEEP:]

    # ------------------------------------------------------------ 采样主循环
    def _loop(self):
        while self.running:
            t0 = time.perf_counter()
            try:
                self._tick()
            except Exception:
                self.last_error = traceback.format_exc(limit=3)
            self.sample_ms = int((time.perf_counter() - t0) * 1000)
            time.sleep(max(0.05, self.sample_interval - (time.perf_counter() - t0)))

    def _tick(self):
        now = time.monotonic()
        with self.lock:
            self.tick += 1
            tick_no = self.tick
            collecting = bool(self.session and self.session["phase"] == "collecting")

        # 会话已结束：只维持最小采样（用于 estats 计数基准），不再累积证据
        snapshot = netapi.enumerate_tcp()
        udp = netapi.enumerate_udp()

        with self.lock:
            self.udp_by_pid = {}
            for u in udp:
                if u["lport"]:
                    self.udp_by_pid.setdefault(u["pid"], []).append(u["lport"])

            live: dict[tuple, dict] = {}
            for c in snapshot:
                if not c["pid"]:
                    continue
                if c["state"] not in netapi.LIVE_STATES:
                    continue
                if not c["rip"]:
                    continue
                sc = ip_scope(c["rip"])
                if sc in ("loopback", "unspecified", "multicast"):
                    continue          # 回环/未指定不构成 C2，直接排除
                live[(c["pid"], c["proto"], c["lip"], c["lport"], c["rip"], c["rport"])] = c
                if len(live) >= MAX_CONNS:
                    break

            if not collecting:
                # 会话结束后：不再累积证据，但保持"活动连接数"可见，
                # 并刷新 last_seen 基准，避免下一轮把老连接误当成新建立。
                for k, c in live.items():
                    st = self.conns.get(k)
                    if st is not None:
                        st.last_seen = now
                for k in list(self.conns):
                    if k not in live:
                        del self.conns[k]
                self._live_count = len(live)
                return

            first_tick = tick_no == (self.session["tick_at_start"] + 1)

            # ---- 新出现的连接 → 记为一次"连接建立事件"
            for k, c in live.items():
                st = self.conns.get(k)
                if st is None:
                    if len(self.flows) >= MAX_FLOWS and \
                            flow_key_of(c["pid"], c["proto"], c["rip"], c["rport"]) not in self.flows:
                        continue
                    st = _Conn(c, now)
                    self.conns[k] = st
                    fk = st.flow_key
                    fl = self.flows.get(fk)
                    if fl is None:
                        fl = _Flow(fk, c["pid"], c["proto"], c["rip"], c["rport"], now)
                        self.flows[fk] = fl
                    fl.instances += 1
                    if first_tick:
                        # 会话开始前就已建立的连接：我们不知道它真正的建立时刻，
                        # 只能记一个 t0 作为估计值，并在证据里标注。
                        fl.pre_existing = True
                        self._add_event(fl.conn_events, 0.0)
                    else:
                        self._add_event(fl.conn_events, now - self.session["started_mono"])
                    fl.last_seen = now
                    # 开启字节统计（每条连接只需一次；失败则整机降级）
                    if c["proto"].startswith("tcp") and self.estats_ok:
                        if netapi.enable_estats(c):
                            st.enabled = True
                            # 成功即清零：否则历史上攒下的失败次数会把
                            # 后来的一次瞬时抖动直接推过阈值。
                            self.estats_fail_streak = 0
                            self.estats_retry_after = 0.0
                        else:
                            self.estats_fail_streak += 1
                            if self.estats_fail_streak >= 3 and self.estats_ok:
                                self.estats_ok = False
                                self.estats_retry_after = now + 60.0
                                self.estats_note = (
                                    "开启字节统计失败，已暂时退化为仅连接事件检测"
                                    "（60 秒后自动重试）。若持续失败，"
                                    "常见原因是未以管理员身份运行")
                else:
                    st.last_seen = now

            # ---- 消失的连接 → 记录存活时长
            for k, st in list(self.conns.items()):
                if k not in live:
                    fl = self.flows.get(st.flow_key)
                    if fl is not None:
                        fl.durations.append(now - st.first_seen)
                        del fl.durations[:-MAX_EVENTS]
                    del self.conns[k]

            # ---- 字节采样
            flow_delta: dict[str, int] = {}
            for k, st in self.conns.items():
                if not st.enabled:
                    continue
                v = netapi.read_estats({"proto": st.proto, "lip": st.lip,
                                        "lport": st.lport, "rip": st.rip, "rport": st.rport})
                if v is None:
                    continue
                out, inn = v
                if st.last_out < 0:
                    st.last_out, st.last_in = out, inn
                    continue
                d_out, d_in = out - st.last_out, inn - st.last_in
                if d_out < 0 or d_in < 0:
                    # 计数回退 = 该四元组已被新连接实例复用（实测确认会出现）。
                    # 这不是错误，反而是"连接重建"的证据；绝不把负增量当流量。
                    st.reset_count += 1
                    fl = self.flows.get(st.flow_key)
                    if fl is not None:
                        fl.resets += 1
                    st.last_out, st.last_in = out, inn
                    continue
                st.last_out, st.last_in = out, inn
                if d_out or d_in:
                    fl = self.flows.get(st.flow_key)
                    if fl is not None:
                        fl.bytes_out += d_out
                        fl.bytes_in += d_in
                        flow_delta[st.flow_key] = flow_delta.get(st.flow_key, 0) + d_out + d_in

            t_rel = now - self.session["started_mono"]
            for fk, delta in flow_delta.items():
                fl = self.flows.get(fk)
                if fl is None:
                    continue
                self._add_event(fl.byte_events, t_rel)
                self._add_event(fl.byte_amounts, delta)
                fl.active_ticks += 1

            active = set(flow_delta)
            for fk, fl in self.flows.items():
                if fk not in active and fl.bytes_out + fl.bytes_in > 0:
                    fl.idle_ticks += 1

            self._live_count = len(live)

            due = time.monotonic() - self.session["started_mono"] >= self.session["duration"]

        # ⚠️ 必须在锁外执行结算/重算：_recompute 会触发告警回调，而回调要去拿
        #    Monitor 的锁。若在锁内触发，就形成 netmon.lock → monitor.lock 的嵌套，
        #    与 Monitor.state() 的取锁顺序相反 → 死锁。
        if due:
            self._finalize()
        elif tick_no % 2 == 0:
            self._recompute()

    @staticmethod
    def _add_event(lst: list, v):
        lst.append(v)
        if len(lst) > MAX_EVENTS:
            del lst[:len(lst) - MAX_EVENTS]

    # ------------------------------------------------------------ 分析
    def _proc_of(self, pid: int) -> dict | None:
        p = self._proc_index.get(pid)
        if p is not None:
            return p
        return None

    def _name_of(self, pid: int) -> tuple[str, str]:
        c = self._name_cache.get(pid)
        if c is not None:
            return c
        name, exe = f"PID {pid}", ""
        try:
            pr = psutil.Process(pid)
            name = pr.name()
            try:
                exe = pr.exe() or ""
            except Exception:
                exe = ""
        except Exception:
            pass
        if len(self._name_cache) > 4000:
            self._name_cache.clear()
        self._name_cache[pid] = (name, exe)
        return name, exe

    def _recompute(self, force: bool = False):
        """计算所有流的规律性与风险分。结果缓存在 _results。

        会话结束后若已有结果，则**冻结不再重算** —— 这是"结算"的语义：
        用户看到的应是那一段观测窗口的结论，而不是随机器状态漂移的数字。
        """
        now = time.monotonic()
        with self.lock:
            if not force and self._result_tick == self.tick:
                return
            if not force and now - self._result_at < 1.2:
                return
            if not force and self.session and self.session["phase"] != "collecting" \
                    and self._results:
                return
            self._result_tick = self.tick
            self._result_at = now
            session = self.session
            flows = list(self.flows.values())
            conns_by_flow: dict[str, list[_Conn]] = {}
            for st in self.conns.values():
                conns_by_flow.setdefault(st.flow_key, []).append(st)
            udp_by_pid = dict(self.udp_by_pid)
            proc_index = self._proc_index
            sample_interval = self.sample_interval

        merge_w = max(1.0, MERGE_FACTOR * sample_interval)
        results: list[dict] = []
        for fl in flows:
            try:
                results.append(self._analyze_flow(fl, conns_by_flow.get(fl.key, []),
                                                  udp_by_pid, proc_index, merge_w,
                                                  sample_interval))
            except Exception:
                continue
        results.sort(key=lambda x: (-x["score"], -(x.get("regularity") or -1)))

        with self.lock:
            self._results = results
            if session:
                session["flows"] = len(results)

        # 高危流量进入告警时间线（每个流每次会话只报一次）
        self._emit_alerts(results)

    def _analyze_flow(self, fl: _Flow, conns: list[_Conn], udp_by_pid: dict,
                      proc_index: dict, merge_w: float,
                      sample_interval: float) -> dict:
        proc = proc_index.get(fl.pid)
        name, exe = self._name_of(fl.pid)
        if proc:
            name = proc.get("name") or name
            exe = proc.get("exe") or exe

        scope = ip_scope(fl.rip)
        pclass = port_class(fl.rport)
        ep_score, ep_why = endpoint_risk(fl.rip, fl.rport)

        # ---- 两条证据流分别分析
        conn_stats = analyze_intervals(fl.conn_events, merge_w)
        byte_stats = analyze_intervals(fl.byte_events, merge_w)

        total_ticks = fl.idle_ticks + fl.active_ticks
        idle_ratio = (fl.idle_ticks / total_ticks) if total_ticks else 0.0
        # 持续传输（例如视频流）在 1 秒采样下"每次都增量"，会伪装成极规律的信号。
        # 心跳的定义性特征是「长时间静默 + 离散突发」，所以必须先过这道门。
        bursty = idle_ratio >= 0.5 or total_ticks < 4

        notes: list[str] = []
        if byte_stats and not bursty:
            notes.append("数据持续传输，不具心跳形态（规律性结论不采用字节证据）")
            byte_stats = None

        reg_src, best = None, None
        for label, st in (("连接建立间隔", conn_stats), ("数据突发间隔", byte_stats)):
            if st is None:
                continue
            if best is None or st["regularity"] > best[1]["regularity"]:
                reg_src, best = label, st

        regularity = best["regularity"] if best else None
        conf = best["confidence"] if best else 0.0
        resolution_limited = bool(best and best["median"] < 4 * sample_interval)
        if resolution_limited:
            notes.append("间隔接近采样精度，结论可靠性下降")

        if best is None:
            n_ev = max(len(fl.conn_events), len(fl.byte_events))
            if fl.instances <= 1 and n_ev <= 1:
                notes.append("观测窗口内连接持续存在且无数据突发 —— 无时间结构可分析")
            elif n_ev < MIN_INTERVALS + 1:
                notes.append(f"观测窗口内仅捕获到 {n_ev} 次事件"
                             f"（至少需要 {MIN_INTERVALS + 1} 次才能判断周期）"
                             f"；可延长观测时间后重试")
            else:
                notes.append("事件间隔过于离散，无法给出规律性结论")

        # ---- 进程侧信息（联合判定用）
        pscore = float((proc or {}).get("score") or 0)
        plevel = (proc or {}).get("level") or "clean"
        # 与 rules.P005 保持同一套口径：只有**明确**不可信（unsigned / forged /
        # untrusted）才作为指控依据。"签名尚未校验(unknown)"、"无镜像文件(noimage)"、
        # "MSIX 包签名(packaged)" 一律不算 —— 否则首轮扫描或系统伪进程
        # （PID 0/4/308 这类没有可执行文件的）会把规律性告警刷满屏。
        untrusted = bool(proc) and rules.is_untrusted(proc)
        kind = rules.sig_kind(proc) if proc else "unknown"
        trusted = kind == "ok" and not any(
            a.lower() in rules.sig_cn(proc).lower() for a in iocs.ABUSED_SIGNERS)

        sig = (proc or {}).get("signature") or {}
        sig_zh = sig.get("status_zh") or ("未在进程表中找到该 PID" if not proc else "校验中")

        # ---- 生成规则命中
        findings: list[dict] = []
        ev_base = (f"PID {fl.pid}（{name}）→ {fl.rip}:{fl.rport}　"
                   f"协议 {fl.proto.upper()}　目标 {SCOPE_ZH.get(scope, scope)}")

        if fl.rip in iocs.MALICIOUS_IPS:
            findings.append(rules.finding(
                "N002", f"连接已知银狐 C2：{fl.rip}:{fl.rport}", "critical", 100, "network",
                f"{ev_base}\n该地址在 CNCERT / 火绒公开报告中列为银狐远控服务器",
                "请立即断网，终止该进程，并检查计划任务、服务与注册表中的持久化项。"))

        if untrusted and pclass == "silverfox":
            findings.append(rules.finding(
                "N004", f"未签名程序连接银狐常用非标端口 {fl.rport}", "high", 78, "network",
                f"{ev_base}\n进程签名状态：{sig_zh}",
                "银狐 C2 常用 18300 / 7000 / 8001 等大端口直连。请核对该连接是否为业务所需。"))

        # N001 的触发门槛：规律性够高，**并且**至少有一条旁证 ——
        #   ① 进程签名明确不可信，或 ② 目标端点本身可疑。
        # 只有规律性、没有任何旁证时不出规则：软件更新检查、遥测上报、NTP 同步
        # 都极其规律，只凭"像机器打拍子"就告警，用户三天内就会对告警脱敏。
        # （规律性本身仍然完整展示在界面上，只是不进入风险维度。）
        if regularity is not None and regularity >= REG_EMIT_MIN and (untrusted or ep_score >= 45):
            if regularity >= 85:
                w, sev = 66, "high"
            elif regularity >= 70:
                w, sev = 54, "medium"
            else:
                w, sev = 38, "medium"
            # 内网目标下调权重：C2 服务器在公网，内网规律流量更可能是
            # 局域网设备轮询、内网服务心跳这类正常行为。
            # 只压 N001 这一条 —— 若进程本身已被判 critical/high，
            # N003 仍会照常按联合判定升级（横向移动不能放过）。
            internal = scope in ("private", "cgnat", "linklocal")
            if internal and fl.rip not in iocs.MALICIOUS_IPS:
                w = min(w, 40)
                sev = "medium"
            detail = (f"观测到 {best['events']} 次事件、{best['n']} 个间隔，"
                      f"平均 {fmt_duration(best['mean'])}，抖动 {best['jitter_pct']:.1f}%"
                      f"（变异系数 {best['cv']:.3f}）")
            if internal:
                detail += "\n目标位于内网 —— 权重已下调（C2 服务器通常位于公网）"
            findings.append(rules.finding(
                "N001", f"外联呈现周期性心跳（规律性 {regularity:.0f}）", sev, w, "network",
                f"{ev_base}\n证据来源：{reg_src}\n{detail}"
                + ("\n⚠ 会话开始前该连接已存在，首个事件时刻为估计值" if fl.pre_existing else ""),
                "固定周期、低抖动的外联是 C2 心跳的典型特征。"
                "但软件更新检查、遥测上报同样具有周期性 —— 请结合进程签名与目标地址判断。"))

        if regularity is not None and regularity >= 70 and plevel in ("critical", "high"):
            findings.append(rules.finding(
                "N003", "规律性外联 + 进程本身已判高风险（联合判定）", "critical", 88, "network",
                f"{ev_base}\n进程风险：{plevel}（{pscore:.0f} 分）\n"
                f"网络规律性：{regularity:.0f}（{reg_src}）",
                "进程行为检测与网络规律性检测相互独立地指向同一目标，"
                "两者共振时应视为高度疑似 C2 通道，建议立即处置。"))

        # N005 不依赖规律性：只要"进程已被判高风险"且"确实握着对外连接"就报。
        # 理由：银狐的最终目的就是建立并维持 C2 通道 —— 一个已判高风险的进程
        # 正在与公网通信，本身就是最该先看的那条连接。
        # 只对 critical/high 生效，避免把"未签名工具连了一下外网"（P005，中危）
        # 也刷进网络页，那会让这一页失去焦点。
        if plevel in ("critical", "high") and scope == "public":
            findings.append(rules.finding(
                "N005", "高风险进程持有对外连接", "high", 76, "network",
                f"{ev_base}\n进程风险：{plevel}（{pscore:.0f} 分）\n"
                f"进程签名状态：{sig_zh}\n该连接当前存活 {len(conns)} 条",
                "该进程已被进程行为规则判为高风险，同时保持着公网连接。"
                "请优先核查这条连接的去向与该进程的来源。"))

        score, level = rules.score_findings(findings)

        # 规律性高但没有任何旁证时，说明清楚"为什么它不算风险"，
        # 免得用户看到 93 分的规律性配 0 分风险而困惑。
        if not findings and regularity is not None and regularity >= REG_EMIT_MIN:
            if trusted and ep_score < 45:
                notes.append("进程签名有效、目标端点无可疑特征 —— "
                             "按已知遥测/更新类心跳处理，仅作规律性观察，不计入风险")
            else:
                notes.append("进程签名未判为不可信、目标端点亦无可疑特征 —— "
                             "仅作规律性观察，不计入风险")

        # 判决语
        if level == "critical":
            verdict = "高度疑似 C2 通道，建议立即处置"
        elif level == "high":
            verdict = "疑似 C2 心跳，建议优先核查"
        elif level == "medium":
            verdict = "存在规律性外联，建议核实"
        elif level == "low":
            verdict = "低度可疑，可继续观察"
        elif regularity is not None and regularity >= 70:
            verdict = "规律性高但上下文无可疑特征"
        else:
            verdict = "未见异常"

        return {
            "key": fl.key,
            "pid": fl.pid,
            "name": name,
            "exe": exe,
            "proto": fl.proto,
            "rip": fl.rip,
            "rport": fl.rport,
            "ip_scope": scope,
            "ip_scope_zh": SCOPE_ZH.get(scope, scope),
            "port_class": pclass,
            "ioc_ip": fl.rip in iocs.MALICIOUS_IPS,
            "live_conns": len(conns),
            "instances": fl.instances,
            "resets": fl.resets,
            "bytes_out": fl.bytes_out,
            "bytes_in": fl.bytes_in,
            "idle_ratio": round(idle_ratio, 3),
            "regularity": regularity,
            "regularity_source": reg_src,
            "regularity_confidence": conf,
            "resolution_limited": resolution_limited,
            "conn_events": len(fl.conn_events),
            "byte_events": len(fl.byte_events),
            "conn_stats": _slim(conn_stats),
            "byte_stats": _slim(byte_stats),
            "avg_interval": round(best["mean"], 2) if best else None,
            "jitter_pct": round(best["jitter_pct"], 1) if best else None,
            "proc_score": pscore,
            "proc_level": plevel,
            "proc_untrusted": untrusted,
            "proc_trusted": trusted,
            "signature_zh": sig_zh,
            "endpoint_score": ep_score,
            "endpoint_why": ep_why,
            "udp_ports": sorted(set(udp_by_pid.get(fl.pid, [])))[:12],
            "first_seen_rel": round(fl.first_seen - (self.session["started_mono"]
                                                     if self.session else fl.first_seen), 2),
            "last_seen_rel": round(fl.last_seen - (self.session["started_mono"]
                                                   if self.session else fl.last_seen), 2),
            "findings": findings,
            "score": score,
            "level": level,
            "verdict": verdict,
            "notes": notes,
        }

    # ------------------------------------------------------------ 告警
    def _emit_alerts(self, results: list[dict]):
        sink = getattr(self, "alert_sink", None)
        if not sink:
            return
        for f in results:
            if f["level"] not in ("critical", "high"):
                continue
            if f["key"] in self._alerted:
                continue
            self._alerted.add(f["key"])
            try:
                sink(f)
            except Exception:
                pass

    # ------------------------------------------------------------ 对外输出
    def _session_view(self) -> dict:
        s = self.session
        if not s:
            return {"phase": "idle", "duration": DEFAULT_DURATION,
                    "elapsed": 0.0, "remaining": 0.0, "progress": 0.0,
                    "auto": False, "flows": 0}
        elapsed = (time.monotonic() - s["started_mono"])
        if s["phase"] == "done":
            elapsed = min(elapsed, s["duration"])
        return {
            "id": s["id"],
            "phase": s["phase"],
            "duration": s["duration"],
            "elapsed": round(elapsed, 1),
            "remaining": round(max(0.0, s["duration"] - elapsed), 1),
            "progress": round(min(1.0, elapsed / s["duration"]), 4) if s["duration"] else 0.0,
            "auto": s["auto"],
            "started_at": time.strftime("%H:%M:%S", time.localtime(s["started_at"])),
            "finished_at": (time.strftime("%H:%M:%S", time.localtime(s["finished_at"]))
                            if s["finished_at"] else ""),
            "flows": len(self._results),
        }

    def snapshot(self, limit: int = 300) -> dict:
        self._recompute()
        with self.lock:
            results = list(self._results)
            session = self._session_view()
            sample_ms = self.sample_ms
            tick = self.tick
            estats_ok = self.estats_ok
            estats_note = self.estats_note
            last_error = self.last_error
            live_conns = self._live_count
            udp_count = sum(len(v) for v in self.udp_by_pid.values())

        levels = {"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0}
        for f in results:
            levels[f["level"]] = levels.get(f["level"], 0) + 1
        evaluated = [f for f in results if f["regularity"] is not None]

        return {
            "available": netapi.available(),
            "estats": estats_ok,
            "estats_note": estats_note,
            "sample_interval": self.sample_interval,
            "sample_ms": sample_ms,
            "tick": tick,
            "live_conns": live_conns,
            "udp_sockets": udp_count,
            "duration_stops": DURATION_STOPS,
            "default_duration": DEFAULT_DURATION,
            "session": session,
            "history": self.history[:HISTORY_KEEP],
            "summary": {
                "flows": len(results),
                "evaluated": len(evaluated),
                "high_reg": sum(1 for f in evaluated if f["regularity"] >= 85),
                "regular": sum(1 for f in evaluated if f["regularity"] >= 70),
                "levels": levels,
                "bytes_out": sum(f["bytes_out"] for f in results),
                "bytes_in": sum(f["bytes_in"] for f in results),
            },
            "flows": [self._slim_flow(f) for f in results[:limit]],
            "error": last_error.splitlines()[-1] if last_error else "",
        }

    @staticmethod
    def _slim_flow(f: dict) -> dict:
        """下发给前端轮询用的精简结构（每 2 秒一次，必须小）。

        ⚠️ 这里**不带完整的 findings**（那会让 2 秒一次的轮询白白变大），
        只带 `finding_ids`（规则号，很短）。报告导出时按规则号去查规则名。
        ⚠️ 正因如此，**任何消费方都不能直接访问 flow['findings']** ——
        报告就因为这个踩过坑：一旦存在"规律性观察项"或"可疑外联"，
        导出就会 KeyError('findings') 整个失败（实测）。
        """
        return {
            "key": f["key"], "pid": f["pid"], "name": f["name"], "exe": f["exe"],
            "proto": f["proto"], "rip": f["rip"], "rport": f["rport"],
            "ip_scope_zh": f["ip_scope_zh"], "port_class": f["port_class"],
            "ioc_ip": f["ioc_ip"], "live_conns": f["live_conns"],
            "bytes_out": f["bytes_out"], "bytes_in": f["bytes_in"],
            "regularity": f["regularity"], "regularity_source": f["regularity_source"],
            "regularity_confidence": f["regularity_confidence"],
            "avg_interval": f["avg_interval"], "jitter_pct": f["jitter_pct"],
            "conn_events": f["conn_events"], "byte_events": f["byte_events"],
            "proc_score": f["proc_score"], "proc_level": f["proc_level"],
            "proc_untrusted": f["proc_untrusted"],
            "signature_zh": f["signature_zh"],
            "endpoint_score": f["endpoint_score"],
            "score": f["score"], "level": f["level"], "verdict": f["verdict"],
            "resolution_limited": f["resolution_limited"],
            "finding_ids": [x.get("rule_id", "") for x in (f.get("findings") or [])],
            "note": f["notes"][0] if f["notes"] else "",
        }

    def flow_detail(self, key: str) -> dict:
        """详情视图：在汇总结果之上，补出完整的时序证据。

        时序数据只在详情里生成，不放进每 2 秒一次的 /api/state ——
        那是轮询接口，塞进几百个流的时间序列会白白吃掉带宽与解析时间。
        """
        self._recompute(force=True)
        with self.lock:
            f = next((x for x in self._results if x["key"] == key), None)
            if f is None:
                return {"error": "该网络流量已不在当前会话中（会话可能已重启）"}
            fl = self.flows.get(key)
            merge_w = max(1.0, MERGE_FACTOR * self.sample_interval)
            udp = sorted(set(self.udp_by_pid.get(f["pid"], [])))
            session = self.session
            duration = session["duration"] if session else 0.0
            out = dict(f)
            out["udp_ports"] = udp[:16]
            if fl is None:
                out["conn_series"] = None
                out["byte_series"] = None
                out["buckets"] = None
                return out

            cs = analyze_intervals(fl.conn_events, merge_w)
            bs = analyze_intervals(fl.byte_events, merge_w)
            out["conn_series"] = _series_view(cs)
            out["byte_series"] = _series_view(bs)
            out["byte_amounts"] = fl.byte_amounts[-200:]
            out["buckets"] = _bucketize(fl.conn_events, fl.byte_events,
                                        fl.byte_amounts, duration, 60)
            out["instances"] = fl.instances
            out["resets"] = fl.resets
            out["idle_ratio"] = round(
                fl.idle_ticks / (fl.idle_ticks + fl.active_ticks), 3
            ) if (fl.idle_ticks + fl.active_ticks) else 0.0
            return out


def _slim(stats: dict | None) -> dict | None:
    if not stats:
        return None
    return {k: v for k, v in stats.items() if k not in ("times", "intervals")}


_SERIES_CAP = 200


def _series_view(stats: dict | None) -> dict | None:
    """详情视图用的时序（带上时刻与间隔序列，但截断到最近 200 项）。"""
    if not stats:
        return None
    out = {k: v for k, v in stats.items() if k not in ("times", "intervals")}
    out["times"] = stats.get("times", [])[-_SERIES_CAP:]
    out["intervals"] = stats.get("intervals", [])[-_SERIES_CAP:]
    return out


def _bucketize(conn_events: list[float], byte_events: list[float],
               byte_amounts: list[int], duration: float, n: int = 60) -> dict | None:
    """把事件按时间分桶，用于界面上的「周期性直方图」。

    心跳在直方图上表现为**等间距的尖峰**——这是给用户看的、一眼能懂的证据，
    比一串数字更有说服力。同时给出连接事件与字节事件两条。
    """
    if duration <= 0:
        return None
    width = duration / n
    if width <= 0:
        return None
    conns = [0] * n
    for t in conn_events:
        i = int(t / width)
        if 0 <= i < n:
            conns[i] += 1
    byts = [0] * n
    for t, a in zip(byte_events, byte_amounts):
        i = int(t / width)
        if 0 <= i < n:
            byts[i] += a
    return {"n": n, "width": round(width, 2), "conns": conns, "bytes": byts}
