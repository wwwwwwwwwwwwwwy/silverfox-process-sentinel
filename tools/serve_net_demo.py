# -*- coding: utf-8 -*-
"""网络监控界面质检用的演示服务器（合成数据，纯内存，不写盘、不联网）。

为什么需要它：本机没有银狐样本，真实运行下网络页只会是"未见异常"的空状态，
测不出高规律性徽章、金色高亮行、周期性直方图、临界卡片换行这类渲染问题。
这里用合成的 6 种典型流量把界面填满，逐屏质检。

用法：python serve_net_demo.py [port]
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _find_app() -> str:
    """定位 app/ 目录：优先环境变量，其次按脚本位置推导（tools/ 与 _dev/ 两种布局）。"""
    cands = [os.environ.get("YINHU_APP", "")]
    cands += [os.path.join(HERE, "..", "app"),        # 仓库 tools/ 布局
              os.path.join(HERE, "..", "..", "app"),  # 会话工作区 _dev/ 布局
              r"D:\银狐进程监视器\app"]                # 本机安装位置（最后兜底）
    for c in cands:
        if c and os.path.isfile(os.path.join(c, "server.py")):
            return os.path.abspath(c)
    raise SystemExit("找不到 app/ 目录，请设置环境变量 YINHU_APP 指向它")


APP = _find_app()
sys.path.insert(0, APP)

import netmon    # noqa: E402
import rules     # noqa: E402
import server    # noqa: E402

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8891


def _f(rid, title, sev, w, cat, ev, adv=""):
    return rules.finding(rid, title, sev, w, cat, ev, adv)


# ---------------------------------------------------------------- 合成流量
def mk(key, pid, name, exe, rip, rport, scope_zh, pclass, reg, src, avg, jitter,
       conf, co, be, bo, bi, live, pscore, plevel, untrusted, sigzh, epscore,
       findings, verdict, note="", reslim=False, proto="tcp4", resets=0,
       instances=1, idle=0.92, epwhy=None, notes=None, amounts=None):
    score, level = rules.score_findings(findings)
    return {
        "key": key, "pid": pid, "name": name, "exe": exe, "proto": proto,
        "rip": rip, "rport": rport, "ip_scope_zh": scope_zh, "port_class": pclass,
        "ioc_ip": epscore >= 100, "live_conns": live,
        "bytes_out": bo, "bytes_in": bi,
        "regularity": reg, "regularity_source": src,
        "regularity_confidence": conf, "avg_interval": avg, "jitter_pct": jitter,
        "conn_events": co, "byte_events": be,
        "proc_score": pscore, "proc_level": plevel, "proc_untrusted": untrusted,
        "proc_trusted": (plevel == "clean" and not untrusted),
        "signature_zh": sigzh, "endpoint_score": epscore,
        "score": score, "level": level, "verdict": verdict,
        "resolution_limited": reslim, "note": note,
        # 详情专用
        "findings": findings, "notes": notes or [], "instances": instances,
        "resets": resets, "idle_ratio": idle, "endpoint_why": epwhy or [],
        "udp_ports": [], "first_seen_rel": 0.0, "last_seen_rel": 300.0,
        "conn_stats": None, "byte_stats": None,
        "conn_series": None, "byte_series": None, "byte_amounts": amounts or [],
        "buckets": None,
    }


def bucketize(duration, n, spikes_at, spike_val, label_bytes=True):
    w = duration / n
    byts = [0] * n
    conns = [0] * n
    for i in spikes_at:
        if 0 <= i < n:
            byts[i] = spike_val
            conns[i] = 1
    return {"n": n, "width": round(w, 2), "conns": conns, "bytes": byts}


# A. 银狐 C2 心跳（核心场景：IOC + 高规律 + 进程高风险）
A_KEY = "6312|tcp4|8.218.106.149|443"
A_F = [
    _f("N002", "连接已知银狐 C2：8.218.106.149:443", "critical", 100, "network",
       "PID 6312（Pl6VgrWG.exe）→ 8.218.106.149:443　协议 TCP4　目标 公网\n"
       "该地址在 CNCERT / 火绒公开报告中列为银狐远控服务器",
       "请立即断网，终止该进程，并检查计划任务、服务与注册表中的持久化项。"),
    _f("N001", "外联呈现周期性心跳（规律性 99）", "high", 66, "network",
       "PID 6312（Pl6VgrWG.exe）→ 8.218.106.149:443　协议 TCP4　目标 公网\n"
       "证据来源：数据突发间隔\n观测到 6 次事件、5 个间隔，平均 1.0 分钟，"
       "抖动 1.4%（变异系数 0.014）",
       "固定周期、低抖动的外联是 C2 心跳的典型特征。"),
    _f("N003", "规律性外联 + 进程本身已判高风险（联合判定）", "critical", 88, "network",
       "PID 6312（Pl6VgrWG.exe）→ 8.218.106.149:443\n进程风险：critical（100 分）\n"
       "网络规律性：99（数据突发间隔）",
       "进程行为检测与网络规律性检测相互独立地指向同一目标，"
       "两者共振时应视为高度疑似 C2 通道，建议立即处置。"),
]
A = mk(A_KEY, 6312, "Pl6VgrWG.exe", r"C:\Users\Public\sgSJd8\Pl6VgrWG.exe",
       "8.218.106.149", 443, "公网", "common", 98.6, "数据突发间隔", 60.02, 1.4,
       1.0, 0, 6, 1440, 2860, 1, 100.0, "critical", True, "签名伪造（摘要校验失败）",
       100.0, A_F, "高度疑似 C2 通道，建议立即处置", resets=1, instances=1,
       epwhy=["8.218.106.149 命中公开披露的银狐 C2 地址清单"],
       notes=["进程签名校验结果为『签名伪造（摘要校验失败）』—— 文件摘要与内嵌签名不符"],
       amounts=[148, 152, 148, 150, 149, 148])
A["buckets"] = bucketize(300, 60, [0, 12, 24, 36, 48, 59], 148)
A["byte_series"] = {
    "n": 5, "events": 6, "mean": 60.02, "median": 60.0, "sd": 0.84, "cv": 0.014,
    "mad_ratio": 0.0042, "min": 59.87, "max": 60.11, "regularity": 98.6,
    "jitter_pct": 1.4, "confidence": 0.833,
    "times": [0.0, 60.02, 119.89, 180.0, 239.95, 300.06],
    "intervals": [60.02, 59.87, 60.11, 59.95, 60.11],
}
A["conn_series"] = None

# B. 高规律但良性（证明"规律性 ≠ 恶意"）
B_KEY = "1044|tcp4|4.145.79.82|443"
B = mk(B_KEY, 1044, "svchost.exe", r"C:\Windows\System32\svchost.exe",
       "4.145.79.82", 443, "公网", "common", 93.2, "连接建立间隔", 75.04, 6.8,
       1.0, 4, 0, 0, 0, 1, 0.0, "clean", False, "签名有效 · Microsoft Windows",
       6.0, [], "规律性高但上下文无可疑特征",
       note="进程签名有效且目标无可疑特征 —— 按已知遥测型心跳处理，不计入风险")
B["conn_series"] = {
    "n": 3, "events": 4, "mean": 75.04, "median": 75.0, "sd": 5.1, "cv": 0.068,
    "mad_ratio": 0.031, "min": 75.0, "max": 75.1, "regularity": 93.2,
    "jitter_pct": 6.8, "confidence": 0.5,
    "times": [0.0, 75.0, 150.1, 225.1], "intervals": [75.0, 75.1, 75.0],
}
B["buckets"] = bucketize(300, 60, [0, 15, 30, 45], 1)

# C. 未签名 + 银狐非标端口 + 高规律
C_KEY = "8842|tcp4|47.243.152.51|18300"
C_F = [
    _f("N004", "未签名程序连接银狐常用非标端口 18300", "high", 78, "network",
       "PID 8842（updatehelper.exe）→ 47.243.152.51:18300　协议 TCP4　目标 公网\n"
       "进程签名状态：未签名",
       "银狐 C2 常用 18300 / 7000 / 8001 等大端口直连。请核对该连接是否为业务所需。"),
    _f("N001", "外联呈现周期性心跳（规律性 88）", "high", 66, "network",
       "PID 8842（updatehelper.exe）→ 47.243.152.51:18300\n证据来源：连接建立间隔\n"
       "观测到 7 次事件、6 个间隔，平均 45.0 秒，抖动 11.6%（变异系数 0.116）",
       "固定周期、低抖动的外联是 C2 心跳的典型特征。"),
]
C = mk(C_KEY, 8842, "updatehelper.exe", r"C:\ProgramData\cgL18U72\updatehelper.exe",
       "47.243.152.51", 18300, "公网", "silverfox", 88.4, "连接建立间隔", 45.0, 11.6,
       1.0, 7, 0, 5200, 1800, 1, 62.0, "high", True, "未签名",
       61.0, C_F, "高度疑似 C2 通道，建议立即处置",
       epwhy=["端口 18300 属银狐公开报告点名的 C2 端口段", "47.243.152.51 命中公开披露的银狐 C2 地址清单"])
C["conn_series"] = {
    "n": 6, "events": 7, "mean": 45.0, "median": 45.0, "sd": 5.2, "cv": 0.116,
    "mad_ratio": 0.052, "min": 38.1, "max": 51.2, "regularity": 88.4,
    "jitter_pct": 11.6, "confidence": 1.0,
    "times": [0.0, 45.1, 90.0, 134.9, 180.1, 225.2, 270.0],
    "intervals": [45.1, 44.9, 44.9, 45.2, 45.1, 44.8],
}
C["buckets"] = bucketize(300, 60, [0, 9, 18, 27, 36, 45, 54], 1)

# D. 长连接、无时序证据
D_KEY = "5176|tcp4|180.111.196.240|443"
D = mk(D_KEY, 5176, "Weixin.exe", r"C:\Program Files\Tencent\Weixin\Weixin.exe",
       "180.111.196.240", 443, "公网", "common", None, None, None, None, 0.0,
       1, 0, 8200, 14000, 3, 0.0, "clean", False, "签名有效 · Tencent Technology(Shenzhen)",
       6.0, [], "未见异常",
       note="观测窗口内连接持续存在且无数据突发 —— 无时间结构可分析", idle=1.0,
       notes=["观测窗口内连接持续存在且无数据突发 —— 无时间结构可分析"])

# E. 不规则外联（非标端口，但无规律）
E_KEY = "12044|tcp4|42.186.187.203|443"
E = mk(E_KEY, 12044, "GameViewerServer.exe", r"C:\Program Files\GameViewer\GameViewerServer.exe",
       "42.186.187.203", 443, "公网", "common", 12.3, "数据突发间隔", 10.57, 39.1,
       1.0, 0, 8, 4200, 2600, 1, 0.0, "clean", False, "签名有效 · NetEase",
       6.0, [], "未见异常", idle=0.86)
E["byte_series"] = {
    "n": 7, "events": 8, "mean": 10.57, "median": 11.0, "sd": 4.1, "cv": 0.391,
    "mad_ratio": 0.27, "min": 4.0, "max": 16.0, "regularity": 12.3,
    "jitter_pct": 39.1, "confidence": 1.0,
    "times": [0.0, 14.0, 30.0, 34.0, 45.0, 54.0, 60.0, 74.0],
    "intervals": [14.0, 16.0, 4.0, 11.0, 9.0, 6.0, 14.0],
}
E["buckets"] = bucketize(300, 60, [2, 10, 21, 34, 41, 55], 70)

# F. 内网规律外联（被内网上限压到中危）
F_KEY = "4|tcp4|10.0.0.5|445"
F = mk(F_KEY, 4, "System", "", "10.0.0.5", 445, "内网", "abused", 71.4, "连接建立间隔",
       30.0, 14.2, 0.667, 4, 0, 0, 0, 1, 0.0, "clean", False, "无镜像文件",
       10.0, [], "未见异常", idle=1.0,
       epwhy=["端口 445 常被远控/横向移动滥用", "目标位于内网"])
F["conn_series"] = {
    "n": 3, "events": 4, "mean": 30.0, "median": 30.0, "sd": 4.3, "cv": 0.142,
    "mad_ratio": 0.06, "min": 26.0, "max": 34.0, "regularity": 71.4,
    "jitter_pct": 14.2, "confidence": 0.5,
    "times": [0.0, 30.0, 60.0, 90.0], "intervals": [30.0, 30.0, 30.0],
}
F["buckets"] = bucketize(300, 60, [0, 6, 12, 18], 1)

# G. 中等规律（62.5）—— 只出现在「重点关注」，不出现在「仅高规律」
G_KEY = "7236|tcp4|106.11.84.10|443"
G = mk(G_KEY, 7236, "DingTalk.exe", r"C:\Program Files\DingDing\DingTalk.exe",
       "106.11.84.10", 443, "公网", "common", 62.5, "连接建立间隔", 120.0, 21.4,
       0.667, 5, 0, 4200, 3100, 1, 0.0, "clean", False, "签名有效 · Alibaba",
       6.0, [], "未见异常",
       note="进程签名有效且目标无可疑特征 —— 按已知遥测型心跳处理，不计入风险",
       notes=["进程签名有效且目标无可疑特征 —— 按已知遥测型心跳处理，不计入风险"])
G["conn_series"] = {
    "n": 4, "events": 5, "mean": 120.0, "median": 120.0, "sd": 25.7, "cv": 0.214,
    "mad_ratio": 0.12, "min": 92.0, "max": 148.0, "regularity": 62.5,
    "jitter_pct": 21.4, "confidence": 0.667,
    "times": [0.0, 92.0, 240.0, 348.0, 480.0], "intervals": [92.0, 148.0, 108.0, 132.0],
}
G["buckets"] = bucketize(300, 60, [0, 18, 48, 59], 1)

# H. 进程已判高风险 + 持有公网连接，但连接毫无规律 → N005（联合判定，不依赖规律性）
H_KEY = "9108|tcp4|45.32.100.77|45678"
H_F = [
    _f("N005", "高风险进程持有对外连接", "high", 76, "network",
       "PID 9108（svc_helper.exe）→ 45.32.100.77:45678　协议 TCP4　目标 公网\n"
       "进程风险：high（58 分）\n进程签名状态：未签名\n该连接当前存活 1 条",
       "该进程已被进程行为规则判为高风险，同时保持着公网连接。"
       "请优先核查这条连接的去向与该进程的来源。"),
]
H = mk(H_KEY, 9108, "svc_helper.exe", r"C:\Users\Public\svc_helper.exe",
       "45.32.100.77", 45678, "公网", "nonstandard", None, None, None, None, 0.0,
       3, 0, 900, 300, 1, 58.0, "high", True, "未签名",
       22.0, H_F, "疑似 C2 心跳，建议优先核查",
       note="仅观测到 3 次连接建立，样本不足以判断规律性；可延长观测时间",
       notes=["仅观测到 3 次连接建立，样本不足以判断规律性；可延长观测时间"],
       epwhy=["端口 45678 非标准服务端口"])

FLOWS = [A, B, C, D, E, F, G, H]
DETAILS = {f["key"]: f for f in FLOWS}


class FakeNet:
    """只提供 server.state() / flow_detail 需要的那几个方法。"""
    alert_sink = None

    def start(self): pass
    def stop(self): pass
    def update_proc_index(self, idx): pass
    def start_session(self, duration, auto=False): return {"ok": True, "duration": duration}
    def stop_session(self): return {"ok": True, "msg": "检测已停止并结算"}
    def set_duration(self, duration): return {"ok": True, "duration": duration}

    def snapshot(self, limit=300):
        lv = {"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0}
        for f in FLOWS:
            lv[f["level"]] = lv.get(f["level"], 0) + 1
        ev = [f for f in FLOWS if f["regularity"] is not None]
        return {
            "available": True, "estats": True, "estats_note": "",
            "sample_interval": 1.0, "sample_ms": 2, "tick": 300,
            "live_conns": 27, "udp_sockets": 54,
            "duration_stops": [30, 60, 120, 180, 300, 600, 900],
            "default_duration": 120,
            "session": {"id": 1, "phase": "collecting", "duration": 300, "elapsed": 187.4,
                        "remaining": 112.6, "progress": 0.6247, "auto": True,
                        "started_at": "18:30:00", "finished_at": "", "flows": len(FLOWS)},
            "history": [{"id": 1, "started_at": "18:22:10", "duration": 120, "flows": 19,
                         "regular": 1, "critical": 0, "high": 0, "top": []}],
            "summary": {"flows": len(FLOWS), "evaluated": len(ev),
                        "high_reg": sum(1 for f in ev if f["regularity"] >= 85),
                        "regular": sum(1 for f in ev if f["regularity"] >= 70),
                        "levels": lv,
                        "bytes_out": sum(f["bytes_out"] for f in FLOWS),
                        "bytes_in": sum(f["bytes_in"] for f in FLOWS)},
            "flows": FLOWS, "error": "",
        }

    def flow_detail(self, key):
        d = DETAILS.get(key)
        if d is None:
            return {"error": "该网络流量已不在当前会话中（会话可能已重启）"}
        return dict(d)


srv, mon = server.serve("127.0.0.1", PORT, net_enabled=False)
mon.netmon = FakeNet()

# 让进程页也有一点内容（否则整页空荡荡，看不出层次）
print(f"[演示] 合成网络数据界面：http://127.0.0.1:{PORT}/")
try:
    srv.serve_forever()
except KeyboardInterrupt:
    pass
