# -*- coding: utf-8 -*-
"""
采集层：进程 / 网络 / 服务 / 计划任务 / 驱动 / hosts / 注册表 / 启动项

设计原则：
· 快照分两级 —— 进程级快照高频刷新（秒级），系统制品（任务/服务/驱动）低频刷新
· 所有可能抛 AccessDenied 的字段单独降级，绝不让单点失败拖垮整轮采集
· 文件魔数校验结果按 (路径, mtime, size) 缓存，避免重复读盘
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any

import psutil

import winapi

# ---------------------------------------------------------------- 缓存

_magic_cache: dict[tuple, str | None] = {}
_hash_cache: dict[tuple, str] = {}
_cmdline_cache: dict[tuple[int, int], list[str]] = {}

# 已知会以受保护进程（PPL / 安全隔离）身份运行、调用 cmdline() 会**阻塞约 1025 ms**
# 才抛 AccessDenied 的映像名。本机逐名实测确认只有这 3 个：
#     LsaIso.exe（凭据保护隔离）、NgcIso.exe（Windows Hello 隔离）、
#     WUDFCompanionHost.exe（UMDF 伴随宿主）
# Defender 的 MsMpEng / NisSrv / MpDefenderCoreService / SecurityHealthService
# 实测均可正常读取，不在表内。
# 其余字段（exe / username / memory_info / num_threads / status）对这些进程都是毫秒级，
# 只有 cmdline 会阻塞 —— 所以只跳过 cmdline，其它规则照常生效。
PROTECTED_IMAGE_NAMES = {"lsaiso.exe", "ngciso.exe", "wudfcompanionhost.exe"}
# 运行时学习：任何一次读取超时或失败的映像名都会被补进来（覆盖未知的受保护进程）
#
# ⚠️ 必须带 TTL（红队 F-007）：原先这是个只增不减的 set，一次慢读就把映像名
# **永久**拉黑 —— 此后 rundll32 / regsvr32 / mshta 这类宿主只要在 System32 下
# 就直接跳过命令行，本会话内永久失明，且没有任何计数暴露。
# 改成 name -> 解除时间(monotonic)，到期后重新尝试。
_DENY_TTL = 600.0
_denied_names: dict[str, float] = {n: float("inf") for n in PROTECTED_IMAGE_NAMES}
_denied_this_round = 0

_CACHE_LIMIT = 20000


def _in_system_dir(path: str) -> bool:
    """判断可执行文件是否位于 Windows 系统目录。
    用途：只有"名字在受保护名单里 **且** 确实住在 System32/SysWOW64"才跳过 cmdline。
    这样即使木马把自己的映像名伪装成 LsaIso.exe 放到用户目录，也不会被漏掉命令行检测。

    加固（2026-10-04）：初版用子串匹配 `\\windows\\system32\\`，
    攻击者在用户目录自建 `windows\\system32` 子目录即可骗过本函数、
    让受保护名单跳过自己的命令行。改为锚定真实 %WINDIR% 前缀。"""
    p = (path or "").replace("/", "\\").lower()
    windir = os.path.expandvars(r"%WINDIR%").replace("/", "\\").lower()
    for d in (windir + "\\system32", windir + "\\syswow64"):
        if p == d or p.startswith(d + "\\"):
            return True
    return False


def _cache_put(d: dict, k, v):
    if len(d) > _CACHE_LIMIT:
        d.clear()          # 简单粗暴但足够：缓存重建成本低，好过无限增长
    d[k] = v


# ⚠️ 性能关键：psutil 在 Windows 上各字段的采集成本相差三个数量级。
# 实测 305 个进程（本机）：
#     pid/name/exe/create_time  ≈ 1.5 ms
#     ppid 16 ms | username 20 ms | memory_info 8 ms
#     num_threads 1341 ms | status 1224 ms | cmdline 5132 ms
# 初版一次性取全部字段 → 单轮采集 9–10 秒，界面实际刷新周期被拖到 9 秒以上。
# 现在的策略：
#   1. 快字段每轮都取（约 50 ms）
#   2. cmdline 按 (pid, create_time) 缓存，每个进程一生只取一次；
#      每轮只允许花掉一个时间预算，避免新进程爆发时卡住主循环
#   3. num_threads / status 挪到详情视图按需获取（status 原本根本没被用到）
FAST_ATTRS = ["pid", "ppid", "name", "exe", "username", "create_time", "memory_info"]

CMD_BUDGET_COLD = 3.0     # 冷启动：一次把存量进程的命令行尽量取完
CMD_BUDGET_WARM = 0.25    # 稳态：每轮最多花 250 ms 补命令行
SLOW_CALL_MS = 200        # 单次 cmdline() 超过该阈值即拉黑，不再重试


def _conn_of(proc: psutil.Process) -> list[dict]:
    """兼容 psutil 6/7 的连接枚举接口。"""
    raw = None
    for fn in ("net_connections", "connections"):
        f = getattr(proc, fn, None)
        if f is None:
            continue
        try:
            raw = f(kind="inet")
            break
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return []
        except Exception:
            continue
    if not raw:
        return []
    out = []
    for c in raw:
        try:
            if c.raddr:
                out.append({
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}",
                    "rip": c.raddr.ip,
                    "rport": c.raddr.port,
                    "status": c.status,
                    "family": "IPv6" if c.family.name == "AF_INET6" else "IPv4",
                })
            elif c.status == "LISTEN":
                out.append({
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "raddr": "", "rip": "", "rport": c.laddr.port if c.laddr else 0,
                    "status": "LISTEN",
                    "family": "IPv6" if c.family.name == "AF_INET6" else "IPv4",
                })
        except Exception:
            continue
    return out


def file_magic(path: str) -> str | None:
    """读取文件前 4 字节，返回类型标记：'PE' / 'MZ' / 'ZIP' / 'PDF' / None"""
    try:
        st = os.stat(path)
        key = (path.lower(), int(st.st_mtime), st.st_size)
    except Exception:
        return None
    if key in _magic_cache:
        return _magic_cache[key]
    magic = None
    try:
        with open(path, "rb") as f:
            head = f.read(4)
        if len(head) >= 2 and head[:2] == b"MZ":
            magic = "PE"
        elif head[:2] == b"PK":
            magic = "ZIP"
        elif head[:4] == b"%PDF":
            magic = "PDF"
        elif head[:2] == b"BM":
            magic = "BMP"
    except Exception:
        magic = None
    _cache_put(_magic_cache, key, magic)
    return magic


def file_hash(path: str, algo: str = "sha256", limit_mb: int = 64) -> str:
    try:
        st = os.stat(path)
        if st.st_size > limit_mb * 1024 * 1024:
            return ""
        key = (path.lower(), int(st.st_mtime), st.st_size, algo)
        if key in _hash_cache:
            return _hash_cache[key]
        h = hashlib.new(algo)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 256), b""):
                h.update(chunk)
        d = h.hexdigest()
        _cache_put(_hash_cache, key, d)
        return d
    except Exception:
        return ""


# ---------------------------------------------------------------- 进程

def collect_processes(sig_cache: dict[str, dict] | None = None) -> list[dict]:
    """采集进程快照。sig_cache 为 winapi.verify_signatures 的结果（可为空）。

    返回的每个进程都带 cmdline_loaded 标记：False 表示本轮的命令行还没轮到采集
    （受时间预算限制），下一轮会补上。规则引擎对未采集的进程不会误判 —— 空命令行
    只是让命令行类规则暂时不触发，不会产生误报。
    """
    sig_cache = sig_cache or {}
    procs: list[dict] = []
    net_map = collect_net_map()

    cold = not _cmdline_cache
    budget = CMD_BUDGET_COLD if cold else CMD_BUDGET_WARM
    t_cmd = time.perf_counter()
    live_keys: set[tuple[int, int]] = set()

    for p in psutil.process_iter(attrs=FAST_ATTRS, ad_value=None):
        try:
            info = p.info
        except Exception:
            continue
        pid = info.get("pid")
        if pid is None:
            continue
        exe = info.get("exe") or ""
        name = info.get("name") or (os.path.basename(exe) if exe else "")
        ct = info.get("create_time") or 0
        key = (pid, int(ct))
        live_keys.add(key)

        cmd = _cmdline_cache.get(key)
        loaded = cmd is not None
        denied = False
        if cmd is None:
            lname = name.lower()
            if not exe or not os.path.isabs(exe):
                # 系统伪进程：System / Registry / Memory Compression 等。
                # psutil 对它们返回的"路径"是 Registry 这种非绝对路径，或干脆为空。
                # 读它们的 cmdline 同样要等 1 秒才失败，而它们既不可能是木马本体、
                # 也没有路径可供其它规则使用 —— 直接跳过。
                cmd = []
                denied = True
            elif lname in _denied_names and \
                    time.monotonic() < _denied_names[lname] and _in_system_dir(exe):
                # 已知的受保护系统进程：直接跳过，不浪费那 1 秒
                cmd = []
                denied = True
            elif time.perf_counter() - t_cmd < budget:
                t_one = time.perf_counter()
                ok_read = True
                try:
                    cmd = list(p.cmdline() or [])
                except Exception:
                    cmd = []
                    ok_read = False
                one_ms = (time.perf_counter() - t_one) * 1000
                if ok_read and one_ms <= SLOW_CALL_MS:
                    _cache_put(_cmdline_cache, key, cmd)
                    loaded = True
                else:
                    # 读不到、或单次耗时离谱 —— 记入名单（带 TTL），之后同名进程跳过
                    _denied_names[lname] = time.monotonic() + _DENY_TTL
                    denied = True
            else:
                cmd = []

        mi = info.get("memory_info")
        try:
            cpu = p.cpu_percent(interval=None)
        except Exception:
            cpu = 0.0

        # 没有可执行文件的进程（PID 0 Idle / 4 System / 308 Secure System 等
        # 内核伪进程与 VBS 隔离组件）**根本没有镜像文件**，签名无从校验。
        # 这里必须给一个明确记录：若返回 None，前端会把"无记录"当成"校验中"，
        # 这几行就会永远显示"数字签名校验中"（实测踩过）。
        # noimage 不在 UNTRUSTED_KINDS 里，所有签名门控规则照旧跳过，不影响检测。
        if exe:
            sig = sig_cache.get(exe.lower())
        else:
            sig = {"status": "NoImage", "status_zh": "无镜像文件", "kind": "noimage",
                   "signer": "", "cn": "", "notafter": ""}

        procs.append({
            "pid": pid,
            "ppid": info.get("ppid") or 0,
            "name": name,
            "exe": exe,
            "dir": os.path.dirname(exe) if exe else "",
            "ext": os.path.splitext(exe)[1].lower() if exe else "",
            "cmdline": cmd,
            "cmdline_str": " ".join(cmd),
            "cmdline_loaded": loaded,
            "cmdline_denied": denied,
            "username": info.get("username") or "",
            "parent_name": "",          # 下面统一回填
            "create_time": ct,
            "rss_mb": round((mi.rss / 1048576) if mi else 0, 1),
            "threads": 0,               # 按需获取，见 enrich_process
            "status": "",
            "cpu": round(cpu, 1),
            "signature": sig,
            "connections": net_map.get(pid, []),
        })

    # 父进程名从本轮已采到的 pid→name 映射里回填。
    # 初版对每个进程调一次 psutil.Process(ppid).name()，即 300+ 次多余 syscall；
    # 这里零额外系统调用。
    name_by_pid = {p["pid"]: p["name"] for p in procs}
    for p in procs:
        p["parent_name"] = name_by_pid.get(p["ppid"], "")

    # 回收已退出进程的命令行缓存
    if len(_cmdline_cache) > len(live_keys) * 2 + 64:
        for k in list(_cmdline_cache):
            if k not in live_keys:
                del _cmdline_cache[k]

    return procs


def collect_net_map() -> dict[int, list[dict]]:
    """全局连接表 → {pid: [连接]}"""
    out: dict[int, list[dict]] = {}
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return out
    for c in conns:
        try:
            if not c.pid:
                continue
            if c.raddr:
                out.setdefault(c.pid, []).append({
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}",
                    "rip": c.raddr.ip,
                    "rport": c.raddr.port,
                    "status": c.status,
                })
            elif c.status == "LISTEN":
                # 加固：初版丢弃 LISTEN 套接字（无 raddr），导致
                # P025「非常规程序监听端口」永远拿不到监听连接 —— 实测为死规则。
                out.setdefault(c.pid, []).append({
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "raddr": "", "rip": "", "rport": c.laddr.port if c.laddr else 0,
                    "status": "LISTEN",
                })
        except Exception:
            continue
    return out


def enrich_process(pid: int) -> dict:
    """详情视图的深度信息：加载模块、打开文件、线程数、状态。
    num_threads / status 采集成本高（各 ~1.2–1.3 s/300 进程），因此不放进每轮快照，
    只在用户点开某个进程时按需取。"""
    out: dict[str, Any] = {"modules": [], "open_files": [], "threads": 0,
                           "status": "", "error": ""}
    try:
        p = psutil.Process(pid)
    except Exception as e:
        out["error"] = str(e)
        return out
    try:
        out["threads"] = p.num_threads()
    except Exception:
        pass
    try:
        out["status"] = p.status()
    except Exception:
        pass
    try:
        maps = p.memory_maps(grouped=False)
        seen = set()
        for m in maps:
            path = getattr(m, "path", "") or ""
            if not path.lower().endswith((".dll", ".sys", ".exe")):
                continue
            key = path.lower()
            if key in seen:
                continue
            seen.add(key)
            out["modules"].append({"path": path})
    except Exception as e:
        out["error"] = f"模块枚举受限：{e}"
    try:
        for f in p.open_files():
            out["open_files"].append(f.path)
    except Exception:
        pass
    return out


# ---------------------------------------------------------------- 服务

def collect_services() -> list[dict]:
    out = []
    try:
        for s in psutil.win_service_iter():
            try:
                d = s.as_dict()
            except Exception:
                continue
            out.append({
                "name": d.get("name", ""),
                "display": d.get("display_name", ""),
                "binpath": d.get("binpath", "") or "",
                "status": d.get("status", ""),
                "start_type": d.get("start_type", ""),
                "username": d.get("username", "") or "",
            })
    except Exception:
        pass
    return out


# ---------------------------------------------------------------- 系统制品聚合

def collect_artifacts() -> dict:
    """低频采集：计划任务 / 驱动 / hosts / 注册表 / 启动项。
    服务由 psutil 提供，速度较快，一并纳入。"""
    t0 = time.time()
    # 性能：五类制品合并为一次外部进程调用（见 winapi.collect_system_snapshot 的说明）
    snap = winapi.collect_system_snapshot()
    art = {
        "tasks": snap["tasks"],
        "drivers": snap["drivers"],
        "hosts": winapi.read_hosts(),
        "hosts_path": winapi.hosts_path(),
        "run_keys": snap["run_keys"],
        "startup": winapi.get_startup_files(),
        "defender": snap["defender"],
        "suspicious_reg": snap["suspicious_reg"],
        "services": collect_services(),
        "elapsed": 0.0,
        "admin": winapi.is_admin(),
    }
    art["elapsed"] = round(time.time() - t0, 2)
    return art


def collect_all_exe_paths(procs: list[dict]) -> list[str]:
    seen = []
    for p in procs:
        e = p.get("exe") or ""
        if e and os.path.isfile(e):
            seen.append(e)
    return list(dict.fromkeys(seen))
