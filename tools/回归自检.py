# -*- coding: utf-8 -*-
"""
规则回归自检 —— 防止「修一个漏洞、引入一个误报」这类回归

背景：本版本为了修 A1（伪造 windows\\system32 子目录绕过 P001），
把目录匹配从「子串包含」改成了「前缀锚定」。改动本身是对的，
但 **漏改了 explorer.exe 的例外值** —— 例外表里写的是相对片段 `\\Windows`，
在锚定匹配下永远匹配不上绝对路径 `C:\\Windows\\explorer.exe`，
导致 explorer.exe 被判「伪装系统进程」（严重 95 分）的误报。

原有的测试只覆盖了 `explorer.exe + P002B`，没有覆盖 `explorer.exe + P001`，
所以这个回归溜了过去。本脚本把这条补上，并把几个关键判据一起固化。

用法：
    python 回归自检.py
    退出码 0 = 全部通过；1 = 有失败项
"""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common  # noqa: E402

_common.ensure_import_path()

import iocs    # noqa: E402
import rules   # noqa: E402

CTX = {"by_pid": {}, "sig_cache": {}, "artifacts": {}, "self_pid": 0}
PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'✅' if cond else '❌'} {name}" + (f"   {extra}" if extra else ""))


def mk(name, exe, parent="userinit.exe", sig_kind="ok", cmd="", conns=None):
    return {
        "pid": 4242, "ppid": 1000, "name": name, "exe": exe,
        "dir": os.path.dirname(exe), "ext": os.path.splitext(exe)[1].lower(),
        "cmdline": cmd.split(), "cmdline_str": cmd, "cmdline_loaded": True,
        "username": "u", "parent_name": parent, "create_time": 0,
        "rss_mb": 1, "threads": 1, "status": "", "cpu": 0,
        "signature": {"kind": sig_kind, "cn": "Microsoft Windows"} if sig_kind else None,
        "connections": conns or [],
    }


def ids_of(proc):
    return [f["rule_id"] for f in rules.rules_process(proc, CTX)]


print("=" * 72)
print("P001 伪装系统进程 —— 必须区分「真系统目录」与「伪造子目录」")
print("=" * 72)

# 1. 真实系统进程：绝不能误报
real = [
    ("explorer.exe 位于 C:\\Windows", "explorer.exe", r"C:\Windows\explorer.exe"),
    ("svchost.exe 位于 System32", "svchost.exe", r"C:\Windows\System32\svchost.exe"),
    ("lsass.exe 位于 System32", "lsass.exe", r"C:\Windows\System32\lsass.exe"),
    ("dwm.exe 位于 System32", "dwm.exe", r"C:\Windows\System32\dwm.exe"),
    ("csrss.exe 位于 System32", "csrss.exe", r"C:\Windows\System32\csrss.exe"),
]
for label, name, exe in real:
    ids = ids_of(mk(name, exe))
    check(f"{label} → 不误报", "P001" not in ids, f"命中 {ids or '无'}")

# 2. 伪造/伪装：必须命中
fake = [
    ("伪造 System32 子目录", "svchost.exe", r"C:\Users\Public\windows\system32\svchost.exe"),
    ("用户目录里的假 explorer", "explorer.exe", r"C:\Users\Public\SXRh6d\explorer.exe"),
    ("ProgramData 里的假 lsass", "lsass.exe", r"C:\ProgramData\cgL18U72\lsass.exe"),
    ("Windows\\Temp 里的假 dwm", "dwm.exe", r"C:\Windows\Temp\dwm.exe"),
]
for label, name, exe in fake:
    ids = ids_of(mk(name, exe))
    check(f"{label} → 命中 P001", "P001" in ids, f"命中 {ids or '无'}")

# 3. 例外表本身的数据健康度：不能是相对片段
print()
print("=" * 72)
print("例外表数据健康度（本次回归的直接原因）")
print("=" * 72)
for pname, roots in getattr(iocs, "SYSTEM_PROCESS_EXTRA_DIRS", {}).items():
    for r in roots:
        expanded = rules.norm(os.path.expandvars(r))
        is_abs = len(expanded) > 1 and expanded[1] == ":"
        check(f"{pname} 的例外项 {r!r} 是绝对路径（锚定匹配可用）", is_abs,
              f"展开为 {expanded!r}")

# 4. 其它关键判据
print()
print("=" * 72)
print("MSIX / Store 应用不得被当成「未签名」")
print("=" * 72)

# \WindowsApps\ 下的 MSIX 应用由包签名整体保护，不单独做 Authenticode 签名。
# 若按"未签名"处理，所有签名门控规则都会系统性误报
# （实测：MicrosoftStartFeedProvider.exe → P005 未签名外联；pwsh.exe → X003 白加黑）
msix_exe = (r"C:\Program Files\WindowsApps\Microsoft.StartExperiencesApp_1.380.2.0_x64__8wekyb3d8bbwe"
            r"\MicrosoftStartFeedProvider\MicrosoftStartFeedProvider.exe")
msix = mk("MicrosoftStartFeedProvider.exe", msix_exe, sig_kind="packaged",
          conns=[{"laddr": "10.0.0.5:5000", "raddr": "4.150.223.110:443",
                  "rip": "4.150.223.110", "rport": 443, "status": "ESTABLISHED"}])
ids_msix = ids_of(msix)
check("MSIX 应用持有外联 → 不误报 P005", "P005" not in ids_msix, f"命中 {ids_msix or '无'}")
check("MSIX 应用不被判为随机名程序 P007", "P007" not in ids_msix, f"命中 {ids_msix or '无'}")

# 对照：同样行为但真正未签名的程序，必须命中
unsigned = mk("unknown_app.exe", r"C:\Users\Public\SXRh6d\unknown_app.exe",
              sig_kind="unsigned",
              conns=[{"laddr": "10.0.0.5:5000", "raddr": "4.150.223.110:443",
                      "rip": "4.150.223.110", "rport": 443, "status": "ESTABLISHED"}])
ids_un = ids_of(unsigned)
check("真未签名程序持有外联 → 命中 P005", "P005" in ids_un, f"命中 {ids_un or '无'}")

# 签名校验层是否真的把 \WindowsApps\ 标为 packaged
import winapi as _w  # noqa: E402
_res = _w.verify_signatures([msix_exe]) if os.path.isfile(msix_exe) else {}
if _res:
    k = list(_res.values())[0]["kind"]
    check("签名校验层把 \\WindowsApps\\ 标为 packaged", k == "packaged", f"实际 {k}")
else:
    print("  （本机未安装该 Store 应用，跳过签名层实测）")

# 5. 其它关键判据
print()
print("=" * 72)
print("其它关键判据")
print("=" * 72)

# hosts 一行多主机名
hosts_file = os.path.join(_common.app_dir(), "winapi.py")
src = open(hosts_file, encoding="utf-8").read()
seg = src[src.find("def read_hosts"):src.find("def read_hosts") + 1200]
check("hosts 支持一行写多个主机名", "parts[1:]" in seg or "for h in" in seg)

# P014 覆盖多种杀安全软件写法
import rules as _r  # noqa: E402
src_rules = open(os.path.join(_common.app_dir(), "rules.py"), encoding="utf-8").read()
check("P014 覆盖 taskkill / Stop-Process / sc stop",
      "stop-process" in src_rules.lower() and "sc\\s+(stop" in src_rules)

# R004 展开环境变量（检查整个 run_keys 处理块，而不是首个 "R004" 字面量之后）
_blk = src_rules[src_rules.find('for rk in art.get("run_keys"'):
                 src_rules.find('for rk in art.get("run_keys"') + 2000]
check("R004 判定前展开环境变量", "expandvars" in _blk)

# 路径穿越：不能再用裸 startswith
src_srv = open(os.path.join(_common.app_dir(), "server.py"), encoding="utf-8").read()
check("/static 路径穿越用 realpath 锚定", "realpath" in src_srv)

# 采集保留 LISTEN（否则 P025 是死规则）
src_col = open(os.path.join(_common.app_dir(), "collector.py"), encoding="utf-8").read()
seg_col = src_col[src_col.find("def collect_net_map"):src_col.find("def collect_net_map") + 900]
check("全局连接表保留 LISTEN（P025 才不是死规则）", "LISTEN" in seg_col)

# X003 不把"未校验"当可疑
check("X003 不把「签名未校验」当可疑依据", "sig is None or" not in src_rules)


# 6. 回环连接不得被当成"外联"
print()
print("=" * 72)
print("回环连接（127.x / ::1）不算外联")
print("=" * 72)
for ip, exp in (("127.0.0.1", True), ("127.8.8.8", True), ("::1", True),
                ("::ffff:127.0.0.1", True), ("8.218.106.109", False),
                ("192.168.1.5", False), ("", False)):
    got = rules.is_loopback_ip(ip)
    check(f"is_loopback_ip({ip!r})", got == exp, f"{got} 期望 {exp}")

_loop = [{"laddr": "127.0.0.1:5000", "raddr": "127.0.0.1:8081", "rip": "127.0.0.1",
          "rport": 8081, "status": "ESTABLISHED"}]
_ext = [{"laddr": "10.0.0.5:5000", "raddr": "8.218.106.109:443",
         "rip": "8.218.106.109", "rport": 443, "status": "ESTABLISHED"}]
_u = mk("tool.exe", r"C:\Users\Public\test\tool.exe", sig_kind="unsigned")
_u["connections"] = _loop
check("未签名程序仅有回环连接 → 不报 P005", "P005" not in ids_of(_u),
      f"命中 {ids_of(_u) or '无'}")
_u2 = mk("tool.exe", r"C:\Users\Public\test\tool.exe", sig_kind="unsigned")
_u2["connections"] = _ext
check("未签名程序有真实外网连接 → 报 P005", "P005" in ids_of(_u2))

# 7. T006：计划任务隐藏执行脚本 + 目标在用户可写位置
print()
print("=" * 72)
print("T006 计划任务动作检测（补此前完全没扫的盲区）")
print("=" * 72)


def _task(wd, args, ex="powershell"):
    return {"tasks": [{"name": "WindowsUpdateHelper", "path": "\\", "state": "Ready",
                       "hidden": False, "runlevel": "Highest", "userid": "SYSTEM",
                       "author": "", "actions": [{"exec": ex, "args": args, "wd": wd}],
                       "triggers": [{"type": "MSFT_TaskLogonTrigger", "interval": "",
                                     "duration": "", "enabled": True}]}],
            "services": [], "drivers": [], "hosts": [], "hosts_path": "",
            "run_keys": [], "startup": [], "suspicious_reg": [],
            "defender": {"accessible": True, "paths": [], "processes": [],
                         "extensions": []}}


_HID = '-Command "Start-Process -WindowStyle Hidden task.bat"'
_PS_APP = ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File '
           '"C:\\Users\\<用户名>\\AppData\\Roaming\\Adobe\\x.ps1"')
for label, wd, args, expect in (
        ("工作目录在 Users\\Public", r"C:\Users\Public\Downloads", _HID, True),
        ("脚本在 AppData", r"C:\Windows", _PS_APP, True),
        ("工作目录在 ProgramData", r"C:\ProgramData\cgL18U72", _HID, True),
        ("Intel 官方任务写法（Program Files）",
         r"C:\Program Files\Intel\SUR\QUEENCREEK\x64", _HID, False),
        ("自建 my-watchdog（Program Files）", r"C:\Program Files\MyWatchdog",
         '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File '
         '"C:\\Program Files\\MyWatchdog\\my-watchdog.ps1"', False),
        ("无隐藏标志", r"C:\Users\Public", '-Command "Start-Process task.bat"', False),
):
    hit = any(f["rule_id"] == "T008"
              for x in rules.rules_tasks(_task(wd, args)) for f in x["findings"])
    check(label, hit == expect, f"命中={hit} 期望={expect}")

# 8. 已知项：守卫哈希必须能防住替换
print()
print("=" * 72)
print("已知项（白名单）—— 守卫哈希机制")
print("=" * 72)
import tempfile  # noqa: E402
import whitelist as _wl  # noqa: E402

_td = tempfile.mkdtemp(prefix="yh-wl-")
_g = os.path.join(_td, "guard.ps1")
io.open(_g, "w", encoding="utf-8").write("Write-Host v1\n")
_f = {"rule_id": "P011", "title": "t", "severity": "medium", "weight": 50}
_sub = {"pid": 1, "name": "powershell.exe", "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "cmdline_str": f'powershell -File "{_g}"'}
_w = {"version": 1, "entries": [{"id": "t", "rule_id": "P011",
                                 "match": {"type": "cmdline_contains", "value": "guard.ps1"},
                                 "guard": {"file": _g, "sha256": _wl._sha256(_g)}}]}
_kept, _drop = _wl.filter_findings([_f], _sub, _w)
check("守卫哈希一致 → 忽略生效", not _kept and len(_drop) == 1)
io.open(_g, "w", encoding="utf-8").write("Write-Host TAMPERED\n")
_kept2, _ = _wl.filter_findings([_f], _sub, _w)
check("守卫文件被改动 → 忽略失效、告警回来", len(_kept2) == 1)
os.remove(_g)
_kept3, _ = _wl.filter_findings([_f], _sub, _w)
check("守卫文件不存在 → 忽略失效", len(_kept3) == 1)
_kept4, _ = _wl.filter_findings([{"rule_id": "P010", "title": "x", "severity": "high",
                                  "weight": 82}], _sub, _w)
check("规则号不同 → 不受影响", len(_kept4) == 1)


# 9. 没有镜像文件的进程（PID 0/4/308 这类系统伪进程与 VBS 组件）
#    必须给出明确记录，不能留 None —— 否则界面永远显示"数字签名校验中"
print()
print("=" * 72)
print("无镜像文件的进程不得显示为「校验中」")
print("=" * 72)
import collector as _col  # noqa: E402

_procs = _col.collect_processes({})
# 语义说明：signature=None 表示"有路径但还没轮到校验"（正常）；
# 空路径则必须给出 noimage 记录，绝不允许是 None。
_bad = [p for p in _procs if not p.get("exe") and not p.get("signature")]
check("空路径进程绝不留 None（否则界面永远显示「校验中」）", not _bad,
      f"{len(_bad)} 个: {[p['pid'] for p in _bad][:6]}" if _bad else "")
_withpath_none = [p for p in _procs if p.get("exe") and not p.get("signature")]
check("有路径但未校验时返回 None（待校验语义）", len(_withpath_none) > 0,
      f"{len(_withpath_none)} 个待校验（空缓存下属正常）")

_noimg = [p for p in _procs if (p.get("signature") or {}).get("kind") == "noimage"]
check("空路径进程被标为 noimage", len(_noimg) > 0, f"{len(_noimg)} 个")
check("noimage 不被视为不可信（不影响检测）",
      not rules.is_untrusted({"signature": {"kind": "noimage"}}))
for _p in _noimg:
    if not _p.get("exe"):
        continue
    check(f"PID {_p['pid']} 路径为空却标了 noimage（异常）", False)
    break
else:
    check("所有 noimage 进程的路径都为空", True,
          f"共 {len(_noimg)} 个: {[p['pid'] for p in _noimg]}")

# 空路径必须给 noimage；有路径的走正常查缓存
check("空 exe 不会退化成 None",
      all((p.get("signature") or {}).get("kind") == "noimage"
          for p in _procs if not p.get("exe")))

# 10. 网络心跳规律性（netmon / netapi）
#     —— 这一块的核心风险不是"检不出"，而是"把系统自身的遥测刷成高危"，
#        所以正向用例与反向用例必须成对出现。
print()
print("=" * 72)
print("网络心跳规律性 —— 算法、门控与误报边界")
print("=" * 72)
import random  # noqa: E402
import netmon  # noqa: E402
import netapi  # noqa: E402

_rng = random.Random(20261005)


def _series(n, interval, cv):
    out, t = [], 0.0
    for _ in range(n):
        out.append(t)
        t += max(0.2, interval * (1 + _rng.gauss(0, cv)))
    return out


# --- 10.1 规律性曲线单调且尺度合理
_prev = 101.0
for _cv, _lo, _hi in ((0.0, 98, 100), (0.05, 86, 98), (0.10, 66, 82),
                      (0.20, 30, 48), (0.40, 5, 22)):
    _st = netmon.analyze_intervals(_series(25, 60.0, _cv), 1.6)
    _reg = _st["regularity"] if _st else None
    check(f"CV={_cv} 的规律性落在 [{_lo},{_hi}]",
          _reg is not None and _lo <= _reg <= _hi, f"实际 {_reg}")
    if _reg is not None:
        check(f"CV={_cv} 规律性单调不增", _reg <= _prev, f"{_reg} <= {_prev}")
        _prev = _reg

# --- 10.2 样本不足必须返回 None（不给假精度）
for _n in (1, 2, 3):
    check(f"{_n} 次事件 → 拒绝给出规律性结论",
          netmon.analyze_intervals(_series(_n, 60.0, 0.0), 1.6) is None)

# --- 10.3 事件合并：一次心跳的「先发后收」不能算成两个事件
_raw = []
for _k in range(6):
    _raw += [_k * 60.0, _k * 60.0 + 1.0]
_st = netmon.analyze_intervals(_raw, 1.6)
check("先发后收被合并为 6 次事件", _st and _st["events"] == 6,
      f"{_st['events'] if _st else '-'}")
check("合并后周期仍为 60 秒", _st and 59 <= _st["mean"] <= 61,
      f"{_st['mean'] if _st else '-'}")

# --- 10.4 浏览器式不规则流量不得被判为高规律
_browser = [0.0]
_t = 0.0
for _ in range(40):
    _t += _rng.choice([0.2, 0.3, 0.8, 1.5, 4.0, 12.0, 35.0, 90.0])
    _browser.append(_t)
_st = netmon.analyze_intervals(_browser, 1.6)
check("浏览器式流量规律性 < 40", _st and _st["regularity"] < 40,
      f"{_st['regularity'] if _st else '-'}")

# --- 10.5 地址归属
for _ip, _exp in (("8.218.106.149", "public"), ("10.0.0.5", "private"),
                  ("100.64.3.7", "cgnat"), ("127.0.0.1", "loopback"),
                  ("::ffff:127.0.0.1", "loopback"), ("169.254.1.1", "linklocal"),
                  ("0.0.0.0", "unspecified"), ("fe80::1", "linklocal"),
                  ("", "unknown")):
    check(f"ip_scope({_ip!r}) == {_exp}", netmon.ip_scope(_ip) == _exp,
          f"实际 {netmon.ip_scope(_ip)}")

# --- 10.6 端点风险
for _ip, _pt, _lo, _hi in (("8.218.106.149", 443, 100, 100),
                           ("1.2.3.4", 18300, 55, 100),
                           ("1.2.3.4", 45678, 15, 40),
                           ("1.2.3.4", 443, 0, 15),
                           ("10.0.0.5", 443, 0, 1)):
    _s, _ = netmon.endpoint_risk(_ip, _pt)
    check(f"端点风险 {_ip}:{_pt} 落在 [{_lo},{_hi}]", _lo <= _s <= _hi, f"实际 {_s}")

# --- 10.7 端到端：把合成流量喂进真正的分析函数
_NM = netmon.NetMonitor(1.0)
_NM.start_session(300)
_T0 = _NM.session["started_mono"]


def _flow(pid, rip, rport, conn=None, byte=None, amounts=None,
          instances=1, idle=0, active=0, bo=0, bi=0):
    _fk = netmon.flow_key_of(pid, "tcp4", rip, rport)
    _f = netmon._Flow(_fk, pid, "tcp4", rip, rport, _T0)
    _f.conn_events = list(conn or [])
    _f.byte_events = list(byte or [])
    _f.byte_amounts = list(amounts or [0] * len(byte or []))
    _f.instances = instances
    _f.idle_ticks = idle
    _f.active_ticks = active
    _f.bytes_out = bo
    _f.bytes_in = bi
    return _f


def _proc(kind, score, level, cn="Test Vendor"):
    return {"pid": 1, "name": "x.exe", "exe": r"C:\x.exe", "score": score,
            "level": level, "signature": {"kind": kind, "cn": cn}}


def _analyze(fl, kind, score, level, cn="Test Vendor"):
    _NM._name_cache[fl.pid] = (f"p{fl.pid}.exe", r"C:\x.exe")
    return _NM._analyze_flow(fl, [], {}, {fl.pid: _proc(kind, score, level, cn)}, 1.6, 1.0)


def _ids(r):
    return [f["rule_id"] for f in r["findings"]]


# 场景 A：银狐 C2 心跳（IOC + 未签名 + 进程已判严重 + 完美周期）
_fa = _flow(9001, "8.218.106.149", 443,
            byte=_series(6, 60.0, 0.0), amounts=[148] * 6, idle=290, active=6,
            bo=900, bi=200)
_ra = _analyze(_fa, "forged", 100, "critical", "Bytedance Pte. Ltd.")
check("A 场景判定为严重", _ra["level"] == "critical", f"{_ra['level']} {_ra['score']}")
check("A 场景命中 N002（已知 C2）", "N002" in _ids(_ra), str(_ids(_ra)))
check("A 场景命中 N001（心跳规律性）", "N001" in _ids(_ra))
check("A 场景命中 N003（联合判定）", "N003" in _ids(_ra))
check("A 场景命中 N005（高风险进程持有外联）", "N005" in _ids(_ra))
check("A 场景规律性 > 95", (_ra["regularity"] or 0) > 95, f"{_ra['regularity']}")

# 场景 B：签名的 Windows 遥测，同样极规律 —— 必须不产生任何告警
_fb = _flow(9002, "4.145.79.82", 443, conn=_series(5, 75.0, 0.0), idle=1, active=0)
_rb = _analyze(_fb, "ok", 0, "clean", "Microsoft Windows")
check("B 场景（可信进程的高规律遥测）不命中任何规则", not _rb["findings"], str(_ids(_rb)))
check("B 场景等级为 clean", _rb["level"] == "clean", f"{_rb['level']} {_rb['score']}")
check("B 场景仍给出高规律性（规律性与风险分离）",
      (_rb["regularity"] or 0) > 90, f"{_rb['regularity']}")

# 场景 C：系统伪进程（无镜像文件）+ 规律的内网连接 —— 这是修过的误报点
_fc = _flow(9003, "10.0.0.5", 445, conn=_series(5, 30.0, 0.0), idle=1, active=0)
_rc = _analyze(_fc, "noimage", 0, "clean", "")
check("C 场景（无镜像文件进程的规律内网连接）不命中任何规则",
      not _rc["findings"], str(_ids(_rc)))

# 场景 C2：签名尚未校验（unknown）同样不得定罪
_fc2 = _flow(9004, "1.2.3.4", 443, conn=_series(5, 40.0, 0.0), idle=1, active=0)
_rc2 = _analyze(_fc2, "unknown", 0, "clean", "")
check("C2 场景（签名未校验）不命中 N001", "N001" not in _ids(_rc2), str(_ids(_rc2)))

# 场景 D：未签名 + 高规律 + 普通公网端口 → 命中 N001
_fd = _flow(9005, "1.2.3.4", 443, conn=_series(6, 45.0, 0.02), idle=1, active=0)
_rd = _analyze(_fd, "unsigned", 45, "medium")
check("D 场景（未签名 + 高规律）命中 N001", "N001" in _ids(_rd), str(_ids(_rd)))

# 场景 E：数据持续传输（非心跳形态）→ 字节证据必须被弃用
_fe = _flow(9006, "1.2.3.4", 443, byte=[i * 1.0 for i in range(60)],
            amounts=[500] * 60, idle=2, active=58)
_re = _analyze(_fe, "unsigned", 45, "medium")
check("E 场景（持续传输）不因字节证据被误判为规律",
      _re["regularity"] is None or _re["regularity"] < 55, f"{_re['regularity']}")
check("E 场景给出「持续传输」说明",
      any("持续传输" in n for n in _re["notes"]), str(_re["notes"]))

# 场景 F：样本不足 → 规律性为 None 且不产生 N001
_ff = _flow(9007, "1.2.3.4", 443, conn=[0.0, 60.0], idle=1, active=0)
_rf = _analyze(_ff, "unsigned", 45, "medium")
check("F 场景样本不足 → 规律性为 None", _rf["regularity"] is None)
check("F 场景不命中 N001", "N001" not in _ids(_rf), str(_ids(_rf)))
check("F 场景给出可读的样本不足说明",
      any("至少需要" in n for n in _rf["notes"]), str(_rf["notes"]))

# 场景 G：内网目标不得被判为高危（C2 几乎不会是内网）
_fg = _flow(9008, "192.168.1.9", 443, conn=_series(6, 30.0, 0.0), idle=1, active=0)
_rg = _analyze(_fg, "unsigned", 45, "medium")
check("G 场景（未签名 + 规律内网外联）等级不超过 medium",
      _rg["level"] in ("clean", "low", "medium"), f"{_rg['level']} {_rg['score']}")

# 场景 H：进程已判高风险 + 公网连接（不依赖规律性）→ 命中 N005
_fh = _flow(9009, "45.32.100.77", 45678, conn=[0.0, 12.0, 90.0], idle=1, active=0)
_rh = _analyze(_fh, "unsigned", 58, "high")
check("H 场景命中 N005", "N005" in _ids(_rh), str(_ids(_rh)))

# 场景 I：非管理员降级 —— 字节统计不可用时仍能工作且明确标注
_NM.estats_ok = False
_NM.estats_note = "开启字节统计失败（通常因为非管理员权限），已退化为仅连接事件检测"
_fi = _flow(9010, "1.2.3.4", 443, conn=_series(6, 30.0, 0.0), idle=1, active=0)
_ri = _analyze(_fi, "unsigned", 45, "medium")
check("I 场景（无字节统计）仍能靠连接事件给出规律性",
      (_ri["regularity"] or 0) > 90, f"{_ri['regularity']}")
_snap = _NM.snapshot()
check("I 场景快照标注 estats 不可用", _snap["estats"] is False)
check("I 场景快照携带降级说明", "非管理员" in (_snap["estats_note"] or ""))
_NM.estats_ok = True

# --- 10.8 采集层自检（真机）
_st_test = netapi.selftest()
check("netapi 扩展接口可用", _st_test["available"], _st_test.get("error", ""))
check("netapi 能枚举到 TCP 连接", _st_test["tcp"] > 0, f"{_st_test['tcp']} 条")
check("netapi 能枚举到 UDP 套接字", _st_test["udp"] > 0, f"{_st_test['udp']} 条")
check("estats 每连接字节统计可读（需管理员）", _st_test["estats_ok"],
      _st_test.get("estats_note", ""))

# --- 10.9 零外联承诺：netmon/netapi 源码中不得出现任何网络客户端调用
for _mod, _path in (("netmon", os.path.join(_common.app_dir(), "netmon.py")),
                    ("netapi", os.path.join(_common.app_dir(), "netapi.py"))):
    _src = open(_path, encoding="utf-8").read()
    _bad = [k for k in ("urllib", "requests", "http.client", "socket.create_connection",
                        "getaddrinfo", "gethostbyname", "urlopen", "subprocess")
            if k in _src]
    check(f"{_mod} 不含任何网络客户端/外联调用", not _bad, f"发现 {_bad}")

print()
print("=" * 72)
print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
for f in FAIL:
    print("  ✗ " + f)
print("=" * 72)
sys.exit(1 if FAIL else 0)
