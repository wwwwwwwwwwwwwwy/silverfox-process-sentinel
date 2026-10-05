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

# 11. 本工具自身辅助进程的排除
#     —— 背景：告警时间线里出现过一条"高危"，实为本工具的签名校验子进程。
#        根因是旧判据只看直接父进程，而 venv 启动器与 MSIX 应用执行别名
#        都会让 ppid ≠ 本进程。这里把三重判据与"免杀通道"底线一起固化。
print()
print("=" * 72)
print("自身辅助进程排除 —— 父进程判据失效时仍必须排除")
print("=" * 72)
import threading  # noqa: E402
import time  # noqa: E402
import psutil  # noqa: E402
import winapi as _w2  # noqa: E402

# 本工具固定把 _PS_PREAMBLE 放在脚本最前，再整体 base64(UTF-16LE) 传给 PowerShell。
# 所以命令行里必然出现该 preamble 的 base64 前缀 —— 这是**测试用**的精确标识，
# 绝不能拿它当排除判据（那就成了免杀通道，见下面的守卫断言）。
import base64 as _b64  # noqa: E402
_PS_B64 = _b64.b64encode(_w2._PS_PREAMBLE.encode("utf-16-le")).decode()
_PS_MARK = _PS_B64[:48]

_SELF = 12345
_CTX0 = {"by_pid": {}, "sig_cache": {}, "artifacts": {}, "self_pid": _SELF,
         "own_children": {}}


def _mkp(pid, ppid, ct=1000.0, cmd="x", exe=r"C:\x.exe"):
    return {"pid": pid, "ppid": ppid, "name": "pwsh.exe", "exe": exe, "dir": "C:\\",
            "ext": ".exe", "cmdline": [cmd], "cmdline_str": cmd,
            "cmdline_loaded": True, "username": "", "parent_name": "",
            "create_time": ct, "rss_mb": 1, "threads": 1, "status": "", "cpu": 0,
            "signature": {"kind": "ok", "cn": "Microsoft Corporation"},
            "connections": []}


check("判据②：直接父进程是本进程 → 排除",
      rules.is_own_aux_process(_mkp(100, _SELF), _CTX0))

_CTX_CHAIN = dict(_CTX0, by_pid={500: {"pid": 500, "ppid": _SELF}})
check("判据③：祖先链上有本进程（venv 启动器多派生一层）→ 排除",
      rules.is_own_aux_process(_mkp(100, 500), _CTX_CHAIN))

_CTX_OWN = dict(_CTX0, own_children={100: 1000.0})
check("判据①：(pid, 创建时间) 命中登记表（broker 激活、父进程不是自己）→ 排除",
      rules.is_own_aux_process(_mkp(100, 999, ct=1000.0), _CTX_OWN))
check("判据①：登记表 PID 相同但创建时间不同（PID 被系统回收）→ 不排除",
      not rules.is_own_aux_process(_mkp(100, 999, ct=9999.0), _CTX_OWN))
check("完全无关的进程 → 不排除", not rules.is_own_aux_process(_mkp(100, 999), _CTX0))

# ⛔ 免杀通道守卫：把判据放宽成"命令行含本工具 preamble 就放过"会让攻击者
#    读一遍源码就能隐身。这条断言就是防止日后有人那样"简化"。
_EVADE = _mkp(100, 999,
              cmd="powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
                  "-EncodedCommand " + _PS_B64,
              exe=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
_ev_ids = [f["rule_id"] for f in rules.rules_process(_EVADE, _CTX0)]
check("⛔ 仅凭「命令行含本工具 preamble」不得免除告警（防免杀通道）",
      "P010B" in _ev_ids or "P011" in _ev_ids, f"命中 {_ev_ids or '无'}")

# 识别"这是同类工具的兄弟进程"只用于补一句证据说明，不改变告警与否
_ev_fs = rules.rules_process(_EVADE, _CTX0)
check("证据里补上了「疑似本工具同类进程」的说明",
      any("本工具自己的 PowerShell 开头" in (f.get("advice") or "") for f in _ev_fs))
check("补说明没有改变判定结果（仍然命中）", bool(_ev_fs), f"{len(_ev_fs)} 条")
_OTHER_B64 = _b64.b64encode("Write-Host hello world".encode("utf-16-le")).decode()
check("别的 Base64 载荷不会被误认成本工具 preamble",
      not rules.looks_like_own_aux_ps(
          f"pwsh.exe -EncodedCommand {_OTHER_B64}"))

check("PS_EXE 是绝对路径（不靠 PATH 解析）", os.path.isabs(_w2.PS_EXE), _w2.PS_EXE)
check("PS_EXE 实际存在", os.path.isfile(_w2.PS_EXE), _w2.PS_EXE)
check("PS_EXE 指向真实安装路径，而不是 MSIX 应用执行别名",
      r"\Microsoft\WindowsApps" not in _w2.PS_EXE, _w2.PS_EXE)

# 端到端（确定性写法）：run_ps 必须把自己的子进程登记进表，且该进程判为无命中。
# 不用"边跑边抓进程表"那种写法 —— 20ms 轮询仍可能错过短命进程，会造成假失败。
_own_before = set(_w2.own_child_create_times())
_w2.run_ps("$null")
_own_after = _w2.own_child_create_times()
_new_own = set(_own_after) - _own_before
check("run_ps 会把自己拉起的子进程登记进表", len(_new_own) >= 1,
      f"新增 {sorted(_new_own)}，表内共 {len(_own_after)} 个")

for _pid in sorted(_new_own):
    _proc = {"pid": _pid, "ppid": 999999, "name": "pwsh.exe",     # 故意给个无关父进程
             "exe": _w2.PS_EXE, "dir": os.path.dirname(_w2.PS_EXE), "ext": ".exe",
             "cmdline": [_w2.PS_EXE, "-EncodedCommand", _PS_MARK],
             "cmdline_str": f"{_w2.PS_EXE} -NoProfile -NonInteractive "
                            f"-ExecutionPolicy Bypass -EncodedCommand {_PS_MARK}",
             "cmdline_loaded": True, "username": "", "parent_name": "",
             "create_time": _own_after.get(_pid) or 0, "rss_mb": 1, "threads": 1,
             "status": "", "cpu": 0,
             "signature": {"kind": "ok", "cn": "Microsoft Corporation"},
             "connections": []}
    _ctx_own = {"by_pid": {}, "sig_cache": {}, "artifacts": {}, "self_pid": os.getpid(),
                "own_children": _own_after}
    _ids2 = [x["rule_id"] for x in rules.rules_process(_proc, _ctx_own)]
    check(f"端到端：已登记的校验子进程 pid={_pid} 被判为无命中", not _ids2,
          f"命中 {_ids2 or '无'}")

# 端到端：**父进程被强制结束时，子进程必须一起消失（不留孤儿）**。
# 这是误报的真正源头 —— 孤儿 PowerShell 的父进程不再是监视器，排除判据失效，
# 下次扫描就会把它报成高危。用 Job Object 的 KILL_ON_JOB_CLOSE 从根上解决。
# 辅助进程用 os._exit(0) 直接终止（模拟"被强制结束"，不跑任何清理代码）。
import subprocess as _sp  # noqa: E402
_HELPER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_tmp_orphan_helper.py")
_HLOG = _HELPER + ".log"
io.open(_HELPER, "w", encoding="utf-8").write(
    "# -*- coding: utf-8 -*-\n"
    "import os, sys, threading, time, traceback\n"
    "LOG = r'" + _HLOG + "'\n"
    "def log(m):\n"
    "    with open(LOG, 'a', encoding='utf-8') as f: f.write(str(m) + '\\n')\n"
    "open(LOG, 'w', encoding='utf-8').close()\n"
    "log('helper start pid=%d' % os.getpid())\n"
    "sys.path.insert(0, r'" + _common.app_dir() + "')\n"
    "import winapi\n"
    "log('winapi imported, PS_EXE=%s' % winapi.PS_EXE)\n"
    "def go():\n"
    "    try:\n"
    "        out = winapi.run_ps('Start-Sleep -Seconds 90')\n"
    "        log('run_ps returned len=%d' % len(out))\n"
    "    except Exception:\n"
    "        log('run_ps raised: ' + traceback.format_exc())\n"
    "threading.Thread(target=go, daemon=True).start()\n"
    "time.sleep(6)\n"
    "log('helper exiting via os._exit(0)')\n"
    "os._exit(0)          # 不做任何清理，模拟被强杀\n")
try:
    os.remove(_HLOG)
except Exception:
    pass
_before_pids = set(psutil.pids())
_hp = _sp.Popen([sys.executable, _HELPER], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
_orphan_pid = 0
_t0 = time.time()
# ⚠️ 必须先按**进程名**过滤再读命令行。直接对全部进程读 cmdline，
#    遇到受保护进程（LsaIso/NgcIso 等）每次要阻塞约 1 秒，一轮就要 6–8 秒，
#    会把 6 秒的观测窗口整个错过（第一版就是这么假失败的）。
while time.time() - _t0 < 25 and not _orphan_pid:
    for _pr in psutil.process_iter(["pid", "name"]):
        if (_pr.info["name"] or "").lower() not in ("pwsh.exe", "powershell.exe"):
            continue
        if _pr.info["pid"] in _before_pids:
            continue
        try:
            _cl = " ".join(_pr.cmdline() or [])
        except Exception:
            continue
        if _PS_MARK in _cl:
            _orphan_pid = _pr.info["pid"]
            break
    time.sleep(0.05)
_hlog = ""
if not _orphan_pid:
    try:
        _hlog = io.open(_HLOG, encoding="utf-8").read()[:400]
    except Exception as e:
        _hlog = f"<日志读取失败 {e}>"
check("孤儿测试：辅助进程成功拉起了校验子进程", bool(_orphan_pid),
      f"pid={_orphan_pid}  解释器={sys.executable}"
      + (f"\n        辅助进程日志：{_hlog}" if _hlog else ""))
if _orphan_pid:
    # 辅助进程会在 6 秒后自己 os._exit(0)
    _t0 = time.time()
    while time.time() - _t0 < 15 and _hp.poll() is None:
        time.sleep(0.2)
    check("孤儿测试：辅助进程已自我终止（模拟被强杀）", _hp.poll() is not None,
          f"返回码 {_hp.poll()}")
    _t0 = time.time()
    while time.time() - _t0 < 15 and psutil.pid_exists(_orphan_pid):
        time.sleep(0.2)
    _alive = psutil.pid_exists(_orphan_pid)
    check("★ 父进程被强杀后，校验子进程被内核连带回收（不留孤儿）", not _alive,
          f"pid={_orphan_pid} " + ("仍存活 → 会变成误报源" if _alive else "已消失"))
else:
    try:
        _hp.kill()
    except Exception:
        pass
try:
    os.remove(_HELPER)
except Exception:
    pass

# 12. 排查报告：顶部数字必须与下方表格逐行对应
#     —— 背景：试用者发现报告顶部写「高危 0」，下面却列出一堆「高危」行。
#        根因是顶部 KPI 只按"进程"分等级，而表格还列了系统痕迹，两处口径不同。
#        这里把"数字 == 表格行数"固化成断言，结构上防止再犯。
print()
print("=" * 72)
print("排查报告 —— 顶部计数必须与表格行一致")
print("=" * 72)
import server as _srv  # noqa: E402


def _mk_f(rid, sev, w):
    return {"rule_id": rid, "title": f"{rid} 标题", "severity": sev,
            "severity_zh": rules.SEVERITY_ZH[sev], "weight": w, "category": "process",
            "evidence": "证据", "advice": "建议"}


def _mk_report_state(p_hi=0, p_med=1, a_hi=0, a_crit=0, n_hi=0, n_watch=0):
    procs, arts, flows = [], [], []
    for i in range(p_hi):
        procs.append({"pid": 100 + i, "name": f"p{i}.exe", "exe": "C:\\x.exe",
                      "level": "high", "score": 70, "cmdline_str": "x",
                      "findings": [_mk_f("P001", "high", 70)],
                      "signature": {"kind": "unsigned", "status_zh": "未签名"}})
    for i in range(p_med):
        procs.append({"pid": 200 + i, "name": f"m{i}.exe", "exe": "C:\\y.exe",
                      "level": "medium", "score": 40, "cmdline_str": "y",
                      "findings": [_mk_f("P006", "medium", 40)],
                      "signature": {"kind": "unsigned", "status_zh": "未签名"}})
    for i in range(a_hi):
        arts.append({"id": f"ah{i}", "kind": "task", "title": f"高危任务{i}",
                     "subtitle": "sub", "level": "high", "score": 70,
                     "findings": [_mk_f("T004", "high", 70)]})
    for i in range(a_crit):
        arts.append({"id": f"ac{i}", "kind": "service", "title": f"严重服务{i}",
                     "subtitle": "sub", "level": "critical", "score": 95,
                     "findings": [_mk_f("S001", "critical", 95)]})
    for i in range(n_hi):
        flows.append({"key": f"k{i}", "pid": 10 + i, "name": "net.exe",
                      "rip": "1.2.3.4", "rport": 443, "ip_scope_zh": "公网",
                      "level": "high", "score": 70, "regularity": 92,
                      "avg_interval": 60, "findings": [_mk_f("N001", "high", 70)],
                      "verdict": "疑似 C2 心跳"})
    for i in range(n_watch):
        flows.append({"key": f"w{i}", "pid": 20 + i, "name": "svc.exe",
                      "rip": "1.2.3.5", "rport": 443, "ip_scope_zh": "公网",
                      "level": "clean", "score": 0, "regularity": 88,
                      "avg_interval": 300, "findings": [],
                      "verdict": "规律性高但上下文无可疑特征"})
    return {
        "summary": {"total": len(procs), "connections": 10, "admin": True,
                    "scan_count": 3},
        "processes": procs, "artifacts": arts,
        "net": {"flows": flows, "estats": True, "sample_interval": 1.0,
                "live_conns": 5,
                "summary": {"flows": len(flows), "evaluated": len(flows),
                            "high_reg": n_watch},
                "session": {"duration": 120}},
    }


def _report_consistency(name, **kw):
    st = _mk_report_state(**kw)
    html = _srv.build_report_html(st)
    n_crit = html.count("<td class='sev critical'>")
    n_high = html.count("<td class='sev high'>")
    total_rows = n_crit + n_high + html.count("<td class='sev medium'>") \
        + html.count("<td class='sev low'>")
    ok = (f'<b style="color:#ff5c5c">{n_crit}</b><span>严重项</span>' in html
          and f'<b style="color:#ffa53d">{n_high}</b><span>高危项</span>' in html
          and f'<b>{total_rows}</b><span>异常项合计</span>' in html)
    check(f"{name}：顶部计数 == 表格行数（严重 {n_crit} / 高危 {n_high} / 合计 {total_rows}）",
          ok)
    return html, n_crit, n_high


# 12.1 ⭐ 试用者报的原场景：0 个高危进程，但系统痕迹里有很多高危
_h1, _c1, _h1n = _report_consistency("0 高危进程 + 3 高危痕迹", p_hi=0, a_hi=3)
check("★ 原场景：结论必须承认存在高危（而不是说「未发现高风险特征」）",
      "存在高危异常项" in _h1)
check("★ 原场景：高危项数字为 3（不是 0）", _h1n == 3, f"实际 {_h1n}")
check("★ 原场景：系统痕迹表里确实有 3 行高危", _h1.count("<td class='sev high'>") == 3)
check("★ 原场景：标题写明各类别项数", "异常进程 —— 1 项" in _h1
      and "系统痕迹异常 —— 3 项" in _h1)

# 12.2 三类对象混合
_h2, _c2, _h2n = _report_consistency("混合场景", p_hi=2, a_hi=1, a_crit=1, n_hi=1)
check("混合场景：严重项 == 1（仅系统痕迹里那 1 条）", _c2 == 1, f"实际 {_c2}")
check("混合场景：高危项 == 4（2 进程 + 1 痕迹 + 1 网络）", _h2n == 4, f"实际 {_h2n}")

# 12.3 「规律性观察」不得被算成风险
_h3, _c3, _h3n = _report_consistency("只有观察项", p_hi=0, p_med=0, n_watch=4)
check("规律性观察项不计入风险等级", _c3 == 0 and _h3n == 0)
check("规律性观察项单独计数并在标题写明", "规律性观察 4 项" in _h3)
check("观察行标为「观察」而不是「高危」", "<td class='sev watch'>观察</td>" in _h3)
check("无风险时结论不应声称发现高风险",
      "未发现银狐相关风险特征" in _h3)

# 12.4 只有中危时，结论不能是"未发现高风险特征"（初版的另一处自相矛盾）
_h4, _, _ = _report_consistency("只有中危", p_hi=0, p_med=2)
check("只有中危时结论明确说明是中危", "存在若干中危可疑项" in _h4)

# 12.5 详情章节数量与顶部「需处置」一致
check("详情章节数量 == 严重+高危合计",
      f"五、高危项详情与处置建议 —— {_c2 + _h2n} 项" in _h2,
      f"期望 {_c2 + _h2n}")

# 12.6 告警记录必须携带 advice
#      —— 像"这条可能是本工具自己的同类进程"这种关键提示写在 advice 里。
#         初版只带 evidence，导致提示只出现在进程详情里、在最需要的告警时间线上缺席。
class _AlertSink:
    def __init__(self):
        self.alerts = []


_AlertSink._push_alert = _srv.Monitor._push_alert
_sink = _AlertSink()
_sink._push_alert({"level": "high", "score": 72.5, "name": "pwsh.exe", "pid": 4242,
                   "ppid": 111, "parent_name": "python.exe", "exe": "C:\\x.exe",
                   "findings": [_mk_f("P010B", "medium", 55)]})
check("告警记录里带上了 advice（否则关键提示不会出现在告警时间线）",
      bool(_sink.alerts and _sink.alerts[0]["rules"][0].get("advice")),
      str(_sink.alerts[0]["rules"][0] if _sink.alerts else None)[:80])
check("告警记录里带上了父进程信息（排查同类误报的关键线索）",
      _sink.alerts[0].get("ppid") == 111 and _sink.alerts[0].get("parent") == "python.exe")

# ================================================================
# 13. 目录名判据 —— 品牌名不得被判「随机命名目录」
#
# 2026-10-05 测试机（LAPTOP-B23G59QJ）实测：looks_random 的
# 「大小写混杂即随机」判据把驼峰式品牌名整片误判 ——
#   looks_random("MySQL") / ("WXWork") / ("MasterPDF") 全为 True，
# 于是 MySQL80 服务、WXWorkUpgrader 服务、迅读PDF 的 DocUpdate 任务与
# DocService 服务，全部因「Program Files 下随机命名目录」被判高危/严重。
# 这四条是纯误报。修复引入 looks_random_dir（只用于目录名场景），
# 本节的断言把「品牌名不误报」与「银狐随机名仍检出」两侧一起钉住。
# ================================================================
print()
print("=" * 72)
print("13. looks_random_dir —— 品牌名 vs 银狐随机目录名")
print("=" * 72)

for _n in ("MySQL", "WXWork", "MasterPDF", "Google", "NVIDIA", "OneDrive",
           "Realtek", "PowerPoint", "McAfee"):
    check(f"品牌名 {_n} 不判为随机目录", not rules.looks_random_dir(_n))

for _n in ("bcCfOw", "SXRh6d", "VBV4HZ", "cgL18U72", "O02PwqGh", "Pl6VgrWG"):
    check(f"银狐随机名 {_n} 仍判为随机目录", rules.looks_random_dir(_n))

# 13.1 测试机上的四条误报路径必须不再命中
check("MySQL80 服务路径不再判非常规",
      not rules.nonstandard_target(
          r"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqld.exe"))
check("WXWorkUpgrader 服务路径不再判非常规",
      not rules.nonstandard_target(
          r"C:\Program Files (x86)\WXWork\WXWorkUpgrader\WXWorkUpgrader.exe"))
check("迅读PDF DocUpdate 任务路径不再判非常规",
      not rules.nonstandard_target(r"C:\Program Files (x86)\MasterPDF\DocUpdate.exe"))
check("迅读PDF DocService 服务路径不再判非常规",
      not rules.nonstandard_target(r"C:\Program Files (x86)\MasterPDF\DocService.exe"))

# 13.2 强信号目录与随机目录必须仍然命中 ——
#      不能为了压误报把检出能力一起砍掉
check("Temp 目录下的可执行文件仍判非常规",
      bool(rules.nonstandard_target(
          r"C:\Users\LIN\AppData\Local\Temp\ScreenShareClientUpdate.exe")))
check("Users\\Public 下的随机名仍判非常规",
      bool(rules.nonstandard_target(r"C:\Users\Public\bcCfOw.exe")))
check("Program Files (x86) 下随机目录仍判非常规",
      bool(rules.nonstandard_target(r"C:\Program Files (x86)\bcCfOw\x.exe")))

# 13.3 端到端：DocUpdate 任务不得再产生任何 T 系列命中
_t_doc = {"name": "DocUpdate", "path": "\\", "state": "Ready", "hidden": False,
          "runlevel": "Highest", "userid": "SYSTEM",
          "actions": [{"exec": r"C:\Program Files (x86)\MasterPDF\DocUpdate.exe"}],
          "triggers": []}
_ids_doc = [f["rule_id"] for it in rules.rules_tasks({"tasks": [_t_doc]})
            for f in it.get("findings", [])]
check("DocUpdate 任务不再产生任何计划任务类告警", not _ids_doc, f"实际 {_ids_doc}")

# 13.4 但同一形态若落在随机目录，必须仍然报（检出能力不回退）
_t_evil = {"name": "DocUpdate", "path": "\\", "state": "Ready", "hidden": False,
           "runlevel": "Highest", "userid": "SYSTEM",
           "actions": [{"exec": r"C:\Program Files (x86)\bcCfOw\DocUpdate.exe"}],
           "triggers": []}
_ids_evil = [f["rule_id"] for it in rules.rules_tasks({"tasks": [_t_evil]})
             for f in it.get("findings", [])]
check("同一任务落在随机目录时仍报（T004/T006）",
      ("T006" in _ids_evil) or ("T004" in _ids_evil), f"实际 {_ids_evil}")
check("高权限任务只报 T006，不与 T004 重复计分",
      "T006" in _ids_evil and "T004" not in _ids_evil, f"实际 {_ids_evil}")

# 13.5 F001 上下文闸
check("正常软件目录不算强信号上下文",
      not rules._in_strong_scan_context(r"C:\ProgramData\MySQL\MySQL Server 8.0")
      and not rules._in_strong_scan_context(
          r"C:\Program Files (x86)\WXWork\WXWorkUpgrader"))
check("强信号目录 / 随机目录算强信号上下文",
      rules._in_strong_scan_context(r"C:\Users\Public")
      and rules._in_strong_scan_context(r"C:\ProgramData\bcCfOw"))

print()
print("=" * 72)
print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
for f in FAIL:
    print("  ✗ " + f)
print("=" * 72)
sys.exit(1 if FAIL else 0)
