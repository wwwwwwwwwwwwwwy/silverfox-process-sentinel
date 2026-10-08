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
# ⚠️ 别用固定长度的源码窗口（原先取 def 之后 1200 字符）——
#    函数体稍一变长，断言就会因为"截不到那一段"而假失败，
#    和被测行为其实毫无关系。按缩进把整个函数体取出来。
_lines = src.splitlines()
_i = next(i for i, l in enumerate(_lines) if l.startswith("def read_hosts"))
_body = []
for _l in _lines[_i + 1:]:
    if _l.strip() and not _l.startswith((" ", "\t")):
        break
    _body.append(_l)
seg = "\n".join(_body)
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
# ⚠️ 旧断言是 `"sig is None or" not in src_rules` —— 它只否掉了一种**写法**，
#    而 2026-10-08 的缺陷恰恰绕过了它：定罪逻辑被写成
#    `if treat_unknown_as_bad: sideload.append(mp)`，源码里没有 "sig is None or"
#    这个字面量，于是测试一路绿灯，误报却把 Edge / 微信 / <workspace> 全判成了严重。
#    教训：**断言"某段代码不存在"时，必须断言那个"行为开关"不存在，
#    而不是它某一种可能的长相。** 真正的守卫在下面的 F-021（行为层）。
check("X003 不把「签名未校验」当可疑依据", "sig is None or" not in src_rules)


def _uses_identifier(src: str, name: str) -> bool:
    """源码里是否**真的使用了**某个标识符（忽略注释与文档字符串）。

    为什么不用 `name in src` 这种子串判断：本文件上一版就是这么写的，
    结果连"注释里解释为什么删掉它"都会被判成违规 —— 一个只会产生假警报的断言，
    最后必然被人随手注释掉，等于没有。改用 AST：只看真实的
    参数声明(arg)、关键字实参(keyword)、名字(Name)与属性(Attribute)。
    解析失败时返回 True（fail-closed），避免"语法坏了反而检查通过"。
    """
    import ast as _ast
    try:
        tree = _ast.parse(src)
    except SyntaxError:
        return True
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Name) and node.id == name:
            return True
        if isinstance(node, _ast.arg) and node.arg == name:
            return True
        if isinstance(node, _ast.keyword) and node.arg == name:
            return True
        if isinstance(node, _ast.Attribute) and node.attr == name:
            return True
    return False


check("X003 不存在「未校验即定罪」的旁路开关（AST 层面）",
      not _uses_identifier(src_rules, "treat_unknown_as_bad")
      and not _uses_identifier(src_srv, "treat_unknown_as_bad"))


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
# ⚠️ 辅助脚本必须写在**临时目录**，不能写在程序目录旁边。
#    2026-10-07 实测：程序目录按 README 第 9.7 节收紧为「仅管理员可写」之后，
#    这里会直接抛 PermissionError，**整个自检跑到一半崩掉**。
#    也就是说：脚本原本与它自己推荐的加固措施互相矛盾 ——
#    加固一做，普通用户就再也跑不了自检。改放临时目录后两者不再冲突。
import tempfile as _tf          # noqa: E402
_HELPER = os.path.join(_tf.gettempdir(), "yh_orphan_helper.py")
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
# ⚠️ 辅助进程的日志也要删 —— 只删 .py 会在仓库/程序目录里留下 _tmp_orphan_helper.py.log
#    这种垃圾文件（实测把安装目录和仓库都污染了一次）。
try:
    os.remove(_HLOG)
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
        # ⚠️ 这里必须**照抄 netmon._slim_flow 的真实字段**：只带 finding_ids，
        #    **不带** findings。夹具里多写一个真实数据没有的字段，
        #    就会把"报告直接访问 flow['findings'] 导致 KeyError"这类 bug 放过去
        #    —— 实测就是这么漏掉的（导出在网络页有观察项时整个失败）。
        flows.append({"key": f"k{i}", "pid": 10 + i, "name": "net.exe",
                      "rip": "1.2.3.4", "rport": 443, "ip_scope_zh": "公网",
                      "level": "high", "score": 70, "regularity": 92,
                      "avg_interval": 60, "finding_ids": ["N001"],
                      "verdict": "疑似 C2 心跳"})
    for i in range(n_watch):
        flows.append({"key": f"w{i}", "pid": 20 + i, "name": "svc.exe",
                      "rip": "1.2.3.5", "rport": 443, "ip_scope_zh": "公网",
                      "level": "clean", "score": 0, "regularity": 88,
                      "avg_interval": 300, "finding_ids": [],
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
    try:
        html = _srv.build_report_html(st)
        _build_err = ""
    except Exception as e:
        check(f"{name}：报告必须能生成（不能抛异常）", False,
              f"{type(e).__name__}: {e}")
        return "", 0, 0
    n_crit = html.count("<td class='sev critical'>")
    n_high = html.count("<td class='sev high'>")
    total_rows = n_crit + n_high + html.count("<td class='sev medium'>") \
        + html.count("<td class='sev low'>")
    ok = (f'<b style="color:#ff5c5c">{n_crit}</b><span>严重项</span>' in html
          and f'<b style="color:#ffa53d">{n_high}</b><span>高危项</span>' in html
          and f'<b>{total_rows}</b><span>异常项合计</span>' in html)
    check(f"{name}：报告能生成且顶部计数 == 表格行数"
          f"（严重 {n_crit} / 高危 {n_high} / 合计 {total_rows}）", ok)
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

# 12.7 网络行的「判定依据」必须靠 finding_ids 还原，不能访问 flow['findings']
#      —— 精简流里没有 findings，直接取会 KeyError，导致报告整个导不出来（实测）
check("网络行判定依据用 finding_ids 还原",
      "[N001]" in _srv._flow_rules_text({"finding_ids": ["N001"], "verdict": "x"}))
check("没有 finding_ids 时退回判决语",
      _srv._flow_rules_text({"finding_ids": [], "verdict": "未见异常"}) == "未见异常")
check("真实精简流形状（只有 finding_ids）不会让报告崩",
      bool(_srv.build_report_html(_mk_report_state(n_hi=1, n_watch=2))))

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

# 13.6 ⚠️ 强信号目录必须按**路径段**匹配，不能用子串包含。
#      实测缺陷：`C:\ProgramData\Vendor\TempData` 含 `\temp` 子串、
#      `...\Downloads_old` 含 `\downloads` 子串，用子串匹配会被判成
#      "在 Temp / Downloads 之下"，于是把刚排除掉的资源文件重新放回
#      F001 的射程 —— 正好抵消了本次要修的误报。已改用段级匹配 in_dirs()。
check("含 \\Temp 子串的正常目录不算强信号（TempData）",
      not rules._in_strong_scan_context(r"C:\ProgramData\Vendor\TempData"))
check("含 \\Downloads 子串的正常目录不算强信号（Downloads_old）",
      not rules._in_strong_scan_context(r"C:\ProgramData\Vendor\Downloads_old"))
check("Program Files 下的 TempDir 不算强信号",
      not rules._in_strong_scan_context(r"C:\Program Files\Foo\TempDir"))
check("真正的 Temp 目录仍算强信号（段级匹配不能把检出也砍掉）",
      rules._in_strong_scan_context(r"C:\Windows\Temp")
      and rules._in_strong_scan_context(r"C:\Users\x\AppData\Local\Temp"))
check("真正的 Downloads 目录仍算强信号",
      rules._in_strong_scan_context(r"C:\Users\x\Downloads"))

# ================================================================
# 14. 版本号 与 本机副本管理
#
# 背景：本机会自然长出多份副本（安装版 / 开源副本 / 打包 exe / 临时测试目录）。
# 在加版本号之前，"哪个是最新版"只能靠文件修改时间猜 —— 实测已经出过问题：
# 用户跑着旧副本，却以为功能坏了。所以加 version.py，并配一个副本管理器。
#
# 本节重点盯住**破坏性操作的两条底线**：
#   ① 脱敏副本与完整副本绝不能互相覆盖（一个会泄露真实路径，一个会让工具失效）
#   ② 覆盖时绝不能碰 python_path.txt / 备份 目录 / %LOCALAPPDATA% 下的用户数据
# ================================================================
print()
print("=" * 72)
print("14. 版本号 与 本机副本管理")
print("=" * 72)

import importlib  # noqa: E402
import re as _re  # noqa: E402

import version as _ver  # noqa: E402

check("VERSION 形如 年.月.日[.序号]",
      bool(_re.fullmatch(r"\d{4}\.\d{2}\.\d{2}(\.\d+)?", _ver.VERSION)), _ver.VERSION)
check("compare：同日序号大者为新", _ver.compare("2026.10.05.3", "2026.10.05.2") == 1)
check("compare：段数不同按 0 补齐（2026.10.05 == 2026.10.05.0）",
      _ver.compare("2026.10.05", "2026.10.05.0") == 0)
check("compare：日期新者为新", _ver.compare("2026.10.06", "2026.10.05.9") == 1)
check("compare：相等返回 0", _ver.compare("2026.10.05.3", "2026.10.05.3") == 0)
check("compare：异常输入不抛异常", isinstance(_ver.compare(None, "2026.10.05"), int))
check("version_line 含版本号", _ver.VERSION in _ver.version_line())

# ---- 副本管理：脱敏判定 + 覆盖计划（用临时目录做，不碰真实副本）
#
# ⚠️ 这里不能用安装版特有的 HERE 变量 —— 仓库版把本文件放在 tools/ 下、
#    没有 HERE，同步脚本会因此报错。改成"往上找 本机副本管理.py"，
#    两种布局都能定位到程序根目录。
def _tool_root() -> str:
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(3):
        if os.path.isfile(os.path.join(d, "本机副本管理.py")):
            return d
        d = os.path.dirname(d)
    return os.path.dirname(os.path.abspath(__file__))


sys.path.insert(0, _tool_root())
_mgr = importlib.import_module("本机副本管理")

import shutil as _sh  # noqa: E402
import tempfile as _tf  # noqa: E402

_tmp = _tf.mkdtemp(prefix="sfx-copytest-")


def _make_copy(root, marker=""):
    """造一个最小可识别副本：app/server.py + app/rules.py + app/version.py"""
    os.makedirs(os.path.join(root, "app"), exist_ok=True)
    for f in ("server.py", "rules.py"):
        io.open(os.path.join(root, "app", f), "w", encoding="utf-8").write("# x\n")
    io.open(os.path.join(root, "app", "version.py"), "w", encoding="utf-8").write(
        'VERSION = "2026.10.05.3"\n')
    if marker:
        io.open(os.path.join(root, "app", "whitelist.py"), "w",
                encoding="utf-8").write(f'NAME = "{marker}"\n')
    io.open(os.path.join(root, "README.md"), "w", encoding="utf-8").write("readme\n")
    return root


_src = _make_copy(os.path.join(_tmp, "src"))
_dst = _make_copy(os.path.join(_tmp, "dst"))
io.open(os.path.join(_dst, "python_path.txt"), "w", encoding="utf-8").write("C:\\py.exe\n")
io.open(os.path.join(_dst, "app", "server.py"), "w", encoding="utf-8").write("# OLD\n")

check("能识别目录是不是工具副本", _mgr.is_copy(_src) and _mgr.is_copy(_dst))
check("普通副本不被判为脱敏", not _mgr.looks_desensitized(_src))
_des = _make_copy(os.path.join(_tmp, "des"), marker="my-watchdog")
check("含占位符的副本被判为脱敏副本", _mgr.looks_desensitized(_des))

# ⛔ 底线①：脱敏 ↔ 完整 互相覆盖必须被拒绝
check("★ 拒绝用脱敏副本覆盖完整副本（否则工具会认不出本机真实任务名）",
      _mgr.do_overwrite(_des, _src, yes=True) == 1)
check("★ 拒绝用完整副本覆盖脱敏副本（否则真实路径会被推到公开仓库）",
      _mgr.do_overwrite(_src, _des, yes=True) == 1)
check("被拒绝后目标文件没被动过",
      io.open(os.path.join(_src, "app", "server.py"), encoding="utf-8").read() == "# x\n")

# ✅ 正常覆盖：旧内容被替换、python_path.txt 必须保留
_plan = _mgr.plan_overwrite(_src, _dst)
check("覆盖计划把 app 列入删除/重写", "app" in _plan["delete"])
check("覆盖计划把 python_path.txt 列入保留", any("python_path" in k for k in _plan["keep"]),
      str(_plan["keep"]))
_rc = _mgr.do_overwrite(_src, _dst, yes=True)
check("正常覆盖执行成功", _rc == 0)
check("覆盖后内容与源一致",
      io.open(os.path.join(_dst, "app", "server.py"), encoding="utf-8").read() == "# x\n")
check("★ 覆盖后 python_path.txt 仍保留（机器相关配置不能被冲掉）",
      os.path.isfile(os.path.join(_dst, "python_path.txt")))
check("覆盖前自动做了备份", os.path.isdir(os.path.join(_dst, "备份")))

_sh.rmtree(_tmp, ignore_errors=True)



# ================================================================
# 15. 红队审计修复的回归断言
#
# 来源：2026-10-06 红蓝对抗（REPORT.md / findings.red.json / 修改建议.md）。
# 本节只放**不需要起服务**就能验的；需要打接口的（GET 来源校验、告警忽略、
# 报告导出）由 _dev 下的接口测试脚本覆盖。
# ================================================================
print()
print("=" * 72)
print("15. 红队审计修复")
print("=" * 72)

import integrity as _it  # noqa: E402
import server as _srvmod  # noqa: E402
import version as _v  # noqa: E402
import whitelist as _wl  # noqa: E402

_srv = io.open(os.path.join(_common.app_dir(), "server.py"), encoding="utf-8").read()
_mn = io.open(os.path.join(_common.app_dir(), "main.py"), encoding="utf-8").read()
_itg = io.open(os.path.join(_common.app_dir(), "integrity.py"), encoding="utf-8").read()
_wls = io.open(os.path.join(_common.app_dir(), "whitelist.py"), encoding="utf-8").read()
_col = io.open(os.path.join(_common.app_dir(), "collector.py"), encoding="utf-8").read()
_wap = io.open(os.path.join(_common.app_dir(), "winapi.py"), encoding="utf-8").read()
_js = io.open(os.path.join(_common.app_dir(), "web", "app.js"), encoding="utf-8").read()

# ---- F-013 · extras 只有一处来源
check("F-013 运行期 extras 走 default_extras",
      "return integrity.default_extras()" in _srv)
check("F-013 --verify-only 走 default_extras", "integrity.default_extras()" in _mn)
check("F-013 不再有内联的 [sys.executable] if ... frozen 写法",
      "extra = [sys.executable] if getattr(sys" not in _srv
      and "extra = [sys.executable] if getattr(sys" not in _mn)
# ⚠️ 不能断言"返回值里一定含这两个文件" —— python_path.txt 与 whitelist.json
#    是**机器相关**的（都在 .gitignore 里），仓库副本里根本不存在。
#    断言"源码层面覆盖了它们"才在两种副本上都成立。
check("F-013 extras 覆盖 python_path.txt 与 whitelist.json（源码层面）",
      "paths.PYTHON_PATH_FILE" in _itg and "paths.WHITELIST_FILE" in _itg)

# ---- F-014 · 启动链纳入覆盖
_ex = _it.default_extras()
check("F-014 .bat 在覆盖范围内", any(p.lower().endswith(".bat") for p in _ex))
check("F-014 extras 的键带 <root>/ 前缀（避免与 app/ 相对路径撞名）",
      any(k.startswith("<root>/") for k in
          _it.collect_manifest(_common.app_dir(), _ex)))

# ---- F-015 · 基线按安装分文件
check("F-015 不同 app_dir 得到不同基线文件名",
      _it.baseline_path("X", "C:/A") != _it.baseline_path("X", "C:/B"))
check("F-015 不同 app_dir 得到不同哨兵文件名",
      _it.sentinel_path("C:/A") != _it.sentinel_path("C:/B"))
check("F-015 verify 按 app_dir 读基线", "load_baseline(workspace, app_dir)" in _itg)
check("F-015 save_baseline 按 app_dir 写基线",
      "baseline_path(workspace, app_dir)" in _itg)

# ---- F-016 · 身份判定与哨兵目录
check("F-016 归属只看 app_dir（数据目录变了仍算本安装）",
      _it.sentinel_belongs_here({"app_dir": "C:/A", "workspace": "Z:/other"}, "C:/A"))
check("F-016 别的安装的哨兵不算本安装",
      not _it.sentinel_belongs_here({"app_dir": "C:/B"}, "C:/A"))
check("F-016 哨兵目录是绝对路径", os.path.isabs(_it.SENTINEL_DIR))
check("F-016 不再用可能没被展开的 expandvars(%LOCALAPPDATA%)",
      'expandvars(r"%LOCALAPPDATA%")' not in _itg)
check("F-016 count 被真正读取（交叉校验）", "count_mismatch" in _itg)
check("F-016 数据目录落在程序目录时会暴露给界面",
      "data_on_program_dir" in _srv)

# ---- F-001 · rule_only 后门
check("F-001 rule_only 不在合法匹配方式里", "rule_only" not in _wl.MATCH_TYPES)
check("F-001 历史 rule_only 条目 fail-closed",
      not _wl.entry_matches({"rule_id": "P001",
                             "match": {"type": "rule_only", "value": ""}, "guard": {}},
                            {"rule_id": "P001"}, {"exe": "x", "name": "y"}))
for _args, _name in ((("P001", "rule_only", ""), "rule_only"),
                     (("P001", "exe_path", ""), "空匹配值")):
    try:
        _wl.add(*_args)
        check(f"F-001 add() 拒绝{_name}", False)
    except ValueError:
        check(f"F-001 add() 拒绝{_name}", True)
check("F-001 服务端显式拒绝 rule_only", "不支持按规则号全量豁免" in _srv)
check("F-001 服务端要求指明对象", "必须指明这条已知项针对哪个对象" in _srv)
check("F-001 服务端断言只命中一个对象", "会同时命中" in _srv)
check("F-001 匹配值有具体性下限",
      bool(_srvmod._match_too_broad("exe_path_prefix", "C:\\"))
      and not bool(_srvmod._match_too_broad(
          "exe_path_prefix", "C:\\Program Files\\Vendor\\App\\")))
check("F-001 suggest() 不再产出 rule_only",
      '"rule_only", ""' not in
      io.open(os.path.join(_common.app_dir(), "whitelist.py"), encoding="utf-8").read())

# ---- F-002 · 基线丢失不得静默重建
# 断言前先把空白压平 —— 否则源码一换行（本来就该换行）断言就假失败
_srv_flat = " ".join(_srv.split())
check("F-002 刷新基线前先判哨兵归属",
      "sentinel_belongs_here( integrity.load_sentinel(APP_DIR), APP_DIR)" in _srv_flat)
check("F-002 拒绝刷新时返回非空（界面能显示 blocked）",
      "已拒绝刷新基线" in _srv)

# ---- F-005 · GET 来源校验
check("F-005 do_GET 调用来源校验", "_guard_origin_host()" in _srv)
check("F-005 来源校验被抽成独立方法（POST/GET 共用）",
      "def _guard_origin_host" in _srv)
check("F-005 Host 解析正确处理 IPv6", 'h.startswith("[")' in _srv)

# ---- F-017 · 白名单原子写与损坏保护
check("F-017 save() 原子替换", "os.replace(" in _wls and ".tmp" in _wls)
check("F-017 损坏时返回 _corrupt 而不是空表", '"_corrupt": repr(e)' in _wls)
check("F-017 add/remove 持锁", "_LOCK" in _wls)
check("F-017 服务端对损坏回 409", "409" in _srv)

# ---- F-018 · 守卫哈希上限
check("F-018 守卫哈希有上限且超限不放行", "_GUARD_MAX_BYTES" in _wls)

# ---- F-006 / F-007 · 降级可恢复、可见
check("F-006 失败结果不写进 sig_cache", "_sig_failed" in _srv
      and '"kind": "unknown"' not in _srv)
check("F-006 state 暴露 sig_failed", '"sig_failed"' in _srv)
check("F-007 命令行拉黑带 TTL", "_DENY_TTL" in _col
      and "time.monotonic() < _denied_names[" in _col)
check("F-007 state 暴露 cmdline_denied", '"cmdline_denied"' in _srv)

# ---- F-008 · 制品采集分节
check("F-008 分节输出（PS 侧有 ##SEC）", "##SEC " in _wap)
check("F-008 缺失小节记入 _unavailable", "_unavailable" in _wap)
check("F-008 报告里区分「未取到」", "未取到" in _srv)

# ---- F-009 / F-010 / F-011 / F-012 / F-019
_bad_js = [i for i, l in enumerate(_js.splitlines(), 1)
           if "localStorage." in l and l and not l[0].isspace()]
check("F-009 前端无未保护的顶层 localStorage 访问", not _bad_js, str(_bad_js[:3]))
check("F-010 移除已知项用事件委托",
      "$('#secBox').addEventListener('click'" in _js)
_nm = io.open(os.path.join(_common.app_dir(), "netmon.py"), encoding="utf-8").read()
check("F-011 estats 失败可退避重试", "estats_retry_after" in _nm)
check("F-011 estats 成功即清零失败计数", "self.estats_fail_streak = 0" in _nm)
check("F-012 hosts 按 BOM/签名判编码", "raw[:2] in (b" in _wap
      and "raw[:3] == b" in _wap)
check("F-003 非有限时长明确拒绝", 'not math.isfinite(duration)' in _nm
      and '"bad": True' in _nm)
check("F-019 compare 对上标数字不抛异常",
      isinstance(_v.compare("2026.10.05\u00b2", "2026.10.05"), int))



# ================================================================
# 15. 红队审计修复的回归断言
#
# 来源：2026-10-06 红蓝对抗（REPORT.md / findings.red.json / 修改建议.md）。
# 本节只放**不需要起服务**就能验的；需要打接口的（GET 来源校验、告警忽略、
# 报告导出）由 _dev 下的接口测试脚本覆盖。
# ================================================================
print()
print("=" * 72)
print("15. 红队审计修复")
print("=" * 72)

import integrity as _it  # noqa: E402
import version as _v  # noqa: E402
import whitelist as _wl  # noqa: E402

_srv = io.open(os.path.join(_common.app_dir(), "server.py"), encoding="utf-8").read()
_mn = io.open(os.path.join(_common.app_dir(), "main.py"), encoding="utf-8").read()
_itg = io.open(os.path.join(_common.app_dir(), "integrity.py"), encoding="utf-8").read()
_wls = io.open(os.path.join(_common.app_dir(), "whitelist.py"), encoding="utf-8").read()
_col = io.open(os.path.join(_common.app_dir(), "collector.py"), encoding="utf-8").read()
_wap = io.open(os.path.join(_common.app_dir(), "winapi.py"), encoding="utf-8").read()
_js = io.open(os.path.join(_common.app_dir(), "web", "app.js"), encoding="utf-8").read()

# ---- F-013 · extras 只有一处来源
check("F-013 运行期 extras 走 default_extras",
      "return integrity.default_extras()" in _srv)
check("F-013 --verify-only 走 default_extras", "integrity.default_extras()" in _mn)
check("F-013 不再有内联的 [sys.executable] if ... frozen 写法",
      "extra = [sys.executable] if getattr(sys" not in _srv
      and "extra = [sys.executable] if getattr(sys" not in _mn)
# ⚠️ 不能断言"返回值里一定含这两个文件" —— python_path.txt 与 whitelist.json
#    是**机器相关**的（都在 .gitignore 里），仓库副本里根本不存在。
#    断言"源码层面覆盖了它们"才在两种副本上都成立。
check("F-013 extras 覆盖 python_path.txt 与 whitelist.json（源码层面）",
      "paths.PYTHON_PATH_FILE" in _itg and "paths.WHITELIST_FILE" in _itg)

# ---- F-014 · 启动链纳入覆盖
_ex = _it.default_extras()
check("F-014 .bat 在覆盖范围内", any(p.lower().endswith(".bat") for p in _ex))
check("F-014 extras 的键带 <root>/ 前缀（避免与 app/ 相对路径撞名）",
      any(k.startswith("<root>/") for k in
          _it.collect_manifest(_common.app_dir(), _ex)))

# ---- F-015 · 基线按安装分文件
check("F-015 不同 app_dir 得到不同基线文件名",
      _it.baseline_path("X", "C:/A") != _it.baseline_path("X", "C:/B"))
check("F-015 不同 app_dir 得到不同哨兵文件名",
      _it.sentinel_path("C:/A") != _it.sentinel_path("C:/B"))
check("F-015 verify 按 app_dir 读基线", "load_baseline(workspace, app_dir)" in _itg)
check("F-015 save_baseline 按 app_dir 写基线",
      "baseline_path(workspace, app_dir)" in _itg)

# ---- F-016 · 身份判定与哨兵目录
check("F-016 归属只看 app_dir（数据目录变了仍算本安装）",
      _it.sentinel_belongs_here({"app_dir": "C:/A", "workspace": "Z:/other"}, "C:/A"))
check("F-016 别的安装的哨兵不算本安装",
      not _it.sentinel_belongs_here({"app_dir": "C:/B"}, "C:/A"))
check("F-016 哨兵目录是绝对路径", os.path.isabs(_it.SENTINEL_DIR))
check("F-016 不再用可能没被展开的 expandvars(%LOCALAPPDATA%)",
      'expandvars(r"%LOCALAPPDATA%")' not in _itg)
check("F-016 count 被真正读取（交叉校验）", "count_mismatch" in _itg)
check("F-016 数据目录落在程序目录时会暴露给界面",
      "data_on_program_dir" in _srv)

# ---- F-001 · rule_only 后门
check("F-001 rule_only 不在合法匹配方式里", "rule_only" not in _wl.MATCH_TYPES)
check("F-001 历史 rule_only 条目 fail-closed",
      not _wl.entry_matches({"rule_id": "P001",
                             "match": {"type": "rule_only", "value": ""}, "guard": {}},
                            {"rule_id": "P001"}, {"exe": "x", "name": "y"}))
for _args, _name in ((("P001", "rule_only", ""), "rule_only"),
                     (("P001", "exe_path", ""), "空匹配值")):
    try:
        _wl.add(*_args)
        check(f"F-001 add() 拒绝{_name}", False)
    except ValueError:
        check(f"F-001 add() 拒绝{_name}", True)
check("F-001 服务端显式拒绝 rule_only", "不支持按规则号全量豁免" in _srv)
check("F-001 服务端要求指明对象", "必须指明这条已知项针对哪个对象" in _srv)
check("F-001 服务端断言只命中一个对象", "会同时命中" in _srv)
check("F-001 匹配值有具体性下限",
      bool(_srvmod._match_too_broad("exe_path_prefix", "C:\\"))
      and not bool(_srvmod._match_too_broad(
          "exe_path_prefix", "C:\\Program Files\\Vendor\\App\\")))
check("F-001 suggest() 不再产出 rule_only",
      '"rule_only", ""' not in
      io.open(os.path.join(_common.app_dir(), "whitelist.py"), encoding="utf-8").read())

# ---- F-002 · 基线丢失不得静默重建
# 断言前先把空白压平 —— 否则源码一换行（本来就该换行）断言就假失败
_srv_flat = " ".join(_srv.split())
check("F-002 刷新基线前先判哨兵归属",
      "sentinel_belongs_here( integrity.load_sentinel(APP_DIR), APP_DIR)" in _srv_flat)
check("F-002 拒绝刷新时返回非空（界面能显示 blocked）",
      "已拒绝刷新基线" in _srv)

# ---- F-005 · GET 来源校验
check("F-005 do_GET 调用来源校验", "_guard_origin_host()" in _srv)
check("F-005 来源校验被抽成独立方法（POST/GET 共用）",
      "def _guard_origin_host" in _srv)
check("F-005 Host 解析正确处理 IPv6", 'h.startswith("[")' in _srv)

# ---- F-017 · 白名单原子写与损坏保护
check("F-017 save() 原子替换", "os.replace(" in _wls and ".tmp" in _wls)
check("F-017 损坏时返回 _corrupt 而不是空表", '"_corrupt": repr(e)' in _wls)
check("F-017 add/remove 持锁", "_LOCK" in _wls)
check("F-017 服务端对损坏回 409", "409" in _srv)

# ---- F-018 · 守卫哈希上限
check("F-018 守卫哈希有上限且超限不放行", "_GUARD_MAX_BYTES" in _wls)

# ---- F-006 / F-007 · 降级可恢复、可见
check("F-006 失败结果不写进 sig_cache", "_sig_failed" in _srv
      and '"kind": "unknown"' not in _srv)
check("F-006 state 暴露 sig_failed", '"sig_failed"' in _srv)
check("F-007 命令行拉黑带 TTL", "_DENY_TTL" in _col
      and "time.monotonic() < _denied_names[" in _col)
check("F-007 state 暴露 cmdline_denied", '"cmdline_denied"' in _srv)

# ---- F-008 · 制品采集分节
check("F-008 分节输出（PS 侧有 ##SEC）", "##SEC " in _wap)
check("F-008 缺失小节记入 _unavailable", "_unavailable" in _wap)
check("F-008 报告里区分「未取到」", "未取到" in _srv)

# ---- F-009 / F-010 / F-011 / F-012 / F-019
_bad_js = [i for i, l in enumerate(_js.splitlines(), 1)
           if "localStorage." in l and l and not l[0].isspace()]
check("F-009 前端无未保护的顶层 localStorage 访问", not _bad_js, str(_bad_js[:3]))
check("F-010 移除已知项用事件委托",
      "$('#secBox').addEventListener('click'" in _js)
_nm = io.open(os.path.join(_common.app_dir(), "netmon.py"), encoding="utf-8").read()
check("F-011 estats 失败可退避重试", "estats_retry_after" in _nm)
check("F-011 estats 成功即清零失败计数", "self.estats_fail_streak = 0" in _nm)
check("F-012 hosts 按 BOM/签名判编码", "raw[:2] in (b" in _wap
      and "raw[:3] == b" in _wap)
check("F-003 非有限时长明确拒绝", 'not math.isfinite(duration)' in _nm
      and '"bad": True' in _nm)
check("F-019 compare 对上标数字不抛异常",
      isinstance(_v.compare("2026.10.05\u00b2", "2026.10.05"), int))


# ================================================================
# 16. 2026-10-07：把「文本断言」换成「真执行断言」
#
# 起因：上面那条 F-003 只做**源码文本匹配**（源码里写着 math.isfinite 就算过）。
# 而真机上的 bug 恰恰是：netmon.py 用了 math.isfinite，却**没有 import math** ——
# set_duration() 一被调用就 NameError，接口回 500。
# 用户看到的现象是「观测时长滑块拖一下就报错」，功能整个废掉。
#
# 文本断言永远测不出「名字写对了、但根本跑不起来」这一类问题；
# 这正是本工具自己在第 16 条陷阱里写下的教训：
# **凡是能用行为验证的，就不要用文本匹配。**
# ================================================================

try:
    _nmo = netmon.NetMonitor()
    _r_ok = _nmo.set_duration(1800)
    _r_inf = _nmo.set_duration(float("inf"))
    _r_nan = _nmo.set_duration(float("nan"))
    check("时长：set_duration 真的能跑（不是只写着）",
          _r_ok.get("ok") is True and _r_ok.get("duration") == 1800.0,
          f"返回 {_r_ok}")
    check("时长：非有限值返回 bad 而不是抛异常",
          _r_inf.get("bad") is True and _r_nan.get("bad") is True)
except Exception as _e:      # noqa: BLE001
    check(f"时长：set_duration 真的能跑（异常 {type(_e).__name__}: {_e}）", False)

check("时长：档位上限已放宽到 30 分钟（1800 秒）",
      1800 in netmon.DURATION_STOPS and max(netmon.DURATION_STOPS) == 1800,
      f"当前档位 {netmon.DURATION_STOPS}")

# ---- 扫描节奏：热路径里不能出现贵字段 -------------------------------
# memory_info / num_threads 留在每轮快照里，会让单轮扫描从 ~0.14 秒涨到 ~3.3 秒
# （本机实测），而它们全项目只有详情抽屉用到。这条断言防止有人"顺手加回来"。
#
# ⚠️ 这里必须拿**模块对象**，不能拿源码文本 —— 本文件上方 `_col` 已被
#    赋成 collector.py 的源码字符串（文本断言用），拿它取属性会 AttributeError。
#    而条断言本身就是要"真执行"，所以老老实实 import 一次模块。
import importlib as _il          # noqa: E402
_colmod = _il.import_module("collector")
check("扫描：FAST_ATTRS 不含 memory_info / num_threads / status / cmdline",
      not ({"memory_info", "num_threads", "status", "cmdline"} & set(_colmod.FAST_ATTRS)),
      f"当前 {_colmod.FAST_ATTRS}")
check("扫描：详情路径 enrich_process 会现取内存与 CPU",
      "memory_info" in __import__("inspect").getsource(_colmod.enrich_process)
      and "cpu_percent" in __import__("inspect").getsource(_colmod.enrich_process))

# ---- 缓存：describe() 不能每次都在磁盘上做写探测 ---------------------
# 真实探测是「建文件→写→删」，本机实测 ~450 ms/次（被杀软实时扫描拦一道）。
# describe() 被 /api/state 每次轮询调用 —— 不缓存就等于界面每秒卡半秒。
try:
    import paths as _paths   # noqa: E402
    _t0 = time.perf_counter()
    _paths._writable(_paths.DATA_DIR)           # 一次真实探测
    _uncached = time.perf_counter() - _t0
    _paths.describe()                           # 先预热，否则第一次调用本身就是探测
    _t0 = time.perf_counter()
    for _ in range(20):
        _paths.describe()
    _cached = time.perf_counter() - _t0
    check("缓存：describe() 走缓存（20 次调用快于 1 次真实探测）",
          _cached < max(_uncached, 0.002),
          f"20 次 {_cached*1000:.2f} ms vs 单次探测 {_uncached*1000:.1f} ms")
except Exception as _e:      # noqa: BLE001
    check(f"缓存：describe() 走缓存（异常 {type(_e).__name__}: {_e}）", False)

# ---- 日志：附加字段不允许覆盖核心字段 -------------------------------
# 曾经写成 **kwargs，调用方传 kind=... 会与第一个形参撞名，
# 整条 auditlog.write 抛 TypeError 又被自身的 try 吞掉 ——
# 表现为「告警正常出现、日志里却什么都没有」，极难发现。
try:
    import auditlog as _alog   # noqa: E402
    # ⚠️ kind 用 "selftest" 而不是 "watch"：
    #    server._restore_alerts_from_log() 会把 watch / integrity / whitelist
    #    这三类日志**还原成告警时间线**。自检若写成 watch，
    #    用户下次启动就会看到一条凭空出现的假告警。
    _alog.write("selftest", "medium", "回归自检探针", "不应影响核心字段",
                extra={"kind": "changed", "file": "x"})
    _rec = next((r for r in reversed(_alog.tail(8))
                 if r.get("title") == "回归自检探针"), None)
    check("日志：附加字段不会覆盖 kind（撞名不再致命）",
          _rec is not None and _rec.get("kind") == "selftest"
          and _rec.get("file") == "x",
          f"写入结果 {_rec}")
except Exception as _e:      # noqa: BLE001
    check(f"日志：附加字段不会覆盖 kind（异常 {type(_e).__name__}: {_e}）", False)

# ---- 受监控文件：改动 / 新增 / 删除三种情况都要能检出 -----------------
try:
    import shutil as _sh
    import watch as _watch   # noqa: E402
    _tmp = os.path.join(tempfile.gettempdir(), "yh_regress_watch")
    _sh.rmtree(_tmp, ignore_errors=True)
    os.makedirs(_tmp, exist_ok=True)
    for _fn, _txt in (("a.txt", "one"), ("b.txt", "two")):
        with open(os.path.join(_tmp, _fn), "w", encoding="utf-8") as _f:
            _f.write(_txt)
    # 先存盘自检前的配置与基线，测完还原 ——
    # 测试脚本不得改动被测对象的真实配置（第 25 条陷阱踩过）
    _saved_cfg = _watch.load()
    _saved_base = _watch.load_baseline()
    _ok, _msg, _tg = _watch.add(_tmp, recursive=True, label="回归自检")
    _watch.rebuild()
    check("受监控文件：刚建完基线时零差异",
          _watch.verify(force_full=True)["stats"]["total"] == 0)
    with open(os.path.join(_tmp, "a.txt"), "w", encoding="utf-8") as _f:
        _f.write("one-changed")
    with open(os.path.join(_tmp, "c.txt"), "w", encoding="utf-8") as _f:
        _f.write("three")
    os.remove(os.path.join(_tmp, "b.txt"))
    _res = _watch.verify(force_full=True)
    _kinds = sorted(f["kind"] for f in _res["findings"])
    check("受监控文件：改 / 增 / 删 三种都能检出",
          _kinds == ["added", "changed", "removed"], f"检出 {_kinds}")
    if _tg:
        _watch.remove(_tg["id"])
    _watch.save(_saved_cfg)
    _watch.save_baseline(_saved_base)
    _sh.rmtree(_tmp, ignore_errors=True)
except Exception as _e:      # noqa: BLE001
    check(f"受监控文件：改 / 增 / 删 三种都能检出（异常 {type(_e).__name__}: {_e}）",
          False)


print()
print("=" * 72)
print("F-020 评分链路健壮性 —— 一条畸形 finding 不得让整张进程表失明")
print("=" * 72)

# 背景（2026-10-08 实测缺陷）：
#   _store_mod_scan 存回深度扫描结论时白名单式挑字段，**漏掉了 weight**。
#   这些残缺 finding 被 _score_all 并回进程后交给 score_findings()，
#   后者读 f["weight"] 抛 KeyError；异常从 _score_all 的 for 循环中逃逸，
#   于是该进程之后的**所有进程都没有 score/level**。
#   实测后果：276 个进程里 156 个缺字段，界面风险列渲染出 undefined、
#   标签页计数恒为 0，服务端每 1 秒打印一次 traceback。
# 本组用例把三层防线（score_findings 容错 / _store_mod_scan 保字段 /
# _score_all 逐进程隔离）全部固化，防止再次回归。

# 1. score_findings 对畸形 finding 必须不抛异常
try:
    _s1, _l1 = rules.score_findings([{"rule_id": "X999", "title": "残缺", "severity": "high"}])
    check("F-020 score_findings 对缺 weight 的 finding 不抛异常", True, f"→ ({_s1}, {_l1})")
except Exception as _e:      # noqa: BLE001
    check(f"F-020 score_findings 对缺 weight 的 finding 不抛异常（{type(_e).__name__}: {_e}）",
          False)

try:
    _s2, _l2 = rules.score_findings([{"weight": "heavy"}, {"weight": None}])
    check("F-020 score_findings 对非数值 weight 不抛异常", True, f"→ ({_s2}, {_l2})")
except Exception as _e:      # noqa: BLE001
    check(f"F-020 score_findings 对非数值 weight 不抛异常（{type(_e).__name__}: {_e}）",
          False)

# 2. 容错不能改坏正常评分：权重模型必须原样保持
_w95 = rules.finding("P001", "伪装系统进程", "critical", 95, "process", "ev")
_w30 = rules.finding("P007", "随机名程序", "medium", 30, "process", "ev")
_w60 = rules.finding("P005", "未签名外联", "high", 60, "process", "ev")
check("F-020 单条正常 finding 的评分不变",
      rules.score_findings([_w95]) == (95.0, "critical"),
      f"→ {rules.score_findings([_w95])}")
# 用不会触及 100 分封顶的组合，才能验证"最高权重 + 0.35×其余"这个模型本身
check("F-020 多条 finding 的加权模型不变（最高 + 0.35×其余）",
      rules.score_findings([_w60, _w30]) == (60.0 + 0.35 * 30, "high"),
      f"→ {rules.score_findings([_w60, _w30])}")
check("F-020 总分仍封顶 100",
      rules.score_findings([_w95, _w30])[0] == 100.0,
      f"→ {rules.score_findings([_w95, _w30])}")

# 3. 行为测试：真实 Monitor 上跑一遍"深扫结论并回评分"的完整链路
try:
    import traceback as _tb
    import server as _srv   # noqa: E402

    _m = _srv.Monitor(net_enabled=False)
    _p1 = mk("a.exe", r"C:\Windows\a.exe")
    _p2 = mk("b.exe", r"C:\Windows\b.exe")     # 这条会被写入深度扫描结论
    _p3 = mk("c.exe", r"C:\Windows\c.exe")
    _p1["pid"], _p2["pid"], _p3["pid"] = 1, 2, 3   # mk() 默认 pid 都是 4242，必须区分开
    _m.procs = [_p1, _p2, _p3]

    _m._store_mod_scan((_p2["pid"], _p2["create_time"]),
                       [rules.finding("X003", "白加黑侧加载", "critical", 90, "process", "ev")])
    _stored = _m.mod_scan[(_p2["pid"], _p2["create_time"])]["findings"][0]
    check("F-020 _store_mod_scan 保留 weight 字段", "weight" in _stored,
          f"键={sorted(_stored)}")
    check("F-020 _store_mod_scan 保留 category 字段", "category" in _stored)

    _m._score_all()
    _missing = [p["pid"] for p in _m.procs if "score" not in p or "level" not in p]
    check("F-020 _score_all 后每个进程都带 score/level", not _missing, f"缺 {_missing}")
    _b = [p for p in _m.procs if p["pid"] == _p2["pid"]][0]
    check("F-020 深度扫描结论被并回进程评分", _b["level"] == "critical",
          f"→ {_b['level']} / {_b['score']}")
    _c = [p for p in _m.procs if p["pid"] == 3][0]
    check("F-020 出问题的进程之后，其余进程仍被评分",
          "score" in _c and "level" in _c, f"→ {_c.get('level')} / {_c.get('score')}")

    # 4. 报告导出：state 里混入缺 score 的进程，也不得抛 KeyError / 印出 undefined
    #    用真实 state 做底（保证 summary 等字段齐全），再塞进一条"缺 score"的进程。
    _bad = mk("d.exe", r"C:\Windows\d.exe")
    _bad["pid"] = 9
    _bad["level"] = "high"          # 等级有、分数没有 —— 正是本次缺陷的形态
    _bad.pop("score", None)
    _st = _m.state()
    _st["processes"] = [_bad, _p2]
    try:
        _html = _srv.build_report_html(_st)
        check("F-020 报告导出对缺 score 的进程不抛异常",
              "undefined" not in _html, f"报告 {len(_html)} 字符")
    except Exception as _e:      # noqa: BLE001
        _tb.print_exc()
        check(f"F-020 报告导出对缺 score 的进程不抛异常（{type(_e).__name__}: {_e}）",
              False)
except Exception as _e:      # noqa: BLE001
    check(f"F-020 评分链路行为测试（{type(_e).__name__}: {_e}）", False)


print()
print("=" * 72)
print("F-021 白加黑 X003 —— 「尚未校验」不得被当作「可疑」")
print("=" * 72)

# 背景（2026-10-08 实测缺陷，本组用例把它固化）：
#   verify_signatures 实测约 297 ms/文件；首次运行签名队列积压 647 个文件
#   （≈3 分钟排空），而 _deep_scan_cycle 的"重试 4 次"只等于约 4 秒。
#   计时器先到期 → treat_unknown_as_bad=True → 把 48 个**已正确签名**的同目录 DLL
#   （Edge / 微信 / <workspace> / 网易 UU / Intel DSA）全部定罪成白加黑(critical 82)，
#   并连带触发 N005 把它们的正常流量再报一遍 —— 界面上"一片爆红"。
#   修复：未校验只排队；由签名线程在结果到达后放行复查（_deep_pending）。

_edge_dir = r"C:\Program Files (x86)\Microsoft\Edge\Application"
_edge_dll = _edge_dir + r"\154.0.4258.62\prefs_enclave_x64.dll"
_edge = mk("msedge.exe", _edge_dir + r"\msedge.exe")
_fake_detail = {"modules": [{"path": _edge_dll}]}
_ctx_x = {"by_pid": {}, "sig_cache": {}, "artifacts": {}, "self_pid": 0, "own_children": {}}

try:
    import collector as _col   # noqa: E402
    _orig_enrich = _col.enrich_process
    _col.enrich_process = lambda _pid: _fake_detail      # 注入伪造的模块清单
    try:
        # ① 尚未校验 → 只能进 pending，绝不能定罪
        _fs1, _pend1 = rules.deep_scan_process(_edge, _ctx_x)
        check("F-021 模块未校验时不产生 X003",
              not any(f["rule_id"] == "X003" for f in _fs1),
              f"命中 {[f['rule_id'] for f in _fs1] or '无'}")
        check("F-021 模块未校验时进入待校验队列", len(_pend1) == 1,
              f"pending={_pend1}")

        # ② 校验结果为「有效」→ 仍然不产生 X003（这正是 5 个正规软件被误判的场景）
        _ctx_ok = dict(_ctx_x, sig_cache={_edge_dll.lower(): {"kind": "ok", "status_zh": "有效"}})
        _fs2, _pend2 = rules.deep_scan_process(_edge, _ctx_ok)
        check("F-021 模块校验为「有效」时不产生 X003",
              not any(f["rule_id"] == "X003" for f in _fs2),
              f"命中 {[f['rule_id'] for f in _fs2] or '无'}")
        check("F-021 校验完成后不再重复排队", _pend2 == [], f"pending={_pend2}")

        # ③ 校验结果确实不可信 → 这时才必须定罪（不能为了防误报把检出砍掉）
        _ctx_bad = dict(_ctx_x, sig_cache={_edge_dll.lower(): {"kind": "unsigned", "status_zh": "未签名"}})
        _fs3, _ = rules.deep_scan_process(_edge, _ctx_bad)
        check("F-021 模块校验为「未签名」时必须产生 X003",
              any(f["rule_id"] == "X003" for f in _fs3),
              f"命中 {[f['rule_id'] for f in _fs3] or '无'}")

        # ④ 严重度标定：普通「同目录未签名 DLL」只判中危。
        #    实测依据：D:\Steam 24 个 DLL 有 23 个由 Valve/Nvidia/Microsoft 签名，
        #    仅 libpyrowave-shared-0.dll 未签名；按旧的 high(82) 标定，steam.exe
        #    一运行就被判 critical，再经 N005 把正常联机流量报成 9 条"疑似 C2 心跳"。
        _x3 = next((f for f in _fs3 if f["rule_id"] == "X003"), None)
        check("F-021 普通未签名同目录 DLL 只判中危（不再 high）",
              _x3 is not None and _x3["severity"] == "medium" and _x3["weight"] == 45,
              f"{_x3['severity']}/{_x3['weight']}" if _x3 else "未命中")

        # ⑤ 反向验证：命中侧加载提示名单（经典劫持名）仍必须 critical ——
        #    降级不能把真正的高精度信号一起砍掉。
        _hint_dll = _edge_dir + r"\wjcapture.dll"
        _col.enrich_process = lambda _pid: {"modules": [{"path": _hint_dll}]}
        _ctx_hint = dict(_ctx_x, sig_cache={_hint_dll.lower(): {"kind": "unsigned", "status_zh": "未签名"}})
        _fs4, _ = rules.deep_scan_process(_edge, _ctx_hint)
        _x3h = next((f for f in _fs4 if f["rule_id"] == "X003"), None)
        check("F-021 命中侧加载提示名单时仍判 critical(92)",
              _x3h is not None and _x3h["severity"] == "critical" and _x3h["weight"] == 92,
              f"{_x3h['severity']}/{_x3h['weight']}" if _x3h else "未命中")
    finally:
        _col.enrich_process = _orig_enrich
except Exception as _e:      # noqa: BLE001
    check(f"F-021 白加黑行为测试（{type(_e).__name__}: {_e}）", False)

# ⑥ 网络侧与进程侧的弱信号门槛必须一致：netmon 只在 X003 判 critical 时才升级。
#    这条断言的价值在于——它正是发现"进程侧判 high 而网络侧当弱信号"这一
#    自相矛盾的依据；两边任何一侧被改动都会在这里暴露。
_src_net = open(os.path.join(_common.app_dir(), "netmon.py"), encoding="utf-8").read()
check("F-021 网络侧弱信号门槛与进程侧标定一致（mod_strong 只在 critical 时升级）",
      'mod_sideload and mod_level == "critical"' in _src_net)

# ④ 结构层面：必须有"签名结果到达后放行复查"的机制，否则又会退化成靠计时器猜
check("F-021 存在「待校验复查」登记表（_deep_pending）", "_deep_pending" in src_srv)
check("F-021 签名线程会放行待复查进程",
      "self.deep_done.discard(_k)" in src_srv)
check("F-021 复查轮即使结论为空也会写回 mod_scan（否则误报会永久粘住）",
      "or self._deep_retry.get(key, 0) > 0" in src_srv)

# ⑤ 自身进程不得被自己评分（2026-10-08 实测：监视器把自己的 pythonw.exe
#    判成 P006「未签名程序运行于用户目录」，纯噪音且损害结果可信度）
_self_proc = mk("pythonw.exe",
                r"C:\Users\<用户名>\AppData\Local\Programs\<workspace>AI\resources\vendor\python\pythonw.exe",
                sig_kind="unsigned")
_self_proc["pid"] = 7777
_ctx_self = {"by_pid": {}, "sig_cache": {}, "artifacts": {}, "self_pid": 7777, "own_children": {}}
_ctx_other = dict(_ctx_self, self_pid=0)
check("F-021 监视器不给自己打分（self_pid 被排除）",
      rules.rules_process(_self_proc, _ctx_self) == [],
      f"命中 {[f['rule_id'] for f in rules.rules_process(_self_proc, _ctx_self)]}")
check("F-021 但同一个进程在 self_pid=0 时仍会被正常检出（排除范围没有放大）",
      any(f["rule_id"] == "P006" for f in rules.rules_process(_self_proc, _ctx_other)),
      f"命中 {[f['rule_id'] for f in rules.rules_process(_self_proc, _ctx_other)]}")


# ============================================================================
print()
print("=" * 72)
print("F-022 完整性假告警 + 「已恢复」标注 —— 历史条目不得冒充当前问题")
print("=" * 72)
import integrity as _it22   # noqa: E402
import server as _srv22     # noqa: E402
import tempfile as _tf22    # noqa: E402
import json as _json22      # noqa: E402

# ⚠️ 从模块自身推导 app 目录 —— 不要写 HERE/app，
#    否则仓库副本（自检在 tools/ 下）会找错路径。
_app22 = os.path.dirname(os.path.abspath(_it22.__file__))
_s22 = io.open(os.path.join(_app22, "server.py"), encoding="utf-8").read()
_j22 = io.open(os.path.join(_app22, "web", "app.js"), encoding="utf-8").read()

# ---- 源码层
check("F-022 integrity 有键名格式判定函数",
      "def _baseline_keys_compatible" in _itg)
check("F-022 load_baseline 的回退候选要过格式校验",
      "not is_primary and not _baseline_keys_compatible" in _itg)
check("F-022 历史条目带来源类别 log_kind",
      '\"log_kind\": r.get(\"kind\")' in _s22)
check("F-022 输出走 _alerts_for_ui（历史条目可标已恢复）",
      "self._alerts_for_ui()[:100]" in _s22)
check("F-022 「发现的问题」徽章排除已恢复条目", "!a.resolved" in _j22)
check("F-022 已恢复标签两套语言都有", _j22.count("alert_resolved:") == 2)

# ---- 行为层：键名格式判定（自包含，不依赖机器上是否存在某些文件）
_legacy22 = {"rules.py": "a", "python_path.txt": "b", "whitelist.json": "c",
             "停止监视器.bat": "d"}
_cur22 = {"rules.py": "a", "<root>/python_path.txt": "b",
          "<root>/whitelist.json": "c", "<root>/停止监视器.bat": "d",
          "web/app.js": "e"}
check("F-022 旧格式基线判为不兼容",
      _it22._baseline_keys_compatible(_legacy22) is False)
check("F-022 新格式基线判为兼容",
      _it22._baseline_keys_compatible(_cur22) is True)
check("F-022 空基线不误伤", _it22._baseline_keys_compatible({}) is True)

# ---- 行为层：旧格式回退必须被拒绝，且不得报成 changed
_td22 = _tf22.mkdtemp(prefix="sfx_f022_")
_fa22 = os.path.join(_td22, "app")
os.makedirs(_fa22, exist_ok=True)
with io.open(os.path.join(_td22, "integrity.baseline.json"), "w",
             encoding="utf-8") as f:
    _json22.dump({"app_dir": _fa22, "created": "2026-10-06 09:59:05",
                  "files": _legacy22}, f, ensure_ascii=False)
check("F-022 只有旧格式基线时 load_baseline 返回 None",
      _it22.load_baseline(_td22, _fa22) is None)

_curman22 = _it22.collect_manifest(_app22, _it22.default_extras())
_incompat22 = {}
for _k, _v in _curman22.items():
    _incompat22[_k[7:] if _k.startswith("<root>/") else _k] = "0" * 8
with io.open(os.path.join(_td22, "integrity.baseline.json"), "w",
             encoding="utf-8") as f:
    _json22.dump({"app_dir": _app22, "created": "2026-10-06 09:59:05",
                  "files": _incompat22}, f, ensure_ascii=False)
_it22.save_sentinel(_td22, _curman22, _app22)
_r22 = _it22.verify(_app22, _td22, _it22.default_extras())
check("F-022 旧格式基线不得报成 changed（假告警）",
      _r22.get("status") != "changed", f"status={_r22.get('status')}")
check("F-022 且 added/removed 为空（不再'每个文件既新增又缺失'）",
      not _r22.get("added") and not _r22.get("removed"),
      f"added={len(_r22.get('added') or [])} removed={len(_r22.get('removed') or [])}")


class _LK22:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


_m22 = _srv22.Monitor.__new__(_srv22.Monitor)   # 不走 __init__，只测这个方法
_m22.lock = _LK22()
_m22.alerts = [
    {"level": "critical", "from_log": True, "log_kind": "integrity",
     "name": "程序文件完整性异常"},
    {"level": "critical", "name": "当前发现的问题"},
    {"level": "medium", "from_log": True, "log_kind": "watch",
     "name": "受监控文件被改动"},
]
_m22.integrity = {"status": "ok"}
_o22 = _m22._alerts_for_ui()
check("F-022 当前完整性 ok → 历史 integrity 条目标为已恢复",
      _o22[0].get("resolved") is True)
check("F-022 非历史条目不受影响", "resolved" not in _o22[1])
check("F-022 历史 watch 条目不受影响（由 check_watch 独立重检）",
      "resolved" not in _o22[2])
check("F-022 不就地改写内部列表（不污染内部状态）",
      "resolved" not in _m22.alerts[0])
_m22.integrity = {"status": "changed"}
check("F-022 当前完整性 changed → **不**标已恢复（不掩盖仍然存在的问题）",
      "resolved" not in _m22._alerts_for_ui()[0])


print()
print("=" * 72)
print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
for f in FAIL:
    print("  ✗ " + f)
print("=" * 72)
sys.exit(1 if FAIL else 0)
