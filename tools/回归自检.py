# -*- coding: utf-8 -*-
"""
规则回归自检 —— 防止「修一个漏洞、引入一个误报」这类回归

这些断言全部来自实际踩过的坑。安全工具最大的风险不是"查不出"，
而是"乱报"：一次误报就足以让用户不再相信任何告警。

无需运行监视器，直接对规则函数喂合成样本，秒级跑完。


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

# 本脚本不写死任何绝对路径：从自身位置推导出仓库根目录下的 app/
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

print()
print("=" * 72)
print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
for f in FAIL:
    print("  ✗ " + f)
print("=" * 72)
sys.exit(1 if FAIL else 0)
