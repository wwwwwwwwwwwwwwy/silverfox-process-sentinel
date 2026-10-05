# -*- coding: utf-8 -*-
"""
Windows 平台底层能力封装
--------------------------------------------------
· 管理员权限判定
· PowerShell 安全调用（-EncodedCommand，彻底规避中文/引号编码问题）
· Authenticode 数字签名批量校验（含"签名有效但摘要不符"= 伪造签名判定）
· 计划任务 / 系统服务 / 内核驱动 / 启动项 / hosts / Defender 排除项 采集
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import subprocess
import tempfile
import threading
import time
from typing import Any

import psutil

# ---------------------------------------------------------------- 基础

CREATE_NO_WINDOW = 0x08000000


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _resolve_pwsh_from_store() -> str:
    """从注册表取 PowerShell 7（MSIX/Store 包）的**真实**安装路径。

    为什么不直接用 `%LOCALAPPDATA%\\Microsoft\\WindowsApps\\pwsh.exe`：
    那是「应用执行别名」（AppExecLink 重解析点）。经它启动时，Windows 的激活
    过程可能插入一个中转进程（broker/stub），于是：
      · `subprocess.Popen` 拿到的 PID 可能是那个中转进程，真正的 pwsh 是它的子进程；
      · 子进程的父进程也不是我们。
    两者都会让"排除自身子进程"失效 —— 本工具会把自己的签名校验进程
    判成 P010B + P011（高危），告警时间线里凭空多一条（实测发生过）。
    直接启动真实 exe 就没有这个问题，顺带省掉一次 MSIX 激活开销。
    """
    try:
        import winreg
        base = (r"Software\Classes\Local Settings\Software\Microsoft"
                r"\Windows\CurrentVersion\AppModel\Repository\Packages")
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base) as k:
            n = winreg.QueryInfoKey(k)[0]
            best = ""
            for i in range(n):
                try:
                    name = winreg.EnumKey(k, i)
                except OSError:
                    continue
                if not name.lower().startswith("microsoft.powershell_"):
                    continue
                try:
                    with winreg.OpenKey(k, name) as sk:
                        root, _ = winreg.QueryValueEx(sk, "PackageRootFolder")
                except OSError:
                    continue
                exe = os.path.join(str(root), "pwsh.exe")
                if os.path.isfile(exe):
                    best = max(best, exe)      # 装了多个版本时取字典序最大的
            return best
    except Exception:
        return ""


def _find_powershell() -> str:
    """优先 pwsh（PowerShell 7），回退 powershell.exe（5.1，系统必备）。

    ⚠️ 三点必须遵守（都是实测踩出来的）：
      1. 返回**绝对路径**，不要返回裸名字 —— 裸名字要走 PATH 解析，
         而 PATH 可能被第三方 shim 目录改写（实测本机 PATH 首项是无效的 `D;`）。
      2. **真实安装路径优先于「应用执行别名」** —— 原因见 _resolve_pwsh_from_store。
      3. 别名只作次选，系统自带 powershell.exe 兜底。
    """
    cands = [
        os.path.expandvars(r"%ProgramFiles%\PowerShell\7\pwsh.exe"),
        _resolve_pwsh_from_store(),
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe"),
        os.path.expandvars(r"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"),
    ]
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return "powershell.exe"          # 最后兜底，交给系统解析


PS_EXE = _find_powershell()

# ---------------------------------------------------------------- 自身辅助进程登记
# 为什么需要按 PID 单独登记，而不是只靠"父进程 == 自己"：
#   实测有两种情况会让子进程的 ppid **不等于**本进程 ——
#     ① venv 的 pythonw.exe 是启动器，会再派生一个真解释器，os.getpid() 是后者；
#     ② 经 WindowsApps 的 pwsh.exe「应用执行别名」启动时，激活可能经过 broker。
#   两者都会让 rules.is_own_aux_process 的父进程判据失效，于是**本工具自己的
#   签名校验进程**被判成 P010B（Base64 执行）+ P011（绕过策略）→ 告警时间线里
#   凭空出现一条"高危"（实测发生过）。
#
# 按 (pid, create_time) 精确排除的好处：
#   · 不受父进程关系影响（broker / 启动器都不怕）；
#   · **不给攻击者留伪造空间** —— 父进程链是可以伪造的，PID + 创建时间不能；
#     所以这里绝不能改成"命令行里含本工具 preamble 就放过"那种宽松判据。
_OWN_CHILDREN: dict[int, tuple[float, float]] = {}   # pid -> (create_time, 登记时刻)
_OWN_CHILDREN_LOCK = threading.Lock()
_OWN_CHILDREN_KEEP = 900.0        # 保留 15 分钟（覆盖"进程已退出、快照还没评分"的窗口）
_OWN_CHILDREN_MAX = 500


def _own_child_register(pid: int) -> None:
    ct = 0.0
    try:
        ct = psutil.Process(pid).create_time()
    except Exception:
        pass
    with _OWN_CHILDREN_LOCK:
        _OWN_CHILDREN[pid] = (ct, time.time())
        if len(_OWN_CHILDREN) > _OWN_CHILDREN_MAX:
            for k in list(_OWN_CHILDREN)[:len(_OWN_CHILDREN) - _OWN_CHILDREN_MAX]:
                _OWN_CHILDREN.pop(k, None)


def own_child_create_times() -> dict[int, float]:
    """返回 {pid: create_time}，供规则引擎排除本工具自己拉起的辅助进程。"""
    now = time.time()
    with _OWN_CHILDREN_LOCK:
        for pid in list(_OWN_CHILDREN):
            if now - _OWN_CHILDREN[pid][1] > _OWN_CHILDREN_KEEP:
                del _OWN_CHILDREN[pid]
        return {pid: ct for pid, (ct, _) in _OWN_CHILDREN.items()}


_PS_PREAMBLE = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$ProgressPreference='SilentlyContinue';"
    "try{[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)}catch{};"
)

# ---------------------------------------------------------------- 子进程随父退出
# 为什么需要 Job Object：
#   监视器被**强制结束**（任务管理器结束任务、父进程被杀）时，正在跑的校验子进程
#   不会被回收，会变成**孤儿**继续挂着。它的命令行里带着本工具的 preamble，
#   而父进程已经不是监视器了 —— 于是下一次扫描（可能是新起的实例）会把它判成
#   P010B + P011 = 高危，告警时间线里凭空多一条假告警。**实测发生过**：
#   本机曾残留一个孤儿 pwsh.exe（命令行含本工具 preamble、父进程已死）。
#   把子进程放进带 KILL_ON_JOB_CLOSE 的 Job 对象，父进程一消失由内核连带清掉，
#   从根上消灭这一类残留。
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_HANDLE = None
_JOB_LOCK = threading.Lock()


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong)]


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", ctypes.c_uint32),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32)]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", _IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t)]


def _own_job():
    """惰性创建「父进程退出即杀掉全部子进程」的 Job 对象。失败返回 0（静默降级）。"""
    global _JOB_HANDLE
    with _JOB_LOCK:
        if _JOB_HANDLE is not None:
            return _JOB_HANDLE
        _JOB_HANDLE = 0
        try:
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.CreateJobObjectW.restype = ctypes.c_void_p
            k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
            h = k32.CreateJobObjectW(None, None)
            if h:
                info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
                info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                k32.SetInformationJobObject.restype = ctypes.c_int
                k32.SetInformationJobObject.argtypes = [
                    ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
                if k32.SetInformationJobObject(
                        h, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                        ctypes.byref(info), ctypes.sizeof(info)):
                    _JOB_HANDLE = h
        except Exception:
            _JOB_HANDLE = 0
        return _JOB_HANDLE


def _assign_to_own_job(pid: int) -> None:
    """把刚拉起的子进程放进 Job。失败无所谓（只是失去"随父退出"的保障）。"""
    h = _own_job()
    if not h:
        return
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        k32.AssignProcessToJobObject.restype = ctypes.c_int
        k32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        # PROCESS_TERMINATE(0x0001) | PROCESS_SET_QUOTA(0x0100)
        hp = k32.OpenProcess(0x0001 | 0x0100, False, pid)
        if hp:
            k32.AssignProcessToJobObject(h, hp)
            k32.CloseHandle(hp)
    except Exception:
        pass


def run_ps(script: str, timeout: int = 60, extra_env: dict | None = None) -> str:
    """执行 PowerShell 片段，返回 UTF-8 文本。脚本以 UTF-16LE base64 传入，
    不含任何引号/中文编码风险。extra_env 用于把文件路径等数据经环境变量传入，
    彻底避免任何路径拼接注入（加固：即使 %TEMP% 路径含单引号/反引号/$ 也安全）。

    用 Popen 而不是 run：需要在进程启动的瞬间就
      ① 把 PID 登记进 _OWN_CHILDREN（供规则引擎精确排除）；
      ② 把它放进 Job 对象（保证监视器被强制结束时它一起被回收，不留孤儿）。
    """
    full = _PS_PREAMBLE + script
    encoded = base64.b64encode(full.encode("utf-16-le")).decode("ascii")
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    try:
        p = subprocess.Popen(
            [PS_EXE, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-EncodedCommand", encoded],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW, env=env,
        )
    except Exception:
        return ""
    _own_child_register(p.pid)
    _assign_to_own_job(p.pid)
    try:
        out, _err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            p.kill()
            out, _err = p.communicate(timeout=5)
        except Exception:
            out = b""
    except Exception:
        out = b""
    raw = out or b""
    for enc in ("utf-8", "utf-8-sig", "gbk"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def run_ps_json(script: str, timeout: int = 90, extra_env: dict | None = None) -> Any:
    """执行 PowerShell 并解析 JSON 结果；失败返回 None。"""
    out = run_ps(script, timeout=timeout, extra_env=extra_env).strip()
    if not out:
        return None
    # 容忍 PS 输出前的杂项行
    start = out.find("[")
    start2 = out.find("{")
    if start == -1 or (start2 != -1 and start2 < start):
        start = start2
    if start > 0:
        out = out[start:]
    try:
        return json.loads(out)
    except Exception:
        return None


# ---------------------------------------------------------------- 数字签名

# Get-AuthenticodeSignature 的 Status 取值 → 中文说明 + 风险语义
SIG_STATUS_MAP = {
    "Valid": ("有效", "ok"),
    "NotSigned": ("未签名", "unsigned"),
    "HashMismatch": ("摘要校验失败（签名被篡改/伪造）", "forged"),
    "NotTrusted": ("不受信任的根证书", "untrusted"),
    "UnknownError": ("校验异常", "unknown"),
    "NotSupported": ("不支持的文件格式", "unknown"),
    "Incompatible": ("签名格式不兼容", "unknown"),
    "InvalidSignature": ("签名无效", "forged"),
}


def _safe_paths(paths: list[str]) -> list[str]:
    """剔除含控制字符的路径。

    ⚠️ 安全：待校验的文件路径来自**进程枚举**，也就是攻击者可控的输入。
    Windows 文件名在 NTFS 原生接口下可以包含换行等控制字符；
    若把这种路径拼进 PowerShell 脚本文本，就能注入额外语句 ——
    而本工具的 PowerShell 是以当前用户（通常是管理员）身份运行的。
    这里连同下面的"路径走临时文件、不拼进脚本"一起做双重防护。
    """
    out = []
    for p in paths:
        if not p:
            continue
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in p):
            continue
        out.append(p)
    return out


def verify_signatures(paths: list[str], timeout: int = 180) -> dict[str, dict]:
    """批量校验 Authenticode 签名。返回 {小写路径: {status, signer, notafter, cn}}

    实现要点：路径**通过临时文件传给 PowerShell**，不做字符串拼接。
    初版是把路径直接拼进 `$paths=@('...','...')`，虽然转义了单引号，
    但换行等控制字符仍可注入语句 —— 已修正（见 _safe_paths 的说明）。
    """
    paths = _safe_paths([p for p in dict.fromkeys(paths) if p and os.path.isfile(p)])
    result: dict[str, dict] = {}
    if not paths:
        return result

    BATCH = 60
    for i in range(0, len(paths), BATCH):
        chunk = paths[i:i + BATCH]
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(suffix=".txt", prefix="yinhu-paths-")
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                f.write("\n".join(chunk))
            # 加固：临时文件路径经环境变量传给 PowerShell，脚本文本里
            # 不再出现任何路径字符串 —— 路径里即使有引号/反引号/$ 也无法注入。
            script = (
                "$paths=@(Get-Content -LiteralPath $env:YINHU_PATHFILE -Encoding UTF8 | "
                "Where-Object { $_ -ne '' });"
                "$out=foreach($p in $paths){"
                "  if(-not (Test-Path -LiteralPath $p)){continue};"
                "  $s=Get-AuthenticodeSignature -LiteralPath $p;"
                "  $signer='';$notafter='';$cn='';"
                "  if($s.SignerCertificate){"
                "    $signer=[string]$s.SignerCertificate.Subject;"
                "    $notafter=$s.SignerCertificate.NotAfter.ToString('yyyy-MM-dd');"
                "    $m=[regex]::Match($signer,'CN=([^,]+)'); if($m.Success){$cn=$m.Groups[1].Value}"
                "  };"
                "  [pscustomobject]@{path=$p;status=[string]$s.Status;signer=$signer;"
                "notafter=$notafter;cn=$cn}"
                "};"
                "ConvertTo-Json -InputObject @($out) -Compress -Depth 4"
            )
            data = run_ps_json(script, timeout=timeout, extra_env={"YINHU_PATHFILE": tmp})
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except Exception:
                    pass
        if not data:
            continue
        if isinstance(data, dict):
            data = [data]
        for item in data:
            if not isinstance(item, dict):
                continue
            p = str(item.get("path", ""))
            if not p:
                continue
            status = str(item.get("status", "UnknownError"))
            zh, kind = SIG_STATUS_MAP.get(status, (status, "unknown"))
            # MSIX / Store 应用（\WindowsApps\）的二进制由包签名整体保护，
            # 不做单独的 Authenticode 签名 —— 对它们套用"未签名"门控会造成
            # 系统性误报（实测：pwsh.exe 白加黑误报、MicrosoftStartFeedProvider.exe
            # 未签名外联误报）。这里统一标为 packaged，使所有签名门控规则自动跳过。
            # 该目录受 ACL 保护（属主 TrustedInstaller），木马无法写入，故无检测盲区。
            if kind == "unsigned" and "\\windowsapps\\" in p.replace("/", "\\").lower():
                kind, zh = "packaged", "MSIX 包签名（不单独签名）"
            result[p.lower()] = {
                "status": status,
                "status_zh": zh,
                "kind": kind,
                "signer": str(item.get("signer", "") or ""),
                "cn": str(item.get("cn", "") or ""),
                "notafter": str(item.get("notafter", "") or ""),
            }
    return result


# ---------------------------------------------------------------- 计划任务


def collect_system_snapshot(timeout: int = 240) -> dict:
    """一次进程启动取回全部系统制品。

    ⚠️ 性能：初版由 5 个独立函数各起一次进程（计划任务 / 驱动 / 启动项 /
    Defender 排除项 / 可疑注册表键），按 45 秒的制品扫描间隔计算，
    每小时要启动 400 次外部进程 —— 实测这占掉了监视器绝大部分 CPU
    与磁盘读（稳态单核 13.9%、磁盘读 323 MB/小时）。
    合并成一次调用后，进程启动次数降到 1/5，单轮耗时从约 5.6 s 降到约 1.5 s。

    每个小节都单独 try/catch：某一节失败不影响其余小节（保持原函数的降级行为）。
    """
    script = r"""
$out = [ordered]@{
  tasks          = @()
  drivers        = @()
  run_keys       = @()
  defender       = $null
  suspicious_reg = @()
}

# ---- 计划任务 ----
try {
  $tasks = Get-ScheduledTask | ForEach-Object {
    $t = $_
    $act = @($t.Actions | ForEach-Object {
      [pscustomobject]@{ exec=[string]$_.Execute; args=[string]$_.Arguments;
                         wd=[string]$_.WorkingDirectory } })
    $trg = @($t.Triggers | ForEach-Object {
      $rep = $_.Repetition
      [pscustomobject]@{ type=[string]$_.CimClass.CimClassName;
                         interval=[string]$rep.Interval; duration=[string]$rep.Duration;
                         enabled=[bool]$_.Enabled } })
    [pscustomobject]@{
      name=[string]$t.TaskName; path=[string]$t.TaskPath; state=[string]$t.State
      hidden=[bool]$t.Settings.Hidden; runlevel=[string]$t.Principal.RunLevel
      userid=[string]$t.Principal.UserId; author=[string]$t.Author
      actions=$act; triggers=$trg }
  }
  $out.tasks = @($tasks)
} catch { $out.tasks = @() }

# ---- 内核驱动 ----
try {
  $d = Get-CimInstance -ClassName Win32_SystemDriver | ForEach-Object {
    [pscustomobject]@{ name=[string]$_.Name; display=[string]$_.DisplayName;
                       path=[string]$_.PathName; state=[string]$_.State;
                       start=[string]$_.StartMode } }
  $out.drivers = @($d)
} catch { $out.drivers = @() }

# ---- 注册表启动项 ----
try {
  $keys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
  )
  $rk = foreach ($k in $keys) {
    $item = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
    if (-not $item) { continue }
    $item.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
      [pscustomobject]@{ key=$k; name=$_.Name; value=[string]$_.Value } }
  }
  $out.run_keys = @($rk)
} catch { $out.run_keys = @() }

# ---- Defender 排除项 ----
$def = [ordered]@{ accessible=$false; paths=@(); processes=@(); extensions=@() }
try {
  $p = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths' -ErrorAction Stop
  if ($p) {
    $def.paths = @($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $_.Name })
    $def.accessible = $true
  }
} catch {}
try {
  $q = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes' -ErrorAction Stop
  if ($q) { $def.processes = @($q.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $_.Name }) }
} catch {}
try {
  $r = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions' -ErrorAction Stop
  if ($r) { $def.extensions = @($r.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $_.Name }) }
} catch {}
$out.defender = $def

# ---- 银狐专用注册表键 ----
try {
  $hits = @()
  foreach ($k in @('HKLM:\SOFTWARE\JDBCC','HKCU:\SOFTWARE\JDBCC','HKLM:\SOFTWARE\WOW6432Node\JDBCC')) {
    if (Test-Path $k) {
      $i = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
      $vals = @()
      if ($i) {
        $vals = @($i.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
                  ForEach-Object { [pscustomobject]@{ n=$_.Name; v=[string]$_.Value } })
      }
      $hits += [pscustomobject]@{ key=$k; values=$vals }
    }
  }
  $out.suspicious_reg = @($hits)
} catch { $out.suspicious_reg = @() }

ConvertTo-Json -InputObject $out -Compress -Depth 6
"""
    data = run_ps_json(script, timeout=timeout)
    empty = {"tasks": [], "drivers": [], "run_keys": [],
             "defender": {"accessible": False, "paths": [], "processes": [],
                          "extensions": []},
             "suspicious_reg": []}
    if not isinstance(data, dict):
        return empty

    def _lst(v):
        if v is None:
            return []
        return [v] if isinstance(v, dict) else list(v)

    tasks = []
    for t in _lst(data.get("tasks")):
        if not isinstance(t, dict):
            continue
        tasks.append({
            "name": str(t.get("name", "")), "path": str(t.get("path", "\\")),
            "state": str(t.get("state", "")), "hidden": bool(t.get("hidden", False)),
            "runlevel": str(t.get("runlevel", "")), "userid": str(t.get("userid", "")),
            "author": str(t.get("author", "")),
            "actions": [{"exec": str(a.get("exec", "") or ""),
                         "args": str(a.get("args", "") or ""),
                         "wd": str(a.get("wd", "") or "")}
                        for a in _lst(t.get("actions")) if isinstance(a, dict)],
            "triggers": [{"type": str(g.get("type", "")),
                          "interval": str(g.get("interval", "") or ""),
                          "duration": str(g.get("duration", "") or ""),
                          "enabled": bool(g.get("enabled", True))}
                         for g in _lst(t.get("triggers")) if isinstance(g, dict)],
        })

    drivers = [{"name": str(d.get("name", "")), "display": str(d.get("display", "")),
                "path": str(d.get("path", "")), "state": str(d.get("state", "")),
                "start": str(d.get("start", ""))}
               for d in _lst(data.get("drivers")) if isinstance(d, dict)]

    run_keys = [{"key": str(r.get("key", "")), "name": str(r.get("name", "")),
                 "value": str(r.get("value", ""))}
                for r in _lst(data.get("run_keys")) if isinstance(r, dict)]

    df = data.get("defender") or {}
    if not isinstance(df, dict):
        df = {}
    defender = {
        "accessible": bool(df.get("accessible", False)),
        "paths": [str(x) for x in _lst(df.get("paths"))],
        "processes": [str(x) for x in _lst(df.get("processes"))],
        "extensions": [str(x) for x in _lst(df.get("extensions"))],
    }

    susp = []
    for h in _lst(data.get("suspicious_reg")):
        if not isinstance(h, dict):
            continue
        susp.append({"key": str(h.get("key", "")),
                     "values": [{"name": str(v.get("n", "")), "value": str(v.get("v", ""))}
                                for v in _lst(h.get("values")) if isinstance(v, dict)]})

    return {"tasks": tasks, "drivers": drivers, "run_keys": run_keys,
            "defender": defender, "suspicious_reg": susp}


def get_scheduled_tasks() -> list[dict]:
    script = (
        "$tasks=Get-ScheduledTask | ForEach-Object {"
        "  $t=$_;"
        "  $act=@($t.Actions | ForEach-Object {"
        "    [pscustomobject]@{exec=[string]$_.Execute;args=[string]$_.Arguments;"
        "wd=[string]$_.WorkingDirectory} });"
        "  $trg=@($t.Triggers | ForEach-Object {"
        "    $rep=$_.Repetition;"
        "    [pscustomobject]@{type=[string]$_.CimClass.CimClassName;"
        "interval=[string]$rep.Interval;duration=[string]$rep.Duration;"
        "enabled=[bool]$_.Enabled} });"
        "  [pscustomobject]@{"
        "name=[string]$t.TaskName;path=[string]$t.TaskPath;"
        "state=[string]$t.State;hidden=[bool]$t.Settings.Hidden;"
        "runlevel=[string]$t.Principal.RunLevel;"
        "userid=[string]$t.Principal.UserId;"
        "author=[string]$t.Author;actions=$act;triggers=$trg}"
        "};"
        "ConvertTo-Json -InputObject @($tasks) -Compress -Depth 6"
    )
    data = run_ps_json(script, timeout=120)
    if not data:
        return []
    if isinstance(data, dict):
        data = [data]
    out = []
    for t in data:
        if not isinstance(t, dict):
            continue
        acts = t.get("actions") or []
        if isinstance(acts, dict):
            acts = [acts]
        trgs = t.get("triggers") or []
        if isinstance(trgs, dict):
            trgs = [trgs]
        out.append({
            "name": str(t.get("name", "")),
            "path": str(t.get("path", "\\")),
            "state": str(t.get("state", "")),
            "hidden": bool(t.get("hidden", False)),
            "runlevel": str(t.get("runlevel", "")),
            "userid": str(t.get("userid", "")),
            "author": str(t.get("author", "")),
            "actions": [{
                "exec": str(a.get("exec", "") or ""),
                "args": str(a.get("args", "") or ""),
                "wd": str(a.get("wd", "") or ""),
            } for a in acts if isinstance(a, dict)],
            "triggers": [{
                "type": str(g.get("type", "")),
                "interval": str(g.get("interval", "") or ""),
                "duration": str(g.get("duration", "") or ""),
                "enabled": bool(g.get("enabled", True)),
            } for g in trgs if isinstance(g, dict)],
        })
    return out


# ---------------------------------------------------------------- 内核驱动

def get_drivers() -> list[dict]:
    script = (
        "$d=Get-CimInstance -ClassName Win32_SystemDriver | ForEach-Object {"
        "[pscustomobject]@{name=[string]$_.Name;display=[string]$_.DisplayName;"
        "path=[string]$_.PathName;state=[string]$_.State;start=[string]$_.StartMode}};"
        "ConvertTo-Json -InputObject @($d) -Compress -Depth 4"
    )
    data = run_ps_json(script, timeout=90)
    if not data:
        return []
    if isinstance(data, dict):
        data = [data]
    return [{
        "name": str(d.get("name", "")),
        "display": str(d.get("display", "")),
        "path": str(d.get("path", "")),
        "state": str(d.get("state", "")),
        "start": str(d.get("start", "")),
    } for d in data if isinstance(d, dict)]


# ---------------------------------------------------------------- 注册表 / 启动项

def get_run_keys() -> list[dict]:
    script = (
        "$keys=@("
        "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',"
        "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',"
        "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',"
        "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',"
        "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'"
        ");"
        "$out=foreach($k in $keys){"
        "  $item=Get-ItemProperty -Path $k -ErrorAction SilentlyContinue;"
        "  if(-not $item){continue};"
        "  $item.PSObject.Properties | Where-Object {$_.Name -notlike 'PS*'} | ForEach-Object {"
        "    [pscustomobject]@{key=$k;name=$_.Name;value=[string]$_.Value}"
        "  }"
        "};"
        "ConvertTo-Json -InputObject @($out) -Compress -Depth 4"
    )
    data = run_ps_json(script, timeout=60)
    if not data:
        return []
    if isinstance(data, dict):
        data = [data]
    return [{
        "key": str(d.get("key", "")),
        "name": str(d.get("name", "")),
        "value": str(d.get("value", "")),
    } for d in data if isinstance(d, dict)]


def get_defender_exclusions() -> dict:
    """读取 Defender 排除项。非管理员可能读不到（返回 accessible=False）。"""
    script = (
        "$res=[pscustomobject]@{accessible=$false;paths=@();processes=@();extensions=@()};"
        "try{"
        "  $p=Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths' "
        "-ErrorAction Stop;"
        "  if($p){$res.paths=@($p.PSObject.Properties | Where-Object {$_.Name -notlike 'PS*'} | "
        "ForEach-Object {$_.Name});$res.accessible=$true}"
        "}catch{};"
        "try{"
        "  $q=Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes' "
        "-ErrorAction Stop;"
        "  if($q){$res.processes=@($q.PSObject.Properties | Where-Object {$_.Name -notlike 'PS*'} | "
        "ForEach-Object {$_.Name})}"
        "}catch{};"
        "try{"
        "  $r=Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions' "
        "-ErrorAction Stop;"
        "  if($r){$res.extensions=@($r.PSObject.Properties | Where-Object {$_.Name -notlike 'PS*'} | "
        "ForEach-Object {$_.Name})}"
        "}catch{};"
        "ConvertTo-Json -InputObject $res -Compress -Depth 4"
    )
    data = run_ps_json(script, timeout=60)
    if not isinstance(data, dict):
        return {"accessible": False, "paths": [], "processes": [], "extensions": []}
    return {
        "accessible": bool(data.get("accessible", False)),
        "paths": [str(x) for x in (data.get("paths") or [])],
        "processes": [str(x) for x in (data.get("processes") or [])],
        "extensions": [str(x) for x in (data.get("extensions") or [])],
    }


def get_suspicious_registry_keys() -> list[dict]:
    """检查银狐专用注册表位置（如 HKLM\\SOFTWARE\\JDBCC）。"""
    script = (
        "$hits=@();"
        "$cand=@('HKLM:\\SOFTWARE\\JDBCC','HKCU:\\SOFTWARE\\JDBCC',"
        "'HKLM:\\SOFTWARE\\WOW6432Node\\JDBCC');"
        "foreach($k in $cand){"
        "  if(Test-Path $k){"
        "    $i=Get-ItemProperty -Path $k -ErrorAction SilentlyContinue;"
        "    $vals=@();"
        "    if($i){$vals=@($i.PSObject.Properties|Where-Object {$_.Name -notlike 'PS*'}|"
        "ForEach-Object {[pscustomobject]@{n=$_.Name;v=[string]$_.Value}})};"
        "    $hits+=[pscustomobject]@{key=$k;values=$vals}"
        "  }"
        "};"
        "ConvertTo-Json -InputObject @($hits) -Compress -Depth 4"
    )
    data = run_ps_json(script, timeout=45)
    if not data:
        return []
    if isinstance(data, dict):
        data = [data]
    out = []
    for h in data:
        if not isinstance(h, dict):
            continue
        vals = h.get("values") or []
        if isinstance(vals, dict):
            vals = [vals]
        out.append({
            "key": str(h.get("key", "")),
            "values": [{"name": str(v.get("n", "")), "value": str(v.get("v", ""))}
                       for v in vals if isinstance(v, dict)],
        })
    return out


# ---------------------------------------------------------------- hosts

def read_hosts() -> list[dict]:
    """解析 hosts 文件，返回非注释条目。"""
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                        "System32", "drivers", "etc", "hosts")
    entries = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        try:
            with open(path, "r", encoding="gbk", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return []
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split("#")[0].split()
        if len(parts) >= 2:
            ip = parts[0]
            # 加固：一行可映射多个主机名（`127.0.0.1 a.com b.com`），
            # 初版只取第二个字段，把 weishi.360.cn 之类的第二主机名
            # 直接丢弃（对抗测试 A3 实测漏检 H001）。
            for h in parts[1:]:
                entries.append({"ip": ip, "host": h.lower()})
    return entries


def hosts_path() -> str:
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                        "System32", "drivers", "etc", "hosts")


# ---------------------------------------------------------------- 启动目录

def get_startup_files() -> list[dict]:
    dirs = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    ]
    out = []
    for d in dirs:
        try:
            for n in os.listdir(d):
                fp = os.path.join(d, n)
                if os.path.isfile(fp) and n.lower() != "desktop.ini":
                    out.append({"dir": d, "name": n, "path": fp})
        except Exception:
            continue
    return out


# ---------------------------------------------------------------- 进程操作

def kill_process(pid: int) -> tuple[bool, str]:
    """结束进程（需要相应权限）。"""
    try:
        import psutil
        p = psutil.Process(pid)
        name = p.name()
        p.kill()
        return True, f"已发送终止信号：{name} (PID {pid})"
    except Exception as e:
        return False, f"终止失败：{e}"


def open_in_explorer(path: str) -> tuple[bool, str]:
    """在资源管理器中定位文件。"""
    try:
        if not os.path.exists(path):
            return False, "文件不存在"
        subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
        return True, "已打开文件所在位置"
    except Exception as e:
        return False, f"打开失败：{e}"
