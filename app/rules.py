# -*- coding: utf-8 -*-
"""
检测规则引擎
============================================================
本文件覆盖 8 类、56 条规则，与 netmon.py 的 5 条网络心跳规则（N 系列）合计 **61 条**：

  P 系列  进程行为（伪装、PPID 欺骗、签名伪造、命令行、外联）
  T 系列  计划任务持久化
  S 系列  系统服务持久化
  D 系列  内核驱动 / BYOVD
  H 系列  hosts 劫持
  R 系列  注册表 / Defender 排除项 / 启动项
  F 系列  文件系统落地特征（伪装扩展名、组合目录特征）
  X 系列  深度扫描（加载模块 / 白加黑侧加载）
  N 系列  网络心跳规律性 —— 见 netmon.py（需要时序证据，故与规则引擎分开放）

评分模型：
    单条规则有独立权重；总分 = min(100, 最高权重 + 0.35 × 其余权重之和)
    该模型避免"5 条低危规则叠加"压过"1 条严重规则"，同时保留关联加成的意义。

规则设计取向：宁可少报，不可误报成灾 —— 用户看到一屏红点就会关掉工具。
每条规则在证据字段里给出可核验的具体字符串。
"""

from __future__ import annotations

import base64
import os
import re

import iocs

# ================================================================
# 数据结构
# ================================================================

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_ZH = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示"}
CATEGORY_ZH = {
    "process": "进程行为", "task": "计划任务", "service": "系统服务",
    "driver": "内核驱动", "hosts": "hosts 劫持", "registry": "注册表",
    "file": "文件特征", "network": "网络通信",
}


def finding(rid: str, title: str, severity: str, weight: int,
            category: str, evidence: str, advice: str = "") -> dict:
    return {
        "rule_id": rid,
        "title": title,
        "severity": severity,
        "severity_zh": SEVERITY_ZH[severity],
        "weight": weight,
        "category": category,
        "category_zh": CATEGORY_ZH.get(category, category),
        "evidence": evidence,
        "advice": advice,
    }


def score_findings(fs: list[dict]) -> tuple[float, str]:
    if not fs:
        return 0.0, "clean"
    weights = sorted((f["weight"] for f in fs), reverse=True)
    total = weights[0] + 0.35 * sum(weights[1:])
    total = min(100.0, round(total, 1))
    if total >= 80:
        return total, "critical"
    if total >= 55:
        return total, "high"
    if total >= 30:
        return total, "medium"
    if total >= 10:
        return total, "low"
    return total, "clean"


# ================================================================
# 工具函数
# ================================================================

def norm(p: str) -> str:
    return (p or "").replace("/", "\\").lower()


def _parts(p: str) -> list[str]:
    return [x for x in norm(p).strip("\\").split("\\") if x]


def is_loopback_ip(ip: str) -> bool:
    """是否为回环地址。

    用途：把 127.0.0.0/8、::1 以及 IPv4-mapped 形式排除在"对外连接"之外。
    回环连接两端都在本机，不构成 C2 —— 不排除的话，任何未签名的本地工具
    （开发脚本、本地服务客户端）只要连一下 127.0.0.1 就会被判"未签名外联"。
    """
    x = (ip or "").strip().lower()
    if not x:
        return False
    if x.startswith("::ffff:"):
        x = x[7:]
    return x.startswith("127.") or x in ("::1", "0:0:0:0:0:0:0:1", "localhost")


def in_dirs(path: str, dirs: list[str]) -> str | None:
    """返回命中的目录片段，未命中返回 None。

    按**路径段**匹配（段级包含），修复初版子串匹配的两个实测缺陷：
    1. 误报：`C:\\Program Files\\TempDir\\app.exe` 误命中 `\\Temp`；
    2. 漏报/绕过：攻击者在用户目录自建 `windows\\system32` 子目录
       （`C:\\Users\\Public\\windows\\system32\\svchost.exe`）被当作系统目录放行。
    """
    parts = _parts(path)
    for d in dirs:
        dp = _parts(d)
        if not dp:
            continue
        for i in range(len(parts) - len(dp) + 1):
            if parts[i:i + len(dp)] == dp:
                return d
    return None


# 系统目录必须锚定到真实 %WINDIR%，不能用段级包含 ——
# 段级包含挡不住"用户目录下伪造 windows\system32 子目录"（对抗测试 A1 实测绕过）。
_WINDIR = norm(os.path.expandvars(r"%WINDIR%"))
SYSTEM_PROCESS_DIRS_REAL = [
    _WINDIR + r"\system32",
    _WINDIR + r"\syswow64",
    _WINDIR + r"\winsxs",
    _WINDIR + r"\servicing",
    _WINDIR + r"\systemapps",
]


def in_anchor_dirs(path: str, dirs: list[str]) -> bool:
    """前缀锚定：路径必须等于目录本身、或以「目录+反斜杠」开头。"""
    n = norm(path)
    return any(n == d or n.startswith(d + "\\") for d in dirs)


def in_real_system_dirs(exe: str, extra_roots: list[str] | None = None) -> bool:
    """判断可执行文件是否位于真实系统目录（防伪造子目录）。"""
    dirs = list(SYSTEM_PROCESS_DIRS_REAL)
    for r in (extra_roots or []):
        dirs.append(norm(os.path.expandvars(r)))
    return in_anchor_dirs(exe, dirs)


_VOWELS = set("aeiouAEIOU")
COMMON_NAMES = {
    "svchost", "explorer", "chrome", "msedge", "firefox", "winlogon", "lsass",
    "services", "csrss", "smss", "wininit", "dwm", "spoolsv", "taskhostw",
    "sihost", "runtimebroker", "ctfmon", "searchindexer", "system", "registry",
    "conhost", "dllhost", "fontdrvhost", "audiodg", "taskmgr", "regedit",
    "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32",
    "regsvr32", "werfault", "wuauclt", "trustedinstaller", "tiworker",
    "widgets", "startmenuexperiencehost", "shellexperiencehost",
    "textinputhost", "applicationframehost", "usoclient", "securityhealthsystray",
    "securityhealthservice", "msmpeng", "nissrv", "onedrive", "teams", "outlook",
    "excel", "winword", "powerpnt", "code", "devenv", "python", "pythonw",
    "node", "java", "git", "wechat", "qq", "dingtalk", "wemeetapp", "sogouinput",
    "yiyong", "notepad", "mspaint", "calculator", "photos", "music", "vlc",
}


def _wordlike(s: str) -> bool:
    """判断是否像一个真实英文单词（元音比例 + 辅音连续长度）。"""
    low = s.lower()
    v = sum(1 for c in low if c in _VOWELS)
    if not low:
        return False
    ratio = v / len(low)
    if ratio < 0.2 or ratio > 0.7:
        return False
    run = 0
    for c in low:
        if c.isalpha() and c not in _VOWELS:
            run += 1
            if run >= 4:
                return False
        else:
            run = 0
    return True


def looks_random(base: str) -> bool:
    """识别银狐式随机命名：5–12 位字母数字、缺乏音节结构。
    例：SXRh6d / VBV4HZ / bcCfOw / cgL18U72 / XsOewfN / O02PwqGh

    关键点：先用 _wordlike 排除"看起来像词"的字符串，否则品牌名会被大量误判 ——
    i4Tools（爱思助手）、AIDA64 都含数字且大小写混杂，初版实现把它们判成了随机名。
    另外本函数只是"加分项"，调用方必须叠加签名等上下文，不能单独定罪。
    """
    if not base or not (5 <= len(base) <= 12):
        return False
    if not re.fullmatch(r"[A-Za-z0-9]+", base):
        return False
    if base.lower() in COMMON_NAMES:
        return False
    if _wordlike(base):
        return False
    has_digit = any(c.isdigit() for c in base)
    has_upper = any(c.isupper() for c in base)
    has_lower = any(c.islower() for c in base)
    if has_upper and has_lower:
        return True
    # 全大写/全小写：仅当同时含数字且长度足够时才判为随机（VBV4HZ、S7UA99K 型）
    return has_digit and len(base) >= 6


def looks_random_dir(name: str) -> bool:
    """目录名是否为银狐式随机命名 —— 比 looks_random 更严的版本。

    ## 为什么需要这个更严的版本

    looks_random 的「大小写混杂即随机」判据，会把**驼峰式品牌名**整片误判。
    2026-10-05 在一台测试机（LAPTOP-B23G59QJ）上实测：

        looks_random("MySQL")     = True
        looks_random("WXWork")    = True
        looks_random("MasterPDF") = True

    于是四条**纯误报**同时出现：

        S002 服务 MySQL80          → C:\\Program Files\\MySQL\\...        （85 分）
        S002 服务 WXWorkUpgrader   → C:\\Program Files (x86)\\WXWork\\... （85 分）
        T004 任务 DocUpdate        → C:\\Program Files (x86)\\MasterPDF\\ （78 分）
        S002 服务 DocService       → C:\\Program Files (x86)\\MasterPDF\\ （85 分）

    根因不在"随机名判据"本身，而在**调用点缺少签名上下文**：
    S004 的写法是 `looks_random(base) and sig_k in UNTRUSTED_KINDS`，
    所以它不会误报；而 T004 / T006 / S002 是**目录级**判断，
    手上只有一个字符串，拿不到签名，只能靠判据自身兜住。

    ## 收紧方式（只用于"目录名"，不影响进程名 / DLL 名的 looks_random）

      · 含数字的随机名（SXRh6d / VBV4HZ / cgL18U72 / O02PwqGh / Pl6VgrWG）
        → 沿用原判据，全部照报；
      · 不含数字的 → 统计**大小写切换次数**，≥3 次才算随机。

    依据：驼峰品牌名的大小写只在"词首"切换（My|SQL、Master|PDF、WX|Work、
    One|Drive），切换次数 ≤2；而随机名的大小写是散乱交替的
    （bcCfOw → b-c-C-f-O-w 切换 4 次；XsOewfN → X-s-O-e-w-f-N 切换 4 次）。

    ⚠️ 两个踩过的坑（不要"优化"回去）：
      1. 不能要求"含元音" —— MySQL 里根本没有 a/e/i/o/u（y 不算），
         用元音判据会把 MySQL 判成随机名。
      2. 不能用 `re.findall(r"[A-Z][a-z]*|[a-z]+")` 切分再看"是否出现单字母片段"
         —— `[a-z]*` 是贪婪的，`bcCfOw` 会被切成 ['bc','Cf','Ow']，
         单字母特征被吃掉，同样失效。

    实测：对 MySQL / WXWork / MasterPDF / Google / NVIDIA / OneDrive 全部
    返回 False；对 bcCfOw / XsOewfN 返回 True。
    """
    if not looks_random(name):
        return False
    if any(c.isdigit() for c in name):
        return True
    switches = sum(1 for a, b in zip(name, name[1:])
                   if a.isalpha() and b.isalpha() and a.isupper() != b.isupper())
    return switches >= 3


def sig_kind(proc: dict) -> str:
    s = proc.get("signature")
    if not s:
        return "unknown"
    return s.get("kind", "unknown")


# 签名状态"明确不可信"。注意：校验中（None）或校验失败（unknown）都不计入 ——
# 不能因为"没查到签名"就给进程定罪，否则首轮扫描会满屏红点。
UNTRUSTED_KINDS = ("unsigned", "forged", "untrusted")

_LEGIT_TASK_TOKEN_SET = set(iocs.LEGIT_TASK_TOKENS)

# T006 用：能"执行脚本"的解释器 / 宿主进程
_SCRIPT_HOSTS = {
    "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "cmd", "cmd.exe", "wscript", "wscript.exe", "cscript", "cscript.exe",
    "mshta", "mshta.exe", "rundll32", "rundll32.exe",
    "regsvr32", "regsvr32.exe", "bitsadmin", "bitsadmin.exe",
    "certutil", "certutil.exe", "msiexec", "msiexec.exe",
    "wmic", "wmic.exe",
}
# T006 用：隐藏窗口 / 无交互 / 编码执行的标志
# 注意：**不要把 `-command` 当成隐藏标志** —— 合法计划任务大量使用它
# （实测：Intel 的 USER_ESRV_SVC_QUEENCREEK 就用 -Command，把 -command 计入
#  隐藏标志会让这条规则几乎命中所有跑 PowerShell 的任务）。
_HIDDEN_FLAGS = (
    "-windowstyle hidden", "-w hidden", "start-process -windowstyle hidden",
    "/hidden", "-nop", "-noprofile", "-noninteractive",
    "-encodedcommand", "-enc ", "-enc:", "start /min", "/c start",
)
# T006 用：从动作参数里抠出被执行的脚本/程序路径
def _task_writable_hit(p: str) -> str:
    """T006 用：判断脚本路径/工作目录是否落在用户可写位置。

    比 nonstandard_target 更宽 —— 后者为了压误报，对 AppData/ProgramData 下的
    路径只认"随机命名的文件或一级子目录"（因为 Defender 就装在 ProgramData 下）。
    但对**计划任务的动作**来说，从 AppData/ProgramData 执行脚本本身就是异常：
    正常软件不会这么干。所以这里在 nonstandard_target 之外再补一层目录级判定。
    """
    if not p:
        return ""
    # 先按「目录语义」排除系统只读目录：Program Files 下默认只有管理员/SYSTEM
    # 可写，子目录叫什么名字都一样 —— 普通用户放不进文件，
    # "脚本可被替换"这个前提就不成立。
    #
    # 注意：不能改用 nonstandard_target 的"子目录名是否随机"来判断 ——
    # looks_random 会把合法的驼峰命名（MyWatchdog / SysMon / Python313）
    # 判成随机名，从而把正常软件的 Program Files 目录误判为"用户可写"（实测踩过）。
    if in_dirs(p, [r"\Program Files", r"\Program Files (x86)", r"\Windows\System32",
                   r"\Windows\SysWOW64"]):
        return ""
    r = nonstandard_target(p)
    if r:
        return r
    return in_dirs(p, iocs.WRITABLE_DIRS) or ""


_REF_PATH_RE = re.compile(r'([A-Za-z]:\\[^"\']+?\.(?:ps1|bat|cmd|vbs|js|py|exe|dll))', re.I)


def is_untrusted(proc: dict) -> bool:
    return sig_kind(proc) in UNTRUSTED_KINDS


def sig_cn(proc: dict) -> str:
    s = proc.get("signature") or {}
    return s.get("cn", "") or ""


def sig_label(proc: dict) -> str:
    s = proc.get("signature")
    if not s:
        return "未校验"
    return f"{s.get('status_zh','')}{(' · ' + s['cn']) if s.get('cn') else ''}"


def nonstandard_target(exe: str) -> str:
    """判断计划任务/服务的执行目标是否为"非常规位置"。命中返回原因描述，否则返回空串。

    三级判定（这是把误报从 45 条压到个位数的关键）：
      1. 强信号目录：Users\\Public、Windows\\Temp、Downloads、Recycle.Bin 等
         —— 正常软件几乎不会从这里运行，命中即可疑。
      2. ProgramData / AppData：**不能只看目录本身**。Windows Defender 自身就装在
         C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\<版本>\\ 下，
         按目录一刀切会把 Defender 判成木马。这里改为只认"随机命名的文件名或一级子目录"。
      3. Program Files：只认一级随机命名子目录（银狐 G01 的安装方式），
         因此 Microsoft\\Edge、Google\\ 这类合法目录不会误判。
    """
    if not exe:
        return ""
    exe = os.path.expandvars(exe)
    # 服务/驱动路径可能写作 \SystemRoot\...，统一展开成真实 Windows 目录
    if exe.lower().startswith("\\systemroot\\"):
        exe = os.path.expandvars(r"%WINDIR%") + exe[len("\\SystemRoot"):]

    hit = in_dirs(exe, iocs.WRITABLE_DIRS_STRONG)
    if hit:
        return hit

    for root in (r"\ProgramData", r"\AppData\Roaming", r"\AppData\Local"):
        m = re.search(re.escape(root) + r"\\(.+)$", exe, re.I)
        if not m:
            continue
        rel = m.group(1)
        first = rel.split("\\")[0]
        if looks_random_dir(os.path.splitext(first)[0]) or looks_random_dir(os.path.splitext(rel)[0]):
            return f"{root}\\{rel}（随机命名）"

    for root in iocs.RANDOM_INSTALL_ROOTS:
        m = re.search(re.escape(root) + r"\\([^\\]+)", exe, re.I)
        if m and looks_random_dir(m.group(1)):
            return f"{root}\\{m.group(1)}\\（随机命名目录）"
    return ""


def is_broad_exclusion(p: str) -> bool:
    """判断 Defender 排除项是否为"整个大目录"被排除。

    必须用**精确相等**判定。初版用 startswith 匹配，结果把
    C:\\Users\\<用户名>\\AppData\\Local\\JetBrains\\PyCharm2026.1 这种
    正常的开发工具排除项也算成了"整个 C:\\Users 被排除" —— 严重误报。
    银狐的信号是排除 C:\\Users 本身，不是它的子目录。
    """
    n = norm(p).rstrip("\\")
    return any(n == norm(b).rstrip("\\") for b in iocs.BROAD_DEFENDER_EXCLUSIONS)


def path_sig_kind(path: str, sig_cache: dict | None) -> str:
    """查询某个文件路径的签名判定结果（供服务/驱动等制品规则使用）。"""
    if not path or not sig_cache:
        return "unknown"
    key = os.path.expandvars(path).lower()
    s = sig_cache.get(key)
    return (s or {}).get("kind", "unknown")


_BINPATH_RE = re.compile(
    r'^\s*"?([^"]+\.(?:exe|dll|sys|bat|cmd|ps1|jpg|png|dat|db|vbs|com))"?', re.I)

# 银狐主机侧路径 IOC（进程路径 P021 与注册表启动项 R004B 共用）
_PATH_IOC_PATTERNS = [
    (r"\\windows\\temp\\ranchserv\.jpg", "C:\\Windows\\Temp\\ranchserv.jpg（火绒样本驱动落地路径）"),
    (r"\\program files\\common files\\scvhost\.exe", "C:\\Program Files\\Common Files\\scvhost.exe（火绒样本持久化路径）"),
    (r"\\programdata\\microsoft\\edgeupdate\\log\\", "C:\\ProgramData\\Microsoft\\EdgeUpdate\\Log\\（火绒样本 kill.bat 路径）"),
    (r"\\adobe\\h\d{10,}\.ini", "%APPDATA%\\Adobe\\h<长数字>.ini（CNCERT G01 主机特征）"),
    (r"\\users\\public\\venwin\.lock", "C:\\Users\\Public\\venwin.lock（CNCERT G01 主机特征）"),
    (r"\\lnte\\lnte\\scuttled\.dll", "C:\\Program Files (x86)\\lnte\\lnte\\scuttled.dll（CNCERT G01 主机特征）"),
]


def bin_from_binpath(binpath: str) -> str:
    """从服务 ImagePath 中提取可执行文件路径（去掉引号与启动参数）。"""
    if not binpath:
        return ""
    m = _BINPATH_RE.match(binpath.strip())
    if m:
        return os.path.expandvars(m.group(1))
    # 无扩展名的兜底：取第一个空白前的片段
    first = binpath.strip().strip('"').split(" ")[0]
    return os.path.expandvars(first) if first else ""


# ================================================================
# P 系列 —— 进程行为
# ================================================================

def is_own_aux_process(proc: dict, ctx: dict) -> bool:
    """判断是否为本工具**自己拉起的辅助进程**（签名校验用的 PowerShell 等）。

    为什么需要这个：本工具的签名校验要调用 PowerShell `-EncodedCommand`，
    这天然命中 P010B（Base64 执行）+ P011（绕过执行策略）。不排除的话，
    工具会把自己的校验进程报成"高危"（实测发生过，告警时间线里凭空多一条）。

    三重判据，任一命中即排除：
      ① `(pid, create_time)` 在"本工具拉起的子进程"登记表里 —— 精确且**不可伪造**；
      ② 直接父进程是本进程；
      ③ 祖先链上有本进程（最多回溯 6 层）。

    ⚠️ 为什么不能只看父进程：实测有两种情况让 ppid ≠ 本进程 ——
      · venv 的 `pythonw.exe` 是启动器，会再派生一个真解释器（`os.getpid()` 是后者）；
      · 经 `%LOCALAPPDATA%\\Microsoft\\WindowsApps\\pwsh.exe` 这个 MSIX「应用执行别名」
        启动时，激活可能经过 broker，子进程的父进程不是我们。
    两者都会让旧版"父进程 == 自己"的判据静默失效。

    ⚠️ 判据绝不能放宽成"命令行里含本工具 preamble 就放过" ——
    那是一条**免杀通道**：攻击者读一遍源码就能把自己的 PowerShell 前缀成同样的
    preamble，从此对本工具隐身。父进程链可以伪造，PID + 创建时间不能。
    """
    self_pid = ctx.get("self_pid") or 0
    if not self_pid:
        return False

    own = ctx.get("own_children") or {}
    pid = proc.get("pid")
    if pid in own:
        ct = proc.get("create_time") or 0
        oct_ = own.get(pid) or 0
        # 比对创建时间：PID 会被系统回收再分配，只比 PID 会误伤复用该号的新进程
        if not ct or not oct_ or abs(ct - oct_) < 1.5:
            return True

    by_pid = ctx.get("by_pid") or {}
    cur = proc.get("ppid") or 0
    for _ in range(6):
        if not cur or cur in (0, 4):
            return False
        if cur == self_pid:
            return True
        parent = by_pid.get(cur)
        if not parent:
            return False
        cur = parent.get("ppid") or 0
    return False


def rules_process(proc: dict, ctx: dict) -> list[dict]:
    fs: list[dict] = []

    # 排除本工具自己拉起的辅助进程。
    # 签名校验会调用 PowerShell（-EncodedCommand），这些子进程的命令行天然带高危特征；
    # 若不排除，工具会把自己的校验进程判成"严重风险"（实测确实发生过）。
    if is_own_aux_process(proc, ctx):
        return fs

    name = (proc.get("name") or "")
    lname = name.lower()
    exe = proc.get("exe") or ""
    nex = norm(exe)
    base = os.path.splitext(name)[0]
    cmd = proc.get("cmdline_str") or ""
    lcmd = cmd.lower()
    conns = proc.get("connections") or []
    kind = sig_kind(proc)
    by_pid = ctx["by_pid"]

    # ---- P001 系统进程名伪装 -------------------------------------------
    if lname in iocs.SYSTEM_PROCESS_PARENTS:
        extra = iocs.SYSTEM_PROCESS_EXTRA_DIRS.get(lname, [])
        if exe and not in_real_system_dirs(exe, extra):
            fs.append(finding(
                "P001", f"伪装系统进程：{name}", "critical", 95, "process",
                f"进程名 {name} 是系统进程名，但可执行文件位于 {exe}，"
                f"不在 System32/SysWOW64/WinSxS 等系统目录",
                "银狐常用手法：把木马命名为 svchost.exe / winlogon.exe 等系统进程名。"
                "请核对该文件签名与来源，确认后立即终止并删除。"))

    # ---- P002 父进程异常（PPID 欺骗）-----------------------------------
    pname = (proc.get("parent_name") or "").lower()
    ppid = proc.get("ppid") or 0
    if lname in iocs.SYSTEM_PROCESS_PARENTS:
        allowed = iocs.SYSTEM_PROCESS_PARENTS[lname]
        if pname and pname not in allowed:
            parent = by_pid.get(ppid)
            pexe = (parent or {}).get("exe") or ""
            # 仅当父进程本身也非系统目录时才告警，抑制系统内部合法调用造成的误报
            if pexe and not in_real_system_dirs(pexe):
                fs.append(finding(
                    "P002", f"父进程异常（疑似 PPID 欺骗）：{name}", "high", 80, "process",
                    f"{name} 的父进程为 {pname}（{pexe}），而合法父进程应为 "
                    f"{'/'.join(sorted(allowed))}",
                    "银狐会伪造进程树把子进程挂到 services.exe 下以逃避检测。"
                    "请检查该父进程是否为恶意程序。"))

    # ---- P002B 系统父进程 + 非常规子进程（银狐 PPID 欺骗核心手法）-------
    # 对抗测试 A2 实测：初版只检查"系统名子进程的父进程是否异常"，
    # 对"随机名子进程挂在系统父进程名下"完全看不见 —— 而后者才是银狐的真实手法。
    # 排除 explorer.exe：用户启动的一切程序都是它的子进程，不能作为指控依据。
    if pname in iocs.SYSTEM_SPAWNERS and exe and not in_real_system_dirs(exe):
        if is_untrusted(proc) and in_dirs(exe, iocs.WRITABLE_DIRS_STRONG):
            fs.append(finding(
                "P002B", f"疑似 PPID 欺骗：{name} 挂在系统父进程 {pname} 下", "high", 82, "process",
                f"{name}（{exe}）的父进程为系统进程 {pname}，"
                f"自身位于用户可写目录且未签名 —— 符合银狐伪造进程树特征",
                "银狐通过 STARTUPINFOEX 把子进程挂到 services.exe / wininit.exe 等"
                "系统父进程名下以逃避检测。请核实该进程是否为你主动启动。"))

    # ---- P003 签名伪造（摘要校验失败）----------------------------------
    if kind == "forged":
        fs.append(finding(
            "P003", "数字签名伪造（摘要校验失败）", "critical", 96, "process",
            f"文件 {exe} 内嵌签名主体「{sig_cn(proc) or '未知'}」，但文件摘要与签名不符 —— "
            f"这是签名被篡改或伪造的确凿证据",
            "CNCERT 报告确认：银狐样本内嵌伪造的「Bytedance Pte. Ltd.」签名。"
            "合法软件绝不会出现摘要不符。请立即隔离该文件。"))

    # ---- P004 滥用已知签名主体 -----------------------------------------
    cn = sig_cn(proc)
    if cn:
        for abused in iocs.ABUSED_SIGNERS:
            if abused.lower() in cn.lower():
                fs.append(finding(
                    "P004", f"使用被滥用/伪造的签名主体：{abused}", "critical", 90, "process",
                    f"{exe} 的签名主体为「{cn}」",
                    "该签名主体在银狐样本中被反复滥用（白加黑的白文件或伪造签名）。"
                    "请核验文件来源。"))
                break

    # ---- P005 未签名进程外联 -------------------------------------------
    # 注意：仅在"明确判定为未签名"时告警。签名尚未校验（None）或校验失败（unknown）
    # 都不作为指控依据 —— 宁可漏报，不可凭"没查到"就给人定罪。
    # 排除回环：127.0.0.1 的连接两端都在本机，不是"对外"连接
    established = [c for c in conns
                   if c.get("status") == "ESTABLISHED" and c.get("rip")
                   and not is_loopback_ip(c.get("rip"))]
    if established and kind == "unsigned":
        fs.append(finding(
            "P005", "未签名程序持有对外连接", "medium", 45, "network",
            f"{exe or name} 无有效数字签名，但持有 {len(established)} 条 ESTABLISHED 外联："
            + "，".join(f"{c['raddr']}" for c in established[:3]),
            "请核对该程序是否为正常业务软件。银狐远控组件通常无签名且长期保持外联。"))

    # ---- P006 位于用户可写目录 -----------------------------------------
    strong_dir = in_dirs(exe, iocs.WRITABLE_DIRS_STRONG)
    weak_dir = in_dirs(exe, iocs.WRITABLE_DIRS)
    if strong_dir:
        fs.append(finding(
            "P006", "程序运行于用户可写目录", "medium", 42, "process",
            f"{exe} 位于 {strong_dir}",
            "银狐常把组件释放到 Users\\Public、Windows\\Temp、Downloads 等目录。"
            "正常软件极少从这些位置运行。"))
    elif weak_dir and is_untrusted(proc):
        fs.append(finding(
            "P006", "未签名程序运行于用户目录", "medium", 34, "process",
            f"{exe} 位于 {weak_dir}，且数字签名不可信（{sig_label(proc)}）",
            "ProgramData / AppData 下的正常软件通常带有效签名。"))

    # ---- P007 随机命名 --------------------------------------------------
    if looks_random(base) and is_untrusted(proc):
        fs.append(finding(
            "P007", f"随机化程序名：{name}", "medium", 35, "process",
            f"文件名 {name} 符合随机生成特征（大小写混杂、无实义），且未通过签名校验",
            "CNCERT 报告：银狐各阶段组件普遍采用 5–8 位随机命名。"))

    # ---- P008 可执行文件伪装扩展名 --------------------------------------
    ext = (proc.get("ext") or "").lower()
    if ext and ext not in (".exe", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".sys", ".dll"):
        fs.append(finding(
            "P008", f"可执行文件伪装扩展名：{name}", "high", 78, "process",
            f"正在运行的进程 {name} 的扩展名为 {ext}（{exe}）",
            "CNCERT / 火绒报告：银狐使用 .jpg/.png/.dat/.db 等迷惑性扩展名承载 PE 载荷。"))

    # ---- P009–P015 命令行规则 -------------------------------------------
    # 2026-10-04 对抗性测试后加固：
    #   · P010B 补上 `-EncodedCommand:xxx`（冒号形式）与 `-enc` 缩写 —— 原正则漏检；
    #   · P011 补上 `-ep bypass` 缩写；
    #   · P013/P014 合并原 iocs.SUSPICIOUS_CMDLINE_PATTERNS / SECURITY_VENDOR_TOKENS
    #     中的 bcdedit 破坏恢复、sc 停安全服务、Stop-Process 杀安全软件、
    #     icacls 改 ACL、net user 建账户等原为死代码的模式。
    cmd_rules = [
        (r"add-mppreference.*(-exclusionpath|-exclusionprocess|-exclusionextension"
         r"|-disablerealtimemonitoring|-disablerealtimemonitoring\s+\$true)",
         "P009", "命令行写入 Windows Defender 排除项/关闭实时防护", "critical", 88,
         "CNCERT 报告明确将该行为列为银狐标志性动作：把 C:\\Users、C:\\ProgramData、"
         "C:\\Windows\\System32 等大范围目录加入 Defender 排除项，或直接关闭实时防护。"),
        (r"frombase64string|downloadstring|\biex\b|invoke-expression",
         "P010", "命令行内存加载 / 下载执行", "high", 82,
         "典型无文件攻击：从网络或 Base64 取载荷直接在内存执行。"),
        (r"-(?:encodedcommand|enc)\b(?::|\s+)[a-z0-9+/=]{32,}",
         "P010B", "命令行使用 Base64 编码执行", "medium", 55,
         "银狐会用 -EncodedCommand 隐藏真实命令，但**这一手法在正规运维中同样常见**"
         "（SCCM / Intune / 各类安装程序、以及本工具自身的签名校验都使用它）。"
         "因此单独出现只给中等权重，需与其他特征叠加才升级。"
         "（已覆盖 -EncodedCommand / -EncodedCommand: / -enc 三种写法。）"),
        (r"(?=.*-(?:executionpolicy|ep)\s+bypass)(?=.*(-windowstyle\s+hidden|-w\s+hidden"
         r"|-encodedcommand|-enc\b|-nop\b|-noprofile|\.ps1))"
         r"|set-executionpolicy\s+(unrestricted|bypass)",
         "P011", "命令行静默绕过 PowerShell 策略", "medium", 50,
         "火绒报告中的银狐命令：`powershell -ExecutionPolicy Bypass -File \\updated.ps1`、"
         "`Set-ExecutionPolicy Unrestricted -Scope CurrentUser`。"
         "注意：单独出现 -ExecutionPolicy Bypass 在正规安装程序中也常见，"
         "因此本条只给中等权重，需与其他特征叠加才升级。"),
        (r"register-scheduledtask.*(-xml|-action\s+new-scheduledtaskaction)"
         r"|schtasks.*/create.*(/ru\s+system|/rl\s+highest)",
         "P012", "命令行注册 SYSTEM 级计划任务", "high", 80,
         "银狐使用 `Register-ScheduledTask -TaskPath $taskPath -Xml $xmlContent -Force` 建立持久化。"),
        (r"vssadmin\s+delete\s+shadows|wbadmin\s+delete|wevtutil\s+cl|clear-eventlog|"
         r"netsh\s+(advfirewall|firewall).*(add|set|delete)|"
         r"bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|"
         r"icacls.*(/grant\s+everyone|/deny)|net\s+user\s+\S+\s+/add|"
         r"net\s+localgroup\s+administrators\s+\S+\s+/add",
         "P013", "命令行破坏系统恢复/日志/防火墙/ACL/建账户", "high", 78,
         "破坏取证与恢复能力、篡改 ACL、创建账户提权的典型远控/勒索前置动作。"),
        (r"taskkill.*(/im\s+(360|huorong|kxe|qqpcmgr|avp|msmpeng|windefend|defender)"
         r"|/pid\s+\d+)|stop-process.*-name\s+(360|huorong|kxe|qqpcmgr|avp|msmpeng"
         r"|windefend|defender)|sc\s+(stop|delete|config)\s+(windefend|wscsvc|sense"
         r"|mdcoresvc|mpssvc)",
         "P014", "命令行终止安全软件进程/服务", "critical", 92,
         "银狐内置 212 个安全软件映像名列表用于批量查杀，配合 BYOVD 驱动强杀。"
         "（已覆盖 taskkill / Stop-Process / sc stop 三种写法。）"),
        (r"reg\s+add.*\\run\b", "P015", "命令行写入注册表启动项", "high", 72,
         "银狐使用 HKCU\\...\\CurrentVersion\\Run 建立用户级持久化。"),
    ]
    # 只有命令行里出现 -enc 才去做 Base64 解码（避免给每个进程白付一次开销）
    own_ps = bool(cmd) and ("-enc" in lcmd) and looks_like_own_aux_ps(cmd)
    for pat, rid, title, sev, w, advice in cmd_rules:
        if re.search(pat, lcmd):
            adv = advice
            if own_ps and rid in ("P010B", "P011"):
                adv = advice + _OWN_PS_HINT
            fs.append(finding(rid, title, sev, w, "process",
                              f"命令行：{cmd[:400]}", adv))

    # ---- P016–P019 网络规则 ---------------------------------------------
    for c in conns:
        rip = c.get("rip") or ""
        rport = c.get("rport") or 0
        raddr = c.get("raddr") or ""
        if rip in iocs.MALICIOUS_IPS:
            fs.append(finding(
                "P016", f"连接已知银狐 C2：{raddr}", "critical", 100, "network",
                f"{name} (PID {proc['pid']}) → {raddr}",
                "该 IP 为 CNCERT / 火绒报告披露的银狐远控服务器。"
                "请立即断网、终止进程并全盘排查。"))
        # P017 加固：只对"明确未签名"的进程告警。
        # 初版对任何进程都告警 —— 8443/7000/9999 是大量合法业务与开发工具常用端口，
        # 已签名软件连这些端口会大面积误报。
        # 同样排除回环：本地服务之间用 8081/9999 这类端口通信是常见做法
        if (rport in iocs.SUSPICIOUS_PORTS and is_untrusted(proc)
                and not is_loopback_ip(rip)):
            fs.append(finding(
                "P017", f"未签名进程连接银狐常用非标端口：{raddr}", "high", 85, "network",
                f"{name} → {raddr}（端口 {rport} 属银狐常用 C2 端口段）",
                "银狐专用 C2 使用大端口直连（如 18300、7000、8001）。"
                "请核对该连接是否为业务所需。"))
        if rip in iocs.DOH_RESOLVERS and rport == 443:
            if is_untrusted(proc) and not _is_browser(lname):
                fs.append(finding(
                    "P019", "非常规进程直连公共 DNS（疑似 DoH 隐蔽信道）", "medium", 42, "network",
                    f"{name} → {raddr}",
                    "银狐 DoH 变种使用 https://223.5.5.5/dns-query 与 https://8.8.8.8/dns-query "
                    "作为隐蔽 C2 通道。非浏览器程序不应直连公共 DNS。"))

    # ---- P018 命中银狐传播/C2 域名 ---------------------------------------
    # 加固说明：psutil 连接表只有 IP、没有域名，初版把域名匹配放在连接循环里，
    # 且只对"有连接的进程"检查 —— 实测两条都是死代码。现在改为独立检查命令行，
    # 无连接、无网络权限的进程只要命令行里带银狐域名也会被告警。
    if any(d in lcmd for d in iocs.MALICIOUS_DOMAINS):
        fs.append(finding(
            "P018", "命中银狐传播/C2 域名", "critical", 98, "network",
            f"进程 {name} 命令行中出现已知银狐域名：{cmd[:400]}",
            "该域名在 CNCERT 报告中列为银狐载荷托管或 C2 地址。"
            "如需域名级网络检测，请配合能记录 DNS 查询的工具。"))

    # ---- P020 进程名命中 IOC ---------------------------------------------
    for bad in iocs.MALICIOUS_FILENAMES:
        if lname == bad.lower():
            fs.append(finding(
                "P020", f"进程名命中银狐 IOC：{name}", "critical", 100, "process",
                f"{exe}",
                "该文件名在银狐公开报告中明确列出。请立即隔离。"))
            break

    # ---- P021 路径命中 IOC 目录特征 --------------------------------------
    # 银狐的目录特征：在系统目录下直接创建"随机名"子目录并常驻其中。
    # 必须用 looks_random 校验目录名，且必须取原始大小写路径（norm 会把路径转小写，
    # 导致 mixed_case 判定失效）。全小写的 Microsoft / Defender / EdgeWebView
    # 这类合法目录因此不会被误判 —— 这是初版实现踩过的坑。
    hit_desc = ""
    for pat, desc in _PATH_IOC_PATTERNS:
        if re.search(pat, nex):
            hit_desc = desc
            break
    if not hit_desc and exe:
        for root, label in (
            (r"\Users\Public", r"C:\Users\Public"),
            (r"\ProgramData", r"C:\ProgramData"),
            (r"\Program Files (x86)", r"C:\Program Files (x86)"),
            (r"\Program Files", r"C:\Program Files"),
        ):
            m = re.search(re.escape(root) + r"\\([^\\]+)", exe, re.I)
            if m and looks_random(m.group(1)):
                hit_desc = (f"{label}\\{m.group(1)}\\ —— 随机命名目录，"
                            f"符合 CNCERT G01 载荷目录特征")
                break
    if hit_desc and is_untrusted(proc):
        fs.append(finding(
            "P021", "进程路径命中银狐 IOC 目录特征", "critical", 98, "process",
            f"{exe}\n匹配特征：{hit_desc}\n签名状态：{sig_label(proc)}",
            "该路径结构在银狐公开报告中作为主机侧 IOC 列出。"))

    # ---- P022 Program Files (x86) 下的随机目录 ---------------------------
    if exe:
        for root in iocs.RANDOM_INSTALL_ROOTS:
            m = re.search(re.escape(root) + r"\\([^\\]+)", exe, re.I)
            if m and looks_random(m.group(1)) and is_untrusted(proc):
                fs.append(finding(
                    "P022", "运行于 Program Files 下的随机目录", "high", 70, "process",
                    f"{exe}\n子目录「{m.group(1)}」符合随机命名特征，"
                    f"签名状态：{sig_label(proc)}",
                    "CNCERT 报告：银狐把二级载荷安装到 C:\\Program Files (x86)\\<随机名>\\。"))
                break

    # ---- P024 从 Startup 启动目录运行 ------------------------------------
    if in_dirs(exe, [r"\Start Menu\Programs\Startup"]):
        fs.append(finding(
            "P024", "程序位于开机启动目录", "high", 75, "process",
            f"{exe}",
            "火绒报告：银狐会把自身复制到 Startup 目录建立持久化。"))

    # ---- P025 用户目录程序监听端口（后门监听）----------------------------
    listeners = [c for c in conns if c.get("status") == "LISTEN"]
    if listeners and is_untrusted(proc) and in_dirs(exe, iocs.WRITABLE_DIRS_STRONG):
        fs.append(finding(
            "P025", "非常规程序监听端口", "high", 72, "network",
            f"{name}（{exe}）正在监听：" + "，".join(c.get("laddr", "") for c in listeners[:3]),
            "远控组件常监听端口等待连接。请确认该端口用途。"))

    return fs


def _is_browser(lname: str) -> bool:
    return any(b in lname for b in
               ("chrome", "msedge", "firefox", "iexplore", "opera", "brave", "360se", "qqbrowser"))


# 本工具自己调用 PowerShell 时固定使用的开头（见 winapi._PS_PREAMBLE）。
_OWN_PS_MARK = "$ErrorActionPreference='SilentlyContinue';$ProgressPreference='SilentlyContinue'"


def looks_like_own_aux_ps(cmd: str) -> bool:
    """命令行里的 Base64 载荷解出来，是不是**本工具自己**的 PowerShell 开头。

    ⚠️ 这个函数**只用来给证据补一句说明**，绝对不参与"是否告警"的判断。
    原因：如果拿它来免除告警，就成了一条**免杀通道** —— 攻击者读一遍源码，
    把自己的 PowerShell 前缀成同样的 preamble，从此对本工具隐身。
    （自身辅助进程的排除走的是 PID 登记表 + 祖先链 + Job 回收，见
      rules.is_own_aux_process；那套判据不可伪造。）

    用途：同一个工具跑两份副本、或在监视器运行期间跑 tools/ 下的验证脚本时，
    对方的校验进程会被本实例看到并告警。这一句说明能让人立刻明白
    "这不是恶意行为，是同类工具的兄弟进程"，而不是去查一个不存在的木马。
    """
    m = re.search(r"-(?:encodedcommand|enc)\b[:\s]+([A-Za-z0-9+/=]{40,})", cmd, re.I)
    if not m:
        return False
    b64 = m.group(1)
    try:
        raw = base64.b64decode(b64 + "=" * (-len(b64) % 4))
        text = raw.decode("utf-16-le", "ignore")
    except Exception:
        return False
    return _OWN_PS_MARK in text


_OWN_PS_HINT = (
    "\n\n⚠ 该 Base64 解出的内容与本工具自己的 PowerShell 开头一致 —— "
    "极可能是**另一个本工具实例或 tools/ 下的验证脚本**拉起的校验进程，不是恶意行为。"
    "确认后可用「已知项」忽略。"
)


# ================================================================
# T 系列 —— 计划任务
# ================================================================

def rules_tasks(art: dict) -> list[dict]:
    out = []
    for t in art.get("tasks", []):
        fs: list[dict] = []
        tname = t.get("name", "")
        tpath = t.get("path", "") or "\\"
        acts = t.get("actions", []) or []
        execs = [a.get("exec", "") for a in acts if a.get("exec")]
        exec_joined = " | ".join(execs)

        # T001 任务名字面命中 IOC
        for bad in iocs.MALICIOUS_TASK_NAMES:
            if bad.lower() in tname.lower():
                fs.append(finding(
                    "T001", "计划任务名命中银狐 IOC", "critical", 100, "task",
                    f"任务「{tname}」（路径 {tpath}）执行 {exec_joined}",
                    "该任务名在银狐公开报告中明确列出。"))
                break

        # T002 冒用系统更新任务名（必须同时满足"执行目标与该厂商无关"）
        # 初版只看"是否在官方目录列表里"，结果把 Google 的
        # C:\Program Files (x86)\Google\GoogleUpdater\...\updater.exe 误判为冒用。
        # 改为按厂商特征串匹配，兼容厂商子目录结构的变化。
        for pref, tokens in iocs.UPDATE_TASK_VENDOR_TOKENS.items():
            if not tname.lower().startswith(pref.lower()):
                continue
            joined = " ".join(norm(os.path.expandvars(e)) for e in execs)
            if not any(tok in joined for tok in tokens):
                fs.append(finding(
                    "T002", f"冒用系统更新任务名：{pref}", "critical", 92, "task",
                    f"任务「{tname}」以「{pref}」开头，但执行目标为 {exec_joined}，"
                    f"不含该厂商的官方路径特征（应包含 {' 或 '.join(tokens)}）",
                    "CNCERT 报告：银狐注册名为 "
                    "`MicrosoftEdgeUpdateTaskUA Task-S-1-5-18 ...` 的隐藏任务，"
                    "实际执行 C:\\Users\\Public、C:\\ProgramData 下的随机名程序。"))
            break

        # T003 隐藏 + 高频重复 + 目标在非常规目录
        intervals = [g.get("interval", "") for g in (t.get("triggers") or [])]
        short_interval = False
        for iv in intervals:
            m = re.match(r"^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$", iv or "")
            if m:
                mins = int(m.group(1) or 0) * 60 + int(m.group(2) or 0) + int(m.group(3) or 0) / 60
                if 0 < mins <= 30:
                    short_interval = True
        tgt_reason = ""
        for e in execs:
            tgt_reason = nonstandard_target(e)
            if tgt_reason:
                break
        if t.get("hidden") and short_interval and tgt_reason:
            fs.append(finding(
                "T003", "隐藏的高频计划任务指向非常规目录", "high", 88, "task",
                f"任务「{tname}」设为隐藏、重复间隔 ≤30 分钟、执行 {exec_joined}\n"
                f"目标非常规：{tgt_reason}",
                "CNCERT 排查建议：重点检查「每隔 1 至 30 分钟重复执行、设为隐藏且无限期运行」的任务。"))

        # T004 目标位于非常规目录
        hit = ""
        for e in execs:
            hit = nonstandard_target(e)
            if hit:
                break
        # ⚠️ 高权限任务交给 T006 报（它更精确），T004 不重复计分。
        #    实测：同一个任务被 T004(78) + T006(85) 各计一次，
        #    score = 85 + 0.35*78 = 112 → 截断成 100，把"中等置信度"
        #    顶成了"严重 100 分"。同一事实只应计一次分。
        _is_high_priv = t.get("runlevel", "").lower() in ("highest", "highestavailable")
        if (hit and not _is_high_priv
                and not any(f["rule_id"] in ("T001", "T002", "T003") for f in fs)):
            fs.append(finding(
                "T004", "计划任务执行目标位于非常规目录", "high", 78, "task",
                f"任务「{tname}」执行 {exec_joined}（命中 {hit}）",
                "正常软件的计划任务极少直接执行 Users\\Public / ProgramData "
                "或 Program Files 下随机命名目录中的程序。"))

        # T008 隐藏执行脚本 + 脚本或工作目录位于用户可写位置
        #
        # ⚠️ 这条规则补的是一个**实测确认的检测盲区**：
        # 此前的任务规则只看 exec 的路径（T004）与任务名（T001/T002/T005），
        # 完全不检查**动作本身**是否用了"隐藏窗口 + 解释器执行脚本"。
        # 实测：构造 Execute=powershell、
        # Arguments=-Command "Start-Process -WindowStyle Hidden task.bat"、
        # WorkingDirectory=C:\Users\Public\Downloads 的任务，全部规则 0 命中。
        # 而"注册一个隐藏执行脚本的计划任务"正是最经典的持久化手法。
        #
        # 误报控制（关键）：**仅当脚本路径或工作目录落在用户可写位置时才告警**。
        # 实测对照组：Intel 的 USER_ESRV_SVC_QUEENCREEK 任务同样是
        # powershell -Command "Start-Process -WindowStyle Hidden task.bat"，
        # 但工作目录在 C:\Program Files\Intel\... —— 因此不会误报。
        for a in acts:
            ex = os.path.basename((a.get("exec") or "").strip().lower())
            if ex not in _SCRIPT_HOSTS:
                continue
            args = a.get("args") or ""
            la = args.lower()
            if not any(h in la for h in _HIDDEN_FLAGS):
                continue

            ref = ""
            m_ref = _REF_PATH_RE.search(args)
            if m_ref:
                ref = m_ref.group(1)

            reasons = []
            if ref:
                r = _task_writable_hit(ref)
                if r:
                    reasons.append(f"脚本位于用户可写位置（命中 {r}）：{ref}")
            wd = a.get("wd") or ""
            if wd:
                r = _task_writable_hit(wd)
                if r:
                    reasons.append(f"工作目录位于用户可写位置（命中 {r}）：{wd}")
            if not ref and not wd:
                reasons.append("未给出脚本绝对路径与工作目录，实际执行内容无法确定")

            if reasons:
                fs.append(finding(
                    "T008", "计划任务以隐藏方式执行脚本，且目标位于用户可写位置",
                    "high", 80, "task",
                    f"任务「{tname}」执行：{a.get('exec', '')} {args}\n" + "\n".join(reasons),
                    "「注册一个隐藏窗口执行脚本的计划任务」是最常见的持久化手法之一。"
                    "目标落在用户可写目录时，任意程序都能替换该脚本内容，"
                    "从而在每次登录时获得执行机会。"
                    "正常软件的计划任务通常把脚本放在 Program Files 下。"))

        # T005 长英文句子式任务名（AI 生成特征）
        # 误报控制是这条规则的命门：初版只判"长度>28 且词数>=4"，结果把
        # Windows Defender Scheduled Scan / .NET Framework NGEN v4.0.30319 /
        # Office ClickToRun Service Monitor 等 20+ 个合法任务全判成了木马。
        # 现在要求：① 不含数字、括号、点号等符号；② 不含任何厂商名或技术术语。
        #
        # 关键细节：术语必须**按词**匹配，不能按子串 —— 否则
        # "Our Empowering Procedure Standardization And" 里的 "Empowering"
        # 会命中术语 "power" 而被误放过（这是实测踩到的坑）。
        low = tname.lower()
        words_low = re.findall(r"[a-z]+", low)
        tokens = _LEGIT_TASK_TOKEN_SET
        if " " in tname.strip():
            has_legit = any(w in tokens for w in words_low)
        else:
            has_legit = any(tok in low for tok in tokens)
        # 兜底：\Microsoft\Windows\ 下的任务是系统自带的，不参与本规则判定
        # （银狐的同类任务名注册在任务根路径 \ 下，不受影响）
        system_task = "microsoft\\windows" in tpath.lower()
        if (not system_task and len(words_low) >= 3 and len(tname) > 24
                and not re.search(r"[0-9_.(){}\[\]\\/+\-]", tname)
                and not has_legit):
            fs.append(finding(
                "T005", "计划任务名为长英文语句（AI 批量生成特征）", "medium", 45, "task",
                f"任务「{tname}」执行 {exec_joined}\n"
                f"该名称由 {len(words_low)} 个通用英文词拼成，不含任何厂商名或技术术语",
                "CNCERT 报告中的恶意任务名形如 "
                "`Our Empowering Procedure Standardization And`、"
                "`Software Business Prioritization`、"
                "`Assessment Intelligent Data Objective Seamlessly`。"))

        # T006 SYSTEM/Highest 权限 + 非常规目录目标
        if t.get("runlevel", "").lower() in ("highest", "highestavailable") and tgt_reason:
            if not any(f["rule_id"] == "T003" for f in fs):
                fs.append(finding(
                    "T006", "高权限计划任务指向非常规目录", "high", 85, "task",
                    f"任务「{tname}」以 {t.get('runlevel')} 权限（用户 {t.get('userid','')}）"
                    f"执行 {exec_joined}\n目标非常规：{tgt_reason}",
                    "提权 + 非常规目录写入是持久化后门的典型组合。"))

        # T007 系统任务路径下的异常任务
        # 初版判据是"路径含 AppID 且任务名不含 microsoft"，把 EDP Policy Manager、
        # PolicyConverter、VerifiedPublisherCertStoreCheck 等合法 AppID 任务全判成恶意。
        # 改为要求"目标非常规"或"任务名随机"，合法 AppID 任务的目标都是 System32 组件。
        if "appid" in tpath.lower() and (tgt_reason or looks_random(tname)):
            fs.append(finding(
                "T007", "系统任务路径下存在异常任务", "high", 72, "task",
                f"任务路径 {tpath}，任务名「{tname}」，执行 {exec_joined}"
                + (f"\n目标非常规：{tgt_reason}" if tgt_reason else ""),
                "火绒报告：银狐把任务注册到 \\Microsoft\\Windows\\AppID\\ 以伪装成系统任务。"
                "合法 AppID 任务的目标都是 System32 下的系统组件。"))

        if fs:
            score, level = score_findings(fs)
            out.append({
                "kind": "task", "id": f"{tpath}{tname}", "title": tname,
                "subtitle": exec_joined or "（无执行动作）",
                "score": score, "level": level, "findings": fs,
                "hidden": t.get("hidden"), "state": t.get("state"),
                "runlevel": t.get("runlevel"), "userid": t.get("userid"),
                "path": tpath, "execs": execs,
            })
    return out


# ================================================================
# S 系列 —— 系统服务
# ================================================================

def rules_services(art: dict, sig_cache: dict | None = None) -> list[dict]:
    out = []
    for s in art.get("services", []):
        fs: list[dict] = []
        name = s.get("name", "")
        binpath = s.get("binpath", "") or ""
        exe = bin_from_binpath(binpath)
        nb = norm(exe)
        sig_k = path_sig_kind(exe, sig_cache)

        for bad in iocs.MALICIOUS_FILENAMES:
            if bad.lower() in nb:
                fs.append(finding("S001", "服务二进制命中银狐 IOC", "critical", 100, "service",
                                  f"服务 {name} → {binpath}",
                                  "该文件名在银狐公开报告中列出。"))
                break

        hit = nonstandard_target(exe)
        if hit:
            fs.append(finding(
                "S002", "服务二进制位于非常规目录", "high", 85, "service",
                f"服务 {name}（{s.get('display','')}）→ {binpath}\n命中：{hit}",
                "合法服务极少从 Users\\Public、Temp 或随机命名目录加载。"
                "注意：Windows Defender 自身位于 C:\\ProgramData\\Microsoft\\Windows Defender\\，"
                "本工具已将其排除在误判之外。"))

        ext = os.path.splitext(exe)[1].lower()
        if ext in iocs.DISGUISED_EXTENSIONS:
            fs.append(finding(
                "S003", f"服务指向伪装扩展名文件（{ext}）", "high", 80, "service",
                f"服务 {name} → {binpath}",
                "银狐用 .jpg/.dat/.db 等扩展名伪装 PE 载荷。"))

        # S004 必须叠加"签名不可信"，否则 SGuardSvc64 / GameInputSvc / WmiApSrv
        # 这类驼峰式技术命名会被 looks_random 大面积误判。
        base = os.path.splitext(os.path.basename(exe))[0]
        if looks_random(base) and sig_k in UNTRUSTED_KINDS and not fs:
            fs.append(finding(
                "S004", "服务指向随机命名的未签名程序", "medium", 55, "service",
                f"服务 {name} → {binpath}\n文件名「{base}」符合随机命名特征，且签名不可信",
                "银狐组件普遍随机命名且无有效签名。"))

        if fs:
            score, level = score_findings(fs)
            out.append({"kind": "service", "id": name, "title": name,
                        "subtitle": binpath, "score": score, "level": level,
                        "findings": fs, "status": s.get("status"),
                        "start_type": s.get("start_type"), "display": s.get("display")})
    return out


# ================================================================
# D 系列 —— 内核驱动 / BYOVD
# ================================================================

def rules_drivers(art: dict) -> list[dict]:
    out = []
    for d in art.get("drivers", []):
        fs: list[dict] = []
        name = d.get("name", "")
        path = d.get("path", "") or ""
        fname = os.path.basename(path).lower()

        for vd in iocs.VULNERABLE_DRIVERS:
            if fname == vd.lower():
                fs.append(finding(
                    "D001", f"加载了已知易受攻击驱动：{vd}", "critical", 88, "driver",
                    f"驱动 {name}（{d.get('display','')}）→ {path}",
                    "银狐使用 BYOVD（自带易受攻击驱动）关闭安全软件。"
                    "viusctrivial.sys（Adlice TrueSight）已被火绒确认为银狐所用；"
                    "其余为业界已知的可被滥用驱动。若你未安装对应硬件工具，请立即卸载该驱动。"))
                break

        if fname in [os.path.basename(x).lower() for x in iocs.MALICIOUS_FILENAMES]:
            fs.append(finding("D002", "驱动文件名命中银狐 IOC", "critical", 100, "driver",
                              f"驱动 {name} → {path}", "该文件名在银狐报告中列出。"))

        hit = nonstandard_target(path)
        if hit:
            fs.append(finding("D003", "驱动文件位于非常规目录", "high", 80, "driver",
                              f"驱动 {name} → {path}（命中 {hit}）",
                              "合法驱动应位于 System32\\drivers 或 DriverStore。"))

        ext = os.path.splitext(fname)[1].lower()
        if ext in iocs.DISGUISED_EXTENSIONS:
            fs.append(finding(
                "D004", f"驱动文件伪装扩展名（{ext}）", "critical", 95, "driver",
                f"驱动 {name} → {path}",
                "火绒报告：银狐把 viusctrivial.sys 落地并重命名为 C:\\Windows\\Temp\\ranchserv.jpg。"))

        if fs:
            score, level = score_findings(fs)
            out.append({"kind": "driver", "id": name, "title": name,
                        "subtitle": path, "score": score, "level": level,
                        "findings": fs, "state": d.get("state"), "start": d.get("start")})
    return out


# ================================================================
# H 系列 —— hosts
# ================================================================

def rules_hosts(art: dict) -> list[dict]:
    out = []
    entries = art.get("hosts", [])
    vendor_hits, loop_hits = [], []
    for e in entries:
        ip, host = e.get("ip", ""), e.get("host", "")
        if any(v in host for v in iocs.HOSTS_HIJACK_DOMAINS):
            if ip in iocs.HOSTS_HIJACK_TARGETS:
                vendor_hits.append(e)
        if ip in iocs.HOSTS_HIJACK_TARGETS:
            loop_hits.append(e)

    if vendor_hits:
        fs = [finding(
            "H001", "安全厂商域名被劫持到回环地址", "critical", 96, "hosts",
            "；".join(f"{e['ip']} {e['host']}" for e in vendor_hits[:6]),
            "CNCERT 报告：银狐修改 hosts 把 weishi.360.cn、www.360.cn、sd.360.cn "
            "指向 127.0.0.1，阻断用户访问安全软件站点。请立即删除这些条目。")]
        score, level = score_findings(fs)
        out.append({"kind": "hosts", "id": "hosts-hijack",
                    "title": "hosts 文件被恶意篡改", "subtitle": art.get("hosts_path", ""),
                    "score": score, "level": level, "findings": fs})

    non_vendor = [e for e in loop_hits if e not in vendor_hits]
    if non_vendor:
        fs = [finding(
            "H002", "hosts 存在指向回环地址的条目", "medium", 40, "hosts",
            "；".join(f"{e['ip']} {e['host']}" for e in non_vendor[:8]),
            "可能是你自己为屏蔽广告添加的，也可能是恶意劫持。请核对。")]
        score, level = score_findings(fs)
        out.append({"kind": "hosts", "id": "hosts-loopback",
                    "title": "hosts 存在回环劫持条目",
                    "subtitle": art.get("hosts_path", ""),
                    "score": score, "level": level, "findings": fs})
    return out


# ================================================================
# R 系列 —— 注册表 / Defender / 启动项
# ================================================================

def rules_registry(art: dict, sig_cache: dict | None = None) -> list[dict]:
    out = []
    df = art.get("defender") or {}

    # R001 宽泛 Defender 排除路径（精确匹配，见 is_broad_exclusion 的说明）
    broad = [p for p in df.get("paths", []) if is_broad_exclusion(p)]
    if broad:
        fs = [finding(
            "R001", "Defender 排除项包含大范围系统目录", "critical", 94, "registry",
            "；".join(broad[:8]),
            "CNCERT 报告：银狐以 SYSTEM 权限把 C:\\Users、C:\\ProgramData、"
            "C:\\Windows\\System32、C:\\Program Files (x86) 等加入 Defender 排除项，"
            "使整个系统失去防护。合法软件绝不会这样做。请立即清除这些排除项。")]
        score, level = score_findings(fs)
        out.append({"kind": "registry", "id": "defender-broad",
                    "title": "Defender 被大面积排除", "subtitle": "Exclusions\\Paths",
                    "score": score, "level": level, "findings": fs})

    # R002 排除进程命中
    bad_proc = [p for p in df.get("processes", [])
                if p.lower() in [x.lower() for x in iocs.DEFENDER_EXCLUSION_PROCESSES]]
    if bad_proc:
        fs = [finding(
            "R002", "Defender 排除了银狐相关进程", "critical", 92, "registry",
            "；".join(bad_proc),
            "CNCERT 报告：银狐通过 PowerShell 把 xwizard.exe、wuauclt.exe 加入 Defender 进程排除项。")]
        score, level = score_findings(fs)
        out.append({"kind": "registry", "id": "defender-proc",
                    "title": "Defender 排除可疑进程", "subtitle": "Exclusions\\Processes",
                    "score": score, "level": level, "findings": fs})

    # R003 银狐专用注册表键
    for k in art.get("suspicious_reg", []):
        fs = [finding(
            "R003", f"存在银狐专用注册表键：{k['key']}", "critical", 90, "registry",
            f"{k['key']} → " + "；".join(f"{v['name']}={v['value']}" for v in k.get("values", [])[:5]),
            "火绒报告：银狐把数据写入 HKLM\\SOFTWARE\\JDBCC → data 作为持久化/配置存储。")]
        score, level = score_findings(fs)
        out.append({"kind": "registry", "id": k["key"], "title": "银狐专用注册表键",
                    "subtitle": k["key"], "score": score, "level": level, "findings": fs})

    # R004 启动项指向非常规目录 / R004B 启动项命中银狐路径 IOC
    for rk in art.get("run_keys", []):
        val = rk.get("value", "")
        # 加固：先展开环境变量。初版直接正则，`%APPDATA%\...` 形式的启动项
        # 完全不参与路径判定（对抗测试 A10 实测漏检）。
        val_exp = os.path.expandvars(val)
        nval = norm(val_exp)
        fs = []

        # R004B：注册表启动项命中银狐主机侧路径 IOC（如 %APPDATA%\Adobe\h<长数字>.ini）
        ioc_desc = ""
        for pat, desc in _PATH_IOC_PATTERNS:
            if re.search(pat, nval):
                ioc_desc = desc
                break
        if ioc_desc:
            fs.append(finding(
                "R004B", "注册表启动项命中银狐路径 IOC", "critical", 95, "registry",
                f"{rk['key']} → {rk['name']} = {val}\n匹配特征：{ioc_desc}",
                "CNCERT 报告：银狐把 %APPDATA%\\Adobe\\h<长数字>.ini 等载荷路径"
                "写入注册表 Run 键建立持久化。请立即核查。"))

        m = re.search(r'([A-Za-z]:\\[^"]+?\.(?:exe|dll|bat|cmd|ps1|vbs|jpg|dat|db))', val_exp, re.I)
        exe = m.group(1) if m else val_exp
        hit = nonstandard_target(exe)
        if hit:
            fs.append(finding(
                "R004", "注册表启动项指向非常规目录", "high", 75, "registry",
                f"{rk['key']} → {rk['name']} = {val}\n命中：{hit}",
                "启动项可执行文件位于非常规位置，属异常。"))

        if fs:
            score, level = score_findings(fs)
            out.append({"kind": "registry", "id": f"{rk['key']}\\{rk['name']}",
                        "title": f"启动项：{rk['name']}", "subtitle": val,
                        "score": score, "level": level, "findings": fs})

    # R005 启动目录中的可疑文件
    for sf in art.get("startup", []):
        name = sf.get("name", "")
        path = sf.get("path", "")
        base = os.path.splitext(name)[0]
        ext = os.path.splitext(name)[1].lower()
        try:
            import collector
            magic = collector.file_magic(path)
        except Exception:
            magic = None
        sig_k = path_sig_kind(path, sig_cache)
        suspicious = (
            (magic == "PE" and ext in iocs.DISGUISED_EXTENSIONS)          # 伪装扩展名的 PE
            or (looks_random(base) and sig_k in UNTRUSTED_KINDS)          # 随机名 + 未签名
        )
        if suspicious:
            fs = [finding(
                "R005", "开机启动目录存在可疑文件", "high", 78, "registry",
                f"{path}\n文件头：{magic or '未知'}，扩展名 {ext or '无'}，"
                f"签名状态：{sig_k}",
                "火绒报告：银狐把自身以随机名复制到 Startup 目录。")]
            score, level = score_findings(fs)
            out.append({"kind": "registry", "id": path, "title": f"启动目录：{name}",
                        "subtitle": path, "score": score, "level": level, "findings": fs})
    return out


# ================================================================
# F 系列 —— 文件系统落地特征
# ================================================================

_SUSPECT_SCAN_DIRS = [
    os.path.expandvars(r"%PUBLIC%"),
    os.path.expandvars(r"%PROGRAMDATA%"),
    os.path.expandvars(r"%WINDIR%\Temp"),
    os.path.expandvars(r"%TEMP%"),
    # ⚠️ 这里**刻意不包含 %PROGRAMFILES(X86)% 的全量遍历**。
    #    2026-10-05 实测：把整个 Program Files (x86) 按深度 ≤3 走一遍，
    #    会把正常软件目录里的资源文件（扩展名是 .dat/.db/.ico/.ini，
    #    内容其实是 PE）整片报成「伪装扩展名的 PE」——
    #    测试机上因此凭空出现「共 5 个」的严重项（90 分）。
    #    银狐在 Program Files (x86) 的落点是**一级随机命名子目录**
    #    （见 iocs.RANDOM_INSTALL_ROOTS 与 nonstandard_target 的注释），
    #    所以改为只下钻这些随机命名子目录，见 _pf86_random_subdirs()。
]


def _pf86_random_subdirs() -> list[str]:
    """Program Files (x86) 下的**随机命名一级子目录**。

    只扫这些目录，而不是整个 Program Files (x86)：
    既保留"银狐把载荷丢进随机名目录"的检出能力，
    又避免把 MySQL / WXWork / MasterPDF 这类正常软件目录里的
    资源文件当成伪装 PE 批量误报。
    """
    root = os.path.expandvars(r"%PROGRAMFILES(X86)%")
    if not root or not os.path.isdir(root):
        return []
    out = []
    try:
        for name in os.listdir(root):
            sub = os.path.join(root, name)
            if os.path.isdir(sub) and looks_random_dir(name):
                out.append(sub)
    except Exception:
        return out
    return out


def _in_strong_scan_context(dirpath: str) -> bool:
    """F001 用：当前目录是否处于「强信号」上下文。

    强信号 = ① 路径位于 Public / Temp / Downloads / Recycle.Bin 之下，
             或 ② 路径中存在**随机命名**的一层目录（银狐落点特征）。

    为什么要加这道闸：`.dat/.db/.ico/.ini` 这类扩展名承载 PE 内容，
    在正常软件目录里并不罕见（安装缓存、资源打包）。2026-10-05 测试机
    因此在 Program Files (x86) 整片扫出「共 5 个伪装 PE」（严重 90 分）。
    真正需要定罪的是"随机目录 / 用户可写目录"里的伪装 PE ——
    正常软件不会把自己的可执行体藏在 `C:\\ProgramData\\aBcDe1\\x.dat`。
    """
    # ⚠️ 必须按**路径段**匹配（in_dirs），不能用子串包含。
    #    子串匹配会把 `C:\\ProgramData\\Vendor\\TempData`、`...\\Downloads_old`
    #    这类正常软件目录也当成「Temp / Downloads 之下」，
    #    于是把刚刚排除掉的资源文件重新放回 F001 的射程里 ——
    #    正是本次要修的那类误报。项目里已有段级匹配工具，直接用。
    if in_dirs(dirpath, iocs.WRITABLE_DIRS_STRONG):
        return True
    # ⚠️ 这里**不能用 _parts()** —— 它内部走 norm() 会把路径整串小写化，
    #    而 looks_random_dir 恰恰依赖大小写分布，小写化后 bcCfOw → bccfow
    #    会被判成"非随机"（实测踩过）。必须保留原始大小写来切分。
    for part in dirpath.replace("/", "\\").split("\\"):
        if part and looks_random_dir(part):
            return True
    return False


def rules_filesystem(art: dict, max_files: int = 4000) -> list[dict]:
    """扫描银狐常驻目录：识别伪装扩展名的 PE、组合目录特征、IOC 文件名。"""
    out: list[dict] = []
    import collector

    combined_dirs: dict[str, set] = {}
    pe_disguised: list[dict] = []
    ioc_hits: list[dict] = []
    scanned = 0

    for root_dir in (_SUSPECT_SCAN_DIRS + _pf86_random_subdirs()):
        if not root_dir or not os.path.isdir(root_dir):
            continue
        for dirpath, dirnames, filenames in os.walk(root_dir):
            # 限制深度，避免全盘遍历
            depth = dirpath[len(root_dir):].count(os.sep)
            if depth > 3:
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d.lower() not in
                           ("winsxs", "assembly", "installer", "packages",
                            "windowsapps", "microsoft", "windows defender",
                            "node_modules", "cache", "logs")]
            for fn in filenames:
                scanned += 1
                if scanned > max_files:
                    break
                fp = os.path.join(dirpath, fn)
                base, ext = os.path.splitext(fn)
                ext = ext.lower()

                # 组合目录特征（先知社区：edge.xml + edge.jpg + 随机 exe + 同名 .dat）
                combined_dirs.setdefault(dirpath.lower(), set()).add(fn.lower())

                if fn.lower() in [x.lower() for x in iocs.MALICIOUS_FILENAMES]:
                    ioc_hits.append({"path": fp, "name": fn})

                if ext in iocs.DISGUISED_EXTENSIONS and _in_strong_scan_context(dirpath):
                    magic = collector.file_magic(fp)
                    if magic == "PE":
                        pe_disguised.append({"path": fp, "ext": ext, "magic": magic})
            if scanned > max_files:
                break
        if scanned > max_files:
            break

    if pe_disguised:
        fs = [finding(
            "F001", "发现伪装扩展名的可执行文件（PE 头）", "critical", 90, "file",
            "；".join(f"{x['path']}（扩展名 {x['ext']}，实际为 PE 可执行体）" for x in pe_disguised[:8])
            + (f"\n… 共 {len(pe_disguised)} 个" if len(pe_disguised) > 8 else ""),
            "CNCERT / 火绒报告：银狐使用 .jpg/.png/.dat/.db 等扩展名承载 PE 载荷以规避检测。"
            "请用杀毒软件扫描这些文件，确认后删除。")]
        score, level = score_findings(fs)
        out.append({"kind": "file", "id": "pe-disguised", "title": "伪装扩展名的 PE 文件",
                    "subtitle": f"共 {len(pe_disguised)} 个", "score": score,
                    "level": level, "findings": fs})

    if ioc_hits:
        fs = [finding(
            "F002", "发现银狐 IOC 文件名", "critical", 100, "file",
            "；".join(x["path"] for x in ioc_hits[:8]),
            "这些文件名在银狐公开报告中明确列出，请立即隔离。")]
        score, level = score_findings(fs)
        out.append({"kind": "file", "id": "ioc-file", "title": "银狐 IOC 文件",
                    "subtitle": f"共 {len(ioc_hits)} 个", "score": score,
                    "level": level, "findings": fs})

    # 组合目录特征
    combos = []
    for d, names in combined_dirs.items():
        has_xml = "edge.xml" in names
        has_jpg = "edge.jpg" in names
        # 加固：初版只认全小写 [a-z0-9]{5,10}.exe，银狐实际用大小写混合随机名
        # （bcCfOw.exe 型，对抗测试 A6 实测漏检）。改用与 P007 一致的 looks_random。
        rand_exe = any(
            re.fullmatch(r"[A-Za-z0-9]{5,12}\.exe", n) and looks_random(n[:-4])
            for n in names)
        if has_xml and has_jpg and rand_exe:
            combos.append(d)
    if combos:
        fs = [finding(
            "F003", "发现银狐组合落地目录特征", "critical", 95, "file",
            "；".join(combos[:5]) + "\n特征组合：同目录同时存在 edge.xml + edge.jpg + 随机名 .exe",
            "先知社区应急复盘记录的银狐落地结构：一个 edge.xml（去 MZ 头的 PE）、"
            "一个 edge.jpg（内含 shellcode）、一个随机名 exe 及同名 dat。")]
        score, level = score_findings(fs)
        out.append({"kind": "file", "id": "combo-dir", "title": "银狐组合落地目录",
                    "subtitle": f"共 {len(combos)} 处", "score": score,
                    "level": level, "findings": fs})

    return out


# ================================================================
# 深度扫描 —— 针对高风险进程检查加载模块（白加黑 / IOC DLL）
# ================================================================

def deep_scan_process(proc: dict, ctx: dict, treat_unknown_as_bad: bool = False):
    """针对高风险进程检查加载模块（白加黑 / IOC DLL / 伪装扩展名）。

    返回 (findings, pending_sig_paths)：
      pending_sig_paths —— 尚未做签名校验的模块路径，由 server 排队校验。
      未校验完成前不据此定罪（宁漏勿冤），下次签名批次完成后再复查。

    ⚠️ 两条实测踩出来的规则：
    1. **必须按规则聚合，不能每个模块产出一条 finding。**
       初版对每个可疑 DLL 各加一条 X003，pwsh.exe 一次加载 15 个同目录 DLL
       就叠加成 15 条 × 82 分 → 分数直接顶到 100，判成"严重"。
    2. **必须排除 MSIX / Store 应用目录（\\WindowsApps\\）。**
       这类应用的 DLL 由包签名整体保护，**不单独做 Authenticode 签名**。
       实测 pwsh.exe（PowerShell 7，装在 D:\\WindowsApps\\Microsoft.PowerShell_*）
       因此被误判为白加黑。合法应用极少从 WindowsApps 之外加载未签名同目录 DLL。
    """
    import collector
    fs: list[dict] = []
    pending_sigs: list[str] = []
    if ctx.get("self_pid") and proc.get("ppid") == ctx["self_pid"]:
        return fs, pending_sigs
    try:
        detail = collector.enrich_process(proc["pid"])
    except Exception:
        return fs, pending_sigs

    own_dir = norm(proc.get("dir") or "")
    ioc_mods: list[str] = []
    disguised_mods: list[str] = []
    sideload: list[str] = []

    for m in detail.get("modules", []):
        mp = m.get("path", "")
        nmp = norm(mp)
        base = os.path.basename(mp).lower()
        ext = os.path.splitext(base)[1].lower()

        for bad in iocs.MALICIOUS_FILENAMES:
            if base == bad.lower():
                ioc_mods.append(mp)
                break

        if ext in iocs.DISGUISED_EXTENSIONS and collector.file_magic(mp) == "PE":
            disguised_mods.append(mp)

        # 白加黑：模块位于进程自身目录（非系统目录）且签名不可信
        if own_dir and nmp.startswith(own_dir) and ext == ".dll":
            if "\\windowsapps\\" in nmp or "\\windowsapps\\" in own_dir:
                continue          # MSIX / Store 应用：DLL 由包签名保护，跳过
            if in_real_system_dirs(mp):
                continue
            sig = ctx["sig_cache"].get(mp.lower())
            if sig is None:
                # 加固：初版把"还没校验"的 DLL 一律当可疑（sig is None → sideload），
                # 而模块路径从未进入签名校验队列 —— 等于对所有同目录 DLL 无差别指控。
                # 现在改为：排队校验，校验完成前不定罪。
                if treat_unknown_as_bad:
                    sideload.append(mp)
                else:
                    pending_sigs.append(mp)
            elif sig.get("kind") in UNTRUSTED_KINDS:
                sideload.append(mp)

    if ioc_mods:
        fs.append(finding("X001", f"加载银狐 IOC 模块：{os.path.basename(ioc_mods[0])}",
                          "critical", 100, "process",
                          f"PID {proc['pid']}（{proc['name']}）加载了：\n" +
                          "\n".join(ioc_mods[:8]),
                          "该模块名在银狐公开报告中列出。"))
    if disguised_mods:
        fs.append(finding("X002", "加载伪装扩展名的可执行模块", "critical", 95, "process",
                          f"PID {proc['pid']}（{proc['name']}）加载了伪装扩展名的 PE 模块：\n" +
                          "\n".join(disguised_mods[:8]),
                          "银狐把恶意载荷伪装成 .jpg/.dat 等扩展名后映射进内存执行。"))
    if sideload:
        hint = any(os.path.basename(s).lower() in
                   [h.lower() for h in iocs.SIDELOAD_DLL_HINTS] for s in sideload)
        fs.append(finding(
            "X003", f"疑似白加黑侧加载（{len(sideload)} 个同目录未签名 DLL"
                    f"{'，命中侧加载提示名单' if hint else ''}）",
            "critical" if hint else "high", 92 if hint else 82, "process",
            f"{proc['name']} 从自身目录（{proc.get('dir','')}）加载了 "
            f"{len(sideload)} 个未签名 / 签名异常的 DLL：\n" +
            "\n".join(sideload[:6]) + (f"\n… 另有 {len(sideload)-6} 个" if len(sideload) > 6 else ""),
            "银狐核心手法：用带有效签名的合法程序（白文件）从自身目录加载恶意 DLL"
            "（黑文件），形成「白加黑」。请核对该 DLL 的来源与签名。"
            "若该程序是你自行安装的开源/绿色软件，其自带 DLL 未签名属正常现象。"))
    return fs, pending_sigs
