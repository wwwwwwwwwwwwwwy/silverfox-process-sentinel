# -*- coding: utf-8 -*-
"""
IOC 库 —— 银狐（SilverFox）木马检测指标

数据来源（均为公开权威报告，2026-10 整理）：
  1. CNCERT & 天融信《关于"银狐"木马"甲蚁（G01）团伙攻击态势深入分析报告》2026-09
  2. FreeBuf《深度拆解银狐木马：七阶段攻击链与防御盲区分析》2026-03
  3. 火绒安全实验室《层层伪装 暗藏玄机——银狐木马借正规驱动静默接管》2026-07
  4. 先知社区《银狐处置及分析》应急复盘
  5. 博客园《HTTPS 隧道里的银狐：DoH 隐蔽通信木马全链路逆向分析》2026-10

⚠️ 重要：银狐是"黑产 SaaS"式持续迭代的家族，服务端按次打包载荷（同名文件哈希不同），
   基于文件哈希与固定文件名的黑名单拦截基本失效。本文件中的 IOC 只是"加分项"，
   真正的检出能力来自 rules.py 中的行为规则。IOC 请定期更新。
"""

# ---------------------------------------------------------------- 版本
IOC_VERSION = "2026.10.04-r2"
IOC_SOURCES = [
    "CNCERT/天融信 · 银狐「甲蚁(G01)」团伙分析报告 2026-09",
    "FreeBuf · 银狐七阶段攻击链分析 2026-03",
    "火绒安全实验室 · 银狐 BYOVD 借正规驱动 2026-07",
    "先知社区 · 银狐处置及分析",
    "博客园 · 银狐 DoH 隐蔽通信逆向分析 2026-10",
]

# ================================================================
# 一、高置信文件 IOC（专属性强，误报概率低）
# ================================================================
MALICIOUS_FILENAMES = [
    # --- 火绒 2026-07 样本（借 Adlice TrueSight 驱动 BYOVD）---
    "thumbs!Edge",
    "mmHjOx.exe",
    "vdi_ipc.dat",
    "npwzwmc64.dll",
    "stage3_synccreate_dll.dll",
    "viusctrivial.sys",
    "ranchserv.jpg",
    "PhilipsSpeechDriverConfiguration.exe",
    "FOM-50.jpg", "FOM-51.jpg", "FOM-52.jpg", "FOM-53.jpg",
    # --- CNCERT G01 团伙样本 ---
    "bcCfOw.exe", "UxEnhance64.dll", "msadox.tb", "adoresd.dat",
    "VBV4HZ.exe", "XPSPLOG.dll",
    "XsOewfN.exe", "Pl6VgrWG.exe", "O02PwqGh.exe", "DnsrvKyi.exe",
    "instell_s2.0.03.exe", "instell_s2.0.04.exe",
    "scuttled.dll", "venwin.lock",
    # --- DoH 变种样本 ---
    "wjcapture.dll",
    "ldplayer9_ld_112_ld.exe",
    # --- 通用高辨识组件名 ---
    "updated.ps1",
]
# 注：原 MALICIOUS_FILENAMES_CONDITIONAL（edge.xml/edge.jpg/kill.bat 等低置信名单）
# 从未被任何规则引用，已删除。edge.xml/edge.jpg 组合由 F003 组合目录规则覆盖，
# kill.bat 由 P021 路径 IOC 覆盖。

# ================================================================
# 二、网络 IOC
# ================================================================
MALICIOUS_DOMAINS = [
    # CNCERT G01
    "download.hzx.me",
    "02bbe6.oss-cn-beijing.aliyuncs.com",
    "mm2027.oss-cn-hangzhou.aliyuncs.com",
    "new2027.oss-cn-hongkong.aliyuncs.com",
    "tianqixiazai.oss-cn-hongkong.aliyuncs.com",
    # FreeBuf 案例
    "update.tj5dde.com",
    "zhong.2j3j.xyz",
    # DoH 变种
    "oidng2.duoshit.com",
]
MALICIOUS_IPS = [
    "14.128.53.194",     # CNCERT G01 C2
    "47.243.152.51",     # CNCERT G01 C2
    "8.218.106.149",     # 火绒样本 C2
]
# 银狐常用非标 C2 端口（配合"非浏览器进程外联"判定）
SUSPICIOUS_PORTS = [18300, 7000, 8001, 8443, 6001, 9999, 12345]

# 公共 DoH 解析器（P019 用）。博客园 2026-10 报告确认银狐 DoH 变种用
# 223.5.5.5 / 8.8.8.8；其余为常见 DoH 端点，规则要求"未签名 + 非浏览器"
# 双条件，误报风险低。
DOH_RESOLVERS = [
    "223.5.5.5", "8.8.8.8", "1.1.1.1", "9.9.9.9",
    "223.6.6.6", "119.29.29.29", "180.76.76.76",
    "208.67.222.222", "208.67.220.220", "94.140.14.14",
]

# ================================================================
# 三、签名特征
# ================================================================
# 被伪造/滥用的签名主体（出现即为高危）
ABUSED_SIGNERS = [
    "Speech Processing Solutions GmbH",   # 白加黑白文件（Philips Speech Driver）
    "Bytedance Pte. Ltd.",                # 伪造签名（摘要校验失败）
    "Adlice",                             # TrueSight 反 rootkit 驱动
]
# 注：原 TRUSTED_SIGNERS 名单从未被任何规则引用（死代码），且"按签名主体名
# 反向排除"会引入可被伪造的绕过路径（攻击者可以用任意 CN 自制证书），故删除。

# ================================================================
# 四、持久化 IOC
# ================================================================
# 计划任务名（字面匹配）
MALICIOUS_TASK_NAMES = [
    "fX8Ia",
    "MicrosoftEdgeUpdateTaskUA Task-S-1-5-18",
    "MicrosoftEdgeUpdateTaskUA Task-S-1-5-18 9Gkjk",
    "MicrosoftEdgeUpdateTaskUA Task-S-1-5-18 gsWzP",
    "Our Empowering Procedure Standardization And",
    "Software Business Prioritization",
    "Assessment Intelligent Data Objective Seamlessly",
]
# 被冒用的合法更新任务名前缀 → 该任务"应该"指向的厂商路径特征
# 判定逻辑：任务名命中前缀，但执行路径不含对应厂商特征 → 冒用
# （原 LEGIT_UPDATE_TASK_PREFIXES / LEGIT_UPDATE_TASK_DIRS 从未被引用，已删除，
#   实际生效的是本字典与 T002 规则。）
UPDATE_TASK_VENDOR_TOKENS = {
    "MicrosoftEdgeUpdateTask": [r"microsoft\edge"],
    "MicrosoftEdgeUpdate": [r"microsoft\edge"],
    "GoogleUpdateTask": [r"google"],
    "GoogleUpdate": [r"google"],
    "Adobe Acrobat Update": [r"adobe"],
    "OfficeBackgroundTaskHandler": [r"microsoft office", r"microsoft shared"],
}

# T005 用：合法计划任务名里几乎必然出现的词。
# 银狐的 AI 生成式任务名（"Our Empowering Procedure Standardization And"）
# 不含任何下列词汇 —— 这是把误报压下去的关键。
LEGIT_TASK_TOKENS = [
    "microsoft", "windows", "win", "google", "edge", "chrome", "office", "onedrive",
    "teams", "outlook", "adobe", "acrobat", "reader", "intel", "nvidia", "amd",
    "realtek", "asus", "dell", "hp", "lenovo", "samsung", "apple", "oracle", "java",
    "mozilla", "firefox", "steam", "valve", "ubisoft", "epic", "tencent", "wechat",
    "aliyun", "alibaba", "baidu", "wps", "kingsoft", "huorong", "qihoo", "360",
    "dropbox", "slack", "zoom", "discord", "telegram", "jetbrains", "pycharm",
    "defender", "security", "antivirus", "firewall", "update", "updater", "upgrade",
    "maintenance", "scan", "cleanup", "clean", "verification", "verify", "cache",
    "sync", "synchronize", "synchronization", "backup", "restore", "recovery",
    "logon", "logoff", "startup", "shutdown", "boot", "idle", "register", "registration",
    "install", "uninstall", "service", "monitor", "policy", "task", "refresh",
    "check", "report", "telemetry", "appraiser", "compatibility", "customer",
    "experience", "feedback", "licensing", "license", "activation", "content",
    "delivery", "notification", "push", "background", "scheduled", "periodic",
    "health", "storage", "file", "filesystem", "network", "device", "driver",
    "firmware", "bios", "power", "battery", "display", "audio", "print", "printer",
    "history", "index", "search", "language", "input", "media", "photo", "music",
    "data", "integrity", "tier", "tiers", "management", "manager", "folders",
    "folder", "work", "works", "profile", "template", "rights", "rms", "ad",
    "credential", "credentials", "exploit", "guard", "mdm", "reboot", "install",
    "optimization", "optimize", "performance", "system", "system32", "framework",
    "net", "ngen", "runtime", "component", "components", "library", "helper",
    "host", "client", "server", "agent", "proxy", "gateway", "cloud", "account",
    "user", "users", "local", "machine", "core", "critical", "priority", "error",
    "debug", "trace", "log", "logs", "diagnostic", "diagnostics", "support",
    "assistant", "center", "centre", "control", "panel", "settings", "config",
    "configuration", "provisioning", "enrollment", "compliance", "audit", "sentinel",
    "graphics", "display", "sound", "camera", "bluetooth", "wireless", "wifi",
    "vpn", "remote", "desktop", "session", "process", "kernel", "memory", "disk",
    # 2026-10-04 实测补充：BitLocker / Sysprep 等 Windows 内置任务名
    "encrypt", "encryption", "decrypt", "cipher", "bitlocker", "sysprep",
    "generalize", "driver", "drivers", "defrag", "chkdsk", "mount", "volume",
    "partition", "dedup", "shadow", "copy", "snapshot", "replica", "cluster",
]

# 银狐使用的注册表持久化位置
MALICIOUS_REG_KEYS = [
    r"SOFTWARE\JDBCC",                       # 火绒样本：HKLM\SOFTWARE\JDBCC → data
    r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
    r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
]
# 会被木马写入的宽泛 Defender 排除路径（出现即高危）
BROAD_DEFENDER_EXCLUSIONS = [
    r"C:\Users", r"C:\Users\Public", r"C:\ProgramData",
    r"C:\Windows\System32", r"C:\Windows\Temp",
    r"C:\Program Files", r"C:\Program Files (x86)",
]
# 被加入 Defender 排除的进程名（银狐专用）
DEFENDER_EXCLUSION_PROCESSES = ["xwizard.exe", "wuauclt.exe"]

# ================================================================
# 五、驱动（BYOVD）
# ================================================================
VULNERABLE_DRIVERS = [
    # 银狐确认使用
    "viusctrivial.sys",     # Adlice TrueSight 反 rootkit 驱动（2026-07 火绒）
    # 通用 BYOVD 名单（攻击者常备，非银狐专属）
    "dbutil_2_3.sys", "dbutil.sys", "iqvw64e.sys", "gdrv.sys", "gdrv2.sys",
    "winring0.sys", "winring0x64.sys", "speedfan.sys", "throttlestop.sys",
    "rtcore64.sys", "asrdrv101.sys", "asrdrv103.sys", "eneio64.sys",
    "enetechio64.sys", "msio64.sys", "phymemx64.sys", "hw rwdrv.sys",
    "hw_rwdrv.sys", "cpuz141.sys", "nvflash.sys", "atsziodriver.sys",
    "kprocesshacker.sys", "winio.sys", "naldrv.sys", "physmem.sys",
    "iomap64.sys", "kis8.sys", "piddrv.sys", "amd64.sys",
]
# 注：原 MALICIOUS_DEVICE_NAMES（TrueSight 设备名）因缺少可靠的
# 进程设备句柄枚举手段而未使用，已删除。

# ================================================================
# 六、进程行为特征
# ================================================================
# 系统进程名 → 允许的合法父进程（父进程不符即为 PPID 欺骗/伪装）
SYSTEM_PROCESS_PARENTS = {
    "svchost.exe":    {"services.exe"},
    "lsass.exe":      {"wininit.exe"},
    "services.exe":   {"wininit.exe"},
    "wininit.exe":    {"smss.exe"},
    "csrss.exe":      {"smss.exe", "wininit.exe"},
    "smss.exe":       {"system", "smss.exe"},
    "winlogon.exe":   {"smss.exe"},
    "taskhostw.exe":  {"svchost.exe"},
    "spoolsv.exe":    {"services.exe"},
    "dwm.exe":        {"winlogon.exe", "csrss.exe"},
    "explorer.exe":   {"userinit.exe", "winlogon.exe"},
    "runtimebroker.exe": {"svchost.exe", "explorer.exe"},
    "sihost.exe":     {"svchost.exe", "explorer.exe"},
}
# P002B 用：其子进程"理应"是系统组件的父进程名。
# 注意：刻意不含 explorer.exe —— 用户启动的一切程序都是它的子进程，不能作为指控依据。
SYSTEM_SPAWNERS = {
    "services.exe", "wininit.exe", "winlogon.exe", "smss.exe", "csrss.exe", "svchost.exe",
}
# 系统进程名允许出现的合法目录
SYSTEM_PROCESS_DIRS = [
    r"\Windows\System32", r"\Windows\SysWOW64", r"\Windows\WinSxS",
    r"\Windows\servicing", r"\Windows\SystemApps",
]
# 个别系统进程的额外合法位置（explorer.exe 正常就住在 C:\Windows 根目录）
# 个别系统进程的额外合法位置。
#
# ⚠️ 这里必须写 **绝对路径或环境变量**（如 %WINDIR%），不能写 \Windows 这种相对片段。
# 原因：本项目的目录匹配已从「子串包含」改为「前缀锚定」（见 rules.in_anchor_dirs），
# 而 \Windows 这个相对片段在锚定匹配下永远匹配不上绝对路径 C:\Windows\explorer.exe，
# 会让这条例外**静默失效** —— explorer.exe 因此被误判为「伪装系统进程」（严重 95 分）。
# 这是把匹配方式从子串改成锚定时漏改数据导致的回归，2026-10-04 修复。
SYSTEM_PROCESS_EXTRA_DIRS = {
    "explorer.exe": [r"%WINDIR%"],
}

# 用户可写 / 非常规执行目录（银狐常驻）
WRITABLE_DIRS = [
    r"\Users\Public", r"\ProgramData", r"\Windows\Temp", r"\Temp",
    r"\AppData\Local\Temp", r"\AppData\Roaming", r"\AppData\Local",
    r"\Downloads", r"\Desktop", r"\Documents", r"$Recycle.Bin",
    r"\Windows\Tasks", r"\Windows\Debug", r"\Windows\Media",
    r"\Program Files\Common Files\scvhost.exe",
    r"\Microsoft\EdgeUpdate\Log",
]
# 强信号目录：正常软件几乎不会从这里运行，命中即可疑（不依赖签名）
WRITABLE_DIRS_STRONG = [
    r"\Users\Public", r"\Windows\Temp", r"\Temp",
    r"\AppData\Local\Temp", r"\Downloads", r"$Recycle.Bin",
    r"\Windows\Tasks", r"\Windows\Debug",
]
# 银狐偏好的二级安装目录（随机目录 + Program Files (x86)）
RANDOM_INSTALL_ROOTS = [r"\Program Files (x86)", r"\Program Files"]

# 高危命令行片段（正则片段，大小写不敏感）
# 注：原 SUSPICIOUS_CMDLINE_PATTERNS / SECURITY_VENDOR_TOKENS / MUTEX_NAMES /
# MALICIOUS_DEVICE_NAMES 四个名单从未被任何规则引用（死代码）。
# 其中 bcdedit 破坏恢复、sc 停安全服务、icacls 改 ACL、net user 建账户、
# Stop-Process 杀安全软件等模式已合并进 rules.py 的 P013/P014，
# 其余（互斥体、设备名）因缺少可靠采集手段而删除。

# ================================================================
# 七、hosts 劫持
# ================================================================
HOSTS_HIJACK_DOMAINS = [
    "weishi.360.cn", "www.360.cn", "sd.360.cn", "360.cn",
    "huorong.cn", "www.huorong.cn",
    "rising.com.cn", "www.rising.com.cn",
    "qianxin.com", "sangfor.com.cn", "venustech.com.cn",
    "microsoft.com", "windowsupdate.com", "defender.microsoft.com",
    "kaspersky.com", "eset.com", "bitdefender.com",
]
HOSTS_HIJACK_TARGETS = ["127.0.0.1", "0.0.0.0", "::1"]

# ================================================================
# 八、其他
# ================================================================
# 白加黑侧加载常见被劫持 DLL 名（借用合法组件名前缀伪装）
# X003 命中本名单的 DLL 时升级为 critical（92 分）
SIDELOAD_DLL_HINTS = [
    "jcapture.dll", "wjcapture.dll", "libcurl.dll", "version.dll",
    "duser.dll", "lz32.dll", "npwzwmc64.dll", "XPSPLOG.dll",
    "UxEnhance64.dll", "scuttled.dll",
]
# 银狐文件类型伪装扩展名（实际为 PE/加密载荷）
DISGUISED_EXTENSIONS = [".jpg", ".png", ".dat", ".db", ".tb", ".ini", ".ico", ".xml", ".log", ".tmp"]
