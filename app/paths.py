# -*- coding: utf-8 -*-
"""
统一的路径解析：**程序目录**（可收紧为只读）与**数据目录**（用户可写）分离。

为什么要分离
------------
程序目录需要收紧为"仅管理员可写"，否则任何登录用户都能改
`python_path.txt`，让启动器去执行他的程序 —— 而监视器根本不会启动，
自检告警永远不出现（详见 README 第九节的威胁模型）。

但程序运行期必须写：端口文件、会话令牌、实例密钥、完整性基线、导出报告。
这些不能落在只读的程序目录里，否则**非管理员运行会直接失败**。

所以：程序代码在 `PROGRAM_DIR`，运行期数据在 `DATA_DIR`。
"""

from __future__ import annotations

import os
import time

# 程序代码目录（本文件所在目录）
APP_DIR = os.path.dirname(os.path.abspath(__file__))
# 程序根目录：放启动器 .bat、python_path.txt
PROGRAM_DIR = os.path.dirname(APP_DIR)

_DATA_SUBDIR = "SilverFoxSentinel"

# 可写性探测的缓存。
#
# ⚠️ 为什么必须缓存（2026-10-07 实测）：`_writable()` 的做法是
#    「建文件 → 写入 → 删掉」，这是一次**真实的磁盘写操作**，
#    本机单次耗时约 **450 ms** —— 文件创建与删除会被杀软的实时防护各拦一道。
#
#    而 `describe()` 会被 `/api/state` 每次轮询调用一次。
#    于是界面每秒凭空卡 450 ms，表现为"点了没反应 / 数据半天不刷新"，
#    看起来像是扫描慢，实际是这一行探测。**这是本次"扫描速度太慢"的第二个真凶**，
#    而且它跟扫描间隔完全无关 —— 把间隔从 3 秒改成 1 秒也不会好一点。
#
#    目录可写性几乎不会变（除非用户去改 ACL），缓存 60 秒足够。
_WRITABLE_CACHE: dict[str, tuple[float, bool]] = {}
_WRITABLE_TTL = 60.0


def _writable(d: str, use_cache: bool = False) -> bool:
    """目录是否存在且真的能写（仅 makedirs 成功不代表能写文件）。

    use_cache=True 时结果缓存 60 秒 —— 给会被高频调用的 describe() 用。
    """
    if use_cache:
        hit = _WRITABLE_CACHE.get(d)
        if hit and (time.monotonic() - hit[0]) < _WRITABLE_TTL:
            return hit[1]
    try:
        os.makedirs(d, exist_ok=True)
        probe = os.path.join(d, ".write_probe")
        with open(probe, "w", encoding="ascii") as f:
            f.write("1")
        os.remove(probe)
        ok = True
    except Exception:
        ok = False
    if use_cache:
        _WRITABLE_CACHE[d] = (time.monotonic(), ok)
    return ok


def data_dir() -> str:
    """返回用户可写的数据目录。

    优先 `%LOCALAPPDATA%\\SilverFoxSentinel`；
    不可写时依次退回 `%TEMP%\\SilverFoxSentinel`、程序目录。
    每次调用都重新判断，便于测试与迁移。
    """
    cands = []
    la = os.environ.get("LOCALAPPDATA")
    if la:
        cands.append(os.path.join(la, _DATA_SUBDIR))
    cands.append(os.path.join(os.path.expanduser("~"), "." + _DATA_SUBDIR))
    tmp = os.environ.get("TEMP") or os.environ.get("TMP")
    if tmp:
        cands.append(os.path.join(tmp, _DATA_SUBDIR))
    cands.append(PROGRAM_DIR)          # 最后兜底：退回程序目录（仍能跑，只是可被写）
    for c in cands:
        if _writable(c):
            return c
    return PROGRAM_DIR


DATA_DIR = data_dir()

# 运行期数据（用户可写）
WHITELIST_FILE = os.path.join(DATA_DIR, "whitelist.json")
REPORT_DIR = os.path.join(DATA_DIR, "reports")
BASELINE_FILE = os.path.join(DATA_DIR, "integrity.baseline.json")
INSTANCE_SECRET_FILE = os.path.join(DATA_DIR, "instance.secret")
PORT_FILE = os.path.join(DATA_DIR, "runtime_port.txt")
TOKEN_FILE = os.path.join(DATA_DIR, "runtime_token.txt")
WINDOW_PROFILE_DIR = os.path.join(DATA_DIR, ".app-window")

# 程序目录里的配置（收紧后普通用户不可写，因此只读使用）
PYTHON_PATH_FILE = os.path.join(PROGRAM_DIR, "python_path.txt")


def ensure_dirs() -> None:
    """确保运行期需要的目录存在。"""
    for d in (DATA_DIR, REPORT_DIR):
        try:
            os.makedirs(d, exist_ok=True)
        except Exception:
            pass


def describe() -> dict:
    """给界面/日志用：当前实际使用的目录。

    ⚠️ 这里的 _writable 必须走缓存：本函数被 /api/state 每次轮询调用，
    直接探测会在磁盘上做一次「建-写-删」，本机实测 450 ms/次（见 _writable 注释）。
    """
    return {
        "app_dir": APP_DIR,
        "program_dir": PROGRAM_DIR,
        "data_dir": DATA_DIR,
        "writable": _writable(DATA_DIR, use_cache=True),
        "on_program_dir": os.path.abspath(DATA_DIR) == os.path.abspath(PROGRAM_DIR),
    }
