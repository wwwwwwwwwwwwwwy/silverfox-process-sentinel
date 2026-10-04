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

# 程序代码目录（本文件所在目录）
APP_DIR = os.path.dirname(os.path.abspath(__file__))
# 程序根目录：放启动器 .bat、python_path.txt
PROGRAM_DIR = os.path.dirname(APP_DIR)

_DATA_SUBDIR = "SilverFoxSentinel"


def _writable(d: str) -> bool:
    """目录是否存在且真的能写（仅 makedirs 成功不代表能写文件）。"""
    try:
        os.makedirs(d, exist_ok=True)
        probe = os.path.join(d, ".write_probe")
        with open(probe, "w", encoding="ascii") as f:
            f.write("1")
        os.remove(probe)
        return True
    except Exception:
        return False


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
    """给界面/日志用：当前实际使用的目录。"""
    return {
        "app_dir": APP_DIR,
        "program_dir": PROGRAM_DIR,
        "data_dir": DATA_DIR,
        "writable": _writable(DATA_DIR),
        "on_program_dir": os.path.abspath(DATA_DIR) == os.path.abspath(PROGRAM_DIR),
    }
