# -*- coding: utf-8 -*-
"""
安全事件留痕 —— 追加式本地日志。

## 为什么必须有这个文件

告警时间线原本**只存在内存里**，重启就清空。这在红队审计里被明确点出来过
（README 3.15 的反面清单第 5 条：「不要用重启来清告警 —— 那会把取证链自己剪断」）。
现实里更糟：用户遇到可疑情况的第一反应往往是"重启一下看看"，
而重启恰好把唯一的证据擦掉了。

有了日志文件之后：

  · 重启后可以把最近的安全事件读回时间线，取证链不断；
  · 「程序文件被改动」「受监控文件被改动」「规则被加进已知项」
    这些**低频但重要**的事件有了持久的、可被第三方查看的记录；
  · 用户可以把日志直接发给别人（或贴进工单），而不必口述。

## 边界（说清楚，别让人误以为这是不可篡改的）

日志就在数据目录里，**同权限的攻击者可以删改它**。
它不是审计级存储（那需要远程 syslog / WORM 介质）。
它的价值是「防遗忘、防误操作、便于转述」，不是「防定向对抗」。
真要防篡改，得把日志实时写到另一台机器上。
"""

from __future__ import annotations

import json
import os
import threading
import time

import paths

LOG_DIR = os.path.join(paths.DATA_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "security.log")
# 单文件上限，超过就滚成 .1（只保留一代，安全日志不该无限膨胀）
MAX_BYTES = 2 * 1024 * 1024
KEEP_LINES_ON_READ = 400

_LOCK = threading.RLock()


def _ensure() -> None:
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except Exception:
        pass


def _rotate_if_needed() -> None:
    try:
        if os.path.getsize(LOG_FILE) < MAX_BYTES:
            return
    except Exception:
        return
    # 只保留一代。用 os.replace 而不是先删后建 —— 中途失败也不会丢日志。
    try:
        os.replace(LOG_FILE, LOG_FILE + ".1")
    except Exception:
        pass


def write(kind: str, level: str, title: str, detail: str = "",
          extra: dict | None = None) -> None:
    """追加一条事件。任何异常都被吞掉 —— 日志失败绝不能影响检测本身。

    ⚠️ 附加字段走**显式的 extra 字典**，不用 `**kwargs`。
    原因是一次实测踩坑：写成 `**extra` 时，调用方传 `kind="changed"`
    会与第一个形参 `kind` 撞名，直接抛
    `TypeError: write() got multiple values for argument 'kind'` ——
    而这条异常又被本函数自己的 try/except 吞掉，
    最终表现是**告警正常出现、日志里却什么都没有**，极难发现。
    改成显式字典后这类撞名从结构上不可能发生；
    同时保留"不覆盖已有字段"的规则作为第二道保险。
    """
    rec = {
        "ts": round(time.time(), 3),
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "kind": kind,          # integrity / watch / whitelist / config / startup
        "level": level,        # critical / high / medium / low / info
        "title": title,
        "detail": detail,
    }
    for k, v in (extra or {}).items():
        if k not in rec:       # 第二道保险：附加字段一律不得覆盖核心字段
            rec[k] = v
    try:
        _ensure()
        with _LOCK:
            _rotate_if_needed()
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


def tail(limit: int = KEEP_LINES_ON_READ) -> list[dict]:
    """读回最近若干条（新的在后）。用于重启后恢复时间线。"""
    out: list[dict] = []
    try:
        with _LOCK:
            with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        continue
    except Exception:
        return []
    return out[-limit:]


def stats() -> dict:
    try:
        return {"path": LOG_FILE, "bytes": os.path.getsize(LOG_FILE),
                "exists": True}
    except Exception:
        return {"path": LOG_FILE, "bytes": 0, "exists": False}
