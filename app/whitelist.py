# -*- coding: utf-8 -*-
"""
已知项（白名单）机制 —— 让用户可以安全地"忽略某条告警"，而不是直接改规则

## 为什么不建议"把误报当 bug 划入正常"

直接改规则或按规则号全局忽略，会连**真正的攻击**一起放过。
例如 `P011`（命令行静默绕过 PowerShell 策略）正是银狐的常用手法，
如果把 P011 整条关掉，攻击者用同样的命令行就再也报不出来。

## 本机制怎么做才安全

一条已知项 = 「规则号」+「匹配条件」+「**守卫文件的哈希**」三者的组合，三个都满足才忽略：

- 匹配条件限定到**具体对象**（如命令行里必须含 `my-watchdog.ps1`），
  而不是"凡是 P011 都不报"；
- 守卫哈希绑定**被执行的脚本文件**。脚本内容一旦变化（哪怕只改一个字节），
  哈希对不上 → 忽略失效 → 告警立刻回来。
  这样即使攻击者替换了那个脚本，也不会被静默放过。

## 已知的局限（必须说清）

`whitelist.json` 与程序同目录，能改程序的人也能改它。
缓解措施：该文件位于 `app/` 下，**已被完整性自检覆盖** ——
被篡改会在界面上触发「程序文件已被改动」的严重告警。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time

import paths

# 放在**数据目录**而不是 app/ 下：程序目录要收紧为只读，写不进去。
# 它仍然受完整性自检保护 —— 通过 server._integrity_extras() 纳入基线。
WHITELIST_FILE = paths.WHITELIST_FILE

# 从命令行里能识别出的"可执行文件"扩展名 —— 用于自动挑守卫文件
GUARD_EXTS = (".ps1", ".bat", ".cmd", ".vbs", ".js", ".exe", ".dll", ".py")

MATCH_TYPES = {
    "cmdline_contains": "命令行包含指定文本",
    "exe_path": "可执行文件路径完全相同",
    "exe_path_prefix": "可执行文件路径以指定前缀开头",
    "subject_text_contains": "对象信息（路径/命令行/名称/标题）包含指定文本",
    "rule_only": "仅按规则号匹配（需谨慎，建议配合守卫哈希）",
}


def _sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 256), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def load() -> dict:
    """读取已知项。

    文件不存在时会**主动创建**一个空表 —— 这不是多余的：
    whitelist.json 位于 app/ 下、被完整性自检覆盖，如果它"有时存在有时不存在"，
    基线就会在 removed/added 之间反复跳，界面一直显示"程序文件已被改动"（实测踩过）。
    让它始终存在，正常使用下基线就永远对得上；
    而真有人绕过界面改它，内容变化仍会触发篡改告警。
    """
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict) and isinstance(d.get("entries"), list):
            return d
    except FileNotFoundError:
        d = {"version": 1, "entries": []}
        try:
            save(d)
        except Exception:
            pass
        return d
    except Exception:
        pass
    return {"version": 1, "entries": []}


def save(d: dict) -> None:
    with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)


def _subject_text(subject: dict) -> str:
    parts = []
    for k in ("exe", "dir", "cmdline_str", "name", "title", "subtitle", "id", "path"):
        v = subject.get(k)
        if isinstance(v, str) and v:
            parts.append(v)
    return "\n".join(parts)


def entry_matches(entry: dict, finding: dict, subject: dict) -> bool:
    """三个条件全部满足才算命中：规则号 + 匹配条件 + 守卫哈希。"""
    if entry.get("rule_id") != finding.get("rule_id"):
        return False

    m = entry.get("match") or {}
    mt, mv = m.get("type", ""), (m.get("value") or "")
    if mt == "cmdline_contains":
        if mv.lower() not in (subject.get("cmdline_str") or "").lower():
            return False
    elif mt == "exe_path":
        if (subject.get("exe") or "").lower() != mv.lower():
            return False
    elif mt == "exe_path_prefix":
        if not (subject.get("exe") or "").lower().startswith(mv.lower()):
            return False
    elif mt == "subject_text_contains":
        if mv.lower() not in _subject_text(subject).lower():
            return False
    elif mt == "rule_only":
        pass
    else:
        return False

    # 守卫：文件必须存在且哈希一致，否则忽略失效（脚本被改动 → 告警回来）
    g = entry.get("guard") or {}
    if g.get("file"):
        cur = _sha256(g["file"])
        if not cur or cur != g.get("sha256"):
            return False
    return True


def filter_findings(findings: list[dict], subject: dict,
                    wl: dict | None = None) -> tuple[list[dict], list[dict]]:
    """返回 (保留的 findings, 被忽略的 findings)。"""
    wl = wl if wl is not None else load()
    entries = wl.get("entries") or []
    if not entries or not findings:
        return findings, []
    kept, dropped = [], []
    for f in findings:
        hit = None
        for e in entries:
            if entry_matches(e, f, subject):
                hit = e
                break
        if hit:
            dropped.append({**f, "_whitelist_id": hit.get("id"),
                            "_whitelist_note": hit.get("note", "")})
        else:
            kept.append(f)
    return kept, dropped


def guess_guard_file(subject: dict) -> str:
    """从命令行/证据里挑出最可能的"被执行脚本"，用于绑定哈希。"""
    text = (subject.get("cmdline_str") or "") + "\n" + (subject.get("exe") or "")
    cands = []
    for m in re.finditer(r'([A-Za-z]:\\[^"\'<>|\r\n]+?\.(?:ps1|bat|cmd|vbs|js|exe|dll|py))',
                         text, re.I):
        p = m.group(1).strip().rstrip("\\")
        if os.path.isfile(p):
            cands.append(p)
    if not cands:
        return ""
    # 优先脚本类扩展名（比解释器本身更贴近"被执行的载荷"）
    for ext in (".ps1", ".bat", ".cmd", ".vbs", ".js"):
        for c in cands:
            if c.lower().endswith(ext):
                return c
    return cands[0]


def suggest(subject: dict, finding: dict) -> dict:
    """给界面用：根据对象与命中规则，生成一条建议的已知项（含守卫哈希）。"""
    guard = guess_guard_file(subject)
    exe = subject.get("exe") or ""
    cmd = subject.get("cmdline_str") or ""

    if guard:
        mt, mv = "cmdline_contains", os.path.basename(guard)
    elif cmd:
        # 取命令行里最有辨识度的一段（跳过解释器名）
        toks = [t for t in cmd.split() if len(t) > 6 and not t.lower().endswith(".exe")]
        mt, mv = "cmdline_contains", (toks[0] if toks else cmd[:40])
    elif exe:
        mt, mv = "exe_path", exe
    else:
        mt, mv = "rule_only", ""

    return {
        "rule_id": finding.get("rule_id", ""),
        "match": {"type": mt, "value": mv},
        "guard": ({"file": guard, "sha256": _sha256(guard)} if guard
                  else {"file": "", "sha256": ""}),
        "note": "",
    }


def add(rule_id: str, match_type: str, match_value: str,
        guard_file: str = "", note: str = "") -> dict:
    d = load()
    eid = "wl-" + time.strftime("%Y%m%d-%H%M%S")
    entry = {
        "id": eid,
        "rule_id": rule_id,
        "match": {"type": match_type, "value": match_value},
        "guard": {"file": guard_file, "sha256": _sha256(guard_file) if guard_file else ""},
        "note": note or "",
        "added": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    d.setdefault("entries", []).append(entry)
    save(d)
    return entry


def remove(entry_id: str) -> bool:
    d = load()
    before = len(d.get("entries") or [])
    d["entries"] = [e for e in (d.get("entries") or []) if e.get("id") != entry_id]
    if len(d["entries"]) == before:
        return False
    save(d)
    return True


def listing() -> dict:
    d = load()
    out = []
    for e in d.get("entries") or []:
        g = e.get("guard") or {}
        # 只对存在且不太大的文件算哈希（listing 会被 /api/state 每 2 秒调用一次）
        gf = g.get("file") or ""
        cur = ""
        if gf and os.path.isfile(gf) and os.path.getsize(gf) <= 8 * 1024 * 1024:
            cur = _sha256(gf)
        out.append({
            **e,
            "guard_ok": (not g.get("file")) or (bool(cur) and cur == g.get("sha256")),
            "guard_exists": bool(g.get("file")) and os.path.isfile(g["file"]),
        })
    return {"file": WHITELIST_FILE, "match_types": MATCH_TYPES, "entries": out}
