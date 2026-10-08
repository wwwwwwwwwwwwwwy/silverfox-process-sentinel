# -*- coding: utf-8 -*-
"""把**历史告警里记录的原始命令行**喂给当前规则，逐条对照 —— 误报回归的取证工具。

## 为什么必须用这个方法

界面上"全是爆红"的那些告警，其对应进程**早已退出**。
所以拿**当前进程快照**去复算规则**根本不会命中** ——
这并不能证明误报被修好了，只能说明"现在没进程了"。
这是一个很容易上当的排查误区：看到"0 命中"就以为规则没问题。

真正有意义的是：把当初触发告警的那串命令行**原样**再跑一遍规则，
看它**现在**还会不会报警。

## 数据来源

运行实例的 `/api/state`（或存下来的快照 JSON）里
`alerts[].rules[].evidence`，其形如 `命令行：<原文>`。

## 用法

    python tools/verify_history.py                      # 自动找运行中的实例
    python tools/verify_history.py <state.json>         # 用存下来的快照
    python tools/verify_history.py <app 目录> <state.json>   # 显式指定

退出码：0 = 全部误报已消除；1 = 仍有残留。
"""
from __future__ import annotations

import ast
import io
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common  # noqa: E402


def extract_cmd_rules(app: str) -> dict:
    """从 rules.py 里取出 cmd_rules 的正则 —— 保证测的是**真代码**，不是手抄副本。"""
    src = io.open(os.path.join(app, "rules.py"), encoding="utf-8").read()
    pats = {}
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name) and t.id == "cmd_rules":
                    for elt in n.value.elts:
                        if isinstance(elt, ast.Tuple) and len(elt.elts) >= 5:
                            pats[elt.elts[1].value] = (elt.elts[0].value,
                                                       elt.elts[3].value,
                                                       elt.elts[4].value)
    return pats


def load_state(argv: list) -> dict:
    args = [a for a in argv[1:] if not a.startswith("-")]
    if len(args) >= 2:
        return json.load(io.open(args[1], encoding="utf-8"))
    if len(args) == 1 and os.path.isfile(args[0]):
        return json.load(io.open(args[0], encoding="utf-8"))
    # 自动找运行中的实例
    ports = _common.app_ports()
    if not ports:
        raise SystemExit("找不到运行中的实例，也没有给出快照 JSON。\n"
                         "用法：python tools/verify_history.py <state.json>")
    status, data = _common.http(ports[0], "/api/state")
    if status != 200 or not isinstance(data, dict):
        raise SystemExit("读取 /api/state 失败（HTTP %s）。" % status)
    return data


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    app = _common.app_dir()
    if len(args) >= 2 and os.path.isdir(args[0]):
        app = args[0]

    pats = extract_cmd_rules(app)
    if not pats:
        raise SystemExit("未能从 rules.py 提取 cmd_rules —— 文件结构可能变了。")

    d = load_state(sys.argv)

    # ---- 收集历史告警里的原始命令行 ----
    cases = []
    for a in d.get("alerts", []):
        for r in a.get("rules", []):
            rid = r.get("id")
            if rid not in ("P010", "P014"):
                continue
            ev = r.get("evidence") or ""
            m = re.match(r"^\s*命令行[：:]\s*(.*)$", ev, re.S)
            cmd = m.group(1).strip() if m else ""
            if cmd:
                cases.append((rid, cmd, a.get("name"), a.get("time")))

    print("=" * 78)
    print("历史告警命令行复算 —— 「那些进程早已退出」的取证途径")
    print("=" * 78)
    print("共收集到 P010/P014 历史命令行 %d 条" % len(cases))
    print()

    if not cases:
        print("（没有可复算的历史命令行）")
        return 0

    ok = bad = 0
    for got_rid, cmd, name, tm in cases:
        lc = cmd.lower()
        still = [rid for rid, (pat, _s, _w) in pats.items() if re.search(pat, lc)]
        residual = [x for x in still if x in ("P010", "P014")]
        good = not residual
        ok += 1 if good else 0
        bad += 0 if good else 1
        print("%s [原文 %s] %s  pid/name=%s" % ("OK  " if good else "FAIL", got_rid, tm, name))
        print("     cmd: %s" % cmd[:150].replace("\n", " "))
        print("     当前命中: %s" % (residual or "无（误报已消除）"))
        for x in residual:
            print("        → %s %s weight=%s" % (x, pats[x][1], pats[x][2]))
        print()

    print("=" * 78)
    print("误报消除：%d / %d 条" % (ok, len(cases)))
    print("=" * 78)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
