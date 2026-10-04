# -*- coding: utf-8 -*-
"""
端到端验证：已知项（白名单）机制

核心要验证的不是"能加白名单"，而是**加了之后还能不能防住替换** ——
守卫文件一旦被改动，忽略必须立即失效、告警自动回来。
否则白名单就成了攻击者的免死金牌。

用法：
    python tools/e2e_whitelist.py

会自行启动监视器、跑完断言、再把它停掉。运行前请先 pip install psutil。
"""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common  # noqa: E402

_common.ensure_import_path()
import whitelist  # noqa: E402

C = _common.Checker()

# ================================================================
print("=" * 72)
print("A. 模块级：守卫哈希必须能防住替换")
print("=" * 72)

_td = tempfile.mkdtemp(prefix="wl-test-")
_guard = os.path.join(_td, "demo.ps1")
with open(_guard, "w", encoding="utf-8") as f:
    f.write("Write-Host v1\n")

_finding = {"rule_id": "P011", "title": "命令行静默绕过脚本执行策略",
            "severity": "medium", "weight": 50}
_subject = {"pid": 1, "name": "powershell.exe",
            "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline_str": f'-File "{_guard}"'}
_wl = {"version": 1, "entries": [{
    "id": "t", "rule_id": "P011",
    "match": {"type": "cmdline_contains", "value": "demo.ps1"},
    "guard": {"file": _guard, "sha256": whitelist._sha256(_guard)},
}]}

kept, dropped = whitelist.filter_findings([_finding], _subject, _wl)
C.check("守卫哈希一致 → 告警被忽略", not kept and len(dropped) == 1)

with open(_guard, "w", encoding="utf-8") as f:
    f.write("Write-Host TAMPERED\n")
kept2, _ = whitelist.filter_findings([_finding], _subject, _wl)
C.check("守卫文件被改动 → 忽略失效、告警回来", len(kept2) == 1)

os.remove(_guard)
kept3, _ = whitelist.filter_findings([_finding], _subject, _wl)
C.check("守卫文件不存在 → 忽略失效", len(kept3) == 1)

other = {"rule_id": "P010", "title": "另一条", "severity": "high", "weight": 82}
kept4, _ = whitelist.filter_findings([other], _subject, _wl)
C.check("同对象但规则号不同 → 不受影响", len(kept4) == 1)

_subj2 = dict(_subject, cmdline_str="powershell.exe -EncodedCommand AAAA")
kept5, _ = whitelist.filter_findings([_finding], _subj2, _wl)
C.check("匹配条件不满足 → 不受影响", len(kept5) == 1)

# ================================================================
print()
print("=" * 72)
print("B. 端到端：真实告警的标记与恢复")
print("=" * 72)

# 先清掉可能残留的已知项，否则待测告警会被静默
_wl_file = os.path.join(_common.app_dir(), "whitelist.json")
if os.path.exists(_wl_file):
    os.remove(_wl_file)
    print("  已清空残留的 whitelist.json（本次测试从干净状态开始）")

_common.kill_app()
port = _common.start_app()
C.check("监视器启动成功", port is not None, f"端口 {port}")
if not port:
    sys.exit(C.report())

st = _common.wait_ready(port)
s = st.get("summary", {})
bad = [p for p in st.get("processes", []) if p.get("level") != "clean"]
print(f"  进程 {s.get('total')}  非 clean {len(bad)} 个")
for p in bad:
    print(f"    [{p['level']}] {p['name']} 规则={[f['rule_id'] for f in p['findings']]}")
if not bad:
    print("  （本机当前没有告警可测。这本身是好消息 —— 说明没有误报。")
    print("    想验证本功能，可先在某个未签名程序上触发一条告警再跑。）")
    _common.kill_app()
    sys.exit(C.report())

target = bad[0]
rid = target["findings"][0]["rule_id"]
token = _common.session_token(port)

code, sg = _common.http(port, "/api/whitelist/suggest",
                        "POST", {"pid": target["pid"], "rule_id": rid}, token)
C.check("能生成建议条目", bool((sg or {}).get("ok")), str((sg or {}).get("msg", "")))
sug = (sg or {}).get("suggest") or {}
print(f"  建议：{json.dumps(sug, ensure_ascii=False)[:180]}")

code, add = _common.http(port, "/api/whitelist/add", "POST",
                         {"rule_id": rid, "match": sug.get("match"),
                          "guard": sug.get("guard"), "note": "e2e 测试"},
                         token)
C.check("加入已知项成功", bool((add or {}).get("ok")), str((add or {}).get("msg", "")))
eid = ((add or {}).get("entry") or {}).get("id", "")

gone = False
for _ in range(30):
    time.sleep(2)
    _, st2 = _common.http(port, "/api/state")
    still = [p for p in (st2 or {}).get("processes", [])
             if any(f["rule_id"] == rid for f in p["findings"])]
    if not still:
        gone = True
        break
C.check("告警已消失", gone)
C.check("summary 正确计数", ((st2 or {}).get("summary") or {}).get("whitelisted", 0) >= 1)

code, rm = _common.http(port, "/api/whitelist/remove", "POST", {"id": eid}, token)
C.check("移除已知项成功", bool((rm or {}).get("ok")))

back = False
for _ in range(30):
    time.sleep(2)
    _, st3 = _common.http(port, "/api/state")
    if [p for p in (st3 or {}).get("processes", [])
            if any(f["rule_id"] == rid for f in p["findings"])]:
        back = True
        break
C.check("移除后告警恢复", back)

_common.kill_app()
sys.exit(C.report())
