# -*- coding: utf-8 -*-
"""F-001 修复验证：直接打 API，不依赖替身进程。

红队 PoC 的实质是「一条 rule_only 条目把某条规则对所有对象关掉」。
这里把该前提拆成可判定的 API 断言 —— 比依赖替身进程稳定得多。
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'[OK]' if cond else '[X] '} {name}" + (f"   {extra}" if extra else ""))


def post(port, path, payload, token):
    import urllib.request
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", method="POST",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-Yinhu-Token": token})
    try:
        with op.open(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}


def get(port, path):
    import urllib.request
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with op.open(f"http://127.0.0.1:{port}{path}", timeout=20) as r:
        return json.loads(r.read().decode())


import urllib.error  # noqa: E402

DD = os.path.join(os.environ["LOCALAPPDATA"], "SilverFoxSentinel")
port = open(os.path.join(DD, "runtime_port.txt"), encoding="ascii").read().strip()
token = open(os.path.join(DD, "runtime_token.txt"), encoding="ascii").read().strip()
print(f"目标 127.0.0.1:{port}\n")

st = get(port, "/api/state")
procs = [p for p in st["processes"] if p.get("findings")]
if not procs:
    print("当前没有带 findings 的进程，无法测试对象限定 —— 先造一个。")
    sys.exit(3)
victim = procs[0]
rid = victim["findings"][0]["rule_id"]
print(f"取一个真实对象：{victim['name']} pid={victim['pid']} 规则={rid}\n")

print("=" * 70)
print("① 核心：rule_only 必须被拒绝（红队 PoC 打的就是这条）")
print("=" * 70)
code, r = post(port, "/api/whitelist/add",
               {"rule_id": rid, "match": {"type": "rule_only", "value": ""},
                "guard": {}, "note": "TEST"}, token)
check("rule_only → 400", code == 400, f"HTTP {code} {r.get('msg')}")
check("拒绝理由点明「全量豁免」", "全量豁免" in str(r.get("msg", "")), r.get("msg"))

print()
print("=" * 70)
print("② 空匹配值必须被拒绝（所有类型，含过去被豁免的）")
print("=" * 70)
for mt in ("exe_path_prefix", "cmdline_contains", "subject_text_contains", "exe_path"):
    code, r = post(port, "/api/whitelist/add",
                   {"rule_id": rid, "match": {"type": mt, "value": ""},
                    "guard": {}, "pid": victim["pid"], "note": "TEST"}, token)
    check(f"{mt} + 空值 → 400", code == 400, f"HTTP {code} {str(r.get('msg'))[:40]}")

print()
print("=" * 70)
print("③ 缺类型必须被拒绝（默认值不能回落到 rule_only）")
print("=" * 70)
code, r = post(port, "/api/whitelist/add",
               {"rule_id": rid, "match": {"value": "x"}, "guard": {},
                "pid": victim["pid"], "note": "TEST"}, token)
check("不给 type → 400", code == 400, f"HTTP {code} {str(r.get('msg'))[:50]}")

print()
print("=" * 70)
print("④ 必须指明对象")
print("=" * 70)
code, r = post(port, "/api/whitelist/add",
               {"rule_id": rid, "match": {"type": "exe_path_prefix", "value": "C:\\"},
                "guard": {}, "note": "TEST"}, token)
check("不给 pid/artifact_id → 400", code == 400, f"HTTP {code} {str(r.get('msg'))[:50]}")

print()
print("=" * 70)
print("⑤ 宽条件必须被拒绝 —— 具体性下限 + 对象断言，两层")
print("=" * 70)
# ⑤a 具体性下限：整个盘 / 顶层目录当前缀必须被拒。
#     只做"当前只命中一个对象"的断言是不够的 —— `C:\` 此刻可能确实只命中一个
#     （因为该规则此刻只有一个对象），但它把整个盘都放行了，将来出现的对象会被静默忽略。
for wide in ("C:\\", "C:\\Windows\\", "C:\\Program Files\\"):
    code, r = post(port, "/api/whitelist/add",
                   {"rule_id": rid, "match": {"type": "exe_path_prefix", "value": wide},
                    "guard": {}, "pid": victim["pid"], "note": "TEST"}, token)
    check(f"过宽前缀 {wide} → 400", code == 400, f"HTTP {code} {str(r.get('msg'))[:60]}")

# ⑤b 过短匹配文本必须被拒
code, r = post(port, "/api/whitelist/add",
               {"rule_id": rid, "match": {"type": "cmdline_contains", "value": "a"},
                "guard": {}, "pid": victim["pid"], "note": "TEST"}, token)
check("过短匹配文本 a → 400", code == 400, f"HTTP {code} {str(r.get('msg'))[:60]}")

# ⑤c 足够具体的路径前缀要放行（别把正常用途一起封死）
code, r = post(port, "/api/whitelist/add",
               {"rule_id": rid,
                "match": {"type": "exe_path_prefix",
                          "value": "C:\\Program Files\\SomeVendor\\App\\"},
                "guard": {}, "pid": victim["pid"], "note": "TEST"}, token)
check("足够具体的路径前缀 → 200", code == 200, f"HTTP {code} {str(r.get('msg'))[:60]}")
_eid = (r.get("entry") or {}).get("id")
if _eid:
    post(port, "/api/whitelist/remove", {"id": _eid}, token)

print()
print("=" * 70)
print("⑥ 正常路径仍要能加（别把功能一起封死）")
print("=" * 70)
narrow = victim.get("exe") or ""
code, r = post(port, "/api/whitelist/add",
               {"rule_id": rid, "match": {"type": "exe_path", "value": narrow},
                "guard": {}, "pid": victim["pid"], "note": "TEST-F001"}, token)
check("精确到单个 exe → 200", code == 200, f"HTTP {code} {str(r.get('msg'))[:70]}")
eid = (r.get("entry") or {}).get("id")
if eid:
    code2, r2 = post(port, "/api/whitelist/remove", {"id": eid}, token)
    check("能正常移除（F-010 的服务端侧）", code2 == 200, f"HTTP {code2} {str(r2.get('msg'))[:50]}")

print()
print("=" * 70)
print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
for f in FAIL:
    print("  x " + f)
print("=" * 70)
sys.exit(1 if FAIL else 0)
