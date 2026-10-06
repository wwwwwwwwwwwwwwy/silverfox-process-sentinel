# -*- coding: utf-8 -*-
"""F-002 修复验证：删基线后，一次日常「加入已知项」不得把基线静默重建。

关键断言（修复前全部反向）：
  · 基线文件**仍然不存在**（修复前会被重建）
  · integrity.status 仍为 baseline_lost（修复前变回 ok）
  · 接口明确回 integrity_refresh = blocked（修复前回正常）

测试会删除真实基线，所以**先备份、结束时无条件还原**。
"""
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.request

DD = os.path.join(os.environ["LOCALAPPDATA"], "SilverFoxSentinel")
BASELINE = os.path.join(DD, "integrity.baseline.json")
BACKUP = os.path.join(os.environ.get("TEMP", r"C:\Temp"), "F-002-test.backup.json")

PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'[OK]' if cond else '[X] '} {name}" + (f"   {extra}" if extra else ""))


op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
port = open(os.path.join(DD, "runtime_port.txt"), encoding="ascii").read().strip()
token = open(os.path.join(DD, "runtime_token.txt"), encoding="ascii").read().strip()


def get(path):
    with op.open(f"http://127.0.0.1:{port}{path}", timeout=20) as r:
        return json.loads(r.read().decode())


def post(path, payload):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", method="POST",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-Yinhu-Token": token})
    try:
        with op.open(req, timeout=25) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}


def integ():
    return (get("/api/state").get("security") or {}).get("integrity") or {}


print(f"目标 127.0.0.1:{port}")
print(f"基线：{BASELINE}\n")

if not os.path.isfile(BASELINE):
    print("基线不存在，先让它建好再测。")
    sys.exit(3)
os.makedirs(os.path.dirname(BACKUP), exist_ok=True)
shutil.copy2(BASELINE, BACKUP)
print(f"已备份基线 → {BACKUP}\n")

try:
    # ---- 找一个真实对象，构造合法（能过 F-001 校验）的已知项
    st = get("/api/state")
    procs = [p for p in st["processes"] if p.get("findings")]
    if not procs:
        print("没有带 findings 的进程，无法构造合法已知项。")
        sys.exit(3)
    v = procs[0]
    rid = v["findings"][0]["rule_id"]
    print(f"用真实对象：{v['name']} pid={v['pid']} 规则={rid}\n")

    print("=" * 70)
    print("第 0 步 · 基线正常时")
    print("=" * 70)
    check("基线存在", os.path.isfile(BASELINE))
    print(f"  integrity.status = {integ().get('status')}")

    print()
    print("=" * 70)
    print("第 1 步 · 删掉基线（模拟「顺手删基线让告警哑火」）")
    print("=" * 70)
    os.remove(BASELINE)
    check("基线已删除", not os.path.isfile(BASELINE))

    print()
    print("=" * 70)
    print("第 2 步 · 打：一次日常的「加入已知项」")
    print("=" * 70)
    code, r = post("/api/whitelist/add",
                   {"rule_id": rid,
                    "match": {"type": "exe_path", "value": v.get("exe") or ""},
                    "guard": {}, "pid": v["pid"], "note": "TEST-F002"})
    print(f"  HTTP {code}  {str(r.get('msg'))[:80]}")
    check("请求本身成功（已知项确实加进去了）", code == 200, f"HTTP {code}")
    check("★ 接口明确回报基线刷新被拒绝",
          r.get("integrity_refresh") == "blocked", str(r.get("integrity_refresh")))

    time.sleep(1.5)
    print()
    print("=" * 70)
    print("第 3 步 · 验（修复前这三条全反）")
    print("=" * 70)
    check("★ 基线文件**没有被重建**", not os.path.isfile(BASELINE))
    it = integ()
    check("★ 状态仍为 baseline_lost", it.get("status") == "baseline_lost",
          f"实际 {it.get('status')} / {it.get('status_zh')}")
    alerts = (get("/api/state").get("alerts") or [])
    hit = [a for a in alerts if "完整性" in (a.get("name") or "")]
    check("★ 出现了完整性告警（不再静默）", bool(hit),
          str(hit[:1])[:120])

    if code == 200 and (r.get("entry") or {}).get("id"):
        post("/api/whitelist/remove", {"id": r["entry"]["id"]})

finally:
    # ---- 无条件还原，避免把机器留在坏状态
    shutil.copy2(BACKUP, BASELINE)
    time.sleep(1.0)
    print()
    print(f"已还原基线（{integ().get('status')}）")

print()
print("=" * 70)
print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
for f in FAIL:
    print("  x " + f)
print("=" * 70)
sys.exit(1 if FAIL else 0)
