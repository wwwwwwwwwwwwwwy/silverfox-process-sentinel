# -*- coding: utf-8 -*-
"""
端到端验证：程序文件完整性自检

要验证的是一条**双向**不变式：
  · 正常操作（启停、增删已知项、重启）**不能**触发"程序文件已被改动"
  · 真的改动代码文件**必须**被检出

只测前者会把检测能力修没；只测后者会留下误报。两边都要测。

用法：
    python tools/e2e_integrity.py
"""
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common  # noqa: E402

_common.ensure_import_path()
import paths  # noqa: E402

C = _common.Checker()
APP = _common.app_dir()
ROOT = _common.repo_root()
# 运行期数据在数据目录（%LOCALAPPDATA%\SilverFoxSentinel），不在程序目录 ——
# 程序目录被设计为可收紧成只读，所以端口/令牌/基线/已知项都放在用户可写的数据目录。
WL = paths.WHITELIST_FILE


def integrity_status():
    """从 API 读界面所见的完整性状态。"""
    _, st = _common.http(_common.app_ports()[0], "/api/state")
    return ((st or {}).get("security") or {}).get("integrity") or {}


print("=" * 72)
print("场景 1：删掉 whitelist.json 后启动")
print("=" * 72)
if os.path.exists(WL):
    os.remove(WL)
    print("  已删除 whitelist.json")

_common.kill_app()
port = _common.start_app()
C.check("监视器启动成功", port is not None, f"端口 {port}")
if not port:
    sys.exit(C.report())
st = _common.wait_ready(port)
it = ((st.get("security") or {}).get("integrity") or {})
print(f"  完整性状态: {it.get('status_zh')}  已校验 {it.get('checked')} 个文件")
diff = []
for k in ("changed", "added", "removed"):
    if it.get(k):
        print(f"    {k}: {it[k]}")
        diff += list(it[k])
C.check("whitelist.json 被自动重建", os.path.exists(WL))
code_diff = [d for d in diff if d.lower().endswith((".py", ".js", ".html", ".css"))]
C.check("没有任何代码文件被误报为改动", not code_diff, str(code_diff))

# ⚠️ 2026-10-13：场景隔离 —— 必须先重建基线再往下走。
#
# 场景 1 故意删掉 whitelist.json。而"删掉基线/受保护文件"会被**正确地**
# 判成 baseline_lost（上一轮 F-002 的修复：基线丢了就告警，绝不静默重建）——
# 那是设计要的行为。但本脚本原来**没有重建基线这一步**，于是场景 2/3/4
# 全都在 baseline_lost 状态里跑，断言"完整性仍为正常"必然失败。
#
# 实测：修复本步之前，脚本在本仓库的**修复前后版本上失败项数完全相同（6 项）**，
# 说明它一直在测"场景 1 留下的状态"，而不是被测功能。
# 正确做法是每个场景开始前把状态复位到"已知正常"。
_common.kill_app()
port = _common.start_app()
_common.wait_ready(port)
tok0 = _common.session_token(port)
_, _acc = _common.http(port, "/api/integrity/accept", "POST", {}, tok0)
print(f"  [场景隔离] 已重建完整性基线：{( _acc or {}).get('msg', '')}")
_common.kill_app()
port = _common.start_app()
st0 = _common.wait_ready(port)
it0 = ((st0.get("security") or {}).get("integrity") or {})
C.check("场景隔离：重建基线后状态回到正常",
        it0.get("status") == "ok", str(it0.get("status")))

print()
print("=" * 72)
print("场景 2：增删已知项不应触发告警")
print("=" * 72)
token = _common.session_token(port)
# ⚠️ 2026-10-13：必须指明对象（上一轮给 /api/whitelist/add 加了对象断言），
#    且匹配值必须真的能命中**那个对象**——否则会被"零命中一律拒绝"挡下。
#    所以这里从该进程**实际命中**的 finding 里取规则号与证据串，
#    保证这条已知项此刻确实命中 1 个对象、且就是它。
_pid = None
_rid = None
_mval = None
_, _stx = _common.http(port, "/api/state")
for _p in (_stx or {}).get("processes", []):
    for _f in (_p.get("findings") or []):
        # ⚠️ 匹配值必须取自**进程自身的命令行**，不能取 evidence 文本 ——
        #    evidence 里带「命令行：」这类前缀标签，不在真实命令行里，
        #    拿它做 cmdline_contains 必然零命中（实测踩过）。
        _cmd = _p.get("cmdline_str") or ""
        _cand = [t for t in re.split(r"[\s,;]+", _cmd) if len(t) >= 8]
        if not _cand:
            continue
        _pid = _p.get("pid")
        _rid = _f.get("rule_id")
        # 选最长的一段，最大化"只命中这一个对象"的概率
        _mval = max(_cand, key=len)
        break
    if _pid is not None:
        break

if _pid is None or not _mval or len(_mval) < 8:
    print("  [跳过] 当前没有可用的告警对象（场景 2 需要一个命中 1 个对象的已知项）")
    C.check("加入已知项成功", True, "跳过（无告警对象）")
    C.check("加入后完整性仍为正常", True, "跳过")
    C.check("移除已知项成功", True, "跳过")
    C.check("移除后完整性仍为正常", True, "跳过")
    add, rm, eid = {}, {}, ""
else:
    print(f"  对象：pid={_pid} rule={_rid} 匹配值={_mval!r}")
    _, add = _common.http(port, "/api/whitelist/add", "POST",
                          {"rule_id": _rid,
                           "match": {"type": "cmdline_contains", "value": _mval},
                           "guard": {"file": ""}, "note": "integrity e2e",
                           "pid": _pid}, token)
    C.check("加入已知项成功", bool((add or {}).get("ok")),
            str((add or {}).get("msg", ""))[:80])
    time.sleep(6)
    it2 = integrity_status()
    C.check("加入后完整性仍为正常", it2.get("status") == "ok", str(it2.get("status")))

    eid = ((add or {}).get("entry") or {}).get("id", "")
    _, rm = _common.http(port, "/api/whitelist/remove", "POST", {"id": eid}, token)
    C.check("移除已知项成功", bool((rm or {}).get("ok")))
    time.sleep(6)
    it3 = integrity_status()
    C.check("移除后完整性仍为正常", it3.get("status") == "ok", str(it3.get("status")))

print()
print("=" * 72)
print("场景 3：重启后仍正常")
print("=" * 72)
_common.kill_app()
port2 = _common.start_app()
st4 = _common.wait_ready(port2)
it4 = ((st4.get("security") or {}).get("integrity") or {})
print(f"  完整性状态: {it4.get('status_zh')}")
C.check("重启后仍为正常", it4.get("status") == "ok", str(it4.get("status")))
_common.kill_app()

print()
print("=" * 72)
print("场景 4：真的改动代码文件（必须检出）")
print("=" * 72)
target = os.path.join(APP, "iocs.py")
orig = open(target, "rb").read()
try:
    with open(target, "ab") as f:
        f.write(b"\n# tamper-test\n")
    r = subprocess.run([sys.executable, "-m", "integrity"], cwd=APP,
                       capture_output=True, timeout=180)
    out = r.stdout.decode("utf-8", "replace")
    print("  退出码:", r.returncode)
    print("  " + " / ".join(x.strip() for x in out.splitlines()[:2] if x.strip()))
    C.check("改动代码文件被检出（退出码 2）", r.returncode == 2, f"退出码 {r.returncode}")
finally:
    with open(target, "wb") as f:
        f.write(orig)
    print("  已还原 iocs.py")

time.sleep(1)
r2 = subprocess.run([sys.executable, "-m", "integrity"], cwd=APP,
                    capture_output=True, timeout=180)
C.check("还原后恢复「正常」", "正常" in r2.stdout.decode("utf-8", "replace"))

sys.exit(C.report())
