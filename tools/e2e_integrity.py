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

print()
print("=" * 72)
print("场景 2：增删已知项不应触发告警")
print("=" * 72)
token = _common.session_token(port)
_, add = _common.http(port, "/api/whitelist/add", "POST",
                      {"rule_id": "P011",
                       "match": {"type": "cmdline_contains", "value": "demo.ps1"},
                       "guard": {"file": ""}, "note": "integrity e2e"}, token)
C.check("加入已知项成功", bool((add or {}).get("ok")))
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
