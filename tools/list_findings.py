# -*- coding: utf-8 -*-
"""
排查助手：列出本机当前所有非 clean 项及命中规则

用途：当界面显示有告警、你想知道"这到底是真检出还是误报"时，
这个脚本会把每条命中的规则、证据、签名状态完整打出来，便于逐条判断。

用法：
    python tools/list_findings.py            # 启动新实例扫描
    python tools/list_findings.py --port 8787  # 连已有实例
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common  # noqa: E402

LINE = "=" * 78


def dump(st: dict):
    s = st.get("summary", {})
    print(f"进程 {s.get('total')}  等级 {s.get('levels')}")
    print(f"制品异常 {s.get('artifact_findings')}  {s.get('artifact_levels')}")
    print(f"签名待校验 {s.get('sig_pending')}   已知项忽略 {s.get('whitelisted')}")

    bad = [p for p in st.get("processes", []) if p.get("level") != "clean"]
    print()
    print(LINE)
    print(f"非 clean 进程（{len(bad)} 个）")
    print(LINE)
    if not bad:
        print("  （无）")
    for p in bad:
        sig = p.get("signature") or {}
        print(f"\n[{p['level']}] {p['score']}  {p['name'] or '(名称不可读)'}  PID {p['pid']}")
        print(f"   路径  : {p['exe'] or '（无法读取路径）'}")
        print(f"   签名  : {sig.get('status_zh') or '—'} | {sig.get('cn') or '无'}")
        print(f"   父进程: {p.get('parent_name')}   用户: {p.get('username')}")
        if p.get("cmdline_str"):
            print(f"   命令行: {p['cmdline_str'][:200]}")
        for f in p.get("findings", []):
            print(f"   ├─ [{f['rule_id']}] {f['title']}  (权重 {f['weight']})")
            print(f"   │   {f['evidence'][:220]}")
            if f.get("advice"):
                print(f"   │   建议: {f['advice'][:200]}")
        if p.get("whitelisted"):
            print(f"   └─ （另有 {p['whitelisted']} 条已被已知项忽略）")

    print()
    print(LINE)
    print("制品异常")
    print(LINE)
    arts = st.get("artifacts") or []
    if not arts:
        print("  （无）")
    for a in arts:
        print(f"\n[{a['level']}] {a['score']} {a['kind']} {a['title']}")
        print(f"   {a.get('subtitle', '')[:170]}")
        for f in a.get("findings", []):
            print(f"   ├─ [{f['rule_id']}] {f['title']}  (权重 {f['weight']})")
            print(f"   │   {f['evidence'][:220]}")


def main():
    port = None
    if "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index("--port") + 1])

    started = False
    if port is None:
        _common.kill_app()
        port = _common.start_app()
        started = True
        if not port:
            print("启动失败")
            return 1

    st = _common.wait_ready(port)
    dump(st)

    if started:
        _common.kill_app()
        print()
        print("已停止监视器。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
