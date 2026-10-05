# -*- coding: utf-8 -*-
"""本机副本管理 —— 检测本机所有「银狐进程监视器」副本，清理旧版，用新版完全覆盖。

## 为什么需要它

这套工具在本机上会自然长出多份副本（安装版、开源副本、打包 exe、测试目录......）。
在加版本号之前，"哪个是最新版"只能靠文件时间猜，实测已经出过问题：
用户跑着旧副本，却以为功能坏了。

## 安全约定（改这个脚本时不要破）

1. **默认只检测、不动任何文件**。要修改必须显式给 `--clean` 或 `--update`。
2. **改之前先备份**到 `<目标>/备份/更新-<时间戳>/`，并在屏幕上列出每一个受影响路径。
3. **绝不碰用户数据**：
   - `%LOCALAPPDATA%\\SilverFoxSentinel\\`（白名单、完整性基线、导出的报告）
   - 目标目录里的 `python_path.txt`（记录本机解释器位置，换机器就没用）
   - 目标目录里的 `备份/`（历史备份，避免递归）
4. **覆盖前先停掉正在运行的监视器** —— 否则文件被占用、且运行中的代码仍是旧的。

## 用法

    python 本机副本管理.py                    # 只检测，列清单
    python 本机副本管理.py --clean            # 清理：解包残留 + 过期的打包 exe
    python 本机副本管理.py --update <源目录>   # 把比源旧的副本完全覆盖成源
    python 本机副本管理.py --update <源> --yes # 跳过确认（脚本化用）

    --all   连"非工具目录"里的副本也一起处理（默认只处理看起来是安装版的）
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "app"))

import version  # noqa: E402

# 控制台兜底：中文 Windows 的 cmd 是 GBK，Python 默认按控制台编码输出，
# 遇到 GBK 里没有的字符（如 ✓ ⛔）会直接抛 UnicodeEncodeError 让脚本崩掉。
# 上面已经把这类字符都换成了 ASCII 标记，这里再加一道保险。
try:
    sys.stdout.reconfigure(errors="replace")
    sys.stderr.reconfigure(errors="replace")
except Exception:
    pass

# ---------------------------------------------------------------- 常量

# 参与"是不是工具副本"判定的标志文件
MARKERS = (os.path.join("app", "server.py"), os.path.join("app", "rules.py"))

# 属于"程序文件"、需要被覆盖的路径（相对路径）
PROGRAM_FILES = [
    "app", "README.md", "requirements.txt", "回归自检.py", "本机副本管理.py",
    "启动银狐监视器.bat", "停止监视器.bat", "调试启动（显示日志）.bat",
    "还原目录权限.bat", "优化说明.md",
]

# 覆盖时必须保留（机器相关 / 用户数据）
KEEP = {"python_path.txt", "备份", "银狐进程监视器.exe"}

# 扫描位置与深度
SCAN_ROOTS = [
    ("D:\\", 3), ("E:\\", 2),
    (os.path.expanduser("~/Desktop"), 2),
    (os.path.expanduser("~/Documents"), 2),
    (os.path.expanduser("~/Downloads"), 2),
    (r"D:\Downloads", 2),
]
SCAN_SKIP = {"$RECYCLE.BIN", "System Volume Information", "node_modules", ".git",
             "__pycache__", "Windows", "Program Files", "Program Files (x86)",
             "AppData", "<workspace>", "备份"}

PYINSTALLER_PREFIX = "_MEI"
PACKED_EXE = "银狐进程监视器.exe"


# ---------------------------------------------------------------- 工具

def md5_file(path: str) -> str:
    h = hashlib.md5()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except Exception:
        return ""
    return h.hexdigest()


def fingerprint(root: str) -> tuple[str, int]:
    """内容指纹：app/ 下所有 .py/.js/.html/.css 与几个根文件的 (相对路径, md5)。

    [注意] 不能用"文件修改时间"判断新旧 —— 复制、解压、改系统时间都会打乱它。
    """
    items = []
    app = os.path.join(root, "app")
    for dp, dn, fn in os.walk(app):
        dn[:] = [d for d in dn if d != "__pycache__"]
        for f in sorted(fn):
            if f.endswith((".py", ".js", ".html", ".css")):
                fp = os.path.join(dp, f)
                items.append((os.path.relpath(fp, root).replace("\\", "/"), md5_file(fp)))
    for f in ("README.md", "requirements.txt", "回归自检.py"):
        fp = os.path.join(root, f)
        if os.path.isfile(fp):
            items.append((f, md5_file(fp)))
    items.sort()
    blob = json.dumps(items, ensure_ascii=False).encode("utf-8")
    return hashlib.md5(blob).hexdigest(), len(items)


def read_version(root: str) -> str:
    """读目标副本自己的 version.py（不 import —— 避免加载到别人的代码）。"""
    vf = os.path.join(root, "app", "version.py")
    if not os.path.isfile(vf):
        return ""
    try:
        import re
        txt = open(vf, encoding="utf-8").read()
        m = re.search(r'^VERSION\s*=\s*["\']([^"\']+)["\']', txt, re.M)
        return m.group(1) if m else ""
    except Exception:
        return ""


def is_copy(d: str) -> bool:
    return all(os.path.isfile(os.path.join(d, m)) for m in MARKERS)


# 开源副本做过脱敏替换（真实计划任务名 → 占位符、真实用户名 → 占位符）。
# [注意] 两种副本**绝不能互相覆盖**：
#    - 脱敏副本 → 安装版：工具会认不出本机真实的计划任务名，等于功能失效；
#    - 安装版 → 脱敏副本：会把真实用户名、真实路径推到公开仓库，属信息泄露。
_DESENSITIZE_MARKERS = ("my-watchdog", "<用户名>", "YOUR_NAME", "<User>")


def looks_desensitized(d: str) -> bool:
    """判断这份副本是不是"脱敏后的公开副本"。"""
    for rel in ("app/whitelist.py", "app/paths.py", "README.md"):
        p = os.path.join(d, rel)
        try:
            txt = open(p, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        if any(m in txt for m in _DESENSITIZE_MARKERS):
            return True
    return False


def find_copies() -> list[dict]:
    out = []

    def walk(root: str, max_depth: int):
        root = os.path.abspath(root)
        if not os.path.isdir(root):
            return
        base = root.rstrip("\\/").count(os.sep)
        for dirpath, dirnames, _fn in os.walk(root):
            if dirpath.count(os.sep) - base > max_depth:
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d not in SCAN_SKIP]
            if is_copy(dirpath):
                out.append(dirpath)
                dirnames[:] = []

    for root, depth in SCAN_ROOTS:
        try:
            walk(root, depth)
        except Exception:
            pass

    # 去重 + 补上"解包残留"（它们不是完整副本，但要报出来）
    seen, copies = set(), []
    for d in out:
        # _MEI* 是 PyInstaller 解包残留，不是真正的副本 —— 单独在【二】里报，
        # 混进副本清单会让人以为本机装了 7 份，反而看不清重点。
        if os.path.basename(d).startswith(PYINSTALLER_PREFIX):
            continue
        if d.lower() not in seen:
            seen.add(d.lower())
            copies.append(d)

    result = []
    for d in copies:
        fp, n = fingerprint(d)
        newest = 0
        for dp, dn, fn in os.walk(os.path.join(d, "app")):
            dn[:] = [x for x in dn if x != "__pycache__"]
            for f in fn:
                try:
                    newest = max(newest, os.path.getmtime(os.path.join(dp, f)))
                except Exception:
                    pass
        result.append({
            "path": d, "version": read_version(d), "fingerprint": fp,
            "files": n, "newest": newest,
            "packed_exe": os.path.isfile(os.path.join(d, PACKED_EXE)),
            "is_master": os.path.abspath(d).lower() == HERE.lower(),
            "desensitized": looks_desensitized(d),
        })
    return result


def find_pyinstaller_junk() -> list[str]:
    """PyInstaller onefile 运行后留下的 _MEI* 解包目录。"""
    junk = []
    for root in (r"D:\Temp", os.environ.get("TEMP", ""), r"C:\Users\<用户名>\AppData\Local\Temp"):
        if not root or not os.path.isdir(root):
            continue
        try:
            for name in os.listdir(root):
                p = os.path.join(root, name)
                if name.startswith(PYINSTALLER_PREFIX) and os.path.isdir(p):
                    junk.append(p)
        except Exception:
            pass
    return sorted(set(junk))


# ---------------------------------------------------------------- 停监视器

def stop_running_monitor() -> bool:
    """覆盖前必须停掉运行中的监视器：文件被占用，且跑的还是旧代码。"""
    dd = os.path.join(os.environ.get("LOCALAPPDATA", ""), "SilverFoxSentinel")
    try:
        port = open(os.path.join(dd, "runtime_port.txt"), encoding="ascii").read().strip()
        tok = open(os.path.join(dd, "runtime_token.txt"), encoding="ascii").read().strip()
    except Exception:
        return False
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/shutdown", method="POST", data=b"{}",
            headers={"Content-Type": "application/json", "X-Yinhu-Token": tok})
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        op.open(req, timeout=8).read()
        time.sleep(2.0)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- 覆盖

def backup_dir_of(target: str) -> str:
    return os.path.join(target, "备份", "更新-" + time.strftime("%Y%m%d-%H%M%S"))


def _dir_size(path: str) -> int:
    total = 0
    for dp, _dn, fn in os.walk(path):
        for f in fn:
            try:
                total += os.path.getsize(os.path.join(dp, f))
            except Exception:
                pass
    return total


def plan_overwrite(src: str, target: str) -> dict:
    """算出要删什么、要拷什么、要留什么。**只算不做**。"""
    delete, copy, keep = [], [], []

    # 0) 先明确列出"要保留"的机器相关文件 / 目录。
    #    它们本来就不在程序清单里、不会被删，但**必须报出来** ——
    #    用户需要亲眼看到"我的 python_path.txt 不会被冲掉"才敢按确认。
    for name in sorted(KEEP):
        if os.path.exists(os.path.join(target, name)):
            keep.append(name)

    # 1) 目标里已有的程序文件 → 删除后用源的版本
    for rel in PROGRAM_FILES:
        tp = os.path.join(target, rel)
        if not os.path.exists(tp):
            continue
        if rel in KEEP:
            keep.append(rel)
            continue
        delete.append(rel)
        if os.path.exists(os.path.join(src, rel)):
            copy.append(rel)

    # 2) 源里有、目标里没有的 → 直接拷
    for rel in PROGRAM_FILES:
        if rel in keep:
            continue
        if rel not in delete and os.path.exists(os.path.join(src, rel)):
            copy.append(rel)

    # 3) 目标里的"旧版残留"：不在程序清单里、且不是要保留的
    try:
        for name in sorted(os.listdir(target)):
            if name in KEEP or name in PROGRAM_FILES:
                continue
            p = os.path.join(target, name)
            if os.path.isfile(p) and name.lower().endswith((".py", ".md", ".txt")):
                delete.append(name)
            elif os.path.isfile(p) and name.lower().endswith(".exe"):
                keep.append(name + "（打包版，单独处理）")
    except Exception:
        pass

    return {"delete": sorted(set(delete)), "copy": sorted(set(copy)), "keep": keep}


def do_overwrite(src: str, target: str, yes: bool) -> int:
    src, target = os.path.abspath(src), os.path.abspath(target)
    if src.lower() == target.lower():
        print("  源与目标是同一个目录，跳过。")
        return 0
    if not is_copy(src):
        print(f"  [X] 源不是有效的工具副本：{src}")
        return 1

    # [拒绝] 脱敏副本与安装版绝不能互相覆盖（见 looks_desensitized 的说明）
    if looks_desensitized(src) != looks_desensitized(target):
        print("\n  [拒绝] 拒绝执行：源与目标属于不同类型的副本（一份脱敏、一份未脱敏）。")
        print(f"     源   {src}  → {'脱敏副本（公开用）' if looks_desensitized(src) else '完整副本（本机用）'}")
        print(f"     目标 {target}  → {'脱敏副本（公开用）' if looks_desensitized(target) else '完整副本（本机用）'}")
        print("     覆盖会造成：真实路径/用户名被推到公开仓库，或工具认不出本机真实计划任务名。")
        print("     如需同步这两类副本，请用专门的单向脱敏同步脚本，不要用本命令。")
        return 1

    plan = plan_overwrite(src, target)
    print(f"\n  源  ：{src}   v{read_version(src) or '?'}")
    print(f"  目标：{target}   v{read_version(target) or '?'}")
    print(f"\n  将删除并覆盖 {len(plan['delete'])} 项：")
    for x in plan["delete"]:
        print(f"      - {x}")
    print(f"  将写入 {len(plan['copy'])} 项（来自源）：")
    for x in plan["copy"][:12]:
        print(f"      + {x}")
    if len(plan["copy"]) > 12:
        print(f"      + ... 另 {len(plan['copy']) - 12} 项")
    print(f"  将保留 {len(plan['keep'])} 项：")
    for x in plan["keep"]:
        print(f"      = {x}")

    if not yes:
        print("\n  [注意] 以上操作会删除目标目录里的程序文件（会先备份）。")
        try:
            ans = input("  确认执行？输入 yes 继续：").strip().lower()
        except EOFError:
            ans = ""
        if ans not in ("yes", "y", "是"):
            print("  已取消，未做任何修改。")
            return 0

    # 1) 备份
    bk = backup_dir_of(target)
    os.makedirs(bk, exist_ok=True)
    backed = 0
    for rel in plan["delete"]:
        sp = os.path.join(target, rel)
        dp = os.path.join(bk, rel)
        try:
            if os.path.isdir(sp):
                shutil.copytree(sp, dp, dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns("__pycache__"))
            elif os.path.isfile(sp):
                os.makedirs(os.path.dirname(dp), exist_ok=True)
                shutil.copy2(sp, dp)
            backed += 1
        except Exception as e:
            print(f"      ! 备份失败 {rel}: {e}")
    print(f"\n  已备份 {backed} 项到：{bk}")

    # 2) 删除
    removed = 0
    for rel in plan["delete"]:
        sp = os.path.join(target, rel)
        try:
            if os.path.isdir(sp):
                shutil.rmtree(sp, ignore_errors=True)
            elif os.path.isfile(sp):
                os.remove(sp)
            removed += 1
        except Exception as e:
            print(f"      ! 删除失败 {rel}: {e}")
    print(f"  已删除 {removed} 项")

    # 3) 复制
    written = 0
    for rel in plan["copy"]:
        sp, dp = os.path.join(src, rel), os.path.join(target, rel)
        try:
            if os.path.isdir(sp):
                shutil.copytree(sp, dp, dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns("__pycache__"))
            elif os.path.isfile(sp):
                os.makedirs(os.path.dirname(dp), exist_ok=True)
                shutil.copy2(sp, dp)
            written += 1
        except Exception as e:
            print(f"      ! 复制失败 {rel}: {e}")
    print(f"  已写入 {written} 项")

    # 4) 校验
    sf, sn = fingerprint(src)
    tf, tn = fingerprint(target)
    ok = sf == tf
    print(f"\n  覆盖后指纹比对：源 {sf[:10]}...（{sn} 个文件） / "
          f"目标 {tf[:10]}...（{tn} 个文件） → {'一致 [OK]' if ok else '不一致 [X]'}")
    return 0 if ok else 1


# ---------------------------------------------------------------- 主流程

def main() -> int:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--clean", action="store_true", help="清理解包残留与过期的打包 exe")
    ap.add_argument("--update", metavar="源目录", help="把比源旧的副本完全覆盖成源")
    ap.add_argument("--yes", action="store_true", help="跳过确认")
    args = ap.parse_args()

    print("=" * 74)
    print(f"  银狐进程监视器 - 本机副本管理    当前版本 v{version.VERSION}")
    print("=" * 74)

    copies = find_copies()
    print(f"\n【一】本机副本（{len(copies)} 个）\n")
    newest_ver, newest_path = "", ""
    for c in copies:
        if version.compare(c["version"], newest_ver) > 0:
            newest_ver, newest_path = c["version"], c["path"]
    for c in copies:
        v = c["version"] or "（无版本号 - 早于 2026-10-05 的旧版）"
        rel = version.compare(c["version"], newest_ver) if c["version"] else -1
        tag = "最新" if rel == 0 and c["version"] else ("较旧" if rel < 0 else "较新")
        mark = "*" if c["path"].lower() == HERE.lower() else " "
        print(f" {mark} {c['path']}")
        kind = "脱敏副本（对外公开用）" if c["desensitized"] else "完整副本（本机运行用）"
        print(f"     版本 {v}   [{tag}]   {kind}")
        print(f"     程序文件 {c['files']} 个   指纹 {c['fingerprint'][:10]}...")
        if c["packed_exe"]:
            exe = os.path.join(c["path"], PACKED_EXE)
            try:
                et = os.path.getmtime(exe)
                stale = et < c["newest"] - 60
                extra = (f"，已过期（打包于 {time.strftime('%Y-%m-%d %H:%M', time.localtime(et))}，"
                         f"比源码旧）" if stale else "")
            except Exception:
                extra = ""
            print(f"     打包 exe：有{extra}")
            print(f"        注意：打包版把代码冻在 exe 里，源码更新不会影响它。"
                  f"桌面快捷方式走的是 .bat，不经过它。")
        else:
            print("     打包 exe：无")
        print()

    junk = find_pyinstaller_junk()
    print(f"【二】打包版运行残留（_MEI*）：{len(junk)} 个")
    for p in junk:
        print(f"     {p}")

    # 同版本不同内容 = 有人改了代码但忘了递增版本号，必须提醒
    same_ver_diff = {}
    for c in copies:
        if c["version"]:
            same_ver_diff.setdefault(c["version"], set()).add(c["fingerprint"])
    for v, fps in same_ver_diff.items():
        if len(fps) > 1:
            print(f"\n  [注意] 版本号 v{v} 却有 {len(fps)} 种不同内容 —— "
                  f"改了代码但没递增 app/version.py 的 VERSION，请修正。")

    if args.update:
        src = os.path.abspath(args.update)
        print(f"\n【三】用「{src}」覆盖其它较旧的副本")
        if not args.yes:
            print("  （先停掉运行中的监视器，避免文件占用）")
        stop_running_monitor()
        rc = 0
        for c in copies:
            if c["path"].lower() == src.lower():
                continue
            if version.compare(c["version"], read_version(src)) >= 0:
                print(f"\n  跳过（版本不旧）：{c['path']}  v{c['version'] or '?'}")
                continue
            rc |= do_overwrite(src, c["path"], args.yes)
        print("\n  覆盖完成。若目标是安装目录，建议重建完整性基线后再启动：")
        print("     cd app && python -m integrity --accept")
        return rc

    if args.clean:
        print("\n【三】清理")
        targets = []
        for p in junk:
            targets.append(("打包版解包残留（可安全删除）", p))
        for c in copies:
            if c["path"].lower() == HERE.lower():
                continue
            exe = os.path.join(c["path"], PACKED_EXE)
            if os.path.isfile(exe):
                targets.append(("过期的打包 exe（源码更新不会影响它，留着只会误导）", exe))
            # Temp 下的旧副本：本来就是个临时测试目录，留着只会让"哪个是最新版"更乱
            if os.path.abspath(c["path"]).lower().startswith(
                    os.path.abspath(r"D:\Temp").lower()):
                targets.append(("Temp 下的旧测试副本", c["path"]))
        if not targets:
            print("  没有需要清理的东西。")
            return 0
        for kind, p in targets:
            print(f"  [{kind}]")
            print(f"      {p}")
        print(f"\n  共 {len(targets)} 项，合计约 "
              f"{sum(os.path.getsize(p) if os.path.isfile(p) else _dir_size(p) for _k, p in targets) / 1048576:.1f} MB")
        # 清理工具**不永久删除**，一律移到暂存目录 —— 判断失误还能捞回来。
        # 暂存放在 备份/ 下（扫描时会被跳过，不会当成"又一份副本"）。
        stage = os.path.join(HERE, "备份", "清理暂存-" + time.strftime("%Y%m%d-%H%M%S"))
        print(f"  这些会被移动到暂存目录（不是永久删除）：")
        print(f"      {stage}")
        if not args.yes:
            print("  确认没问题后你可以随时手动删掉暂存目录。")
            try:
                ans = input("  确认继续？输入 yes 继续：").strip().lower()
            except EOFError:
                ans = ""
            if ans not in ("yes", "y", "是"):
                print("  已取消。")
                return 0
        os.makedirs(stage, exist_ok=True)
        for kind, p in targets:
            try:
                name = os.path.basename(p.rstrip("\\/")) or "item"
                dst = os.path.join(stage, name)
                k = 1
                while os.path.exists(dst):
                    dst = os.path.join(stage, f"{name}-{k}")
                    k += 1
                shutil.move(p, dst)
                print(f"  [OK] 已移入暂存 {name}   （原位置 {p}）")
            except Exception as e:
                print(f"  [X] 移动失败 {p}: {e}")
        print(f"\n  暂存目录：{stage}")
        print("  确认一切正常后，直接删掉这个目录即可回收空间。")
        return 0

    print("\n【三】未做任何修改（默认只检测）。")
    print("     要清理残留：      python 本机副本管理.py --clean")
    print("     要用新版覆盖旧版：python 本机副本管理.py --update <最新版目录>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
