# -*- coding: utf-8 -*-
"""
程序自身完整性校验（防篡改）

## 它能做到什么

在首次运行时为 `app/` 下所有代码与前端文件生成 SHA-256 基线，此后每次启动、
以及运行期间每 5 分钟重新计算并比对。一旦有人改了规则文件（例如木马想关掉检测），
界面上会立刻出现醒目的红色告警，并列出被改动的具体文件。

## 它做不到什么（必须说清楚）

**同权限的攻击者可以同时改代码和改基线文件，本机制无法发现。**
这是所有用户态自校验的固有上限：

- 基线文件 `integrity.baseline.json` 就在同一个目录里，能改代码的人就能改它；
- 本工具以当前用户身份运行，没有内核驱动、也没有 PPL（受保护进程）保护，
  攻击者可以直接结束它、也可以给它打补丁；
- 专业 EDR 之所以能抗篡改，靠的是**内核驱动 + 以 PPL 身份运行**
  （需要 EV 代码签名证书 + 微软审核），纯 Python 脚本做不到。

所以本机制的真实价值是：
  1. 发现**意外的损坏**（磁盘错误、拷贝不完整、更新中断）；
  2. 发现**顺手改一把的普通恶意程序** —— 绝大多数木马不会专门针对本工具做免杀，
     它们更可能粗暴地删掉/替换规则文件，这种情况能被抓到；
  3. 让用户**有一个办法确认**手上的这份程序没被人动过（配合 `--verify-only` 参数）。

若要真正抗篡改，正确做法是：把程序放到受保护目录（如 `C:\\Program Files\\`），
并以专用低权限账户运行，由管理员控制文件写权限。见 README「安全性说明」。
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time

BASELINE_FILE = "integrity.baseline.json"
SKIP_DIRS = {"__pycache__", ".app-window", "reports", "build", "dist"}
SKIP_EXT = {".pyc", ".pyo", ".log", ".tmp"}
HASH_LIMIT_MB = 64

# 加固（2026-10-04）：基线丢失哨兵。
# 对抗测试发现：攻击者只需删除 workspace\\integrity.baseline.json，
# verify() 就会把这次运行当作"首次运行"、静默重建基线 ——
# 完整性告警从此永远哑火。哨兵文件放在 %LOCALAPPDATA% 下的独立位置，
# 与基线文件不在同一目录，删除基线但不同时删哨兵 → 立即告警 baseline_lost。
# 诚实边界：同权限攻击者知道哨兵位置后可以两个一起删 —— 用户态自校验
# 无法防御针对性攻击，本机制防的是"顺手删基线"的普通恶意程序与意外丢失。
SENTINEL_DIR = os.path.join(os.path.expandvars(r"%LOCALAPPDATA%"), "YinhuSentinel")
SENTINEL_FILE = "integrity.sentinel.json"


def sentinel_path() -> str:
    return os.path.join(SENTINEL_DIR, SENTINEL_FILE)


def load_sentinel() -> dict | None:
    try:
        with open(sentinel_path(), "r", encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict):
            return d
    except Exception:
        pass
    return None


def save_sentinel(workspace: str, manifest: dict, app_dir: str | None = None) -> None:
    try:
        os.makedirs(SENTINEL_DIR, exist_ok=True)
        d = {"created": time.strftime("%Y-%m-%d %H:%M:%S"),
             "workspace": os.path.abspath(workspace),
             # 同时记 app_dir：数据目录是每用户的，同机多份副本共用它。
             # 只比 workspace 的话，另一份副本会被判成"基线被人删除"。
             "app_dir": os.path.abspath(app_dir) if app_dir else "",
             "count": len(manifest)}
        with open(sentinel_path(), "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


def _sha256(path: str) -> str:
    try:
        if os.path.getsize(path) > HASH_LIMIT_MB * 1024 * 1024:
            return ""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 256), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def collect_manifest(app_dir: str, extra_files: list[str] | None = None) -> dict:
    """计算 {相对路径: sha256}。相对 app 目录，避免因安装位置不同而误报。"""
    manifest: dict[str, str] = {}
    base = os.path.abspath(app_dir)
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in sorted(files):
            if os.path.splitext(fn)[1].lower() in SKIP_EXT:
                continue
            p = os.path.join(root, fn)
            rel = os.path.relpath(p, base).replace("\\", "/")
            manifest[rel] = _sha256(p)
    for p in (extra_files or []):
        if p and os.path.isfile(p):
            manifest[os.path.basename(p)] = _sha256(p)
    return manifest


def baseline_path(workspace: str) -> str:
    return os.path.join(workspace, BASELINE_FILE)


def load_baseline(workspace: str) -> dict | None:
    try:
        with open(baseline_path(workspace), "r", encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict) and isinstance(d.get("files"), dict):
            return d
    except Exception:
        pass
    return None


def save_baseline(workspace: str, manifest: dict, note: str = "",
                  app_dir: str | None = None) -> dict:
    d = {
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "note": note or "程序首次运行或用户手动重建",
        # 记下这份基线是给哪个程序目录算的：数据目录是「每用户」的，
        # 同机多份副本会共用它，没有这个字段就会互相误报"文件已被改动"。
        "app_dir": os.path.abspath(app_dir) if app_dir else "",
        "files": manifest,
    }
    with open(baseline_path(workspace), "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    return d


def verify(app_dir: str, workspace: str, extra_files: list[str] | None = None) -> dict:
    """返回完整性检查结果。

    status:
      first_run      —— 首次运行，刚建立基线（不是问题）
      ok             —— 全部一致
      changed        —— 有文件被改动 / 新增 / 缺失（**需警惕**）
      baseline_lost  —— 基线文件消失但哨兵还在（**需警惕**，可能被人删除）
    """
    cur = collect_manifest(app_dir, extra_files)
    base = load_baseline(workspace)
    # 基线属于另一个程序目录（同机多份副本共用数据目录）→ 按首次运行处理，
    # 否则另一份副本会看到满屏"文件已被改动"的假告警。
    if base and base.get("app_dir") and \
            os.path.normcase(base["app_dir"]) != os.path.normcase(os.path.abspath(app_dir)):
        base = None
    if not base:
        sent = load_sentinel()
        # 哨兵只对"同一安装位置"有效：文件夹整体被拷贝到新位置时
        # 视为全新安装，正常建立基线，而不是误报基线丢失。
        sent_here = bool(sent) and sent.get("workspace") == os.path.abspath(workspace)
        if sent_here and sent.get("app_dir") and \
                os.path.normcase(sent["app_dir"]) != os.path.normcase(os.path.abspath(app_dir)):
            sent_here = False      # 哨兵属于另一个程序目录（同机多份副本）
        if sent_here:
            # 加固：基线没了但哨兵还在 → 基线被人删除或损坏，告警而不是重建
            return {
                "status": "baseline_lost",
                "status_zh": "⚠️ 完整性基线丢失（可能已被删除）",
                "checked": len(cur),
                "changed": [], "added": [], "removed": [],
                "baseline_time": sent.get("created", "未知"),
                "ts": time.time(),
            }
        save_baseline(workspace, cur, app_dir=app_dir)
        save_sentinel(workspace, cur, app_dir)
        return {
            "status": "first_run",
            "status_zh": "首次运行，已建立完整性基线",
            "checked": len(cur),
            "changed": [], "added": [], "removed": [],
            "baseline_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ts": time.time(),
        }

    old = base.get("files", {})
    changed = sorted(k for k in old if k in cur and cur[k] != old[k])
    added = sorted(k for k in cur if k not in old)
    removed = sorted(k for k in old if k not in cur)

    status = "changed" if (changed or added or removed) else "ok"
    return {
        "status": status,
        "status_zh": {
            "ok": "文件完整性正常",
            "changed": "⚠️ 程序文件已被改动",
        }[status],
        "checked": len(cur),
        "changed": changed[:20],
        "added": added[:20],
        "removed": removed[:20],
        "baseline_time": base.get("created", ""),
        "ts": time.time(),
    }


def main():
    """命令行自检：python -m integrity [--accept]"""
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    # 数据目录（用户可写）与程序目录已分离：基线在数据目录，
    # 不能再按"程序目录的上一级"去猜。
    import paths
    workspace = paths.DATA_DIR
    extra = [sys.executable] if getattr(sys, "frozen", False) else []
    for p in (paths.PYTHON_PATH_FILE, paths.WHITELIST_FILE):
        if os.path.isfile(p):
            extra.append(p)
    if "--accept" in sys.argv:
        m = collect_manifest(here, extra)
        save_baseline(workspace, m, app_dir=here, note="用户通过命令行重建基线")
        save_sentinel(workspace, m, here)
        print(f"已重建完整性基线，共 {len(m)} 个文件。")
        print(f"数据目录：{workspace}")
        return
    r = verify(here, workspace, extra)
    print(f"状态：{r['status_zh']}")
    print(f"基线时间：{r['baseline_time']}   已校验文件数：{r['checked']}")
    for label, key in (("被修改", "changed"), ("新增", "added"), ("缺失", "removed")):
        if r[key]:
            print(f"  {label}（{len(r[key])}）:")
            for f in r[key]:
                print("    " + f)
    print()
    print("提示：如确认这些改动是你自己做的（例如更新了 IOC），"
          "执行 python -m integrity --accept 重建基线。")
    print("注意：同权限的攻击者可以同时改代码和基线文件，本自检无法发现那种情况。")
    # 便于脚本化调用：0=正常/首次运行，2=检测到改动或基线丢失
    sys.exit(2 if r["status"] in ("changed", "baseline_lost") else 0)


if __name__ == "__main__":
    main()
