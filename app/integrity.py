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
# ⚠️ 不要用 os.path.expandvars：%LOCALAPPDATA% 未定义时它**原样留下字面量**，
#    于是 SENTINEL_DIR 退化成相对 CWD 的路径 —— 哨兵整体失效（红队 F-016）。
#    这里显式判断：拿不到绝对路径就退到家目录下的点目录。
_lad = os.environ.get("LOCALAPPDATA")
if _lad and os.path.isabs(_lad):
    SENTINEL_DIR = os.path.join(_lad, "YinhuSentinel")
else:
    SENTINEL_DIR = os.path.join(os.path.expanduser("~"), ".YinhuSentinel")
SENTINEL_FILE = "integrity.sentinel.json"


def _install_tag(app_dir: str | None) -> str:
    """把「程序目录」压成一个短标签，用于给基线/哨兵文件命名。

    为什么需要它（红队 F-015）：基线原本是每用户单份文件、只能记一个 app_dir。
    同机跑两份副本时，A 写完写 app_dir=A，B 启动发现"基线属于别的目录" →
    当作首次运行 → 重建基线（app_dir=B）；A 再启动又被顶回去。
    **交替运行 = 每次都是 first_run，changed 永远不出现。**
    而本仓库自带的「本机副本管理」恰恰鼓励用户保留多份副本。

    改成每份安装各有一个基线文件后，冲突从根上消失。
    """
    if not app_dir:
        return "default"
    key = os.path.normcase(os.path.abspath(app_dir)).encode("utf-8")
    return hashlib.sha256(key).hexdigest()[:12]


def sentinel_path(app_dir: str | None = None) -> str:
    return os.path.join(SENTINEL_DIR,
                        f"integrity.sentinel.{_install_tag(app_dir)}.json")


def sentinel_belongs_here(sent: dict | None, app_dir: str) -> bool:
    """哨兵是否属于**本安装**。

    判据**只看 app_dir（程序目录）**，不看数据目录。两条理由都是实测出来的：

      · 数据目录是每用户的，同机多份副本共用它 —— 把它算进判据，
        另一份副本会被误判成"本安装的基线被删"（假告警）；
      · 数据目录本身会变（改 LOCALAPPDATA、%TEMP% 每会话不同）——
        把它算进判据，**本安装**又会被误判成"别人的哨兵"，
        于是走"首次运行、静默重建基线"（红队 F-016）——
        这是往"不告警"的方向错，比假告警危险得多。

    程序目录才是"这是哪一份安装"的稳定标识。

    ⚠️ 抽成函数的原因：原先这段逻辑内联在 verify() 里，
    而 _refresh_integrity_baseline() 完全没有 —— 于是"删基线 + 点一次加入已知项"
    就能把基线静默重建、完整性告警永远不出现（红队 F-002，实测 2/2）。
    两份实现必然漂移，所以只留一份。
    """
    if not sent:
        return False
    a = str(sent.get("app_dir") or "")
    if not a:
        return False
    return os.path.normcase(a) == os.path.normcase(os.path.abspath(app_dir))


def load_sentinel(app_dir: str | None = None) -> dict | None:
    try:
        with open(sentinel_path(app_dir), "r", encoding="utf-8") as f:
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
        with open(sentinel_path(app_dir), "w", encoding="utf-8") as f:
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


def default_extras() -> list[str]:
    """完整性覆盖范围的**唯一**来源 —— 不允许调用方各自决定。

    ## 为什么必须收敛到一处

    原先三处调用点各写一份，其中两处漏掉了 python_path.txt 与 whitelist.json：

        · server.py 运行期 _integrity_extras()   → 完整（含 python_path.txt）
        · main.py   --verify-only                → 只有 sys.executable（漏）
        · server.py accept_integrity()           → 只有 sys.executable（漏）

    后果是**健康安装上 `--verify-only` 也报「程序文件已被改动」并 exit 2**
    （实测：`缺失：python_path.txt、whitelist.json`），而重建基线用的又是弱清单 ——
    怎么点都消不掉。这条 critical 告警一旦常态化误报，用户就会学会无视它，
    等于把整个完整性自检废掉。任何"启动自检门"在此之前都不能启用（启用即锁死）。

    收敛之后：调用方只负责调用，覆盖范围只有这里一处定义。
    """
    import paths                      # 局部导入，避免与 server 的循环依赖
    extra: list[str] = []
    if getattr(sys, "frozen", False):
        extra.append(sys.executable)
    for p in (paths.PYTHON_PATH_FILE, paths.WHITELIST_FILE):
        if os.path.isfile(p):
            extra.append(p)
    # F-014：启动链上真正决定"执行什么"的东西原先**不在覆盖范围内** ——
    #   启动银狐监视器.bat（它 start 解释器）与 runtime\pythonw.exe。
    #   改一个 .bat 的字节就能劫持启动，而自检完全无感。
    #   作者已经把 python_path.txt 纳进来了（理由正是"启动器会执行它写的解释器"），
    #   同一逻辑要贯彻到启动器本身。
    import glob
    for pattern in (os.path.join(paths.PROGRAM_DIR, "*.bat"),
                    os.path.join(paths.PROGRAM_DIR, "*.py"),
                    os.path.join(paths.PROGRAM_DIR, "runtime", "pythonw.exe")):
        extra.extend(sorted(f for f in glob.glob(pattern) if os.path.isfile(f)))
    return extra


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
            # ⚠️ 键要带 <root>/ 前缀：否则 app/ 下若出现同名文件（例如
            #    app/README.md 与根目录 README.md）会在字典里互相覆盖，
            #    覆盖掉的那一个就**悄悄不再被校验**了。
            manifest["<root>/" + os.path.basename(p)] = _sha256(p)
    return manifest


def baseline_path(workspace: str, app_dir: str | None = None) -> str:
    """基线文件路径 —— **每份安装一个**（见 _install_tag 的说明）。"""
    if app_dir is None:
        return os.path.join(workspace, BASELINE_FILE)
    return os.path.join(workspace, f"integrity.baseline.{_install_tag(app_dir)}.json")


def load_baseline(workspace: str, app_dir: str | None = None) -> dict | None:
    """读本安装的基线；找不到再退到无后缀的旧文件名（一次性迁移）。"""
    cands = [baseline_path(workspace, app_dir)]
    if app_dir is not None:
        cands.append(baseline_path(workspace, None))   # 旧命名，兼容迁移
    for p in cands:
        try:
            with open(p, "r", encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, dict) and isinstance(d.get("files"), dict):
                return d
        except Exception:
            continue
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
    with open(baseline_path(workspace, app_dir), "w", encoding="utf-8") as f:
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
    # 基线按安装分文件（F-015）——"属于别的程序目录"那种冲突从命名上就不存在了，
    # 所以原先那段"app_dir 对不上就当首次运行"的逻辑整段删掉。
    base = load_baseline(workspace, app_dir)
    if not base:
        sent = load_sentinel(app_dir)
        # 归属判断走公共函数（唯一口径）—— 同一安装换了数据目录仍算"本安装"，
        # 所以这里会判成基线丢失（告警），而不是静默重建。
        if sentinel_belongs_here(sent, app_dir):
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

    # F-016：用哨兵里的 count 做一次廉价交叉校验。
    # 哨兵是我们自己写的、记录"当时算出来几个文件"。若基线里的文件数
    # 与哨兵记录的对不上，说明这份基线**不是我们写的那一份**（被整份换过）——
    # 即使逐文件比对看起来"一致"，也应当警惕。
    # count 字段原先写进去却从没被读过，这是最廉价的一个信号，不该浪费。
    sent = load_sentinel(app_dir)
    count_mismatch = False
    if sentinel_belongs_here(sent, app_dir):
        n = sent.get("count")
        if isinstance(n, int) and n > 0 and len(old) != n:
            count_mismatch = True

    status = "changed" if (changed or added or removed or count_mismatch) else "ok"
    zh = {
        "ok": "文件完整性正常",
        "changed": "⚠️ 程序文件已被改动",
    }[status]
    if count_mismatch:
        zh = f"⚠️ 基线文件数与记录不符（记录 {sent.get('count')} / 实际 {len(old)}）"
    return {
        "status": status,
        "status_zh": zh,
        "checked": len(cur),
        "changed": changed[:20],
        "added": added[:20],
        "removed": removed[:20],
        "count_mismatch": count_mismatch,
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
    # 覆盖范围唯一来源（原先这里是一份内联实现，与其它调用点不一致）
    extra = default_extras()
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
