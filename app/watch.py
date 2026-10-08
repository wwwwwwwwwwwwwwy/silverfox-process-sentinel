# -*- coding: utf-8 -*-
"""
受监控文件 / 目录 —— 把"文件被改动就告警"从「只管程序自身」扩展到「用户指定的任意路径」。

## 与 integrity.py 的分工（刻意不合并）

  `integrity.py`  管**程序自己**的 24 个文件。基线随程序走，
                  改动含义是「我这个工具被人动了」—— 这是安全工具的自保。

  `watch.py`      管**用户关心的任意文件 / 目录**。基线随配置走，
                  改动含义是「我在乎的东西变了」—— 这是使用者的资产监控。

不合并的理由：生命周期不同（一个跟版本走、一个跟用户走）、
误报语义也不同（前者一旦变了就一定是异常，后者很可能是用户自己改的）。
混在一起会出现"我改了自己的文档，工具说程序被篡改了"这种荒谬结论。

## 为什么配置与基线放在**数据目录**而不是 app/

`app/` 被完整性自检覆盖。若把监控配置放进去，用户**每加一个路径**
都会改动被基线覆盖的文件 → 触发「程序文件已被改动」。
这与 `whitelist.json` 的处境相同，但 whitelist 只有一份、变更路径单一，
可以特判（见 server._refresh_integrity_baseline）；
而监控目标会频繁增删、内容还随文件系统变化，特判会迅速演变成一团特例。

所以配置与基线都放数据目录，并用另一套机制补上"谁改的"这个问题：
**每一次配置变更都写进 auditlog 留痕**。

## 明确的边界（必须说清，否则用户会以为它能做更多）

- **只知道「变了」，不知道「改了什么」。** 输出的是哈希差异，
  不是行级 diff；也**不阻断**改动，只告警。想知道具体内容得靠
  版本控制或备份对比。
- **有规模上限。** 单目标文件数与单文件哈希体积都有封顶（见下方常量）。
  超限时**如实报出被跳过的数量**，绝不静默略过 ——
  静默略过等于给攻击者留一扇门：把载荷放进一个巨大的目录里就隐身了。
- **改完又改回来的发现不了。** 默认 60 秒一轮，两次采样之间的
  「改 → 复原」与静止状态完全一致。抓这种需要文件系统的审计策略（SACL）。
- **快路径的取舍。** 默认用「文件大小 + 修改时间」做预筛，不变就跳过哈希
  （否则一个 2 万文件的目录每轮全量哈希会把 CPU 吃光）。
  代价是：**能改回时间戳的攻击者可以躲过快路径**。
  因此每 `FULL_RECHECK_EVERY` 轮做一次全量哈希兜底 ——
  这是"性能"与"漏报"之间显式的取舍，而不是无意中的疏漏。
"""

from __future__ import annotations

import hashlib
import json
import os
import stat as _stat
import threading
import time

import paths

WATCH_FILE = os.path.join(paths.DATA_DIR, "watchlist.json")
BASELINE_FILE = os.path.join(paths.DATA_DIR, "watch.baseline.json")

# 单目标文件数上限。到顶之后不再收录，但会在结果里报出被跳过的数量。
MAX_FILES_PER_TARGET = 20000
# 单文件哈希上限：超过就不算哈希（记为空串），并在结果里标注。
MAX_HASH_MB = 64
# 目录遍历时直接跳过的目录名（缓存 / 元数据，没有监控价值且会拖慢每轮扫描）
SKIP_DIR_NAMES = {"__pycache__", ".git", ".svn", "node_modules", "$RECYCLE.BIN",
                  "System Volume Information", ".venv", "venv"}
# 每多少轮做一次忽略 mtime 的全量哈希（兜底能改时间戳的干扰）
FULL_RECHECK_EVERY = 20

_LOCK = threading.RLock()
_cycle = 0


def _sha256(path: str, limit_mb: int = MAX_HASH_MB) -> str:
    """算文件哈希。读不到或超限返回空串 —— 调用方必须区分"空串"与"缺失"。"""
    try:
        if os.path.getsize(path) > limit_mb * 1024 * 1024:
            return ""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 256), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def target_id(path: str) -> str:
    """由绝对路径推出稳定短 ID。

    用路径的哈希而不是随机 UUID：重启后 ID 不变，用户导出的报告、
    历史日志里的 ID 才能跟界面上的对得上。
    """
    key = os.path.normcase(os.path.abspath(str(path or ""))).encode("utf-8", "replace")
    return hashlib.sha256(key).hexdigest()[:10]


def _is_reparse_point(p: str) -> bool:
    """目录联接 / 符号链接 / 挂载点。

    ⚠️ 必须跳过：本机 C 盘上就有 5 个目录联接（见用户长期记忆），
    不跳的话 os.walk 会顺着走进另一个卷，扫描量翻几倍还可能成环。
    """
    try:
        st = os.lstat(p)
        return bool(getattr(st, "st_file_attributes", 0) & _stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except Exception:
        return True


# ---------------------------------------------------------------- 配置读写

def _default_config() -> dict:
    return {"version": 1, "targets": []}


def load() -> dict:
    """读配置。文件不存在时**主动创建空表** —— 与 whitelist 同理：
    让"文件是否存在"这件事恒定，避免下游把"首次运行"当成"配置被人删了"。"""
    try:
        with open(WATCH_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict) and isinstance(d.get("targets"), list):
            d.setdefault("version", 1)
            return d
    except FileNotFoundError:
        d = _default_config()
        try:
            save(d)
        except Exception:
            pass
        return d
    except Exception as e:
        # 损坏 ≠ 空表。保留原文件，并把损坏状态报出去（调用方据此拒绝写入）。
        d = _default_config()
        d["_corrupt"] = repr(e)
        return d
    return _default_config()


def save(d: dict) -> None:
    """原子写：临时文件 + fsync + os.replace。

    直接用 "w" 覆写时读方可能拿到半截 JSON；一旦它再把半截内容写回来，
    用户的监控目标就全丢了（whitelist 踩过同一个坑，见 F-017）。
    """
    tmp = WATCH_FILE + ".tmp"
    with _LOCK:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, WATCH_FILE)


# ---------------------------------------------------------------- 清单采集

def _collect_dir(base: str, recursive: bool) -> tuple[dict, dict]:
    """返回 ({相对路径: {h,s,t}}, 统计)。s=size t=mtime_ns h=sha256。"""
    out: dict[str, dict] = {}
    skipped_big = 0
    truncated = 0
    try:
        if recursive:
            walker = os.walk(base, followlinks=False, onerror=lambda e: None)
        else:
            # 非递归：只列一层。用一个假的 walker 保持下面逻辑一致。
            names = os.listdir(base)
            walker = [(base, [], sorted(names))]
        for root, dirs, files in walker:
            dirs[:] = [d for d in dirs
                       if d not in SKIP_DIR_NAMES
                       and not _is_reparse_point(os.path.join(root, d))]
            for fn in sorted(files):
                p = os.path.join(root, fn)
                if len(out) >= MAX_FILES_PER_TARGET:
                    truncated += 1
                    continue
                try:
                    st = os.stat(p)
                except Exception:
                    continue
                if not _stat.S_ISREG(st.st_mode):
                    continue
                rel = os.path.relpath(p, base).replace("\\", "/")
                size = st.st_size
                if size > MAX_HASH_MB * 1024 * 1024:
                    skipped_big += 1
                    out[rel] = {"h": "", "s": size, "t": st.st_mtime_ns}
                    continue
                out[rel] = {"h": _sha256(p), "s": size, "t": st.st_mtime_ns}
    except Exception:
        pass
    return out, {"files": len(out), "too_big": skipped_big, "truncated": truncated}


def scan_target(t: dict) -> dict:
    """采集单个目标的当前状态。返回 {status, files:{}, stats:{}}。"""
    p = str(t.get("path") or "")
    if not p:
        return {"status": "empty", "files": {}, "stats": {}}
    if not os.path.exists(p):
        return {"status": "missing", "files": {}, "stats": {}}
    if os.path.isdir(p):
        if _is_reparse_point(p):
            return {"status": "reparse", "files": {}, "stats": {}}
        files, stats = _collect_dir(p, bool(t.get("recursive", True)))
        return {"status": "ok", "files": files, "stats": stats}
    st = os.stat(p)
    return {"status": "ok",
            "files": {".": {"h": _sha256(p), "s": st.st_size, "t": st.st_mtime_ns}},
            "stats": {"files": 1, "too_big": 1 if st.st_size > MAX_HASH_MB * 1024 * 1024 else 0,
                      "truncated": 0}}


# ---------------------------------------------------------------- 基线

def load_baseline() -> dict:
    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict) and isinstance(d.get("targets"), dict):
            return d
    except Exception:
        pass
    return {"version": 1, "created": "", "targets": {}}


def save_baseline(d: dict) -> None:
    tmp = BASELINE_FILE + ".tmp"
    with _LOCK:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, BASELINE_FILE)


def rebuild(cfg: dict | None = None) -> dict:
    """把当前状态整体记为「已知正常」。加完监控目标后必须走这一步。

    ⚠️ 这也正是「篡改告警」最容易被自己绊倒的地方：
    程序自身被改动后如果忘了重建基线，界面会一直红着。
    所以 server 在每次版本变更后会自动重建（见 Monitor.check_integrity 的注释）。
    """
    cfg = cfg if cfg is not None else load()
    base = {"version": 1, "created": time.strftime("%Y-%m-%d %H:%M:%S"), "targets": {}}
    for t in cfg.get("targets") or []:
        tid = t.get("id") or target_id(t.get("path"))
        if not t.get("enabled", True):
            continue
        r = scan_target(t)
        base["targets"][tid] = {
            "path": t.get("path"),
            "status": r["status"],
            "files": r["files"],
        }
    save_baseline(base)
    return base


# ---------------------------------------------------------------- 比对

def verify(cfg: dict | None = None, force_full: bool = False) -> dict:
    """比对当前状态与基线，返回差异。

    返回结构：
      {"findings": [...], "targets": [{...}], "stats": {...}}
    findings 每条 = 一个具体的差异对象（某个文件被改 / 新增 / 删除）。
    """
    global _cycle
    _cycle += 1
    full = force_full or (_cycle % FULL_RECHECK_EVERY == 0)

    cfg = cfg if cfg is not None else load()
    base = load_baseline().get("targets", {})
    findings: list[dict] = []
    targets: list[dict] = []
    # 基线中已不存在于配置里的目标要清理掉，否则文件会无限增长
    live_ids = set()

    for t in cfg.get("targets") or []:
        tid = t.get("id") or target_id(t.get("path"))
        live_ids.add(tid)
        if not t.get("enabled", True):
            targets.append({"id": tid, "path": t.get("path"), "label": t.get("label", ""),
                            "recursive": bool(t.get("recursive", True)), "status": "disabled",
                            "files": 0, "changed": 0, "added": 0, "removed": 0})
            continue

        cur = scan_target(t)
        old = (base.get(tid) or {}).get("files")
        row = {
            "id": tid, "path": t.get("path"), "label": t.get("label", ""),
            "recursive": bool(t.get("recursive", True)),
            "status": cur["status"], "files": cur["stats"].get("files", 0),
            "too_big": cur["stats"].get("too_big", 0),
            "truncated": cur["stats"].get("truncated", 0),
            "changed": 0, "added": 0, "removed": 0,
        }

        if cur["status"] == "missing":
            row["note"] = "路径不存在"
            targets.append(row)
            continue
        if cur["status"] == "reparse":
            row["note"] = "目录联接/符号链接，已跳过（避免跨卷遍历）"
            targets.append(row)
            continue
        if old is None:
            # 还没建基线 —— 首次采集不算篡改，只是"待建立基线"。
            row["note"] = "尚未建立基线"
            targets.append(row)
            continue

        curf, oldf = cur["files"], old
        for rel in sorted(oldf):
            if rel not in curf:
                findings.append(_mk(tid, t, rel, "removed", oldf[rel].get("h"), None))
                row["removed"] += 1
            else:
                o, c = oldf[rel], curf[rel]
                # 快路径：大小与 mtime 都没变就跳过哈希（除非本轮是全量复核）
                if not full and o.get("s") == c.get("s") and o.get("t") == c.get("t"):
                    continue
                if (o.get("h") or "") != (c.get("h") or ""):
                    findings.append(_mk(tid, t, rel, "changed", o.get("h"), c.get("h")))
                    row["changed"] += 1
        for rel in sorted(curf):
            if rel not in oldf:
                findings.append(_mk(tid, t, rel, "added", None, curf[rel].get("h")))
                row["added"] += 1

        targets.append(row)

    # 清理已从配置中移除的目标的基线
    stale = [k for k in base if k not in live_ids]
    if stale:
        b = load_baseline()
        for k in stale:
            b["targets"].pop(k, None)
        try:
            save_baseline(b)
        except Exception:
            pass

    return {
        "findings": findings,
        "targets": targets,
        "stats": {"total": len(findings),
                  "changed": sum(1 for f in findings if f["kind"] == "changed"),
                  "added": sum(1 for f in findings if f["kind"] == "added"),
                  "removed": sum(1 for f in findings if f["kind"] == "removed"),
                  "full_recheck": full, "cycle": _cycle},
    }


def _mk(tid: str, t: dict, rel: str, kind: str, old_h, new_h) -> dict:
    p = t.get("path") or ""
    full = p if rel == "." else os.path.join(p, rel.replace("/", os.sep))
    return {
        "target_id": tid,
        "label": t.get("label") or os.path.basename(p.rstrip("\\/")) or p,
        "path": p,
        "file": rel,
        "full_path": full,
        "kind": kind,
        "old": (old_h or "")[:16],
        "new": (new_h or "")[:16],
    }


def signature(f: dict) -> str:
    """一条差异的稳定指纹 —— 供服务端去重，避免每轮重复告警。"""
    return "|".join([f.get("target_id", ""), f.get("file", ""),
                     f.get("kind", ""), f.get("new") or "x"])


# ---------------------------------------------------------------- 增删

def add(path: str, recursive: bool = True, label: str = "") -> tuple[bool, str, dict | None]:
    """添加监控目标。返回 (成功, 说明, 目标)。"""
    p = os.path.abspath(os.path.expandvars((path or "").strip().strip('"')))
    if not p:
        return False, "路径为空", None
    if "\x00" in p or any(ord(c) < 32 for c in p):
        return False, "路径含控制字符，已拒绝", None
    if not os.path.exists(p):
        return False, f"路径不存在：{p}", None
    if os.path.isdir(p) and _is_reparse_point(p):
        return False, "该目录是联接/符号链接，请填它指向的真实目录", None

    cfg = load()
    if cfg.get("_corrupt"):
        return False, "配置文件已损坏，拒绝写入（避免覆盖掉原有目标）", None
    tid = target_id(p)
    for t in cfg["targets"]:
        if t.get("id") == tid:
            t["enabled"] = True
            t["recursive"] = bool(recursive)
            if label:
                t["label"] = label
            save(cfg)
            return True, "该路径已在监控列表中，已重新启用", t
    t = {"id": tid, "path": p, "recursive": bool(recursive),
         "label": label or (os.path.basename(p.rstrip("\\/")) or p),
         "enabled": True, "added": time.strftime("%Y-%m-%d %H:%M:%S")}
    cfg["targets"].append(t)
    save(cfg)
    return True, "已添加，正在为它建立基线", t


def remove(tid: str) -> tuple[bool, str]:
    cfg = load()
    if cfg.get("_corrupt"):
        return False, "配置文件已损坏，拒绝写入"
    before = len(cfg["targets"])
    cfg["targets"] = [t for t in cfg["targets"] if t.get("id") != tid]
    if len(cfg["targets"]) == before:
        return False, "没有找到该监控目标"
    save(cfg)
    try:
        b = load_baseline()
        b["targets"].pop(tid, None)
        save_baseline(b)
    except Exception:
        pass
    return True, "已移除"


def listing() -> dict:
    cfg = load()
    return {
        "targets": cfg.get("targets") or [],
        "corrupt": bool(cfg.get("_corrupt")),
        "corrupt_detail": cfg.get("_corrupt") or "",
        "limits": {"max_files": MAX_FILES_PER_TARGET, "max_hash_mb": MAX_HASH_MB,
                   "full_recheck_every": FULL_RECHECK_EVERY},
    }


def main():
    """命令行：python -m watch [--rebuild] [--add <路径>] [--remove <id>]"""
    import sys
    if "--rebuild" in sys.argv:
        b = rebuild()
        print(f"已重建监控基线，共 {len(b['targets'])} 个目标。")
        return
    if "--add" in sys.argv:
        i = sys.argv.index("--add")
        ok, msg, t = add(sys.argv[i + 1] if i + 1 < len(sys.argv) else "")
        print(msg)
        if ok:
            rebuild()
        return
    r = verify(force_full=True)
    for row in r["targets"]:
        print(f"[{row['status']}] {row['path']}  文件 {row['files']}  "
              f"改 {row['changed']} 增 {row['added']} 删 {row['removed']}")
    for f in r["findings"][:50]:
        print(f"  {f['kind']:8s} {f['full_path']}")
    print(f"合计 {r['stats']['total']} 条差异")


if __name__ == "__main__":
    main()
