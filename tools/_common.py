# -*- coding: utf-8 -*-
"""
验证脚本的公共模块

设计目标：**可移植**。所有脚本不写死任何绝对路径，
而是从自身位置推导出仓库根目录，并**按进程归属**识别正在运行的实例。

为什么强调"按进程归属"：如果按端口段（8787-8816）找实例，
在同一台机器上跑着多份副本时很可能连错对象，得出完全相反的结论。
所以这里先枚举进程、用命令行里的 app\\main.py 路径筛出目标，再取它监听的端口。
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request

import psutil

# ---------------------------------------------------------------- 路径

def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def app_dir() -> str:
    return os.path.join(repo_root(), "app")


def ensure_import_path() -> str:
    d = app_dir()
    if d not in sys.path:
        sys.path.insert(0, d)
    return d


# ---------------------------------------------------------------- 实例识别

def _self_pid() -> int:
    return os.getpid()


def ancestor_pids() -> set[int]:
    """自身 + 所有祖先进程的 PID。

    ⚠️ 必须排除整条祖先链，不能只排除自己：
    脚本的命令行里往往也含 "main.py" 之类的字样，
    只排除自身的话会把**父进程（shell）**一起杀掉 —— 本项目开发中因此丢过两次测试输出。
    """
    out = {os.getpid()}
    try:
        p = psutil.Process(os.getpid())
        while True:
            p = p.parent()
            if p is None:
                break
            out.add(p.pid)
    except Exception:
        pass
    return out


def app_pids() -> set[int]:
    """找出属于**本仓库**的监视器进程。

    判据：命令行里出现本仓库 `app\\main.py` 的**完整路径**（正则允许 / 与 \\ 混用）。
    不用"含 main.py"这种宽松条件 —— 同机存在多份副本时会认错对象，
    而按端口段猜更不可靠（8787-8816 可能被别的程序占用）。
    """
    skip = ancestor_pids()
    pat = re.compile(
        re.escape(os.path.join(app_dir(), "main.py")).replace(r"\\", r"[\\\\/]"),
        re.I,
    )
    out = set()
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            if p.pid in skip:
                continue
            cl = " ".join(p.info["cmdline"] or [])
            if pat.search(cl):
                out.add(p.pid)
        except Exception:
            pass
    return out


def app_ports() -> list[int]:
    pids = app_pids()
    ports = set()
    for c in psutil.net_connections("tcp"):
        try:
            if c.status == "LISTEN" and c.laddr and c.pid in pids:
                ports.add(c.laddr.port)
        except Exception:
            pass
    return sorted(ports)


def kill_app(wait: float = 2.0) -> list[int]:
    """结束本仓库的监视器实例（含它打开的界面窗口）。"""
    killed = []
    for pid in app_pids():
        try:
            psutil.Process(pid).kill()
            killed.append(pid)
        except Exception:
            pass
    # 关掉界面窗口（应用模式启动的 Edge 进程）
    skip = ancestor_pids()
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            if p.pid in skip or (p.info["name"] or "").lower() != "msedge.exe":
                continue
            cl = " ".join(p.info["cmdline"] or []).replace("/", "\\").lower()
            if "app-window" in cl or "yinhu" in cl:
                p.kill()
        except Exception:
            pass
    if wait:
        time.sleep(wait)
    return killed


# ---------------------------------------------------------------- HTTP

def http(port: int, path: str, method: str = "GET", body: dict | None = None,
         token: str = "", timeout: float = 8.0):
    """裸 HTTP 请求，绕过浏览器缓存与 urllib 的重定向行为。

    返回 (状态码, 解析后的 JSON 或原文)。
    """
    payload = json.dumps(body or {}).encode() if method == "POST" else b""
    head = {
        "Host": f"127.0.0.1:{port}",
        "Connection": "close",
        "Content-Length": str(len(payload)),
    }
    if method == "POST":
        head["Content-Type"] = "application/json"
        if token:
            head["X-Yinhu-Token"] = token
    req = f"{method} {path} HTTP/1.1\r\n" + \
          "".join(f"{k}: {v}\r\n" for k, v in head.items()) + "\r\n"
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.sendall(req.encode() + payload)
    data = b""
    try:
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            data += chunk
    except Exception:
        pass
    s.close()
    txt = data.decode("utf-8", "replace")
    if not txt:
        return 0, None
    status = int(txt.split(" ")[1]) if " " in txt.split("\r\n")[0] else 0
    body_txt = txt.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in txt else ""
    try:
        return status, json.loads(body_txt)
    except Exception:
        return status, body_txt


def session_token(port: int) -> str:
    """从首页 HTML 里取本次会话令牌（仅用于本地测试）。"""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=6) as r:
            html = r.read().decode("utf-8", "replace")
        m = re.search(r'name="yinhu-token" content="([^"]+)"', html)
        return m.group(1) if m else ""
    except Exception:
        return ""


# ---------------------------------------------------------------- 启停

def start_app(wait_port: float = 45.0, use_launcher: bool = False) -> int | None:
    """拉起监视器，返回它监听的端口（失败返回 None）。

    默认用 **当前解释器**（`sys.executable`）启动，不走 `.bat`。原因有两条：

    1. 能跑起这个测试脚本，就说明当前解释器**必然装了 psutil** ——
       而 `.bat` 要靠猜（PATH / py 启动器），本机就出现过
       "psutil 装在 venv 里、`.bat` 找不到" 的情况；
    2. `.bat` 在找不到解释器时会 `pause`（对双击的用户是对的），
       但自动化调用会**永久阻塞** —— 本项目开发中因此挂死过一次。

    需要专门验证 `.bat` 本身时，传 use_launcher=True。
    """
    if use_launcher:
        bat = os.path.join(repo_root(), "启动银狐监视器.bat")
        if not os.path.isfile(bat):
            return None
        subprocess.Popen(["cmd", "/c", bat], cwd=repo_root())
    else:
        subprocess.Popen(
            [sys.executable, os.path.join(app_dir(), "main.py"), "--no-window"],
            cwd=repo_root(),
        )
    deadline = time.time() + wait_port
    while time.time() < deadline:
        time.sleep(1)
        ports = app_ports()
        if ports:
            return ports[0]
    return None


def wait_ready(port: int, timeout: float = 180.0, settle: float = 12.0) -> dict:
    """等首轮扫描与签名校验完成，再**多留一个扫描周期**。

    ⚠️ settle 不能省：签名结果先写进缓存，要等下一轮进程扫描才附加到进程对象上。
    队列排空后立刻采样，会看到一批 signature=None 的假象（这个坑踩过）。
    """
    deadline = time.time() + timeout
    st = {}
    while time.time() < deadline:
        time.sleep(2)
        try:
            code, st = http(port, "/api/state")
            s = (st or {}).get("summary") or {}
            if s.get("total", 0) > 50 and s.get("sig_pending") == 0 \
                    and s.get("scan_count", 0) >= 3:
                break
        except Exception:
            continue
    if settle:
        time.sleep(settle)
    try:
        _, st = http(port, "/api/state")
    except Exception:
        pass
    return st or {}


# ---------------------------------------------------------------- 断言

class Checker:
    def __init__(self, title: str = ""):
        self.passed: list[str] = []
        self.failed: list[str] = []
        if title:
            print(title)

    def check(self, name: str, cond, extra: str = ""):
        (self.passed if cond else self.failed).append(name)
        mark = "✅" if cond else "❌"
        print(f"  {mark} {name}" + (f"   {extra}" if extra else ""))
        return bool(cond)

    def report(self) -> int:
        print()
        print("=" * 72)
        print(f"通过 {len(self.passed)} 项，失败 {len(self.failed)} 项")
        for f in self.failed:
            print("  ✗ " + f)
        print("=" * 72)
        return 1 if self.failed else 0
