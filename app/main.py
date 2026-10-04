# -*- coding: utf-8 -*-
"""
银狐进程监视器 · 启动入口

启动流程：
  1. 在本地回环地址上起 HTTP 服务（默认 127.0.0.1:8787，端口占用则自动顺延）
  2. 以「应用模式」打开一个独立窗口（Edge / Chrome 的 --app 模式，无地址栏、无标签页）
     找不到 Chromium 内核浏览器时回退到系统默认浏览器
  3. 阻塞运行，等待用户关闭窗口后 Ctrl+C 退出

以应用模式运行的好处：无需 WebView2 / Electron 等额外运行时，
界面表现力却与原生应用一致，且部署体积几乎为零。
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import server  # noqa: E402

CREATE_NO_WINDOW = 0x08000000


def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def pick_port(start: int = 8787, tries: int = 30) -> int:
    for p in range(start, start + tries):
        if port_free(p):
            return p
    return 0


def find_chromium() -> str | None:
    cands = [
        os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    ]
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


def launch_window(url: str) -> str:
    """以独立应用窗口打开界面。返回所用方式说明。"""
    exe = find_chromium()
    if exe:
        profile = os.path.join(server.WORKSPACE, ".app-window")
        os.makedirs(profile, exist_ok=True)
        args = [
            exe,
            f"--app={url}",
            f"--user-data-dir={profile}",
            "--window-size=1520,960",
            "--window-position=60,40",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-features=Translate,msEdgeTranslate",
        ]
        try:
            subprocess.Popen(args, creationflags=CREATE_NO_WINDOW)
            return f"独立应用窗口（{os.path.basename(exe)}）"
        except Exception:
            pass
    try:
        webbrowser.open(url)
        return "系统默认浏览器"
    except Exception:
        return "未找到可用浏览器，请手动访问"


def find_running_instance() -> str | None:
    """探测是否已有监视器实例在运行。

    为什么需要：初版没有单实例保护，重复双击会开出多个实例 ——
    每个实例各占一个端口、各开一个窗口、各自重复做全盘扫描。
    实测中曾出现 3 个实例同时运行（端口 8787/8788/8789）。
    这里用 /api/ping 的专属标识确认是我们自己的实例，而不是恰好占用同端口的别的服务。

    加固（2026-10-04）：APP_ID 是源码常量、人人可见，本地攻击者起一个假 HTTP
    服务应答 `{"app": "yinhu-sentinel"}` 就能让启动器打开假界面（对抗测试 L8）。
    现在必须同时校验实例密钥 —— 密钥在首次运行时随机生成并保存在
    workspace\\instance.secret，伪造者拿不到密钥就骗不过探测。
    （同权限攻击者可以读取该文件，这是用户态工具的固有上限，见 README 第九节。）
    """
    import urllib.request
    for port in server.PORT_RANGE:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/ping", timeout=0.4) as r:
                d = json.loads(r.read().decode("utf-8"))
                if d.get("app") == server.APP_ID and \
                        d.get("secret") == server.INSTANCE_SECRET:
                    return f"http://127.0.0.1:{port}/"
        except Exception:
            continue
    return None


def main():
    import argparse
    ap = argparse.ArgumentParser(
        prog="银狐进程监视器",
        description="银狐（SilverFox）木马进程行为监视器")
    ap.add_argument("--port", type=int, default=None,
                    help="指定监听端口（默认在 8787-8816 中自动选择空闲端口）")
    ap.add_argument("--host", default="127.0.0.1",
                    help="监听地址，默认 127.0.0.1（仅本机）。不建议改成 0.0.0.0")
    ap.add_argument("--no-window", action="store_true",
                    help="不自动打开界面窗口（只起服务，自己用浏览器访问）")
    ap.add_argument("--verify-only", action="store_true",
                    help="只做程序文件完整性校验然后退出，不启动监视器")
    ap.add_argument("--proc-interval", type=float, default=3.0, metavar="秒",
                    help="进程扫描间隔，默认 3 秒。调大会降低 CPU 占用，"
                         "但存活时间短于该间隔的进程会漏掉")
    ap.add_argument("--artifact-interval", type=float, default=180.0, metavar="秒",
                    help="系统制品（计划任务/服务/驱动/启动项/Defender 排除项）扫描间隔，"
                         "默认 180 秒。这类东西变化很慢，调小意义不大且明显增加磁盘读")
    args = ap.parse_args()

    if args.verify_only:
        import integrity
        # 加固：GBK 控制台（chcp 936）下打印 ⚠️ 等字符会抛 UnicodeEncodeError，
        # 把 stdout 改为 errors=replace，避免自检因控制台编码崩溃。
        try:
            sys.stdout.reconfigure(errors="replace")
        except Exception:
            pass
        extra = [sys.executable] if getattr(sys, "frozen", False) else []
        r = integrity.verify(server.APP_DIR, server.WORKSPACE, extra)
        print(f"完整性状态：{r['status_zh']}")
        print(f"  基线时间：{r['baseline_time']}   已校验 {r['checked']} 个文件")
        for label, key in (("被修改", "changed"), ("新增", "added"), ("缺失", "removed")):
            if r.get(key):
                print(f"  {label}：")
                for f in r[key]:
                    print("    " + f)
        print("\n注意：同权限的攻击者可同时改代码与基线，本自检无法发现那种情况。")
        sys.exit(0 if r["status"] in ("ok", "first_run") else 2)

    if args.host not in ("127.0.0.1", "localhost"):
        print(f"⚠️  警告：监听地址被改为 {args.host}。这会让局域网内其他机器访问本界面，"
              f"强烈建议保持 127.0.0.1。")

    existing = find_running_instance()
    if existing:
        print("=" * 62)
        print("  检测到监视器已在运行，直接打开现有实例的窗口。")
        print(f"  地址：{existing}")
        print("=" * 62)
        if not args.no_window:
            launch_window(existing)
        return

    if args.port:
        if not port_free(args.port):
            print(f"错误：端口 {args.port} 已被占用")
            sys.exit(1)
        port = args.port
    else:
        port = pick_port(server.PORT_RANGE.start, len(server.PORT_RANGE))
    if not port:
        print("错误：找不到可用端口")
        sys.exit(1)

    srv, monitor = server.serve(args.host, port,
                                  proc_interval=max(0.5, args.proc_interval),
                                  artifact_interval=max(10.0, args.artifact_interval))
    url = f"http://{args.host}:{port}/"

    # 记录端口与会话令牌，供「停止监视器.bat」定位本实例并携带凭据
    # 加固背景：初版停止脚本裸发 POST /api/shutdown，被四层校验 403 拦截 ——
    # 实测停止功能完全失效（详见《优化说明.md》）。
    port_file = os.path.join(server.WORKSPACE, "runtime_port.txt")
    token_file = os.path.join(server.WORKSPACE, "runtime_token.txt")
    try:
        with open(port_file, "w", encoding="ascii") as f:
            f.write(str(port))
        with open(token_file, "w", encoding="ascii") as f:
            f.write(server.SESSION_TOKEN)
    except Exception:
        port_file = ""
        token_file = ""

    print("=" * 62)
    print("  银狐进程监视器  SilverFox Process Sentinel")
    print("=" * 62)
    print(f"  界面地址 : {url}")
    print(f"  监听范围 : {args.host}（{'仅本机可访问' if args.host.startswith('127.') else '⚠ 已开放给其他机器'}）")
    print("  网络外联 : 无（不发起任何外部连接）")
    print(f"  管理员   : {'是' if __import__('winapi').is_admin() else '否（部分检测能力受限）'}")
    print(f"  工作目录 : {server.WORKSPACE}")
    print(f"  扫描节奏 : 进程每 {args.proc_interval:g} 秒 / "
          f"系统制品每 {args.artifact_interval:g} 秒（可用 --proc-interval、"
          f"--artifact-interval 调整）")
    print("=" * 62)

    if args.no_window:
        print(f"  （--no-window：请自行用浏览器打开 {url}）")
    else:
        # 等首次扫描出数据再开窗，避免用户看到空表
        threading.Thread(target=_open_when_ready, args=(url,), daemon=True).start()

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已退出。")
    finally:
        monitor.running = False
        srv.server_close()
        for f in (port_file, token_file):
            if f:
                try:
                    os.remove(f)
                except Exception:
                    pass


def _open_when_ready(url: str, timeout: float = 40.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            import urllib.request
            with urllib.request.urlopen(url + "api/state", timeout=2) as r:
                d = json.loads(r.read().decode("utf-8"))
                if d.get("summary", {}).get("scan_count", 0) >= 1:
                    break
        except Exception:
            pass
        time.sleep(0.4)
    how = launch_window(url)
    print(f"  界面已通过「{how}」打开。")


if __name__ == "__main__":
    main()
