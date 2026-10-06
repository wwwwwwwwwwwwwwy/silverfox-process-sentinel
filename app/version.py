# -*- coding: utf-8 -*-
"""版本标识 —— 让"哪个是旧版"这件事变成可判断的。

## 为什么需要这个文件

2026-10-05 之前，这套工具**没有任何版本号**。后果是实打实的：

  · 本机同时存在 4 个副本（安装版 / 开源副本 / 一个 2026-10-04 打包的 exe /
    Temp 里一份旧测试副本），谁新谁旧**只能靠文件时间猜**；
  · 用户看到界面长得一样，就以为"都是最新的"，结果点导出报错 ——
    因为跑的那份和修好的那份不是同一个；
  · 每次同步都要人工核对 md5，很容易漏。

所以加一个版本戳，并在界面、报告、副本清单里都显示出来。

## 版本号怎么定

`VERSION` = 日期 + 当日序号，例如 `2026.10.05.2` 表示 10 月 5 日的第 3 版
（序号从 0 开始）。**只要改了 app/ 下任何文件就必须递增** ——
`tools/本机副本.py` 会拿它来判断哪份新、哪份旧，不递增就会误判。

`BUILD` 是构建时刻，纯给人看的。

⚠️ 不要用"文件修改时间"来判断新旧 —— 复制、解压、改系统时间都会打乱它。
   内容哈希 + 显式版本号才可靠。
"""
from __future__ import annotations

VERSION = "2026.10.06.0"
BUILD = "2026-10-06 10:30"
CHANNEL = "stable"


def version_line() -> str:
    """一行式版本描述，给界面 / 报告 / 命令行共用。"""
    return f"v{VERSION}（{BUILD}）"


def compare(a: str, b: str) -> int:
    """比较两个版本号：a > b 返回 1，相等 0，a < b 返回 -1。

    逐段按数字比，段数不同时缺的段按 0 处理 ——
    这样 `2026.10.05` 与 `2026.10.05.0` 视为相同，不会因为写法差异误判。
    """
    def parts(v):
        out = []
        for seg in str(v or "").strip().split("."):
            # ⚠️ 不能用 isdigit()：它对上标数字（²）等 Unicode 字符也返回 True，
            #    但 int("²") 会抛 ValueError —— 而本函数在回归自检里明确声明
            #    "异常输入不抛异常"。改成只认 ASCII 数字 + 兜底。
            if seg.isascii() and seg.isdigit():
                out.append(int(seg))
            else:
                out.append(0)
        return out

    pa, pb = parts(a), parts(b)
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    return (pa > pb) - (pa < pb)
