# -*- coding: utf-8 -*-
"""
网络采集层 —— 纯 ctypes 调用 Windows 原生接口，**零第三方依赖、零网络外联**。

对外提供三件事：

  1. `enumerate_tcp()`  当前全部 TCP 连接（IPv4 + IPv6），含状态、四元组与所属 PID
  2. `enumerate_udp()`  当前全部 UDP 套接字（用于端口清点）
  3. `estats`           每条 TCP 连接的**累计收发字节数**

为什么必须拿字节数
------------------
`psutil.net_connections()` 只能回答"此刻存在哪些连接"，回答不了"这条连接传了多少数据"。
而银狐的 C2 心跳恰恰表现为「长时间静默 + 周期性小数据突发」——
只看连接表，一条持久 C2 连接永远是"一直存在"，毫无时间结构可分析。
`GetPerTcpConnectionEStats` 是 Windows 自带的**每连接 TCP 统计**接口
（与 Wireshark 的 TCP Stream Graphs、`netsh trace` 同源），
读取的是 TCP 协议栈已经维护的计数器：**不需要内核驱动、不需要抓包、不改变任何流量**。

实测（2026-10-05，本机）：
    启用前读取 → 成功但全为 0（未开启采集）
    启用后读取 → 立刻拿到累计值（如 out=14996 / in=9925）
    连续采样   → 计数单调不减，且呈「离散突发」形态（t=6 出 1414B，t=7 入 333B，随后长时间不变）

安全边界
--------
本模块**只调用本机内核接口**：不发起任何网络请求、不做 DNS 解析、不打开任何 socket。
这是本工具"零外联"承诺的一部分，改动本文件时不得引入任何外部通信。

权限与降级
----------
读取 estats 需要管理员权限。非管理员时 `enable_estats` 会失败，
上层（netmon）自动退化为「仅连接建立事件」的检测模式 —— 仍能识别重连型心跳，
只是对"长连接上的周期性数据"无感。降级是静默且安全的，不会报错打断。
"""

from __future__ import annotations

import ctypes
import socket
import struct
import sys
from ctypes import wintypes

# ================================================================
# 常量
# ================================================================

AF_INET = 2
AF_INET6 = 23

TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1

ERROR_SUCCESS = 0
ERROR_INSUFFICIENT_BUFFER = 122

# MIB_TCP_STATE（Windows 定义）
TCP_STATE = {
    1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED",
    6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING",
    10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}

# 「连接当前存在」的状态集合。
# ⚠️ 必须排除 TIME_WAIT / CLOSED / DELETE_TCB：
#    客户端主动关闭后，四元组会在 TIME_WAIT 里停留 30–120 秒（Windows 默认 2×MSL）。
#    若把 TIME_WAIT 也算作"连接存在"，那么"关闭→重连"就永远观测不到，
#    重连型心跳会被误判成一条长连接 —— 这是本模块最容易踩的坑，实测确认。
LIVE_STATES = {"ESTABLISHED", "SYN_SENT", "SYN_RCVD",
               "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "LAST_ACK", "CLOSING"}

# TCP_ESTATS_TYPE
TCP_ESTATS_DATA = 1

MIB_TCP_STATE_ESTAB = 5

# ================================================================
# 结构体
# ================================================================


class MIB_TCPROW(ctypes.Structure):
    """estats 接口用的 TCP 行（不含 PID —— 它按四元组定位连接）。"""
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
    ]


class MIB_TCP6ROW(ctypes.Structure):
    """⚠️ 注意字段顺序与 MIB_TCP6ROW_OWNER_PID **不同**：这里 State 在最前。"""
    _fields_ = [
        ("State", ctypes.c_uint),
        ("LocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("RemoteAddr", ctypes.c_ubyte * 16),
        ("dwRemoteScopeId", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
    ]


class TCP_ESTATS_DATA_ROD_v0(ctypes.Structure):
    """只读动态数据（Read-Only Dynamic）—— 我们需要的累计字节数在这里。"""
    _fields_ = [
        ("DataBytesOut", ctypes.c_ulonglong),
        ("DataSegsOut", ctypes.c_ulonglong),
        ("DataBytesIn", ctypes.c_ulonglong),
        ("DataSegsIn", ctypes.c_ulonglong),
        ("SegsOut", ctypes.c_ulonglong),
        ("SegsIn", ctypes.c_ulonglong),
        ("SoftErrors", ctypes.c_ulong),
        ("SoftErrorReason", ctypes.c_ulong),
        ("SndUna", ctypes.c_ulong),
        ("SndNxt", ctypes.c_ulong),
        ("SndMax", ctypes.c_ulong),
        ("ThruBytesAcked", ctypes.c_ulonglong),
        ("RcvNxt", ctypes.c_ulong),
        ("ThruBytesReceived", ctypes.c_ulonglong),
    ]


class TCP_ESTATS_DATA_RW_v0(ctypes.Structure):
    """可写配置 —— 只有 EnableCollection 一项。"""
    _fields_ = [("EnableCollection", ctypes.c_ubyte)]


# ================================================================
# 动态库与函数签名
# ================================================================
# ⚠️ 必须显式声明 argtypes/restype：64 位下不声明会把指针截断成 32 位，
#    表现为随机崩溃或读到垃圾数据（ctypes 的经典坑）。

_AVAILABLE = False
_LOAD_ERROR = ""
_U64 = ctypes.POINTER(ctypes.c_ubyte)

try:
    _iphlpapi = ctypes.WinDLL("iphlpapi")

    _iphlpapi.GetExtendedTcpTable.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
        wintypes.ULONG, wintypes.ULONG, wintypes.ULONG]
    _iphlpapi.GetExtendedTcpTable.restype = wintypes.ULONG

    _iphlpapi.GetExtendedUdpTable.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
        wintypes.ULONG, wintypes.ULONG, wintypes.ULONG]
    _iphlpapi.GetExtendedUdpTable.restype = wintypes.ULONG

    _iphlpapi.SetPerTcpConnectionEStats.argtypes = [
        ctypes.POINTER(MIB_TCPROW), ctypes.c_int,
        _U64, wintypes.ULONG, wintypes.ULONG,
        _U64, wintypes.ULONG, wintypes.ULONG,
        _U64, wintypes.ULONG, wintypes.ULONG]
    _iphlpapi.SetPerTcpConnectionEStats.restype = wintypes.ULONG

    _iphlpapi.GetPerTcpConnectionEStats.argtypes = [
        ctypes.POINTER(MIB_TCPROW), ctypes.c_int,
        _U64, wintypes.ULONG, wintypes.ULONG,
        _U64, wintypes.ULONG, wintypes.ULONG,
        _U64, wintypes.ULONG, wintypes.ULONG]
    _iphlpapi.GetPerTcpConnectionEStats.restype = wintypes.ULONG

    _iphlpapi.SetPerTcp6ConnectionEStats.argtypes = [
        ctypes.POINTER(MIB_TCP6ROW), ctypes.c_int,
        _U64, wintypes.ULONG, wintypes.ULONG,
        _U64, wintypes.ULONG, wintypes.ULONG,
        _U64, wintypes.ULONG, wintypes.ULONG]
    _iphlpapi.SetPerTcp6ConnectionEStats.restype = wintypes.ULONG

    _iphlpapi.GetPerTcp6ConnectionEStats.argtypes = [
        ctypes.POINTER(MIB_TCP6ROW), ctypes.c_int,
        _U64, wintypes.ULONG, wintypes.ULONG,
        _U64, wintypes.ULONG, wintypes.ULONG,
        _U64, wintypes.ULONG, wintypes.ULONG]
    _iphlpapi.GetPerTcp6ConnectionEStats.restype = wintypes.ULONG

    _AVAILABLE = True
except Exception as e:                      # pragma: no cover - 非 Windows 或极端环境
    _LOAD_ERROR = f"{type(e).__name__}: {e}"


def available() -> bool:
    """扩展接口是否可用（老系统 / 非 Windows 上为 False）。"""
    return _AVAILABLE


def load_error() -> str:
    return _LOAD_ERROR


# ================================================================
# 地址与端口工具
# ================================================================

def _ntohs(v: int) -> int:
    return socket.ntohs(v & 0xFFFF)


def _ip4(v: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", v & 0xFFFFFFFF))


def _ip6(raw: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, raw)
    except Exception:
        return ""


# ================================================================
# 表枚举
# ================================================================

def _get_table(fn, family: int, table_class: int) -> bytes | None:
    """两次调用：先问大小，再取内容。返回原始缓冲区。"""
    size = wintypes.DWORD(0)
    rc = fn(None, ctypes.byref(size), False, family, table_class, 0)
    if rc != ERROR_INSUFFICIENT_BUFFER or size.value == 0:
        return None
    buf = ctypes.create_string_buffer(size.value)
    rc = fn(buf, ctypes.byref(size), False, family, table_class, 0)
    if rc != ERROR_SUCCESS:
        return None
    return buf.raw


def enumerate_tcp() -> list[dict]:
    """当前全部 TCP 连接（IPv4 + IPv6）。

    返回 [{proto, state, lip, lport, rip, rport, pid}, ...]
    `proto` 取 'tcp4' / 'tcp6'。任何异常都返回已采到的部分，绝不抛出。
    """
    if not _AVAILABLE:
        return []
    out: list[dict] = []

    raw = _get_table(_iphlpapi.GetExtendedTcpTable, AF_INET, TCP_TABLE_OWNER_PID_ALL)
    if raw:
        n = struct.unpack_from("<I", raw, 0)[0]
        off = 4
        need = 24
        if len(raw) >= 4 + n * need:
            for _ in range(n):
                st, la, lp, ra, rp, pid = struct.unpack_from("<IIIIII", raw, off)
                off += need
                out.append({
                    "proto": "tcp4", "state": TCP_STATE.get(st, str(st)),
                    "lip": _ip4(la), "lport": _ntohs(lp),
                    "rip": _ip4(ra), "rport": _ntohs(rp), "pid": pid,
                })

    raw = _get_table(_iphlpapi.GetExtendedTcpTable, AF_INET6, TCP_TABLE_OWNER_PID_ALL)
    if raw:
        n = struct.unpack_from("<I", raw, 0)[0]
        off = 4
        need = 56
        if len(raw) >= 4 + n * need:
            for _ in range(n):
                la = raw[off:off + 16]
                lp = struct.unpack_from("<I", raw, off + 20)[0]
                ra = raw[off + 24:off + 40]
                rp = struct.unpack_from("<I", raw, off + 44)[0]
                st = struct.unpack_from("<I", raw, off + 48)[0]
                pid = struct.unpack_from("<I", raw, off + 52)[0]
                off += need
                out.append({
                    "proto": "tcp6", "state": TCP_STATE.get(st, str(st)),
                    "lip": _ip6(la), "lport": _ntohs(lp),
                    "rip": _ip6(ra), "rport": _ntohs(rp), "pid": pid,
                })
    return out


def enumerate_udp() -> list[dict]:
    """当前全部 UDP 套接字。

    ⚠️ UDP 表**只有本地地址/端口，没有远端**（UDP 无连接语义），
    所以它只能用于"端口清点"，无法参与远端维度的规律性分析。
    """
    if not _AVAILABLE:
        return []
    out: list[dict] = []

    raw = _get_table(_iphlpapi.GetExtendedUdpTable, AF_INET, UDP_TABLE_OWNER_PID)
    if raw:
        n = struct.unpack_from("<I", raw, 0)[0]
        off = 4
        need = 12
        if len(raw) >= 4 + n * need:
            for _ in range(n):
                la, lp, pid = struct.unpack_from("<III", raw, off)
                off += need
                out.append({"proto": "udp4", "lip": _ip4(la),
                            "lport": _ntohs(lp), "pid": pid})

    raw = _get_table(_iphlpapi.GetExtendedUdpTable, AF_INET6, UDP_TABLE_OWNER_PID)
    if raw:
        n = struct.unpack_from("<I", raw, 0)[0]
        off = 4
        need = 28
        if len(raw) >= 4 + n * need:
            for _ in range(n):
                la = raw[off:off + 16]
                lp = struct.unpack_from("<I", raw, off + 20)[0]
                pid = struct.unpack_from("<I", raw, off + 24)[0]
                off += need
                out.append({"proto": "udp6", "lip": _ip6(la),
                            "lport": _ntohs(lp), "pid": pid})
    return out


# ================================================================
# 每连接字节统计（estats）
# ================================================================

def _mkrow4(c: dict) -> MIB_TCPROW | None:
    try:
        row = MIB_TCPROW()
        row.dwState = MIB_TCP_STATE_ESTAB
        row.dwLocalAddr = struct.unpack("<I", socket.inet_aton(c["lip"]))[0]
        row.dwLocalPort = socket.htons(int(c["lport"]))
        row.dwRemoteAddr = struct.unpack("<I", socket.inet_aton(c["rip"]))[0]
        row.dwRemotePort = socket.htons(int(c["rport"]))
        return row
    except Exception:
        return None


def _mkrow6(c: dict) -> MIB_TCP6ROW | None:
    try:
        row = MIB_TCP6ROW()
        row.State = MIB_TCP_STATE_ESTAB
        row.LocalAddr = (ctypes.c_ubyte * 16)(*socket.inet_pton(socket.AF_INET6, c["lip"]))
        row.dwLocalPort = socket.htons(int(c["lport"]))
        row.RemoteAddr = (ctypes.c_ubyte * 16)(*socket.inet_pton(socket.AF_INET6, c["rip"]))
        row.dwRemotePort = socket.htons(int(c["rport"]))
        return row
    except Exception:
        return None


def _mkrow(c: dict):
    return _mkrow6(c) if c.get("proto") == "tcp6" else _mkrow4(c)


def enable_estats(c: dict) -> bool:
    """对一条 TCP 连接开启字节统计采集。

    必须每条连接单独调用一次 —— 采集开关是**按连接**保存的，不是全局的。
    开启后计数即为**自连接建立以来**的累计值（实测确认，不是从开启时刻起算），
    因此首次读取就能拿到有意义的数据，delta 计算天然成立。

    返回 True 表示成功。失败（多为非管理员）不抛异常，由上层降级处理。
    """
    if not _AVAILABLE:
        return False
    row = _mkrow(c)
    if row is None:
        return False
    rw = TCP_ESTATS_DATA_RW_v0()
    rw.EnableCollection = 1
    p = ctypes.cast(ctypes.byref(rw), _U64)
    try:
        if c.get("proto") == "tcp6":
            rc = _iphlpapi.SetPerTcp6ConnectionEStats(
                ctypes.byref(row), TCP_ESTATS_DATA, p, 0, ctypes.sizeof(rw),
                None, 0, 0, None, 0, 0)
        else:
            rc = _iphlpapi.SetPerTcpConnectionEStats(
                ctypes.byref(row), TCP_ESTATS_DATA, p, 0, ctypes.sizeof(rw),
                None, 0, 0, None, 0, 0)
        return rc == ERROR_SUCCESS
    except Exception:
        return False


def read_estats(c: dict) -> tuple[int, int] | None:
    """读取一条 TCP 连接的累计 (bytes_out, bytes_in)。

    返回 None 表示读不到（连接已消失 / 权限不足 / 未开启采集）。
    ⚠️ 调用方必须自行处理"计数回退"：连接被关闭后同一四元组可能被新连接复用，
    此时计数会跳回小值。这不是错误，而是"连接实例已更换"的信号。
    """
    if not _AVAILABLE:
        return None
    row = _mkrow(c)
    if row is None:
        return None
    rod = TCP_ESTATS_DATA_ROD_v0()
    p = ctypes.cast(ctypes.byref(rod), _U64)
    try:
        if c.get("proto") == "tcp6":
            rc = _iphlpapi.GetPerTcp6ConnectionEStats(
                ctypes.byref(row), TCP_ESTATS_DATA, None, 0, 0, None, 0, 0,
                p, 0, ctypes.sizeof(rod))
        else:
            rc = _iphlpapi.GetPerTcpConnectionEStats(
                ctypes.byref(row), TCP_ESTATS_DATA, None, 0, 0, None, 0, 0,
                p, 0, ctypes.sizeof(rod))
        if rc != ERROR_SUCCESS:
            return None
        return int(rod.DataBytesOut), int(rod.DataBytesIn)
    except Exception:
        return None


def selftest() -> dict:
    """自检：给界面「安全状态」面板用，证明采集层真的在工作。"""
    res = {"available": _AVAILABLE, "error": _LOAD_ERROR,
           "tcp": 0, "udp": 0, "estats_ok": False, "estats_note": ""}
    if not _AVAILABLE:
        res["estats_note"] = "iphlpapi 接口不可用"
        return res
    try:
        t = enumerate_tcp()
        res["tcp"] = len(t)
        res["udp"] = len(enumerate_udp())
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"
        return res
    # 找一条真实外网 ESTABLISHED 连接试读 estats
    for c in t:
        if c["state"] != "ESTABLISHED" or c["proto"] != "tcp4":
            continue
        if c["rip"].startswith(("127.", "0.")):
            continue
        if enable_estats(c):
            v = read_estats(c)
            if v is not None:
                res["estats_ok"] = True
                res["estats_note"] = f"示例连接 {c['rip']}:{c['rport']} 累计 out={v[0]} in={v[1]}"
            else:
                res["estats_note"] = "已开启采集但读取失败"
        else:
            res["estats_note"] = "开启采集失败（通常因为非管理员权限）"
        break
    return res


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    import json
    print(json.dumps(selftest(), ensure_ascii=False, indent=2))
