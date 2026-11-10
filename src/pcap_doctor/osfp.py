"""Passive OS fingerprinting beyond the initial TTL (issue #244): p0f-style TCP SYN signatures and User-Agent families.

The SYN table is a subset of the p0f v3 signature database, section ``[tcp:request]`` of ``p0f.fp``
(Michal Zalewski, LGPL; https://github.com/p0f/p0f/blob/master/p0f.fp). Only the labels and the signature
fields are copied, for the entries listed below. In p0f's notation a signature is
``ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass``; here ``ittl`` is the initial TTL, ``df`` the DF bit,
``window`` the window size (``mss*N`` means N times the MSS), ``mss`` and ``wscale`` the option values
(``*`` matches anything, ``0`` for ``wscale`` means no window-scale option), and ``layout`` the option kinds in
wire order with EOL left out. The first matching entry wins. Like p0f, this is a guess from the bytes a host
sends, not proof of the operating system.
"""

from __future__ import annotations

import re
from typing import NamedTuple


class SynSig(NamedTuple):
    label: str
    ittl: int
    df: bool
    window: str
    mss: str
    wscale: str
    layout: tuple[str, ...]


_LINUX = ("mss", "sok", "ts", "nop", "ws")
_WINDOWS = ("mss", "nop", "nop", "sok")
_WINDOWS_WS = ("mss", "nop", "ws", "nop", "nop", "sok")
_MAC = ("mss", "nop", "ws", "nop", "nop", "ts", "sok")

#: p0f v3 ``[tcp:request]`` entries (copied as data; the table order is the p0f match order for these fields).
P0F_TCP_REQUEST: tuple[SynSig, ...] = (
    SynSig("Linux 3.11 and newer", 64, True, "mss*20", "*", "10", _LINUX),
    SynSig("Linux 3.11 and newer", 64, True, "mss*20", "*", "7", _LINUX),
    SynSig("Linux 3.1-3.10", 64, True, "mss*10", "*", "*", _LINUX),
    SynSig("Linux 2.6.x", 64, True, "mss*4", "*", "*", _LINUX),
    SynSig("Android", 64, True, "mss*44", "*", "*", _LINUX),
    SynSig("Windows XP", 128, True, "65535", "*", "0", _WINDOWS),
    SynSig("Windows 7 or 8", 128, True, "8192", "*", "0", _WINDOWS),
    SynSig("Windows 7 or 8", 128, True, "8192", "*", "2", _WINDOWS_WS),
    SynSig("MacOS X 10.9 or newer", 64, True, "65535", "*", "4", _MAC),
    SynSig("iOS", 64, True, "65535", "*", "2", _MAC),
)

#: TCP option kinds by name (RFC 793, 2018, 7323 and 2018 SACK-permitted); unknown kinds keep their number.
_KIND_NAME = {0: "eol", 1: "nop", 2: "mss", 3: "ws", 4: "sok", 8: "ts"}


def parse_syn_options(raw: bytes) -> tuple[tuple[str, ...], int | None, int | None]:
    """Option layout (kinds in wire order, EOL excluded), the MSS value and the window-scale shift of a SYN."""
    layout: list[str] = []
    mss: int | None = None
    wscale: int | None = None
    i = 0
    while i < len(raw):
        kind = raw[i]
        if kind == 0:  # EOL ends the option list
            break
        if kind == 1:  # NOP is a single byte
            layout.append("nop")
            i += 1
            continue
        if i + 1 >= len(raw) or raw[i + 1] < 2 or i + raw[i + 1] > len(raw):
            break  # malformed: keep what was read
        length = raw[i + 1]
        value = raw[i + 2:i + length]
        if kind == 2 and length == 4:
            mss = int.from_bytes(value, "big")
        elif kind == 3 and length == 3:
            wscale = value[0]
        layout.append(_KIND_NAME.get(kind, f"kind{kind}"))
        i += length
    return tuple(layout), mss, wscale


def match_syn(ittl: int, df: bool, window: int, mss: int | None, wscale: int | None,
              layout: tuple[str, ...]) -> str | None:
    """The p0f label of the first ``P0F_TCP_REQUEST`` entry that matches these SYN fields, or None."""
    for sig in P0F_TCP_REQUEST:
        if sig.ittl != ittl or sig.df != df or sig.layout != layout:
            continue
        if sig.window.startswith("mss*"):
            if mss is None or window != int(sig.window[4:]) * mss:
                continue
        elif int(sig.window) != window:
            continue
        if sig.mss != "*" and (mss is None or int(sig.mss) != mss):
            continue
        if sig.wscale == "0" and wscale is not None:
            continue
        if sig.wscale not in ("*", "0") and (wscale is None or int(sig.wscale) != wscale):
            continue
        return sig.label
    return None


#: User-Agent product tokens, most specific first (an Android UA also says Linux, an iPhone UA also says Mac OS X).
_UA_FAMILIES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"Windows NT 10\.0"), "Windows 10/11"),
    (re.compile(r"Windows NT 6\.[23]"), "Windows 8"),
    (re.compile(r"Windows NT 6\.1"), "Windows 7"),
    (re.compile(r"Windows NT 5\.1"), "Windows XP"),
    (re.compile(r"iPhone|iPad|iPod"), "iOS"),
    (re.compile(r"Android"), "Android"),
    (re.compile(r"Macintosh|Mac OS X"), "macOS"),
    (re.compile(r"Linux"), "Linux"),
)


def user_agent_os(user_agent: str | None) -> str | None:
    """OS family a User-Agent claims. The host chooses this string, so it is a claim, not a measurement."""
    if not user_agent:
        return None
    for pattern, family in _UA_FAMILIES:
        if pattern.search(user_agent):
            return family
    return None
