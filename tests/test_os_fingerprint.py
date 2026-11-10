"""Passive OS fingerprinting beyond the TTL: p0f-style SYN signatures and User-Agent families (issue #244)."""

from __future__ import annotations

import subprocess

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows
from pcap_doctor.osfp import match_syn, parse_syn_options, user_agent_os

LINUX_LAYOUT = ("mss", "sok", "ts", "nop", "ws")


def test_p0f_entries_match_their_own_fields() -> None:
    assert match_syn(64, True, 29200, 1460, 7, LINUX_LAYOUT) == "Linux 3.11 and newer"  # window = 20 x MSS
    assert match_syn(128, True, 8192, 1460, None, ("mss", "nop", "nop", "sok")) == "Windows 7 or 8"
    assert match_syn(64, True, 65535, 1460, 4, ("mss", "nop", "ws", "nop", "nop", "ts", "sok")) == "MacOS X 10.9 or newer"
    assert match_syn(64, False, 29200, 1460, 7, LINUX_LAYOUT) is None  # DF clear: no signature matches
    assert match_syn(64, True, 29200, 1400, 7, LINUX_LAYOUT) is None  # window is not 20 x this MSS


def test_option_parser_reads_layout_mss_and_window_scale() -> None:
    raw = bytes([2, 4, 0x05, 0xB4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7])
    assert parse_syn_options(raw) == (LINUX_LAYOUT, 1460, 7)


def test_user_agent_families_and_their_limits() -> None:
    assert user_agent_os("Mozilla/5.0 (Windows NT 10.0; Win64; x64)") == "Windows 10/11"
    assert user_agent_os("Mozilla/5.0 (Linux; Android 14; Pixel 8)") == "Android"  # not Linux
    assert user_agent_os("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)") == "iOS"  # not macOS
    assert user_agent_os("curl/8.4.0") is None


@requires_tshark
def test_os_log_carries_signature_and_user_agent(analyze_capture) -> None:
    rows = {r["host"]: r for r in log_rows(analyze_capture(fixture("os_syn_signatures.pcap")).index, "os")}
    assert rows["10.40.0.1"]["syn_signature"] == "Linux 3.11 and newer"
    assert rows["10.40.0.1"]["user_agent_os"] == "Linux"
    assert rows["10.40.0.2"]["syn_signature"] == "Windows 7 or 8"
    assert rows["10.40.0.2"]["user_agent_os"] is None
    assert rows["10.40.0.3"]["syn_signature"] == "MacOS X 10.9 or newer"
    assert rows["10.40.0.1"]["initial_ttl"] == 64  # the TTL guess is still there


@requires_tshark
def test_wireshark_reads_the_crafted_syn_fields() -> None:
    """Independent check: Wireshark decodes the MSS, window scale, window and TTL the fixture was built with."""
    out = subprocess.run(
        ["tshark", "-r", str(fixture("os_syn_signatures.pcap")), "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
         "-T", "fields", "-e", "ip.src", "-e", "tcp.options.mss_val", "-e", "tcp.options.wscale.shift",
         "-e", "tcp.window_size_value", "-e", "ip.ttl", "-e", "ip.flags.df"],
        capture_output=True, text=True, check=True,
    ).stdout
    rows = [line.split("\t") for line in out.splitlines() if line]
    assert rows[:3] == [
        ["10.40.0.1", "1460", "7", "29200", "64", "True"],
        ["10.40.0.2", "1460", "", "8192", "128", "True"],
        ["10.40.0.3", "1460", "4", "65535", "64", "True"],
    ]
