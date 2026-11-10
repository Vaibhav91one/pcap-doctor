"""MS-SQL TDS: pre-login encryption negotiation, the Login7 credential and tds.log (issue #231)."""

from __future__ import annotations

import subprocess

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_login7_password_is_reported_present_and_redacted(analyze_capture) -> None:
    report = analyze_capture(fixture("mssql_tds.pcap")).report
    creds = [f for f in report.findings
             if f.code == "CLEARTEXT_CREDENTIAL" and f.evidence[0].field == "tds.7login.password"]
    # one cleartext login (ENCRYPT_NOT_SUP); the ENCRYPT_REQ connection carries no readable login
    assert len(creds) == 1
    assert creds[0].evidence[0].frame == 8
    assert creds[0].evidence[0].value == "<redacted 9 chars>"
    assert "Passw0rd!" not in repr(report.findings)


@requires_tshark
def test_tds_log_records_negotiation_and_login_never_the_password(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("mssql_tds.pcap")).index, "tds")
    # pre-login request and response on each connection: cleartext (NOT_SUP), then ENCRYPT_REQ
    assert [r["encryption"] for r in rows if r["msg_type"] == "prelogin"] == [
        "ENCRYPT_NOT_SUP", "ENCRYPT_NOT_SUP", "ENCRYPT_REQ", "ENCRYPT_REQ"]
    login = next(r for r in rows if r["msg_type"] == "login7")
    assert login["username"] == "sa"
    assert login["app_name"] == "pcap-test"
    assert login["server_name"] == "SQLHOST"
    assert login["password"] == "<redacted 9 chars>"
    assert "Passw0rd!" not in repr(rows)


@requires_tshark
def test_fixture_obfuscation_is_undone_by_wireshark() -> None:
    """Independent check: Wireshark's TDS dissector reverses the Login7 obfuscation of the fixture
    back to the password it was built with, so the bytes follow [MS-TDS] and not our own reading of it."""
    out = subprocess.run(
        ["tshark", "-r", str(fixture("mssql_tds.pcap")), "-Y", "tds.7login.password",
         "-T", "fields", "-e", "tds.7login.password"],
        capture_output=True, text=True, check=True,
    ).stdout
    assert out.strip() == "Passw0rd!"
