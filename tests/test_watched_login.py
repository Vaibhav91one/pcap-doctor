"""Logins from watched countries: detector d23 with the local GeoIP database and --watch-country (issue #238)."""

from __future__ import annotations

from pathlib import Path

from conftest import fixture, requires_tshark
from pcap_doctor.geoip import load_geoip
from pcap_doctor.pipeline import analyze

#: The FTP client is 198.51.100.7 (RU); the HTTP client is 10.30.0.9 (US, a private range given a row for the test).
GEO_CSV = "network,asn,as_name,country\n198.51.100.0/24,64496,Example Transit,RU\n10.0.0.0/8,64497,Lab Net,US\n"


def _watched(tmp_path: Path, countries: tuple[str, ...], *, with_geoip: bool = True):
    geo = None
    if with_geoip:
        path = tmp_path / "geo.csv"
        path.write_text(GEO_CSV)
        geo = load_geoip(path)
    return analyze(fixture("watched_login.pcap"), watch_countries=countries, geoip=geo).report.findings


@requires_tshark
def test_login_from_a_watched_country_is_reported(tmp_path: Path) -> None:
    findings = [f for f in _watched(tmp_path, ("ru",)) if f.code == "WATCHED_COUNTRY_LOGIN"]
    assert len(findings) == 1
    assert findings[0].subjects[0] == "198.51.100.7"
    assert "FTP login from watched country RU" in findings[0].title


@requires_tshark
def test_each_watched_country_is_matched_separately(tmp_path: Path) -> None:
    findings = [f for f in _watched(tmp_path, ("ru", "us")) if f.code == "WATCHED_COUNTRY_LOGIN"]
    assert sorted(f.subjects[0] for f in findings) == ["10.30.0.9", "198.51.100.7"]


@requires_tshark
def test_nothing_is_reported_without_a_watch_list_or_a_database(tmp_path: Path) -> None:
    assert not [f for f in _watched(tmp_path, ()) if f.code == "WATCHED_COUNTRY_LOGIN"]
    assert not [f for f in _watched(tmp_path, ("ru",), with_geoip=False) if f.code == "WATCHED_COUNTRY_LOGIN"]
