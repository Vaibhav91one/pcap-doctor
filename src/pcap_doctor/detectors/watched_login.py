"""D24 -- logins from watched countries (``analyze --watch-country``, judged by ``--geoip-db``, issue #238).

A login attempt is a credential the client sent in cleartext: an HTTP Authorization header, a Telnet password, an
FTP PASS, a POP3 PASS, an IMAP LOGIN or an SMTP AUTH. The client is the endpoint that is not on the service port,
and its country comes from the GeoIP CSV the user supplied. Nothing is looked up online. Confidence is medium: the
country is only as good as that file, and the client is picked from the port numbers.
"""

from __future__ import annotations

from typing import ClassVar

from ..index import WELL_KNOWN_PORTS, CaptureIndex
from ..models import Finding, Flow
from .base import Detector, ev

#: Login attempts in the services pass: protocol and a fragment of its detail. Values are never read.
_SERVICE_LOGIN_MARKERS: tuple[tuple[str, str], ...] = (
    ("ftp", "ftp.request.command=PASS"),
    ("pop3", "pop.request.command=PASS"),
    ("imap", " LOGIN "),
    ("smtp", "smtp.req.command=AUTH"),
)


def _client_and_server(flow: Flow) -> tuple[str, str]:
    """The client is the endpoint not on the service port. With no well-known port on either side, the lower port is the service."""
    a_service = flow.port_a in WELL_KNOWN_PORTS
    b_service = flow.port_b in WELL_KNOWN_PORTS
    if b_service and not a_service:
        return flow.endpoint_a, flow.endpoint_b
    if a_service and not b_service:
        return flow.endpoint_b, flow.endpoint_a
    if flow.port_a <= flow.port_b:
        return flow.endpoint_b, flow.endpoint_a
    return flow.endpoint_a, flow.endpoint_b


def _login_events(index: CaptureIndex) -> list[tuple[str, str, int]]:
    """(protocol, flow key, frame) for each login attempt the capture shows in cleartext."""
    events: list[tuple[str, str, int]] = [("http", exch.key, exch.frame) for exch in index.http if exch.auth_present]
    events += [("telnet", login.key, login.password_frame) for login in index.telnet_logins]
    for hit in index.services:
        for protocol, marker in _SERVICE_LOGIN_MARKERS:
            if hit.protocol == protocol and hit.detail and marker in hit.detail:
                events.append((protocol, hit.key, hit.frame))
                break
    return events


class WatchedCountryLoginDetector(Detector):
    name: ClassVar[str] = "d24.watched_country_login"
    title: ClassVar[str] = "Logins from watched countries"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "network"
    description: ClassVar[str] = (
        "Login attempts (HTTP Authorization, Telnet, FTP, POP3, IMAP, SMTP AUTH) whose client address the local "
        "GeoIP database places in a country you watch with analyze --watch-country (WATCHED_COUNTRY_LOGIN)."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        if not index.watch_countries or index.geoip is None:
            return []  # nothing to watch, or no local database to judge the address by
        out: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for protocol, key, frame in sorted(_login_events(index), key=lambda e: e[2]):
            flow = index.flows.get(key)
            if flow is None or (protocol, key) in seen:
                continue
            client, server = _client_and_server(flow)
            geo = index.geoip.lookup(client)
            if geo is None or geo.country.upper() not in index.watch_countries:
                continue
            seen.add((protocol, key))
            country = geo.country.upper()
            out.append(
                self.finding(
                    code="WATCHED_COUNTRY_LOGIN",
                    title=f"{protocol.upper()} login from watched country {country}",
                    severity="medium",
                    confidence="medium",
                    summary=(
                        f"{client} (AS{geo.asn} {geo.as_name}, {country}) sent a {protocol.upper()} login attempt to "
                        f"{server} at frame {frame}. The country comes from the GeoIP database you supplied, which "
                        "can be out of date for this address."
                    ),
                    scope=f"{key}|watched-login|{protocol}",
                    flow_key=key,
                    subjects=[client, server],
                    evidence=[ev(frame, f"{protocol}.login", f"{client} from {country}")],
                    remediation=(
                        "Check that this account is expected to log in from that country. If it is not, block or "
                        "review the source address and rotate the credential."
                    ),
                    references=[],
                    tags=["login", "geoip", "policy"],
                )
            )
        return out
