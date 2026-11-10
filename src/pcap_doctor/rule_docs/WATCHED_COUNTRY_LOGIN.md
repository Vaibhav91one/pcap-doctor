# WATCHED_COUNTRY_LOGIN

## What it means
A login attempt in this capture came from a client address that the GeoIP database you supplied with `--geoip-db` places in a country you listed with `--watch-country`. The login is an HTTP Authorization header, a Telnet password, an FTP, POP3 or IMAP login, or an SMTP AUTH. The finding names the client, its ASN and country, the server and the frame.

## Why it matters
The login was sent in the clear, so its credential was visible to anyone on the path, and the source is somewhere you chose to watch. A login from that country may be expected (a travelling employee, a partner site) or may be a stolen credential being used from elsewhere. The country is only as accurate as the database, so this is a prompt to check, not a verdict.

## How to fix
- Check whether the account is expected to log in from that country.
- If it is not, block or review the source address and rotate the credential that was sent.
- Move the protocol to its encrypted form (HTTPS, IMAPS, POP3S, SMTPS with AUTH over TLS) so the credential is not exposed on the path.
- Refresh the GeoIP database if the address has moved.

## How to verify
Re-run `pcap-doctor analyze <capture> --geoip-db <file> --watch-country <CC>` against the same capture. The `WATCHED_COUNTRY_LOGIN` finding for that client must no longer appear, or the account must be confirmed as expected from that country.
