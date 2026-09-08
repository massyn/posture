"""Collect HTTP response headers for a handful of sites and print the DataFrame.

Run it directly:

    python examples/http_headers.py

The ``http`` source needs no credentials — the list of hosts below *is* the
scope boundary. Each host must carry an explicit ``http://`` or ``https://``
scheme; list a host twice with both schemes if you want both checked.
"""

from __future__ import annotations

from posture import CCM

HOSTS = [
    "https://www.google.com",
    "https://github.com",
    "http://neverssl.com",
    "https://expired.badssl.com",  # cert expired — falls back to insecure
    "https://this-host-does-not-exist.example",  # DNS failure — one error row
]


def main() -> None:
    ccm = CCM("http")
    df = ccm.collect("headers", hosts=HOSTS)
    print(df)


if __name__ == "__main__":
    main()
