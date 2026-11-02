#!/usr/bin/env python3
"""SLAD — opcjonalne przypinanie w Pinata.

Pinata to hostowana usługa pinowania IPFS. Ten skrypt wywołuje wyłącznie jej
publiczne REST API przez bibliotekę `requests` — nie dołącza kodu Pinaty, więc
nie ma tu żadnej kwestii licencyjnej (SDK Pinaty jest zresztą MIT, jak SLAD).

Pinata jest OPCJONALNA: protokół SLAD nie zależy od żadnego serwera.
Używaj jej tylko jako dodatkowej kopii dla dostępności.

UWAGA: publiczna bramka Pinaty nie serwuje HTML (403). Pinata służy do
przypinania danych/śladów, nie do hostowania PWA.

Wymaga zmiennej środowiskowej PINATA_JWT (klucz JWT z konta Pinata).
Nigdy nie wpisuj klucza do kodu ani do aplikacji przeglądarkowej.

Użycie:
  PINATA_JWT='...' python3 pinata_pin.py <CID> [<CID> ...]
  PINATA_JWT='...' python3 pinata_pin.py --plik <ścieżka>

Obowiązują limity darmowego konta Pinata (rozmiar / liczba pinów).
"""
import os
import sys

try:
    import requests
except ImportError:
    sys.exit("Brak modułu requests. Zainstaluj: pip install requests")

API = "https://api.pinata.cloud"


def _jwt():
    token = os.environ.get("PINATA_JWT", "").strip()
    if not token:
        sys.exit('Brak PINATA_JWT. Ustaw: export PINATA_JWT="<twoj_jwt_z_pinata>"')
    return token


def pin_cid(cid):
    return requests.post(
        API + "/pinning/pinByHash",
        headers={"Authorization": "Bearer " + _jwt()},
        json={"hashToPin": cid},
        timeout=60,
    )


def pin_file(path):
    if not os.path.isfile(path):
        sys.exit("Nie ma pliku: " + path)
    with open(path, "rb") as f:
        return requests.post(
            API + "/pinning/pinFileToIPFS",
            headers={"Authorization": "Bearer " + _jwt()},
            files={"file": f},
            timeout=300,
        )


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)

    if args[0] == "--plik":
        if len(args) < 2:
            sys.exit("Podaj ścieżkę po --plik")
        r = pin_file(args[1])
        print(r.status_code, r.text[:500])
        return

    rc = 0
    for cid in args:
        r = pin_cid(cid)
        ok = r.status_code == 200
        print(cid, "->", r.status_code, ("OK" if ok else r.text[:200]))
        if not ok:
            rc = 1
    sys.exit(rc)


if __name__ == "__main__":
    main()
