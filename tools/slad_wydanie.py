#!/usr/bin/env python3
"""
SLAD — podpisywanie wydań oprogramowania.

Bierze pliki wydania, liczy SHA-256, tworzy podpisany ślad Ed25519
i publikuje go w IPFS. Wypisuje CID do wklejenia w README.

Użycie:
    SLAD_HASLO='...' python3 slad_wydanie.py --repo <url> --wersja <v> plik1 plik2...

Wynik:
    - ślad opublikowany w IPFS (CID),
    - plik WERYFIKACJA.md gotowy do commita,
    - kod wyjścia 0 przy sukcesie.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import slad_protokolu as S

WALLET = os.path.join(os.path.expanduser("~"), ".slad", "portfel.json")
STATE = os.path.join(os.path.expanduser("~"), ".slad", "stan.json")
ANCHOR = os.path.join(os.path.expanduser("~"), ".slad", "genesis-anchor.json")


def sha256_pliku(sciezka: str) -> str:
    """Hash pliku w strumieniu — działa dla plików wielogigabajtowych."""
    h = hashlib.sha256()
    with open(sciezka, "rb") as f:
        for blok in iter(lambda: f.read(1024 * 1024), b""):
            h.update(blok)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="Podpisuje wydanie oprogramowania śladem SLAD.")
    ap.add_argument("--repo", required=True, help="URL repozytorium / repository URL")
    ap.add_argument("--wersja", "--version", required=True, dest="wersja",
                    help="oznaczenie wersji, np. 1.0 / version label")
    ap.add_argument("--projekt", "--project", dest="projekt", default=None,
                    help="nazwa projektu (domyślnie: z --repo)")
    ap.add_argument("--haslo", "--password", dest="haslo", default=None,
                    help="hasło portfela / wallet password")
    ap.add_argument("--md", default="WERYFIKACJA.md", help="plik wyjściowy z instrukcją")
    ap.add_argument("--bez-ipfs", "--dry-run", "--no-ipfs",
                    action="store_true", dest="bez_ipfs",
                    help="only compute hashes, do not publish")
    ap.add_argument("pliki", nargs="+", help="pliki wydania")
    args = ap.parse_args()

    haslo = args.haslo or os.environ.get("SLAD_HASLO") or None
    projekt = args.projekt or args.repo.rstrip("/").split("/")[-1]

    # 1. hashe wszystkich plików
    wydania = []
    for p in args.pliki:
        if not os.path.isfile(p):
            print(f"błąd: brak pliku {p}", file=sys.stderr)
            return 1
        rozmiar = os.path.getsize(p)
        h = sha256_pliku(p)
        wydania.append({
            "plik": os.path.basename(p),
            "sha256": h,
            "rozmiar": rozmiar,
        })
        print(f"  {os.path.basename(p)}")
        print(f"    sha256: {h}")
        print(f"    rozmiar: {rozmiar} B")

    if args.bez_ipfs:
        print("\n[--bez-ipfs] Nic nie opublikowano.")
        return 0

    # 2. klucz i stan
    if not os.path.exists(WALLET):
        print(f"błąd: brak portfela {WALLET}", file=sys.stderr)
        print("      utwórz go: python3 slad_protokolu.py nowy-portfel", file=sys.stderr)
        return 1
    key = S.wczytaj_portfel(WALLET, haslo)
    autor = S.klucz_publiczny_hex(key)

    ipfs = S.IpfsKlient()
    stan = S.StanLokalny.wczytaj_klub_nowy(STATE)

    # 3. rodzic: korzeń zasiewu (jeśli znamy) — ślad wydania wisi pod nim
    rodzic = None
    if os.path.exists(ANCHOR):
        with open(ANCHOR, "r", encoding="utf-8") as f:
            rodzic = json.load(f).get("genesis_cid")
        if rodzic and rodzic not in stan.znane_slady:
            try:
                stan.znane_slady[rodzic] = S.pobierz_slad(ipfs, rodzic)
                stan.korzen_cid = rodzic
            except S.SladError:
                rodzic = None

    # 4. ślad
    payload = {
        "typ": "release",
        "projekt": projekt,
        "repo": args.repo,
        "wersja": args.wersja,
        "wydania": wydania,
        "data": time.strftime("%Y-%m-%d"),
    }

    try:
        cid, slad, koszt = S.publikuj_domyslnie(
            ipfs, stan, key, payload, parent_cid=rodzic, cooldown_s=0,
            wymuszone=True,
        )
    except S.SladError as exc:
        print(f"błąd publikacji: {exc}", file=sys.stderr)
        return 1

    # 5. ogłoś w DHT
    try:
        endpoint = ipfs.oglos_w_sieci(cid)
        ogloszono = f"tak ({endpoint})"
    except S.SladError as exc:
        ogloszono = f"nie ({exc})"

    print()
    print(f"CID śladu   : {cid}")
    print(f"Autor       : {S.adres_klucza(autor)}")
    print(f"Głębokość   : {slad['depth']}")
    print(f"Odcisk      : {S.hash_tresci(slad)}")
    print(f"Ogłoszono   : {ogloszono}")

    # 6. README dla użytkownika
    linie = [
        "# Weryfikacja wydania",
        "",
        f"Wydanie **{projekt} {args.wersja}** jest podpisane kryptograficznie",
        "kluczem Ed25519 autora i zapisane w IPFS jako ślad SLAD.",
        "",
        "## Ślad wydania",
        "",
        "```",
        f"CID        : {cid}",
        f"Autor      : {S.adres_klucza(autor)}",
        f"Klucz publ.: {autor}",
        f"Data       : {payload['data']}",
        "```",
        "",
        "## Sumy kontrolne plików",
        "",
        "| Plik | Rozmiar | SHA-256 |",
        "|---|---:|---|",
    ]
    for w in wydania:
        linie.append(f"| `{w['plik']}` | {w['rozmiar']} B | `{w['sha256']}` |")

    linie += [
        "",
        "## Jak sprawdzić pobrany plik",
        "",
        "**1. Policz SHA-256** i porównaj z tabelą powyżej:",
        "",
        "```bash",
        "# Linux / macOS",
        "sha256sum UNI-CNC-PRO-demo-linux-x86_64.tar.gz",
        "",
        "# Windows (PowerShell)",
        "Get-FileHash .\\UNI-CNC-PRO-demo-windows-x86_64.zip -Algorithm SHA256",
        "```",
        "",
        "**2. Pobierz i zweryfikuj ślad** (wymaga węzła IPFS):",
        "",
        "```bash",
        f"ipfs cat {cid}",
        "```",
        "",
        "**3. Sprawdź podpis** w aplikacji SLAD (zakładka 'Weryfikuj')",
        "lub w Pythonie:",
        "",
        "```python",
        "import json, sys",
        "sys.path.insert(0, 'raspbery')",
        "import slad_protokolu as S",
        f"slad = json.load(open('slad-{cid[:12]}.json'))",
        "S.weryfikuj_podpis(slad)   # brak wyjątku = podpis poprawny",
        "```",
        "",
        "## Co to daje, a czego nie daje",
        "",
        "**Daje:** pewność, że plik jest identyczny z tym, który podpisał autor.",
        "Nawet jeśli pobrałeś go z innego serwera, lustra lub od osoby trzeciej.",
        "",
        "**Nie daje:** oceny, czy program jest bezpieczny, poprawny lub przydatny.",
        "Podpis potwierdza pochodzenie, nie jakość.",
        "",
        "---",
        "",
        "Protokół: [SLAD](https://scifilabx.org/slad.php) · bez tokenów, bez pośredników",
        "",
    ]

    with open(args.md, "w", encoding="utf-8") as f:
        f.write("\n".join(linie))
    print(f"\nZapisano instrukcję: {args.md}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
