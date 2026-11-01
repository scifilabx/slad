#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SLAD — niezależny protokół śladów oparty na IPFS.

Architektura
------------
* Brak serwerów centralnych, giełd i walut fiat w rdzeniu protokołu.
  Wartość wynika z użyteczności usługowej i dobrowolnego obrotu P2P.
* Ślad (trace) = podpisany kryptograficznie obiekt JSON publikowany w IPFS.
  CID obiektu staje się identyfikatorem śladu, a drzewo CID-ów — strukturą
  historii (każdy ślad wskazuje przez `parent_cid` na poprzednika).
* Tożsamość = klucz publiczny Ed25519 (32 B, hex). Ten sam klucz pochodzi
  z ziarna, więc jest odtwarzalny na papierze i możliwy do wyliczenia
  w portfelach sprzętowych (Ledger obsługuje Ed25519/EdDSA).
* Faza Zero: dokładnie 1024 pierwotne ślady rozchodzące się z jednego pnia
  (stożek binarny: 1 -> 2 -> 4 -> ... -> 512 + domknięcie stożka).

Ochrona przed botami (bez cenzury treści)
-----------------------------------------
1. Cooldown (time-lock): klucz nie może publikować śladów częściej niż
   co `cooldown` sekund — zegar jest liczony od `timestamp` ostatniego
   zaakceptowanego wpisu (łańcuch sam jest zegarem).
2. Kara za wielogałęziowość: koszt każdego następnego śladu rośnie
   wykładniczo z liczbą równoległych gałęzi prowadzonych tym samym kluczem.

Kodowanie CID
-------------
CIDv1 nie jest wynikiem krypto-hashu, więc nie da się go wyliczyć lokalnie.
Moduł używa węzła IPFS Kubo jako warstwy adresowania (`/api/v0/add`),
ale treść śladu jest deterministyczna, więc sha256(payload) pozwala
wykryć duplikaty i porównać ślady niezależnie od implementacji CID.

Wymagania: Python 3.9+, `requests`, `pynacl`, `cryptography` (opcjonalnie:
hasło portfela); działający `ipfs daemon` (Kubo) z API na 127.0.0.1:5001.
Uruchomienie: `python3 slad_protokolu.py --help`
Instrukcja krok po kroku: `README_SLAD.md`.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

# ---------------------------------------------------------------------------
# STAŁE PROTOKOŁU
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = "1.0"
DEFAULT_API_URL = os.environ.get("IPFS_API_URL", "http://127.0.0.1:5001")

# Faza Zero: dokładnie 1024 ślady w stożku binarnym (1 + 2 + 4 + ... + 256).
GENESIS_TRACE_COUNT = 1024
GENESIS_SEED_BANNER = (
    "SLAD://FAZA-ZERO — pierwszy zasiew sieci. "
    "Traktuj każdy ślad jako zaproszenie do świadczenia usługi."
)

# Parametry matematyki kosztu (jednostki umowne, nie fiat).
COST_BASE = 1.0  # koszt bazowy pierwszego śladu
COST_DEPTH_LINEAR = 0.05  # liniowy wzrost kosztu z głębokością (za poziom)
COST_BRANCH_EXP_BASE = 2.0  # podstawa kary wykładniczej za wielogałęziowość

DEFAULT_COOLDOWN = 600  # sekundy między śladami jednego klucza
DEFAULT_THRESHOLD = 2.0  # akceptowany koszt (bezpiecznik przy >1 gałęzi)
DEFAULT_STATE_FILE = os.path.join(os.path.expanduser("~"), ".slad", "stan.json")
DEFAULT_WALLET_FILE = os.path.join(os.path.expanduser("~"), ".slad", "portfel.json")
# Anchor zasiewu (tryb --jednorazowy) trafia tutaj — zawiera tylko dane publiczne.
DEFAULT_ANCHOR_FILE = os.path.join(
    os.path.expanduser("~"), ".slad", "genesis-anchor.json"
)

# Tolerance for clock skew between node and ledger (seconds).
CLOCK_SKEW_TOLERANCE = 60


# ---------------------------------------------------------------------------
# WYJĄTKI
# ---------------------------------------------------------------------------


class SladError(Exception):
    """Błąd protokołu / walidacji danych."""


class IpfsError(SladError):
    """Błąd komunikacji z lokalnym węzłem IPFS."""


# ---------------------------------------------------------------------------
# KRYPTGRAFIA — Ed25519 (zgodność z portfelami sprzętowymi)
# ---------------------------------------------------------------------------

# Stałe derywacji klucza. Zmiana ich łamie zgodność wszystkich portfeli,
# dlatego traktujemy je jak część specyfikacji, a nie parametr.
WALLET_KDF_ITERATIONS = 200_000
WALLET_KDF_SALT = b"slad-wallet-v1"


def klucz_z_ziarna(ziarno: bytes) -> SigningKey:
    """Buduje klucz Ed25519 z 32-bajtowego ziarna."""
    if len(ziarno) != 32:
        raise SladError("Ziarno Ed25519 musi mieć dokładnie 32 bajty.")
    return SigningKey(ziarno)


def klucz_publiczny_hex(signing_key: SigningKey) -> str:
    """Zwraca klucz publiczny w hex (małe litery) — unikalna tożsamość autora."""
    return bytes(signing_key.verify_key).hex()


def klucz_publiczny_z_hex(pubkey_hex: str) -> VerifyKey:
    """Odtwarza klucz weryfikujący z hex; waliduje długość i format."""
    try:
        raw = bytes.fromhex(pubkey_hex)
    except (ValueError, TypeError) as exc:
        raise SladError(f"Nieprawidłowy klucz publiczny (hex): {exc}") from exc
    if len(raw) != 32:
        raise SladError("Klucz publiczny Ed25519 ma 32 bajty.")
    return VerifyKey(raw)


def adres_klucza(pubkey_hex: str) -> str:
    """
    Krótki adres klucza = SHA-256(pubkey)[:8] w hex.
    Służy do indeksowania bez ujawniania pełnego klucza w podglądach.
    """
    return hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()[:16]


# ---------------------------------------------------------------------------
# KANONICZNE KODOWANIE I CID (po stronie Kubo)
# ---------------------------------------------------------------------------


def _kanoniczny_json(obiekt: Dict[str, Any]) -> bytes:
    """
    Kanoniczna serializacja podpisywanego obiektu.

    Wariant DAG-JSON: posortowane klucze, bez spacji, UTF-8, bez ASCII-escape.
    Dzięki temu CID = sha256(bajty) jest identyczny w każdym węźle IPFS,
    niezależnie od tego, czy podpisał go Python, JS czy Ledger.
    """
    return json.dumps(
        obiekt,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sygnowany_rekord(tresc: Dict[str, Any]) -> bytes:
    """
    Bajty przeznaczone do podpisania: wszystkie pola śladu poza `signature`.
    """
    do_podpisu = {k: v for k, v in tresc.items() if k != "signature"}
    return _kanoniczny_json(do_podpisu)


def hash_tresci(payload: Dict[str, Any]) -> str:
    """
    sha256 z pełnego obiektu (z podpisem) — deterministyczny odcisk śladu,
    niezależny od implementacji CID-u.
    """
    return hashlib.sha256(_kanoniczny_json(payload)).hexdigest()


class IpfsKlient:
    """
    Minimalny klient lokalnego węzła IPFS Kubo (REST API).

    Wymaga działającego `ipfs daemon` z włączonym API (domyślnie :5001).
    Domyślnie klient **nie ogłasza** niczego w sieci: bloki trafiają do
    lokalnego repozytorium i są przypięte. Ogłoszenie to osobna, świadoma
    operacja (`oglos_w_sieci`).
    """

    def __init__(self, api_url: str = DEFAULT_API_URL, timeout: float = 30.0):
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout

    def _post(
        self,
        endpoint: str,
        params: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Any]] = None,
    ):
        url = f"{self.api_url}/api/v0/{endpoint}"
        try:
            return requests.post(url, params=params, files=files, timeout=self.timeout)
        except requests.RequestException as exc:
            raise IpfsError(
                f"Nie można połączyć się z węzłem IPFS ({self.api_url}): {exc}. "
                "Uruchom `ipfs daemon`."
            ) from exc

    def dodaj_bytes(self, dane: bytes) -> str:
        """
        Publikuje nieprzetworzone bajty (raw block → CIDv1 bafkrei...) i zwraca CID.
        """
        params = {
            "cid-version": "1",
            "raw-leaves": "true",
            "pin": "true",
            "wrap-with-directory": "false",
            "chunker": "size-1048576",
        }
        resp = self._post(
            "add",
            params=params,
            files={"file": ("slad.json", dane, "application/json")},
        )
        if resp.status_code != 200:
            raise IpfsError(
                f"IPFS add nie powiodło się: HTTP {resp.status_code} {resp.text[:300]}"
            )
        cid = None
        for linia in resp.text.splitlines():
            linia = linia.strip()
            if not linia:
                continue
            try:
                rekord = json.loads(linia)
            except json.JSONDecodeError as exc:
                raise IpfsError(f"Nieoczekiwana odpowiedź IPFS: {linia[:200]}") from exc
            if "Hash" not in rekord:
                continue
            if rekord.get("Name") in ("slad.json", ""):
                cid = rekord["Hash"]
        if not cid:
            raise IpfsError("Węzeł IPFS nie zwrócił CID-u.")
        return cid

    def pobierz_bytes(self, cid: str) -> bytes:
        """Pobiera surowe bajty bloku po CID (przez `/api/v0/cat`)."""
        resp = self._post("cat", params={"arg": cid})
        if resp.status_code != 200:
            raise IpfsError(f"Nie można pobrać CID {cid}: HTTP {resp.status_code}")
        return resp.content

    def ma_blok(self, cid: str) -> bool:
        """Sprawdza obecność bloku w lokalnym repozytorium."""
        resp = self._post("block/stat", params={"arg": cid})
        return resp.status_code == 200

    def przypnij(self, cid: str, recursive: bool = True) -> None:
        """Trwale przypina blok (ochrona przed `ipfs repo gc`)."""
        resp = self._post(
            "pin/add",
            params={"arg": cid, "recursive": "true" if recursive else "false"},
        )
        if resp.status_code != 200:
            raise IpfsError(
                f"Nie można przypiąć {cid}: HTTP {resp.status_code} {resp.text[:200]}"
            )

    def jest_przypiety(self, cid: str) -> bool:
        """Czy blok jest przypięty (lokalnie lub rekurencyjnie)."""
        resp = self._post("pin/ls", params={"arg": cid, "type": "all"})
        return resp.status_code == 200

    def oglos_w_sieci(self, cid: str) -> str:
        """
        Ogłasza CID w sieci DHT — dopiero ten krok czyni zasiew osiągalnym
        dla innych węzłów.

        Preferuje nowsze `/api/v0/provide/once` (Kubo >= 0.30, eksperymentalne),
        a przy starszym węźle spada na `/api/v0/routing/provide` (przestarzałe,
        ale stabilne). Zwraca nazwę użytego endpointu.

        Uwaga: na węźle z włączonym DHT Kubo może rozgłaszać dostarczane
        bloki samodzielnie. Pełną izolację daje `ipfs daemon --offline`.
        """
        for endpoint, params in (
            ("provide/once", {"arg": cid}),
            ("routing/provide", {"arg": cid}),
        ):
            resp = self._post(endpoint, params=params)
            if resp.status_code == 200:
                return endpoint
            if resp.status_code != 404:
                raise IpfsError(
                    f"Nie można ogłosić {cid} w DHT ({endpoint}): "
                    f"HTTP {resp.status_code} {resp.text[:200]}. "
                    "Sprawdź, czy demon nie działa z --offline."
                )
        raise IpfsError(
            f"Węzeł nie obsługuje żadnego endpointu ogłaszania ({cid}). "
            "Zaktualizuj Kubo albo ogłoś ręcznie: `ipfs provide once <CID>`."
        )

    def id(self) -> Dict[str, Any]:
        """Informacje o węźle — używane jako test dostępności."""
        resp = self._post("id")
        if resp.status_code != 200:
            raise IpfsError(f"IPFS id: HTTP {resp.status_code}")
        return resp.json()


# ---------------------------------------------------------------------------
# WALIDACJA STRUKTURY ŚLADU
# ---------------------------------------------------------------------------

WYMAGANE_POLA = (
    "version",
    "parent_cid",
    "depth",
    "timestamp",
    "author_pubkey",
    "payload",
    "signature",
)


def waliduj_strukture(slad: Dict[str, Any]) -> None:
    """Sprawdza typy i obecność wszystkich pól specyfikacji v1.0."""
    if not isinstance(slad, dict):
        raise SladError("Ślad musi być obiektem JSON.")
    brakujace = [p for p in WYMAGANE_POLA if p not in slad]
    if brakujace:
        raise SladError(f"Brakujące pola śladu: {', '.join(brakujace)}")
    if slad["version"] != PROTOCOL_VERSION:
        raise SladError(f"Nieobsługiwana wersja: {slad['version']!r}")
    if slad["parent_cid"] is not None and not isinstance(slad["parent_cid"], str):
        raise SladError("parent_cid musi być stringiem lub null.")
    if not isinstance(slad["depth"], int) or slad["depth"] < 0:
        raise SladError("depth musi być nieujemną liczbą całkowitą.")
    if not isinstance(slad["timestamp"], (int, float)):
        raise SladError("timestamp musi być liczbą (Unix).")
    if not isinstance(slad["payload"], dict):
        raise SladError("payload musi być obiektem (opis usługi/zasobu).")
    if not isinstance(slad["author_pubkey"], str):
        raise SladError("author_pubkey musi być hexem.")
    if not isinstance(slad["signature"], str):
        raise SladError("signature musi być hexem.")
    # Długość payloadu ograniczona — ślady mają być lekkie.
    if len(_kanoniczny_json(slad["payload"])) > 64 * 1024:
        raise SladError("payload przekracza 64 KiB.")


def podpisz_slad(
    signing_key: SigningKey,
    parent_cid: Optional[str],
    depth: int,
    payload: Dict[str, Any],
    timestamp: Optional[int] = None,
) -> Dict[str, Any]:
    """Tworzy kompletny, podpisany obiekt śladu (gotowy do publikacji)."""
    if depth < 0:
        raise SladError("depth nie może być ujemne.")
    if depth == 0 and parent_cid is not None:
        raise SladError("Korzeń (depth=0) nie może mieć rodzica.")
    if depth > 0 and parent_cid is None:
        raise SladError("Ślad potomny musi wskazywać parent_cid.")

    slad: Dict[str, Any] = {
        "version": PROTOCOL_VERSION,
        "parent_cid": parent_cid,
        "depth": depth,
        "timestamp": int(timestamp if timestamp is not None else time.time()),
        "author_pubkey": klucz_publiczny_hex(signing_key),
        "payload": payload,
    }
    slad["signature"] = signing_key.sign(sygnowany_rekord(slad)).signature.hex()
    return slad


def weryfikuj_podpis(slad: Dict[str, Any]) -> VerifyKey:
    """
    Weryfikuje podpis Ed25519 całego obiektu.
    Zwraca klucz weryfikujący (przydatny do porównań autora).
    """
    waliduj_strukture(slad)
    vk = klucz_publiczny_z_hex(slad["author_pubkey"])
    try:
        vk.verify(sygnowany_rekord(slad), bytes.fromhex(slad["signature"]))
    except (BadSignatureError, ValueError) as exc:
        raise SladError(f"Nieprawidłowy podpis śladu: {exc}") from exc
    return vk


# ---------------------------------------------------------------------------
# MATEMATYCZNA KRZYWA KOSZTU
# ---------------------------------------------------------------------------


def oblicz_koszt_nastepnego_sladu(
    gliebokosc: int, aktywne_galezie_klucza: int
) -> float:
    """
    Koszt (w jednostkach umownych) kolejnego śladu dla danego klucza.

        koszt = (BASE + LINEAR * głębokość) * BRANCH_BASE ** (aktywne_gałęzie - 1)

    * Koszt liniowy z głębokością nagradza „wierność” jednej gałęzi:
      długi, spójny łańcuch jest tańszy niż równoległe rozgałęzianie.
    * Kara wykładnicza sprawia, że farmienie N gałęzi jednym kluczem
      kosztuje 2^(N-1) — to opłaca się ekonomicznie tylko dla realnej
      użyteczności, nie dla botów.
    Wynik jest zawsze >= COST_BASE.
    """
    if gliebokosc < 0:
        raise ValueError("głębokość nie może być ujemna")
    if aktywne_galezie_klucza < 1:
        raise ValueError("aktywne gałęzie klucza >= 1")
    koszt = (COST_BASE + COST_DEPTH_LINEAR * gliebokosc) * (
        COST_BRANCH_EXP_BASE ** (aktywne_galezie_klucza - 1)
    )
    return round(koszt, 6)


def koszt_w_jezyku_ludzi(koszt: float) -> str:
    """Opis kosztu na poziomie zero — bez krypticznego żargonu."""
    if koszt <= COST_BASE:
        return "koszt bazowy"
    if koszt < COST_BASE * 8:
        return "umiarkowany — warto przemyśleć cel śladu"
    return "wysoki — rozważ zamknięcie zbędnych gałęzi"


# ---------------------------------------------------------------------------
# WERYFIKACJA CZASU PRZETRZYMANIA (COOLDOWN)
# ---------------------------------------------------------------------------


def sprawdz_cooldown(
    ostatni_timestamp: Optional[float],
    cooldown_s: float = DEFAULT_COOLDOWN,
    teraz: Optional[float] = None,
) -> Tuple[bool, float]:
    """
    Sprawdza, czy od ostatniego wpisu klucza minęło wymagane opóźnienie.

    `teraz` musi pochodzić z lokalnego zegara, ale walidacja łańcucha wymusza
    monotoniczność timestampów, więc cofanie zegara na węźle nie pomaga
    w generowaniu większej liczby śladów niż na to pozwala szybkość sieci.

    Zwraca (czy_mozna, pozostalo_sekund).
    """
    if ostatni_timestamp is None:
        return True, 0.0
    teraz = time.time() if teraz is None else teraz
    pozostalo = (float(ostatni_timestamp) + cooldown_s) - teraz
    return pozostalo <= 0, max(0.0, pozostalo)


# ---------------------------------------------------------------------------
# STAN LOKALNY (KSIĘGA GAŁĘZI I OSTATNICH WPISÓW)
# ---------------------------------------------------------------------------


@dataclass
class StanLokalny:
    """
    Lokalny notatnik klucza: ostatni timestamp per autor, aktywne gałęzie
    per autor oraz mapowanie CID -> ślad (żeby nie pytać IPFS za każdym razem).
    Ślad w IPFS pozostaje źródłem prawdy — ten plik tylko przyspiesza pracę.

    „Aktywna gałąź” = ślad, który nie ma jeszcze następnika (końcówka
    równoległej ścieżki). Dopisanie śladu do końcówki ją „przedłuża”
    (liczba gałęzi bez zmian), a dopisanie do starszego śladu otwiera
    nową równoległą gałąź (kara wykładnicza).
    """

    sciezka: str
    ostatni_timestamp: Dict[str, int] = field(default_factory=dict)
    aktywne_galezie: Dict[str, List[str]] = field(default_factory=dict)
    bezpiecznik_wylaczony: Dict[str, bool] = field(default_factory=dict)
    znane_slady: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    korzen_cid: Optional[str] = None
    ostatni_cid_klucza: Dict[str, str] = field(default_factory=dict)

    # ----- I/O -----

    @classmethod
    def wczytaj_klub_nowy(cls, sciezka: str) -> "StanLokalny":
        if os.path.exists(sciezka):
            try:
                with open(sciezka, "r", encoding="utf-8") as f:
                    dane = json.load(f)
                return cls(
                    sciezka=sciezka,
                    ostatni_timestamp=dane.get("ostatni_timestamp", {}),
                    aktywne_galezie=dane.get("aktywne_galezie", {}),
                    bezpiecznik_wylaczony=dane.get("bezpiecznik_wylaczony", {}),
                    znane_slady=dane.get("znane_slady", {}),
                    korzen_cid=dane.get("korzen_cid"),
                    ostatni_cid_klucza=dane.get("ostatni_cid_klucza", {}),
                )
            except (OSError, json.JSONDecodeError):
                pass  # uszkodzony plik nie blokuje pracy — start od zera
        return cls(sciezka=sciezka)

    def zapisz(self) -> None:
        os.makedirs(os.path.dirname(self.sciezka) or ".", exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.sciezka) or ".")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "ostatni_timestamp": self.ostatni_timestamp,
                        "aktywne_galezie": self.aktywne_galezie,
                        "bezpiecznik_wylaczony": self.bezpiecznik_wylaczony,
                        "znane_slady": self.znane_slady,
                        "korzen_cid": self.korzen_cid,
                        "ostatni_cid_klucza": self.ostatni_cid_klucza,
                    },
                    f,
                    indent=1,
                    ensure_ascii=False,
                )
            os.replace(tmp, self.sciezka)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    # ----- logika gałęzi -----

    def zapamietaj(self, cid: str, slad: Dict[str, Any]) -> None:
        """
        Rejestruje nowy ślad: aktualizuje zegar, końcówki gałęzi i wskaźnik.

        Jeśli autor dopisał ślad do wybranej końcówki, ta końcówka przestaje
        być aktywna, a nowy ślad nią zostaje — liczba gałęzi nie rośnie.
        """
        self.znane_slady[cid] = slad
        autor = slad["author_pubkey"]
        self.ostatni_timestamp[autor] = max(
            int(slad["timestamp"]), self.ostatni_timestamp.get(autor, 0)
        )
        # Gałęzie liczymy przed dopisaniem nowego śladu: nowa końcówka jeszcze
        # nie istnieje, więc nie wolno jej doliczać przed naliczeniem kosztu.
        autor = slad["author_pubkey"]
        nowa_koncowka = cid
        dotychczasowe = [
            g
            for g in self.aktywne_galezie.get(autor, [])
            if g != cid and g != slad.get("parent_cid")
        ]
        self.aktywne_galezie[autor] = dotychczasowe + [nowa_koncowka]
        self.ostatni_cid_klucza[autor] = cid

    def liczba_aktywnych_galezi(self, autor: str) -> int:
        return max(1, len(self.aktywne_galezie.get(autor, [])))


# ---------------------------------------------------------------------------
# POMOCNICZE: ZAPIS PORTFELA (PAPIEROWEGO)
# ---------------------------------------------------------------------------


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("ascii"))


def portfel_do_json(ziarno: bytes, signing_key: SigningKey) -> Dict[str, Any]:
    """Portfel papierowy = ziarno + klucz publiczny + adres (bez hasła)."""
    pub = klucz_publiczny_hex(signing_key)
    return {
        "scheme": "ed25519",
        "version": 1,
        "seed_b64": _b64(ziarno),
        "pubkey": pub,
        "address": adres_klucza(pub),
        "created": int(time.time()),
        "uwaga": "Ziarno = pełna kontrola nad kluczem. Trzymaj offline na papierze.",
    }


def portfel_na_papier(portfel: Dict[str, Any]) -> str:
    """Czytelny wydruk portfela papierowego do przepisania ręcznie."""
    ziarno = portfel["seed_b64"]
    linie = [
        "+" + "-" * 68 + "+",
        "|                 SLAD — PORTFEL PAPIEROWY (Ed25519)                  |",
        "+" + "-" * 68 + "+",
        f"| Adres       : {portfel['address']:<54}|",
        f"| Klucz publ. : {portfel['pubkey']}",
        "| Ziarno (64 znaki, bez spacji):",
    ]
    for i in range(0, len(ziarno), 43):
        linie.append(f"|   {ziarno[i : i + 43]}")
    linie += [
        "| Hasło (ustaw samodzielnie, NIE jest przechowywane):",
        "|   ____________________________________________________________",
        "|",
        "| Odtworzenie: --import-portfel <plik> --haslo <hasło>",
        "+" + "-" * 68 + "+",
    ]
    return "\n".join(linie)


def _szyfruj_ziarno(ziarno: bytes, haslo: str) -> Dict[str, str]:
    """AES-GCM z kluczem z PBKDF2-SHA256 — ochrona pliku portfela."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    sol = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=sol, iterations=WALLET_KDF_ITERATIONS
    )
    klucz = kdf.derive(haslo.encode("utf-8"))
    nonce = secrets.token_bytes(12)
    szyfrogram = AESGCM(klucz).encrypt(nonce, ziarno, WALLET_KDF_SALT)
    return {
        "kdf": "pbkdf2-sha256",
        "iterations": WALLET_KDF_ITERATIONS,
        "salt": _b64(sol),
        "nonce": _b64(nonce),
        "ciphertext": _b64(szyfrogram),
    }


def _deszyfruj_ziarno(zaszyfrowane: Dict[str, Any], haslo: str) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_unb64(zaszyfrowane["salt"]),
        iterations=int(zaszyfrowane["iterations"]),
    )
    try:
        klucz = kdf.derive(haslo.encode("utf-8"))
        return AESGCM(klucz).decrypt(
            _unb64(zaszyfrowane["nonce"]),
            _unb64(zaszyfrowane["ciphertext"]),
            WALLET_KDF_SALT,
        )
    except Exception as exc:  # noqa: BLE001 — każdy błąd = złe hasło/dane
        raise SladError("Nie można odszyfrować portfela (złe hasło?)") from exc


def zapisz_portfel(portfel: Dict[str, Any], sciezka: str, haslo: Optional[str]) -> None:
    dane: Dict[str, Any] = dict(portfel)
    if haslo:
        dane["seed_b64"] = None
        dane["encrypted_seed"] = _szyfruj_ziarno(_unb64(portfel["seed_b64"]), haslo)
        del dane["uwaga"]
    os.makedirs(os.path.dirname(sciezka) or ".", exist_ok=True)
    fd = os.open(sciezka, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(dane, f, indent=2, ensure_ascii=False)
    os.chmod(sciezka, 0o600)


def wczytaj_portfel(sciezka: str, haslo: Optional[str]) -> SigningKey:
    """Otwiera portfel (zaszyfrowany lub czysty) i zwraca klucz podpisujący."""
    if not os.path.exists(sciezka):
        raise SladError(f"Brak pliku portfela: {sciezka}")
    with open(sciezka, "r", encoding="utf-8") as f:
        dane = json.load(f)
    if dane.get("scheme") != "ed25519":
        raise SladError("Nieobsługiwany schemat portfela.")
    if dane.get("seed_b64"):
        ziarno = _unb64(dane["seed_b64"])
    elif dane.get("encrypted_seed"):
        if not haslo:
            raise SladError("Portfel jest zaszyfrowany — podaj --haslo / $SLAD_HASLO.")
        ziarno = _deszyfruj_ziarno(dane["encrypted_seed"], haslo)
    else:
        raise SladError("Portfel nie zawiera ziarna.")
    key = klucz_z_ziarna(ziarno)
    if klucz_publiczny_hex(key) != dane.get("pubkey"):
        raise SladError(
            "Ziarno nie odpowiada kluczowi publicznemu (uszkodzony portfel)."
        )
    return key


# ---------------------------------------------------------------------------
# DZIENNIK GAŁĘZI (proof-of-work-lite): liczba aktywnych gałęzi z łańcucha
# ---------------------------------------------------------------------------


def policz_aktywne_galezie(klucz: str, slady: Iterable[Dict[str, Any]]) -> int:
    """
    Wariant „z sieci”: liczba różnych rodziców, do których autor podłączył
    swoje ślady. Jeden autor spisujący historię jednej gałęzi ma 1.
    """
    rodzice = {s.get("parent_cid") for s in slady if s.get("author_pubkey") == klucz}
    return max(1, len(rodzice))


# ---------------------------------------------------------------------------
# GENESIS: 1024 ŚLADY FAZY ZERO
# ---------------------------------------------------------------------------


def _dodaj_zasiew(
    ipfs: IpfsKlient,
    stan: StanLokalny,
    signing_key: SigningKey,
    parent_cid: str,
    poziom: int,
    indeks: int,
) -> str:
    """Podpisuje jeden ślad zasiewu pod danym rodzicem i publikuje go."""
    rodzic = stan.znane_slady[parent_cid]
    slad = podpisz_slad(
        signing_key,
        parent_cid=parent_cid,
        depth=glebokosc_dziecka(rodzic),
        payload={
            "typ": "zasiew",
            "poziom": poziom,
            "indeks": indeks,
            "opis": GENESIS_SEED_BANNER,
        },
        timestamp=int(time.time()),
    )
    cid = ipfs.dodaj_bytes(_kanoniczny_json(slad))
    stan.zapamietaj(cid, slad)
    return cid


def generuj_zasiew_genezy(
    ipfs: IpfsKlient,
    stan: StanLokalny,
    signing_key: SigningKey,
    cooldown_s: float = 0,
    progress: bool = True,
) -> str:
    """
    Tworzy i publikuje w lokalnym IPFS dokładnie 1024 ślady rozchodzące się
    z jednego pnia (stożek binarny: 1 + 2 + 4 + ... + 512 + domknięcie).

    Zasiew celowo omija cooldown i karę za wielogałęziowość — to inicjalizacja
    sieci (Faza Zero), a nie aktywność użytkownika. Każdy kolejny ślad
    publikowany przez zwykłe `publish` podlega już obu ograniczeniom.

    Zwraca CID korzenia.
    """
    if progress:
        print(
            f"[genesis] start — {GENESIS_TRACE_COUNT} śladów, autor "
            f"{adres_klucza(klucz_publiczny_hex(signing_key))}"
        )

    # Korzeń Fazy Zero. Jego parents są puste, więc każde drzewo zaczyna się
    # od jednego punktu — dokładnie tak, jak zakłada specyfikacja.
    korzen = podpisz_slad(
        signing_key,
        parent_cid=None,
        depth=0,
        payload={
            "typ": "genesis",
            "opis": GENESIS_SEED_BANNER,
            "zasiew": GENESIS_TRACE_COUNT,
            "korzen": True,
        },
        timestamp=int(time.time()),
    )
    korzen_raw = _kanoniczny_json(korzen)
    korzen_cid = ipfs.dodaj_bytes(korzen_raw)
    stan.zapamietaj(korzen_cid, korzen)
    stan.korzen_cid = korzen_cid
    if progress:
        print(f"[genesis] 001/{GENESIS_TRACE_COUNT} korzeń {korzen_cid}")

    # Drzewo Faza Zero:
    #   poziomy 1..9 — każdy węzeł ma dwoje dzieci: 1+2+...+512 = 1023 ślady,
    #   ślad nr 1024 — domyka stożek pod pierwszym liściem poziomu 9.
    # Każdy węzeł poza ostatnim ma dokładnie dwoje dzieci, więc struktura
    # zasiewu jest deterministyczna i weryfikowalna.
    poziom: List[str] = [korzen_cid]
    opublikowane = 1
    poziom_nr = 1
    while opublikowane < GENESIS_TRACE_COUNT - 1:
        nastepny: List[str] = []
        for parent_cid in poziom:
            for indeks in (0, 1):
                cid = _dodaj_zasiew(
                    ipfs, stan, signing_key, parent_cid, poziom_nr, indeks
                )
                nastepny.append(cid)
                opublikowane += 1
                if progress and opublikowane % 32 == 0:
                    print(
                        f"[genesis] {opublikowane:04d}/{GENESIS_TRACE_COUNT} "
                        f"poziom {poziom_nr}"
                    )
                if cooldown_s > 0:
                    time.sleep(cooldown_s)
        poziom = nastepny
        poziom_nr += 1

    # Domknięcie stożka: ostatni ślad dopina się pod pierwszy liść.
    cid = _dodaj_zasiew(ipfs, stan, signing_key, poziom[0], poziom_nr, 0)
    poziom = poziom[1:] + [cid]
    opublikowane += 1
    if progress:
        print(f"[genesis] {opublikowane:04d}/{GENESIS_TRACE_COUNT} domknięcie")

    # Zasiew kończy się 512 liśćmi — to jedyne aktywne końcówki autora:
    # kolejny ślad przedłuży jedną z nich (bez kary), zamiast otwierać setki
    # nowych gałęzi naraz.
    stan.aktywne_galezie[klucz_publiczny_hex(signing_key)] = list(poziom)
    stan.zapisz()
    if progress:
        print(f"[genesis] gotowe — korzeń: {korzen_cid}, liści: {len(poziom)}")
    return korzen_cid


# Głębokość śladu potomnego względem rodzica. Wydzielone, aby zasiew i
# zwykła publikacja liczyły głębokość jednym wzorem (bez rozjazdów).
def glebokosc_dziecka(rodzic: Dict[str, Any]) -> int:
    return int(rodzic["depth"]) + 1


# ---------------------------------------------------------------------------
# TRYB JEDNORAZOWY: ANONIMOWY ZASIEW BEZ ZACHOWANIA KLUCZA
# ---------------------------------------------------------------------------


def zniszcz_klucz(signing_key: SigningKey, ziarno: Optional[bytes] = None) -> None:
    """
    Kasuje materiał klucza z pamięci best-effort.

    Uczciwie: w Pythonie nie da się zagwarantować wymazania pamięci (GC,
    kopie w `bytes`, swap). Robimy to, co możliwe: zerujemy bufor `bytearray`
    i usuwamy referencję. Klucz i tak był tylko w pamięci procesu — nigdy
    nie trafił na dysk, jeśli nie zapisano portfela.
    """
    if ziarno is not None:
        try:
            bufor = bytearray(ziarno)
            for i in range(len(bufor)):
                bufor[i] = 0
        except (TypeError, ValueError):
            pass
    del signing_key


def zapisz_anchor(
    sciezka: str,
    korzen_cid: str,
    autor_pubkey: str,
    odcisk_korzenia: str,
    timestamp_korzenia: int,
    stat: "StatystykiDrzewa",
    bledy: List[str],
) -> Dict[str, Any]:
    """
    Zapisuje publiczny „Genesis Anchor” — wszystko, co potrzebne, by inni
    mogli zweryfikować zasiew. Bez klucza prywatnego i bez ziarna.
    """
    anchor = {
        "protokol": "SLAD",
        "wersja": PROTOCOL_VERSION,
        "typ": "genesis-anchor",
        "genesis_cid": korzen_cid,
        "zasiew": GENESIS_TRACE_COUNT,
        "autor_pubkey": autor_pubkey,
        "adres": adres_klucza(autor_pubkey),
        "korzen_odcisk": odcisk_korzenia,
        "korzen_timestamp": timestamp_korzenia,
        "weryfikacja": {
            "sladow": stat.liczba_sladow,
            "lisci": stat.liczba_lisci,
            "max_glebokosc": stat.max_glebokosc,
            "bledy": len(bledy),
        },
        "uwaga": "Zasiew jednorazowy. Klucz prywatny nie został zachowany; "
        "nowe ślady pod ten pień nie są możliwe — buduj własne gałęzie.",
    }
    os.makedirs(os.path.dirname(sciezka) or ".", exist_ok=True)
    with open(sciezka, "w", encoding="utf-8") as f:
        json.dump(anchor, f, indent=2, ensure_ascii=False)
    return anchor


def anchor_na_papier(anchor: Dict[str, Any]) -> str:
    """Krótki wydruk-anchor do skopiowania do ogłoszenia / na papier."""
    return "\n".join(
        [
            "+" + "-" * 68 + "+",
            "|                    SLAD — GENESIS ANCHOR (publiczny)                  |",
            "+" + "-" * 68 + "+",
            f"| Genesis CID : {anchor['genesis_cid']}",
            f"| Klucz publ. : {anchor['autor_pubkey']}",
            f"| Adres       : {anchor['adres']}",
            f"| Odcisk      : {anchor['korzen_odcisk']}",
            f"| Zasiew      : {anchor['zasiew']} śladów (Faza Zero)",
            "+" + "-" * 68 + "+",
        ]
    )


# ---------------------------------------------------------------------------
# WERYFIKACJA ŁAŃCUCHA / DRZEWA
# ---------------------------------------------------------------------------


@dataclass
class StatystykiDrzewa:
    liczba_sladow: int = 0
    liczba_autorow: int = 0
    max_glebokosc: int = 0
    srednia_glebokosc: float = 0.0
    liczba_lisci: int = 0
    timestamp_min: Optional[int] = None
    timestamp_max: Optional[int] = None
    autorzy: Dict[str, int] = field(default_factory=dict)  # autor -> liczba śladów
    galezie_autorow: Dict[str, int] = field(default_factory=dict)


def _deserializuj_slad(bajty: bytes) -> Dict[str, Any]:
    """Parsuje bajty bloku IPFS do słownika śladu."""
    try:
        slad = json.loads(bajty.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SladError(f"Blok nie jest poprawnym JSON-em: {exc}") from exc
    return slad


def pobierz_slad(
    ipfs: IpfsKlient, cid: str, stan: Optional[StanLokalny] = None
) -> Dict[str, Any]:
    """Pobiera ślad z cache lokalnego albo z węzła IPFS."""
    if stan is not None and cid in stan.znane_slady:
        return stan.znane_slady[cid]
    slad = _deserializuj_slad(ipfs.pobierz_bytes(cid))
    if stan is not None:
        stan.znane_slady[cid] = slad
    return slad


def weryfikuj_lancuch(
    ipfs: IpfsKlient,
    korzen_cid: str,
    cooldown_s: float,
    stan: Optional[StanLokalny] = None,
    limit: Optional[int] = None,
) -> Tuple[StatystykiDrzewa, List[str]]:
    """
    Przechodzi całe drzewo od korzenia (BFS), weryfikując każdy ślad:

    * struktura i podpis Ed25519 (`weryfikuj_podpis`),
    * `depth` = głębokość rodzica + 1 (korzeń ma 0),
    * monotoniczność czasu w obrębie klucza autora (cooldown),
    * kara wykładnicza za równoległe gałęzie tego samego klucza.

    Ślady zasiewu Fazy Zero są zwolnione z cooldownu — powstały jako jedna
    operacja inicjalizacyjna (patrz `generuj_zasiew_genezy`).

    Zwraca (statystyki, lista błędów). Pusta lista = łańcuch poprawny.
    """
    stat = StatystykiDrzewa()
    bledy: List[str] = []
    widziane: set = set()
    kolejka: List[Tuple[str, Optional[str], int]] = [(korzen_cid, None, 0)]
    dzieci: Dict[str, int] = {}
    suma_glebokosci = 0
    ostatni_czas_autora: Dict[str, int] = {}
    rodzice_autora: Dict[str, set] = {}

    # Jeden indeks na całe przejście: relacje rodzic->dzieci w O(n), zamiast
    # liniowego skanowania słownika przy każdym węźle (to było O(n²)).
    indeks = IndeksDrzewa(stan.znane_slady) if stan is not None else None

    while kolejka:
        cid, oczekiwany_rodzic, oczekiwana_glebokosc = kolejka.pop(0)
        if cid in widziane:
            continue
        widziane.add(cid)
        if limit is not None and stat.liczba_sladow >= limit:
            bledy.append(f"Przerwano na limicie {limit} śladów.")
            break

        try:
            slad = pobierz_slad(ipfs, cid, stan)
            weryfikuj_podpis(slad)
        except SladError as exc:
            bledy.append(f"{cid}: {exc}")
            continue

        # Spójność struktury względem rodzica.
        if slad["parent_cid"] != oczekiwany_rodzic:
            bledy.append(
                f"{cid}: oczekiwano rodzica {oczekiwany_rodzic}, "
                f"jest {slad['parent_cid']}"
            )
            continue
        if slad["depth"] != oczekiwana_glebokosc:
            bledy.append(
                f"{cid}: zła głębokość {slad['depth']} "
                f"(oczekiwano {oczekiwana_glebokosc})"
            )
            continue

        # Cooldown — zegar liczony per klucz autora, w kolejności drzewa.
        # Zasiew Fazy Zero jest tworzony „w jednym oddechu” (inicjalizacja
        # sieci), więc jego ślady (`typ: genesis|zasiew`) są zwolnione z limitu.
        # Każda inna aktywność autora podlega normalnemu cooldownowi.
        autor = slad["author_pubkey"]
        ts = int(slad["timestamp"])
        typ = slad["payload"].get("typ")
        w_zasiewie = typ in ("genesis", "zasiew")
        poprzedni = ostatni_czas_autora.get(autor)
        if (
            not w_zasiewie
            and poprzedni is not None
            and ts < poprzedni + cooldown_s - CLOCK_SKEW_TOLERANCE
        ):
            bledy.append(
                f"{cid}: naruszenie cooldownu autora {adres_klucza(autor)} "
                f"(odstęp {ts - poprzedni}s < {cooldown_s:.0f}s)"
            )
        ostatni_czas_autora[autor] = max(ts, poprzedni or 0)

        rodzic = slad["parent_cid"]
        if rodzic is not None:
            dzieci[rodzic] = dzieci.get(rodzic, 0) + 1
        rodzice_autora.setdefault(autor, set()).add(rodzic)

        stat.liczba_sladow += 1
        suma_glebokosci += slad["depth"]
        stat.max_glebokosc = max(stat.max_glebokosc, slad["depth"])
        stat.autorzy[autor] = stat.autorzy.get(autor, 0) + 1
        stat.timestamp_min = (
            ts if stat.timestamp_min is None else min(stat.timestamp_min, ts)
        )
        stat.timestamp_max = (
            ts if stat.timestamp_max is None else max(stat.timestamp_max, ts)
        )
        if stan is not None:
            stan.znane_slady[cid] = slad
            if indeks is not None:
                indeks.dodaj(cid, slad)

        # Dzieci z indeksu (O(1) na węzeł): CID nie indeksuje wstecz,
        # więc relacje rodzic->dziecko znamy tylko z zebranych śladów.
        if indeks is not None:
            for kandydat in indeks.dzieci(cid):
                kolejka.append((kandydat, cid, slad["depth"] + 1))
        else:
            for kandydat in _dzieci_z_cache(cid, stan):
                kolejka.append((kandydat, cid, slad["depth"] + 1))

    stat.liczba_autorow = len(stat.autorzy)
    if stat.liczba_sladow:
        stat.srednia_glebokosc = round(suma_glebokosci / stat.liczba_sladow, 3)
    stat.liczba_lisci = sum(1 for c in widziane if dzieci.get(c, 0) == 0)
    # Minus jeden: wspólny korzeń drzewa (parent_cid=None) nie jest gałęzią.
    stat.galezie_autorow = {
        a: max(1, len(r) - (1 if None in r else 0)) for a, r in rodzice_autora.items()
    }
    if stan is not None:
        stan.zapisz()
    return stat, bledy


def _dzieci_z_cache(cid: str, stan: Optional[StanLokalny]) -> List[str]:
    """
    Szuka w lokalnym cache śladów, które wskazują jako rodzica na `cid`.

    UWAGA: to wyszukiwanie liniowe O(n). Przy dużych drzewach (dziesiątki
    tysięcy śladów) używaj `IndeksDrzewa`, który buduje mapę raz O(n),
    a potem odpowiada w O(1). Funkcja zostaje dla zgodności i małych zbiorów.
    """
    if stan is None:
        return []
    return [k for k, s in stan.znane_slady.items() if s.get("parent_cid") == cid]


class IndeksDrzewa:
    """
    Jednorazowy indeks relacji rodzic -> dzieci.

    Problem: `_dzieci_z_cache` przeszukuje cały słownik śladów przy każdym
    zapytaniu. W BFS po całym drzewie daje to O(n²) — przy 128 tys. śladów
    to już sekundy, przy milionie minuty.

    Rozwiązanie: zbuduj indeks raz (O(n)), potem każde zapytanie to O(dzieci).
    Dodatkowo indeks zna wszystkie znane CID-y, więc `pobierz_slad` w trakcie
    weryfikacji nie odpytuje IPFS o to, co już ma lokalnie.
    """

    __slots__ = ("_dzieci", "_znane", "liczba")

    def __init__(self, slady: Dict[str, Dict[str, Any]]):
        self._dzieci: Dict[str, List[str]] = {}
        self._znane = slady
        for cid, slad in slady.items():
            rodzic = slad.get("parent_cid")
            if rodzic is None:
                continue
            lista = self._dzieci.get(rodzic)
            if lista is None:
                self._dzieci[rodzic] = [cid]
            else:
                lista.append(cid)
        self.liczba = len(slady)

    def dodaj(self, cid: str, slad: Dict[str, Any]) -> None:
        """Dopisuje ślad do indeksu (np. pobrany w trakcie BFS)."""
        if cid in self._znane:
            return
        self._znane[cid] = slad
        rodzic = slad.get("parent_cid")
        if rodzic is not None:
            lista = self._dzieci.get(rodzic)
            if lista is None:
                self._dzieci[rodzic] = [cid]
            else:
                lista.append(cid)
        self.liczba += 1

    def dzieci(self, cid: str) -> List[str]:
        """Bezpośrednie dzieci węzła (pusta lista, jeśli brak)."""
        return self._dzieci.get(cid, [])

    def ma(self, cid: str) -> bool:
        return cid in self._znane

    def korzenie(self) -> List[str]:
        """Wszystkie ślady bez rodzica."""
        return [c for c, s in self._znane.items() if s.get("parent_cid") is None]


def indeksuj_drzewo(
    ipfs: IpfsKlient,
    korzen_cid: str,
    stan: StanLokalny,
    limit: Optional[int] = None,
) -> None:
    """
    Buduje lokalny cache drzewa: od korzenia pobiera kolejne ślady i zapisuje
    każdy CID, żeby `weryfikuj_lancuch` mógł odtworzyć relacje rodzic-dziecko.

    Węzeł IPFS nie potrafi „wypisać dzieci” bloku (treść jest adresowana
    hashem), więc drzewo jest odtwarzane ze znanych śladów (`stan.znane_slady`).
    """
    pobrane = 0
    kolejka = [korzen_cid]
    widziane: set = set()
    indeks = IndeksDrzewa(stan.znane_slady)
    while kolejka:
        cid = kolejka.pop(0)
        if cid in widziane:
            continue
        widziane.add(cid)
        if cid not in stan.znane_slady:
            try:
                slad = _deserializuj_slad(ipfs.pobierz_bytes(cid))
            except SladError:
                continue
            indeks.dodaj(cid, slad)
        pobrane += 1
        if limit is not None and pobrane >= limit:
            break
        kolejka.extend(indeks.dzieci(cid))


# ---------------------------------------------------------------------------
# MIEJSCE UŻYTECZNOŚCI I BEZPIECZNIK KOSZTU
# ---------------------------------------------------------------------------


def znajdz_miejsce(
    ipfs: IpfsKlient,
    wezel_cid: str,
    stan: StanLokalny,
) -> Tuple[Optional[str], int, int]:
    """
    Wyznacza parametry kolejnego śladu dopisywanego pod istniejący węzeł.

    Zwraca (parent_cid, depth, aktywne_gałęzie). Ślad rodzica jest
    weryfikowany podpisem, żeby nie dało się „przyczepić” się do fałszywej
    historii; liczba gałęzi pochodzi z lokalnej księgi autora.
    """
    slad = pobierz_slad(ipfs, wezel_cid, stan)
    weryfikuj_podpis(slad)
    autor = slad["author_pubkey"]
    galezie = stan.liczba_aktywnych_galezi(autor)
    return wezel_cid, int(slad["depth"]) + 1, galezie


def buduj_payload(
    usluga: Optional[str],
    zasob: Optional[str],
    opis: Optional[str],
    typ: str = "usluga",
) -> Dict[str, Any]:
    """Payload śladu: opis usługi/zasobu/celu. Puste pola są pomijane."""
    payload = {"typ": typ, "usluga": usluga, "zasob": zasob, "opis": opis}
    return {k: v for k, v in payload.items() if v is not None}


def publikuj_domyslnie(
    ipfs: IpfsKlient,
    stan: StanLokalny,
    signing_key: SigningKey,
    payload: Dict[str, Any],
    parent_cid: Optional[str] = None,
    cooldown_s: float = DEFAULT_COOLDOWN,
    prog: float = DEFAULT_THRESHOLD,
    wymuszone: bool = False,
    teraz: Optional[float] = None,
) -> Tuple[str, Dict[str, Any], float]:
    """
    Publikacja z sensownym wyborem rodzica:

    1. `parent_cid` podany wprost — szanujemy decyzję,
    2. inaczej ostatni ślad tego klucza — przedłużamy własną gałąź (brak kary),
    3. inaczej korzeń sieci z lokalnego stanu,
    4. inaczej nowy korzeń autora.
    """
    autor = klucz_publiczny_hex(signing_key)
    if parent_cid is None:
        parent_cid = stan.ostatni_cid_klucza.get(autor) or stan.korzen_cid
    return opublikuj_slad(
        ipfs,
        stan,
        signing_key,
        parent_cid=parent_cid,
        payload=payload,
        cooldown_s=cooldown_s,
        prog=prog,
        wymuszone=wymuszone,
        teraz=teraz,
    )


def sprawdz_bezpiecznik(
    klucz: str,
    koszt: float,
    prog: float,
    stan: StanLokalny,
    wymuszone: bool,
) -> None:
    """
    „Bezpiecznik” na poziomie zera: jeśli koszt przekracza próg rozsądku,
    publikacja wymaga jednorazowego potwierdzenia (`--wtwardz`).

    To nie jest cenzura treści — protokół nigdy nie odrzuca śladu z powodu
    jego payloadu. Blokuje jedynie masowe, nieużyteczne mnożenie gałęzi.
    """
    if koszt <= prog or wymuszone:
        return
    if stan.bezpiecznik_wylaczony.get(klucz):
        return
    raise SladError(
        f"Koszt {koszt:.2f} przekracza próg {prog:.2f} "
        f"({koszt_w_jezyku_ludzi(koszt)}).\n"
        "Zamknij zbędne gałęzie (dopisuj do ostatniego śladu) lub użyj --wtwardz, "
        "jeśli cel jest realny."
    )


# ---------------------------------------------------------------------------
# PUBLIKACJA
# ---------------------------------------------------------------------------


def opublikuj_slad(
    ipfs: IpfsKlient,
    stan: StanLokalny,
    signing_key: SigningKey,
    parent_cid: Optional[str],
    payload: Dict[str, Any],
    cooldown_s: float = DEFAULT_COOLDOWN,
    prog: float = DEFAULT_THRESHOLD,
    wymuszone: bool = False,
    teraz: Optional[float] = None,
) -> Tuple[str, Dict[str, Any], float]:
    """
    Pełny przepływ publikacji jednego śladu:

    1. cooldown autora (time-lock),
    2. koszt kolejnego śladu (głębokość + aktywne gałęzie),
    3. bezpiecznik progowy,
    4. podpis Ed25519,
    5. publikacja w lokalnym IPFS (Kubo),
    6. zapis stanu.

    Zwraca (cid, slad, koszt).
    """
    autor = klucz_publiczny_hex(signing_key)
    teraz = time.time() if teraz is None else teraz

    mozna, pozostalo = sprawdz_cooldown(
        stan.ostatni_timestamp.get(autor), cooldown_s, teraz
    )
    if not mozna:
        raise SladError(
            f"Cooldown: pozostało {pozostalo:.0f}s do następnego śladu "
            f"tego klucza (wymagane {cooldown_s:.0f}s)."
        )

    if parent_cid is None:
        # Pierwszy ślad klucza — własny korzeń, głębokość 0.
        depth, galezie = 0, 1
    else:
        _, depth, galezie = znajdz_miejsce(ipfs, parent_cid, stan)
        # Gałęzie liczone po stronie publikacji: do liczby otwartych końcówek
        # doliczamy tę, którą właśnie otwieramy (nowy ślad nie jest jeszcze
        # zapisany w księdze). Przedłużenie końcówki nie zmienia liczby gałęzi.
        otwarte = stan.aktywne_galezie.get(autor, [])
        if parent_cid not in otwarte:
            galezie = max(1, len(otwarte) + 1)

    koszt = oblicz_koszt_nastepnego_sladu(depth, galezie)
    sprawdz_bezpiecznik(autor, koszt, prog, stan, wymuszone)

    slad = podpisz_slad(signing_key, parent_cid, depth, payload, timestamp=int(teraz))
    cid = ipfs.dodaj_bytes(_kanoniczny_json(slad))
    stan.zapamietaj(cid, slad)
    if parent_cid is None and stan.korzen_cid is None:
        stan.korzen_cid = cid
    stan.zapisz()
    return cid, slad, koszt


# ---------------------------------------------------------------------------
# RAPORTY
# ---------------------------------------------------------------------------


def formatuj_statystyki(
    stat: StatystykiDrzewa, korzen_cid: Optional[str] = None
) -> str:
    """Tekstowy raport drzewa — bez żargonu, zrozumiały dla użytkownika."""
    linie = [
        "=" * 64,
        "STATYSTYKI DRZEWA ŚLADÓW",
        "=" * 64,
    ]
    if korzen_cid:
        linie.append(f"Korzeń        : {korzen_cid}")
    if stat.liczba_sladow:
        linie += [
            f"Ślady         : {stat.liczba_sladow}",
            f"Autorzy       : {stat.liczba_autorow}",
            f"Max głębokość : {stat.max_glebokosc}",
            f"Śr. głębokość : {stat.srednia_glebokosc:.2f}",
            f"Liście        : {stat.liczba_lisci}",
        ]
    else:
        linie.append("Brak odczytanych śladów — sprawdź CID i stan węzła IPFS.")
    if stat.timestamp_min is not None:
        linie.append(
            f"Czas          : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.timestamp_min))}"
            f" .. {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.timestamp_max))}"
        )
    if stat.autorzy:
        linie.append("-" * 64)
        linie.append("Autorzy (adres: ślady / gałęzie):")
        for autor, liczba in sorted(stat.autorzy.items(), key=lambda x: -x[1]):
            galezie = stat.galezie_autorow.get(autor, 1)
            linie.append(f"  {adres_klucza(autor)}: {liczba} / {galezie}")
    linie.append("=" * 64)
    return "\n".join(linie)


# ---------------------------------------------------------------------------
# CLI — HANDLERY
# ---------------------------------------------------------------------------


def _haslo_z_env(inline: Optional[str]) -> Optional[str]:
    return inline or os.environ.get("SLAD_HASLO") or None


def _wczytaj_klucz_lub_blad(args: argparse.Namespace) -> SigningKey:
    return wczytaj_portfel(args.portfel, _haslo_z_env(args.haslo))


def cmd_nowy_portfel(args: argparse.Namespace) -> int:
    ziarno = secrets.token_bytes(32)
    signing_key = klucz_z_ziarna(ziarno)
    portfel = portfel_do_json(ziarno, signing_key)
    haslo = _haslo_z_env(args.haslo)

    if os.path.exists(args.portfel) and not args.nadpisz:
        raise SladError(f"Portfel już istnieje: {args.portfel} (użyj --nadpisz).")

    zapisz_portfel(portfel, args.portfel, haslo)
    print(portfel_na_papier(portfel))
    print(
        f"\nZapisano: {args.portfel}"
        f"{' (ziarno zaszyfrowane hasłem)' if haslo else ' (ziarno jawne!)'}"
    )
    if not haslo:
        print(
            "OSTRZEŻENIE: brak hasła — plik zawiera jawne ziarno. "
            "Przenieś go offline lub dodaj hasło."
        )
    return 0


def cmd_pokaz_portfel(args: argparse.Namespace) -> int:
    signing_key = _wczytaj_klucz_lub_blad(args)
    pub = klucz_publiczny_hex(signing_key)
    print(f"Klucz publiczny : {pub}")
    print(f"Adres           : {adres_klucza(pub)}")
    return 0


def cmd_import_portfel(args: argparse.Namespace) -> int:
    """Odtworzenie portfela z ziarna (np. przepisanego z papieru)."""
    try:
        ziarno = _unb64(args.ziarno.strip())
    except Exception as exc:  # noqa: BLE001
        raise SladError(f"Nieprawidłowe ziarno base64: {exc}") from exc
    signing_key = klucz_z_ziarna(ziarno)
    portfel = portfel_do_json(ziarno, signing_key)
    zapisz_portfel(portfel, args.portfel, _haslo_z_env(args.haslo))
    print(portfel_na_papier(portfel))
    print(f"\nZapisano: {args.portfel}")
    return 0


def cmd_genesis(args: argparse.Namespace) -> int:
    ipfs = IpfsKlient(args.api)
    stan = StanLokalny.wczytaj_klub_nowy(args.stan)

    if args.jednorazowy:
        return _genesis_jednorazowy(args, ipfs, stan)

    signing_key = _wczytaj_klucz_lub_blad(args)
    if stan.liczba_aktywnych_galezi(klucz_publiczny_hex(signing_key)) > 1:
        if not args.wtwardz:
            raise SladError(
                "Ten klucz ma już aktywność w sieci. Zasiew Fazy Zero tworzy "
                f"{GENESIS_TRACE_COUNT} śladów naraz — użyj --wtwardz, jeśli to "
                "zamierzona inicjalizacja."
            )

    korzen_cid = generuj_zasiew_genezy(ipfs, stan, signing_key)
    if args.json:
        print(json.dumps({"genesis": korzen_cid}, ensure_ascii=False))
    return 0


def _genesis_jednorazowy(
    args: argparse.Namespace, ipfs: IpfsKlient, stan: StanLokalny
) -> int:
    """
    Zasiew anonimowy: świeży losowy klucz w pamięci, publikacja 1024 śladów,
    natychmiastowe zniszczenie klucza. Na dysk trafia tylko stan (publiczne
    CID-y) i Genesis Anchor. Klucz nie jest nigdzie zapisywany — nawet
    przy przerwaniu (Ctrl+C) proces kończy się bez pliku portfela.
    """
    if not args.wtwardz:
        raise SladError(
            "Tryb --jednorazowy jest nieodwracalny: klucz prywatny zostanie "
            "zniszczony, a zasiewu nie da się później uzupełnić. "
            "Dodaj --wtwardz, aby potwierdzić."
        )
    if os.path.exists(args.anchor) and not args.nadpisz:
        raise SladError(f"Anchor już istnieje: {args.anchor} (użyj --nadpisz).")

    ziarno = secrets.token_bytes(32)
    signing_key = klucz_z_ziarna(ziarno)
    autor_pubkey = klucz_publiczny_hex(signing_key)
    try:
        korzen_cid = generuj_zasiew_genezy(
            ipfs, stan, signing_key, progress=not args.json
        )
        korzen = stan.znane_slady[korzen_cid]
        stat, bledy = weryfikuj_lancuch(ipfs, korzen_cid, 0, stan)
        anchor = zapisz_anchor(
            args.anchor,
            korzen_cid,
            autor_pubkey,
            hash_tresci(korzen),
            int(korzen["timestamp"]),
            stat,
            bledy,
        )
    finally:
        # Klucz ginie niezależnie od wyniku (błąd, Ctrl+C, brak sieci).
        zniszcz_klucz(signing_key, ziarno)

    if args.json:
        print(json.dumps(anchor, ensure_ascii=False))
        return 0

    print(anchor_na_papier(anchor))
    print(f"\nAnchor zapisany: {args.anchor}")
    print(
        f"Weryfikacja: {stat.liczba_sladow} śladów, "
        f"{len(bledy)} błędów, liści: {stat.liczba_lisci}"
    )
    print("\nKlucz prywatny został zniszczony — nie istnieje kopia na dysku.")
    print("Zapisz Genesis CID i klucz publiczny: to cała tożsamość zasiewu.")
    print("\nZasiew NIE został ogłoszony w sieci. Gdy będziesz gotowy:")
    print(f"  python3 slad_protokolu.py oglos --anchor {args.anchor}")
    return 0


def _przeczytaj_anchor(sciezka: str) -> Dict[str, Any]:
    if not os.path.exists(sciezka):
        raise SladError(f"Brak pliku anchoru: {sciezka}")
    with open(sciezka, "r", encoding="utf-8") as f:
        dane = json.load(f)
    if dane.get("typ") != "genesis-anchor" or "genesis_cid" not in dane:
        raise SladError(f"Plik nie jest Genesis Anchor: {sciezka}")
    return dane


def cmd_oglos(args: argparse.Namespace) -> int:
    """
    Drugi krok publikacji: ogłoszenie korzenia zasiewu w sieci DHT.

    Najpierw sprawdza, że korzeń jest lokalnie dostępny i przypięty,
    a także czy zgadza się z odciskiem z anchoru — ogłaszamy tylko to,
    co na pewno jest tym samym zasiewem.
    """
    anchor = _przeczytaj_anchor(args.anchor)
    cid = anchor["genesis_cid"]
    ipfs = IpfsKlient(args.api)

    if not ipfs.ma_blok(cid):
        raise SladError(
            f"Korzeń {cid} nie istnieje w tym węźle — uruchom `oglos` na "
            "maszynie, która zrobiła zasiew, albo najpierw pobierz blok."
        )

    lokalny = _deserializuj_slad(ipfs.pobierz_bytes(cid))
    if hash_tresci(lokalny) != anchor.get("korzen_odcisk"):
        raise SladError(
            "Odcisk korzenia nie zgadza się z anchorem — blok został podmieniony."
        )
    if lokalny.get("author_pubkey") != anchor.get("autor_pubkey"):
        raise SladError("Klucz publiczny korzenia nie zgadza się z anchorem.")

    ipfs.przypnij(cid)

    if args.tylko_sprawdz:
        print(f"Korzeń {cid} jest lokalny i przypięty. Nic nie ogłoszono.")
        return 0

    endpoint = ipfs.oglos_w_sieci(cid)
    print(f"Ogłoszono w sieci: {cid} (przez {endpoint})")
    print("Inne węzły mogą teraz pobrać korzeń (o ile mają trasę do DHT).")
    if args.json:
        print(json.dumps({"ogloszony": cid, "endpoint": endpoint}, ensure_ascii=False))
    return 0


def cmd_publikuj(args: argparse.Namespace) -> int:
    signing_key = _wczytaj_klucz_lub_blad(args)
    ipfs = IpfsKlient(args.api)
    stan = StanLokalny.wczytaj_klub_nowy(args.stan)

    parent = args.rodzic
    payload = buduj_payload(args.usluga, args.zasob, args.opis, args.typ)

    cid, slad, koszt = publikuj_domyslnie(
        ipfs,
        stan,
        signing_key,
        payload,
        parent_cid=parent,
        cooldown_s=args.cooldown,
        prog=args.prog,
        wymuszone=args.wtwardz,
    )

    print(f"CID       : {cid}")
    print(f"Głębokość : {slad['depth']}")
    print(f"Koszt     : {koszt:.4f} ({koszt_w_jezyku_ludzi(koszt)})")
    print(f"Odcisk    : {hash_tresci(slad)}")
    if args.json:
        print(json.dumps({"cid": cid, "trace": slad}, ensure_ascii=False))
    return 0


def cmd_weryfikuj(args: argparse.Namespace) -> int:
    ipfs = IpfsKlient(args.api)
    stan = StanLokalny.wczytaj_klub_nowy(args.stan)
    korzen = args.korzen or stan.korzen_cid
    if not korzen:
        raise SladError("Nie podano korzenia (--korzen) i brak zapisanego stanu.")

    if not stan.znane_slady:
        indeksuj_drzewo(ipfs, korzen, stan, limit=args.limit)

    stat, bledy = weryfikuj_lancuch(ipfs, korzen, args.cooldown, stan, args.limit)
    print(formatuj_statystyki(stat, korzen))
    if bledy:
        print(f"\nZNALEZIONO {len(bledy)} problemów:")
        for b in bledy[: args.max_bledow]:
            print(f"  - {b}")
        if len(bledy) > args.max_bledow:
            print(f"  ... i {len(bledy) - args.max_bledow} więcej")
        if args.json:
            print(json.dumps({"ok": False, "bledy": bledy}, ensure_ascii=False))
        return 1
    print("\nŁańcuch poprawny: wszystkie ślady mają ważne podpisy.")
    if args.json:
        print(json.dumps({"ok": True, "statystyki": stat.__dict__}, ensure_ascii=False))
    return 0


def cmd_koszt(args: argparse.Namespace) -> int:
    """Kalkulator kosztu — prosty podgląd matematyki protokołu."""
    print(f"{'gł.':>5} {'gałęzie':>8} {'koszt':>14}  opis")
    for g in range(0, args.glebokosci + 1):
        for b in range(1, args.galezie + 1):
            koszt = oblicz_koszt_nastepnego_sladu(g, b)
            print(f"{g:>5} {b:>8} {koszt:>14.2f}  {koszt_w_jezyku_ludzi(koszt)}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    ipfs = IpfsKlient(args.api)
    info = ipfs.id()
    stan = StanLokalny.wczytaj_klub_nowy(args.stan)
    print(f"IPFS ID   : {info.get('ID', '?')}")
    print(f"Wersja    : {info.get('AgentVersion', '?')}")
    print(f"API       : {args.api}")
    print(f"Korzeń    : {stan.korzen_cid or '(brak — uruchom genesis)'}")
    print(f"Znane     : {len(stan.znane_slady)} śladów w cache")
    if os.path.exists(args.anchor):
        anchor = _przeczytaj_anchor(args.anchor)
        print(f"Anchor    : {anchor['genesis_cid']} ({anchor.get('adres', '?')})")
    else:
        print("Anchor    : (brak)")
    # Kubo nie podaje trybu w /id, ale przy --offline routing/provide kończy się błędem.
    print("\nWskazówka: do próby generalnej uruchom `ipfs daemon --offline`.")
    return 0


# ---------------------------------------------------------------------------
# CLI — PARSER
# ---------------------------------------------------------------------------


def zbuduj_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="slad",
        description="SLAD — niezależny protokół śladów oparty na IPFS "
        "(Ed25519, cooldown, koszt wykładniczy).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--api", default=DEFAULT_API_URL, help="adres API węzła IPFS Kubo"
    )
    parser.add_argument(
        "--stan", default=DEFAULT_STATE_FILE, help="plik lokalnego stanu"
    )
    parser.add_argument("--portfel", default=DEFAULT_WALLET_FILE, help="plik portfela")
    parser.add_argument(
        "--anchor", default=DEFAULT_ANCHOR_FILE, help="plik Genesis Anchor"
    )
    parser.add_argument(
        "--haslo", default=None, help="hasło portfela (lepiej: zmienna SLAD_HASLO)"
    )
    parser.add_argument("--json", action="store_true", help="wyjście maszynowe (JSON)")

    sub = parser.add_subparsers(dest="komenda", required=True)

    p = sub.add_parser("nowy-portfel", help="generuje nowy portfel papierowy")
    p.add_argument("--nadpisz", action="store_true")
    p.set_defaults(func=cmd_nowy_portfel)

    p = sub.add_parser("portfel", help="pokazuje klucz publiczny i adres")
    p.set_defaults(func=cmd_pokaz_portfel)

    p = sub.add_parser("import-portfel", help="odtwarza portfel z ziarna (base64)")
    p.add_argument("--ziarno", required=True)
    p.set_defaults(func=cmd_import_portfel)

    p = sub.add_parser(
        "genesis", help=f"publikuje {GENESIS_TRACE_COUNT} ślady Fazy Zero"
    )
    p.add_argument(
        "--wtwardz", action="store_true", help="potwierdź inicjalizację zasiewu"
    )
    p.add_argument(
        "--jednorazowy",
        action="store_true",
        help="anonimowy zasiew: świeży klucz z pamięci, zniszczony po publikacji",
    )
    p.add_argument(
        "--anchor",
        default=argparse.SUPPRESS,
        help="plik publicznego Genesis Anchor (tryb --jednorazowy; "
        "domyślnie z opcji globalnej --anchor)",
    )
    p.add_argument("--nadpisz", action="store_true", help="nadpisz istniejący anchor")
    p.set_defaults(func=cmd_genesis)

    p = sub.add_parser(
        "oglos", help="ogłasza korzeń zasiewu w sieci DHT (osobny krok publikacji)"
    )
    # SUPPRESS: bez tego argparse nadpisywałby globalne --anchor domyślną wartością.
    p.add_argument("--anchor", default=argparse.SUPPRESS, help="plik Genesis Anchor")
    p.add_argument(
        "--tylko-sprawdz",
        action="store_true",
        dest="tylko_sprawdz",
        help="sprawdź lokalną dostępność i przypięcie, nic nie ogłaszaj",
    )
    p.set_defaults(func=cmd_oglos)

    p = sub.add_parser("publikuj", help="podpisuje i publikuje nowy ślad w IPFS")
    p.add_argument(
        "--rodzic", default=None, help="CID rodzica (domyślnie: ostatni ślad)"
    )
    p.add_argument("--usluga", default=None, help="nazwa świadczonej usługi")
    p.add_argument("--zasob", default=None, help="adres/identyfikator zasobu")
    p.add_argument("--opis", default="", help="opis śladu (payload)")
    p.add_argument("--typ", default="usluga", help="typ śladu w payloadzie")
    p.add_argument(
        "--cooldown",
        type=float,
        default=DEFAULT_COOLDOWN,
        help="minimalny odstęp między śladami klucza [s]",
    )
    p.add_argument(
        "--prog",
        type=float,
        default=DEFAULT_THRESHOLD,
        help="progowy koszt bezpiecznika",
    )
    p.add_argument(
        "--wtwardz",
        action="store_true",
        help="pomiń bezpiecznik kosztu (świadoma decyzja)",
    )
    p.set_defaults(func=cmd_publikuj)

    p = sub.add_parser("weryfikuj", help="weryfikuje drzewo śladów i liczy statystyki")
    p.add_argument("--korzen", default=None, help="CID korzenia (domyślnie ze stanu)")
    p.add_argument(
        "--cooldown",
        type=float,
        default=DEFAULT_COOLDOWN,
        help="wymagany odstęp między śladami klucza [s]",
    )
    p.add_argument(
        "--limit", type=int, default=None, help="limit śladów do sprawdzenia"
    )
    p.add_argument(
        "--max-bledow",
        type=int,
        default=20,
        dest="max_bledow",
        help="ile błędów pokazać",
    )
    p.set_defaults(func=cmd_weryfikuj)

    p = sub.add_parser("koszt", help="kalkulator kosztu kolejnego śladu")
    p.add_argument("--glebokosci", type=int, default=5, dest="glebokosci")
    p.add_argument("--galezie", type=int, default=8)
    p.set_defaults(func=cmd_koszt)

    p = sub.add_parser("status", help="sprawdza węzeł IPFS i lokalny stan")
    p.set_defaults(func=cmd_status)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = zbuduj_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except SladError as exc:
        print(f"błąd: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nprzerwano", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
