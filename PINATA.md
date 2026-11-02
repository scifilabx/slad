# Pinata — opcjonalne przypinanie (dobrowolne)

Pinata to **hostowana usługa pinowania IPFS**. Skrypt `pinata_pin.py` pozwala
przypiąć istniejący CID (np. ślad SLAD albo drzewo PWA) po stronie Pinaty —
jako **dodatkową kopię** dla dostępności.

## Licencja

- **SDK Pinaty jest na licencji MIT** (ta sama co SLAD) — więc nawet
  dołączenie kodu byłoby zgodne.
- Ten skrypt **nie dołącza** kodu Pinaty: wywołuje tylko jej publiczne
  **REST API** przez `requests`. Nie ma tu żadnej kwestii licencyjnej.
- Sam **serwis** Pinata ma własne warunki korzystania (konto, limity
  darmowego planu). To zewnętrzna usługa, nie część protokołu.

## Ważne

- **Protokół SLAD nie zależy od Pinaty.** Pinata jest w pełni opcjonalna.
- Publiczna bramka Pinaty **nie serwuje HTML** (HTTP 403). Pinata nadaje się
  do przypinania **danych/śladów**, a nie do hostowania samej PWA.
  PWA hostujemy osobno (np. `https://scifilabx.org/slad/`).

## Użycie

```bash
# klucz JWT z konta Pinata — TYLKO w zmiennej środowiskowej, nigdy w kodzie
export PINATA_JWT='...'

# przypnij istniejący CID (np. korzeń PWA albo ślad wydania)
python3 pinata_pin.py QmYRWm7kHvFEjjThMxf4kfx8DR454NXLPtckHrLopw2vNV

# przypnij plik z dysku (zwraca nowy CID)
python3 pinata_pin.py --plik slad_web/index.html
```

## Bezpieczeństwo

- **Nigdy nie wpisuj JWT do kodu, repozytorium ani do aplikacji
  przeglądarkowej.** Trzymaj go wyłącznie w zmiennej środowiskowej / menedżerze
  sekretów.
- Pinowanie nie zmienia treści ani protokołu — to tylko dodatkowa replikacja.
