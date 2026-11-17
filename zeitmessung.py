"""
Wie schnell laesst sich n zerlegen?
===================================
Das Skript erzeugt RSA-Moduln n wachsender Laenge (in Bit) und misst,
wie lange die Probedivision braucht, um n zu zerlegen.
Jeder Versuch wird nach spaetestens ZEITLIMIT Sekunden abgebrochen.
Danach endet die Messung und das Skript rechnet hoch.

Start:   python zeitmessung.py      (Windows: py zeitmessung.py)
Benoetigt: Python ab Version 3.8, keine Zusatzpakete.
"""

import math
import random
import time

ZEITLIMIT = 5.0     # Sekunden
START_BIT = 20
SCHRITT_BIT = 4
MAX_BIT = 64


def ist_primzahl(z):
    if z < 2:
        return False
    if z % 2 == 0:
        return z == 2
    t = 3
    while t * t <= z:
        if z % t == 0:
            return False
        t += 2
    return True


def zufalls_primzahl(bits):
    while True:
        z = random.randrange(2 ** (bits - 1), 2 ** bits) | 1
        if ist_primzahl(z):
            return z


def zerlege(n, frist):
    """Probedivision. Gibt einen Teiler zurueck oder None, wenn die Frist ablaeuft."""
    if n % 2 == 0:
        return 2
    t = 3
    schritte = 0
    while t * t <= n:
        if n % t == 0:
            return t
        t += 2
        schritte += 1
        if schritte % 65536 == 0 and time.perf_counter() > frist:
            return None
    return n


def main():
    print(f"{'Bit von n':>10} | {'n':>22} | {'Zeit':>12}")
    print("-" * 52)
    letzte_bit, letzte_zeit = None, None
    bits = START_BIT
    while bits <= MAX_BIT:
        p = zufalls_primzahl(bits // 2)
        q = zufalls_primzahl(bits // 2)
        while q == p:
            q = zufalls_primzahl(bits // 2)
        n = p * q
        start = time.perf_counter()
        teiler = zerlege(n, start + ZEITLIMIT)
        dauer = time.perf_counter() - start
        if teiler is None:
            print(f"{n.bit_length():>10} | {n:>22} | {'abgebrochen':>12}")
            print(f"Abbruch nach {ZEITLIMIT:.0f} s. Ab hier wird hochgerechnet.")
            break
        print(f"{n.bit_length():>10} | {n:>22} | {dauer:>10.3f} s")
        letzte_bit, letzte_zeit = n.bit_length(), dauer
        bits += SCHRITT_BIT

    print("-" * 52)
    print("Faustregel: 4 Bit mehr bei n bedeuten bei diesem Verfahren etwa 4-mal so viel Zeit.")
    print(f"Hochgerechnet wird von der letzten vollstaendigen Messung ({letzte_bit} Bit).")
    # Hochrechnung: Aufwand waechst mit Wurzel(n), also Faktor 2 pro 2 Bit
    for ziel in (512, 2048, 3072):
        sekunden_log10 = math.log10(max(letzte_zeit, 1e-6)) + (ziel - letzte_bit) / 2 * math.log10(2)
        jahre_log10 = sekunden_log10 - math.log10(3600 * 24 * 365)
        print(f"Hochrechnung fuer {ziel:>4} Bit: etwa 10^{jahre_log10:.0f} Jahre")
    print("Zum Vergleich: Das Universum ist etwa 1,4 * 10^10 Jahre alt.")
    print("ACHTUNG: Diese Hochrechnung gilt nur fuer die Probedivision.")
    print("Echte Angreifer nutzen viel bessere Verfahren als die Probedivision,")
    print("fuer 3000-Bit-Schluessel reicht nach heutigem Wissen aber auch das nicht.")


if __name__ == "__main__":
    main()
