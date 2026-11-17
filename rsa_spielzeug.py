"""
RSA zum Anfassen (Spielzeug-Version)
====================================
Dieses Skript zeigt, wie RSA im Kern rechnet. Es verwendet absichtlich
winzige Primzahlen und KEIN Padding. Es ist deshalb UNSICHER und nur fuer
den Unterricht gedacht. Echte Programme nutzen gepruefte Bibliotheken
(siehe hybrid.py).

Start:   python rsa_spielzeug.py      (Windows: py rsa_spielzeug.py)
Benoetigt: Python ab Version 3.8, keine Zusatzpakete.

Aendere nur die Werte im Block EINSTELLUNGEN und starte das Skript erneut.
"""

from math import gcd

# ---------------------------------------------------------------- EINSTELLUNGEN
P = 61            # erste Primzahl
Q = 53            # zweite Primzahl (anders als P)
E = 17            # oeffentlicher Exponent
NACHRICHT = "HALLO"
SIGNIERE_ZAHL = 42  # fuer Schritt 5 (Signatur)
# ------------------------------------------------------------------------------


def ist_primzahl(z):
    if z < 2:
        return False
    t = 2
    while t * t <= z:
        if z % t == 0:
            return False
        t += 1
    return True


def linie():
    print("-" * 64)


def main():
    linie()
    print("SCHRITT 1: Schluessel erzeugen")
    linie()
    for name, wert in (("P", P), ("Q", Q)):
        if not ist_primzahl(wert):
            print(f"Fehler: {name} = {wert} ist keine Primzahl. Bitte aendern.")
            return
    if P == Q:
        print("Fehler: P und Q muessen verschieden sein.")
        return
    n = P * Q
    phi = (P - 1) * (Q - 1)
    print(f"n   = P * Q             = {P} * {Q} = {n}")
    print(f"phi = (P-1) * (Q-1)     = {P-1} * {Q-1} = {phi}")
    if gcd(E, phi) != 1:
        print(f"Fehler: E = {E} passt nicht zu phi = {phi} (gemeinsamer Teiler).")
        print("Waehle ein anderes E, z. B. 3, 5, 7, 11, 13, 17 oder 65537.")
        return
    d = pow(E, -1, phi)
    print(f"d   = Gegenstueck zu E  = {d}   (es gilt: E * d mod phi = {E * d % phi})")
    print()
    print(f"OEFFENTLICHER Schluessel (E, n) = ({E}, {n})   -> darf jeder kennen")
    print(f"PRIVATER Schluessel      (d, n) = ({d}, {n})   -> bleibt geheim")
    print("P, Q und phi werden danach nicht mehr gebraucht und muessen ebenfalls geheim bleiben.")

    print()
    linie()
    print(f'SCHRITT 2: Nachricht "{NACHRICHT}" in Zahlen umwandeln')
    linie()
    zahlen = [ord(z) for z in NACHRICHT]
    for z, m in zip(NACHRICHT, zahlen):
        print(f"  {z!r} -> {m}")
    if max(zahlen) >= n:
        print(f"Fehler: Eine Zahl ist groesser als n = {n}. Waehle groessere Primzahlen.")
        return

    print()
    linie()
    print("SCHRITT 3: Verschluesseln mit dem OEFFENTLICHEN Schluessel:  c = m^E mod n")
    linie()
    geheim = [pow(m, E, n) for m in zahlen]
    for m, c in zip(zahlen, geheim):
        print(f"  {m:>5} ^ {E} mod {n} = {c}")
    print()
    print("Geheimtext (zum Kopieren):", ", ".join(str(c) for c in geheim))

    print()
    linie()
    print("SCHRITT 4: Entschluesseln mit dem PRIVATEN Schluessel:  m = c^d mod n")
    linie()
    zurueck = [pow(c, d, n) for c in geheim]
    for c, m in zip(geheim, zurueck):
        print(f"  {c:>5} ^ {d} mod {n} = {m}  -> {chr(m)!r}")
    print()
    print("Entschluesselt:", "".join(chr(m) for m in zurueck))

    print()
    linie()
    print("SCHRITT 5 (Ausblick): Signieren mit dem PRIVATEN Schluessel")
    linie()
    if SIGNIERE_ZAHL >= n:
        print(f"SIGNIERE_ZAHL muss kleiner als n = {n} sein.")
        return
    s = pow(SIGNIERE_ZAHL, d, n)
    print(f"Signatur  s = {SIGNIERE_ZAHL} ^ d mod n = {s}")
    print(f"Pruefen:  s ^ E mod n = {pow(s, E, n)}  (stimmt mit {SIGNIERE_ZAHL} ueberein: {pow(s, E, n) == SIGNIERE_ZAHL})")
    print("Jeder kann mit dem oeffentlichen Schluessel pruefen, aber nur der Besitzer")
    print("des privaten Schluessels kann diese Signatur erzeugen.")
    linie()


if __name__ == "__main__":
    main()
