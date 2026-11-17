"""
Angriff auf Spielzeug-RSA
=========================
Du kennst nur den OEFFENTLICHEN Schluessel (E, n) und einen Geheimtext.
Das Skript zerlegt n in seine beiden Primfaktoren, berechnet daraus den
privaten Schluessel und entschluesselt die Nachricht.

Das klappt nur, weil n hier winzig ist. Bei echten Schluesseln
(3000 Bit und mehr) ist das Zerlegen nach heutigem Wissen praktisch unmoeglich.

Start:   python rsa_angriff.py      (Windows: py rsa_angriff.py)
Benoetigt: Python ab Version 3.8, keine Zusatzpakete.
"""

import time


def zerlege(n):
    """Probedivision: probiert alle moeglichen Teiler der Reihe nach."""
    if n % 2 == 0:
        return 2, n // 2
    t = 3
    while t * t <= n:
        if n % t == 0:
            return t, n // t
        t += 2
    return None


def main():
    print("Angriff auf Spielzeug-RSA")
    print("-" * 64)
    try:
        n = int(input("Oeffentlicher Schluessel, Wert n: ").strip())
        e = int(input("Oeffentlicher Schluessel, Wert E: ").strip())
        text = input("Geheimtext (Zahlen mit Komma getrennt): ")
        geheim = [int(x) for x in text.replace(";", ",").split(",") if x.strip()]
    except ValueError:
        print("Eingabe nicht verstanden. Bitte nur ganze Zahlen eingeben.")
        return

    start = time.perf_counter()
    faktoren = zerlege(n)
    dauer = time.perf_counter() - start
    if not faktoren:
        print(f"{n} laesst sich nicht zerlegen (ist n eine Primzahl?).")
        return
    p, q = faktoren
    print()
    print(f"n = {p} * {q}   (gefunden in {dauer * 1000:.2f} ms)")
    phi = (p - 1) * (q - 1)
    try:
        d = pow(e, -1, phi)
    except ValueError:
        print("E passt nicht zu n. Sind die Werte richtig abgeschrieben?")
        return
    print(f"phi = {phi}")
    print(f"Privater Schluessel d = {d}")
    klar = [pow(c, d, n) for c in geheim]
    try:
        print("Entschluesselte Nachricht:", "".join(chr(m) for m in klar))
    except (ValueError, OverflowError):
        print("Entschluesselte Zahlen:", klar)


if __name__ == "__main__":
    main()
