"""
Hybride Verschluesselung mit einer geprueften Bibliothek
========================================================
So arbeiten z. B. S/MIME und PGP bei verschluesselten E-Mails:
  1. Fuer jede Datei wird ein zufaelliger AES-256-Schluessel erzeugt.
  2. Die Datei wird schnell mit AES-GCM verschluesselt.
  3. Nur der kleine AES-Schluessel wird mit RSA-OAEP fuer den Empfaenger verschluesselt.

Benoetigt: Python ab 3.8 und das Paket "cryptography" (Installation siehe Aufgabenblatt).

Befehle (Windows: "py" statt "python" bzw. Python aus der venv):
  python hybrid.py schluessel  NAME                  Schluesselpaar erzeugen
  python hybrid.py fingerprint DATEI.pem             Fingerprint eines Schluessels anzeigen
  python hybrid.py verschluesseln DATEI EMPFAENGER_oeffentlich.pem
  python hybrid.py entschluesseln DATEI.krypt NAME_privat.pem
  python hybrid.py nur_rsa     DATEI EMPFAENGER_oeffentlich.pem   (Versuch ohne AES)
  python hybrid.py tempo                             AES und RSA im Geschwindigkeitsvergleich
"""

import getpass
import hashlib
import os
import sys
import time

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print('Das Paket "cryptography" fehlt. Installation siehe Aufgabenblatt.')
    sys.exit(1)

RSA_BIT = 3072          # Empfehlung des BSI: mindestens 3000 Bit
MAGIC = b"KRYPT1"
OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def fingerprint(public_key):
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    h = hashlib.sha256(der).hexdigest()[:32].upper()
    return " ".join(h[i:i + 4] for i in range(0, 32, 4))


def lade_oeffentlich(pfad):
    with open(pfad, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def lade_privat(pfad):
    pw = getpass.getpass("Passwort fuer den privaten Schluessel: ").encode()
    with open(pfad, "rb") as f:
        try:
            return serialization.load_pem_private_key(f.read(), password=pw)
        except (ValueError, TypeError):
            print("Falsches Passwort oder keine gueltige Schluesseldatei.")
            sys.exit(1)


def cmd_schluessel(name):
    pw1 = getpass.getpass("Passwort zum Schutz des privaten Schluessels: ")
    pw2 = getpass.getpass("Passwort wiederholen: ")
    if pw1 != pw2 or len(pw1) < 4:
        print("Passwoerter stimmen nicht ueberein oder sind zu kurz.")
        return
    print(f"Erzeuge RSA-Schluesselpaar mit {RSA_BIT} Bit ...")
    start = time.perf_counter()
    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BIT)
    dauer = time.perf_counter() - start
    privat = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                               serialization.BestAvailableEncryption(pw1.encode()))
    oeff = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(f"{name}_privat.pem", "wb") as f:
        f.write(privat)
    with open(f"{name}_oeffentlich.pem", "wb") as f:
        f.write(oeff)
    print(f"Fertig nach {dauer:.2f} s.")
    print(f"  {name}_privat.pem       -> bleibt bei dir (mit Passwort geschuetzt)")
    print(f"  {name}_oeffentlich.pem  -> darfst du weitergeben")
    print(f"Fingerprint deines oeffentlichen Schluessels: {fingerprint(key.public_key())}")


def cmd_fingerprint(pfad):
    with open(pfad, "rb") as f:
        daten = f.read()
    if b"PRIVATE KEY" in daten:
        print("Das ist ein PRIVATER Schluessel. Den gibt man nicht weiter!")
        return
    print("Fingerprint:", fingerprint(serialization.load_pem_public_key(daten)))


def cmd_verschluesseln(datei, empfaenger):
    pub = lade_oeffentlich(empfaenger)
    with open(datei, "rb") as f:
        klartext = f.read()
    print(f"Empfaenger-Schluessel, Fingerprint: {fingerprint(pub)}")
    aes_key = AESGCM.generate_key(bit_length=256)
    print(f"1. Zufaelliger AES-256-Schluessel erzeugt ({len(aes_key)} Byte)")
    nonce = os.urandom(12)
    name = os.path.basename(datei).encode()
    start = time.perf_counter()
    geheim = AESGCM(aes_key).encrypt(nonce, klartext, name)
    t_aes = time.perf_counter() - start
    print(f"2. Datei mit AES-GCM verschluesselt: {len(klartext)} Byte in {t_aes * 1000:.2f} ms")
    start = time.perf_counter()
    key_geheim = pub.encrypt(aes_key, OAEP)
    t_rsa = time.perf_counter() - start
    print(f"3. AES-Schluessel mit RSA-OAEP verschluesselt: {len(key_geheim)} Byte in {t_rsa * 1000:.2f} ms")
    ziel = datei + ".krypt"
    with open(ziel, "wb") as f:
        f.write(MAGIC + len(name).to_bytes(2, "big") + name + len(key_geheim).to_bytes(2, "big")
                + key_geheim + nonce + geheim)
    print(f"4. Paket geschrieben: {ziel}")


def cmd_entschluesseln(paket, privat_pfad):
    with open(paket, "rb") as f:
        daten = f.read()
    if not daten.startswith(MAGIC):
        print("Das ist keine mit hybrid.py verschluesselte Datei.")
        return
    i = len(MAGIC)
    ln = int.from_bytes(daten[i:i + 2], "big"); i += 2
    name = daten[i:i + ln]; i += ln
    lk = int.from_bytes(daten[i:i + 2], "big"); i += 2
    key_geheim = daten[i:i + lk]; i += lk
    nonce = daten[i:i + 12]; i += 12
    geheim = daten[i:]
    key = lade_privat(privat_pfad)
    try:
        aes_key = key.decrypt(key_geheim, OAEP)
    except ValueError:
        print("Der AES-Schluessel laesst sich nicht entschluesseln. Ist das Paket fuer diesen Schluessel bestimmt?")
        return
    print("1. AES-Schluessel mit dem privaten RSA-Schluessel entschluesselt")
    try:
        klartext = AESGCM(aes_key).decrypt(nonce, geheim, name)
    except Exception:
        print("2. FEHLER: Die Datei wurde veraendert oder ist beschaedigt (Pruefung von AES-GCM fehlgeschlagen).")
        return
    print("2. Datei mit AES-GCM entschluesselt und auf Veraenderung geprueft: in Ordnung")
    ziel = "entschluesselt_" + name.decode()
    with open(ziel, "wb") as f:
        f.write(klartext)
    print(f"3. Gespeichert als: {ziel}")


def cmd_nur_rsa(datei, empfaenger):
    pub = lade_oeffentlich(empfaenger)
    with open(datei, "rb") as f:
        klartext = f.read()
    max_len = pub.key_size // 8 - 2 * hashes.SHA256.digest_size - 2
    print(f"Versuche, {len(klartext)} Byte direkt mit RSA-OAEP ({pub.key_size} Bit) zu verschluesseln ...")
    try:
        pub.encrypt(klartext, OAEP)
        print(f"Hat geklappt, weil die Datei sehr klein ist (hoechstens {max_len} Byte moeglich).")
    except ValueError:
        print(f"FEHLER: Zu gross. RSA-OAEP mit {pub.key_size} Bit schafft hoechstens {max_len} Byte am Stueck.")


def cmd_tempo():
    daten = os.urandom(1_000_000)
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    start = time.perf_counter()
    g = AESGCM(aes_key).encrypt(nonce, daten, None)
    AESGCM(aes_key).decrypt(nonce, g, None)
    t_aes = time.perf_counter() - start
    print(f"Erzeuge Test-Schluesselpaar ({RSA_BIT} Bit) ...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BIT)
    pub = key.public_key()
    block = RSA_BIT // 8 - 66
    probe = daten[:100 * block]          # 100 Bloecke messen und hochrechnen
    start = time.perf_counter()
    for i in range(0, len(probe), block):
        key.decrypt(pub.encrypt(probe[i:i + block], OAEP), OAEP)
    t_probe = time.perf_counter() - start
    t_rsa = t_probe * len(daten) / len(probe)
    print()
    print("Verschluesseln und wieder Entschluesseln von 1 MB:")
    print(f"  AES-256-GCM : {t_aes * 1000:10.1f} ms")
    print(f"  RSA-{RSA_BIT}    : {t_rsa * 1000:10.1f} ms   (in Bloecken zu {block} Byte, hochgerechnet)")
    print(f"  RSA ist hier etwa {t_rsa / t_aes:,.0f}-mal langsamer.".replace(",", "."))


def main():
    a = sys.argv[1:]
    befehle = {
        "schluessel": (cmd_schluessel, 1), "fingerprint": (cmd_fingerprint, 1),
        "verschluesseln": (cmd_verschluesseln, 2), "entschluesseln": (cmd_entschluesseln, 2),
        "nur_rsa": (cmd_nur_rsa, 2), "tempo": (cmd_tempo, 0),
    }
    if not a or a[0] not in befehle or len(a) - 1 != befehle[a[0]][1]:
        print(__doc__)
        return
    try:
        befehle[a[0]][0](*a[1:])
    except FileNotFoundError as e:
        print(f"Datei nicht gefunden: {e.filename}")


if __name__ == "__main__":
    main()
