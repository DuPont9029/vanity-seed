# /// script
# requires-python = ">=3.12,<3.13"
# dependencies = [
#   "coincurve>=20",
#   "pycryptodome>=3.20",
#   "bip_utils>=2.9",
#   "numpy>=1.26",
#   "pyzipper>=0.3.6",
#   "cupy-cuda12x>=13; sys_platform != 'darwin'",
#   "nvidia-cuda-nvrtc-cu12; sys_platform != 'darwin'",
#   "nvidia-cuda-runtime-cu12; sys_platform != 'darwin'",
# ]
# ///
"""
Vanity address Ethereum con seed BIP39 (12 parole), su GPU CUDA.

Ogni tentativo = mnemonic casuale nuovo -> m/44'/60'/0'/0/0 (primo account in
qualunque wallet). Ogni risultato della GPU viene ricalcolato sulla CPU e con
bip_utils (implementazione indipendente) prima di essere salvato in found.txt.
"""
import argparse
import faulthandler
import hashlib
import hmac
import json
import math
import multiprocessing as mp
import os
import queue
import secrets
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np
from coincurve import PublicKey
from Crypto.Hash import keccak

VERSION = "1.2.0"
faulthandler.enable()  # in caso di crash nativo (driver/NVRTC) stampa dove
HERE = Path(__file__).resolve().parent
WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
_raw = (HERE / "english.txt").read_bytes()
if hashlib.sha256(_raw).hexdigest() != WORDLIST_SHA256:
    sys.exit("ERRORE: english.txt non corrisponde alla wordlist BIP39 ufficiale")
WORDS = _raw.decode().split()

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
H = 0x80000000
PATH = "m/44'/60'/0'/0/0"


# ================================================================ crypto CPU
def keccak256(data: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=data).digest()


def mnemonic_from_entropy(ent: bytes) -> str:
    cs = hashlib.sha256(ent).digest()[0] >> 4
    bits = (int.from_bytes(ent, "big") << 4) | cs  # 132 bit
    return " ".join(WORDS[(bits >> (11 * (11 - i))) & 0x7FF] for i in range(12))


def address_from_mnemonic(mnemonic: str) -> str:
    """Indirizzo (40 hex minuscoli) di m/44'/60'/0'/0/0."""
    seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonic", 2048)
    I = hmac.digest(b"Bitcoin seed", seed, "sha512")
    k, c = int.from_bytes(I[:32], "big"), I[32:]
    for idx in (44 | H, 60 | H, 0 | H):
        I = hmac.digest(c, b"\x00" + k.to_bytes(32, "big") + idx.to_bytes(4, "big"), "sha512")
        il = int.from_bytes(I[:32], "big")
        if il >= N:
            raise ValueError("chiave invalida")
        k, c = (il + k) % N, I[32:]
        if k == 0:
            raise ValueError("chiave invalida")
    pub = PublicKey.from_secret(k.to_bytes(32, "big"))
    for idx in (0, 0):
        I = hmac.digest(c, pub.format(compressed=True) + idx.to_bytes(4, "big"), "sha512")
        pub, c = pub.add(I[:32]), I[32:]
    return keccak256(pub.format(compressed=False)[1:])[-20:].hex()


def checksum_address(addr: str) -> str:
    h = keccak256(addr.encode()).hex()
    return "".join(ch.upper() if int(h[i], 16) >= 8 else ch for i, ch in enumerate(addr))


def reference_address(mnemonic: str) -> str:
    """Implementazione indipendente (bip_utils). Ritorna formato EIP-55."""
    from bip_utils import (Bip39MnemonicValidator, Bip39SeedGenerator, Bip44,
                           Bip44Changes, Bip44Coins)
    Bip39MnemonicValidator().Validate(mnemonic)
    seed = Bip39SeedGenerator(mnemonic).Generate()
    acc = (Bip44.FromSeed(seed, Bip44Coins.ETHEREUM).Purpose().Coin()
           .Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0))
    return acc.PublicKey().ToAddress()


KNOWN = ("abandon " * 11 + "about", "9858effd232b4033e47d90003d41ec34ecaeda94")


def cpu_self_test():
    assert mnemonic_from_entropy(bytes(16)) == KNOWN[0]
    assert address_from_mnemonic(KNOWN[0]) == KNOWN[1]
    for _ in range(10):
        m = mnemonic_from_entropy(secrets.token_bytes(16))
        if "0x" + checksum_address(address_from_mnemonic(m)) != reference_address(m):
            raise AssertionError("mismatch tra implementazione CPU e bip_utils")


# ================================================================ dati per la GPU
def build_table() -> np.ndarray:
    """table[i][d] = d * 16^i * G (affine), limb u32 little-endian: x[8], y[8]."""
    t = np.zeros((64, 16, 16), dtype=np.uint32)
    for i in range(64):
        for d in range(1, 16):
            raw = PublicKey.from_secret((d << (4 * i)).to_bytes(32, "big")).format(compressed=False)
            x, y = int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:], "big")
            for j in range(8):
                t[i, d, j] = (x >> (32 * j)) & 0xFFFFFFFF
                t[i, d, 8 + j] = (y >> (32 * j)) & 0xFFFFFFFF
    return t.reshape(-1)


def build_words():
    w = np.zeros((2048, 8), dtype=np.uint8)
    lens = np.zeros(2048, dtype=np.uint8)
    for i, word in enumerate(WORDS):
        b = word.encode()
        assert len(b) <= 8
        w[i, :len(b)] = list(b)
        lens[i] = len(b)
    return w.reshape(-1), lens


# ================================================================ risultati
HEXCH = "0123456789abcdefABCDEF"


def seg_ok(seg: str, pat: str, case: bool) -> bool:
    """seg: pezzo di indirizzo (minuscolo o EIP-55). pat: hex esatto o '#' = cifra 0-9."""
    for ac, p in zip(seg, pat):
        a = ac.lower()
        if p == "#":
            if a not in "0123456789":
                return False
        elif a != p.lower():
            return False
        elif case and p.isalpha() and ac != p:
            return False
    return True


def addr_matches(addr: str, prefix: str, suffix: str, case: bool = False) -> bool:
    return seg_ok(addr[:len(prefix)], prefix, case) and (
        not suffix or seg_ok(addr[-len(suffix):], suffix, case))


def write_encrypted_zip(path: Path, inner_name: str, content: str, password: str):
    import pyzipper
    with pyzipper.AESZipFile(path, "w", compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as z:
        z.setpassword(password.encode())
        z.setencryption(pyzipper.WZ_AES, nbits=256)
        z.writestr(inner_name, content)
    with pyzipper.AESZipFile(path) as z:  # rilettura di controllo
        z.setpassword(password.encode())
        if z.read(inner_name).decode() != content:
            raise RuntimeError(f"verifica di {path} fallita")


class Results:
    def __init__(self, outdir: Path, prefix, suffix, case, count, names=None, password=None):
        self.outdir, self.prefix, self.suffix, self.case = outdir, prefix, suffix, case
        self.pending = list(names) if names else None
        self.password = password
        self.target = len(self.pending) if names else count
        self.found = 0

    def done(self):
        return self.found >= self.target

    def check_and_save(self, mnemonic: str) -> bool:
        """Ricontrolla un candidato con CPU + bip_utils; se valido lo salva."""
        mine = checksum_address(address_from_mnemonic(mnemonic))
        ref = reference_address(mnemonic)
        if "0x" + mine != ref:
            print(f"\n!! Candidato scartato: CPU {mine} ≠ bip_utils {ref}")
            return False
        if not addr_matches(mine, self.prefix, self.suffix):
            print(f"\n!! Candidato GPU non corrisponde al pattern ({ref}): bug del kernel?")
            return False
        if not addr_matches(mine, self.prefix, self.suffix, self.case):
            return False  # pattern giusto ma maiuscole EIP-55 diverse
        content = (f"address:  {ref}\npath:     {PATH}\nmnemonic: {mnemonic}\n"
                   f"created:  {datetime.now().isoformat(timespec='seconds')}\n")
        if self.pending is not None:
            name = self.pending.pop(0)
            dest = self.outdir / f"{name}.zip"
            write_encrypted_zip(dest, f"{name}.txt", content, self.password)
        else:
            dest = self.outdir / "found.txt"
            new = not dest.exists()
            with open(dest, "a", encoding="utf-8") as f:
                f.write(content + "\n")
            if new:
                try:
                    os.chmod(dest, 0o600)
                except OSError:
                    pass
        self.found += 1
        print(f"\n\n*** TROVATO {self.found}/{self.target}: {ref}\n    salvato in {dest}\n")
        return True


def fmt_dur(sec):
    if sec == float("inf"):
        return "∞"
    sec = int(sec)
    d, sec = divmod(sec, 86400)
    h, sec = divmod(sec, 3600)
    m, sec = divmod(sec, 60)
    return (f"{d}g " if d else "") + (f"{h}h " if h or d else "") + f"{m:02d}m {sec:02d}s"


class Progress:
    def __init__(self, expected, status_path: Path, label):
        self.expected, self.status, self.label = expected, status_path, label
        self.t0 = time.time()

    def show(self, tried, found):
        el = time.time() - self.t0
        rate = tried / el if el > 0 else 0
        prob = 1 - math.exp(-tried / self.expected)
        eta = (self.expected - tried) / rate if rate and tried < self.expected else (0 if rate else float("inf"))
        line = (f"\r[{self.label}] {tried:>14,} tentativi | {rate:>9,.0f}/s | {fmt_dur(el)} | "
                f"prob. finora {prob*100:5.1f}% | media attesa tra {fmt_dur(eta)} | trovati {found}   ")
        sys.stdout.write(line.replace(",", "."))
        sys.stdout.flush()
        try:
            self.status.write_text(json.dumps({"backend": self.label, "tried": tried, "rate": round(rate),
                                               "elapsed": round(el), "prob": round(prob, 4),
                                               "found": found, "updated": time.time()}))
        except OSError:
            pass


# ================================================================ GPU
def _preload_nvidia_libs():
    """Rende visibili a CuPy le librerie CUDA installate via pip (nvidia-*)."""
    import ctypes
    import site
    roots = list(site.getsitepackages())
    try:
        roots.append(site.getusersitepackages())
    except Exception:
        pass
    for r in roots:
        nv = Path(r) / "nvidia"
        if not nv.is_dir():
            continue
        if os.name == "nt":
            for d in list(nv.glob("*/bin")) + list(nv.glob("*/lib")):
                try:
                    os.add_dll_directory(str(d))
                except OSError:
                    pass
                os.environ["PATH"] = str(d) + os.pathsep + os.environ.get("PATH", "")
        else:
            for pat in ("cuda_runtime/lib/libcudart.so*", "cuda_nvrtc/lib/libnvrtc-builtins.so*",
                        "cuda_nvrtc/lib/libnvrtc.so*"):
                for f in sorted(nv.glob(pat)):
                    try:
                        ctypes.CDLL(str(f), mode=ctypes.RTLD_GLOBAL)
                    except OSError:
                        pass


def gpu_search(args, prefix, suffix, expected, results: Results, status: Path):
    _preload_nvidia_libs()
    import warnings
    warnings.filterwarnings("ignore", message="CUDA path could not be detected")
    import cupy as cp

    props = cp.cuda.runtime.getDeviceProperties(args.device)
    cp.cuda.Device(args.device).use()
    name = props["name"].decode() if isinstance(props["name"], bytes) else props["name"]
    print(f"GPU: {name}  (compute {props['major']}.{props['minor']}, {props['multiProcessorCount']} SM)")

    t = time.time()
    if args.nvrtc:
        print("Compilo il kernel CUDA con NVRTC...", end=" ", flush=True)
        mod = cp.RawModule(code=(HERE / "kernel.cu").read_text(), options=("-std=c++14",))
    else:
        print("Carico il kernel PTX precompilato (JIT del driver)...", end=" ", flush=True)
        mod = cp.RawModule(path=str(HERE / "kernel.ptx"))
    k_derive = mod.get_function("derive")
    k_search = mod.get_function("search")
    print(f"OK ({time.time() - t:.1f}s)")

    words, wlen = build_words()
    d_words, d_wlen = cp.asarray(words), cp.asarray(wlen)
    d_table = cp.asarray(build_table())
    TPB = args.threads

    # ---- self-test GPU vs CPU
    n_test = 512
    print(f"Self-test GPU su {n_test} seed contro la CPU...", end=" ", flush=True)
    ents = [bytes(16)] + [secrets.token_bytes(16) for _ in range(n_test - 1)]
    arr = np.array([[int.from_bytes(e[:8], "big"), int.from_bytes(e[8:], "big")] for e in ents],
                   dtype=np.uint64).reshape(-1)
    d_out = cp.zeros(20 * n_test, dtype=cp.uint8)
    k_derive(((n_test + TPB - 1) // TPB,), (TPB,),
             (d_words, d_wlen, d_table, cp.asarray(arr), np.uint32(n_test), d_out))
    out = cp.asnumpy(d_out).reshape(n_test, 20)
    for e, a in zip(ents, out):
        if bytes(a).hex() != address_from_mnemonic(mnemonic_from_entropy(e)):
            sys.exit("FALLITO: la GPU produce indirizzi diversi dalla CPU. Non proseguo.\n"
                     "Riprova più tardi: il repository verrà corretto e il bootstrap scarica l'ultima versione.")
    print("OK")

    pat = np.array([16 if ch == "#" else int(ch, 16) for ch in prefix + suffix] or [0], dtype=np.uint8)
    d_pat = cp.asarray(pat)
    MAXH = 64
    d_count = cp.zeros(1, dtype=cp.uint32)
    d_hits = cp.zeros(2 * MAXH, dtype=cp.uint64)

    batch = TPB * props["multiProcessorCount"] * 4
    target = args.kernel_ms / 1000
    prog = Progress(expected, status, "GPU")
    tried = 0
    print(f"Ricerca avviata. Risultati → {results.outdir}\nCtrl+C per fermare.\n")
    while not results.done():
        base = secrets.randbits(128)
        d_count.fill(0)
        t = time.time()
        k_search(((batch + TPB - 1) // TPB,), (TPB,),
                 (d_words, d_wlen, d_table, np.uint64(base >> 64), np.uint64(base & (2**64 - 1)),
                  np.uint32(batch), d_pat, np.uint32(len(prefix)), np.uint32(len(suffix)),
                  d_count, d_hits, np.uint32(MAXH)))
        cp.cuda.Stream.null.synchronize()
        dt = time.time() - t
        tried += batch
        cnt = int(d_count.get()[0])
        if cnt:
            hits = d_hits.get()
            for i in range(min(cnt, MAXH)):
                ent = int(hits[2 * i]).to_bytes(8, "big") + int(hits[2 * i + 1]).to_bytes(8, "big")
                results.check_and_save(mnemonic_from_entropy(ent))
                if results.done():
                    break
        prog.show(tried, results.found)
        # adatta la dimensione del batch per stare intorno a kernel_ms per lancio
        if dt > 0:
            batch = int(min(max(batch * (target / dt) ** 0.5, TPB * 8), 1 << 24))
            batch -= batch % TPB


# ================================================================ CPU (fallback)
def cpu_worker(prefix, suffix, counter, found_q, stop):
    local = 0
    while not stop.is_set():
        m = mnemonic_from_entropy(secrets.token_bytes(16))
        try:
            a = address_from_mnemonic(m)
        except ValueError:
            continue
        local += 1
        if addr_matches(a, prefix, suffix):
            found_q.put(m)
        if local >= 64:
            with counter.get_lock():
                counter.value += local
            local = 0


def cpu_search(args, prefix, suffix, expected, results: Results, status: Path):
    counter, found_q, stop = mp.Value("Q", 0), mp.Queue(), mp.Event()
    procs = [mp.Process(target=cpu_worker, daemon=True, args=(prefix, suffix, counter, found_q, stop))
             for _ in range(args.workers)]
    for pr in procs:
        pr.start()
    print(f"Avviati {args.workers} processi CPU. Risultati → {results.outdir}\nCtrl+C per fermare.\n")
    prog = Progress(expected, status, "CPU")
    try:
        while not results.done():
            try:
                results.check_and_save(found_q.get(timeout=1))
            except queue.Empty:
                pass
            prog.show(counter.value, results.found)
    finally:
        stop.set()
        for pr in procs:
            pr.join(timeout=2)


# ================================================================ main
def desktop_dir() -> Path:
    if os.name == "nt":
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(260)
            if ctypes.windll.shell32.SHGetFolderPathW(None, 0x10, None, 0, buf) == 0:  # CSIDL_DESKTOPDIRECTORY
                return Path(buf.value)
        except Exception:
            pass
    return Path.home() / "Desktop"


def ask_password() -> str:
    pw = os.environ.get("VANITY_PASSWORD")
    if pw:
        print("Password presa da VANITY_PASSWORD.")
        return pw
    import getpass
    while True:
        a = getpass.getpass("Password per cifrare i file: ")
        if not a:
            print("La password non può essere vuota.")
            continue
        if getpass.getpass("Ripeti la password: ") == a:
            return a
        print("Le password non coincidono, riprova.")


def main():
    ap = argparse.ArgumentParser(description="Vanity address ETH con seed BIP39 (GPU CUDA)")
    ap.add_argument("--prefix", default="C0DEAD", help="hex; '#' = una cifra 0-9 (es. C0DEAD#)")
    ap.add_argument("--suffix", default="", help="hex; '#' = una cifra 0-9")
    ap.add_argument("--case", action="store_true", help="rispetta maiuscole EIP-55 (x2 per lettera)")
    ap.add_argument("--count", type=int, default=1, help="quanti risultati trovare (senza --names)")
    ap.add_argument("--names", default="",
                    help="nomi separati da virgola: un seed per nome, ognuno in <nome>.zip cifrato AES-256")
    ap.add_argument("--outdir", default="",
                    help="cartella di output (default: Desktop/vanity-seeds con --names, altrimenti corrente)")
    ap.add_argument("--cpu", action="store_true", help="forza la ricerca su CPU")
    ap.add_argument("--nvrtc", action="store_true", help="compila kernel.cu con NVRTC invece del PTX")
    ap.add_argument("--workers", type=int, default=os.cpu_count(), help="processi CPU")
    ap.add_argument("--device", type=int, default=0, help="indice GPU")
    ap.add_argument("--threads", type=int, default=128, help="thread per blocco CUDA")
    ap.add_argument("--kernel-ms", type=int, default=200, help="durata obiettivo di ogni lancio")
    args = ap.parse_args()

    prefix = args.prefix.removeprefix("0x").removeprefix("0X")
    suffix = args.suffix
    pattern = prefix + suffix
    bad = sorted({ch for ch in pattern if ch not in HEXCH + "#"})
    if bad:
        sys.exit(f"Pattern non valido: {bad}. Ammessi 0-9, a-f e '#' (= cifra). 'O' lettera ≠ '0' zero.")
    if len(pattern) > 40:
        sys.exit("Pattern troppo lungo")
    expected = 1.0
    for ch in pattern:
        expected *= 1.6 if ch == "#" else (32 if (args.case and ch.isalpha()) else 16)
    expected = int(expected)

    names = [n.strip() for n in args.names.split(",") if n.strip()]
    bad_names = [n for n in names if not all(c.isalnum() or c in "-_" for c in n)]
    if bad_names:
        sys.exit(f"Nomi non validi: {bad_names} (solo lettere, numeri, - e _)")
    if args.outdir:
        outdir = Path(args.outdir).expanduser().resolve()
    elif names:
        outdir = desktop_dir() / "vanity-seeds"
    else:
        outdir = Path.cwd()
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"vanity-seed {VERSION}")
    print(f"Pattern: 0x{prefix}…{suffix}   (maiuscole {'esatte' if args.case else 'ignorate'}; # = cifra)")
    print(f"Tentativi attesi per ogni risultato: {expected:,}".replace(",", "."))

    password = None
    if names:
        done = [n for n in names if (outdir / f"{n}.zip").exists()]
        names = [n for n in names if n not in done]
        if done:
            print(f"Già presenti in {outdir} (salto): {', '.join(done)}")
        if not names:
            print("Tutti i file esistono già. Niente da fare.")
            return
        print(f"Da trovare: {', '.join(names)}  →  {outdir}")
        password = ask_password()

    print("Self-test CPU (vettore noto + bip_utils)...", end=" ", flush=True)
    try:
        cpu_self_test()
        if names:
            import tempfile
            with tempfile.TemporaryDirectory() as td:
                write_encrypted_zip(Path(td) / "t.zip", "t.txt", "test", password)
    except Exception as e:
        sys.exit(f"FALLITO: {e}")
    print("OK")

    results = Results(outdir, prefix, suffix, args.case, args.count, names or None, password)
    status = Path.cwd() / "status.json"
    total = expected * results.target
    try:
        if args.cpu:
            cpu_search(args, prefix, suffix, total, results, status)
        else:
            try:
                gpu_search(args, prefix, suffix, total, results, status)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"\n!! GPU non utilizzabile ({type(e).__name__}: {e}).\n"
                      f"   Mandami l'errore qui sopra. Intanto passo alla CPU.\n")
                cpu_search(args, prefix, suffix, total, results, status)
    except KeyboardInterrupt:
        print("\nInterrotto. Rilanciando, i nomi già salvati vengono saltati.")
    print(f"\nFine. Trovati {results.found}/{results.target}. Cartella: {outdir}")


if __name__ == "__main__":
    mp.freeze_support()
    main()
