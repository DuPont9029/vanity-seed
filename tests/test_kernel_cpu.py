"""
Compila kernel.cu come C (CPU_TEST) e confronta gli indirizzi con
l'implementazione Python di riferimento su N entropie casuali.
Uso: python tests/test_kernel_cpu.py [N]
"""
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import vanity  # noqa: E402

n = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    exe = td / "harness"
    subprocess.run(["cc", "-O2", "-DCPU_TEST", "-x", "c", str(ROOT / "kernel.cu"), "-o", str(exe)],
                   check=True)
    vanity.build_table().tofile(td / "table.bin")
    w, l = vanity.build_words()
    (td / "words.bin").write_bytes(w.tobytes() + l.tobytes())
    ents = [bytes(16), bytes([0xFF] * 16)] + [secrets.token_bytes(16) for _ in range(n - 2)]
    inp = "".join(e.hex() + "\n" for e in ents)
    res = subprocess.run([str(exe), str(td / "table.bin"), str(td / "words.bin")],
                         input=inp, capture_output=True, text=True, check=True).stdout.split()
    bad = 0
    for e, a in zip(ents, res):
        ref = vanity.address_from_mnemonic(vanity.mnemonic_from_entropy(e))
        if a != ref:
            bad += 1
            if bad <= 5:
                print("MISMATCH", e.hex(), a, ref)
    assert len(res) == len(ents), "output incompleto"
    print(f"{len(ents) - bad}/{len(ents)} OK")
    sys.exit(1 if bad else 0)
