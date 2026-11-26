# vanity-seed

Vanity address Ethereum **con seed BIP39 da 12 parole** (non solo chiave privata), su GPU CUDA.

Ogni tentativo è un mnemonic casuale nuovo (entropia da `secrets`), e l'indirizzo
cercato è `m/44'/60'/0'/0/0`: il primo account che qualunque wallet (MetaMask,
Rabby, Ledger, ...) mostra importando il seed.

## Avvio

Serve solo il driver NVIDIA. Python, CuPy e le librerie CUDA vengono installate
in automatico da [uv](https://docs.astral.sh/uv/). A ogni avvio il bootstrap
scarica l'ultima versione del codice da questo repository.

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/DuPont9029/vanity-seed/main/run.ps1 | iex
```

**Linux / WSL:**
```bash
curl -fsSL https://raw.githubusercontent.com/DuPont9029/vanity-seed/main/run.sh | bash
```

Default: prefisso `C0DEAD`, si ferma al primo risultato. Opzioni (es. `bash -s -- --prefix C0DE --count 3`):

| opzione | |
|---|---|
| `--prefix` / `--suffix` | pattern esadecimale |
| `--case` | rispetta le maiuscole EIP-55 (×2 per ogni lettera) |
| `--count N` | quanti risultati trovare |
| `--cpu` | forza la CPU |
| `--kernel-ms` | durata di ogni lancio GPU (default 200, sotto il watchdog di Windows) |

## Output

- `~/vanity-seed/found.txt`: indirizzo, path e mnemonic di ogni risultato (permessi 600)
- `~/vanity-seed/status.json`: progresso (tentativi, velocità, probabilità), aggiornato ogni lancio

## Sicurezza

- La GPU fa solo la ricerca. All'avvio un self-test confronta 512 seed GPU con la CPU;
  ogni risultato viene ricalcolato sulla CPU **e** con `bip_utils` prima di essere salvato.
- Dopo che la ricerca è partita puoi staccare la rete: non serve internet.
- `found.txt` contiene il seed in chiaro: copialo su carta e cancellalo.
- L'auto-aggiornamento esegue il codice di questo repository: chi controlla l'account GitHub controlla il generatore.

## Sviluppo

`python tests/test_kernel_cpu.py 2000` compila `kernel.cu` come C e confronta
gli indirizzi con l'implementazione Python.
