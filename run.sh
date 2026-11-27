#!/usr/bin/env bash
# Bootstrap Linux / WSL / macOS:
#   curl -fsSL https://raw.githubusercontent.com/DuPont9029/vanity-seed/main/run.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/DuPont9029/vanity-seed/main/run.sh | bash -s -- --prefix C0DEAD
# Installa uv (che scarica Python e le dipendenze), aggiorna il codice
# dall'ultima versione su GitHub e avvia la ricerca.
set -euo pipefail

REPO="DuPont9029/vanity-seed"
BRANCH="${VANITY_BRANCH:-main}"
DIR="${VANITY_DIR:-$HOME/vanity-seed}"

mkdir -p "$DIR"
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

if ! command -v uv >/dev/null 2>&1; then
  echo ">> Installo uv..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi

echo ">> Aggiorno il codice da github.com/$REPO ($BRANCH)..."
TMP="$(mktemp -d)"
if curl -fsSL "https://github.com/$REPO/archive/refs/heads/$BRANCH.tar.gz" | tar xz -C "$TMP" --strip-components=1; then
  rm -rf "$DIR/app"
  mv "$TMP" "$DIR/app"
else
  echo "!! Aggiornamento fallito, uso la copia locale"
  rm -rf "$TMP"
  [ -f "$DIR/app/vanity.py" ] || { echo "Nessuna copia locale disponibile"; exit 1; }
fi

cd "$DIR"
# argomenti extra anche via variabile: VANITY_ARGS="--suffix C0DE"
# shellcheck disable=SC2086
exec uv run --script app/vanity.py "$@" ${VANITY_ARGS:-}
