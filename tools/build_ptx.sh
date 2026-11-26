#!/usr/bin/env bash
# Genera kernel.ptx da kernel.cu con clang/LLVM (non serve il CUDA SDK).
# Uso: tools/build_ptx.sh [clang++]
set -euo pipefail
cd "$(dirname "$0")/.."
CLANG="${1:-$(brew --prefix llvm 2>/dev/null)/bin/clang++}"
"$CLANG" -D__CUDACC__ -x cuda --cuda-device-only --cuda-gpu-arch=sm_75 \
  -nocudainc -nocudalib -O3 -include tools/cuda_shim.h -S -o kernel.ptx kernel.cu
echo "kernel.ptx: $(wc -l < kernel.ptx) righe"
