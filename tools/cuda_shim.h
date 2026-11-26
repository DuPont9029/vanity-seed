// Minimal CUDA shim to compile kernel.cu with clang -nocudainc (no CUDA SDK).
#include <__clang_cuda_builtin_vars.h>
#define __constant__ __attribute__((constant))
#define __device__ __attribute__((device))
#define __global__ __attribute__((global))
#define __forceinline__ __attribute__((always_inline))
static __device__ unsigned atomicAdd(unsigned* p, unsigned v) {
  return (unsigned)__nvvm_atom_add_gen_i((int*)p, (int)v);
}
