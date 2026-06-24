# Minimal reproducer — native x86_64-macOS crash, Zig static lib linked into C++

Reproduces, with **no kcov involved**, the SIGSEGV seen when dwarf-zig is linked into the
kcov binary and run natively on x86_64 macOS: entering a `noinline` Zig function that returns
`!std.AutoHashMapUnmanaged(...)` by value, the process faults on a truncated 32-bit pointer
(`si_addr` ≈ `0xf0000032`) at the function's `+5` prologue offset.

- `repro.zig` — a Zig static lib mirroring dwarf-zig's `collectStmtAddrs` (same return shape,
  `noinline`, same std touchpoints), with a self-reporting fault handler.
- `main.cc` — a C++ host that links and calls it (the same static-lib-into-C++-exe shape as kcov).

## Run on a real x86_64 macOS host

```sh
zig build -Doptimize=ReleaseFast            # native CPU
./zig-out/bin/repro
# also try the baseline CPU (the config that crashed in CI):
zig build -Doptimize=ReleaseFast -Dcpu=baseline && ./zig-out/bin/repro
```

- Prints `repro_run rc=N` and exits 0 → **no crash** (this minimal shape doesn't trigger it;
  widen it toward the real `collectStmtAddrs`, or inflate the exe).
- Prints `*** FAULT sig=11 si_addr=0x… rip=0x… collectStmtAddrs=0x… (rip-base=5) ***` →
  **reproduced** independent of kcov.

## Pinpoint the faulting instruction

```sh
lldb -- ./zig-out/bin/repro
(lldb) run
(lldb) register read rip rsp rbp rax
(lldb) disassemble --pc        # the instruction at collectStmtAddrs+5
(lldb) x/6i $pc-8              # find which register holds the truncated 0xf0000032
```

## What's already ruled out (from the kcov investigation)

- **Not AVX-512** — crash persists with `-Dcpu=baseline`.
- **Not the zig host/install** — the x86_64 and aarch64 zig 0.16.0 emit byte-identical
  cross-compiled code; setup-zig just unpacks the stock official tarball.
- **Not user logic** — the fault is in the compiler-emitted prologue, before the first
  statement runs.
- Reproduces only **natively** (Rosetta masks it) and only when the Zig lib is **linked into**
  the larger C++ binary — pointing at a code-model / relocation issue (a truncated
  `R_X86_64_*` against a Zig global) or a register clobbered across the call.

If this binary faults, it's a clean `ziglang/zig` upstream report: `x86_64-macos`, small code
model, error-union-of-struct return, static lib into a C++ executable.
