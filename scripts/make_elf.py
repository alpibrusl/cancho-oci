#!/usr/bin/env python3
"""Tiny Linux ELF64 executables for the build gate: `exit(0)` as raw syscalls, no libc, so they run in a
`scratch` image on their own architecture. Also a dynamic variant (a PT_INTERP naming a loader), which
a scratch image cannot start, and the pieces to break a header on purpose.

    make_elf.py <arch> <path> [--dynamic]      arch: amd64 | arm64 | riscv64
"""
import struct, sys

CODE = {
    # xor edi,edi ; mov eax,60 ; syscall
    "amd64": (62, bytes.fromhex("31ff" + "b83c000000" + "0f05")),
    # mov x0,#0 ; mov x8,#93 ; svc #0
    "arm64": (183, struct.pack("<III", 0xD2800000, 0xD2800BA8, 0xD4000001)),
    # addi a0,x0,0 ; addi a7,x0,93 ; ecall
    "riscv64": (243, struct.pack("<III", 0x00000513, 0x05D00893, 0x00000073)),
}
LOADER = b"/lib64/ld-linux-x86-64.so.2\0"
BASE = 0x400000


def elf(arch, dynamic=False):
    machine, code = CODE[arch]
    nph = 2 if dynamic else 1
    ph_end = 64 + 56 * nph
    interp_off = ph_end
    code_off = ph_end + (len(LOADER) if dynamic else 0)
    total = code_off + len(code)
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4], hdr[5], hdr[6] = 2, 1, 1
    struct.pack_into("<HHIQQQIHHHHHH", hdr, 16, 2, machine, 1, BASE + code_off, 64, 0, 0, 64, 56, nph, 64, 0, 0)
    phs = struct.pack("<IIQQQQQQ", 1, 5, 0, BASE, BASE, total, total, 0x1000)       # PT_LOAD, R+X
    if dynamic:
        phs = struct.pack("<IIQQQQQQ", 3, 4, interp_off, BASE + interp_off, BASE + interp_off, len(LOADER), len(LOADER), 1) + phs
    return bytes(hdr) + phs + (LOADER if dynamic else b"") + code


if __name__ == "__main__":
    arch, path = sys.argv[1], sys.argv[2]
    open(path, "wb").write(elf(arch, "--dynamic" in sys.argv))
    import os
    os.chmod(path, 0o755)
