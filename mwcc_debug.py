#!/usr/bin/env python3
import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import shlex
import struct
import subprocess
import sys
from typing import Optional, Self

try:
    import gdb

    IN_GDB = True
except ImportError:
    IN_GDB = False


# Helpers for parsing structs
def parse_s8(mem: memoryview, offset: int) -> int:
    return int.from_bytes(mem[offset : offset + 1], "little", signed=True)


def parse_u8(mem: memoryview, offset: int) -> int:
    return int.from_bytes(mem[offset : offset + 1], "little", signed=False)


def parse_s16(mem: memoryview, offset: int) -> int:
    return int.from_bytes(mem[offset : offset + 2], "little", signed=True)


def parse_u16(mem: memoryview, offset: int) -> int:
    return int.from_bytes(mem[offset : offset + 2], "little", signed=False)


def parse_s32(mem: memoryview, offset: int) -> int:
    return int.from_bytes(mem[offset : offset + 4], "little", signed=True)


def parse_u32(mem: memoryview, offset: int) -> int:
    return int.from_bytes(mem[offset : offset + 4], "little", signed=False)


# Helpers for reading memory
def read_s8(addr: int) -> int:
    return parse_s8(gdb.selected_inferior().read_memory(addr, 1), 0)


def read_u8(addr: int) -> int:
    return parse_u8(gdb.selected_inferior().read_memory(addr, 1), 0)


def read_s16(addr: int) -> int:
    return parse_s16(gdb.selected_inferior().read_memory(addr, 2), 0)


def read_u16(addr: int) -> int:
    return parse_u16(gdb.selected_inferior().read_memory(addr, 2), 0)


def read_s32(addr: int) -> int:
    return parse_s32(gdb.selected_inferior().read_memory(addr, 4), 0)


def read_u32(addr: int) -> int:
    return parse_u32(gdb.selected_inferior().read_memory(addr, 4), 0)


# Read a C string
def read_string(addr: int) -> str:
    return gdb.Value(addr).cast(gdb.lookup_type("char").pointer()).string()


@dataclass
class MwccVersion:
    # Version name (e.g. "GC/1.1")
    name: str
    # Breakpoint address for start of CodeGen_Generator, after gFunction has been set
    codegen_addr: int
    # Address of gFunction
    gfunction_addr: Optional[int] = None
    # Address of CMangler_GetLinkName
    cmangler_getlinkname_addr: Optional[int] = None


MWCC_VERSION: MwccVersion = None


def init_mwcc_version():
    # TODO: detect compiler version
    global MWCC_VERSION
    MWCC_VERSION = MwccVersion(
        name="GC/1.1",
        codegen_addr=0x435BEE,
        gfunction_addr=None,
        cmangler_getlinkname_addr=0x4C2C70,
    )


@dataclass
class MwccObject:
    name: str
    linkname: Optional[str]

    @classmethod
    def load(cls, addr: int) -> Self:
        # Force the linkname to be evaluated by calling CMangler_GetLinkName. Hopefully this
        # doesn't cause any side effects.
        gdb.execute(
            f"call ((void (*) (void *)) {MWCC_VERSION.cmangler_getlinkname_addr:#x})({addr:#x})"
        )
        mem = gdb.selected_inferior().read_memory(addr, 0x36)
        if MWCC_VERSION.name == "GC/1.1":
            datatype = parse_u8(mem, 0x2)
            name = read_string(parse_u32(mem, 0xA) + 0xA)
            if datatype in (3, 4):  # FUNC, VFUNC
                linkname = read_string(parse_u32(mem, 0x2E) + 0xA)
            else:
                linkname = None
            return cls(
                name=name,
                linkname=linkname,
            )
        else:
            raise ValueError(f"Unsupported MWCC version: {MWCC_VERSION.name}")


def find_current_function() -> MwccObject:
    if MWCC_VERSION.gfunction_addr is None:
        # For GC/1.1, there seems to be no global variable for the current function.
        # Instead, we walk the stack looking for the return address for the callers
        # of CodeGen_Generator, and inspect the second argument to CodeGen_Generator.
        if MWCC_VERSION.name == "GC/1.1":
            stack_start = 0x00111000
            sp = int(gdb.parse_and_eval("$esp"))
            mem = gdb.selected_inferior().read_memory(sp, stack_start - sp)
            for offset in range(0, len(mem), 4):
                value = parse_u32(mem, offset)
                if value in (0x50F08B, 0x50F7B2, 0x510080):
                    # Found a return address for CodeGen_Generator
                    # The second argument is the current function pointer
                    current_function_addr = parse_u32(mem, offset + 8)
                    break
            else:
                raise ValueError(f"Could not find current function")
        else:
            raise ValueError(f"Unsupported MWCC version: {MWCC_VERSION.name}")
    else:
        current_function_addr = read_u32(MWCC_VERSION.gfunction_addr)
    return MwccObject.load(current_function_addr)


def run_compiler():
    # Connect to the remote GDB server
    gdb.execute("set architecture i386")
    gdb.execute("set osabi none")
    gdb.execute("target remote localhost:9001")

    init_mwcc_version()

    # Find the function to analyze
    gdb.execute(f"break *{MWCC_VERSION.codegen_addr:#x}")

    while True:
        gdb.execute("continue")
        func = find_current_function()
        print(f"Compiling function {func.linkname}")
        if FUNCTION_NAME is None or func.linkname == FUNCTION_NAME:
            break

    print()
    print(f"Analyzing function {func.linkname}")


def start_gdb():
    # TODO: Run ninja to get compiler path and arguments?
    parser = argparse.ArgumentParser(
        description="Dump MWCC compiler internals while compiling a file."
    )
    parser.add_argument(
        "--emulator",
        "-e",
        default="retrowin32",
        help="Path to retrowin32 (default: retrowin32)",
    )
    parser.add_argument(
        "--gdb",
        "-g",
        default="gdb-multiarch",
        help="Path to x86 gdb (default: gdb-multiarch)",
    )
    parser.add_argument("--compiler", "-c", required=True, help="Path to mwcceppc.exe")
    parser.add_argument(
        "--args", "-a", required=True, help="Compiler arguments (in quotes)"
    )
    parser.add_argument(
        "--function",
        "-f",
        help="The (mangled) name of the function to analyze (default: first function found)",
    )
    parser.add_argument("INPUT_FILE", help="Input C file")
    parser.add_argument("OUTPUT_DIR", help="Output directory for debug files")

    args = parser.parse_args()
    output_dir = os.path.abspath(args.OUTPUT_DIR)
    os.makedirs(output_dir, exist_ok=True)

    emulator_command = [
        args.emulator,
        "--gdb-stub",
        args.compiler,
        "-c",
        *shlex.split(args.args),
        args.INPUT_FILE,
        "-o",
        "/dev/null",
    ]
    print(f"Emulator command: {shlex.join(emulator_command)}", file=sys.stderr)

    gdb_command = [
        args.gdb,
        "-batch",
        "-nx",
        "-ex",
        f"py FUNCTION_NAME = {args.function!r}",
        "-x",
        str(Path(__file__).resolve()),
    ]
    print(f"GDB command: {shlex.join(gdb_command)}", file=sys.stderr)

    # TODO: The retrowin32 GDB stub is really noisy. Can we disable debug logging instead of hiding its output?
    emulator_process = subprocess.Popen(
        emulator_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    subprocess.run(gdb_command, check=True)

    emulator_process.wait(timeout=10)
    if emulator_process.returncode != 0:
        print(
            f"Emulator process exited with code {emulator_process.returncode}",
            file=sys.stderr,
        )
        sys.exit(emulator_process.returncode)


if __name__ == "__main__":
    # IF we're running under GDB, proceed with the GDB script. If we're not, run start_gdb() to invoke ourselves.
    if IN_GDB:
        run_compiler()
    else:
        start_gdb()
