#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path
import shlex
import struct
import subprocess
import sys
from typing import Optional

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
    # Breakpoint address for start of CodeGen_Generator(), after gFunction has been set
    codegen_start_addr: int
    # Breakpoint address for end of CodeGen_Generator()
    codegen_end_addr: int
    # Address of gFunction
    gfunction_addr: Optional[int]
    # Address of CMangler_GetLinkName()
    cmangler_getlinkname_addr: int
    # Address of opcode info table
    opcodeinfo_addr: int
    # Number of entries in the opcode info table
    opcodeinfo_size: int
    # Address of pcbasicblocks
    pcbasicblocks_addr: int
    # Breakpoint addresses for dumping pcode, with the names of output files
    pcode_breakpoints: dict[int, str]
    # Breakpoint for regalloc, at the end of colorgraph()
    regalloc_breakpoint_addr: int
    # Address of interferencegraph
    interferencegraph_addr: int
    # Address of used_virtual_registers[RegClass_GPR]
    used_virtual_registers_gpr_addr: int
    # Address of used_virtual_registers[RegClass_FPR]
    used_virtual_registers_fpr_addr: int
    # Address of coloring_class
    coloring_class_addr: Optional[int]


MWCC_VERSION: MwccVersion = None


def init_mwcc_version():
    global MWCC_VERSION
    # Look for string "Metrowerks C/C++ Compiler for Embedded PowerPC"
    if bytes(gdb.selected_inferior().read_memory(0x541BBC, 10)) == b"Metrowerks":
        MWCC_VERSION = MwccVersion(
            name="GC/1.1",
            codegen_start_addr=0x4351B0,
            codegen_end_addr=0x435DA9,
            gfunction_addr=None,
            cmangler_getlinkname_addr=0x4C2C70,
            opcodeinfo_addr=0x5664B0,
            opcodeinfo_size=468,
            pcbasicblocks_addr=0x588474,
            pcode_breakpoints={
                0x435AF4: "backend-00-initial-code.txt",
                0x435B69: "backend-01-before-scheduling.txt",
                0x435B6E: "backend-02-after-scheduling.txt",
                0x435BEE: "backend-03-before-regalloc.txt",
                0x435BF3: "backend-04-after-regalloc.txt",
                0x435D60: "backend-05-before-final-scheduling.txt",
                0x435D65: "backend-06-after-final-scheduling.txt",
                0x435DA9: "backend-07-final-code.txt",
            },
            regalloc_breakpoint_addr=0x4CEB04,
            interferencegraph_addr=0x58863C,
            used_virtual_registers_gpr_addr=0x588C72,
            used_virtual_registers_fpr_addr=0x588C70,
            coloring_class_addr=None,
        )
    elif bytes(gdb.selected_inferior().read_memory(0x58D224, 10)) == b"Metrowerks":
        MWCC_VERSION = MwccVersion(
            name="GC/2.6",
            codegen_start_addr=0x433492,
            codegen_end_addr=0x4340B1,
            gfunction_addr=0x05E9EC0,
            cmangler_getlinkname_addr=0x4FE6A0,
            opcodeinfo_addr=0x5C0FA8,
            opcodeinfo_size=471,
            pcbasicblocks_addr=0x5EA748,
            pcode_breakpoints={
                0x433D77: "backend-00-initial-code.txt",
                0x433E07: "backend-01-before-scheduling.txt",
                0x433E0C: "backend-02-after-scheduling.txt",
                0x433EA6: "backend-03-before-regalloc.txt",
                0x433EAB: "backend-04-after-regalloc.txt",
                0x43405E: "backend-05-before-final-scheduling.txt",
                0x434063: "backend-06-after-final-scheduling.txt",
                0x4340B1: "backend-07-final-code.txt",
            },
            regalloc_breakpoint_addr=0x5089A9,
            interferencegraph_addr=0x5EA768,
            used_virtual_registers_gpr_addr=0x5EAA3C,
            used_virtual_registers_fpr_addr=0x5EAA38,
            coloring_class_addr=0x5EB2CF,
        )
    else:
        raise ValueError("Unsupported MWCC version or not an MWCC binary")
    print(f"MWCC version: {MWCC_VERSION.name}")


@dataclass
class MwccObject:
    name: str
    linkname: Optional[str]

    @classmethod
    def load(cls, addr: int, load_linkname=False) -> MwccObject:
        # Force the linkname to be evaluated by calling CMangler_GetLinkName. Hopefully this
        # doesn't cause any side effects.
        gdb.execute(
            f"call ((void (*) (void *)) {MWCC_VERSION.cmangler_getlinkname_addr:#x})({addr:#x})"
        )
        mem = gdb.selected_inferior().read_memory(addr, 0x36)
        datatype = parse_u8(mem, 0x2)
        name = read_string(parse_u32(mem, 0xA) + 0xA)
        if load_linkname and datatype in (3, 4):  # FUNC, VFUNC
            if MWCC_VERSION.name == "GC/1.1":
                offset = 0x2E
            elif MWCC_VERSION.name == "GC/2.6":
                offset = 0x32
            else:
                raise ValueError(f"Unsupported MWCC version: {MWCC_VERSION.name}")
            linkname = read_string(parse_u32(mem, offset) + 0xA)
        else:
            linkname = None
        return cls(
            name=name,
            linkname=linkname,
        )


@dataclass
class MwccOpcodeInfo:
    mnemonic: str
    format_str: str


@dataclass
class MwccPCodeArg:
    class Kind(Enum):
        GPR = 0  # General Purpose Register
        FPR = 1  # Floating Point Register
        SPR = 2  # Special Purpose Register
        CRFIELD = 3  # Condition Register Field
        VR = 4  # Vector Register
        IMMEDIATE = 5  # Immediate Value
        MEMORY = 6  # Memory Address
        LABEL = 7  # Label
        PLACEHOLDER = 8  # Placeholder for unused arguments

    kind: Kind
    reg: Optional[int] = None  # For GPR, FPR, SPR, crfield, vector register
    imm: Optional[int] = None  # For immediate, memory
    obj_addr: Optional[int] = None  # For memory
    block_index: Optional[int] = None  # For label


@dataclass
class MwccPcode:
    next_addr: int
    line: Optional[int]
    op: int
    # TODO: flags
    args: list[MwccPCodeArg]

    @classmethod
    def load(cls, addr: int) -> MwccPcode:
        if MWCC_VERSION.name == "GC/1.1":
            mem = gdb.selected_inferior().read_memory(addr, 0x1C)
            # flags = parse_u32(mem, 0x16)
            arg_count = parse_s16(mem, 0x1A)
            if arg_count > 0:
                arg_mem = gdb.selected_inferior().read_memory(
                    addr + 0x1C, arg_count * 0xC
                )

            args = []
            for i in range(arg_count):
                arg_offset = i * 0xC
                kind = parse_u8(arg_mem, arg_offset)
                if kind == 0:  # GPR
                    reg = parse_u16(arg_mem, arg_offset + 2)
                    args.append(MwccPCodeArg(MwccPCodeArg.Kind.GPR, reg=reg))
                elif kind == 1:  # FPR
                    reg = parse_u16(arg_mem, arg_offset + 2)
                    args.append(MwccPCodeArg(MwccPCodeArg.Kind.FPR, reg=reg))
                elif kind == 2:  # SPR
                    reg = parse_u16(arg_mem, arg_offset + 2)
                    args.append(MwccPCodeArg(MwccPCodeArg.Kind.SPR, reg=reg))
                elif kind == 3:  # crfield
                    reg = parse_u16(arg_mem, arg_offset + 2)
                    args.append(MwccPCodeArg(MwccPCodeArg.Kind.CRFIELD, reg=reg))
                elif kind == 4:  # immediate
                    imm = parse_s32(arg_mem, arg_offset + 2)
                    obj_addr = parse_u32(arg_mem, arg_offset + 6)
                    args.append(
                        MwccPCodeArg(
                            MwccPCodeArg.Kind.IMMEDIATE, imm=imm, obj_addr=obj_addr
                        )
                    )
                elif kind == 5:  # memory
                    imm = parse_s32(arg_mem, arg_offset + 2)
                    obj_addr = parse_u32(arg_mem, arg_offset + 6)
                    args.append(
                        MwccPCodeArg(
                            MwccPCodeArg.Kind.MEMORY, imm=imm, obj_addr=obj_addr
                        )
                    )
                elif kind == 6:  # label
                    label_addr = parse_u32(arg_mem, arg_offset + 2)
                    label = MwccPCodeLabel.load(label_addr)
                    block = MwccBlock.load(label.block_addr)
                    block_index = block.index
                    args.append(
                        MwccPCodeArg(MwccPCodeArg.Kind.LABEL, block_index=block_index)
                    )
                elif kind == 9:  # vector register
                    reg = parse_u16(arg_mem, arg_offset + 2)
                    args.append(MwccPCodeArg(MwccPCodeArg.Kind.VR, reg=reg))
                elif kind == 10:  # placeholder
                    args.append(MwccPCodeArg(MwccPCodeArg.Kind.PLACEHOLDER))
                else:
                    raise ValueError(f"Unknown operand kind: {kind}")

            return cls(
                next_addr=parse_u32(mem, 0x0),
                line=None,
                op=parse_s16(mem, 0x14),
                args=args,
            )
        elif MWCC_VERSION.name == "GC/2.6":
            mem = gdb.selected_inferior().read_memory(addr, 0x24)
            line = parse_s32(mem, 0x1C)
            if line == -1:
                line = None

            arg_count = parse_s16(mem, 0x22)
            if arg_count > 0:
                arg_mem = gdb.selected_inferior().read_memory(
                    addr + 0x24, arg_count * 0xC
                )

            args = []
            for i in range(arg_count):
                arg_offset = i * 0xC
                kind = parse_u8(arg_mem, arg_offset)
                if kind == 0:  # Register
                    regclass = parse_u8(arg_mem, arg_offset + 1)
                    reg = parse_u16(arg_mem, arg_offset + 4)
                    if regclass == 0:  # SPR
                        kind = MwccPCodeArg.Kind.SPR
                    elif regclass == 1:  # crfield
                        kind = MwccPCodeArg.Kind.CRFIELD
                    elif regclass == 2:  # vector register
                        kind = MwccPCodeArg.Kind.VR
                    elif regclass == 3:  # FPR
                        kind = MwccPCodeArg.Kind.FPR
                    elif regclass == 4:  # GPR
                        kind = MwccPCodeArg.Kind.GPR
                    else:
                        raise ValueError(f"Unknown register class: {regclass}")
                    args.append(MwccPCodeArg(kind, reg=reg))
                elif kind == 1:  # sysreg
                    reg = parse_u16(arg_mem, arg_offset + 4)
                    args.append(MwccPCodeArg(MwccPCodeArg.Kind.SPR, reg=reg))
                elif kind == 2:  # immediate
                    imm = parse_s32(arg_mem, arg_offset + 2)
                    obj_addr = parse_u32(arg_mem, arg_offset + 6)
                    args.append(
                        MwccPCodeArg(
                            MwccPCodeArg.Kind.IMMEDIATE, imm=imm, obj_addr=obj_addr
                        )
                    )
                elif kind == 3:  # memory
                    imm = parse_s32(arg_mem, arg_offset + 2)
                    obj_addr = parse_u32(arg_mem, arg_offset + 6)
                    args.append(
                        MwccPCodeArg(
                            MwccPCodeArg.Kind.MEMORY, imm=imm, obj_addr=obj_addr
                        )
                    )
                elif kind == 4:  # label
                    label_addr = parse_u32(arg_mem, arg_offset + 2)
                    label = MwccPCodeLabel.load(label_addr)
                    block = MwccBlock.load(label.block_addr)
                    block_index = block.index
                    args.append(
                        MwccPCodeArg(MwccPCodeArg.Kind.LABEL, block_index=block_index)
                    )
                elif kind == 6:  # placeholder
                    args.append(MwccPCodeArg(MwccPCodeArg.Kind.PLACEHOLDER))
                else:
                    raise ValueError(f"Unknown operand kind: {kind}")

            return cls(
                next_addr=parse_u32(mem, 0x0),
                line=line,
                op=parse_s16(mem, 0x20),
                args=args,
            )
        else:
            raise ValueError(f"Unsupported MWCC version: {MWCC_VERSION.name}")


@dataclass
class MwccBlock:
    next_addr: int
    prev_addr: int
    label_addr: int
    predecessors_addr: int
    successors_addr: int
    instr_addr: int
    index: int
    line: Optional[int]
    loop_weight: int
    pcode_count: int
    flags: int  # TODO: parse flags

    @classmethod
    def load(cls, addr: int) -> MwccBlock:
        if MWCC_VERSION.name == "GC/1.1":
            mem = gdb.selected_inferior().read_memory(addr, 0x30)
            line = parse_s32(mem, 0x20)
            if line == -1:
                line = None
            return cls(
                next_addr=parse_u32(mem, 0x0),
                prev_addr=parse_u32(mem, 0x4),
                label_addr=parse_u32(mem, 0x8),
                predecessors_addr=parse_u32(mem, 0xC),
                successors_addr=parse_u32(mem, 0x10),
                instr_addr=parse_u32(mem, 0x14),
                index=parse_s32(mem, 0x1C),
                line=line,
                loop_weight=parse_s32(mem, 0x28),
                pcode_count=parse_s16(mem, 0x2C),
                flags=parse_u16(mem, 0x2E),
            )
        elif MWCC_VERSION.name == "GC/2.6":
            mem = gdb.selected_inferior().read_memory(addr, 0x2C)
            return cls(
                next_addr=parse_u32(mem, 0x0),
                prev_addr=parse_u32(mem, 0x4),
                label_addr=parse_u32(mem, 0x8),
                predecessors_addr=parse_u32(mem, 0xC),
                successors_addr=parse_u32(mem, 0x10),
                instr_addr=parse_u32(mem, 0x14),
                index=parse_s32(mem, 0x1C),
                line=None,
                loop_weight=parse_s32(mem, 0x24),
                pcode_count=parse_s16(mem, 0x28),
                flags=parse_u16(mem, 0x2A),
            )
        else:
            raise ValueError(f"Unsupported MWCC version: {MWCC_VERSION.name}")


@dataclass
class MwccPCodeLabel:
    next_addr: int
    block_addr: int
    index: int

    @classmethod
    def load(cls, addr: int) -> MwccPCodeLabel:
        mem = gdb.selected_inferior().read_memory(addr, 0xC)
        return cls(
            next_addr=parse_u32(mem, 0x0),
            block_addr=parse_u32(mem, 0x4),
            index=parse_u16(mem, 0xA),
        )


@dataclass
class MwccIGNode:
    class Flag(Enum):
        fSpilled = 0
        fCoalesced = 1
        fCoalescedInto = 2
        fPairHigh = 3
        fPairLow = 4
        fRematerialized = 5

    next_addr: int
    virtual_reg: int
    physical_reg: int
    cost: int
    flags: list[Flag]
    obj_name: Optional[str]
    neighbors: list[int]

    @classmethod
    def load(cls, addr: int) -> MwccIGNode:
        if MWCC_VERSION.name == "GC/1.1":
            mem = gdb.selected_inferior().read_memory(addr, 0x16)
            next_addr = parse_u32(mem, 0x0)
            obj_addr = parse_u32(mem, 0x4)
            cost = parse_s32(mem, 0x8)
            virtual_reg = parse_s16(mem, 0xC)
            physical_reg = parse_s16(mem, 0x10)
            flags_value = parse_u8(mem, 0x12)
            num_neighbors = parse_s16(mem, 0x14)
            neighbors_addr = addr + 0x16
        elif MWCC_VERSION.name == "GC/2.6":
            mem = gdb.selected_inferior().read_memory(addr, 0x1A)
            next_addr = parse_u32(mem, 0x0)
            obj_addr = parse_u32(mem, 0x4)
            cost = parse_s32(mem, 0xC)
            virtual_reg = parse_s16(mem, 0x10)
            physical_reg = parse_s16(mem, 0x14)
            flags_value = parse_u8(mem, 0x16)
            num_neighbors = parse_s16(mem, 0x18)
            neighbors_addr = addr + 0x1A
        else:
            raise ValueError(f"Unsupported MWCC version: {MWCC_VERSION.name}")

        neighbors = []
        if num_neighbors > 0:
            mem = gdb.selected_inferior().read_memory(
                neighbors_addr, num_neighbors * 0x2
            )
            for i in range(num_neighbors):
                neighbor = parse_s16(mem, i * 0x2)
                neighbors.append(neighbor)

        flags = []
        if flags_value & 0x01:
            flags.append(MwccIGNode.Flag.fSpilled)
        if flags_value & 0x04:
            flags.append(MwccIGNode.Flag.fCoalesced)
        if flags_value & 0x08:
            flags.append(MwccIGNode.Flag.fCoalescedInto)
        if flags_value & 0x10:
            flags.append(MwccIGNode.Flag.fPairHigh)
        if flags_value & 0x20:
            flags.append(MwccIGNode.Flag.fPairLow)

        if obj_addr != 0:
            obj = MwccObject.load(obj_addr)
            obj_name = obj.name
        else:
            obj_name = None

        return cls(
            next_addr=next_addr,
            virtual_reg=virtual_reg,
            physical_reg=physical_reg,
            cost=cost,
            flags=flags,
            obj_name=obj_name,
            neighbors=neighbors,
        )


MWCC_OPCODE_INFO: list[MwccOpcodeInfo] = []


def load_opcode_info():
    if MWCC_OPCODE_INFO:
        return

    if MWCC_VERSION.name == "GC/1.1":
        size = 0x10
    elif MWCC_VERSION.name == "GC/2.6":
        size = 0x12
    else:
        raise ValueError(f"Unsupported MWCC version: {MWCC_VERSION.name}")

    # Load opcode info from the binary
    mem = gdb.selected_inferior().read_memory(
        MWCC_VERSION.opcodeinfo_addr, MWCC_VERSION.opcodeinfo_size * size
    )
    for i in range(MWCC_VERSION.opcodeinfo_size):
        offset = i * size
        mnemonic = read_string(parse_u32(mem, offset))
        format_str = read_string(parse_u32(mem, offset + 4))
        MWCC_OPCODE_INFO.append(
            MwccOpcodeInfo(mnemonic=mnemonic, format_str=format_str)
        )


def format_operands(instr) -> str:
    out = ""
    arg_count = len(instr.args)
    for i in range(min(arg_count, 6)):
        arg = instr.args[i]

        if arg.kind == MwccPCodeArg.Kind.PLACEHOLDER:
            continue

        if i != 0:
            out += ","

        if arg.kind == MwccPCodeArg.Kind.GPR:
            out += f"r{arg.reg}"
        elif arg.kind == MwccPCodeArg.Kind.FPR:
            out += f"f{arg.reg}"
        elif arg.kind == MwccPCodeArg.Kind.SPR:
            if arg.reg == 0:
                out += "zero"
            elif arg.reg == 1:
                out += "ctr"
            elif arg.reg == 2:
                out += "lr"
            else:
                out += f"spr{arg.reg}"
        elif arg.kind == MwccPCodeArg.Kind.CRFIELD:
            out += f"cr{arg.reg}"
        elif arg.kind == MwccPCodeArg.Kind.VR:
            out += f"vr{arg.reg}"
        elif arg.kind in (MwccPCodeArg.Kind.IMMEDIATE, MwccPCodeArg.Kind.MEMORY):
            if arg.imm < 0:
                out += f"-0x{-arg.imm:x}"
            elif arg.imm < 10:
                out += str(arg.imm)
            else:
                out += f"0x{arg.imm:x}"
            if arg.obj_addr != 0:
                obj = MwccObject.load(arg.obj_addr)
                out += f"({obj.name})"
        elif arg.kind == MwccPCodeArg.Kind.LABEL:
            out += f"B{arg.block_index}"
        else:
            raise ValueError(f"Unknown operand kind: {arg.kind}")

    if arg_count > 6:
        out += ",..."

    return out


def print_instruction(f, instr: MwccPcode, block_line_number: Optional[int]):
    operands = format_operands(instr)
    # TODO: show "record" bit as dot
    mnemonic = MWCC_OPCODE_INFO[instr.op].mnemonic.lower()

    line_number = instr.line or block_line_number
    line_number_str = f"{line_number:>5}" if line_number else "     "
    print(f" {line_number_str}  {mnemonic:<8} {operands}", file=f)


def print_block(f, block: MwccBlock):
    print(
        f":{{{block.flags:04x}}}::::::::::::::::::::::::::::::::::::::::LOOPWEIGHT={block.loop_weight}",
        file=f,
    )
    print(f"B{block.index}: ", end="", file=f)
    print("Successors = { ", end="", file=f)
    link_addr = block.successors_addr
    while link_addr != 0:
        link_block = MwccBlock.load(read_u32(link_addr + 0x4))
        print(f"B{link_block.index} ", end="", file=f)
        link_addr = read_u32(link_addr + 0x0)
    print("}  Predecessors = { ", end="", file=f)
    link_addr = block.predecessors_addr
    while link_addr != 0:
        link_block = MwccBlock.load(read_u32(link_addr + 0x4))
        print(f"B{link_block.index} ", end="", file=f)
        link_addr = read_u32(link_addr + 0x0)
    print("}  Labels = { ", end="", file=f)
    label_addr = block.label_addr
    while label_addr != 0:
        label = MwccPCodeLabel.load(label_addr)
        print(f"L{label.index} ", end="", file=f)
        label_addr = label.next_addr
    print("}", file=f)

    instr_addr = block.instr_addr
    while instr_addr != 0:
        instr = MwccPcode.load(instr_addr)
        print_instruction(f, instr, block.line)
        instr_addr = instr.next_addr

    print("", file=f)


def print_pcode(output_file: str):
    load_opcode_info()
    output_path = Path(OUTPUT_DIR) / output_file
    print(f"Dumping PCode to {output_path}")
    with open(Path(OUTPUT_DIR) / output_file, "w") as f:
        block_addr = read_u32(MWCC_VERSION.pcbasicblocks_addr)
        while block_addr != 0:
            block = MwccBlock.load(block_addr)
            print_block(f, block)
            block_addr = block.next_addr


GPR_PASS = 0
FPR_PASS = 0


def print_regalloc():
    global GPR_PASS, FPR_PASS

    assigned_nodes_addr = None
    pass_name = ""

    # Find out which register class we are processing (GPR or FPR)
    sp = int(gdb.parse_and_eval("$esp"))
    if MWCC_VERSION.name == "GC/1.1":
        # For GC/1.1, coloring class is first argument, assigned variables is second argument
        coloring_class = read_u32(sp + 0x4)
        assigned_nodes_addr = read_u32(sp + 0x8)
        if coloring_class == 0:
            pass_name = "gpr"
        elif coloring_class == 1:
            pass_name = "fpr"
        else:
            raise ValueError(f"Unexpected coloring class: {coloring_class}")
    else:
        # For other versions, coloring class is in a global variable, assigned variables is first argument
        coloring_class = read_u8(MWCC_VERSION.coloring_class_addr)
        assigned_nodes_addr = read_u32(sp + 0x4)
        if coloring_class == 4:
            pass_name = "gpr"
        elif coloring_class == 3:
            pass_name = "fpr"
        else:
            raise ValueError(f"Unexpected coloring class: {coloring_class}")

    if pass_name == "gpr":
        GPR_PASS += 1
        pass_number = GPR_PASS
        prefix = "r"
        num_regs = read_s16(MWCC_VERSION.used_virtual_registers_gpr_addr)
    elif pass_name == "fpr":
        FPR_PASS += 1
        pass_number = FPR_PASS
        prefix = "f"
        num_regs = read_s16(MWCC_VERSION.used_virtual_registers_fpr_addr)

    # Read all interference graph nodes
    graph_addr = read_u32(MWCC_VERSION.interferencegraph_addr)
    nodes = OrderedDict()
    if num_regs > 0:
        mem = gdb.selected_inferior().read_memory(graph_addr, num_regs * 0x4)
        for i in range(32, num_regs):
            node_addr = parse_u32(mem, i * 0x4)
            if node_addr == 0:
                continue
            node = MwccIGNode.load(node_addr)
            nodes[node_addr] = node

    output_path = Path(OUTPUT_DIR) / f"regalloc-{pass_name}-pass-{pass_number}-all.txt"
    print(f"Dumping all registers to {output_path}")
    with open(output_path, "w") as f:
        for node in nodes.values():
            if node.physical_reg == -1:
                physical_reg = "fSpilled"
            else:
                physical_reg = f"{prefix}{node.physical_reg}"
            print(
                f"{prefix}{node.virtual_reg} -> {physical_reg}",
                file=f,
                end="",
            )
            if node.obj_name:
                print(f" {node.obj_name}", file=f, end="")
            print("", file=f)
            print(f"  flags:", file=f, end="")
            for flag in node.flags:
                print(f" {flag.name}", file=f, end="")
            print("", file=f)
            print(f"  cost: {node.cost}", file=f)
            if node.neighbors:
                neighbors_str = " ".join(f"{prefix}{i}" for i in sorted(node.neighbors))
                print(
                    f"  neighbors: {len(node.neighbors)} ({neighbors_str})",
                    file=f,
                )
            else:
                print("  neighbors: 0", file=f)

    output_path = (
        Path(OUTPUT_DIR) / f"regalloc-{pass_name}-pass-{pass_number}-assigned.txt"
    )
    print(f"Dumping assigned registers to {output_path}")
    with open(output_path, "w") as f:
        # TODO: print free registers
        assigned_nodes = []
        while assigned_nodes_addr != 0:
            assigned_nodes.append(nodes[assigned_nodes_addr])
            assigned_nodes_addr = nodes[assigned_nodes_addr].next_addr

        for i, node in enumerate(assigned_nodes):
            prev_neighbors = set(node.neighbors)
            for j in range(i, len(assigned_nodes)):
                prev_neighbors.discard(assigned_nodes[j].virtual_reg)
            if node.physical_reg == -1:
                physical_reg = "fSpilled"
            else:
                physical_reg = f"{prefix}{node.physical_reg}"
            print(
                f"{prefix}{node.virtual_reg} -> {physical_reg}",
                file=f,
                end="",
            )
            if node.obj_name:
                print(f" {node.obj_name}", file=f, end="")
            print("", file=f)
            print(f"  flags:", file=f, end="")
            for flag in node.flags:
                print(f" {flag.name}", file=f, end="")
            print("", file=f)
            print(f"  cost: {node.cost}", file=f)
            print(
                f"  adjusted cost: {node.cost / len(prev_neighbors) if prev_neighbors else 0:.2f}",
                file=f,
            )
            if prev_neighbors:
                prev_neighbors_str = " ".join(f"{prefix}{i}" for i in sorted(prev_neighbors))
                print(
                    f"  previous neighbors: {len(prev_neighbors)} ({prev_neighbors_str})",
                    file=f,
                )
            else:
                print("  previous neighbors: 0", file=f)
            if node.neighbors:
                neighbors_str = " ".join(f"{prefix}{i}" for i in sorted(node.neighbors))
                print(
                    f"  neighbors: {len(node.neighbors)} ({neighbors_str})",
                    file=f,
                )
            else:
                print("  neighbors: 0", file=f)


def print_variables():
    # TODO: implement
    pass
    # output_file = "variables.txt"
    # output_path = Path(OUTPUT_DIR) / output_file
    # print(f"Dumping variables to {output_path}")
    # with open(output_path, "w") as f:
    #     pass


def find_current_function() -> MwccObject:
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
        current_function_addr = read_u32(MWCC_VERSION.gfunction_addr)
    return MwccObject.load(current_function_addr, load_linkname=True)


def run_compiler():
    gdb.execute("set python print-stack full")

    # Connect to the remote GDB server
    gdb.execute("set architecture i386")
    gdb.execute("set osabi none")
    gdb.execute("target remote localhost:9001")

    init_mwcc_version()

    # Find the function to analyze
    gdb.execute(f"break *{MWCC_VERSION.codegen_start_addr:#x}")

    while True:
        gdb.execute("continue")
        func = find_current_function()
        if func.linkname == FUNCTION_NAME:
            break
        print(f"Skipping function {func.linkname}")

    print(f"Found function {func.linkname}")
    print()

    # Set breakpoints
    gdb.execute(f"break *{MWCC_VERSION.codegen_end_addr:#x}")
    gdb.execute(f"break *{MWCC_VERSION.regalloc_breakpoint_addr:#x}")
    for addr in MWCC_VERSION.pcode_breakpoints:
        gdb.execute(f"break *{addr:#x}")

    # Loop through breakpoints
    while True:
        gdb.execute("continue")
        current_addr = int(gdb.parse_and_eval("$pc"))

        if current_addr in MWCC_VERSION.pcode_breakpoints:
            output_file = MWCC_VERSION.pcode_breakpoints[current_addr]
            print_pcode(output_file)

        if current_addr == MWCC_VERSION.regalloc_breakpoint_addr:
            print_regalloc()

        if current_addr == MWCC_VERSION.codegen_end_addr:
            print_variables()
            gdb.execute("quit")


def start_gdb():
    # TODO: Run ninja to get compiler path and arguments?
    parser = argparse.ArgumentParser(
        description="Dump MWCC compiler internals while compiling a file."
    )
    parser.add_argument(
        "--args",
        "-a",
        required=True,
        help="compiler command line (in quotes), starting with mwcceppc.exe",
    )
    parser.add_argument(
        "--emulator",
        "-e",
        default="retrowin32",
        help="path to retrowin32 (default: retrowin32)",
    )
    parser.add_argument(
        "--gdb",
        "-g",
        default="gdb",
        help="path to x86 gdb (default: gdb)",
    )
    parser.add_argument(
        "FUNCTION_NAME", help="the (mangled) name of the function to analyze"
    )
    parser.add_argument(
        "OUTPUT_DIR",
        nargs="?",
        help="output directory for debug files (default: debug-FUNCTION_NAME)",
    )

    args = parser.parse_args()
    function_name = args.FUNCTION_NAME
    output_dir = args.OUTPUT_DIR or f"debug-{function_name}"

    os.makedirs(output_dir, exist_ok=True)

    emulator_command = [
        args.emulator,
        "--gdb-stub",
        *shlex.split(args.args),
    ]
    print(f"Emulator command: {shlex.join(emulator_command)}", file=sys.stderr)

    gdb_command = [
        args.gdb,
        "-batch",
        "-nx",
        "-ex",
        f"py FUNCTION_NAME = \"{function_name}\"; OUTPUT_DIR = \"{output_dir}\"",
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
