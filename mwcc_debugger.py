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
from typing import Optional, Tuple

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


def parse_f32(mem: memoryview, offset: int) -> float:
    return struct.unpack("<f", mem[offset : offset + 4])[0]


def parse_f64(mem: memoryview, offset: int) -> float:
    return struct.unpack("<d", mem[offset : offset + 8])[0]


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
    # TODO: We should probably use raw bytes and not a Unicode string
    return gdb.Value(addr).cast(gdb.lookup_type("char").pointer()).string("latin-1")


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
    # Address of nodenames array in DumpExpression()
    nodenames_addr: int
    # Number of entries in nodenames array
    nodenames_size: int
    # Breakpoint address for call to COpt_Optimizer()
    copt_optimizer_call_addr: int
    # Address of opcode info table
    opcodeinfo_addr: int
    # Number of entries in the opcode info table
    opcodeinfo_size: int
    # Address of pcbasicblocks
    pcbasicblocks_addr: int
    # Breakpoint addresses for dumping pcode, with the names of backend passes
    # Many pass names set a flag indicating that the pass actually did anything. If so,
    # this breakpoint should be just after that flag is checked.
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
            nodenames_addr=0x561CB4,
            nodenames_size=75,
            copt_optimizer_call_addr=0x43538E,
            opcodeinfo_addr=0x5664B0,
            opcodeinfo_size=468,
            pcbasicblocks_addr=0x588474,
            pcode_breakpoints={
                0x435AEF: "initial-code",
                # -O2
                0x4C4B96: "after-common-subexpression-elimination",
                0x4C4BC9: "after-copy-propagation",
                0x4C4BF9: "after-add-propagation",
                # -O3
                0x4C5036: "after-common-subexpression-elimination",
                0x4C5069: "after-copy-propagation",
                0x4C50A3: "after-add-propagation",
                0x4C5106: "after-loop-code-motion",
                0x4C5136: "after-loop-strength-reduction",
                0x4C513D: "after-copy-propagation",
                0x4C516E: "after-loop-transforms",
                0x4C5175: "after-copy-propagation",
                0x4C517B: "after-add-propagation",
                0x4C51B7: "after-copy-propagation",
                0x4C51EB: "after-constant-propagation",
                0x4C521B: "after-load-deletion",
                0x4C524B: "after-add-propagation",
                0x4C527E: "after-common-subexpression-elimination",
                0x4C5285: "after-copy-propagation",
                # -O4
                0x4C4C56: "after-common-subexpression-elimination",
                0x4C4C89: "after-copy-propagation",
                0x4C4CC3: "after-add-propagation",
                0x4C4D26: "after-loop-code-motion",
                0x4C4D56: "after-loop-strength-reduction",
                0x4C4D5D: "after-copy-propagation",
                0x4C4D8E: "after-loop-transforms",
                0x4C4D95: "after-copy-propagation",
                0x4C4D9B: "after-add-propagation",
                0x4C4DD7: "after-copy-propagation",
                0x4C4E0B: "after-constant-propagation",
                0x4C4E3B: "after-load-deletion",
                0x4C4E6D: "after-copy-propagation",
                0x4C4E7C: "after-add-propagation",
                0x4C4EB5: "after-array-register-transforms",
                0x4C4EE5: "after-constant-propagation",
                0x4C4EEC: "after-copy-propagation",
                0x4C4F1D: "after-common-subexpression-elimination",
                0x4C4F27: "after-copy-propagation",
                0x4C4FBB: "after-code-motion",
                0x4C4FEE: "after-common-subexpression-elimination",
                0x4C4FF5: "after-copy-propagation",
                # Shared passes
                0x435B6E: "after-scheduling",
                0x435BCA: "after-peephole-forward",
                0x435BEE: "before-regalloc",
                0x435BF3: "after-regalloc",
                0x435CA8: "after-prologue-epilogue",
                0x435D10: "after-peephole",
                0x435D65: "after-scheduling",
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
            nodenames_addr=0x5BC980,
            nodenames_size=77,
            copt_optimizer_call_addr=0x43356D,
            opcodeinfo_addr=0x5C0FA8,
            opcodeinfo_size=471,
            pcbasicblocks_addr=0x5EA748,
            pcode_breakpoints={
                0x433CF5: "initial-code",
                # -O2
                0x50054E: "after-common-subexpression-elimination",
                0x500576: "after-copy-propagation",
                0x50057E: "after-add-propagation",
                # -O3
                0x500981: "after-peephole-forward",
                0x5009B4: "after-common-subexpression-elimination",
                0x5009DC: "after-copy-propagation",
                0x5009EE: "after-add-propagation",
                0x500A1C: "after-loop-code-motion",
                0x500A5E: "after-loop-strength-reduction",
                0x500A86: "after-copy-propagation",
                0x500A96: "after-loop-transforms",
                0x500ABE: "after-copy-propagation",
                0x500AC1: "after-add-propagation",
                0x500AE3: "after-copy-propagation",
                0x500B11: "after-constant-propagation",
                0x500B37: "after-load-deletion",
                0x500B3E: "after-add-propagation",
                0x500B6B: "after-peephole-forward",
                0x500B9E: "after-common-subexpression-elimination",
                0x500BC6: "after-copy-propagation",
                # -O4
                0x5005D0: "after-peephole-forward",
                0x500604: "after-common-subexpression-elimination",
                0x50062C: "after-copy-propagation",
                0x50063E: "after-add-propagation",
                0x50066C: "after-loop-code-motion",
                0x5006AE: "after-loop-strength-reduction",
                0x5006D6: "after-copy-propagation",
                0x5006F0: "after-loop-transforms",
                0x500718: "after-copy-propagation",
                0x500720: "after-add-propagation",
                0x500732: "after-copy-propagation",
                0x500746: "after-constant-propagation",
                0x50076C: "after-load-deletion",
                0x50077E: "after-copy-propagation",
                0x500786: "after-add-propagation",
                0x50079E: "after-array-register-transforms",
                0x5007C3: "after-constant-propagation",
                0x5007F4: "after-copy-propagation",
                0x500822: "after-peephole-forward",
                0x500855: "after-common-subexpression-elimination",
                0x50087D: "after-copy-propagation",
                0x5008F0: "after-code-motion",
                0x500923: "after-common-subexpression-elimination",
                0x50094B: "after-copy-propagation",
                # Shared passes
                0x433E0C: "after-scheduling",
                0x433E79: "after-peephole-forward",
                0x433EA6: "before-regalloc",
                0x433EAB: "after-regalloc",
                0x433EFD: "after-common-subexpression-elimination",
                0x433F8C: "after-prologue-epilogue",
                0x434006: "after-peephole",
                0x434063: "after-scheduling.txt",
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


TYPE_CACHE: dict[str, MwccType] = {}


@dataclass
class MwccType:
    type_type: int
    size: int
    integral: Optional[int] = None  # For TYPEINT, TYPEFLOAT
    name: Optional[str] = None
    target: Optional[MwccType] = None
    offset: Optional[int] = None  # For TYPEBITFIELD
    bitlength: Optional[int] = None  # For TYPEBITFIELD
    scope: Optional[MwccType] = None  # For TYPEMEMBERPOINTER
    # TODO
    pass

    @classmethod
    def load(cls, addr: int) -> MwccType:
        if addr in TYPE_CACHE:
            return TYPE_CACHE[addr]

        mem = gdb.selected_inferior().read_memory(addr, 0x16)
        type_type = parse_s8(mem, 0x0)
        size = parse_u32(mem, 0x2)

        if type_type in (-1, 0, 8):  # TYPEILLEGAL, TYPEVOID, TYPELABEL
            rtype = cls(
                type_type=type_type,
                size=size,
            )
        elif type_type in (1, 2):  # TYPEINT, TYPEFLOAT
            integral = parse_u8(mem, 0x6)
            rtype = cls(
                type_type=type_type,
                size=size,
                integral=integral,
            )
        elif type_type in (3, 4, 5):  # TYPEENUM, TYPESTRUCT, TYPECLASS
            if type_type == 3:  # TYPEENUM
                name_addr = parse_u32(mem, 0x12)
            elif type_type == 4:  # TYPESTRUCT
                name_addr = parse_u32(mem, 0x6)
            elif type_type == 5:  # TYPECLASS
                name_addr = parse_u32(mem, 0xA)
            if name_addr == 0:
                name = None
            else:
                name = read_string(name_addr + 0xA)
            rtype = cls(
                type_type=type_type,
                size=size,
                name=name,
            )
        elif type_type == 6:  # TYPEFUNC
            target = MwccType.load(parse_u32(mem, 0xE))
            rtype = cls(
                type_type=type_type,
                size=size,
                target=target,
            )
        elif type_type == 7:  # TYPEBITFIELD
            target = MwccType.load(parse_u32(mem, 0x6))
            offset = parse_s8(mem, 0xA)
            bitlength = parse_s8(mem, 0xB)
            rtype = cls(
                type_type=type_type,
                size=size,
                target=target,
                offset=offset,
                bitlength=bitlength,
            )
        elif type_type == 10:  # TYPEMEMBERPOINTER
            scope = MwccType.load(parse_u32(mem, 0xA))
            target = MwccType.load(parse_u32(mem, 0x6))
            rtype = cls(
                type_type=type_type,
                size=size,
                scope=scope,
                target=target,
            )
        elif type_type in (11, 12):  # TYPEPOINTER, TYPEARRAY
            target = MwccType.load(parse_u32(mem, 0x6))
            rtype = cls(
                type_type=type_type,
                size=size,
                target=target,
            )
        else:
            raise ValueError(f"Unknown type: {type_type}")

        TYPE_CACHE[addr] = rtype
        return rtype


INTEGRAL_NAMES: list[str] = [
    "bool",
    "char",
    "signed char",
    "unsigned char",
    "wchar_t",
    "short",
    "unsigned short",
    "int",
    "unsigned int",
    "long",
    "unsigned long",
    "long long",
    "unsigned long long",
    "float",
    "short double",
    "double",
    "long double",
]


def format_type(rtype: MwccType) -> str:
    type_type = rtype.type_type
    if type_type == -1:  # TYPEILLEGAL
        return "illegal"
    elif type_type == 0:  # TYPEVOID
        return "void"
    elif type_type in (1, 2):  # TYPEINT, TYPEFLOAT
        return INTEGRAL_NAMES[rtype.integral]
    elif type_type == 3:  # TYPEENUM
        name = rtype.name if rtype.name else "<anonymous>"
        return f"enum {name}"
    elif type_type == 4:  # TYPESTRUCT
        name = rtype.name if rtype.name else "<anonymous>"
        return f"struct {name}"
    elif type_type == 5:  # TYPECLASS
        name = rtype.name if rtype.name else "<anonymous>"
        return f"class {name}"
    elif type_type == 6:  # TYPEFUNC
        return f"freturns({format_type(rtype.target)})"
    elif type_type == 7:  # TYPEBITFIELD
        return (
            f"bitfield({format_type(rtype.target)}){{{rtype.offset}:{rtype.bitlength}}}"
        )
    elif type_type == 8:  # TYPELABEL
        return "label"
    elif type_type == 10:  # TYPEMEMBERPOINTER
        return f"memberpointer({format_type(rtype.scope)},{format_type(rtype.target)})"
    elif type_type == 11:  # TYPEPOINTER
        return f"pointer({format_type(rtype.target)})"
    elif type_type == 12:  # TYPEARRAY
        return f"array({format_type(rtype.target)})"
    else:
        raise ValueError(f"Unknown type: {type_type}")


NODE_NAMES: list[str] = []


def load_node_names():
    if NODE_NAMES:
        return

    mem = gdb.selected_inferior().read_memory(
        MWCC_VERSION.nodenames_addr, MWCC_VERSION.nodenames_size * 0x4
    )
    for i in range(MWCC_VERSION.nodenames_size):
        str_addr = parse_u32(mem, i * 0x4)
        NODE_NAMES.append(read_string(str_addr))


@dataclass
class MwccENode:
    expr_type: str
    rtype: MwccType
    # Child expressions
    children: list[MwccENode]
    # Constants
    int_const: Optional[int] = None  # For EINTCONST
    float_const: Optional[float] = None  # For EFLOATCONST
    string_const: Optional[str] = None  # For ESTRINGCONST
    name: Optional[str] = None  # For EOBJREF, ELABEL

    @classmethod
    def load(cls, addr: int) -> MwccENode:
        mem = gdb.selected_inferior().read_memory(addr, 0x1A)
        expr_type = NODE_NAMES[parse_u8(mem, 0x0)]
        rtype = MwccType.load(parse_u32(mem, 0x6))
        if MWCC_VERSION.name == "GC/1.1":
            data_offset = 0xA
        elif MWCC_VERSION.name == "GC/2.6":
            data_offset = 0xE
        else:
            raise ValueError(f"Unsupported MWCC version: {MWCC_VERSION.name}")
        if expr_type == "EINTCONST":
            hi = parse_s32(mem, data_offset + 0)
            lo = parse_u32(mem, data_offset + 4)
            int_const = (hi << 32) | lo
            return cls(
                expr_type=expr_type,
                rtype=rtype,
                children=[],
                int_const=int_const,
            )
        elif expr_type == "EFLOATCONST":
            float_const = parse_f64(mem, data_offset)
            return cls(
                expr_type=expr_type,
                rtype=rtype,
                children=[],
                float_const=float_const,
            )
        elif expr_type == "ESTRINGCONST":
            string_const = read_string(parse_u32(mem, data_offset + 4))
            return cls(
                expr_type=expr_type,
                rtype=rtype,
                children=[],
                string_const=string_const,
            )
        elif expr_type == "EOBJREF":
            obj = MwccObject.load(parse_u32(mem, data_offset))
            name = obj.name
            return cls(
                expr_type=expr_type,
                rtype=rtype,
                children=[],
                name=name,
            )
        elif expr_type == "ELABEL":
            label_addr = parse_u32(mem, data_offset)
            label_name = read_u32(label_addr + 0x8)
            label_name = read_string(label_name + 0xA)
            return cls(
                expr_type=expr_type,
                rtype=rtype,
                children=children,
            )
        elif expr_type in (
            "EPOSTINC",
            "EPOSTDEC",
            "EPREINC",
            "EPREDEC",
            "EINDIRECT",
            "EMONMIN",
            "EBINNOT",
            "ELOGNOT",
            "EFORCELOAD",
            "ETYPCON",
            "EBITFIELD",
        ):
            # Unary operators
            expr = cls.load(parse_u32(mem, data_offset))
            return cls(
                expr_type=expr_type,
                rtype=rtype,
                children=[expr],
            )
        elif expr_type in (
            "EMUL",
            "EMULV",
            "EDIV",
            "EMODULO",
            "EADDV",
            "ESUBV",
            "EADD",
            "ESUB",
            "ESHL",
            "ESHR",
            "ELESS",
            "EGREATER",
            "ELESSEQU",
            "EGREATEREQU",
            "EEQU",
            "ENOTEQU",
            "EAND",
            "EXOR",
            "EOR",
            "ELAND",
            "ELOR",
            "EASS",
            "EMULASS",
            "EDIVASS",
            "EMODASS",
            "EADDASS",
            "ESUBASS",
            "ESHLASS",
            "ESHRASS",
            "EANDASS",
            "EXORASS",
            "EORASS",
            "EBCLR",
            "EBSET",
            "ECOMMA",
            "EPMODULO",
            "EROTL",
            "EROTR",
            "EBTST",
            # TODO: ENULLCHECK has a unique id too
            "ENULLCHECK",
        ):
            # Binary operators
            left = cls.load(parse_u32(mem, data_offset))
            right = cls.load(parse_u32(mem, data_offset + 4))
            return cls(
                expr_type=expr_type,
                rtype=rtype,
                children=[left, right],
            )
        elif expr_type in ("ECOND", "ECONDASS"):
            # Ternary operators
            cond = cls.load(parse_u32(mem, data_offset))
            expr1 = cls.load(parse_u32(mem, data_offset + 4))
            expr2 = cls.load(parse_u32(mem, data_offset + 8))
            return cls(
                expr_type=expr_type,
                rtype=rtype,
                children=[cond, expr1, expr2],
            )
        elif expr_type in ("EFUNCCALL", "EFUNCCALLP"):
            # Function call
            funcref = cls.load(parse_u32(mem, data_offset))
            args_addr = parse_u32(mem, data_offset + 4)
            children = [funcref]
            while args_addr != 0:
                args_mem = gdb.selected_inferior().read_memory(args_addr, 0x8)
                arg = MwccENode.load(parse_u32(args_mem, 0x4))
                children.append(arg)
                args_addr = parse_u32(args_mem, 0x0)
            return cls(
                expr_type=expr_type,
                rtype=rtype,
                children=children,
            )
        elif expr_type in (
            "EVECTORCONST",
            "EPRECOMP",
            "ETEMP",
            "EINITTRYCATCH",
            "EDEFINE",
            "EREUSE",
        ):
            pass  # TODO
        else:
            raise ValueError(f"Unsupported expression type: {expr_type}")


@dataclass
class MwccStatement:
    next_addr: int
    stmt_type: int
    expr_addr: int
    line: Optional[int]
    label_name: Optional[str]
    # For ST_SWITCH
    switch_cases: Optional[Tuple[int, str]] = None
    default_label_name: Optional[str] = None

    @classmethod
    def load(cls, addr: int) -> MwccStatement:
        mem = gdb.selected_inferior().read_memory(addr, 0x1A)
        next_addr = parse_u32(mem, 0x0)
        stmt_type = parse_u8(mem, 0x4)
        expr_addr = parse_u32(mem, 0xA)
        line = parse_s32(mem, 0x16)
        if line == -1:
            line = None
        if stmt_type in (2, 3, 6, 7):  # ST_LABEL, ST_GOTO, ST_IFGOTO, ST_IFNGOTO
            label_addr = parse_u32(mem, 0xE)
            label_name = read_u32(label_addr + 0x8)
            label_name = read_string(label_name + 0xA)
        else:
            label_name = None
        if stmt_type == 5:  # ST_SWITCH
            switch_info_addr = parse_u32(mem, 0xE)
            switch_mem = gdb.selected_inferior().read_memory(switch_info_addr, 0x8)

            case_addr = parse_u32(switch_mem, 0x0)
            switch_cases = []
            while case_addr != 0:
                case_mem = gdb.selected_inferior().read_memory(case_addr, 0x10)
                label_addr = parse_u32(case_mem, 0x4)
                label_name = read_u32(label_addr + 0x8)
                label_name = read_string(label_name + 0xA)
                hi = parse_s32(case_mem, 0x8)
                lo = parse_u32(case_mem, 0xC)
                value = (hi << 32) | lo
                switch_cases.append((value, label_name))
                case_addr = parse_u32(case_mem, 0x0)
            default_label_addr = parse_u32(switch_mem, 0x4)
            default_label_name = read_u32(default_label_addr + 0x8)
            default_label_name = read_string(default_label_name + 0xA)
        else:
            switch_cases = None
            default_label_name = None
        return cls(
            next_addr=next_addr,
            stmt_type=stmt_type,
            expr_addr=expr_addr,
            line=line,
            label_name=label_name,
            switch_cases=switch_cases,
            default_label_name=default_label_name,
        )


def print_type(f, rtype: MwccType):
    print(f" {format_type(rtype)}", file=f)


def print_expression(f, expr: MwccENode, indent):
    print("  " * indent, end="", file=f)

    # TODO: print flags
    expr_type = expr.expr_type
    rtype = expr.rtype
    print(f"{expr_type}", end="", file=f)

    if expr_type == "EINTCONST":
        print(f" [0x{expr.int_const:x}]", end="", file=f)
        print_type(f, rtype)
    elif expr_type == "EFLOATCONST":
        # 17 significant figures is enough for any double, but we try 15 first
        # to get a shorter representation if possible
        float_str = f"{expr.float_const:.15g}"
        if float(float_str) != expr.float_const:
            float_str = f"{expr.float_const:.17g}"
        print(f" [{float_str}]", end="", file=f)
        print_type(f, rtype)
    elif expr_type == "ESTRINGCONST":
        encoding = ""
        for c in expr.string_const:
            if c == "\x00":
                encoding += "\\0"
            elif c == "\t":
                encoding += "\\t"
            elif c == "\n":
                encoding += "\\n"
            elif c == "\r":
                encoding += "\\r"
            elif c == "\\":
                encoding += "\\\\"
            elif c == '"':
                encoding += '\\"'
            elif c >= "\x20" and c <= "\x7e":
                encoding += c
            else:
                encoding += f"\\x{ord(c):02x}"
        print(f' ["{encoding}"]', end="", file=f)
        print_type(f, rtype)
    elif expr_type == "EVECTORCONST":
        print(" <unimplemented>", file=f)
    elif expr_type in ("EOBJREF", "ELABEL"):
        print(f" [{expr.name}]", end="", file=f)
        print_type(f, rtype)
    elif expr_type in (
        "EVECTORCONST",
        "EPRECOMP",
        "ETEMP",
        "EINITTRYCATCH",
        "EDEFINE",
        "EREUSE",
    ):
        print(" <unimplemented>", file=f)
    else:
        print_type(f, rtype)
        for child in expr.children:
            print_expression(f, child, indent + 1)


def print_statement(f, stmt: MwccStatement):
    stmt_type = stmt.stmt_type
    if stmt.line:
        print(f"{stmt.line} ", end="", file=f)

    if stmt_type == 1:
        print(f"ST_NOP", file=f)
    elif stmt_type == 2:
        print(f"ST_LABEL L{stmt.label_name}", file=f)
    elif stmt_type == 3:
        print(f"ST_GOTO L{stmt.label_name}", file=f)
    elif stmt_type == 4:
        print(f"ST_EXPRESSION", file=f)
        expr = MwccENode.load(stmt.expr_addr)
        print_expression(f, expr, 1)
    elif stmt_type == 5:
        print(f"ST_SWITCH", file=f)
        expr = MwccENode.load(stmt.expr_addr)
        print_expression(f, expr, 1)
        for value, label_name in stmt.switch_cases:
            print(f"  CASE {value:#x}: L{label_name}", file=f)
        print(f"  DEFAULT: L{stmt.default_label_name}", file=f)
    elif stmt_type == 6:
        print(f"ST_IFGOTO L{stmt.label_name}", file=f)
        expr = MwccENode.load(stmt.expr_addr)
        print_expression(f, expr, 1)
    elif stmt_type == 7:
        print(f"ST_IFNGOTO L{stmt.label_name}", file=f)
        expr = MwccENode.load(stmt.expr_addr)
        print_expression(f, expr, 1)
    elif stmt_type == 8:
        print(f"ST_RETURN", file=f)
        if stmt.expr_addr != 0:
            expr = MwccENode.load(stmt.expr_addr)
            print_expression(f, expr, 1)
    elif stmt_type == 12:
        print(f"ST_BEGINCATCH", file=f)
        expr = MwccENode.load(stmt.expr_addr)
        print_expression(f, expr, 1)
    elif stmt_type == 13:
        print(f"ST_ENDCATCH", file=f)
        expr = MwccENode.load(stmt.expr_addr)
        print_expression(f, expr, 1)
    elif stmt_type == 14:
        print(f"ST_ENDCATCHDTOR", file=f)
        expr = MwccENode.load(stmt.expr_addr)
        print_expression(f, expr, 1)
    elif stmt_type == 15:
        print(f"ST_GOTOEXPR", file=f)
        expr = MwccENode.load(stmt.expr_addr)
        print_expression(f, expr, 1)
    elif stmt_type == 16:
        print(f"ST_ASM", file=f)
        print("  ...", file=f)
    else:
        raise ValueError(f"Unknown statement type: {stmt_type}")


def print_ast(stmt_addr: int, pass_number: int, pass_name: str):
    output_path = Path(OUTPUT_DIR) / f"frontend-{pass_number:02}-ast-{pass_name}.txt"
    print(f"Dumping AST to {output_path}")
    with open(output_path, "w") as f:
        while stmt_addr != 0:
            stmt = MwccStatement.load(stmt_addr)
            print_statement(f, stmt)
            stmt_addr = stmt.next_addr


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


def print_pcode(pass_number: int, pass_name: str):
    output_path = Path(OUTPUT_DIR) / f"backend-{pass_number:02}-{pass_name}.txt"
    print(f"Dumping PCode to {output_path}")
    with open(output_path, "w") as f:
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
                prev_neighbors_str = " ".join(
                    f"{prefix}{i}" for i in sorted(prev_neighbors)
                )
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
        # TODO: figure this out properly instead of guessing
        stack_start = 0x00114000
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
    load_node_names()
    load_opcode_info()

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
    gdb.execute(f"break *{MWCC_VERSION.copt_optimizer_call_addr:#x}")
    gdb.execute(f"break *{MWCC_VERSION.copt_optimizer_call_addr + 5:#x}")
    for addr in MWCC_VERSION.pcode_breakpoints:
        gdb.execute(f"break *{addr:#x}")
    gdb.execute(f"break *{MWCC_VERSION.regalloc_breakpoint_addr:#x}")
    gdb.execute(f"break *{MWCC_VERSION.codegen_end_addr:#x}")

    # Loop through breakpoints
    frontend_pass_number = 0
    backend_pass_number = 0
    while True:
        gdb.execute("continue")
        current_addr = int(gdb.parse_and_eval("$pc"))

        if current_addr == MWCC_VERSION.copt_optimizer_call_addr:
            # Print argument 2 (before return address has been pushed)
            sp = int(gdb.parse_and_eval("$esp"))
            statement_addr = read_u32(sp + 0x4)
            print_ast(statement_addr, frontend_pass_number, "initial-code")
            frontend_pass_number += 1

        if current_addr == MWCC_VERSION.copt_optimizer_call_addr + 5:
            # Print returned statements in EAX
            statements_addr = int(gdb.parse_and_eval("$eax"))
            print_ast(statements_addr, frontend_pass_number, "final-code")
            frontend_pass_number += 1

        if current_addr in MWCC_VERSION.pcode_breakpoints:
            pass_name = MWCC_VERSION.pcode_breakpoints[current_addr]
            print_pcode(backend_pass_number, pass_name)
            backend_pass_number += 1

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
        f'py FUNCTION_NAME = "{function_name}"; OUTPUT_DIR = "{output_dir}"',
        "-x",
        str(Path(__file__).resolve()),
    ]
    print(f"GDB command: {shlex.join(gdb_command)}", file=sys.stderr)

    emulator_process = subprocess.Popen(emulator_command)
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
