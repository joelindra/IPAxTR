"""Minimal pure-Python Mach-O / FAT reader.

Only what the tool needs:
  * parse the load commands of a Mach-O slice
  * report the FairPlay crypt id (LC_ENCRYPTION_INFO / _64)
  * report the cpu type and minimum OS version

No third-party dependency on purpose (lief is not required).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# magic values (as little-endian i32)
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE  # big-endian 64-bit (never seen in practice)
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

LC_ENCRYPTION_INFO = 0x21  # 21
LC_ENCRYPTION_INFO_64 = 0x2C  # 44
LC_VERSION_MIN_IPHONEOS = 0x25  # 37
LC_BUILD_VERSION = 0x32  # 50
LC_SEGMENT = 0x1  # 1
LC_SEGMENT_64 = 0x19  # 25

CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_ARM64_32 = 0x0200000C

MAX_COMMANDS = 100_000  # guard against corrupt headers


@dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int


@dataclass
class MachoInfo:
    cpu_type: int | None = None
    is_fat: bool = False
    n_slices: int = 1
    has_crypt_info: bool = False
    crypt_id: int | None = None
    crypt_off: int | None = None
    crypt_size: int | None = None
    platform: str | None = None
    min_os: str | None = None
    segments: list = field(default_factory=list)

    @property
    def is_encrypted(self) -> bool:
        return bool(self.has_crypt_info and self.crypt_id)

    def text_segment(self) -> Segment | None:
        for s in self.segments:
            if s.name == "__TEXT":
                return s
        return None


def _fmt_version(v: int) -> str:
    return f"{v >> 16}.{(v >> 8) & 0xFF}.{v & 0xFF}"


def _walk_load_commands(data: bytes, off: int, le: bool, is64: bool) -> MachoInfo:
    info = MachoInfo()
    fmt = "<" if le else ">"
    header_size = 32 if is64 else 28
    if off + header_size > len(data):
        raise ValueError("truncated Mach-O header")
    # mach_header[_64]: magic(I) cputype(i) cpusubtype(i) filetype(I)
    #                  ncmds(I) sizeofcmds(I) flags(I) [reserved(I)]
    if is64:
        _, cpu_type, _, _, ncmds, sizeofcmds, _, _ = struct.unpack_from(
            fmt + "IiiIIIII", data, off
        )
    else:
        _, cpu_type, _, _, ncmds, sizeofcmds, _ = struct.unpack_from(
            fmt + "IiiIIII", data, off
        )
    info.cpu_type = cpu_type
    pos = off + header_size
    end = pos + sizeofcmds
    n = 0
    while pos + 8 <= min(end, len(data)) and n < MAX_COMMANDS:
        cmd, cmdsize = struct.unpack_from(fmt + "II", data, pos)
        n += 1
        if cmdsize < 8:
            break
        if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            # struct: cmd, cmdsize, cryptoff, cryptsize, cryptid
            if pos + 20 <= len(data):
                cryptoff, cryptsize, cryptid = struct.unpack_from(
                    fmt + "III", data, pos + 8
                )
                if cryptid != 0 or cryptsize != 0:
                    info.has_crypt_info = True
                    info.crypt_id = cryptid
                    info.crypt_off = cryptoff
                    info.crypt_size = cryptsize
        elif cmd == LC_SEGMENT_64 and pos + 72 <= len(data):
            segname = data[pos + 8 : pos + 24].rstrip(b"\x00").decode("ascii", "replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                fmt + "QQQQ", data, pos + 24
            )
            info.segments.append(Segment(segname, vmaddr, vmsize, fileoff, filesize))
        elif cmd == LC_SEGMENT and pos + 56 <= len(data):
            segname = data[pos + 8 : pos + 24].rstrip(b"\x00").decode("ascii", "replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                fmt + "IIII", data, pos + 24
            )
            info.segments.append(Segment(segname, vmaddr, vmsize, fileoff, filesize))
        elif cmd == LC_VERSION_MIN_IPHONEOS and pos + 16 <= len(data):
            ver = struct.unpack_from(fmt + "I", data, pos + 8)[0]
            info.platform = info.platform or "iphoneos"
            info.min_os = info.min_os or _fmt_version(ver)
        elif cmd == LC_BUILD_VERSION and pos + 24 <= len(data):
            platform, minos = struct.unpack_from(fmt + "II", data, pos + 8)
            names = {1: "macos", 2: "iphoneos", 3: "tvos", 4: "watchos", 6: "maccatalyst"}
            info.platform = info.platform or names.get(platform, f"platform:{platform}")
            info.min_os = info.min_os or _fmt_version(minos)
        pos += cmdsize
    return info


def analyze_file(path: str) -> MachoInfo:
    """Parse a Mach-O (or universal) file and return the info for its first slice."""
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 32:
        raise ValueError("file too small to be a Mach-O")

    magic, = struct.unpack_from("<I", data, 0)
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        is64fat = magic == FAT_MAGIC_64
        nfat = struct.unpack_from(">I", data, 4)[0]
        if nfat > 64:
            raise ValueError("too many fat slices")
        for i in range(nfat):
            pos = 8 + i * (32 if is64fat else 20)
            _, cpu_type, _, off, _ = struct.unpack_from(">iiIII", data, pos)
            try:
                sub_magic, = struct.unpack_from("<I", data, off)
                sub_is64 = sub_magic in (MH_MAGIC_64, MH_CIGAM_64)
                sub = _walk_load_commands(data, off, True, sub_is64)
            except (ValueError, struct.error):
                continue
            sub.is_fat = True
            sub.n_slices = nfat
            return sub
        raise ValueError("no readable slices in fat binary")

    if magic in (MH_MAGIC, MH_MAGIC_64):
        return _walk_load_commands(data, 0, True, magic == MH_MAGIC_64)
    if magic in (MH_CIGAM, MH_CIGAM_64):
        return _walk_load_commands(data, 0, False, magic == MH_CIGAM_64)
    raise ValueError("not a Mach-O file")


# ------------------------------------------------- name helpers -----------------


def cryptid_description(info: MachoInfo) -> str:
    """Human verdict, ready for console output."""
    if not info.has_crypt_info:
        return "decrypted (no encryption info)"
    if info.crypt_id == 0:
        return "decrypted (cryptid=0)"
    return f"ENCRYPTED / FairPlay (cryptid={info.crypt_id})"


def cpu_name(cpu_type: int | None) -> str:
    return {
        7: "x86",
        12: "arm",
        CPU_TYPE_ARM64: "arm64",
        CPU_TYPE_ARM64_32: "arm64_32",
        CPU_TYPE_X86_64: "x86_64",
    }.get(cpu_type, str(cpu_type) if cpu_type is not None else "?")
