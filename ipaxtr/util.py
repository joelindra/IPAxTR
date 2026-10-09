"""Small shared utilities: colors, filesystem helpers, plist parsing."""

from __future__ import annotations

import os
import plistlib
import re
import sys

# ---------------------------------------------------------------- colors ----

_USE_COLOR = True
if os.environ.get("NO_COLOR"):
    _USE_COLOR = False
if sys.platform == "win32" and not os.environ.get("WT_SESSION"):
    try:
        import ctypes

        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7
        )
    except Exception:
        pass

_CODES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[97m",
}


def _paint(name: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return _CODES.get(name, "") + text + _CODES["reset"]


def red(t):
    return _paint("red", t)


def green(t):
    return _paint("green", t)


def yellow(t):
    return _paint("yellow", t)


def blue(t):
    return _paint("blue", t)


def cyan(t):
    return _paint("cyan", t)


def magenta(t):
    return _paint("magenta", t)


def bold(t):
    return _paint("bold", t)


def dim(t):
    return _paint("dim", t)


def ok(msg: str) -> None:
    print(f"  {green('[ OK ]')} {msg}")


def warn(msg: str) -> None:
    print(f"  {yellow('[WARN]')} {msg}")


def err(msg: str) -> None:
    print(f"  {red('[FAIL]')} {msg}")


def info(msg: str) -> None:
    print(f"  {blue('[INFO]')} {msg}")


def step(msg: str) -> None:
    print(f"\n{bold('>> ' + msg)}")


# ------------------------------------------------------------ filesystem ----


def human_size(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return str(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024.0:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024.0
    return f"{n:.1f} PB"


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


# Sidecar manifest describing a pulled tree (symlinks + unix modes) so that
# packaging can restore POSIX structure even on Windows where os.symlink and
# mode bits are not available.
META_NAME = ".__ipaxtr_meta__.json"
_WIN_BAD_CHARS = '<>:"/\\|?*'


def local_name(device_name: str) -> str:
    """Map a device file name to a local (Windows-safe) name."""
    out = "".join(c if c not in _WIN_BAD_CHARS and ord(c) >= 32 else "_" for c in device_name)
    out = out.rstrip(". ")
    return out or "_"


def read_maybe_compressed(data: bytes) -> bytes:
    """lzma-compressed share caches break plistlib's XML detection; sniff magic."""
    if data[:6] == b"\xfd7zXZ\x00":
        import lzma

        return lzma.decompress(data)
    return data


# ---------------------------------------------------------------- plist -----


def plist_from_bytes(data: bytes):
    """Parse a plist that may be XML, binary, or lzma-compressed."""
    data = read_maybe_compressed(data)
    try:
        return plistlib.loads(data)
    except Exception:
        pass
    if b"bplist" in data[:64]:
        # skip any leading garbage before the binary plist magic
        idx = data.find(b"bplist")
        try:
            return plistlib.loads(data[idx:])
        except Exception:
            return None
    return None


def read_info_plist(app_dir: str):
    """Parse Info.plist from a local .app directory."""
    path = os.path.join(app_dir, "Info.plist")
    try:
        with open(path, "rb") as fh:
            return plist_from_bytes(fh.read())
    except OSError:
        return None


def main_executable(app_dir: str, info: dict | None = None) -> str | None:
    """Resolve the main Mach-O executable name inside a .app directory."""
    name = (info or {}).get("CFBundleExecutable")
    if isinstance(name, str) and name and os.path.isfile(os.path.join(app_dir, name)):
        return name
    if isinstance(name, str) and name:
        # some builds append a suffix like "-debug"; look for a prefix match
        for entry in os.listdir(app_dir):
            if entry.startswith(name) and os.path.isfile(os.path.join(app_dir, entry)):
                return entry
    # fallback: any file whose name matches the .app basename
    base = os.path.basename(app_dir)
    if base.endswith(".app"):
        base = base[:-4]
    cand = os.path.join(app_dir, base)
    if os.path.isfile(cand):
        return base
    return None


_PROVISION_PLIST_RE = re.compile(rb"<\?xml[\s\S]*?</plist>", re.IGNORECASE)
_PROVISION_BPLIST_RE = re.compile(rb"bplist00[\s\S]*$")


def decode_provision(data: bytes):
    """Extract the plist payload from an embedded.mobileprovision (CMS blob)."""
    m = _PROVISION_PLIST_RE.search(data)
    if m:
        try:
            return plistlib.loads(m.group(0))
        except Exception:
            pass
    m = _PROVISION_BPLIST_RE.search(data)
    if m:
        try:
            return plistlib.loads(m.group(0))
        except Exception:
            pass
    return None
