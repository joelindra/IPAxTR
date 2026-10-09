"""Frida-based filesystem pull route for jailbroken devices.

Why this exists: on a jailbroken iPhone running frida-server as root, Frida is
a full filesystem oracle — you can read any file the root user can read, which
includes /var/containers/Bundle/Application (the installed app bundles). This
needs no SSH and no AFC2 tweak; it only needs frida-server running on-device
and the Python `frida` package on the host.

The module attaches to a root process (frida-server first), injects a small
agent exposing RPC calls (stat / listdir / readlink / chunked read), and pulls
a bundle recursively. POSIX details that Windows cannot represent locally
(symlinks, unix mode bits) are recorded in a sidecar manifest
(util.META_NAME) that packaging.py replays when building the IPA.

Use only on devices/apps you own or are authorised to test.
"""

from __future__ import annotations

import json
import os
import shutil
import stat as statmod
import time
from dataclasses import dataclass

from . import util

S_IFMT = 0xF000
S_IFDIR = 0x4000
S_IFREG = 0x8000
S_IFLNK = 0xA000

DEFAULT_META = {
    "links": {},    # local rel path -> symlink target (as stored on device)
    "modes": {},    # local rel path -> st_mode
    "rename": {},   # local rel path -> original device name (Windows sanitising)
}


class FridaError(RuntimeError):
    pass


_AGENT = r"""
'use strict';
var OPENDIR = Module.getGlobalExportByName('opendir');
var READDIR = Module.getGlobalExportByName('readdir');
var CLOSEDIR = Module.getGlobalExportByName('closedir');
var LSTAT = Module.getGlobalExportByName('lstat');
var STAT = Module.getGlobalExportByName('stat');
var READLINK = Module.getGlobalExportByName('readlink');
var GETUID = Module.getGlobalExportByName('getuid');

var _opendir = new NativeFunction(OPENDIR, 'pointer', ['pointer']);
var _readdir = new NativeFunction(READDIR, 'pointer', ['pointer']);
var _closedir = new NativeFunction(CLOSEDIR, 'int', ['pointer']);
var _lstat = new NativeFunction(LSTAT, 'int', ['pointer', 'pointer']);
var _stat = new NativeFunction(STAT, 'int', ['pointer', 'pointer']);
var _readlink = new NativeFunction(READLINK, 'long', ['pointer', 'pointer', 'ulong']);
var _getuid = new NativeFunction(GETUID, 'int', []);

// darwin arm64 struct stat: st_mode @4 (u16), st_size @96 (i64)
function statFields(path) {
    var st = Memory.alloc(256);
    if (_lstat(Memory.allocUtf8String(path), st) !== 0) return null;
    var mode = st.add(4).readU16();
    var size = Number(st.add(96).readS64());
    return { mode: mode, size: size };
}

rpc.exports = {
    uid: function () { return _getuid(); },

    exists: function (path) {
        var st = Memory.alloc(256);
        return _stat(Memory.allocUtf8String(path), st) === 0;
    },

    stat: function (path) {
        return statFields(path);
    },

    ls: function (dirPath) {
        var out = [];
        var d = _opendir(Memory.allocUtf8String(dirPath));
        if (d.isNull()) throw new Error('opendir failed: ' + dirPath);
        try {
            while (true) {
                var e = _readdir(d);
                if (e.isNull()) break;
                var name = e.add(21).readUtf8String(); // d_name offset on darwin
                if (!name || name === '.' || name === '..') continue;
                var full = dirPath.replace(/\/+$/, '') + '/' + name;
                var f = statFields(full);
                if (f === null) continue;
                out.push({ name: name, mode: f.mode, size: f.size });
            }
        } finally {
            _closedir(d);
        }
        return out;
    },

    readlink: function (path) {
        var buf = Memory.alloc(4096);
        var n = _readlink(Memory.allocUtf8String(path), buf, 4095);
        if (n < 0) return null;
        return buf.readUtf8String(Number(n));
    },

    readchunk: function (path, offset, size) {
        var f = new File(path, 'rb');
        try {
            f.seek(offset, File.SEEK_SET);
            var buf = f.readBytes(size);
            return buf;
        } finally {
            f.close();
        }
    },

    writefile: function (path, data) {
        var f = new File(path, 'wb');
        try { f.write(data); } finally { f.close(); }
        return true;
    }
};
"""


@dataclass
class RemoteEntry:
    name: str
    mode: int
    size: int

    @property
    def is_dir(self) -> bool:
        return (self.mode & S_IFMT) == S_IFDIR

    @property
    def is_link(self) -> bool:
        return (self.mode & S_IFMT) == S_IFLNK


def _choose_device(frida_mod, udid: str | None):
    mgr = frida_mod.get_device_manager()
    if udid:
        return mgr.get_device(udid, timeout=10)
    # newest USB device first
    for d in mgr.enumerate_devices():
        if d.type == "usb":
            return d
    raise FridaError(
        "no USB device visible to frida. Check: iPhone connected + trusted, and "
        "frida-server running on the device."
    )


class FridaBridge:
    """Attach to a root process on the device and expose filesystem RPCs."""

    def __init__(self, udid: str | None = None, chunk_size: int = 4 * 1024 * 1024):
        self.udid = udid
        self.chunk_size = chunk_size
        self._device = None
        self._session = None
        self._script = None
        self._rpc = None
        self.uid: int | None = None

    # ------------------------------------------------------------- lifecycle

    def open(self) -> "FridaBridge":
        try:
            import frida
        except ImportError as exc:
            raise FridaError(
                "frida is not installed on this host: pip install frida"
            ) from exc
        self._device = _choose_device(frida, self.udid)

        last = None
        for name in ("frida-server", "launchd", "SpringBoard"):
            try:
                proc = next(
                    (p for p in self._device.enumerate_processes() if p.name == name),
                    None,
                )
                if proc is None:
                    continue
                self._session = self._device.attach(proc.pid)
                self._script = self._session.create_script(_AGENT)
                self._script.load()
                self._rpc = self._script.exports_sync
                self.uid = int(self._rpc.uid())
                if self.uid == 0:
                    return self
                # non-root: keep it as a fallback but warn once the caller fails
                last = name
            except Exception as exc:  # noqa: BLE001
                last = f"{name}: {exc}"
                self._teardown()
        self._teardown()
        if last:
            raise FridaError(
                f"attached to {last} but it is not running as root; cannot read "
                "app bundles. Start frida-server as root on the device "
                "(it normally runs as root when launched from the jailbreak app)."
            )
        raise FridaError(
            "no attachable process found (tried frida-server, launchd, SpringBoard). "
            "Is frida-server running on the device?"
        )

    def _teardown(self) -> None:
        for obj, meth in ((self._script, "unload"), (self._session, "detach")):
            try:
                if obj:
                    getattr(obj, meth)()
            except Exception:  # noqa: BLE001
                pass
        self._script = None
        self._session = None
        self._rpc = None

    def close(self) -> None:
        self._teardown()

    def __enter__(self):
        return self.open()

    def __exit__(self, *exc):
        self.close()
        return False

    # ------------------------------------------------------------- RPC

    def stat(self, path: str) -> dict | None:
        return self._rpc.stat(path)

    def exists(self, path: str) -> bool:
        return bool(self._rpc.exists(path))

    def ls(self, path: str) -> list[RemoteEntry]:
        raw = self._rpc.ls(path)
        out = []
        for e in raw or []:
            if not isinstance(e, dict):
                continue
            out.append(RemoteEntry(str(e.get("name")), int(e.get("mode") or 0),
                                   int(e.get("size") or 0)))
        out.sort(key=lambda e: e.name)
        return out

    def readlink(self, path: str) -> str | None:
        return self._rpc.readlink(path)

    def read_at(self, path: str, offset: int, size: int) -> bytes:
        data = self._rpc.readchunk(path, int(offset), int(size))
        return bytes(data) if data is not None else b""

    def size(self, path: str) -> int:
        st = self.stat(path)
        if st is None:
            raise FridaError(f"stat failed: {path}")
        return int(st["size"])

    def read_all(self, path: str, max_size: int | None = None) -> bytes:
        total = self.size(path)
        if max_size is not None:
            total = min(total, max_size)
        parts = []
        off = 0
        while off < total:
            n = min(self.chunk_size, total - off)
            chunk = self.read_at(path, off, n)
            if not chunk:
                break
            parts.append(chunk)
            off += len(chunk)
        return b"".join(parts)

    # ------------------------------------------------------------- pull

    def pull_dir(self, remote_root: str, local_root: str, on_file=None) -> int:
        """Recursively copy remote_root into local_root; write the sidecar meta."""
        meta = json.loads(json.dumps(DEFAULT_META))  # deep copy
        count = self._pull(remote_root, local_root, "", meta, on_file)
        if meta["links"] or meta["rename"] or any(
            m & 0o111 and (m & S_IFMT) == S_IFREG for m in meta["modes"].values()
        ):
            util.ensure_dir(local_root)
            with open(os.path.join(local_root, util.META_NAME), "w", encoding="utf-8") as fh:
                json.dump(meta, fh, indent=1)
        return count

    def _pull(self, remote_dir: str, local_dir: str, rel: str, meta: dict, on_file) -> int:
        util.ensure_dir(local_dir)
        count = 0
        for entry in self.ls(remote_dir):
            r = f"{remote_dir.rstrip('/')}/{entry.name}"
            local_name = util.local_name(entry.name)
            l = os.path.join(local_dir, local_name)
            child_rel = f"{rel}/{local_name}" if rel else local_name
            if local_name != entry.name:
                meta["rename"][child_rel] = entry.name
            meta["modes"][child_rel] = entry.mode

            if entry.is_link:
                target = self.readlink(r)
                if target is None:
                    continue
                meta["links"][child_rel] = target
                try:
                    os.symlink(target, l)
                except OSError:
                    pass  # Windows without privileges: manifest will restore it
                continue

            if entry.is_dir:
                count += self._pull(r, l, child_rel, meta, on_file)
                continue

            # regular file
            expected = entry.size
            received = 0
            with open(l, "wb") as fh:
                off = 0
                while off < expected:
                    n = min(self.chunk_size, expected - off)
                    chunk = self.read_at(r, off, n)
                    if not chunk:
                        raise FridaError(
                            f"short read on {r}: {received}/{expected} bytes "
                            "(device disconnected?)"
                        )
                    fh.write(chunk)
                    off += len(chunk)
                    received += len(chunk)
            count += 1
            if on_file:
                on_file(r, received)
        return count


def open_bridge(udid: str | None = None) -> FridaBridge:
    return FridaBridge(udid).open()


def _cleanup_partial(local_dir: str) -> None:
    # only used when a pull fails halfway; leave pulled data in place but note it
    pass


def wait_for_ready(device, name: str, timeout: float = 10.0):
    """Wait until an app appears in the running-process list (best effort)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if any(p.name == name for p in device.enumerate_processes()):
            return True
        time.sleep(0.3)
    return False


def copy_remote_file(bridge: FridaBridge, remote: str, local: str, on_file=None) -> int:
    """Single-file convenience pull with chunked reads."""
    size = bridge.size(remote)
    util.ensure_dir(os.path.dirname(os.path.abspath(local)))
    written = 0
    with open(local, "wb") as fh:
        off = 0
        while off < size:
            n = min(bridge.chunk_size, size - off)
            chunk = bridge.read_at(remote, off, n)
            if not chunk:
                break
            fh.write(chunk)
            off += len(chunk)
            written += len(chunk)
    if on_file:
        on_file(remote, written)
    return written
