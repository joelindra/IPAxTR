"""FairPlay decryption via Frida (frida-server must run as root on the device).

LEGAL / ETHICAL SCOPE — read this:
  FairPlay decryption may only be used on applications you own, or in a
  security-research context on your own device, and only under your local law.
  Decrypting and redistributing third-party App Store / TestFlight binaries
  violates Apple's terms and typically copyright law. This module is gated
  behind an explicit --i-own-this-build flag so it cannot happen by accident.

Algorithm (robust across iOS versions, incl. iOS 16+ lazy decryption):
  * the app is launched so the kernel decrypts pages as they are faulted in
    (FairPlay decryption is lazy, page by page),
  * Frida attaches; for every Mach-O in the bundle whose disk cryptid=1, its
    __TEXT file range is compared page-by-page with the same offset inside the
    loaded module image in memory,
  * pages that differ are overwritten with the memory bytes. cryptoff/cryptsize
    from LC_ENCRYPTION_INFO are NOT trusted: on iOS 16+ they no longer
    describe the full extent (often a single page),
  * cryptid is patched to 0 and the bundle is repackaged as an IPA.
  * app extensions (widgets etc.) live in their own processes: binaries not
    found in the launched process are picked up from the running process whose
    name matches the extension (activate the widget first if needed).

Input: a bundle already pulled with `ipaxtr pull` (local .app directory
holding the original encrypted binaries).
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field

from . import macho, packaging, util


class DecryptError(RuntimeError):
    pass


@dataclass
class FileResult:
    rel_path: str
    pages_patched: int = 0
    pages_compared: int = 0
    bytes_patched: int = 0
    from_process: str | None = None
    skipped: str | None = None
    action_taken: str | None = None
    category: str = "Binary"


@dataclass
class DecryptResult:
    app_dir: str
    ipa_path: str
    files: list = field(default_factory=list)
    total_machos: int = 0
    already_plaintext: int = 0

    @property
    def total_patched(self) -> int:
        return sum(f.bytes_patched for f in self.files)

    @property
    def patched_files(self) -> int:
        return sum(1 for f in self.files if f.pages_patched > 0)

    @property
    def leftover(self) -> list:
        return [f for f in self.files if f.skipped]


_AGENT = r"""
'use strict';

function findModule(suffix) {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        var p = mods[i].path || '';
        if (p.length >= suffix.length && p.slice(-suffix.length) === suffix) return mods[i];
        // also allow plain basename match (host passes "/Name" for that)
        if (p === suffix) return mods[i];
    }
    return null;
}

rpc.exports = {
    modulesLoaded: function () { return Process.enumerateModules().length; },
    hasModule: function (suffix) { return findModule(suffix) !== null; },
    // read the module's memory image at vm offset (= offset from module base)
    diffPage: function (suffix, vm_off, size) {
        var mod = findModule(suffix);
        if (mod === null) return null;
        try {
            return mod.base.add(vm_off).readByteArray(size);
        } catch (e) {
            return null; // unreadable page stays as-is on disk
        }
    }
};
"""


def _require_frida():
    try:
        import frida
    except ImportError as exc:
        raise DecryptError("frida is not installed on this host: pip install frida") from exc
    return frida


def _patch_cryptid(buf: bytearray) -> bool:
    """Set LC_ENCRYPTION_INFO(_64).cryptid = 0 in a little-endian Mach-O."""
    if len(buf) < 32:
        return False
    magic, = struct.unpack_from("<I", buf, 0)
    if magic == macho.MH_MAGIC_64:
        is64 = True
    elif magic == macho.MH_MAGIC:
        is64 = False
    else:
        return False  # fat or big-endian
    fmt = "<"
    header = 32 if is64 else 28
    ncmds, sizeofcmds = struct.unpack_from(fmt + "II", buf, 16)
    pos = header
    end = pos + sizeofcmds
    while pos + 8 <= end and pos + 24 <= len(buf):
        cmd, cmdsize = struct.unpack_from(fmt + "II", buf, pos)
        if cmd in (macho.LC_ENCRYPTION_INFO, macho.LC_ENCRYPTION_INFO_64):
            struct.pack_into(fmt + "I", buf, pos + 16, 0)
            return True
        if cmdsize < 8:
            break
        pos += cmdsize
    return False


def _is_macho(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    return head in (
        b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
        b"\xbf\xba\xfe\xca", b"\xca\xfe\xba\xbf",
    )


def find_encrypted_binaries(app_dir: str) -> list[tuple[str, macho.MachoInfo]]:
    """All Mach-O files in the bundle whose disk cryptid is still 1."""
    out = []
    for root, dirs, files in os.walk(app_dir):
        for name in files:
            path = os.path.join(root, name)
            if not _is_macho(path):
                continue
            try:
                mi = macho.analyze_file(path)
            except Exception:  # noqa: BLE001
                continue
            if mi.is_encrypted:
                out.append((path, mi))
    return out


def scan_bundle_binaries(app_dir: str) -> dict:
    """Classify all Mach-O binaries in the bundle by type and encryption state."""
    out = {
        "main": None,
        "frameworks": [],
        "extensions": [],
        "all": [],
        "encrypted": [],
        "plaintext": [],
    }
    for root, dirs, files in os.walk(app_dir):
        for name in files:
            path = os.path.join(root, name)
            if not _is_macho(path):
                continue
            try:
                mi = macho.analyze_file(path)
            except Exception:  # noqa: BLE001
                continue
            rel = os.path.relpath(path, app_dir).replace(os.sep, "/")
            if os.path.dirname(path) == app_dir:
                cat = "Main Executable"
            elif "/PlugIns/" in f"/{rel}":
                cat = "App Extension"
            elif "/Frameworks/" in f"/{rel}":
                cat = "Framework"
            else:
                cat = "Helper / Binary"

            item = {
                "path": path,
                "rel": rel,
                "macho": mi,
                "category": cat,
                "encrypted": mi.is_encrypted,
            }

            if cat == "Main Executable":
                out["main"] = item
            elif cat == "App Extension":
                out["extensions"].append(item)
            elif cat == "Framework":
                out["frameworks"].append(item)

            out["all"].append(item)
            if mi.is_encrypted:
                out["encrypted"].append(item)
            else:
                out["plaintext"].append(item)
    return out


_PAGE = 0x1000
_CHUNK = 4 * 1024 * 1024


def _dump_in_rpc(rpc, path: str, mi: macho.MachoInfo, suffix: str,
                 res: FileResult) -> bool:
    """Page-diff one binary in memory (via rpc) against the file on disk.

    Returns True when the local file changed."""
    text = mi.text_segment()
    if text is None or text.filesize <= 0:
        res.skipped = "no __TEXT segment"
        return False
    if mi.is_fat:
        res.skipped = "fat binary (thin with lipo first)"
        return False

    changed = False
    with open(path, "r+b") as fh:
        disk = bytearray(fh.read())
        off = 0
        while off < text.filesize:
            n = min(_CHUNK, text.filesize - off)
            mem = rpc.diffPage(suffix, off, n)
            if mem is None:
                off += n
                continue
            mem = bytes(mem)
            full = len(mem) // _PAGE * _PAGE
            disk_chunk = disk[text.fileoff + off:text.fileoff + off + full]
            if mem[:full] != disk_chunk:
                for p in range(0, full, _PAGE):
                    mp = mem[p:p + _PAGE]
                    if mp == disk_chunk[p:p + _PAGE]:
                        res.pages_compared += 1
                        continue
                    fh.seek(text.fileoff + off + p)
                    fh.write(mp)
                    res.pages_patched += 1
                    res.bytes_patched += len(mp)
                changed = True
            off += n

        if changed:
            fh.seek(0)
            head = bytearray(fh.read(64 * 1024))
            if _patch_cryptid(head):
                fh.seek(0)
                fh.write(head)
    return changed


def _safe_unload(script=None, session=None) -> None:
    for obj, meth in ((script, "unload"), (session, "detach")):
        try:
            if obj:
                getattr(obj, meth)()
        except Exception:  # noqa: BLE001
            pass


def decrypt_app(
    udid: str | None,
    bundle_id: str,
    output_dir: str,
    app_dir_local: str,
    spawn_timeout: float = 20.0,
    settle_time: float = 2.0,
    extension_action: str = "strip",
) -> DecryptResult:
    """Launch the app, page-diff every encrypted binary against memory, repack.

    `extension_action` controls how un-decrypted on-demand extensions are handled:
      - "strip" (default): remove the un-decrypted .appex folder so the resulting
        IPA can be cleanly sideloaded/installed without FairPlay DRM blocks.
      - "patch": patch cryptid=0 on the Mach-O header on disk.
      - "keep": keep original encrypted files as-is.
    """
    frida = _require_frida()
    if not app_dir_local or not os.path.isdir(app_dir_local):
        raise DecryptError("app_dir_local must be a pulled .app directory")

    scan_before = scan_bundle_binaries(app_dir_local)
    encrypted = find_encrypted_binaries(app_dir_local)
    if not encrypted:
        util.info("no encrypted binaries in this bundle — packaging as-is")
        ipa = packaging.package_app(app_dir_local, output_dir)
        return DecryptResult(
            app_dir_local,
            ipa,
            [],
            total_machos=len(scan_before["all"]),
            already_plaintext=len(scan_before["plaintext"]),
        )

    util.info(f"{len(encrypted)} encrypted binary/binaries found (out of {len(scan_before['all'])} total)")
    app_basename = os.path.basename(app_dir_local)
    results: list[FileResult] = []
    pending: list[tuple[str, macho.MachoInfo, FileResult]] = []

    def suffix_for(rel: str) -> str:
        return f"/{app_basename}/{rel}"

    from .frida_bridge import _choose_device

    device = _choose_device(frida, udid)
    util.info(f"device: {device.name}")

    main_exe = None
    for path, mi in encrypted:
        if os.path.dirname(path) == app_dir_local:
            main_exe = os.path.basename(path)
            break

    util.info(f"launching {bundle_id} …")
    try:
        pid = device.spawn([bundle_id])
    except Exception as exc:  # noqa: BLE001
        raise DecryptError(
            f"cannot launch {bundle_id} via frida (is it installed?): {exc}"
        ) from exc

    session = None
    script = None
    try:
        session = device.attach(pid)
        script = session.create_script(_AGENT)
        script.load()
        rpc = script.exports_sync

        util.info(f"resuming pid {pid} …")
        device.resume(pid)
        deadline = time.time() + spawn_timeout
        while time.time() < deadline:
            try:
                if rpc.modulesLoaded() > 1:
                    break
            except Exception:  # noqa: BLE001
                pass
            time.sleep(0.25)
        time.sleep(settle_time)

        for path, mi in encrypted:
            rel = os.path.relpath(path, app_dir_local).replace(os.sep, "/")
            cat = "Main Executable" if os.path.dirname(path) == app_dir_local else (
                "App Extension" if "/PlugIns/" in f"/{rel}" else (
                    "Framework" if "/Frameworks/" in f"/{rel}" else "Binary"
                )
            )
            res = FileResult(rel, from_process=f"app pid {pid}", category=cat)
            loaded = False
            try:
                loaded = bool(rpc.hasModule(suffix_for(rel)))
                if loaded:
                    _dump_in_rpc(rpc, path, mi, suffix_for(rel), res)
                    res.action_taken = "decrypted"
                else:
                    res.skipped = "module not loaded in the app process"
            except Exception as exc:  # noqa: BLE001
                res.skipped = f"error: {exc}"
            results.append(res)
            if loaded:
                util.info(f"  {rel}: {_status_line(res)}")
            else:
                pending.append((path, mi, res))
    finally:
        _safe_unload(script, session)
        try:
            device.kill(pid)
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------- second pass: extensions
    if pending:
        util.info(f"{len(pending)} extension binary/binaries not loaded in the app "
                  "process — searching other device processes …")
        _dump_pending_from_processes(frida, device, pending, suffix_for)

    leftovers = [r for r in results if r.skipped]
    if leftovers and extension_action in ("strip", "patch"):
        for path, mi, res in pending:
            if not res.skipped:
                continue
            if extension_action == "strip":
                cur = path
                appex_dir = None
                while cur and cur != app_dir_local:
                    if cur.endswith(".appex"):
                        appex_dir = cur
                        break
                    cur = os.path.dirname(cur)
                if appex_dir and os.path.isdir(appex_dir):
                    import shutil

                    shutil.rmtree(appex_dir, ignore_errors=True)
                    plugins_dir = os.path.join(app_dir_local, "PlugIns")
                    if os.path.isdir(plugins_dir) and not os.listdir(plugins_dir):
                        try:
                            os.rmdir(plugins_dir)
                        except OSError:
                            pass
                res.skipped = None
                res.action_taken = "stripped (clean install on TrollStore/Sideloadly)"
                util.ok(f"  {res.rel_path}: stripped un-decrypted extension for clean sideloading")
            elif extension_action == "patch":
                with open(path, "r+b") as fh:
                    head = bytearray(fh.read(64 * 1024))
                    if _patch_cryptid(head):
                        fh.seek(0)
                        fh.write(head)
                res.skipped = None
                res.action_taken = "header patched cryptid=0 (on-demand extension)"
                util.ok(f"  {res.rel_path}: patched header cryptid=0 (on-demand extension)")

    leftovers = [r for r in results if r.skipped]
    if leftovers:
        util.warn("not decrypted (activate the widget/extension on the device, "
                  "then re-run; some extensions only load on demand):")
        for r in leftovers:
            print(f"        - {r.rel_path}  ({r.skipped})")

    ipa = packaging.package_app(app_dir_local, output_dir)
    scan_after = scan_bundle_binaries(app_dir_local)
    return DecryptResult(
        app_dir=app_dir_local,
        ipa_path=ipa,
        files=results,
        total_machos=len(scan_after["all"]),
        already_plaintext=len(scan_after["plaintext"]),
    )


def _status_line(res: FileResult) -> str:
    if res.action_taken:
        return res.action_taken
    if res.pages_patched:
        return f"{res.pages_patched} page(s) patched, {res.bytes_patched/1024:.0f} KB recovered"
    if res.skipped:
        return f"skipped: {res.skipped}"
    return "memory matches disk (already decrypted)"


def _dump_pending_from_processes(frida, device, pending, suffix_for) -> None:
    """Try to dump extension binaries from other running processes."""
    try:
        procs = device.enumerate_processes()
    except Exception as exc:  # noqa: BLE001
        for _, _, res in pending:
            res.skipped = f"cannot enumerate processes: {exc}"
        return

    for path, mi, res in pending:
        basename = os.path.basename(path)
        # candidate processes: name contains the extension binary name
        candidates = [
            p for p in procs
            if p.name and (basename.lower() in p.name.lower() or p.name.lower() in basename.lower())
        ][:3]
        for proc in candidates:
            session = script = None
            try:
                session = device.attach(proc.pid)
                script = session.create_script(_AGENT)
                script.load()
                rpc = script.exports_sync
                if not rpc.hasModule(suffix_for(res.rel_path)):
                    continue
                res.from_process = f"{proc.name} pid {proc.pid}"
                _dump_in_rpc(rpc, path, mi, suffix_for(res.rel_path), res)
                res.skipped = None if res.pages_patched else "loaded but no differing pages"
                break
            except Exception:  # noqa: BLE001
                continue
            finally:
                _safe_unload(script, session)
        util.info(f"  {res.rel_path}: {_status_line(res)}")


__all__ = ["decrypt_app", "find_encrypted_binaries", "scan_bundle_binaries",
           "DecryptError", "DecryptResult", "FileResult"]
