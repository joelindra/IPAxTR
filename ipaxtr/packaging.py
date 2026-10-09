"""Package a local .app directory back into an .ipa (zip with Payload/).

When the bundle was pulled from a device, a sidecar manifest
(util.META_NAME, written by frida_bridge) records POSIX details that the local
filesystem could not hold — symlink targets and unix mode bits. `package_app`
consumes it: symlink entries are written into the zip as real symlinks and the
manifest file itself is excluded from the result.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import zipfile

from . import util


def load_meta(root: str) -> dict | None:
    path = os.path.join(root, util.META_NAME)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            meta = json.load(fh)
        if isinstance(meta, dict):
            return meta
    except (OSError, ValueError):
        pass
    return None


def package_app(
    app_dir: str,
    out_path: str,
    extra_dirs: list[str] | None = None,
) -> str:
    """Zip <app_dir> as Payload/<Name>.app into an IPA.

    extra_dirs: additional top-level entries to include, e.g. SwiftSupport.
    """
    app_dir = os.path.abspath(app_dir)
    if not os.path.isdir(app_dir):
        raise FileNotFoundError(app_dir)
    if not app_dir.endswith(".app"):
        raise ValueError(f"not a .app directory: {app_dir}")

    out_path = os.path.abspath(out_path)
    if os.path.isdir(out_path):
        out_path = os.path.join(out_path, os.path.basename(app_dir)[:-4] + ".ipa")
    if not out_path.endswith(".ipa"):
        out_path += ".ipa"
    util.ensure_dir(os.path.dirname(out_path) or ".")

    with tempfile.TemporaryDirectory(prefix="ipaxtr_pkg_") as tmp:
        payload = os.path.join(tmp, "Payload")
        os.makedirs(payload)
        dest_app = os.path.join(payload, os.path.basename(app_dir))
        shutil.copytree(app_dir, dest_app, symlinks=True, ignore_dangling_symlinks=True)

        meta = load_meta(dest_app)
        manifest_zip = {util.META_NAME: meta} if meta else {}

        for d in extra_dirs or []:
            if os.path.isdir(d):
                dest = os.path.join(tmp, os.path.basename(d))
                if not os.path.exists(dest):
                    shutil.copytree(d, dest, symlinks=True, ignore_dangling_symlinks=True)

        _zip_tree(tmp, out_path, manifest=manifest_zip,
                  app_prefix=f"Payload/{os.path.basename(app_dir)}")
    return out_path


def _merge_meta(meta: dict, rel: str) -> dict | None:
    """Return the manifest entry for app-relative path `rel`, if any."""
    if not meta:
        return None
    out = {}
    for key in ("links", "modes", "rename"):
        table = meta.get(key) or {}
        if rel in table:
            out[key] = table[rel]
    return out or None


def _zip_tree(root: str, out_path: str, manifest: dict | None = None,
              app_prefix: str | None = None) -> None:
    """Store everything under root into a zip; replay manifest symlinks/modes."""
    meta = None
    if manifest and app_prefix:
        meta = manifest.get(util.META_NAME)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for name in sorted(filenames + dirnames):
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                if os.path.basename(rel) == util.META_NAME:
                    continue  # never ship the sidecar
                if os.path.isdir(full) and not os.path.islink(full):
                    continue  # dirs appear implicitly through their files

                # manifest lookup uses app-relative path
                app_rel = None
                if app_prefix and rel.startswith(app_prefix + "/"):
                    app_rel = rel[len(app_prefix) + 1:]
                entry = _merge_meta(meta, app_rel) if app_rel else None
                mode = (entry or {}).get("modes")
                link_target = (entry or {}).get("links")

                if link_target is not None:
                    _write_symlink(zf, rel, link_target, mode)
                elif os.path.islink(full):
                    target = os.readlink(full)
                    _write_symlink(zf, rel, target, mode)
                else:
                    if mode is not None:
                        _write_file(zf, full, rel, mode)
                    else:
                        zf.write(full, rel)


def _write_symlink(zf: zipfile.ZipFile, rel: str, target: str, mode: int | None) -> None:
    prec = mode if mode is not None else 0o120777
    zi = zipfile.ZipInfo(rel)
    zi.create_system = 3  # unix
    zi.external_attr = (prec & 0xFFFF) << 16
    zf.writestr(zi, target)


def _write_file(zf: zipfile.ZipFile, full: str, rel: str, mode: int) -> None:
    zi = zipfile.ZipInfo(rel)
    zi.create_system = 3
    zi.external_attr = (mode & 0xFFFF) << 16
    zi.compress_type = zipfile.ZIP_DEFLATED
    with open(full, "rb") as fh:
        zf.writestr(zi, fh.read())


def restructure(extracted_root: str, out_path: str) -> str:
    """Wrap an already-extracted tree into an IPA.

    If <extracted_root> contains a Payload dir, zip it as-is; otherwise look
    for a single .app inside and package that.
    """
    if os.path.isdir(os.path.join(extracted_root, "Payload")):
        out_path = os.path.abspath(out_path)
        _zip_tree(extracted_root, out_path)
        return out_path
    for entry in os.listdir(extracted_root):
        full = os.path.join(extracted_root, entry)
        if entry.endswith(".app") and os.path.isdir(full):
            return package_app(full, out_path)
    raise ValueError(f"no Payload/ or *.app found in {extracted_root}")
