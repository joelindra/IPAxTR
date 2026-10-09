"""Read an existing .ipa file: info, encryption status, unpack."""

from __future__ import annotations

import os
import posixpath
import tempfile
import zipfile
from dataclasses import dataclass, field

from . import macho, util


@dataclass
class IpaInfo:
    path: str
    size: int
    bundle_id: str | None = None
    name: str | None = None
    version: str | None = None
    build: str | None = None
    min_os: str | None = None
    platform: str | None = None
    executable: str | None = None
    crypt: str | None = None
    encrypted: bool | None = None
    signer: str | None = None
    team: str | None = None
    provisioning_expiry: str | None = None
    entries: int = 0
    app_root: str | None = None
    extensions: list = field(default_factory=list)


def _first_payload_app(zf: zipfile.ZipFile) -> str | None:
    for name in zf.namelist():
        parts = name.split("/")
        if len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app"):
            return posixpath.join(parts[0], parts[1])
    return None


def inspect(path: str) -> IpaInfo:
    """Parse metadata + encryption state of an IPA without unpacking it."""
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    info = IpaInfo(path=path, size=os.path.getsize(path))
    with zipfile.ZipFile(path) as zf:
        info.entries = len(zf.namelist())
        app_root = _first_payload_app(zf)
        if not app_root:
            raise ValueError("no Payload/*.app directory found inside the IPA")
        info.app_root = app_root

        plist = util.plist_from_bytes(zf.read(posixpath.join(app_root, "Info.plist")))
        plist = plist or {}
        info.bundle_id = plist.get("CFBundleIdentifier")
        info.name = plist.get("CFBundleDisplayName") or plist.get("CFBundleName")
        info.version = plist.get("CFBundleShortVersionString")
        info.build = plist.get("CFBundleVersion")
        info.min_os = plist.get("MinimumOSVersion")
        info.platform = plist.get("DTPlatformName")
        info.executable = plist.get("CFBundleExecutable")

        # list nested app extensions and frameworks
        exts = set()
        for name in zf.namelist():
            low = name.lower()
            if "plugins/" in low and low.endswith(".appex/info.plist"):
                exts.add(name)
        info.extensions = sorted(exts)

        # signer / team from embedded provisioning profile
        try:
            prov = util.decode_provision(
                zf.read(posixpath.join(app_root, "embedded.mobileprovision"))
            )
        except KeyError:
            prov = None
        if isinstance(prov, dict):
            info.team = prov.get("TeamName")
            expiry = prov.get("ExpirationDate")
            if expiry is not None:
                info.provisioning_expiry = str(expiry)

        # FairPlay status: analyse the main executable header only (load
        # commands live in the first MB; avoids reading 100s of MB)
        exe_name = info.executable
        if not exe_name:
            base = posixpath.basename(app_root)[:-4]
            exe_name = base
        try:
            with zf.open(posixpath.join(app_root, exe_name)) as fh:
                blob = fh.read(1024 * 1024)
            with tempfile.NamedTemporaryFile(suffix=".macho", delete=False) as tmp:
                tmp.write(blob)
                tmp_path = tmp.name
            try:
                mi = macho.analyze_file(tmp_path)
            finally:
                os.unlink(tmp_path)
            info.crypt = macho.cryptid_description(mi)
            info.encrypted = mi.is_encrypted
            info.min_os = info.min_os or mi.min_os
            info.platform = info.platform or mi.platform
        except Exception as exc:  # binary missing or not Mach-O
            info.crypt = f"could not read executable ({exc.__class__.__name__})"
    return info


def unpack(path: str, out_dir: str | None = None) -> str:
    """Extract an IPA. Returns the directory that contains Payload/."""
    path = os.path.abspath(path)
    if out_dir is None:
        out_dir = os.path.splitext(path)[0] + "_unpacked"
    util.ensure_dir(out_dir)
    with zipfile.ZipFile(path) as zf:
        zf.extractall(out_dir)
    return out_dir
