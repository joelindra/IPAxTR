"""Offline tests: no device and no third-party packages required.

Run:  python -m pytest tests -q     (or: python tests/test_offline.py)
"""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ipaxtr import ipa, macho, packaging, util  # noqa: E402


def _fake_macho(cryptid: int, min_os: int = 0x0E0000,
                text_fileoff: int = 0, text_filesize: int = 0x3000) -> bytes:
    """Minimal arm64 Mach-O with LC_SEGMENT_64(__TEXT) + LC_ENCRYPTION_INFO_64."""
    cmds = b""

    # LC_SEGMENT_64 (0x19): cmd, cmdsize, segname[16], vmaddr, vmsize,
    #                      fileoff, filesize, maxprot, initprot, nsects, flags
    segname = b"__TEXT" + b"\x00" * 10
    cmds += struct.pack("<II16sQQQQiiII", 0x19, 72, segname,
                        0x100000000, text_filesize, text_fileoff, text_filesize,
                        5, 5, 0, 0)

    # LC_VERSION_MIN_IPHONEOS (0x25): cmd, cmdsize, version, sdk
    cmds += struct.pack("<IIII", 0x25, 16, min_os, min_os)

    # LC_ENCRYPTION_INFO_64 (0x2C): cmd, cmdsize, cryptoff, cryptsize, cryptid, pad
    cmds += struct.pack("<IIIIII", 0x2C, 24, text_fileoff + 0x1000, 0x1000, cryptid, 0)

    ncmds = 3
    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,          # magic
        0x0100000C,          # CPU_TYPE_ARM64
        0,                   # cpusubtype
        2,                   # MH_EXECUTE
        ncmds,
        len(cmds),
        0,                   # flags
        0,                   # reserved
    )
    body = header + cmds
    body += b"\x00" * max(0, text_filesize - len(body))
    return body


def _fake_app(tmp: str, cryptid: int) -> str:
    app = os.path.join(tmp, "Demo.app")
    os.makedirs(app, exist_ok=True)
    with open(os.path.join(app, "Demo"), "wb") as fh:
        fh.write(_fake_macho(cryptid))
    with open(os.path.join(app, "Info.plist"), "wb") as fh:
        import plistlib

        plistlib.dump(
            {
                "CFBundleIdentifier": "com.example.demo",
                "CFBundleName": "Demo",
                "CFBundleDisplayName": "Demo App",
                "CFBundleExecutable": "Demo",
                "CFBundleShortVersionString": "1.2.3",
                "CFBundleVersion": "456",
                "MinimumOSVersion": "14.0",
                "DTPlatformName": "iphoneos",
            },
            fh,
        )
    with open(os.path.join(app, "Resource.txt"), "w") as fh:
        fh.write("hello")
    return app


def test_macho_encrypted():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "enc")
        with open(p, "wb") as fh:
            fh.write(_fake_macho(1))
        mi = macho.analyze_file(p)
        assert mi.is_encrypted
        assert mi.crypt_id == 1
        assert mi.crypt_off == 0x1000
        assert mi.min_os == "14.0.0"
        assert "ENCRYPTED" in macho.cryptid_description(mi)
        # segment parsing
        text = mi.text_segment()
        assert text is not None and text.name == "__TEXT"
        assert text.fileoff == 0 and text.filesize == 0x3000


def test_macho_plain():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "plain")
        with open(p, "wb") as fh:
            fh.write(_fake_macho(0))
        mi = macho.analyze_file(p)
        assert not mi.is_encrypted


def test_decrypt_patch_cryptid():
    from ipaxtr import decrypt

    blob = bytearray(_fake_macho(1))
    assert decrypt._patch_cryptid(blob)
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "patched")
        with open(p, "wb") as fh:
            fh.write(blob)
        mi = macho.analyze_file(p)
        assert not mi.is_encrypted
        assert mi.crypt_id == 0


def test_find_encrypted_binaries():
    from ipaxtr import decrypt

    with tempfile.TemporaryDirectory() as tmp:
        app = _fake_app(tmp, cryptid=1)
        os.makedirs(os.path.join(app, "Frameworks", "X.framework"), exist_ok=True)
        with open(os.path.join(app, "Frameworks", "X.framework", "X"), "wb") as fh:
            fh.write(_fake_macho(1, text_filesize=0x2000))
        with open(os.path.join(app, "Frameworks", "Y.framework"), "wb") as fh:
            pass  # not a Mach-O
        found = decrypt.find_encrypted_binaries(app)
        rels = sorted(os.path.relpath(p, app).replace(os.sep, "/") for p, _ in found)
        assert rels == ["Demo", "Frameworks/X.framework/X"], rels


def test_meta_manifest_roundtrip():
    """Sidecar manifest restores symlinks (and is stripped) on package."""
    from ipaxtr import util as u

    with tempfile.TemporaryDirectory() as tmp:
        app = _fake_app(tmp, cryptid=0)
        # fabricate a pull-produced symlink that Windows could not create
        link_rel = "Resources/link.txt"
        os.makedirs(os.path.join(app, "Resources"), exist_ok=True)
        with open(os.path.join(app, "Resources", "link.txt"), "w") as fh:
            fh.write("")  # placeholder (would be a symlink on posix)
        meta = {
            "links": {link_rel: "Payload/whatever"},
            "modes": {"Demo": 0o100755, link_rel: 0o120777},
            "rename": {},
        }
        import json

        with open(os.path.join(app, u.META_NAME), "w") as fh:
            json.dump(meta, fh)

        ipa_path = packaging.package_app(app, os.path.join(tmp, "Meta.ipa"))
        with zipfile.ZipFile(ipa_path) as zf:
            names = zf.namelist()
            assert u.META_NAME not in "".join(names)
            zi = zf.getinfo("Payload/Demo.app/Resources/link.txt")
            assert (zi.external_attr >> 16) & 0xA000 == 0xA000, "not a symlink entry"
            assert zf.read(zi) == b"Payload/whatever"
            demo = zf.getinfo("Payload/Demo.app/Demo")
            assert (demo.external_attr >> 16) & 0o111, "exec bit lost"


def test_pack_inspect_unpack_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        app = _fake_app(tmp, cryptid=0)
        ipa_path = packaging.package_app(app, os.path.join(tmp, "Demo.ipa"))
        assert os.path.isfile(ipa_path)

        with zipfile.ZipFile(ipa_path) as zf:
            names = zf.namelist()
        assert any(n.startswith("Payload/Demo.app/") for n in names)
        assert "Payload/Demo.app/Demo" in names

        info = ipa.inspect(ipa_path)
        assert info.bundle_id == "com.example.demo"
        assert info.version == "1.2.3"
        assert info.build == "456"
        assert info.encrypted is False
        assert info.executable == "Demo"

        out = ipa.unpack(ipa_path, os.path.join(tmp, "out"))
        assert os.path.isfile(os.path.join(out, "Payload", "Demo.app", "Demo"))

        # re-pack the extracted folder should give the same shape again
        rebuilt = packaging.restructure(out, os.path.join(tmp, "rebuilt.ipa"))
        info2 = ipa.inspect(rebuilt)
        assert info2.bundle_id == "com.example.demo"


def test_inspect_encrypted_ipa():
    with tempfile.TemporaryDirectory() as tmp:
        app = _fake_app(tmp, cryptid=1)
        ipa_path = packaging.package_app(app, os.path.join(tmp, "Enc.ipa"))
        info = ipa.inspect(ipa_path)
        assert info.encrypted is True
        assert info.crypt and "ENCRYPTED" in info.crypt


def test_provision_decoding():
    import base64
    import plistlib

    payload = plistlib.dumps({"TeamName": "Demo Team", "ExpirationDate": 0})
    # CMS-ish wrapper with raw plist inside
    blob = b"\x30\x82\x03\xeeSMIMEv2" + payload
    decoded = util.decode_provision(blob)
    assert isinstance(decoded, dict)
    assert decoded["TeamName"] == "Demo Team"


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  [ OK ] {name}")
            except AssertionError as exc:
                failures += 1
                print(f"  [FAIL] {name}: {exc}")
    sys.exit(1 if failures else 0)
