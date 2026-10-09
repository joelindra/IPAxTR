"""Device-side work: list iPhones, list installed apps, pull bundles.

Everything goes through libimobiledevice's usbmux/lockdown stack via the
`pymobiledevice3` package (v11+ async API). This module presents a small
synchronous facade (each public function runs its own event loop) because the
CLI is synchronous.

Three access routes exist for reading files off a device, in order of how much
they can see:

  1. com.apple.afc2      (jailbroken, AFC2 tweak)  -> full filesystem
  2. SSH/SFTP over iproxy (jailbroken, OpenSSH)    -> full filesystem
  3. house_arrest        (any device, per-app)     -> app DATA container only

The app *bundle* (/var/containers/Bundle/Application/...) is NOT reachable on
a stock device; reading it requires route 1 or 2. Routes always respect the
device's pairing + trust.
"""

from __future__ import annotations

import asyncio
import getpass
import os
import stat as statmod
from dataclasses import dataclass, field

from . import macho, util


class DeviceError(RuntimeError):
    pass


def run(coro):
    """Run an async device coroutine to completion (one loop per operation)."""
    try:
        return asyncio.run(coro)
    except DeviceError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise DeviceError(str(exc)) from exc


# ------------------------------------------------------------- pymd bridge --


def _require_pymd():
    try:
        import pymobiledevice3  # noqa: F401
    except ImportError as exc:
        raise DeviceError(
            "pymobiledevice3 is not installed. Run: pip install -r requirements.txt"
        ) from exc


# ------------------------------------------------------------- devices ------


@dataclass
class Device:
    serial: str
    connection_type: str = "usb"
    name: str | None = None
    model: str | None = None
    ios: str | None = None

    def __str__(self):
        bits = [self.name or "(unnamed)", self.model or "?", f"iOS {self.ios or '?'}"]
        return f"{self.serial}  [{self.connection_type}]  " + "  ".join(bits)


async def _list_devices_async() -> list[Device]:
    from pymobiledevice3.usbmux import list_devices as _ld

    raw = await _ld()
    out = []
    for d in raw:
        serial = getattr(d, "serial", None) or getattr(d, "udid", None)
        if not serial:
            continue
        conn = str(getattr(d, "connection_type", "usb")).lower()
        out.append(Device(serial=str(serial), connection_type=conn))
    return out


def list_devices() -> list[Device]:
    _require_pymd()
    try:
        return run(_list_devices_async())
    except DeviceError:
        raise
    except Exception as exc:
        raise DeviceError(f"cannot talk to usbmuxd: {exc}") from exc


def pick_device(udid: str | None = None) -> str:
    devices = list_devices()
    if not devices:
        raise DeviceError(
            "no iPhone detected. Plug it in via USB, unlock it, and tap 'Trust This Computer'."
        )
    if udid:
        for d in devices:
            if d.serial == udid:
                return udid
        raise DeviceError(
            f"device {udid} not found (connected: {[d.serial for d in devices]})"
        )
    return devices[0].serial


# -------------------------------------------------------------- lockdown ----


async def _create_lockdown(serial: str | None, autopair: bool = True):
    from pymobiledevice3.lockdown import create_using_usbmux

    return await create_using_usbmux(serial=serial, autopair=autopair)


class lockdown_session:
    """Async context manager around a lockdown client (used inside run())."""

    def __init__(self, udid: str | None = None, autopair: bool = True):
        self.udid = udid
        self.autopair = autopair
        self.ld = None

    async def __aenter__(self):
        serial = self.udid
        if serial is None:
            devices = await _list_devices_async()
            if not devices:
                raise DeviceError(
                    "no iPhone detected. Plug it in via USB, unlock it, and tap "
                    "'Trust This Computer'."
                )
            serial = devices[0].serial
        return await _create_lockdown(serial, self.autopair)

    async def __aexit__(self, *exc):
        return False


def resolve_udid(udid: str | None) -> str:
    """Return a concrete UDID: the given one, or the first connected device.

    Synchronous helper for user-facing code; async internals must not call it
    (lockdown_session resolves the device itself to avoid nested event loops).
    """
    _require_pymd()
    return pick_device(udid)


def _lockdown(udid: str | None) -> lockdown_session:
    # NOTE: keep udid as-is (may be None); lockdown_session.__aenter__ resolves
    # it inside the running loop. Never call the sync list_devices() here.
    return lockdown_session(udid)


async def _device_summary_async(udid: str | None) -> Device:
    async with _lockdown(udid) as ld:
        serial = getattr(ld, "udid", None) or getattr(ld, "serial", None)

        async def gv(key):
            try:
                return await ld.get_value(key=key)
            except TypeError:
                return await ld.get_value(key)

        return Device(
            serial=str(serial),
            name=await gv("DeviceName"),
            model=await gv("ProductType"),
            ios=await gv("ProductVersion"),
        )


def device_summary(udid: str | None = None) -> Device:
    _require_pymd()
    try:
        return run(_device_summary_async(udid))
    except DeviceError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise DeviceError(
            f"cannot open a lockdown session (is the device unlocked and trusted?): {exc}"
        ) from exc


# --------------------------------------------------------------- apps ------


@dataclass
class InstalledApp:
    bundle_id: str
    name: str = ""
    version: str = ""
    build: str = ""
    path: str = ""
    app_type: str = "User"
    minimum_os: str = ""
    disk_usage: int = 0

    @property
    def is_system(self) -> bool:
        return self.app_type in ("System", "Internal")


def _scan_jailbreak_apps(udid: str | None = None) -> list[InstalledApp]:
    """Scan rootless jailbreak apps in /var/jb/Applications if accessible via frida."""
    from . import frida_bridge, util

    jb_apps: list[InstalledApp] = []
    try:
        with frida_bridge.open_bridge(udid) as bridge:
            for p in ("/var/jb/Applications", "/jb/Applications"):
                try:
                    entries = bridge.ls(p)
                    for e in entries:
                        if e.name.endswith(".app"):
                            pl_raw = bridge.read_all(f"{p}/{e.name}/Info.plist", max_size=512 * 1024)
                            pl = util.plist_from_bytes(pl_raw) or {}
                            jb_apps.append(
                                InstalledApp(
                                    bundle_id=pl.get("CFBundleIdentifier") or e.name[:-4],
                                    name=pl.get("CFBundleDisplayName") or pl.get("CFBundleName") or e.name[:-4],
                                    version=pl.get("CFBundleShortVersionString") or pl.get("CFBundleVersion") or "-",
                                    path=f"{p}/{e.name}",
                                    app_type="Jailbreak",
                                )
                            )
                except Exception:
                    pass
    except Exception:
        pass
    return jb_apps


async def _list_apps_async(udid: str | None, app_type: str) -> list[InstalledApp]:
    from pymobiledevice3.services.installation_proxy import InstallationProxyService

    raw_type = app_type
    if app_type in ("UserFacing", "Installed", "AppleBundle", "All"):
        raw_type = "Any"

    async with _lockdown(udid) as ld:
        svc = InstallationProxyService(ld)
        async with svc:
            raw = await svc.get_apps(application_type=raw_type)
    apps = []
    for bundle_id, info in (raw or {}).items():
        if not isinstance(info, dict):
            continue
        p = info.get("Path") or info.get("BundleContainer") or ""
        t = info.get("ApplicationType") or "User"
        is_bundle = "/private/var/containers/Bundle/Application" in p

        if t == "User":
            cat = "User"
        elif is_bundle:
            cat = "Apple"
        else:
            cat = "System"

        if app_type in ("UserFacing", "Installed"):
            if cat not in ("User", "Apple"):
                continue
        elif app_type == "User" and cat != "User":
            continue
        elif app_type == "AppleBundle" and cat != "Apple":
            continue
        elif app_type == "System" and cat == "User":
            continue

        apps.append(
            InstalledApp(
                bundle_id=bundle_id,
                name=info.get("CFBundleDisplayName") or info.get("CFBundleName") or "",
                version=info.get("CFBundleShortVersionString") or "",
                build=info.get("CFBundleVersion") or "",
                path=p,
                app_type=cat,
                minimum_os=info.get("MinimumOSVersion") or "",
                disk_usage=int(info.get("StaticDiskUsage") or 0),
            )
        )

    # Append rootless jailbreak apps if applicable
    if app_type in ("UserFacing", "Installed", "All", "Any", "Jailbreak"):
        jb = _scan_jailbreak_apps(udid)
        known_ids = {a.bundle_id for a in apps}
        for j in jb:
            if j.bundle_id not in known_ids:
                apps.append(j)

    apps.sort(key=lambda a: (a.app_type not in ("User", "Jailbreak"), a.name.lower()))
    return apps


def list_installed_apps(udid: str | None = None, app_type: str = "UserFacing") -> list[InstalledApp]:
    _require_pymd()
    try:
        return run(_list_apps_async(udid, app_type))
    except DeviceError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise DeviceError(
            f"installation_proxy failed: {exc} (unlock the device and make sure it is paired)"
        ) from exc


def find_app(udid: str | None, bundle_id: str, apps: list[InstalledApp] | None = None):
    apps = apps if apps is not None else list_installed_apps(udid, app_type="Any")
    app = next((a for a in apps if a.bundle_id == bundle_id), None)
    if app:
        return app
    matches = [a for a in apps if bundle_id.lower() in a.bundle_id.lower()]
    if matches:
        util.info(f"matching: {matches[0].bundle_id}")
        return matches[0]
    raise DeviceError(f"app '{bundle_id}' is not installed on this device")


# ------------------------------------------------------------ AFC routes ---


async def _afc_pull_dir(afc, remote_dir: str, local_dir: str, on_file=None) -> int:
    """Recursive pull through an AfcService (used for afc2 and house_arrest)."""
    util.ensure_dir(local_dir)
    count = 0
    for name in await afc.listdir(remote_dir):
        r = f"{remote_dir.rstrip('/')}/{name}"
        l = os.path.join(local_dir, name)
        try:
            if await afc.isdir(r):
                count += await _afc_pull_dir(afc, r, l, on_file)
                continue
        except Exception:  # noqa: BLE001  (not a dir / stat failed -> try as file)
            pass
        try:
            data = await afc.get_file_contents(r)
        except Exception as exc:  # noqa: BLE001
            raise DeviceError(f"cannot read {r}: {exc}") from exc
        if isinstance(data, bytes):
            with open(l, "wb") as fh:
                fh.write(data)
            count += 1
            if on_file:
                on_file(r, len(data))
    return count


async def _pull_afc_async(
    udid: str | None, service_name: str, remote_app_path: str, local_dir: str, on_file=None
) -> int:
    from pymobiledevice3.services.afc import AfcService

    async with _lockdown(udid) as ld:
        svc = AfcService(ld, service_name=service_name)
        async with svc:
            return await _afc_pull_dir(svc, remote_app_path, local_dir, on_file)


def pull_bundle_afc(
    udid: str | None, remote_app_path: str, local_dir: str, on_file=None
) -> int:
    """Route 1: full-filesystem AFC2 (jailbroken devices only)."""
    _require_pymd()
    try:
        return run(_pull_afc_async(udid, "com.apple.afc2", remote_app_path, local_dir, on_file))
    except DeviceError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise DeviceError(
            "com.apple.afc2 unavailable — this device is not jailbroken (or the "
            "AFC2 tweak is missing). App bundles cannot be read on stock iOS. "
            f"Original error: {exc}"
        ) from exc


async def _pull_house_arrest_async(
    udid: str | None, bundle_id: str, local_dir: str, on_file=None
) -> int:
    from pymobiledevice3.services.house_arrest import HouseArrestService

    async with _lockdown(udid) as ld:
        svc = await HouseArrestService.create(ld, bundle_id, documents_only=False)
        async with svc:
            return await _afc_pull_dir(svc, "/", local_dir, on_file)


def pull_data_container_afc(
    udid: str | None, bundle_id: str, local_dir: str, on_file=None
) -> int:
    """Route 3: house_arrest — the app's DATA container (works on stock devices)."""
    _require_pymd()
    try:
        return run(_pull_house_arrest_async(udid, bundle_id, local_dir, on_file))
    except DeviceError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise DeviceError(f"house_arrest failed for {bundle_id}: {exc}") from exc


async def _cryptid_afc_async(
    udid: str | None, remote_binary: str, service_name: str
) -> macho.MachoInfo:
    """Read the header of a remote binary through an AFC service (afc2/jailbreak)."""
    import tempfile

    from pymobiledevice3.services.afc import AfcService

    async with _lockdown(udid) as ld:
        svc = AfcService(ld, service_name=service_name)
        async with svc:
            data = await svc.get_file_contents(remote_binary)
    with tempfile.NamedTemporaryFile(suffix=".macho", delete=False) as tmp:
        tmp.write(data[: 1024 * 1024])  # header + load commands are in the first MB
        tmp_path = tmp.name
    try:
        return macho.analyze_file(tmp_path)
    finally:
        os.unlink(tmp_path)


def check_cryptid_over_afc(
    udid: str | None, remote_binary: str, service_name: str = "com.apple.afc2"
) -> macho.MachoInfo:
    """Read a remote binary's crypt id over AFC (afc2 = jailbroken devices)."""
    _require_pymd()
    try:
        return run(_cryptid_afc_async(udid, remote_binary, service_name))
    except DeviceError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise DeviceError(f"AFC read failed for {remote_binary}: {exc}") from exc


# ------------------------------------------------------------- SSH route ---


def _connect_sftp(target: str, user: str, password: str | None, key: str | None):
    try:
        import paramiko
    except ImportError as exc:
        raise DeviceError("paramiko is required for SSH pulls: pip install paramiko") from exc
    if ":" in target:
        host, port = target.rsplit(":", 1)
    else:
        host, port = target, "2222"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=int(port),
        username=user,
        password=password,
        key_filename=key,
        timeout=15,
        banner_timeout=15,
        auth_timeout=15,
    )
    return client, client.open_sftp()


def pull_bundle_ssh(
    remote_app_path: str,
    local_dir: str,
    target: str = "127.0.0.1:2222",
    user: str = "mobile",
    password: str | None = None,
    key: str | None = None,
    on_file=None,
) -> int:
    """Route 2: SFTP over a usbmux-forwarded SSH port (jailbroken devices)."""
    client, sftp = _connect_sftp(target, user, password, key)
    try:
        return _sftp_pull_dir(sftp, remote_app_path, local_dir, on_file)
    finally:
        sftp.close()
        client.close()


def _sftp_pull_dir(sftp, remote_dir: str, local_dir: str, on_file=None) -> int:
    util.ensure_dir(local_dir)
    count = 0
    for item in sftp.listdir_attr(remote_dir):
        r = f"{remote_dir.rstrip('/')}/{item.filename}"
        l = os.path.join(local_dir, item.filename)
        if statmod.S_ISLNK(item.st_mode):
            target = sftp.readlink(r)
            try:
                os.symlink(target, l)
                continue
            except OSError:
                pass  # symlink needs privileges on Windows; copy content instead
        if statmod.S_ISDIR(item.st_mode):
            count += _sftp_pull_dir(sftp, r, l, on_file)
        else:
            sftp.get(r, l)
            count += 1
            if on_file:
                on_file(r, item.st_size)
    return count


def check_cryptid_over_ssh(
    binary_path: str,
    target: str = "127.0.0.1:2222",
    user: str = "mobile",
    password: str | None = None,
    key: str | None = None,
) -> macho.MachoInfo:
    """Read only the Mach-O header of a remote binary to get its crypt id."""
    import struct
    import tempfile

    client, sftp = _connect_sftp(target, user, password, key)
    try:
        with sftp.open(binary_path, "rb") as fh:
            head = fh.read(4096)
            if len(head) < 4:
                raise DeviceError(f"cannot read {binary_path}")
            offset = 0
            magic, = struct.unpack_from("<I", head, 0)
            if magic in (macho.FAT_MAGIC, macho.FAT_MAGIC_64):
                step = 20 if magic == macho.FAT_MAGIC else 32
                fmt = ">iiIII" if magic == macho.FAT_MAGIC else ">iiIIQ"
                offset = struct.unpack_from(fmt, head, 8)[3]
            fh.seek(offset)
            blob = fh.read(65536)
        with tempfile.NamedTemporaryFile(suffix=".macho", delete=False) as tmp:
            tmp.write(blob + b"\x00" * 16)
            tmp_path = tmp.name
        try:
            return macho.analyze_file(tmp_path)
        finally:
            os.unlink(tmp_path)
    finally:
        sftp.close()
        client.close()


def ask_password() -> str | None:
    try:
        return getpass.getpass("SSH password: ")
    except Exception:  # noqa: BLE001
        return None


# ------------------------------------------------------------ frida route --


def pull_bundle_frida(
    udid: str | None, remote_app_path: str, local_dir: str, on_file=None
) -> int:
    """Route 4: Frida (jailbroken, frida-server as root) — full filesystem."""
    from . import frida_bridge

    try:
        with frida_bridge.open_bridge(udid) as bridge:
            return bridge.pull_dir(remote_app_path, local_dir, on_file=on_file)
    except frida_bridge.FridaError as exc:
        # surface as a routing error so auto mode can try the next route
        raise DeviceError(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise DeviceError(f"frida pull failed: {exc}") from exc


def check_cryptid_over_frida(udid: str | None, remote_binary: str) -> "macho.MachoInfo":
    """Read a remote binary's header through a root frida-server."""
    import os
    import tempfile

    from . import frida_bridge

    with frida_bridge.open_bridge(udid) as bridge:
        head = bridge.read_at(remote_binary, 0, 2 * 1024 * 1024)
    if not head:
        raise DeviceError(f"cannot read {remote_binary} over frida")
    with tempfile.NamedTemporaryFile(suffix=".macho", delete=False) as tmp:
        tmp.write(head)
        tmp_path = tmp.name
    try:
        return macho.analyze_file(tmp_path)
    finally:
        os.unlink(tmp_path)
