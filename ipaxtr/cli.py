"""Command line interface for IPAxTR.

Usage examples (run from the project root):

    python -m ipaxtr devices
    python -m ipaxtr apps
    python -m ipaxtr info 00008110-001A2C3E4F5G6H7I
    python -m ipaxtr check  MyApp.ipa
    python -m ipaxtr check  com.example.app --device
    python -m ipaxtr unpack MyApp.ipa -o out/
    python -m ipaxtr pack   out/Payload/MyApp.app -o rebuilt.ipa
    python -m ipaxtr pull   com.example.app --method ssh --ssh 127.0.0.1:2222
    python -m ipaxtr pull   com.example.app --method afc2
    python -m ipaxtr extract com.example.app --method ssh --out ipas/
    python -m ipaxtr decrypt com.example.app --app-dir work/com.example.app --i-own-this-build
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__, ipa as ipa_mod, packaging, util
from . import device as dev


def _banner():
    print(util.bold("=" * 72))
    print(util.bold("  IPAxTR  ·  IPA extractor / inspector for iPhone + local files"))
    print(util.bold("=" * 72))


def _no_device_help():
    print()
    util.warn("Checklist when no device is found:")
    print("    1. iPhone unlocked, plugged in with a data cable (not charge-only)")
    print("    2. Tap 'Trust This Computer' and enter the passcode")
    print("    3. Windows: install the Apple Devices / iTunes driver (or run usbmuxd)")
    print("    4. pip install -r requirements.txt  (pymobiledevice3 powers usbmux)")


# ---------------------------------------------------------------- devices ----


def cmd_devices(args) -> int:
    try:
        devices = dev.list_devices()
    except dev.DeviceError as exc:
        util.err(str(exc))
        _no_device_help()
        return 2
    if not devices:
        util.warn("no devices detected")
        _no_device_help()
        return 1
    print()
    for d in devices:
        try:
            info = dev.device_summary(d.serial)
            print(f"  {util.green('●')} {info}")
        except Exception:  # noqa: BLE001
            print(f"  {util.green('●')} {d.serial}  [{d.connection_type}] (info unavailable — unlock to pair)")
    print()
    return 0


def cmd_info(args) -> int:
    try:
        d = dev.device_summary(args.device)
    except dev.DeviceError as exc:
        util.err(str(exc))
        _no_device_help()
        return 2
    print()
    print(f"  {'UDID':10} {d.serial}")
    print(f"  {'Name':10} {d.name}")
    print(f"  {'Model':10} {d.model}")
    print(f"  {'iOS':10} {d.ios}")
    print()
    return 0


# ------------------------------------------------------------------ apps ----


def cmd_apps(args) -> int:
    try:
        apps = dev.list_installed_apps(args.device, app_type=args.type)
    except dev.DeviceError as exc:
        util.err(str(exc))
        _no_device_help()
        return 2
    if not apps:
        util.warn("no apps returned")
        return 1
    filt = (args.filter or "").lower()
    if filt:
        apps = [a for a in apps if filt in a.bundle_id.lower() or filt in a.name.lower()]

    if not args.verbose:
        for a in apps:
            kind = util.dim("sys") if a.is_system else util.green("usr")
            print(f"  {kind}  {a.name:<32.32} {a.bundle_id:<44.44} {a.version}")
        print(f"\n  {len(apps)} app(s). Use -v for full paths.")
    else:
        for a in apps:
            print(f"\n  {util.bold(a.name)}  ({a.bundle_id})")
            print(f"    version : {a.version} (build {a.build})")
            print(f"    path    : {a.path}")
            print(f"    type    : {a.app_type}   minOS: {a.minimum_os}")
    print()
    return 0


# ----------------------------------------------------------------- check ----


def cmd_check(args) -> int:
    if args.device:
        return _check_device_app(args)
    if not args.file:
        util.err("give a file (.ipa) or --device with a bundle id")
        return 2
    return _check_ipa_file(args.file, verbose=args.verbose)


def _check_ipa_file(path: str, verbose: bool) -> int:
    try:
        info = ipa_mod.inspect(path)
    except Exception as exc:  # noqa: BLE001
        util.err(f"cannot read {path}: {exc}")
        return 2
    print()
    print(f"  {util.bold(info.name or os.path.basename(path))}")
    print(f"    file      : {info.path}  ({util.human_size(info.size)})")
    print(f"    bundle id : {info.bundle_id}")
    print(f"    version   : {info.version} (build {info.build})  minOS {info.min_os}")
    print(f"    platform  : {info.platform}   entries: {info.entries}")
    if info.team:
        print(f"    signer    : {info.team}  (profile expires {info.provisioning_expiry})")
    if info.extensions:
        print(f"    extensions: {len(info.extensions)} appex")
    crypt_line = info.crypt or "unknown"
    if info.encrypted:
        print(f"    binary    : {util.red(crypt_line)}")
        print()
        util.warn("This IPA contains a FairPlay-encrypted binary. It will only run")
        print("           on the device/account it was downloaded with (and only")
        print("           after the decryption step on a jailbroken device).")
    else:
        print(f"    binary    : {util.green(crypt_line)}")
    print()
    return 0


def _check_device_app(args) -> int:
    if not args.file:
        util.err("--device needs a bundle id, e.g.  check com.example.app --device")
        return 2
    bundle_id = args.file
    try:
        apps = dev.list_installed_apps(args.udid, app_type="Any")
    except dev.DeviceError as exc:
        util.err(str(exc))
        _no_device_help()
        return 2
    app = next((a for a in apps if a.bundle_id == bundle_id), None)
    if not app:
        matches = [a for a in apps if bundle_id.lower() in a.bundle_id.lower()]
        if not matches:
            util.err(f"app '{bundle_id}' is not installed on this device")
            return 1
        app = matches[0]
        util.info(f"matching: {app.bundle_id}")

    print()
    print(f"  {util.bold(app.name)}  ({app.bundle_id})")
    print(f"    installed at : {app.path}")
    print(f"    version      : {app.version} (build {app.build})  minOS {app.minimum_os}")

    if args.frida:
        util.step("reading crypt id over frida")
        try:
            exe = os.path.basename(app.path.rstrip("/"))
            if exe.endswith(".app"):
                exe = exe[:-4]
            mi = dev.check_cryptid_over_frida(args.udid, f"{app.path}/{exe}")
            _print_crypt(mi)
        except Exception as exc:  # noqa: BLE001
            util.err(f"frida check failed: {exc}")
            return 1
    elif args.ssh:
        util.step("reading crypt id over SSH")
        try:
            exe = os.path.basename(app.path.rstrip("/"))
            if exe.endswith(".app"):
                exe = exe[:-4]
            password = args.password or dev.ask_password()
            mi = dev.check_cryptid_over_ssh(
                f"{app.path}/{exe}",
                target=args.ssh, user=args.ssh_user, password=password, key=args.key,
            )
            _print_crypt(mi)
        except Exception as exc:  # noqa: BLE001
            util.err(f"SSH check failed: {exc}")
            return 1
    else:
        util.info("crypt-id check needs filesystem access on the device.")
        util.info("Re-run with --frida (jailbroken + frida-server) or --ssh host:port.")
    print()
    return 0


def _print_crypt(mi) -> None:
    from . import macho

    print(f"    binary       : {macho.cryptid_description(mi)}")
    print(f"    cpu          : {macho.cpu_name(mi.cpu_type)}"
          f"{'  (fat, {} slices)'.format(mi.n_slices) if mi.is_fat else ''}")
    if mi.min_os:
        print(f"    min os       : {mi.platform} {mi.min_os}")


# ---------------------------------------------------------------- unpack ----


def cmd_unpack(args) -> int:
    path = args.file
    if not path:
        util.err("give the .ipa path")
        return 2
    try:
        out = ipa_mod.unpack(path, args.out)
    except Exception as exc:  # noqa: BLE001
        util.err(f"unpack failed: {exc}")
        return 2
    util.ok(f"unpacked to {out}")
    return 0


# ------------------------------------------------------------------ pack ----


def cmd_pack(args) -> int:
    if not args.path:
        util.err("give a .app directory (or a folder containing Payload/)")
        return 2
    path = args.path
    try:
        if os.path.isdir(path) and not path.endswith(".app"):
            out = packaging.restructure(path, args.out or "Unpacked.ipa")
        else:
            out = packaging.package_app(path, args.out or "Repacked.ipa")
    except Exception as exc:  # noqa: BLE001
        util.err(f"pack failed: {exc}")
        return 2
    util.ok(f"wrote {out}  ({util.human_size(os.path.getsize(out))})")
    return 0


# ------------------------------------------------------------------ pull ----


def _find_app(args, bundle_id: str):
    apps = dev.list_installed_apps(args.device)
    app = next((a for a in apps if a.bundle_id == bundle_id), None)
    if not app:
        matches = [a for a in apps if bundle_id.lower() in a.bundle_id.lower()]
        if not matches:
            raise dev.DeviceError(f"app '{bundle_id}' not found on the device")
        app = matches[0]
        util.info(f"matching: {app.bundle_id}")
    if not app.path:
        raise dev.DeviceError("device did not report a bundle path for this app")
    return app


def _do_pull(args, bundle_id: str):
    """Pull an app bundle off the device using the chosen route.

    Returns (app, local_app_dir).
    """
    app = _find_app(args, bundle_id)
    app_name = app.path.rstrip("/").split("/")[-1] or f"{bundle_id}.app"
    local_app_dir = os.path.join(args.work or "work", app_name)

    def on_file(remote, size):
        if args.verbose:
            print(f"      {util.dim(os.path.basename(remote))}  {util.human_size(size)}")

    util.step(f"pulling {app.name or bundle_id}  ({app.app_type})")
    util.info(f"device path : {app.path}")
    util.info(f"local path  : {local_app_dir}")

    if args.method == "ssh":
        if not args.ssh:
            util.err("--method ssh needs --ssh host:port (e.g. 127.0.0.1:2222 via a forward)")
            return None, None
        password = args.password
        if not args.key and password is None:
            password = dev.ask_password()
        count = dev.pull_bundle_ssh(
            app.path, local_app_dir,
            target=args.ssh, user=args.ssh_user, password=password, key=args.key,
            on_file=on_file,
        )
    elif args.method == "afc2":
        count = dev.pull_bundle_afc(args.device, app.path, local_app_dir, on_file=on_file)
    elif args.method == "frida":
        count = dev.pull_bundle_frida(args.device, app.path, local_app_dir, on_file=on_file)
    elif args.method == "data":
        util.warn("'data' copies the DATA container (Documents/Library), NOT the app "
                  "bundle — the result is not an installable app, only its user data")
        data_dir = local_app_dir + "_Data"
        count = dev.pull_data_container_afc(args.device, bundle_id, data_dir, on_file=on_file)
        util.ok(f"data container written to {data_dir}")
        return app, None  # no bundle to package
    else:
        raise dev.DeviceError(f"unknown method {args.method!r}")
    util.ok(f"pulled {count} files")
    return app, local_app_dir


def cmd_pull(args) -> int:
    if not args.bundle_id:
        util.err("give a bundle id (see: python -m ipaxtr apps)")
        return 2
    try:
        app, local_dir = _do_pull(args, args.bundle_id)
    except dev.DeviceError as exc:
        util.err(str(exc))
        return 1
    except Exception as exc:  # noqa: BLE001
        util.err(f"pull failed: {exc}")
        return 1
    if not app:
        return 1
    if local_dir is None:
        return 0  # data-route pull already reported and finished

    # encryption report + package
    _report_local_bundle(local_dir)
    if not args.no_package:
        out = args.out or "."
        ipa_path = packaging.package_app(local_dir, os.path.join(out, f"{_slug(app.bundle_id)}-{app.version or '0'}.ipa"))
        util.ok(f"packaged: {ipa_path}")
    return 0


def _report_local_bundle(app_dir: str) -> None:
    from . import macho

    info = util.read_info_plist(app_dir) or {}
    exe = util.main_executable(app_dir, info)
    if not exe:
        util.warn("could not locate the main executable (Windows Defender may have "
                  "quarantined it — jailbreak-related binaries often trip heuristics; "
                  "add an exclusion for this folder)")
        return
    try:
        mi = macho.analyze_file(os.path.join(app_dir, exe))
        line = macho.cryptid_description(mi)
        if mi.is_encrypted:
            util.warn(f"binary: {line}")
            print("           -> to make it runnable elsewhere you need the decrypt step")
        else:
            util.ok(f"binary: {line}")
    except OSError:
        util.warn("cannot read the executable — Windows Defender may have quarantined "
                  f"it ({exe}); add an exclusion for this folder and pull again")
    except Exception as exc:  # noqa: BLE001
        util.warn(f"cannot analyse the executable: {exc}")


def _slug(s: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in s)


# --------------------------------------------------------------- extract ----


def cmd_extract(args) -> int:
    """End-to-end: pull from device -> report -> package into ipas/."""
    if not args.bundle_id:
        util.err("give a bundle id (see: python -m ipaxtr apps)")
        return 2
    if args.method == "auto":
        util.info("auto mode: trying frida, then ssh, then afc2")
        for method in ("frida", "ssh", "afc2"):
            probe = argparse.Namespace(**vars(args))
            probe.method = method
            try:
                return _extract_with(probe)
            except dev.DeviceError as exc:
                # routing/auth failure -> try the next route
                util.warn(f"{method}: {exc}")
            # any other exception is terminal (packaging, AV interference, ...)
        util.err("all routes failed — see the checklist below")
        _access_help()
        return 1
    try:
        return _extract_with(args)
    except dev.DeviceError as exc:
        util.err(str(exc))
        _access_help()
        return 1
    except Exception as exc:  # noqa: BLE001
        util.err(f"extract failed: {exc}")
        return 1


def _extract_with(args) -> int:
    app, local_dir = _do_pull(args, args.bundle_id)
    if not app:
        return 1
    if local_dir is None:
        raise dev.DeviceError(
            "--method data only copies the app's data container; there is no app "
            "bundle to package. Use --method frida/ssh/afc2 for a real IPA."
        )
    _report_local_bundle(local_dir)
    out_dir = args.out or "ipas"
    util.ensure_dir(out_dir)
    ipa_path = packaging.package_app(
        local_dir, os.path.join(out_dir, f"{_slug(app.bundle_id)}-{app.version or '0'}.ipa")
    )
    util.ok(f"IPA ready: {ipa_path}  ({util.human_size(os.path.getsize(ipa_path))})")
    print()
    util.warn("Reminder: only extract apps you own or are authorised to test.")
    return 0


def _access_help() -> None:
    print()
    util.info("Reading an installed app bundle needs one of:")
    print("    • frida-server running as root on a jailbroken device  -> --method frida")
    print("      (all you need is the device + frida-server; no SSH, no AFC2)")
    print("    • jailbroken device + OpenSSH                          -> --method ssh --ssh 127.0.0.1:2222")
    print("      (forward the port first:  iproxy 2222 22  or  ssh -L 2222:localhost:22)")
    print("    • jailbroken device + AFC2 tweak                       -> --method afc2")
    print("    • stock device                                         -> app bundles are sandboxed; only the")
    print("      DATA container is reachable (not an installable IPA). Use Xcode")
    print("      (Window > Devices > your app > Download Container) for your own builds.")


# --------------------------------------------------------------- decrypt ----


def cmd_decrypt(args) -> int:
    from . import decrypt as dec_mod

    if not args.i_own_this_build:
        util.err("refusing: FairPlay decryption is limited to apps you own / are")
        print("           authorised to research. Re-run with --i-own-this-build to confirm.")
        return 2
    if not args.app_dir:
        util.err("pass --app-dir <local pulled .app> (pull it first with `pull`)")
        return 2
    try:
        ext_action = getattr(args, "extensions", "strip") or "strip"
        result = dec_mod.decrypt_app(
            args.udid, args.bundle_id, args.out or "decrypted",
            app_dir_local=args.app_dir,
            extension_action=ext_action,
        )
    except Exception as exc:  # noqa: BLE001
        util.err(f"decrypt failed: {exc}")
        return 1
    if result.patched_files:
        util.ok(f"decrypted {result.patched_files} binary/binaries "
                f"({result.total_patched/1024/1024:.2f} MB recovered)")
    else:
        util.info("nothing needed patching")
    util.ok(f"IPA: {result.ipa_path}")
    print()
    util.warn("The result is for analysis/research on your own app; its signature is invalid")
    print("           for installation (re-sign it yourself if you need to run it).")
    return 0


# ------------------------------------------------------------------ main ----


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ipaxtr",
        description="IPA extractor / inspector for a connected iPhone and local .ipa files.",
        epilog="Legal: only use on devices/apps you own or are authorised to test.",
    )
    p.add_argument("--version", action="version", version=f"IPAxTR {__version__}")
    sub = p.add_subparsers(dest="command")

    d = sub.add_parser("devices", help="list connected iPhones")
    d.set_defaults(func=cmd_devices)

    i = sub.add_parser("info", help="show a device summary")
    i.add_argument("device", nargs="?", help="UDID (optional)")
    i.set_defaults(func=cmd_info)

    a = sub.add_parser("apps", help="list apps installed on the device")
    a.add_argument("filter", nargs="?", help="substring filter on name/bundle id")
    a.add_argument("-t", "--type", default="User", help="User (default) or System/All")
    a.add_argument("--device", help="UDID (optional)")
    a.add_argument("-v", "--verbose", action="store_true", help="show full paths")
    a.set_defaults(func=cmd_apps)

    c = sub.add_parser("check", help="inspect an .ipa file or a device app")
    c.add_argument("file", nargs="?", help="path to the .ipa (or bundle id with --device)")
    c.add_argument("--device", action="store_true", help="treat FILE as a bundle id on the iPhone")
    c.add_argument("--udid", help="UDID (optional)")
    c.add_argument("--frida", action="store_true",
                   help="read the binary over frida (jailbroken + frida-server)")
    c.add_argument("--ssh", help="host:port to read the binary over SSH (jailbroken)")
    c.add_argument("--ssh-user", default="mobile")
    c.add_argument("--password", help="SSH password (prompted when missing)")
    c.add_argument("--key", help="SSH private key path")
    c.add_argument("-v", "--verbose", action="store_true")
    c.set_defaults(func=cmd_check)

    u = sub.add_parser("unpack", help="extract an .ipa file")
    u.add_argument("file", nargs="?", help="path to the .ipa")
    u.add_argument("-o", "--out", help="output directory")
    u.set_defaults(func=cmd_unpack)

    k = sub.add_parser("pack", help="package a .app (or Payload/ folder) into an .ipa")
    k.add_argument("path", nargs="?", help=".app directory or folder containing Payload/")
    k.add_argument("-o", "--out", help="output .ipa path")
    k.set_defaults(func=cmd_pack)

    for name, help_text, has_bundle in (
        ("pull", "copy an installed app bundle off the device", True),
        ("extract", "pull + package an installed app into an .ipa", True),
    ):
        s = sub.add_parser(name, help=help_text)
        if has_bundle:
            s.add_argument("bundle_id", nargs="?", help="e.g. com.example.app")
        s.add_argument("--method", default="auto",
                       choices=["auto", "frida", "ssh", "afc2", "data"],
                       help="filesystem route (default: auto -> frida, ssh, afc2; "
                            "data = app DATA container only, stock devices)")
        s.add_argument("--ssh", help="host:port of forwarded SSH (jailbroken device)")
        s.add_argument("--ssh-user", default="mobile")
        s.add_argument("--password", help="SSH password (prompted when missing)")
        s.add_argument("--key", help="SSH private key path")
        s.add_argument("--work", help="work directory for the raw pull (default work/)")
        s.add_argument("--device", help="UDID (optional)")
        s.add_argument("-o", "--out", help="output directory for the .ipa")
        s.add_argument("-v", "--verbose", action="store_true")
        if name == "pull":
            s.add_argument("--no-package", action="store_true", help="skip IPA packaging")
        if name == "extract":
            pass
        s.set_defaults(func=cmd_pull if name == "pull" else cmd_extract)

    x = sub.add_parser("decrypt", help="FairPlay-decrypt a pulled bundle (jailbroken, own apps)")
    x.add_argument("bundle_id", nargs="?", help="bundle id of the app to launch for the dump")
    x.add_argument("--app-dir", help="local .app directory already pulled with `pull`")
    x.add_argument("--udid", help="UDID (optional)")
    x.add_argument("-o", "--out", help="output directory for the decrypted .ipa")
    x.add_argument("--extensions", choices=["strip", "patch", "keep"], default="strip",
                   help="how to handle un-decrypted on-demand extensions (default: strip)")
    x.add_argument("--i-own-this-build", action="store_true",
                   help="confirm you own / are authorised to decrypt this app")
    x.set_defaults(func=cmd_decrypt)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        _banner()
        parser.print_help()
        print()
        util.info("quick start:")
        print("    python -m ipaxtr devices")
        print("    python -m ipaxtr check MyApp.ipa")
        print("    python -m ipaxtr extract com.example.app --method ssh --ssh 127.0.0.1:2222")
        print()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print()
        util.warn("interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
