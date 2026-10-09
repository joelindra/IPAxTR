#!/usr/bin/env python3
"""main.py — Interactive Launcher for IPAxTR.

Automatically detects connected iPhones, performs system & prerequisite checks,
displays all extractable applications (User 3rd-party, Apple bundle apps, and
Jailbreak apps), and enables one-click extraction into valid .ipa files.
Features a colorful, clean, emoji-free terminal UI powered by the Rich library,
fully localized in English.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import os
import sys
import time

# Ensure project root is available in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ipaxtr import cli, decrypt, macho, packaging, util
from ipaxtr import device as dev

# Global Rich console instance
console = Console()

# -------------------------------------------------- Status & Output Helpers ----


def log_success(message: str) -> None:
    console.print(f"  [bold green][SUCCESS][/bold green] {message}")


def log_warning(message: str) -> None:
    console.print(f"  [bold yellow][WARNING][/bold yellow] {message}")


def log_error(message: str) -> None:
    console.print(f"  [bold red][FAILED][/bold red] {message}")


def log_info(message: str) -> None:
    console.print(f"  [bold cyan][INFO][/bold cyan] {message}")


def log_step(message: str) -> None:
    console.print(f"\n[bold cyan][>>][/bold cyan] [bold white]{message}[/bold white]")


def safe_prompt(text: str, default: str = "") -> str:
    """Read line from stdin safely without raising EOFError on automated or headless runs."""
    try:
        val = input(text)
        return val.strip() if val.strip() else default
    except (EOFError, KeyboardInterrupt):
        return default


# ---------------------------------------------------- Header & Banner ----


def render_header() -> None:
    """Render a colorful, professional header panel using Rich."""
    header_text = Text()
    header_text.append("IPAxTR", style="bold cyan")
    header_text.append("  |  ", style="dim")
    header_text.append("iPhone Application Extractor & Binary Inspector", style="bold white")
    header_text.append("\nInteractive CLI Suite for Research, Backup & Security Analysis", style="dim italic")

    panel = Panel(
        Align.center(header_text),
        box=box.DOUBLE,
        border_style="bold cyan",
        padding=(1, 2),
    )
    console.print(panel)

    legal_text = Text()
    legal_text.append("[LEGAL & ETHICAL NOTICE] ", style="bold yellow")
    legal_text.append(
        "Only extract applications you own, your authorized TestFlight builds, or "
        "software for lawful security research on devices you are authorized to test.",
        style="dim white",
    )
    console.print(Panel(legal_text, box=box.ROUNDED, border_style="yellow", padding=(0, 1)))


# ------------------------------------------------- Prerequisites Diagnostics ----


def get_installed_version(package_name: str) -> str | None:
    try:
        return importlib.metadata.version(package_name)
    except Exception:
        pass
    try:
        mod = __import__(package_name)
        return getattr(mod, "__version__", "Installed")
    except Exception:
        return None


def inspect_jailbreak_environment(udid: str | None = None) -> dict:
    """Inspect jailbreak status and root privileges on target iPhone."""
    from ipaxtr import frida_bridge

    # 1. Active root bridge check
    try:
        with frida_bridge.open_bridge(udid) as bridge:
            if bridge.uid == 0:
                flavor = "Rootless Jailbreak"
                if bridge.exists("/var/jb/.installed_dopamine"):
                    flavor = "Dopamine (Rootless)"
                elif bridge.exists("/var/jb"):
                    flavor = "Rootless (/var/jb)"
                elif bridge.exists("/Applications/Cydia.app") or bridge.exists("/bin/bash"):
                    flavor = "Rootful Jailbreak"
                return {
                    "ready": True,
                    "badge": "[bold green][READY][/bold green]",
                    "flavor": flavor,
                    "details": f"{flavor} active (UID 0, full root access)",
                    "hint": "",
                    "frida_ready": True,
                    "frida_details": "Running on device as root (UID 0)",
                }
            else:
                return {
                    "ready": False,
                    "badge": "[bold yellow][LIMITED][/bold yellow]",
                    "flavor": "Unprivileged Frida Agent",
                    "details": f"frida-server active with non-root UID ({bridge.uid})",
                    "hint": "Ensure frida-server is executed as root in jailbreak environment",
                    "frida_ready": True,
                    "frida_details": f"Running with non-root uid={bridge.uid}",
                }
    except Exception:
        pass

    # 2. Check if jailbreak apps are installed on device (dormant / rebooted / agent offline)
    try:
        jb_apps = dev._scan_jailbreak_apps(udid)
        if jb_apps:
            return {
                "ready": False,
                "badge": "[bold yellow][NOT READY][/bold yellow]",
                "flavor": "Jailbreak Installed (Agent Offline)",
                "details": f"Jailbreak apps found ({', '.join(a.name for a in jb_apps[:2])}), but root agent is inactive",
                "hint": "Open jailbreak app (Dopamine/Sileo) and verify frida-server is active",
                "frida_ready": False,
                "frida_details": "Not reachable over USB usbmux",
            }
    except Exception:
        pass

    # 3. Stock / Unjailbroken iOS
    return {
        "ready": False,
        "badge": "[bold yellow][NOT READY][/bold yellow]",
        "flavor": "Stock iOS (Jailed)",
        "details": "Standard stock iOS (Root bundle pull & FairPlay decrypt unavailable)",
        "hint": "Jailbreak required for full bundle extraction & FairPlay decryption",
        "frida_ready": False,
        "frida_details": "Not reachable (Stock iOS without frida-server)",
    }


def run_prerequisites_check(udid: str | None = None) -> tuple[list[dict], dict | None]:
    """Inspect all required Python libraries, drivers, device states, and jailbreak status."""
    results = []
    jb_status = None

    # 1. Python Dependencies
    packages = [
        ("pymobiledevice3", "Core iOS usbmuxd & lockdown communication", True, "pip install pymobiledevice3"),
        ("frida", "High-speed root filesystem pull & decryption", True, "pip install frida"),
        ("paramiko", "SSH / SFTP network transfer fallback", False, "pip install paramiko"),
        ("rich", "Terminal UI & diagnostic rendering", True, "pip install rich"),
    ]

    for pkg_name, purpose, is_critical, install_hint in packages:
        ver = get_installed_version(pkg_name)
        if ver:
            results.append({
                "item": pkg_name,
                "role": purpose,
                "ready": True,
                "badge": "[bold green][READY][/bold green]",
                "details": f"v{ver} installed",
                "hint": "",
            })
        else:
            badge = "[bold red][MISSING][/bold red]" if is_critical else "[bold yellow][OPTIONAL][/bold yellow]"
            results.append({
                "item": pkg_name,
                "role": purpose,
                "ready": not is_critical,
                "badge": badge,
                "details": "Not found in Python environment",
                "hint": f"Run: {install_hint}",
            })

    # 2. Driver / usbmuxd service
    try:
        devices = dev.list_devices()
        results.append({
            "item": "usbmuxd / Driver",
            "role": "Apple Mobile Device USB multiplexer",
            "ready": True,
            "badge": "[bold green][READY][/bold green]",
            "details": "Service active and responding",
            "hint": "",
        })
    except Exception as exc:
        results.append({
            "item": "usbmuxd / Driver",
            "role": "Apple Mobile Device USB multiplexer",
            "ready": False,
            "badge": "[bold red][NOT FOUND][/bold red]",
            "details": f"Unable to reach usbmuxd ({exc.__class__.__name__})",
            "hint": "Install Apple Devices or iTunes from Microsoft Store",
        })
        devices = []

    # 3. Connected iPhone
    if devices:
        active_udid = udid or devices[0].serial
        results.append({
            "item": "Connected iPhone",
            "role": "Physical iOS target device",
            "ready": True,
            "badge": "[bold green][READY][/bold green]",
            "details": f"Connected via USB ({active_udid[:12]}...)",
            "hint": "",
        })

        # 4. Lockdown pairing / Trust
        try:
            summary = dev.device_summary(active_udid)
            results.append({
                "item": "Device Pairing",
                "role": "Host authorization & lockdown pairing",
                "ready": True,
                "badge": "[bold green][READY][/bold green]",
                "details": f"{summary.model} (iOS {summary.ios}) paired & trusted",
                "hint": "",
            })
        except Exception:
            results.append({
                "item": "Device Pairing",
                "role": "Host authorization & lockdown pairing",
                "ready": False,
                "badge": "[bold red][UNPAIRED][/bold red]",
                "details": "Pairing record missing or rejected",
                "hint": "Unlock device screen and tap 'Trust This Computer'",
            })

        # 5. Jailbreak Environment & Frida-Server
        jb_status = inspect_jailbreak_environment(active_udid)
        results.append({
            "item": "Jailbreak Status",
            "role": "Root filesystem & unsigned app access",
            "ready": jb_status["ready"],
            "badge": jb_status["badge"],
            "details": jb_status["details"],
            "hint": jb_status["hint"],
        })

        results.append({
            "item": "frida-server",
            "role": "On-device filesystem & memory agent",
            "ready": jb_status["frida_ready"],
            "badge": "[bold green][READY][/bold green]" if jb_status["frida_ready"] else "[bold yellow][OFFLINE][/bold yellow]",
            "details": jb_status["frida_details"],
            "hint": "Start frida-server in jailbreak app if root pull is needed" if not jb_status["frida_ready"] else "",
        })
    else:
        results.append({
            "item": "Connected iPhone",
            "role": "Physical iOS target device",
            "ready": False,
            "badge": "[bold red][DISCONNECTED][/bold red]",
            "details": "No iOS device detected via USB",
            "hint": "Connect iPhone with USB data cable and unlock screen",
        })
        results.append({
            "item": "Jailbreak Status",
            "role": "Root filesystem & unsigned app access",
            "ready": False,
            "badge": "[bold yellow][NOT READY][/bold yellow]",
            "details": "No device connected to inspect",
            "hint": "Connect device via USB",
        })

    return results, jb_status


def render_prerequisites_panel(checks: list[dict], show_all: bool = True) -> None:
    """Render a structured status card displaying all prerequisites."""
    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold cyan",
        title_style="bold white",
        padding=(0, 1),
        expand=True,
    )
    table.add_column("Component", style="bold white", no_wrap=True)
    table.add_column("Status", justify="center", no_wrap=True)
    table.add_column("Details & Recommendations", style="white")

    all_ready = True
    for item in checks:
        if not item["ready"]:
            all_ready = False
        detail_text = item["details"]
        if item["hint"]:
            detail_text += f"\n[dim yellow]-> {item['hint']}[/dim yellow]"
        table.add_row(item["item"], item["badge"], detail_text)

    status_title = (
        "[bold green]Prerequisites & Environment Status: ALL SYSTEMS READY[/bold green]"
        if all_ready
        else "[bold yellow]Prerequisites & Environment Status: ACTION REQUIRED[/bold yellow]"
    )

    console.print(Panel(table, title=status_title, border_style="cyan" if all_ready else "yellow", box=box.ROUNDED))


# ---------------------------------------------------- Device Info Card ----


def render_device_info(summary: dev.Device, udid: str, jb_status: dict | None = None) -> None:
    """Render an organized device summary card with jailbreak status."""
    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column("Key", style="bold cyan", width=18)
    table.add_column("Value", style="bold white")

    table.add_row("Device Name", summary.name or "iPhone")
    table.add_row("Hardware Model", f"{summary.model or 'Unknown'}")
    table.add_row("iOS Version", f"iOS {summary.ios or 'Unknown'}")
    if jb_status:
        if jb_status["ready"]:
            jb_val = f"[bold green]{jb_status['flavor']} (READY)[/bold green]"
        else:
            jb_val = f"[bold yellow]{jb_status['flavor']} (NOT READY)[/bold yellow]"
        table.add_row("Jailbreak Status", jb_val)
    table.add_row("Serial / UDID", udid)
    table.add_row("Connection Route", "USB usbmuxd (Lightning / USB-C)")

    console.print(Panel(table, title="[bold cyan]Target Device Information[/bold cyan]", border_style="cyan", box=box.ROUNDED))


def render_no_device_screen() -> bool:
    """Troubleshooting screen when no device is detected. Returns True to retry, False to quit."""
    log_error("No iPhone detected on USB bus.")
    print()
    log_info("Troubleshooting Steps:")
    print("  1. Verify the iPhone is connected with a data-capable USB cable (not charge-only).")
    print("  2. Unlock your iPhone screen and tap 'Trust This Computer' if prompted.")
    print("  3. Windows: ensure Apple Devices or iTunes driver is installed.")
    print("  4. Verify visibility using terminal CLI:  python -m ipaxtr devices")
    print("-" * 88)

    while True:
        choice = safe_prompt("\n[R] Retry Detection  |  [Q] Exit : ", default="q").lower()
        if choice in ("r", "retry"):
            return True
        if choice in ("q", "quit", "exit"):
            return False


# ------------------------------------------------ Category Formatters ----


def format_category_badge(app_type: str) -> str:
    if app_type == "User":
        return "[bold green][User][/bold green]     "
    elif app_type == "Jailbreak":
        return "[bold magenta][Jailbreak][/bold magenta]"
    elif app_type == "Apple":
        return "[bold cyan][Apple][/bold cyan]    "
    else:
        return f"[dim][{app_type[:9]:<9}][/dim]"


def get_category_description(app_type: str) -> str:
    if app_type == "User":
        return "Third-Party App (App Store / TestFlight / Sideloaded)"
    elif app_type == "Jailbreak":
        return "Jailbreak Package (Rootless /var/jb/Applications)"
    elif app_type == "Apple":
        return "Removable Apple Stock App (Bundle Application Container)"
    else:
        return "Apple System Firmware Daemon"


# ------------------------------------------------ Applications Table ----


def render_applications_table(apps: list[dev.InstalledApp], mode_title: str, query: str = "") -> None:
    """Render a clean, colorful applications table using Rich."""
    title = f"Available Applications ({mode_title})"
    if query:
        title += f" [Filter: '{query}']"

    table = Table(
        title=f"\n[bold white]{title}[/bold white] - [bold green]{len(apps)} found[/bold green]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        padding=(0, 1),
        expand=True,
    )
    table.add_column("No", justify="right", style="bold cyan", no_wrap=True)
    table.add_column("Category", no_wrap=True)
    table.add_column("Application Name", style="bold white")
    table.add_column("Bundle Identifier", style="dim cyan")
    table.add_column("Version", style="dim yellow", justify="right", no_wrap=True)

    for idx, app in enumerate(apps, start=1):
        badge = format_category_badge(app.app_type)
        name = (app.name or "Unknown")[:30]
        bid = (app.bundle_id or "-")[:38]
        ver = (app.version or "-")[:12]
        table.add_row(f"[{idx:2d}]", badge, name, bid, ver)

    console.print(table)


# ------------------------------------------------ Extraction Handlers ----


def handle_standard_extraction(app: dev.InstalledApp, udid: str) -> None:
    """Pull application bundle from iPhone and package into a clean .ipa file."""
    log_step(f"Starting standard IPA extraction: {app.name or app.bundle_id}")
    app_folder = app.path.rstrip("/").split("/")[-1] or f"{app.bundle_id}.app"
    work_dir = os.path.join("work", app_folder)

    console.print(f"  Device Path  : [dim]{app.path}[/dim]")
    console.print(f"  Staging Dir  : [dim]{work_dir}[/dim]")

    try:
        log_info("Pulling bundle directory from iPhone over high-speed USB bridge...")
        file_count = dev.pull_bundle_frida(udid, app.path, work_dir)
        log_success(f"Successfully pulled {file_count} files from device.")
    except Exception as exc:
        log_error(f"Bundle transfer failed: {exc}")
        console.print("  [dim]Tip: Ensure frida-server is running as root on your jailbroken iPhone.[/dim]")
        return

    # Check executable encryption state
    info_plist = util.read_info_plist(work_dir) or {}
    main_exe = util.main_executable(work_dir, info_plist)
    if main_exe:
        bin_path = os.path.join(work_dir, main_exe)
        try:
            mi = macho.analyze_file(bin_path)
            desc = macho.cryptid_description(mi)
            if mi.is_encrypted:
                log_warning(f"Binary encryption: {desc}")
                console.print("    [dim](Protected with FairPlay DRM; runs on original device/account)[/dim]")
            else:
                log_success(f"Binary encryption: {desc} (Plaintext / Decrypted)")
        except Exception:
            pass

    # Package into IPA
    try:
        util.ensure_dir("ipas")
        slug_id = "".join(c if c.isalnum() or c in "._-" else "_" for c in app.bundle_id)
        out_ipa = os.path.join("ipas", f"{slug_id}-{app.version or '0'}.ipa")
        log_info("Packaging and compressing into .ipa archive (replaying POSIX symlinks & permissions)...")
        final_path = packaging.package_app(work_dir, out_ipa)
        file_size = util.human_size(os.path.getsize(final_path))
        print()
        log_success("IPA package generated successfully!")
        console.print(f"  Archive Path : [bold green]{final_path}[/bold green]")
        console.print(f"  Archive Size : [bold white]{file_size}[/bold white]")
    except Exception as exc:
        log_error(f"Packaging failed: {exc}")


def handle_decrypt_extraction(app: dev.InstalledApp, udid: str) -> None:
    """Extract and FairPlay-decrypt application binary via Frida on jailbroken device."""
    log_step(f"Extract & FairPlay Decrypt: {app.name or app.bundle_id}")
    console.print("  [dim]Notice: Runtime decryption requires a jailbroken device with frida-server running as root.[/dim]")
    confirm = safe_prompt("\nDo you own this application or have authorization for security testing? (y/N): ", default="n").lower()
    if confirm not in ("y", "yes"):
        log_warning("Operation cancelled by user.")
        return

    app_folder = app.path.rstrip("/").split("/")[-1] or f"{app.bundle_id}.app"
    work_dir = os.path.join("work", app_folder)

    # 1. Inspect existing staging or pull fresh
    need_pull = True
    if os.path.isdir(work_dir):
        scan_local = decrypt.scan_bundle_binaries(work_dir)
        total_cnt = len(scan_local["all"])
        enc_cnt = len(scan_local["encrypted"])
        plain_cnt = len(scan_local["plaintext"])

        log_info(f"Existing local bundle staging found: {work_dir}")
        console.print(f"  [dim]Local Mach-O Binaries: {total_cnt} total ({plain_cnt} plaintext, {enc_cnt} encrypted)[/dim]")

        choice = safe_prompt("Use existing local staging? [Y/n, default: Y]: ", default="y").lower()
        if choice in ("", "y", "yes"):
            need_pull = False

    if need_pull:
        log_info(f"Pulling bundle from iPhone to {work_dir} via Frida...")
        try:
            dev.pull_bundle_frida(udid, app.path, work_dir)
            log_success("Initial bundle transfer complete.")
        except Exception as exc:
            log_error(f"Failed to pull application bundle: {exc}")
            return

    # Check extension presence and configure handling
    scan_now = decrypt.scan_bundle_binaries(work_dir)
    ext_encrypted = [
        e for e in scan_now.get("extensions", [])
        if (e.get("encrypted") if isinstance(e, dict) else e[2].is_encrypted)
    ]
    ext_action = "strip"

    if ext_encrypted:
        print()
        console.print(f"[bold cyan]Notice on App Extensions ({len(ext_encrypted)} found in PlugIns/):[/bold cyan]")
        console.print("  App extensions (Widgets & Notification Services) run as isolated iOS background daemons.")
        console.print("  They are not loaded into the main app memory unless triggered on-demand by the system.")
        console.print("  [bold white]Select how to handle un-loaded extensions:[/bold white]")
        console.print("    [bold cyan][1][/bold cyan] Strip un-decrypted extensions [bold green](Recommended for Sideloadly / TrollStore)[/bold green] [dim][DEFAULT][/dim]")
        console.print("    [bold cyan][2][/bold cyan] Patch cryptid=0 header on extensions (Preserves files, marks unencrypted)")
        console.print("    [bold cyan][3][/bold cyan] Keep original encrypted extensions as-is")

        ext_choice = safe_prompt("Enter choice [1/2/3, default: 1]: ", default="1")
        if ext_choice == "2":
            ext_action = "patch"
        elif ext_choice == "3":
            ext_action = "keep"
        else:
            ext_action = "strip"

    # 2. Run runtime page-diff decryption
    print()
    log_info("Launching app via Frida and comparing __TEXT memory pages against disk...")
    try:
        util.ensure_dir("ipas")
        res = decrypt.decrypt_app(
            udid=udid,
            bundle_id=app.bundle_id,
            output_dir="ipas",
            app_dir_local=work_dir,
            extension_action=ext_action,
        )

        # 3. Render Rich Summary Table
        print()
        table = Table(
            title="[bold white]Binary Decryption Results[/bold white]",
            box=box.ROUNDED,
            header_style="bold cyan",
            expand=True,
            padding=(0, 1),
        )
        table.add_column("Binary Target", style="bold white")
        table.add_column("Classification", style="dim", no_wrap=True)
        table.add_column("Status", justify="center", no_wrap=True)
        table.add_column("Details & Metrics", style="white")

        for f in res.files:
            badge = "[bold green][DECRYPTED][/bold green]"
            detail = f"{f.pages_patched} page(s) patched, {f.bytes_patched/1024:.0f} KB recovered"
            if f.action_taken:
                if "stripped" in f.action_taken:
                    badge = "[bold yellow][STRIPPED][/bold yellow]"
                    detail = "Removed from package for clean sideloading"
                elif "header patched" in f.action_taken:
                    badge = "[bold cyan][HEADER PATCHED][/bold cyan]"
                    detail = "Mach-O cryptid set to 0"
                elif "kept" in f.action_taken:
                    badge = "[bold yellow][KEPT ENCRYPTED][/bold yellow]"
                    detail = "Retained original encrypted binary"
            elif f.skipped:
                badge = "[bold yellow][SKIPPED][/bold yellow]"
                detail = f.skipped
            elif f.pages_patched == 0:
                badge = "[bold green][PLAINTEXT][/bold green]"
                detail = "Memory matched disk (already plaintext)"

            table.add_row(f.rel_path, f.category, badge, detail)

        console.print(table)

        print()
        if res.patched_files:
            mb = res.total_patched / 1024 / 1024
            log_success(f"Successfully decrypted {res.patched_files} Mach-O binaries ({mb:.2f} MB recovered)!")
        else:
            log_success("All packaged application binaries are plaintext and unencrypted.")

        console.print(f"  Archive Path : [bold green]{res.ipa_path}[/bold green]")
        console.print(f"  Archive Size : [bold white]{util.human_size(os.path.getsize(res.ipa_path))}[/bold white]")
        print()
        log_warning("Note: Decrypted IPAs invalidate Apple DRM signatures; re-sign with TrollStore, Sideloadly, or AltStore.")

        # Offer immediate export for Ghidra / IDA Pro
        print()
        prep_ghidra = safe_prompt("Export raw Mach-O binary for Ghidra / IDA Pro analysis? [Y/n, default: Y]: ", default="y").lower()
        if prep_ghidra in ("", "y", "yes"):
            export_and_guide_ghidra(app.name or app.bundle_id, work_dir, app.bundle_id)
    except Exception as exc:
        log_error(f"Decryption failed: {exc}")


def export_and_guide_ghidra(app_name: str, app_dir: str, bundle_id: str | None = None) -> str | None:
    """Extract and export the raw Mach-O executable for Ghidra / IDA Pro analysis."""
    log_step(f"Prepare Mach-O Binary for Ghidra / IDA: {app_name}")

    # 1. Locate main binary
    info_plist = util.read_info_plist(app_dir)
    exe_name = info_plist.get("CFBundleExecutable") if info_plist else None
    if not exe_name:
        base = os.path.basename(app_dir.rstrip("/\\"))
        if base.endswith(".app"):
            base = base[:-4]
        exe_name = base

    source_path = os.path.join(app_dir, exe_name)
    if not os.path.isfile(source_path):
        log_error(f"Cannot locate executable binary inside {app_dir} ({exe_name})")
        return None

    # 2. Check encryption and Mach-O header
    try:
        mi = macho.analyze_file(source_path)
    except Exception as exc:
        log_error(f"Cannot analyze Mach-O header: {exc}")
        return None

    # 3. Export to binaries/ directory
    clean_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in (app_name or exe_name))
    out_dir = os.path.join("binaries", clean_name)
    util.ensure_dir(out_dir)
    dest_path = os.path.join(out_dir, exe_name)

    log_info(f"Exporting raw Mach-O executable to: {dest_path}...")
    try:
        import shutil
        if not os.path.exists(dest_path) or os.path.getsize(dest_path) != os.path.getsize(source_path):
            shutil.copy2(source_path, dest_path)
        log_success(f"Executable exported successfully ({util.human_size(os.path.getsize(dest_path))})")
    except Exception as exc:
        log_error(f"Failed to copy binary: {exc}")
        return None

    # 4. Check for embedded Frameworks
    fw_dir = os.path.join(app_dir, "Frameworks")
    fw_count = 0
    if os.path.isdir(fw_dir):
        fw_count = len([d for d in os.listdir(fw_dir) if d.endswith(".framework")])

    # 5. Render Ghidra / IDA Guide Panel
    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column("Key", style="bold cyan", width=22)
    table.add_column("Value", style="bold white")

    table.add_row("Executable Path", os.path.abspath(dest_path))
    table.add_row("File Size", f"{util.human_size(os.path.getsize(dest_path))} ({os.path.getsize(dest_path):,} bytes)")
    table.add_row("Binary Format", f"Mac OS X Mach-O (64-bit {macho.cpu_name(mi.cpu_type)})")

    if mi.is_encrypted:
        enc_badge = "[bold red][ENCRYPTED FairPlay DRM (cryptid=1)][/bold red]"
        enc_detail = "WARNING: Code is still encrypted! Ghidra will not decompile instructions properly. Decrypt first."
    else:
        enc_badge = "[bold green][DECRYPTED / PLAINTEXT (cryptid=0)][/bold green]"
        enc_detail = "Ready for disassembly and full decompilation in Ghidra / IDA Pro."
    table.add_row("Encryption Status", f"{enc_badge}\n[dim]{enc_detail}[/dim]")

    if fw_count > 0:
        table.add_row("Embedded Frameworks", f"{fw_count} frameworks in {os.path.abspath(fw_dir)}")

    table.add_row("", "")
    table.add_row(
        "[bold yellow]Ghidra Instructions[/bold yellow]",
        "[bold red]DO NOT import the .ipa file into Ghidra![/bold red] (.ipa is a ZIP archive)\n"
        "Drag & drop the [bold green]Mach-O executable file[/bold green] listed above into Ghidra.\n\n"
        "Ghidra Import Settings:\n"
        "  • Format   : [bold cyan]Mac OS X Mach-O[/bold cyan]\n"
        "  • Language : [bold cyan]AARCH64:LE:64:v8A (Apple)[/bold cyan] or ARM:v8:64\n"
        "  • Compiler : [bold cyan]default[/bold cyan]\n"
        "Then double-click to open CodeBrowser and run Auto Analysis.",
    )

    console.print()
    console.print(
        Panel(
            table,
            title="[bold white]Ghidra / IDA Pro Reverse Engineering Guide[/bold white]",
            border_style="green" if not mi.is_encrypted else "yellow",
            box=box.ROUNDED,
        )
    )

    # 6. Offer to open Windows Explorer with file selected
    print()
    open_exp = safe_prompt("Open folder in Windows File Explorer now? [Y/n, default: Y]: ", default="y").lower()
    if open_exp in ("", "y", "yes"):
        try:
            import subprocess
            if sys.platform == "win32":
                subprocess.Popen(["explorer", f"/select,{os.path.abspath(dest_path)}"])
            else:
                os.startfile(os.path.abspath(out_dir))
            log_success("Opened in Windows File Explorer (file highlighted). Drag it into Ghidra!")
        except Exception as exc:
            log_warning(f"Unable to launch Explorer: {exc}")

    return dest_path


def handle_prepare_for_ghidra(app: dev.InstalledApp, udid: str) -> None:
    """Ensure app bundle is pulled and decrypted, then export raw Mach-O for Ghidra."""
    log_step(f"Prepare for Ghidra / IDA: {app.name or app.bundle_id}")

    app_folder = app.path.rstrip("/").split("/")[-1] or f"{app.bundle_id}.app"
    work_dir = os.path.join("work", app_folder)

    # 1. Pull bundle if not cached locally
    if not os.path.isdir(work_dir):
        log_info(f"Pulling bundle from iPhone to {work_dir} via Frida...")
        try:
            dev.pull_bundle_frida(udid, app.path, work_dir)
            log_success("Initial bundle transfer complete.")
        except Exception as exc:
            log_error(f"Failed to pull application bundle: {exc}")
            return
    else:
        log_info(f"Using existing local bundle staging: {work_dir}")

    # 2. Check if main binary is encrypted
    info_plist = util.read_info_plist(work_dir)
    exe_name = info_plist.get("CFBundleExecutable") if info_plist else None
    if not exe_name:
        exe_name = os.path.basename(work_dir)[:-4] if work_dir.endswith(".app") else os.path.basename(work_dir)
    main_bin = os.path.join(work_dir, exe_name)

    mi = None
    if os.path.isfile(main_bin):
        try:
            mi = macho.analyze_file(main_bin)
        except Exception:
            pass

    if mi and mi.is_encrypted:
        log_warning("Binary is currently FairPlay-encrypted (cryptid=1).")
        console.print("  [dim]Ghidra cannot decompile encrypted ARM64 instructions without runtime decryption.[/dim]")
        run_dec = safe_prompt("Run Frida runtime memory decryption now? [Y/n, default: Y]: ", default="y").lower()
        if run_dec in ("", "y", "yes"):
            handle_decrypt_extraction(app, udid)
            return

    export_and_guide_ghidra(app.name or app.bundle_id, work_dir, app.bundle_id)


def handle_unpack_ipa_tool() -> None:
    """Tool to unpack any existing .ipa file and extract its Mach-O binary for Ghidra."""
    log_step("Unpack .ipa File for Ghidra / IDA Pro")

    # Find IPAs in ipas/ directory
    ipa_files = []
    if os.path.isdir("ipas"):
        ipa_files = [os.path.join("ipas", f) for f in os.listdir("ipas") if f.lower().endswith(".ipa")]

    target_ipa = None
    if ipa_files:
        console.print("\n[bold cyan]Found .ipa files in ipas/:[/bold cyan]")
        for idx, f in enumerate(ipa_files, start=1):
            sz = util.human_size(os.path.getsize(f))
            console.print(f"  [bold cyan][{idx}][/bold cyan] {f} [dim]({sz})[/dim]")
        console.print("  [bold cyan][M][/bold cyan] Enter custom file path manually")
        console.print("  [bold cyan][B][/bold cyan] Back")

        choice = safe_prompt("\nSelect .ipa to unpack [1-N / M / B, default: 1]: ", default="1")
        if choice.lower() in ("b", "back"):
            return
        elif choice.lower() == "m":
            p = safe_prompt("Enter path to .ipa file: ", default="").strip('"')
            if os.path.isfile(p):
                target_ipa = p
            else:
                log_error(f"File not found: {p}")
                return
        else:
            try:
                sel = int(choice) if choice else 1
                if 1 <= sel <= len(ipa_files):
                    target_ipa = ipa_files[sel - 1]
            except ValueError:
                target_ipa = ipa_files[0]
    else:
        p = safe_prompt("Enter path to .ipa file: ", default="").strip('"')
        if os.path.isfile(p):
            target_ipa = p
        else:
            log_error(f"File not found: {p}")
            return

    if not target_ipa:
        return

    ipa_basename = os.path.splitext(os.path.basename(target_ipa))[0]
    unpack_dir = os.path.join("work", f"unpacked_{ipa_basename}")

    log_info(f"Unpacking {target_ipa} to {unpack_dir}...")
    try:
        from ipaxtr import ipa as ipa_mod
        ipa_mod.unpack(target_ipa, unpack_dir)
        log_success("Unpack complete.")
    except Exception as exc:
        log_error(f"Failed to unpack IPA: {exc}")
        return

    # Find the .app folder inside Payload/
    payload_dir = os.path.join(unpack_dir, "Payload")
    app_dir = None
    if os.path.isdir(payload_dir):
        for entry in os.listdir(payload_dir):
            if entry.endswith(".app"):
                app_dir = os.path.join(payload_dir, entry)
                break

    if not app_dir:
        log_error("Could not find Payload/*.app folder inside unpacked archive.")
        return

    export_and_guide_ghidra(ipa_basename, app_dir)


def handle_encryption_inspection(app: dev.InstalledApp, udid: str) -> None:
    """Inspect remote Mach-O header encryption flag without downloading the full app."""
    log_step(f"Inspect Mach-O encryption header: {app.name or app.bundle_id}")
    exe_name = os.path.basename(app.path.rstrip("/"))
    if exe_name.endswith(".app"):
        exe_name = exe_name[:-4]
    remote_binary = f"{app.path}/{exe_name}"

    try:
        mi = dev.check_cryptid_over_frida(udid, remote_binary)
        console.print(f"  Binary Target  : [dim]{remote_binary}[/dim]")
        console.print(f"  Crypt Status   : {macho.cryptid_description(mi)}")
        console.print(f"  CPU Target     : {macho.cpu_name(mi.cpu_type)}")
        if mi.min_os:
            console.print(f"  Minimum OS     : iOS {mi.min_os}")
        if mi.is_encrypted:
            log_warning("Application is FairPlay-encrypted (cryptid=1).")
        else:
            log_success("Application is free of FairPlay encryption (Plaintext cryptid=0).")
    except Exception as exc:
        log_error(f"Encryption check over Frida failed: {exc}")
        console.print("  [dim]Verify that frida-server is active on the jailbroken device.[/dim]")


# ------------------------------------------------ Selected App Submenu ----


def show_app_actions_menu(app: dev.InstalledApp, udid: str) -> None:
    """Submenu for chosen application."""
    while True:
        table = Table(box=None, show_header=False, padding=(0, 2))
        table.add_column("Key", style="bold cyan", width=18)
        table.add_column("Value", style="bold white")

        table.add_row("Application Name", f"{app.name or 'Unknown'} {format_category_badge(app.app_type)}")
        table.add_row("Classification", get_category_description(app.app_type))
        table.add_row("Bundle Identifier", app.bundle_id)
        table.add_row("Version", f"{app.version or '-'} (build {app.build or '-'})")
        table.add_row("Device Filesystem", app.path)

        console.print(Panel(table, title="[bold cyan]Selected Application Details[/bold cyan]", border_style="cyan", box=box.ROUNDED))

        console.print("[bold white]Available Actions:[/bold white]")
        console.print("  [bold cyan][1][/bold cyan] Standard IPA Extract       (Pull bundle -> Package into .ipa in ipas/) [dim][DEFAULT][/dim]")
        console.print("  [bold cyan][2][/bold cyan] Extract & Decrypt .ipa     (FairPlay runtime decryption -> .ipa package)")
        console.print("  [bold cyan][3][/bold cyan] Prepare for Ghidra / IDA   (Export decrypted Mach-O executable for decompiler)")
        console.print("  [bold cyan][4][/bold cyan] Inspect Encryption Header  (Check Mach-O cryptid flag directly on device)")
        console.print("  [bold cyan][B][/bold cyan] Back to Applications List")
        print("-" * 88)

        choice = safe_prompt("Enter choice [1/2/3/4/B, default: 1]: ", default="1").lower()

        if choice in ("", "1"):
            handle_standard_extraction(app, udid)
            safe_prompt("\nPress Enter to continue...", default="")
            break
        elif choice == "2":
            handle_decrypt_extraction(app, udid)
            safe_prompt("\nPress Enter to continue...", default="")
            break
        elif choice == "3":
            handle_prepare_for_ghidra(app, udid)
            safe_prompt("\nPress Enter to continue...", default="")
            break
        elif choice == "4":
            handle_encryption_inspection(app, udid)
            safe_prompt("\nPress Enter to continue...", default="")
        elif choice in ("b", "back"):
            break
        else:
            log_warning("Invalid choice. Please select 1, 2, 3, 4, or B.")


# ------------------------------------------------------------ Main Loop ----


def main() -> int:
    mode = "UserFacing"
    search_query = ""

    mode_labels = {
        "UserFacing": "All Visible Screen Apps (User + Apple Removable + Jailbreak)",
        "User": "User 3rd-Party Only (App Store / TestFlight - 8 apps)",
        "AppleBundle": "Apple Removable Bundles (Calculator, Notes, Files, etc. - 32 apps)",
        "Jailbreak": "Jailbreak Tweaks Only (Sileo, Zebra)",
        "All": "All Installed Applications (Including Background System Daemons)",
    }

    while True:
        console.clear()
        render_header()

        # Run Live Prerequisites & Diagnostics Check
        checks, jb_status = run_prerequisites_check()
        render_prerequisites_panel(checks)

        # Detect Device
        summary, udid = None, None
        try:
            devices = dev.list_devices()
            if devices:
                udid = devices[0].serial
                summary = dev.device_summary(udid)
        except Exception:
            pass

        if not summary or not udid:
            retry = render_no_device_screen()
            if retry:
                continue
            console.print("\n[dim]Goodbye![/dim]")
            return 0

        render_device_info(summary, udid, jb_status)

        # Query applications
        with console.status("[bold cyan]Querying application directory on device...[/bold cyan]", spinner="line"):
            try:
                all_apps = dev.list_installed_apps(udid=udid, app_type=mode)
            except Exception as exc:
                log_error(f"Failed to query applications: {exc}")
                all_apps = []

        # Apply search filter if active
        displayed_apps = all_apps
        if search_query:
            q = search_query.lower()
            displayed_apps = [a for a in all_apps if q in (a.name or "").lower() or q in a.bundle_id.lower()]

        if not displayed_apps:
            log_warning("No applications matched the current filter.")
        else:
            render_applications_table(displayed_apps, mode_labels.get(mode, mode), search_query)

        # Navigation Bar
        console.print(
            f"Navigation: [bold cyan][1-{len(displayed_apps)}][/bold cyan] Select App  |  "
            f"[bold cyan][U][/bold cyan] Unpack .ipa for Ghidra  |  "
            f"[bold cyan][C][/bold cyan] Category  |  "
            f"[bold cyan][S][/bold cyan] Search  |  "
            f"[bold cyan][R][/bold cyan] Refresh  |  "
            f"[bold cyan][Q][/bold cyan] Quit"
        )
        if search_query:
            console.print(f"            [bold yellow][X][/bold yellow] Clear Search Filter ('{search_query}')")

        user_input = safe_prompt("\nEnter your selection: ", default="")

        if not user_input:
            continue

        cmd = user_input.lower()
        if cmd in ("q", "quit", "exit"):
            console.print("\n[bold green]Session closed. Goodbye![/bold green]")
            return 0
        if cmd in ("r", "refresh"):
            continue
        if cmd in ("u", "unpack", "ghidra", "ida"):
            handle_unpack_ipa_tool()
            safe_prompt("\nPress Enter to continue...", default="")
            continue
        if cmd == "x" and search_query:
            search_query = ""
            continue
        if cmd in ("s", "search", "f", "find"):
            val = safe_prompt("Enter application name or bundle ID keyword to filter: ", default="")
            search_query = val
            continue
        if cmd in ("c", "category", "m", "mode"):
            console.print("\n[bold cyan]Select Display Category:[/bold cyan]")
            console.print("  [1] All Visible Screen Apps (User + Apple Removable + Jailbreak) [DEFAULT]")
            console.print("  [2] Third-Party User Apps Only (App Store / TestFlight - 8 apps)")
            console.print("  [3] Apple Removable Apps Only (Calculator, Notes, Files, etc. - 32 apps)")
            console.print("  [4] Jailbreak Apps Only (Sileo, Zebra)")
            console.print("  [5] All System & Daemons (Complete device index - 170+ apps)")
            pick = safe_prompt("Choose category [1-5]: ", default="1")
            mapping = {
                "1": "UserFacing",
                "2": "User",
                "3": "AppleBundle",
                "4": "Jailbreak",
                "5": "All",
            }
            if pick in mapping:
                mode = mapping[pick]
                search_query = ""
            continue

        # Handle numeric selection
        try:
            sel_num = int(user_input)
            if 1 <= sel_num <= len(displayed_apps):
                selected = displayed_apps[sel_num - 1]
                show_app_actions_menu(selected, udid)
            else:
                log_warning(f"Number out of range (choose between 1 and {len(displayed_apps)}).")
                time.sleep(1.2)
        except ValueError:
            log_warning("Invalid input. Please enter an application number or a menu key.")
            time.sleep(1.2)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user (Ctrl+C).")
        sys.exit(0)
