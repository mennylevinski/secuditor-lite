# MIT License – Copyright (c) 2026 Menahem Levinski

"""
Presents a detailed report of the system's settings and inventory.
"""

import os
import sys
import platform
import socket
import subprocess
import winreg
import psutil
import json

# --- Get Windows Edition ---
def _get_windows_edition():
    try:
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            edition, _ = winreg.QueryValueEx(key, "EditionID")
            product, _ = winreg.QueryValueEx(key, "ProductName")
            build, _ = winreg.QueryValueEx(key, "CurrentBuildNumber")

        edition_names = {
            "Core": "Home",
            "CoreSingleLanguage": "Home Single Language",
            "CoreCountrySpecific": "Home Country Specific",
            "Professional": "Pro",
            "ProfessionalN": "Pro N",
            "ProfessionalWorkstation": "Pro for Workstations",
            "ProfessionalWorkstationN": "Pro for Workstations N",
            "ProfessionalEducation": "Pro Education",
            "ProfessionalEducationN": "Pro Education N",
            "Enterprise": "Enterprise",
            "EnterpriseN": "Enterprise N",
            "Education": "Education",
            "EducationN": "Education N",
            "ServerStandard": "Standard",
            "ServerDatacenter": "Datacenter",
            "ServerEssentials": "Essentials",
            "ServerStandardCore": "Standard Core",
            "ServerDatacenterCore": "Datacenter Core",
        }

        edition_name = edition_names.get(edition, edition)

        if "server" in product.casefold():
            return product

        os_name = "Windows 11" if int(build) >= 22000 else "Windows 10"

        return f"{os_name} {edition_name}"

    except (OSError, ValueError, TypeError):
        return "Unknown"

def _get_cim_value(class_name, property_name):
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"(Get-CimInstance -ClassName {class_name}).{property_name}",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        value = result.stdout.strip()
        return value if result.returncode == 0 and value else "Unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "Unknown"

def _get_firmware_type():
    try:
        import ctypes

        class FIRMWARE_TYPE(ctypes.c_int):
            pass

        firmware_type = FIRMWARE_TYPE()

        get_firmware_type = ctypes.windll.kernel32.GetFirmwareType
        get_firmware_type.argtypes = [ctypes.POINTER(FIRMWARE_TYPE)]
        get_firmware_type.restype = ctypes.c_bool

        if get_firmware_type(ctypes.byref(firmware_type)):
            return {
                1: "BIOS",
                2: "UEFI",
            }.get(firmware_type.value, "Unknown")

        return "Unknown"

    except (AttributeError, OSError):
        return "Unknown"

def _get_bios_info():
    return _get_cim_value("Win32_BIOS", "SMBIOSBIOSVersion")

# --- Collect basic OS and Resources info using platform module ---
def get_system_settings():
    os_name = platform.system()
    os_release = platform.release()
    windows_edition = _get_windows_edition()

    unified_os = (
        windows_edition
        if os_name == "Windows" and windows_edition != "Unknown"
        else f"{os_name}{os_release}"
    )
            
    firmware_type = _get_firmware_type()
    bios_version = _get_bios_info()

    firmware_version = (
        f"{firmware_type} {bios_version.split(' - ')[-1]}"
        if firmware_type != "Unknown" and bios_version != "Unknown"
        else bios_version
    )

    # --- Gather resources info ---
    memory = psutil.virtual_memory()
    cpu_freq = psutil.cpu_freq()
    boot_time = psutil.boot_time()

    resources = {
        "Machine": platform.machine(),
        "Processor": platform.processor() or "Unknown",
        "Architecture": (
            "x64" if platform.architecture()[0] == "64bit" else "x86"
        ),
        "CPU Cores": psutil.cpu_count(logical=False),
        "Threads": psutil.cpu_count(logical=True),
        "CPU Frequency (MHz)": (
            round(cpu_freq.current) if cpu_freq else "Unknown"
        ),
        "RAM (GB)": round(memory.total / (1024**3), 2),
    }

    # --- Gather disks info safely ---
    disks = {}

    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)

            disks[part.device] = {
                "Mountpoint": part.mountpoint,
                "File System": part.fstype,
                "Total (GB)": round(usage.total / (1024**3), 2),
                "Used (GB)": round(usage.used / (1024**3), 2),
                "Free (GB)": round(usage.free / (1024**3), 2),
                "Usage %": usage.percent,
            }

        except (PermissionError, FileNotFoundError, OSError):
            # Skip drives that are not ready or accessible
            continue

    return {
        "Hostname": socket.gethostname(),
        "OS": unified_os,
        "Firmware": firmware_version,
        "Resources": resources,
        "Disks": disks,
    }

def format_system_settings(settings):
    output = [""]  # Upperline added
    keys = list(settings.keys())

    for i, key in enumerate(keys):
        value = settings[key]

        if isinstance(value, dict):
            # Add section header (special handling for Resources and Disks)
            if key == "Resources":
                # Standard Resources section
                output.append("–" * 50)
                output.append(f"{key}:")
                output.append("")
            elif key == "Disks":
                # Always add a separator before Disks (even if after Resources)
                output.append("–" * 50)
                output.append(f"{key}:")
                output.append("")
            else:
                output.append(f"{key}:")

            sub_keys = list(value.keys())
            for j, (sub_key, sub_value) in enumerate(value.items()):
                if isinstance(sub_value, dict):
                    output.append(f"{sub_key}:")
                    for k, v in sub_value.items():
                        output.append(f"  {k}: {v}")
                    # Separator between disks (except last)
                    if key == "Disks" and j != len(sub_keys) - 1:
                        output.append("–" * 50)
                else:
                    output.append(f"{sub_key}: {sub_value}")

            # Section separator for non-Disk/Resource sections (except last)
            if key not in ("Disks", "Resources") and i != len(keys) - 1:
                output.append("–" * 50)

        else:
            output.append(f"{key}: {value}")
            # Add separator if not last and next isn’t Resources/Disks
            if i != len(keys) - 1 and keys[i + 1] not in ("Resources", "Disks"):
                output.append("–" * 50)

    return "\n".join(output)

def get_formatted_system_settings():
    """Call get_system_settings and return formatted string"""
    settings = get_system_settings()
    return format_system_settings(settings)

# --- Scan related hardware devices ---
if sys.platform.startswith("win"):
    _CREATE_NO_WINDOW = 0x08000000
    _STARTUPINFO = subprocess.STARTUPINFO()
    _STARTUPINFO.dwFlags |= subprocess.STARTF_USESHOWWINDOW
else:
    _CREATE_NO_WINDOW = 0
    _STARTUPINFO = None

def _run_ps(cmd):
    """Run PowerShell command, return JSON list, hide window, ignore non-zero exit code."""
    try:
        # Use subprocess.run instead of check_output to avoid exception on exit code != 0
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            text=True,
            capture_output=True,
            creationflags=_CREATE_NO_WINDOW,
            startupinfo=_STARTUPINFO
        )
        out = result.stdout.strip()

        if not out:
            return []

        data = json.loads(out)

        # Always return a list
        if isinstance(data, dict):
            return [data]
        return data

    except Exception as e:
        # Only print actual unexpected errors
        print(f"[PS ERROR] {e}")
        return []

# --- PnP scanning ---
PNP_CLASS_MAP = {
    "Printers": "Printer",
    "Cameras": "Image", 
    "Bluetooth Devices": "Bluetooth",
    "Biometric Devices": "Biometric",
}

def scan_pnp_category(category_name):
    """Scan PnP devices for a specific category."""
    cmd = (
        f'powershell -NoProfile -Command '
        f'"Get-PnpDevice -Class {category_name} | '
        f'Select-Object Name,Status,InstanceId | ConvertTo-Json -Depth 2"'
    )

    devices = _run_ps(cmd)
    unique_devices = []
    seen = set()

    for device in devices:
        instance_id = (
            device.get("InstanceId") or ""
        ).strip().casefold()

        key = instance_id or (
            (device.get("Name") or "").strip().casefold()
        )

        if key in seen:
            continue

        seen.add(key)

        unique_devices.append({
            "Name": device.get("Name"),
            "Status": device.get("Status"),
        })

    return unique_devices

def scan_usb_devices():
    """Scan USB hubs."""
    cmd = ('powershell -NoProfile -Command '
           '"Get-WmiObject -Class Win32_USBHub | Select-Object DeviceID,PNPDeviceID,Description | ConvertTo-Json -Depth 2"')
    return _run_ps(cmd)

def scan_network_adapters():
    """Scan network adapters and their IP addresses."""
    adapters = []
    try:
        # Adapters
        cmd1 = ('powershell -NoProfile -Command '
                '"Get-NetAdapter | Select-Object Name,InterfaceDescription,MacAddress,Status | ConvertTo-Json -Depth 2"')
        net_data = _run_ps(cmd1)
        for a in net_data:
            adapters.append({
                "Name": a.get("Name"),
                "Description": a.get("InterfaceDescription"),
                "MAC": a.get("MacAddress"),
                "Status": a.get("Status"),
                "IPs": []
            })
        # IP addresses
        cmd2 = ('powershell -NoProfile -Command '
                '"Get-NetIPAddress | Select-Object InterfaceAlias,IPAddress,AddressFamily | ConvertTo-Json -Depth 2"')
        ip_data = _run_ps(cmd2)
        for ipinfo in ip_data:
            alias = ipinfo.get("InterfaceAlias")
            for a in adapters:
                if a.get("Name") == alias:
                    a["IPs"].append(ipinfo.get("IPAddress"))
    except Exception:
        pass
    return adapters

def get_hardware_report():
    """Return formatted report for selected device categories."""
    categories = {
        "Printers": scan_pnp_category("Printer") or [],
        "Cameras": scan_pnp_category("Camera") or [],
        "Bluetooth Devices": scan_pnp_category("Bluetooth") or [],
        "USB Devices": scan_usb_devices() or [],
        "Biometric Devices": scan_pnp_category("Biometric") or [],
        "Network Adapters": scan_network_adapters() or [],
    }

    lines = []
    lines.append("–" * 50)

    category_keys = list(categories.keys())
    for i, category in enumerate(category_keys):
        items = categories[category]

        # Header
        lines.append(f"{category}:")

        if not items:
            lines.append("  (None)")
        else:
            seen_names = set()

            for item in items:
                name = (
                    item.get("Name")
                    or item.get("Description")
                    or "(Unknown)"
                )

                key = name.strip().casefold()

                if key in seen_names:
                    continue

                seen_names.add(key)
                lines.append(f"  {name}")

        # Only add separator if not the last category
        if i != len(category_keys) - 1:
            lines.append("–" * 50)

    return "\n".join(lines)

# --- Output ---
if __name__ == "__main__":
    print("\nSystem & Hardware Report")
    print("–" * len("System & Hardware Report"))
    print(get_formatted_system_settings())
    print(get_hardware_report())
    print("")
    
    os.system("pause")
