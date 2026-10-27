# MIT License – Copyright (c) 2026 Menahem Levinski

"""
Detects remote access capabilities and services exposure.
"""

import os
import sys
import subprocess
import winreg
import json
import socket
import threading
import itertools
import time

def running_in_idle():
    return "idlelib" in sys.modules

# --- Dots worker ---
class Spinner:
    """Simple console spinner/dots animation in a separate thread."""
    def __init__(self, message: str = "Working"):
        self.message = message
        self._stop_event = threading.Event()
        self.thread = threading.Thread(target=self._spin, daemon=True)

    def _spin(self):
        for dots in itertools.cycle(["", ".", "..", "...", "....", "....."]):
            if self._stop_event.is_set():
                break
            print(f"\r{self.message}{dots}   ", end="", flush=True)
            time.sleep(0.5)
            
        print("\r" + " " * (len(self.message) + 10) + "\r", end="", flush=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self._stop_event.set()
        self.thread.join()

# --- Helper ---
def _run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return ""
    
# --- WinRM Settings ---
def check_winrm_service():
    output = _run(["sc", "qc", "WinRM"])

    if "SERVICE_NAME" not in output:
        return {
            "status": "Disabled",
            "running": False
        }

    if "DISABLED" in output:
        return {
            "status": "Disabled",
            "running": False
        }

    running = "RUNNING" in _run(["sc", "query", "WinRM"])

    return {
        "status": "Enabled",
        "running": running
    }

def check_winrm_startup():
    output = _run(["sc", "qc", "WinRM"])
    if "AUTO_START" in output:
        return "Automatic"
    if "DEMAND_START" in output:
        return "Manual"
    if "DISABLED" in output:
        return "Disabled"
    return "Unknown"

def check_listeners():
    output = _run(["winrm", "enumerate", "winrm/config/listener"])
    return {
        "http": "Transport = HTTP" in output,
        "https": "Transport = HTTPS" in output
    }

def check_ports():
    ports = []
    for port in (5985, 5986):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                ports.append(port)
    return ports

def check_auth():
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service\Auth"
        ) as key:
            auth = {}
            for name in ["Basic", "Kerberos", "Negotiate", "Certificate"]:
                try:
                    auth[name] = bool(winreg.QueryValueEx(key, name)[0])
                except FileNotFoundError:
                    auth[name] = False
            return auth
    except Exception:
        return {}

def check_encryption():
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service"
        ) as key:
            allow = winreg.QueryValueEx(key, "AllowUnencrypted")[0]
            return not bool(allow)
    except Exception:
        return True

def assess_risk(service, listeners, auth, encrypted):
    if not service["running"]:
        return "None"

    if auth.get("Basic"):
        return "Critical"

    if listeners["http"] and not encrypted:
        return "High"

    if listeners["http"] and listeners["https"]:
        return "Medium"

    if listeners["https"]:
        return "Low"

    return "Medium"

def audit_winrm():
    service = check_winrm_service()
    startup = check_winrm_startup()
    listeners = check_listeners()
    ports = check_ports()
    auth = check_auth()
    encrypted = check_encryption()
    risk = assess_risk(service, listeners, auth, encrypted)
    verdict = winrm_verdict(service, listeners, ports, risk)

    return {
        "service": service,
        "startup": startup,
        "listeners": listeners,
        "ports": ports,
        "authentication": auth,
        "encryption": encrypted,
        "risk": risk,
        "verdict": verdict
    }

def winrm_verdict(service, listeners, ports, risk):
    status = service.get("status", "Unknown").lower()

    if status != "enabled":
        return "Disabled, no exposure, no risk"

    if not listeners.get("http") and not listeners.get("https"):
        return "Enabled, no listeners, low risk"

    if not ports:
        return "Enabled, no ports listening, low risk"

    if risk == "Low":
        return "Enabled, restricted exposure, medium risk"

    if risk == "Medium":
        return "Enabled, network exposure, medium risk"

    if risk in ("High", "Critical"):
        return "Enabled, remote access exposed, high risk"

    return "Enabled, exposure unknown"

def winrm_verdict(service, listeners, ports, risk):
    status = service.get("status", "Unknown").lower()

    if status != "enabled":
        return "Disabled"

    if not listeners.get("http") and not listeners.get("https"):
        return "Enabled, Low Risk (No listeners)"

    if not ports:
        return "Enabled, Low Risk (No ports listeners)"

    if risk == "Low":
        return "Enabled, Moderate Risk (Restricted exposure)"

    if risk == "Medium":
        return "Enabled, Moderate Risk (Network exposure)"

    if risk in ("High", "Critical"):
        return "Enabled, High Risk (Remote access exposed)"

    return "Enabled, Unknown Risk (Exposure unknown)"

def check_bluetooth():
    try:
        ps_script = r"""
        $ErrorActionPreference = 'Stop'

        $devices = @(
            Get-PnpDevice -Class Bluetooth -ErrorAction Stop |
            Select-Object Status, FriendlyName, InstanceId,
                @{Name='ProblemCode'; Expression={
                    try {
                        (Get-PnpDeviceProperty `
                            -InstanceId $_.InstanceId `
                            -KeyName 'DEVPKEY_Device_ProblemCode' `
                            -ErrorAction Stop).Data
                    }
                    catch {
                        $null
                    }
                }}
        )

        # --- Bluetooth driver signature status ---
        $signedDrivers = @(
            Get-CimInstance -ClassName Win32_PnPSignedDriver `
                -ErrorAction Stop |
            Select-Object DeviceID, IsSigned, Signer, DriverVersion
        )

        foreach ($device in $devices) {
            $driver = $signedDrivers |
                Where-Object {
                    $_.DeviceID -eq $device.InstanceId
                } |
                Select-Object -First 1

            if ($null -ne $driver) {
                $device | Add-Member -NotePropertyName DriverIsSigned `
                    -NotePropertyValue $driver.IsSigned -Force
                $device | Add-Member -NotePropertyName DriverSigner `
                    -NotePropertyValue $driver.Signer -Force
                $device | Add-Member -NotePropertyName DriverVersion `
                    -NotePropertyValue $driver.DriverVersion -Force
            }
            else {
                $device | Add-Member -NotePropertyName DriverIsSigned `
                    -NotePropertyValue $null -Force
                $device | Add-Member -NotePropertyName DriverSigner `
                    -NotePropertyValue $null -Force
                $device | Add-Member -NotePropertyName DriverVersion `
                    -NotePropertyValue $null -Force
            }
        }

        $serviceStatus = 'Unknown'

        try {
            $serviceStatus = (
                Get-Service -Name bthserv -ErrorAction Stop
            ).Status.ToString()
        }
        catch {
            $serviceStatus = 'Unknown'
        }

        [PSCustomObject]@{
            QuerySucceeded = $true
            Devices = @($devices)
            ServiceStatus = $serviceStatus
        } | ConvertTo-Json -Depth 5 -Compress
        """

        output = subprocess.check_output(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                ps_script,
            ],
            shell=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            stderr=subprocess.DEVNULL,
            timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW,
        ).strip()

        if not output:
            raise ValueError("Empty PowerShell response")

        data = json.loads(output)

        if not data.get("QuerySucceeded", False):
            raise ValueError("Bluetooth device query failed")

        devices = data.get("Devices", [])

        if isinstance(devices, dict):
            devices = [devices]

        if not devices:
            return "Not detected"

        # --- Check device status ---
        operational_devices = [
            device for device in devices
            if str(device.get("Status", "")).strip().upper() == "OK"
        ]

        disabled_devices = [
            device for device in devices
            if str(device.get("ProblemCode", "")).strip() == "22"
        ]

        if not operational_devices:
            if disabled_devices:
                return "Disabled"
            return "Not detected"

        # Driver signature information is now available in each
        # device dictionary for reporting or further assessment.
        service_status = data.get("ServiceStatus", "Unknown")

       # --- Check connectability ---
        try:
            bluetooth_api = ctypes.WinDLL("bthprops.cpl")

            is_connectable = bluetooth_api.BluetoothIsConnectable
            is_connectable.argtypes = [ctypes.c_void_p]
            is_connectable.restype = ctypes.c_int

            connectable = bool(is_connectable(None))

        except (OSError, AttributeError):
            connectable = False

        # --- Assess driver signature ---
        signed_status = (
            "Signed"
            if all(
                device.get("DriverIsSigned") is True
                for device in operational_devices
            )
            else "Unknown"
        )
        
        if signed_status != "Signed":
            signed_error = True
        else:
            signed_error = False

        # --- Assess risk ---
        if connectable and signed_error:
            return "Enabled, Moderate Risk (Bluetooth driver unknown or unsigned)"

        elif connectable and service_status == "Running":
            return "Enabled, Low Risk (Default settings)"

        elif connectable and service_status == "Stopped":
            return "Enabled, Moderate Risk (Support Service stopped)"

        elif service_status == "Stopped":
            return "Enabled, Exposure status unknown"

        return "Enabled, Exposure status unknown"

    except (
        subprocess.SubprocessError,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ):
        return "Unknown"

    except Exception:
        return "Unknown"

# --- Remote Access Settings ---
def get_remote_access_settings():
    
    result = {
        "Remote Desktop": "Unknown",
        "Remote Registry": "Unknown",
        "Remote Assistance": "Unknown",
        "PowerShell Remoting": "Unknown",
        "FTP Service": "Unknown",
        "Rsync Service": "Unknown",
        "RPC Print Spooler": "Unknown",
        "Bluetooth": "Unknown",
        "UPnPHost": "Unknown",
        "NetBIOS": "Unknown",
        "DCOM": "Unknown",
        "WinRM": "Unknown",
        "SMB1": "Unknown",
        "SMB2": "Unknown",
    }

    # --- Remote Desktop (RDP) ---
    try:
        key_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
        with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hklm:
            with winreg.OpenKey(hklm, key_path) as key:
                # --- Check if RDP is enabled ---
                fDenyTSConnections, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
                rdp_enabled = fDenyTSConnections == 0

                if rdp_enabled:
                    # --- Check Network Level Authentication (NLA) ---
                    try:
                        key_sec_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
                        with winreg.OpenKey(hklm, key_sec_path) as sec_key:
                            nla, _ = winreg.QueryValueEx(sec_key, "UserAuthentication")
                            min_encryption, _ = winreg.QueryValueEx(sec_key, "MinEncryptionLevel")

                            # Assess security
                            if nla == 1 and min_encryption >= 2:  # 2 or higher = moderate/strong
                                verdict = "Enabled, Low Risk (Default settings)"
                            else:
                                verdict = "Enabled, Potentially Exposed (Without NLA or weak encryption)"
                    except FileNotFoundError:
                        verdict = "Enabled, Potentially Exposed (Configuration missing or insecure)"
                else:
                    verdict = "Disabled"

                result["Remote Desktop"] = verdict

    except FileNotFoundError:
        result["Remote Desktop"] = "Disabled"
    except PermissionError:
        result["Remote Desktop"] = "Unknown"
    except Exception:
        result["Remote Desktop"] = "Unknown"

    # --- SMB1 ---
    try:
        cmd = (
            'powershell -Command '
            '"Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | '
            'Select-Object -ExpandProperty State"'
        )
        output = subprocess.check_output(cmd, shell=True, text=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW).strip()

        # --- Final verdict ---
        if output == "Enabled":
            verdict = "Enabled, High Risk"  # SMB1 enabled → insecure
        elif output == "Disabled":
            verdict = "Disabled"  # Safe
        else:
            verdict = output or "Unknown"

        result["SMB1"] = verdict

    except subprocess.CalledProcessError:
        result["SMB1"] = "Disabled"
    except Exception:
        result["SMB1"] = "Unknown"

    # --- SMB2 ---
    try:
        result["SMB2"] = "Unknown"
        internal = {}

        # Get SMB2 configuration
        cmd = (
            'powershell -Command '
            '"Get-SmbServerConfiguration | '
            'Select-Object EnableSMB2Protocol, RequireSecuritySignature, EncryptData, EnableGuestAccess, EnableSMB1Protocol, AuditSmbAccess | '
            'ConvertTo-Json"'
        )
        output = subprocess.check_output(cmd, shell=True, text=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW).strip()
        data = json.loads(output)

        enable_smb2 = data.get("EnableSMB2Protocol", False)
        signing = data.get("RequireSecuritySignature", False)
        encryption = data.get("EncryptData", False)
        guest = data.get("EnableGuestAccess", False)
        smb1_enabled = data.get("EnableSMB1Protocol", False)
        audit = data.get("AuditSmbAccess", False)

        internal.update({
            "EnableSMB2Protocol": enable_smb2,
            "RequireSecuritySignature": signing,
            "EncryptData": encryption,
            "EnableGuestAccess": guest,
            "EnableSMB1Protocol": smb1_enabled,
            "AuditSmbAccess": audit,
            "InsecurePermissions": False
        })

        insecure_permissions = False

        if enable_smb2:
            # Check SMB shares for insecure access
            try:
                cmd_shares = (
                    'powershell -Command '
                    '"Get-SmbShare | '
                    'Select-Object Name, Path, FullAccess, ChangeAccess, ReadAccess | ConvertTo-Json"'
                )
                shares_output = subprocess.check_output(cmd_shares, shell=True, text=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW).strip()
                shares_data = json.loads(shares_output)

                if isinstance(shares_data, dict):
                    shares_data = [shares_data]

                for share in shares_data:
                    for access_type in ["FullAccess", "ChangeAccess", "ReadAccess"]:
                        users = share.get(access_type, [])
                        if isinstance(users, str):
                            users = [users]
                        for u in users:
                            if u.lower() in ["everyone", "guest", "anonymous"]:
                                insecure_permissions = True
            except Exception:
                insecure_permissions = False

            internal["InsecurePermissions"] = insecure_permissions

            # Determine final verdict
            if not insecure_permissions:
                if signing or encryption:
                    verdict = "Enabled, Low Risk (Default settings)"
                else:
                    verdict = "Enabled, Moderate Risk (Weak SMB configuration)"
            else:
                verdict = "Enabled, Potentially Dangerous (Allow Guest/Everyone/Anonymous access)"
        else:
            verdict = "Disabled"

        result["SMB2"] = verdict

    except Exception:
        result["SMB2"] = "Unknown"

    # --- Bluetooth ---
    result["Bluetooth"] = check_bluetooth()

    # --- DCOM ---
    try:
        # --- Check if DCOM is enabled ---
        cmd = r'powershell -Command "Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Ole -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableDCOM"'
        reg_output = subprocess.check_output(cmd, shell=True, text=True, encoding="utf-8").strip()

        # --- Check Windows Firewall profiles ---
        try:
            fw_status = subprocess.check_output(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "(Get-NetFirewallProfile | "
                    "Select-Object -ExpandProperty Enabled) -join ','"
                ],
                shell=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                stderr=subprocess.DEVNULL,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            ).strip().lower().split(",")

            if len(fw_status) != 3 or any(
                value not in ("true", "false") for value in fw_status
            ):
                firewall_state = "Unknown"
            elif all(value == "true" for value in fw_status):
                firewall_state = "Fully Enabled"
            elif all(value == "false" for value in fw_status):
                firewall_state = "Fully Disabled"
            else:
                firewall_state = "Partially Enabled"

        except (subprocess.SubprocessError, OSError):
            firewall_state = "Unknown"

        if reg_output == "Y":
            # 🔹 Check authentication level
            try:
                cmd = r'powershell -Command "Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Ole -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LegacyAuthenticationLevel"'
                auth_output = subprocess.check_output(cmd, shell=True, text=True, encoding="utf-8").strip()
                level_map = {
                    "1": "None (Dangerous)",
                    "2": "Connect",
                    "3": "Call",
                    "4": "Packet",
                    "5": "Packet Integrity (Safe)",
                    "6": "Packet Privacy (Best)"
                }
                auth_state = level_map.get(auth_output, "Unknown")
            except Exception:
                auth_state = "Unknown"

            # 🔹 Check for Microsoft DCOM Hardening flag
            try:
                cmd = r'powershell -Command "Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Ole -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RequireIntegrityActivationAuthenticationLevel"'
                harden_output = subprocess.check_output(cmd, shell=True, text=True, encoding="utf-8").strip()
                harden_state = "Enabled" if harden_output == "1" else "Disabled"
            except Exception:
                harden_state = "Unknown"

            # 🔹 Determine final verdict
            if auth_state in ["Packet Integrity (Safe)", "Packet Privacy (Best)"]:
                reg_state = "Enabled, Low Risk (Secured authentication)"
            elif harden_state == "Enabled":
                reg_state = "Enabled, Hardened by Patch"
            else:
                # Weak authentication / no hardening → potentially dangerous
                if firewall_state:
                    reg_state = "Enabled, Moderate Risk (Firewall On)"
                else:
                    reg_state = "Enabled, Potentially Dangerous (Firewall Off)"

        elif reg_output == "N":
            reg_state = "Remote Disabled"  # ✅ safest option
        else:
            reg_state = "Unknown"

    except Exception:
        reg_state = "Unknown"

    result["DCOM"] = reg_state

    # --- NetBIOS ---
    try:
        output = subprocess.check_output(
            "ipconfig /all",
            shell=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )

        result["NetBIOS"] = "Unknown"

        for line in output.splitlines():
            if "NetBIOS over Tcpip" in line:
                status = line.split(":", 1)[-1].strip()

                if status.lower() == "enabled":
                    result["NetBIOS"] = "Enabled, Legacy default"
                elif status.lower() == "disabled":
                    result["NetBIOS"] = "Disabled"
                else:
                    result["NetBIOS"] = status

                break

    except Exception:
        result["NetBIOS"] = "Unknown"

    # --- Remote Assistance ---
    try:
        key_path = r"SYSTEM\CurrentControlSet\Control\Remote Assistance"
        with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hklm:
            with winreg.OpenKey(hklm, key_path) as key:
                ra_value, _ = winreg.QueryValueEx(key, "fAllowToGetHelp")
                result["Remote Assistance"] = "Enabled, Moderate Risk" if ra_value == 1 else "Disabled"
    except FileNotFoundError:
        result["Remote Assistance"] = "Disabled"
    except PermissionError:
        result["Remote Assistance"] = "Unknown"
    except Exception:
        result["Remote Assistance"] = "Unknown"

    # --- PowerShell Remoting (WinRM) ---
    try:
        # Check if WinRM service exists and status
        cmd_status = (
            'powershell -Command "if (Get-Service -Name WinRM -ErrorAction SilentlyContinue) {'
            '(Get-Service -Name WinRM).Status} else {\'NotInstalled\'}"'
        )
        winrm_status = subprocess.check_output(cmd_status, shell=True, text=True, encoding="utf-8").strip().lower()

        if not winrm_status or winrm_status == "notinstalled":
            result["PowerShell Remoting"] = "Disabled"
        elif winrm_status != "running":
            result["PowerShell Remoting"] = "Disabled"
        else:
            # Check if any WSMan listener exists (Server 2022 reliable method)
            cmd_listener = (
                'powershell -Command "if (Get-ChildItem WSMan:\\localhost\\Listener -ErrorAction SilentlyContinue) {\'Enabled\'} else {\'Disabled\'}"'
            )
            listener_status = subprocess.check_output(cmd_listener, shell=True, text=True, encoding="utf-8").strip().lower()

            if "enabled" in listener_status:
                result["PowerShell Remoting"] = "Enabled, Potentially Dangerous"
            else:
                # Fallback: AllowRemoteShellAccess registry
                cmd_reg = (
                    r'powershell -Command "$val = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service -ErrorAction SilentlyContinue).AllowRemoteShellAccess; '
                    r'if ($val -eq $null) {\'Unknown\'} elseif ($val -eq 1 -or $val -eq \'true\') {\'Enabled\'} else {\'Disabled\'}"'
                )
                reg_status = subprocess.check_output(cmd_reg, shell=True, text=True, encoding="utf-8").strip().lower()
                if reg_status in ("enabled", "1", "true"):
                    result["PowerShell Remoting"] = "Enabled, Potentially Dangerous"
                elif reg_status == "disabled":
                    result["PowerShell Remoting"] = "Disabled"
                else:
                    result["PowerShell Remoting"] = "Unknown"

    except Exception:
        result["PowerShell Remoting"] = "Unknown"

    # --- RPC Print Spooler ---
    try:
        # Check if RPC Print Spooler key exists
        check_rpc = subprocess.run(
            'powershell -Command "Test-Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print\\RpcEnabled"',
            shell=True, text=True, capture_output=True
        ).stdout.strip()

        if check_rpc.lower() == "true":
            # Read RpcEnabled value
            rpc_value = subprocess.check_output(
                'powershell -Command "Get-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print '
                '| Select-Object -ExpandProperty RpcEnabled"',
                shell=True, text=True, errors="ignore"
            ).strip()

            if rpc_value == "1":
                # --- Service is enabled, assess risk ---
                # Check if remote clients are restricted
                restrict_clients = subprocess.run(
                    'powershell -Command "Get-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print '
                    '| Select-Object -ExpandProperty RestrictRemoteClients"',
                    shell=True, text=True, capture_output=True
                ).stdout.strip()

                # Check if privacy/authentication is enabled
                privacy_enabled = subprocess.run(
                    'powershell -Command "Get-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print '
                    '| Select-Object -ExpandProperty RpcAuthnLevelPrivacyEnabled"',
                    shell=True, text=True, capture_output=True
                ).stdout.strip()

                # Determine risk with explanations
                if restrict_clients == "1" and privacy_enabled == "1":
                    verdict = "Enabled, Low Risk (Restricted access)"
                elif restrict_clients == "1" or privacy_enabled == "1":
                    verdict = "Enabled, Moderate Risk (Partially restricted)"
                else:
                    verdict = "Enabled, Potentially Dangerous (Unrestricted network access)"

            else:
                verdict = "Disabled"
        else:
            verdict = "Disabled"

        result["RPC Print Spooler"] = verdict

    except Exception:
        result["RPC Print Spooler"] = "Unknown"

    # --- Rsync Service ---
    try:
        ps_script = (
            "$svc = Get-CimInstance Win32_Service "
            "-Filter \"Name='rsync'\" -ErrorAction Stop; "
            "if ($null -eq $svc) { 'Not Detected' } "
            "else { \"$($svc.State)|$($svc.StartMode)\" }"
        )

        output = subprocess.check_output(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                ps_script,
            ],
            shell=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            stderr=subprocess.DEVNULL,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        ).strip()

        if output == "Not Detected":
            result["Rsync Service"] = "Not Detected"

        elif "|" in output:
            state, start_mode = output.split("|", 1)

            if state == "Running":
                result["Rsync Service"] = "Running"
            elif start_mode == "Disabled":
                result["Rsync Service"] = "Disabled"
            elif state == "Stopped":
                result["Rsync Service"] = "Stopped"
            else:
                result["Rsync Service"] = "Unknown"

        else:
            result["Rsync Service"] = "Unknown"

    except (subprocess.SubprocessError, OSError):
        result["Rsync Service"] = "Unknown"

    except Exception:
        result["Rsync Service"] = "Unknown"

    # --- UPnP Service ---
    try:
        ps_script = (
            "$svc = Get-CimInstance Win32_Service "
            "-Filter \"Name='upnphost'\" -ErrorAction Stop; "
            "if ($null -eq $svc) { 'Not Detected' } "
            "else { \"$($svc.State)|$($svc.StartMode)\" }"
        )

        output = subprocess.check_output(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                ps_script,
            ],
            shell=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            stderr=subprocess.DEVNULL,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        ).strip()

        if output == "Not Detected":
            result["UPnPHost"] = "Not Detected"

        elif "|" in output:
            state, start_mode = output.split("|", 1)

            if state == "Running":
                result["UPnPHost"] = "Running, Moderate Risk"
            elif start_mode == "Disabled":
                result["UPnPHost"] = "Disabled"
            elif state == "Stopped":
                result["UPnPHost"] = "Stopped"
            else:
                result["UPnPHost"] = "Unknown"
        else:
            result["UPnPHost"] = "Unknown"

    except (subprocess.SubprocessError, OSError):
        result["UPnPHost"] = "Unknown"

    except Exception:
        result["UPnPHost"] = "Unknown"

    # --- Remote Registry ---
    try:
        # --- Check RemoteRegistry service startup type ---
        config_output = subprocess.check_output(
            ["sc", "qc", "RemoteRegistry"],
            text=True,
            encoding="utf-8",
            stderr=subprocess.DEVNULL,
            timeout=10,
        ).lower()

        if "start_type" not in config_output:
            reg_state = "Unknown"

        elif "disabled" in config_output:
            reg_state = "Disabled"

        elif "auto_start" in config_output or "demand_start" in config_output:
            # --- Check whether the service is currently running ---
            try:
                state_output = subprocess.check_output(
                    ["sc", "query", "RemoteRegistry"],
                    text=True,
                    encoding="utf-8",
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                ).lower()

                if "running" in state_output:
                    service_running = True
                elif "stopped" in state_output:
                    service_running = False
                else:
                    service_running = None

            except Exception:
                service_running = None

            # --- Check all Windows Firewall profiles ---
            try:
                fw_status = subprocess.check_output(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        "(Get-NetFirewallProfile | "
                        "Select-Object -ExpandProperty Enabled) -join ','",
                    ],
                    shell=False,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                ).strip().lower().split(",")

                if (
                    len(fw_status) == 3
                    and all(value in ("true", "false") for value in fw_status)
                ):
                    firewall_on = all(value == "true" for value in fw_status)
                else:
                    firewall_on = None

            except Exception:
                firewall_on = None

            # --- Determine final verdict ---
            if service_running is False:
                reg_state = "Enabled, Low Risk (Service stopped)"

            elif service_running is None:
                reg_state = "Enabled, Unknown (Service state unavailable)"

            elif firewall_on is True:
                reg_state = "Enabled, Moderate Risk (Firewall On)"

            elif firewall_on is False:
                reg_state = "Enabled, Potentially Dangerous"

            else:
                reg_state = "Enabled, Potentially Dangerous"

        else:
            reg_state = "Unknown"

    except (subprocess.SubprocessError, OSError, Exception):
        reg_state = "Unknown"

    result["Remote Registry"] = reg_state

    # --- FTP Service ---
    try:
        service_state = None
        ftp_detected = False
        ftp_port = None
        sftp = False
        tftp_detected = False

        # 1. Known FTP services
        ftp_services = {
            "ftpsvc": "IIS FTP Service",
            "filezilla": "FileZilla Server"
        }

        try:
            service_cmd = (
                'powershell -NoProfile -Command '
                '"Get-Service | Where-Object { '
                '$_.Name -match \'ftpsvc|filezilla\' '
                '} | Select-Object Name, Status | ConvertTo-Json"'
            )

            services = subprocess.check_output(
                service_cmd,
                shell=True,
                text=True,
                encoding="utf-8"
            ).strip()

            if services:
                data = json.loads(services)

                if isinstance(data, dict):
                    data = [data]

                for svc in data:
                    name = svc.get("Name", "").lower()
                    status = svc.get("Status")

                    if "filezilla" in name or "ftpsvc" in name:
                        ftp_detected = True

                        if status == "Running":
                            service_state = "Running"
                        elif status == "Stopped" and service_state is None:
                            service_state = "Stopped"

        except Exception:
            pass

        # 2. TCP port detection (FTP/FTPS/HTTP)
        try:
            netstat = subprocess.check_output(
                "netstat -ano",
                shell=True,
                text=True,
                encoding="utf-8"
            )

            for line in netstat.splitlines():
                if not re.search(r"\bLISTENING\b", line, re.IGNORECASE):
                    continue

                match = re.search(
                    r"^\s*TCP\s+\S+:(\d+)\s+\S+\s+LISTENING\b",
                    line,
                    re.IGNORECASE
                )

                if not match:
                    continue

                port = int(match.group(1))

                if port in (21, 990):
                    ftp_port = port

                    if not (ftp_detected and service_state == "Stopped"):
                        ftp_detected = True
                        service_state = "Running"

                    break

        except Exception:
            pass

        # 3. FileZilla process detection
        if not ftp_detected:
            try:
                tasklist = subprocess.check_output(
                    "tasklist",
                    shell=True,
                    text=True,
                    encoding="utf-8"
                ).lower()

                if "filezilla server.exe" in tasklist:
                    ftp_detected = True
                    service_state = "Running"

            except Exception:
                pass

        # 4. SFTP detection (OpenSSH Server + TCP 22)
        try:
            ssh_service = subprocess.check_output(
                'powershell -NoProfile -Command '
                '"Get-Service -Name sshd -ErrorAction SilentlyContinue | '
                'Select-Object -ExpandProperty Status"',
                shell=True,
                text=True,
                encoding="utf-8"
            ).strip()

            if ssh_service == "Running":
                try:
                    netstat = subprocess.check_output(
                        "netstat -ano",
                        shell=True,
                        text=True,
                        encoding="utf-8"
                    )

                    if re.search(r":22\s+.*LISTENING", netstat, re.IGNORECASE):
                        sftp = True

                except Exception:
                    pass

        except Exception:
            pass

        # 5. TFTP detection (UDP port 69 + process)
        try:
            netstat = subprocess.check_output(
                "netstat -ano -p udp",
                shell=True,
                text=True,
                encoding="utf-8"
            )

            for line in netstat.splitlines():
                match = re.search(
                    r"^\s*UDP\s+\S+:69\s+\S+\s+(\d+)\s*$",
                    line,
                    re.IGNORECASE
                )

                if not match:
                    continue

                tftp_pid = match.group(1)

                try:
                    tasklist = subprocess.check_output(
                        f'tasklist /FI "PID eq {tftp_pid}" /FO CSV /NH',
                        shell=True,
                        text=True,
                        encoding="utf-8"
                    ).strip().lower()

                    # Confirm the process belongs to a known TFTP server
                    if any(name in tasklist for name in (
                        "tftpd.exe",
                        "tftpserver.exe",
                        "tftpsrv.exe",
                        "solarwinds tftp server.exe"
                    )):
                        tftp_detected = True
                        break

                except Exception:
                    pass

        except Exception:
            pass

        # 6. Final normalization
        if ftp_detected and service_state == "Stopped":
            result["FTP Service"] = "Stopped"

        elif ftp_detected and ftp_port == 21:
            result["FTP Service"] = (
                "Running, Potentially Exposed (FTP Port 21)"
            )

        elif sftp:
            result["FTP Service"] = (
                "Running, Potentially Exposed (SSH/SFTP Port 22)"
            )

        elif ftp_detected and ftp_port == 990:
            result["FTP Service"] = (
                "Running, Potentially Exposed (FTPS Port 990)"
            )

        elif tftp_detected:
            result["FTP Service"] = (
                "Running, Potentially Exposed (TFTP Port 69)"
            )

        elif ftp_detected and service_state == "Running":
            result["FTP Service"] = "Running, Unknown Port"

        else:
            result["FTP Service"] = "Not Detected"

    except Exception:
        result["FTP Service"] = "Unknown"
    
    # --- WinRM ---
    winrm_data = audit_winrm()         # run full WinRM audit
    result["WinRM"] = winrm_data["verdict"]
    
    return format_remote_access_settings(result)

def format_remote_access_settings(settings):
    report = [""]
    keys = list(settings.keys())
    
    for i, key in enumerate(keys):
        report.append(f"{key}:")
        report.append(f"  {settings[key]}")
        if i != len(keys) - 1:
            report.append("–" * 40)

    return "\n".join(report)

# --- Output ---
if __name__ == "__main__":
    print("\nRemote Access Report")
    print("–" * len("Remote Access Report"))
    
    if running_in_idle():
        print("Working... (please wait)")
        report = get_remote_access_settings()
    else:
        spinner = Spinner("Working")
        spinner.start()
        try:
            report = get_remote_access_settings()
        finally:
            spinner.stop()

    print(report)
    print("")
    os.system("pause")


