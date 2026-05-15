# -*- coding: utf-8 -*-
import subprocess
import re
import random
import winreg
import socket
import ctypes
import sys
import os
import time
import string
import shutil
import uuid
import hashlib
import json
import urllib.request
import urllib.error
import webbrowser
import threading
import datetime
import tkinter as tk
from tkinter import ttk, messagebox

HIDE = 0x08000000


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_network_adapters():
    adapters = []
    try:
        result = subprocess.run(
            ["getmac", "/v", "/fo", "csv"],
            capture_output=True, text=True, creationflags=HIDE, timeout=10
        )
        lines = result.stdout.strip().split("\n")
        if len(lines) < 2:
            return adapters
        for line in lines[1:]:
            parts = line.replace('"', '').split(',')
            if len(parts) >= 4:
                conn_name = parts[0].strip()
                adapter_desc = parts[1].strip()
                mac = parts[2].strip()
                if mac == "N/A" or not mac or len(mac) < 12:
                    continue
                atype = "Ethernet"
                nl = conn_name.lower()
                if "wi-fi" in nl or "wifi" in nl or "wireless" in nl or "wlan" in nl:
                    atype = "Wi-Fi"
                ip = get_adapter_ip(conn_name)
                rk = find_registry_key_for_adapter(adapter_desc, mac)
                adapters.append({
                    "name": conn_name,
                    "desc": adapter_desc,
                    "mac": mac.replace("-", ":"),
                    "ip": ip,
                    "type": atype,
                    "regkey": rk
                })
    except:
        pass
    return adapters

def get_adapter_ip(name):
    try:
        import psutil
        for iface, addrs in psutil.net_if_addrs().items():
            if name.lower() in iface.lower() or iface.lower() in name.lower():
                for a in addrs:
                    if a.family == socket.AF_INET:
                        return a.address
    except:
        pass
    try:
        r = subprocess.run(["ipconfig"], capture_output=True, text=True, creationflags=HIDE, timeout=5)
        found = False
        for line in r.stdout.split("\n"):
            if name.lower() in line.lower():
                found = True
            if found and "IPv4" in line and ":" in line:
                return line.split(":")[-1].strip()
    except:
        pass
    return "N/A"

def find_registry_key_for_adapter(adapter_desc, mac_address="", log_fn=None):
    mac_clean = mac_address.replace("-", "").replace(":", "").upper() if mac_address else ""
    reg_base = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
    candidates = []
    try:
        reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_base)
        i = 0
        while True:
            try:
                sn = winreg.EnumKey(reg_key, i)
                i += 1
                sp = reg_base + "\\" + sn
                try:
                    sk = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sp)
                    desc = ""
                    try:
                        desc, _ = winreg.QueryValueEx(sk, "DriverDesc")
                    except:
                        pass
                    net_addr = ""
                    try:
                        net_addr, _ = winreg.QueryValueEx(sk, "NetworkAddress")
                    except:
                        pass
                    orig_addr = ""
                    try:
                        orig_addr, _ = winreg.QueryValueEx(sk, "OriginalNetworkAddress")
                    except:
                        pass
                    winreg.CloseKey(sk)
                    if desc:
                        candidates.append({"path": sp, "desc": desc, "net": net_addr, "orig": orig_addr, "idx": sn})
                except:
                    pass
            except OSError:
                break
        winreg.CloseKey(reg_key)
    except Exception as ex:
        if log_fn:
            log_fn("Registry open failed: " + str(ex))
        return None

    if log_fn:
        log_fn("Found " + str(len(candidates)) + " registry adapter entries")

    if adapter_desc:
        ad = adapter_desc.lower().strip()
        for c in candidates:
            if c["desc"].lower().strip() == ad:
                if log_fn:
                    log_fn("Exact match: " + c["path"] + " -> " + c["desc"])
                return c["path"]
        for c in candidates:
            if ad in c["desc"].lower() or c["desc"].lower() in ad:
                if log_fn:
                    log_fn("Partial match: " + c["path"] + " -> " + c["desc"])
                return c["path"]

    if mac_clean:
        for c in candidates:
            na = c["net"].upper().replace("-", "").replace(":", "")
            oa = c["orig"].upper().replace("-", "").replace(":", "")
            if (na and na == mac_clean) or (oa and oa == mac_clean):
                if log_fn:
                    log_fn("MAC match: " + c["path"])
                return c["path"]

    if log_fn:
        log_fn("No match found. Candidates:")
        for c in candidates[:10]:
            log_fn("  " + c["idx"] + ": " + c["desc"])
    return None

def generate_random_mac():
    mac = [
        random.randint(0x00, 0xFF) & 0xFE | 0x02,
        random.randint(0x00, 0xFF),
        random.randint(0x00, 0xFF),
        random.randint(0x00, 0xFF),
        random.randint(0x00, 0xFF),
        random.randint(0x00, 0xFF),
    ]
    return ":".join("%02X" % b for b in mac)

def set_mac_address(conn_name, new_mac, regkey, adapter_desc="", log_fn=None):
    mc = new_mac.replace(":", "").replace("-", "").upper()
    steps = []
    rk = regkey
    if not rk and adapter_desc:
        rk = find_registry_key_for_adapter(adapter_desc, "", log_fn)
        steps.append("Key by desc: " + str(rk))
    if not rk:
        rk = find_registry_key_for_adapter(conn_name, "", log_fn)
        steps.append("Key by name: " + str(rk))
    if not rk:
        steps.append("NO REGISTRY KEY FOUND - cannot proceed")
        if log_fn:
            for s in steps:
                log_fn(s)
        return False, None, steps

    ok = False
    err_msgs = []
    access_list = [
        ("KEY_ALL_ACCESS|64BIT", winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY),
        ("KEY_SET_VALUE|64BIT", winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY),
        ("KEY_ALL_ACCESS", winreg.KEY_ALL_ACCESS),
        ("KEY_SET_VALUE", winreg.KEY_SET_VALUE),
        ("KEY_WRITE", winreg.KEY_WRITE),
    ]
    for label, access in access_list:
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rk, 0, access)
            winreg.SetValueEx(k, "NetworkAddress", 0, winreg.REG_SZ, mc)
            winreg.CloseKey(k)
            ok = True
            steps.append("Registry WRITE OK (" + label + ")")
            break
        except PermissionError as e:
            err_msgs.append(label + ": PermissionError - " + str(e))
        except OSError as e:
            err_msgs.append(label + ": OSError - " + str(e))
        except Exception as e:
            err_msgs.append(label + ": " + str(e))

    if not ok:
        steps.append("Registry WRITE FAILED - tried " + str(len(access_list)) + " methods")
        for em in err_msgs:
            steps.append("  " + em)
        if log_fn:
            for s in steps:
                log_fn(s)
        return False, rk, steps

    verify_ok = False
    try:
        vk = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rk)
        stored, _ = winreg.QueryValueEx(vk, "NetworkAddress")
        winreg.CloseKey(vk)
        if stored.upper() == mc:
            verify_ok = True
            steps.append("Registry VERIFY OK: " + stored)
        else:
            steps.append("Registry VERIFY MISMATCH: wrote " + mc + " read " + stored)
    except Exception as e:
        steps.append("Registry VERIFY ERROR: " + str(e))

    steps.append("Restarting adapter: " + conn_name)
    r_ok, r_method = restart_adapter(conn_name, adapter_desc, log_fn)
    steps.append("Restart: " + ("OK via " + r_method if r_ok else "FAILED"))

    if log_fn:
        for s in steps:
            log_fn(s)
    return True, rk, steps


def restart_adapter(name, adapter_desc="", log_fn=None):
    disabled = False
    method = ""

    try:
        r = subprocess.run(
            ["powershell", "-Command",
             "Disable-NetAdapter -Name '" + name + "' -Confirm:$false; $LASTEXITCODE"],
            capture_output=True, text=True, creationflags=HIDE, timeout=20)
        if r.returncode == 0 and "error" not in r.stderr.lower():
            disabled = True
            method = "Disable-NetAdapter"
            if log_fn:
                log_fn("Disabled via PowerShell Disable-NetAdapter")
    except Exception as e:
        if log_fn:
            log_fn("PowerShell Disable-NetAdapter failed: " + str(e))

    if not disabled:
        try:
            r = subprocess.run(["netsh", "interface", "set", "interface", name, "admin=disable"],
                                capture_output=True, text=True, creationflags=HIDE, timeout=15)
            if r.returncode == 0:
                disabled = True
                method = "netsh"
                if log_fn:
                    log_fn("Disabled via netsh")
        except Exception as e:
            if log_fn:
                log_fn("netsh disable failed: " + str(e))

    if not disabled:
        try:
            r = subprocess.run(["wmic", "path", "win32_networkadapter", "where",
                                "NetConnectionID='" + name + "'", "call", "disable"],
                                capture_output=True, text=True, creationflags=HIDE, timeout=15)
            if "ReturnValue = 0" in r.stdout:
                disabled = True
                method = "wmic"
                if log_fn:
                    log_fn("Disabled via wmic")
        except Exception as e:
            if log_fn:
                log_fn("wmic disable failed: " + str(e))

    if not disabled and adapter_desc:
        try:
            ps_cmd = (
                "$a = Get-PnpDevice | Where-Object { $_.FriendlyName -like '*" +
                adapter_desc.replace("'", "''") +
                "*' -and $_.Class -eq 'Net' }; "
                "if ($a) { Disable-PnpDevice -InstanceId $a.InstanceId -Confirm:$false }"
            )
            r = subprocess.run(["powershell", "-Command", ps_cmd],
                                capture_output=True, text=True, creationflags=HIDE, timeout=20)
            if r.returncode == 0 and "error" not in r.stderr.lower():
                disabled = True
                method = "PnP-device"
                if log_fn:
                    log_fn("Disabled via PnP device (hardware level)")
        except Exception as e:
            if log_fn:
                log_fn("PnP disable failed: " + str(e))

    if not disabled:
        if log_fn:
            log_fn("WARNING: Could not disable adapter - MAC might not change!")
        method = "none"

    time.sleep(3)

    enabled = False
    try:
        r = subprocess.run(
            ["powershell", "-Command",
             "Enable-NetAdapter -Name '" + name + "' -Confirm:$false"],
            capture_output=True, text=True, creationflags=HIDE, timeout=20)
        if r.returncode == 0:
            enabled = True
    except:
        pass

    if not enabled:
        try:
            r = subprocess.run(["netsh", "interface", "set", "interface", name, "admin=enable"],
                                capture_output=True, text=True, creationflags=HIDE, timeout=15)
            if r.returncode == 0:
                enabled = True
        except:
            pass

    if not enabled:
        try:
            subprocess.run(["wmic", "path", "win32_networkadapter", "where",
                            "NetConnectionID='" + name + "'", "call", "enable"],
                            capture_output=True, text=True, creationflags=HIDE, timeout=15)
            enabled = True
        except:
            pass

    if not enabled and adapter_desc:
        try:
            ps_cmd = (
                "$a = Get-PnpDevice | Where-Object { $_.FriendlyName -like '*" +
                adapter_desc.replace("'", "''") +
                "*' -and $_.Class -eq 'Net' }; "
                "if ($a) { Enable-PnpDevice -InstanceId $a.InstanceId -Confirm:$false }"
            )
            subprocess.run(["powershell", "-Command", ps_cmd],
                            capture_output=True, text=True, creationflags=HIDE, timeout=20)
            enabled = True
        except:
            pass

    time.sleep(3)
    return disabled, method

def get_current_mac_live(name):
    try:
        r = subprocess.run(["getmac", "/v", "/fo", "csv"],
                            capture_output=True, text=True, creationflags=HIDE, timeout=10)
        for line in r.stdout.strip().split("\n")[1:]:
            parts = line.replace('"', '').split(',')
            if len(parts) >= 4:
                if name.lower() in parts[0].strip().lower():
                    mac = parts[2].strip()
                    if mac and mac != "N/A":
                        return mac.replace("-", ":")
    except:
        pass
    try:
        r = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, creationflags=HIDE, timeout=10)
        found = False
        for line in r.stdout.split("\n"):
            if name.lower() in line.lower():
                found = True
            if found and "Physical Address" in line:
                parts = line.split(":", 1)
                if len(parts) >= 2:
                    return parts[1].strip().replace("-", ":")
    except:
        pass
    return None

def set_ip_address(name, ip, subnet, gw):
    try:
        cmd = ["netsh", "interface", "ip", "set", "address", "name=" + name, "static", ip, subnet, gw]
        r = subprocess.run(cmd, capture_output=True, text=True, creationflags=HIDE, timeout=10)
        return r.returncode == 0
    except:
        return False

def set_dhcp(name):
    try:
        cmd = ["netsh", "interface", "ip", "set", "address", "name=" + name, "dhcp"]
        r = subprocess.run(cmd, capture_output=True, text=True, creationflags=HIDE, timeout=10)
        return r.returncode == 0
    except:
        return False

def reset_mac(conn_name, regkey, adapter_desc=""):
    rk = regkey
    if not rk and adapter_desc:
        rk = find_registry_key_for_adapter(adapter_desc)
    if not rk:
        rk = find_registry_key_for_adapter(conn_name)
    if rk:
        for access in [winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY,
                       winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
                       winreg.KEY_ALL_ACCESS, winreg.KEY_SET_VALUE]:
            try:
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rk, 0, access)
                try:
                    winreg.DeleteValue(k, "NetworkAddress")
                except:
                    pass
                winreg.CloseKey(k)
                restart_adapter(conn_name, adapter_desc)
                return True
            except:
                pass
    return False

def flush_dns():
    try:
        r = subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, creationflags=HIDE, timeout=10)
        return r.returncode == 0
    except:
        return False

def set_dns(name, p, s=""):
    try:
        c1 = ["netsh", "interface", "ip", "set", "dns", "name=" + name, "static", p]
        r = subprocess.run(c1, capture_output=True, text=True, creationflags=HIDE, timeout=10)
        if s:
            c2 = ["netsh", "interface", "ip", "add", "dns", "name=" + name, s, "index=2"]
            subprocess.run(c2, capture_output=True, text=True, creationflags=HIDE, timeout=10)
        return r.returncode == 0
    except:
        return False

def set_dns_auto(name):
    try:
        cmd = ["netsh", "interface", "ip", "set", "dns", "name=" + name, "dhcp"]
        r = subprocess.run(cmd, capture_output=True, text=True, creationflags=HIDE, timeout=10)
        return r.returncode == 0
    except:
        return False

def get_computer_name():
    return os.environ.get("COMPUTERNAME", socket.gethostname())

def set_computer_name(n):
    try:
        rp = r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rp, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, "ComputerName", 0, winreg.REG_SZ, n)
        winreg.CloseKey(k)
        rp2 = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        k2 = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rp2, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k2, "Hostname", 0, winreg.REG_SZ, n)
        winreg.SetValueEx(k2, "NV Hostname", 0, winreg.REG_SZ, n)
        winreg.CloseKey(k2)
        return True
    except:
        return False

def random_hostname():
    p = random.choice(["DESKTOP", "PC", "LAPTOP", "WIN"])
    s = "".join(random.choices(string.ascii_uppercase + string.digits, k=7))
    return p + "-" + s

def get_hwid():
    info = {}
    cmds = {
        "Disk Serial": ["wmic", "diskdrive", "get", "serialnumber"],
        "Motherboard": ["wmic", "baseboard", "get", "serialnumber"],
        "BIOS Serial": ["wmic", "bios", "get", "serialnumber"],
        "CPU ID": ["wmic", "cpu", "get", "processorid"],
    }
    for label, cmd in cmds.items():
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, creationflags=HIDE, timeout=10)
            lines = [l.strip() for l in r.stdout.strip().split("\n") if l.strip() and l.strip() not in ("SerialNumber", "ProcessorId")]
            info[label] = lines[0] if lines else "N/A"
        except:
            info[label] = "N/A"
    try:
        rp = r"SOFTWARE\Microsoft\Cryptography"
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rp)
        v, _ = winreg.QueryValueEx(k, "MachineGuid")
        winreg.CloseKey(k)
        info["Machine GUID"] = v
    except:
        info["Machine GUID"] = "N/A"
    return info

def spoof_guid():
    ng = str(uuid.uuid4())
    try:
        rp = r"SOFTWARE\Microsoft\Cryptography"
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rp, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
        winreg.SetValueEx(k, "MachineGuid", 0, winreg.REG_SZ, ng)
        winreg.CloseKey(k)
        return ng
    except:
        return None

def clean_browser(bname):
    user = os.path.expanduser("~")
    local = os.environ.get("LOCALAPPDATA", os.path.join(user, "AppData", "Local"))
    roaming = os.environ.get("APPDATA", os.path.join(user, "AppData", "Roaming"))
    targets = {
        "Chrome": os.path.join(local, "Google", "Chrome", "User Data", "Default"),
        "Edge": os.path.join(local, "Microsoft", "Edge", "User Data", "Default"),
        "Brave": os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data", "Default"),
        "Opera": os.path.join(roaming, "Opera Software", "Opera Stable"),
    }
    count = 0
    if bname == "Firefox":
        fp = os.path.join(roaming, "Mozilla", "Firefox", "Profiles")
        if os.path.exists(fp):
            for p in os.listdir(fp):
                pp = os.path.join(fp, p)
                if os.path.isdir(pp):
                    for f in ["cookies.sqlite", "cache2", "webappsstore.sqlite", "places.sqlite"]:
                        try:
                            tp = os.path.join(pp, f)
                            if os.path.isfile(tp):
                                os.remove(tp)
                                count += 1
                            elif os.path.isdir(tp):
                                shutil.rmtree(tp, ignore_errors=True)
                                count += 1
                        except:
                            pass
        return count
    if bname in targets:
        base = targets[bname]
        for f in ["Cookies", "Cache", "Local Storage", "History", "Web Data"]:
            try:
                tp = os.path.join(base, f)
                if os.path.isfile(tp):
                    os.remove(tp)
                    count += 1
                elif os.path.isdir(tp):
                    shutil.rmtree(tp, ignore_errors=True)
                    count += 1
            except:
                pass
    return count

def get_public_ip():
    try:
        r = urllib.request.urlopen("https://ipinfo.io/json", timeout=8)
        return json.loads(r.read().decode())
    except:
        try:
            r = urllib.request.urlopen("https://api.ipify.org?format=json", timeout=8)
            return {"ip": json.loads(r.read().decode()).get("ip", "N/A")}
        except:
            return {"ip": "Failed"}

def get_wifi_passwords():
    results = []
    try:
        r = subprocess.run(["netsh", "wlan", "show", "profiles"],
                            capture_output=True, text=True, creationflags=HIDE, timeout=10)
        for line in r.stdout.split("\n"):
            if "All User Profile" in line or "Tous les utilisateurs" in line:
                p = line.split(":")[-1].strip()
                if p:
                    try:
                        r2 = subprocess.run(
                            ["netsh", "wlan", "show", "profile", p, "key=clear"],
                            capture_output=True, text=True, creationflags=HIDE, timeout=10)
                        pwd = ""
                        for l2 in r2.stdout.split("\n"):
                            if "Key Content" in l2 or "Contenu de la" in l2:
                                pwd = l2.split(":")[-1].strip()
                                break
                        results.append({"name": p, "password": pwd if pwd else "(none)"})
                    except:
                        results.append({"name": p, "password": "(error)"})
    except:
        pass
    return results

def get_active_connections():
    try:
        r = subprocess.run(["netstat", "-an"], capture_output=True, text=True, creationflags=HIDE, timeout=15)
        return r.stdout
    except:
        return "Failed"

def ping_host(host, count=4):
    try:
        r = subprocess.run(["ping", "-n", str(count), host],
                            capture_output=True, text=True, creationflags=HIDE, timeout=30)
        return r.stdout
    except:
        return "Ping failed"

def get_network_info():
    info = {}
    try:
        info["Computer Name"] = get_computer_name()
        info["Local IP"] = socket.gethostbyname(socket.gethostname())
    except:
        info["Local IP"] = "N/A"
    try:
        r = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, creationflags=HIDE, timeout=10)
        for line in r.stdout.split("\n"):
            line = line.strip()
            if "Default Gateway" in line and ":" in line:
                val = line.split(":")[-1].strip()
                if val:
                    info["Gateway"] = val
            elif "DNS Servers" in line and ":" in line:
                val = line.split(":")[-1].strip()
                if val:
                    info["DNS Server"] = val
            elif "DHCP Enabled" in line and ":" in line:
                info["DHCP"] = line.split(":")[-1].strip()
    except:
        pass
    try:
        r = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                            capture_output=True, text=True, creationflags=HIDE, timeout=10)
        for line in r.stdout.split("\n"):
            line = line.strip()
            if "SSID" in line and "BSSID" not in line and ":" in line:
                info["WiFi SSID"] = line.split(":")[-1].strip()
            elif "Signal" in line and ":" in line:
                info["WiFi Signal"] = line.split(":")[-1].strip()
            elif "Receive rate" in line and ":" in line:
                info["Speed (Rx)"] = line.split(":")[-1].strip()
            elif "Transmit rate" in line and ":" in line:
                info["Speed (Tx)"] = line.split(":")[-1].strip()
    except:
        pass
    return info

def toggle_firewall(enable):
    try:
        st = "on" if enable else "off"
        r = subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", st],
                            capture_output=True, text=True, creationflags=HIDE, timeout=10)
        return r.returncode == 0
    except:
        return False

def traceroute(host):
    try:
        r = subprocess.run(["tracert", "-d", "-h", "15", host],
                            capture_output=True, text=True, creationflags=HIDE, timeout=60)
        return r.stdout
    except:
        return "Traceroute failed"

def scan_ports(host, ports):
    results = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            r = s.connect_ex((host, port))
            if r == 0:
                try:
                    svc = socket.getservbyport(port)
                except:
                    svc = "unknown"
                results.append((port, "OPEN", svc))
            s.close()
        except:
            pass
    return results

def get_arp_table():
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True, creationflags=HIDE, timeout=10)
        return r.stdout
    except:
        return "Failed"

def get_routing_table():
    try:
        r = subprocess.run(["route", "print"], capture_output=True, text=True, creationflags=HIDE, timeout=10)
        return r.stdout
    except:
        return "Failed"

def read_hosts_file():
    try:
        with open(r"C:\Windows\System32\drivers\etc\hosts", "r") as f:
            return f.read()
    except:
        return "Failed to read hosts file"

def write_hosts_file(content):
    try:
        with open(r"C:\Windows\System32\drivers\etc\hosts", "w") as f:
            f.write(content)
        return True
    except:
        return False

def get_proxy_settings():
    try:
        rp = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, rp)
        enabled = 0
        server = ""
        try:
            enabled, _ = winreg.QueryValueEx(k, "ProxyEnable")
        except:
            pass
        try:
            server, _ = winreg.QueryValueEx(k, "ProxyServer")
        except:
            pass
        winreg.CloseKey(k)
        return {"enabled": bool(enabled), "server": server}
    except:
        return {"enabled": False, "server": ""}

def set_proxy(server, enable=True):
    try:
        rp = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, rp, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
        if server:
            winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, server)
        winreg.CloseKey(k)
        return True
    except:
        return False

def disable_proxy():
    try:
        rp = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, rp, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(k)
        return True
    except:
        return False

def whois_lookup(domain):
    try:
        r = subprocess.run(["nslookup", domain], capture_output=True, text=True, creationflags=HIDE, timeout=10)
        out = r.stdout
        r2 = subprocess.run(["nslookup", "-type=MX", domain], capture_output=True, text=True, creationflags=HIDE, timeout=10)
        out += "\n--- MX Records ---\n" + r2.stdout
        r3 = subprocess.run(["nslookup", "-type=NS", domain], capture_output=True, text=True, creationflags=HIDE, timeout=10)
        out += "\n--- NS Records ---\n" + r3.stdout
        return out
    except:
        return "Lookup failed"

def get_system_info():
    info = {}
    try:
        info["OS"] = sys.platform
        r = subprocess.run(["systeminfo"], capture_output=True, text=True, creationflags=HIDE, timeout=30)
        for line in r.stdout.split("\n"):
            line = line.strip()
            for tag in ["OS Name", "OS Version", "System Manufacturer", "System Model",
                        "Total Physical Memory", "Available Physical Memory",
                        "Processor(s)", "BIOS Version", "System Boot Time"]:
                if line.startswith(tag):
                    info[tag] = line.split(":", 1)[-1].strip()
    except:
        info["Error"] = "Could not load system info"
    return info

def toggle_adapter(name, enable):
    action = "enable" if enable else "disable"
    try:
        r = subprocess.run(["netsh", "interface", "set", "interface", name, action],
                            capture_output=True, text=True, creationflags=HIDE, timeout=10)
        return r.returncode == 0
    except:
        return False

def network_scan(subnet_prefix):
    devices = []
    def ping_one(ip):
        try:
            r = subprocess.run(["ping", "-n", "1", "-w", "500", ip],
                                capture_output=True, text=True, creationflags=HIDE, timeout=3)
            if r.returncode == 0 and "TTL=" in r.stdout:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = ""
                devices.append((ip, hostname))
        except:
            pass
    threads = []
    for i in range(1, 255):
        ip = subnet_prefix + "." + str(i)
        t = threading.Thread(target=ping_one, args=(ip,), daemon=True)
        threads.append(t)
        t.start()
        if len(threads) >= 30:
            for t in threads:
                t.join(timeout=4)
            threads = []
    for t in threads:
        t.join(timeout=4)
    devices.sort(key=lambda x: list(map(int, x[0].split("."))))
    return devices

def speed_test_download():
    results = []
    for url, size_mb in [("http://speedtest.tele2.net/1MB.zip", 1), ("http://speedtest.tele2.net/10MB.zip", 10)]:
        try:
            start = time.time()
            data = urllib.request.urlopen(url, timeout=15).read()
            elapsed = time.time() - start
            speed = round((len(data) * 8) / (elapsed * 1000000), 2)
            results.append((str(size_mb) + "MB", speed, round(elapsed, 2)))
        except:
            results.append((str(size_mb) + "MB", 0, 0))
    return results

def get_network_processes():
    try:
        r = subprocess.run(["netstat", "-b", "-n"], capture_output=True, text=True, creationflags=HIDE, timeout=15)
        return r.stdout
    except:
        return "Failed (need Admin)"

def send_wol(mac_address):
    mc = mac_address.replace(":", "").replace("-", "").replace(" ", "")
    if len(mc) != 12:
        return False
    try:
        mac_bytes = bytes.fromhex(mc)
        magic = b'\xff' * 6 + mac_bytes * 16
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(magic, ('<broadcast>', 9))
        s.close()
        return True
    except:
        return False

def generate_hash(text, algo):
    data = text.encode("utf-8")
    h = {"MD5": hashlib.md5, "SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
    return h.get(algo, hashlib.md5)(data).hexdigest()

def generate_password(length=20, use_special=True):
    chars = string.ascii_letters + string.digits
    if use_special:
        chars += "!@#$%^&*()_+-="
    pwd = [random.choice(string.ascii_uppercase), random.choice(string.ascii_lowercase), random.choice(string.digits)]
    if use_special:
        pwd.append(random.choice("!@#$%^&*"))
    for _ in range(length - len(pwd)):
        pwd.append(random.choice(chars))
    random.shuffle(pwd)
    return "".join(pwd)

def clean_temp_files():
    cleaned = 0
    total_size = 0
    temp_dirs = [os.environ.get("TEMP", ""), os.environ.get("TMP", ""),
                 os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp"),
                 os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Temp")]
    pf = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Prefetch")
    if os.path.exists(pf):
        temp_dirs.append(pf)
    seen = set()
    for d in temp_dirs:
        if not d or d in seen or not os.path.exists(d):
            continue
        seen.add(d)
        for root, dirs, files in os.walk(d, topdown=False):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    sz = os.path.getsize(fp)
                    os.remove(fp)
                    cleaned += 1
                    total_size += sz
                except:
                    pass
            for dd in dirs:
                try:
                    os.rmdir(os.path.join(root, dd))
                except:
                    pass
    return cleaned, total_size

def get_startup_items():
    items = []
    locs = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
    ]
    for hive, path, label in locs:
        try:
            k = winreg.OpenKey(hive, path)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(k, i)
                    items.append({"name": name, "path": value, "location": label})
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(k)
        except:
            pass
    sf = os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    if os.path.exists(sf):
        for f in os.listdir(sf):
            items.append({"name": f, "path": os.path.join(sf, f), "location": "Startup Folder"})
    return items


# ============================================================
#  NEW TOOLS (v2.0)
# ============================================================

def mac_vendor_lookup(mac: str) -> str:
    try:
        prefix = mac.replace(":", "").replace("-", "").strip().upper()[:6]
        if not prefix or len(prefix) < 6:
            return "Invalid MAC prefix"
        r = urllib.request.urlopen(f"https://api.macvendors.com/{prefix}", timeout=6)
        return r.read().decode().strip()
    except urllib.error.HTTPError as e:
        return f"Not found ({e.code})"
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        return f"Lookup failed: {e}"

def subnet_calculator(ip_cidr: str) -> dict:
    import ipaddress
    try:
        net = ipaddress.IPv4Network(ip_cidr, strict=False)
        hosts = list(net.hosts())
        return {
            "Network": str(net.network_address),
            "Broadcast": str(net.broadcast_address),
            "Netmask": str(net.netmask),
            "CIDR": str(net.prefixlen),
            "Wildcard": str(net.hostmask),
            "Hosts Min": str(hosts[0]) if hosts else "N/A",
            "Hosts Max": str(hosts[-1]) if hosts else "N/A",
            "Total Hosts": str(net.num_addresses - 2) if net.num_addresses > 2 else "0",
            "Is Private": "Yes" if net.is_private else "No",
        }
    except ValueError as e:
        return {"error": f"Invalid CIDR: {e}"}
    except Exception as e:
        return {"error": str(e)}

def dns_benchmark(servers: list[str] | None = None) -> list[dict]:
    import struct
    if servers is None:
        servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "8.8.4.4", "1.0.0.1"]
    results = []
    for svr in servers:
        times = []
        for _ in range(3):
            try:
                start = time.perf_counter()
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(3)
                tid = random.randint(0, 0xFFFF)
                pkt = struct.pack(">H", tid) + struct.pack(">H", 0x0100) + struct.pack(">HHHH", 1, 0, 0, 0)
                pkt += b'\x03' + b'www' + b'\x06' + b'google' + b'\x03' + b'com' + b'\x00'
                pkt += struct.pack(">H", 1) + struct.pack(">H", 1)
                s.sendto(pkt, (svr, 53))
                s.recvfrom(512)
                elapsed = (time.perf_counter() - start) * 1000
                times.append(round(elapsed, 1))
            except Exception:
                times.append(None)
            finally:
                try:
                    s.close()
                except Exception:
                    pass
        avg = round(sum(t for t in times if t is not None) / max(len([t for t in times if t is not None]), 1), 1) if any(times) else None
        results.append({"server": svr, "times": times, "average": avg})
    return results

def get_network_usage() -> list[dict]:
    import psutil
    stats = []
    try:
        io = psutil.net_io_counters(pernic=True)
        for iface, counters in io.items():
            stats.append({
                "interface": iface,
                "bytes_sent": counters.bytes_sent,
                "bytes_recv": counters.bytes_recv,
                "packets_sent": counters.packets_sent,
                "packets_recv": counters.packets_recv,
                "errin": counters.errin,
                "errout": counters.errout,
                "dropin": counters.dropin,
                "dropout": counters.dropout,
            })
        stats.sort(key=lambda x: x["bytes_recv"] + x["bytes_sent"], reverse=True)
    except Exception as e:
        stats.append({"interface": f"Error: {e}"})
    return stats

def format_bytes(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.2f} {unit}"
        b /= 1024
    return f"{b:.2f} PB"

def get_bluetooth_devices() -> list[dict]:
    devices = []
    try:
        r = subprocess.run(
            ["powershell", "-Command", "Get-PnpDevice -Class Bluetooth | Select-Object FriendlyName, Status, InstanceId | ConvertTo-Json"],
            capture_output=True, text=True, creationflags=HIDE, timeout=15
        )
        if r.stdout.strip():
            data = json.loads(r.stdout)
            if isinstance(data, dict):
                data = [data]
            for d in data:
                devices.append({
                    "name": d.get("FriendlyName", "Unknown"),
                    "status": d.get("Status", "Unknown"),
                    "id": d.get("InstanceId", "")[-20:],
                })
    except Exception:
        pass
    if not devices:
        try:
            r = subprocess.run(
                ["powershell", "-Command", "Get-PnpDevice -Class Bluetooth | Format-Table -AutoSize | Out-String"],
                capture_output=True, text=True, creationflags=HIDE, timeout=15
            )
            devices.append({"name": "Raw output", "status": "", "id": r.stdout.strip()[:200]})
        except Exception:
            devices.append({"name": "No Bluetooth devices found", "status": "", "id": ""})
    return devices

def get_scheduled_tasks() -> list[dict]:
    tasks = []
    try:
        r = subprocess.run(
            ["powershell", "-Command", "Get-ScheduledTask | Where-Object State -ne Disabled | Select-Object -First 50 TaskName, TaskPath, State | ConvertTo-Json"],
            capture_output=True, text=True, creationflags=HIDE, timeout=15
        )
        if r.stdout.strip():
            data = json.loads(r.stdout)
            if isinstance(data, dict):
                data = [data]
            for t in data:
                tasks.append({
                    "name": t.get("TaskName", "?"),
                    "path": t.get("TaskPath", "?"),
                    "state": t.get("State", "?"),
                })
    except Exception:
        pass
    return tasks

def get_disk_info() -> list[dict]:
    disks = []
    try:
        import psutil
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append({
                    "device": part.device,
                    "mount": part.mountpoint,
                    "fstype": part.fstype,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent,
                })
            except Exception:
                disks.append({
                    "device": part.device,
                    "mount": part.mountpoint,
                    "fstype": part.fstype,
                    "total": 0, "used": 0, "free": 0, "percent": 0,
                })
    except Exception as e:
        disks.append({"device": f"Error: {e}", "mount": "", "fstype": "", "total": 0, "used": 0, "free": 0, "percent": 0})
    return disks

def mac_convert(mac: str) -> dict:
    raw = mac.replace(":", "").replace("-", "").replace(".", "").strip().upper()
    if len(raw) != 12:
        return {"error": "Invalid MAC - need 12 hex chars"}
    return {
        "IEEE": ":".join(raw[i:i+2] for i in range(0, 12, 2)),
        "Cisco": ".".join(raw[i:i+4] for i in range(0, 12, 4)),
        "Plain": raw,
        "Dash": "-".join(raw[i:i+2] for i in range(0, 12, 2)),
        "Reverse": ":".join(reversed([raw[i:i+2] for i in range(0, 12, 2)])),
    }

def get_uptime() -> str:
    try:
        r = subprocess.run(["net", "statistics", "workstation"],
                           capture_output=True, text=True, creationflags=HIDE, timeout=10)
        for line in r.stdout.split("\n"):
            if "since" in line.lower():
                return line.split("since")[-1].strip()
    except Exception:
        pass
    try:
        r = subprocess.run(["wmic", "os", "get", "lastbootuptime"],
                           capture_output=True, text=True, creationflags=HIDE, timeout=10)
        lines = [l.strip() for l in r.stdout.split("\n") if l.strip() and "LastBoot" not in l]
        if lines:
            return lines[0][:19]
    except Exception:
        pass
    return "N/A"

def get_installed_apps() -> list[dict]:
    apps = []
    keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    seen = set()
    for hive, path in keys:
        try:
            k = winreg.OpenKey(hive, path)
            i = 0
            while True:
                try:
                    subkey = winreg.EnumKey(k, i)
                    i += 1
                    try:
                        sk = winreg.OpenKey(hive, path + "\\" + subkey)
                        try:
                            name, _ = winreg.QueryValueEx(sk, "DisplayName")
                        except:
                            winreg.CloseKey(sk)
                            continue
                        ver = ""
                        try:
                            ver, _ = winreg.QueryValueEx(sk, "DisplayVersion")
                        except:
                            pass
                        publisher = ""
                        try:
                            publisher, _ = winreg.QueryValueEx(sk, "Publisher")
                        except:
                            pass
                        if name and name not in seen:
                            seen.add(name)
                            apps.append({"name": name, "version": ver, "publisher": publisher})
                        winreg.CloseKey(sk)
                    except:
                        pass
                except OSError:
                    break
            winreg.CloseKey(k)
        except Exception:
            pass
    apps.sort(key=lambda x: x["name"].lower())
    return apps

def get_services(status_filter: str = "all") -> list[dict]:
    services = []
    try:
        cmd = ["powershell", "-Command",
               "Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json"]
        r = subprocess.run(cmd, capture_output=True, text=True, creationflags=HIDE, timeout=20)
        if r.stdout.strip():
            data = json.loads(r.stdout)
            if isinstance(data, dict):
                data = [data]
            for s in data:
                services.append({
                    "name": s.get("Name", "?"),
                    "display": s.get("DisplayName", "?"),
                    "status": s.get("Status", "?"),
                })
    except Exception:
        pass
    if status_filter == "running":
        services = [s for s in services if s["status"].lower() == "running"]
    elif status_filter == "stopped":
        services = [s for s in services if s["status"].lower() == "stopped"]
    return services

def get_env_vars() -> list[dict]:
    return sorted([{"name": k, "value": v[:120]} for k, v in os.environ.items()], key=lambda x: x["name"].lower())

def get_ntp_time(server: str = "pool.ntp.org") -> dict:
    try:
        import struct
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(5)
        pkt = b'\x1b' + 47 * b'\x00'
        start = time.perf_counter()
        client.sendto(pkt, (server, 123))
        data, addr = client.recvfrom(1024)
        rtt = round((time.perf_counter() - start) * 1000, 1)
        client.close()
        import struct
        t = struct.unpack("!12I", data)[10]
        from datetime import datetime, timezone
        ntp_time = datetime.fromtimestamp(t - 2208988800, tz=timezone.utc)
        return {
            "server": server,
            "time": ntp_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "rtt_ms": rtt,
            "local": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
    except Exception as e:
        return {"server": server, "error": str(e)}

def get_display_info() -> list[dict]:
    displays = []
    try:
        import psutil
        from PIL import ImageGrab
        img = ImageGrab.grab()
        displays.append({
            "width": img.width,
            "height": img.height,
            "mode": img.mode,
        })
    except Exception:
        pass
    try:
        r = subprocess.run(["wmic", "desktopmonitor", "get", "name,screenwidth,screenheight,/format:csv"],
                           capture_output=True, text=True, creationflags=HIDE, timeout=10)
        for line in r.stdout.split("\n")[1:]:
            parts = line.strip().split(",")
            if len(parts) >= 3:
                try:
                    displays.append({"width": parts[-2], "height": parts[-1], "mode": ""})
                except:
                    pass
    except Exception:
        pass
    return displays


# ============================================================
#  THEME COLORS
# ============================================================
BG = "#0d1117"
BG2 = "#161b22"
BG3 = "#21262d"
FG = "#e6edf3"
DIM = "#7d8590"
BLUE = "#2f81f7"
GREEN = "#3fb950"
RED = "#f85149"
ORANGE = "#d29922"
PURPLE = "#a371f7"
CYAN = "#39d2c0"
PINK = "#db61a2"

def geolocate_ip(ip):
    try:
        r = urllib.request.urlopen("https://ipinfo.io/" + ip + "/json", timeout=8)
        return json.loads(r.read().decode())
    except:
        return {"error": "Failed to lookup " + ip}


def get_bandwidth_stats():
    try:
        r = subprocess.run(["netstat", "-e"], capture_output=True, text=True, creationflags=HIDE, timeout=10)
        return r.stdout
    except:
        return "Failed"


def kill_process(name):
    try:
        r = subprocess.run(["taskkill", "/F", "/IM", name], capture_output=True, text=True, creationflags=HIDE, timeout=10)
        return r.returncode == 0, r.stdout + r.stderr
    except:
        return False, "Failed"


def get_running_processes():
    try:
        r = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True, creationflags=HIDE, timeout=10)
        procs = []
        for line in r.stdout.strip().split("\n"):
            parts = line.replace('"', '').split(',')
            if len(parts) >= 5:
                procs.append({"name": parts[0], "pid": parts[1], "mem": parts[4]})
        return procs
    except:
        return []


def clear_clipboard():
    try:
        subprocess.run(["cmd", "/c", "echo off | clip"], capture_output=True, creationflags=HIDE, timeout=5)
        return True
    except:
        return False


def export_to_file(content, filename):
    try:
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        path = os.path.join(desktop, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path
    except:
        return None


TOOL_EMOJI = {
    "MAC Address": "\U0001f512", "IP Address": "\U0001f310", "DNS": "\U0001f4e1",
    "Hostname": "\U0001f4bb", "Hardware ID": "\U0001f194",
    "Browser Clean": "\U0001f9f9", "Proxy": "\U0001f50c", "Hosts File": "\U0001f4c4",
    "Public IP": "\U0001f30d", "WiFi Pass": "\U0001f4f6", "Net Info": "\U0001f4ca",
    "NetScan": "\U0001f50d", "Speed Test": "\u26a1", "Network Usage": "\U0001f4c8",
    "Connections": "\U0001f517", "Ping/Trace": "\U0001f4e8", "DNS Lookup": "\U0001f50e",
    "ARP/Routes": "\U0001f30d", "IP Geolocate": "\U0001f4cd", "DNS Benchmark": "\u23f0",
    "Subnet Calc": "\U0001f9ee", "Network Time": "\U0001f550",
    "Firewall": "\U0001f6e1", "Port Scanner": "\U0001f513", "Processes": "\u2699",
    "Adapter Ctl": "\U0001f518",
    "System Info": "\U0001f5a5", "Startup": "\U0001f680", "Temp Cleaner": "\U0001f5d1",
    "Task Kill": "\u2620", "Scheduled Tasks": "\U0001f4cb", "Disk Info": "\U0001f4be",
    "Uptime": "\u23f0", "Installed Apps": "\U0001f4e6", "Services": "\U0001f527",
    "Environment": "\U0001f33f",
    "Hash Gen": "#", "PassGen": "\U0001f511", "Wake on LAN": "\U0001f319",
    "Clipboard": "\U0001f4cb", "MAC Vendor": "\U0001f3ed", "Bluetooth": "\U0001f501",
    "About": "\u2139", "MAC Converter": "\U0001f504",
}
CATEGORIES = [
    ("\U0001f512 Identity", BLUE, ["MAC Address", "IP Address", "DNS", "Hostname", "Hardware ID"]),
    ("\U0001f6f8 Privacy", PURPLE, ["Browser Clean", "Proxy", "Hosts File"]),
    ("\U0001f30d Network", GREEN, ["Public IP", "WiFi Pass", "Net Info", "NetScan", "Speed Test", "Network Usage"]),
    ("\U0001f52c Diagnostic", CYAN, ["Connections", "Ping/Trace", "DNS Lookup", "ARP/Routes", "IP Geolocate", "DNS Benchmark", "Subnet Calc", "Network Time"]),
    ("\U0001f6e1 Security", RED, ["Firewall", "Port Scanner", "Processes", "Adapter Ctl"]),
    ("\U0001f5a5 System", ORANGE, ["System Info", "Startup", "Temp Cleaner", "Task Kill", "Scheduled Tasks", "Disk Info", "Uptime", "Installed Apps", "Services", "Environment"]),
    ("\U0001f3b2 Utils", PINK, ["Hash Gen", "PassGen", "Wake on LAN", "Clipboard", "MAC Vendor", "Bluetooth", "About", "MAC Converter"]),
]


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MACalypse")
        try:
            self.iconbitmap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico"))
        except:
            pass
        self.geometry("1150x780")
        self.minsize(1050, 700)
        self.configure(bg=BG)
        self.adapters = []
        self.sel = None
        self._pages = {}
        self._built_pages = set()

        self._setup_styles()
        self._build_layout()

        self.lift()
        self.attributes("-topmost", True)
        self.after(300, lambda: self.attributes("-topmost", False))
        self.after(500, self._load_adapters)

    def _setup_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=BG2, foreground=FG, padding=[10, 5],
                     font=("Segoe UI", 9, "bold"))
        s.map("TNotebook.Tab", background=[("selected", BLUE)], foreground=[("selected", "#fff")])

    def _build_layout(self):
        hdr = tk.Frame(self, bg=BG2, height=48)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="  \U0001f47e MACalypse", bg=BG2, fg=RED,
                 font=("Segoe UI", 15, "bold")).pack(side="left", padx=8, pady=8)
        tk.Label(hdr, text="42 Tools", bg=BG2, fg=PURPLE, font=("Segoe UI", 9)).pack(side="left", padx=4)
        atxt = "ADMIN" if is_admin() else "NO ADMIN"
        acol = GREEN if is_admin() else RED
        tk.Label(hdr, text=atxt, bg=BG2, fg=acol, font=("Segoe UI", 10, "bold")).pack(side="right", padx=12)

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=8, pady=4)

        sidebar = tk.Frame(body, bg=BG2, width=220)
        sidebar.pack(side="left", fill="y", padx=(0, 6))
        sidebar.pack_propagate(False)

        sel_panel = tk.Frame(sidebar, bg=BG3, padx=6, pady=4)
        sel_panel.pack(fill="x", padx=4, pady=(6, 4))
        tk.Label(sel_panel, text="SELECTED", bg=BG3, fg=DIM, font=("Segoe UI", 7, "bold")).pack(anchor="w")
        self.lbl_sel_name = tk.Label(sel_panel, text="(none)", bg=BG3, fg=FG, font=("Segoe UI", 9, "bold"), anchor="w")
        self.lbl_sel_name.pack(anchor="w")
        self.lbl_sel_mac = tk.Label(sel_panel, text="MAC: ---", bg=BG3, fg=BLUE, font=("Consolas", 8), anchor="w")
        self.lbl_sel_mac.pack(anchor="w")
        self.lbl_sel_ip = tk.Label(sel_panel, text="IP: ---", bg=BG3, fg=GREEN, font=("Consolas", 8), anchor="w")
        self.lbl_sel_ip.pack(anchor="w")

        hdr2 = tk.Frame(sidebar, bg=BG2)
        hdr2.pack(fill="x", padx=4, pady=(4, 2))
        tk.Label(hdr2, text="Adapters", bg=BG2, fg=FG, font=("Segoe UI", 9, "bold")).pack(side="left")
        tk.Button(hdr2, text="\U0001f504 Refresh", bg=BLUE, fg="#fff", font=("Segoe UI", 7, "bold"),
                  bd=0, cursor="hand2", command=self._load_adapters).pack(side="right")

        self.adapter_frame = tk.Frame(sidebar, bg=BG2)
        self.adapter_frame.pack(fill="both", expand=True, padx=4, pady=2)

        tk.Button(sidebar, text="\U0001f504 FULL IDENTITY RESET", bg=RED, fg="#fff",
                  font=("Segoe UI", 10, "bold"), bd=0, cursor="hand2", height=2,
                  command=self._full_reset).pack(fill="x", padx=6, pady=(4, 4))
        tk.Button(sidebar, text="Export Log", bg=BG3, fg=DIM, font=("Segoe UI", 8),
                  bd=0, cursor="hand2", command=self._export_log).pack(fill="x", padx=6, pady=(0, 6))

        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        cat_bar = tk.Frame(right, bg=BG)
        cat_bar.pack(fill="x", pady=(0, 4))
        self._cat_btns = {}
        for cat_name, color, _ in CATEGORIES:
            b = tk.Button(cat_bar, text=cat_name, bg=BG2, fg=color,
                          font=("Segoe UI", 9, "bold"), bd=0, cursor="hand2", padx=10, pady=4,
                          command=lambda c=cat_name: self._show_category(c))
            b.pack(side="left", padx=2)
            self._cat_btns[cat_name] = b

        self._content = tk.Frame(right, bg=BG)
        self._content.pack(fill="both", expand=True)

        self._current_cat = None
        self._cat_frames = {}

        lf = tk.Frame(right, bg=BG2)
        lf.pack(fill="x", pady=(6, 0))
        tk.Label(lf, text="\U0001f4dd Activity Log", bg=BG2, fg=DIM, font=("Segoe UI", 8, "bold")).pack(
            anchor="w", padx=6, pady=(4, 1))
        self.log_box = tk.Text(lf, bg="#0d1117", fg=FG, font=("Consolas", 8), height=5,
                               bd=0, wrap="word", insertbackground=FG)
        self.log_box.pack(fill="x", padx=4, pady=(0, 4))

        for cat_name, _, tools in CATEGORIES:
            nb = ttk.Notebook(self._content)
            for tool_name in tools:
                page = tk.Frame(nb, bg=BG2, padx=12, pady=12)
                tab_name = TOOL_EMOJI.get(tool_name, "") + " " + tool_name
                nb.add(page, text="  " + tab_name + "  ")
                self._build_tool(tool_name, page)
            self._cat_frames[cat_name] = nb

        status = tk.Frame(self, bg=BG3, height=24)
        status.pack(fill="x", side="bottom")
        status.pack_propagate(False)
        self.lbl_status_left = tk.Label(status, text="Ready", bg=BG3, fg=DIM, font=("Segoe UI", 8))
        self.lbl_status_left.pack(side="left", padx=8)
        self.lbl_status_right = tk.Label(status, text="", bg=BG3, fg=DIM, font=("Segoe UI", 8))
        self.lbl_status_right.pack(side="right", padx=8)
        self._update_status_time()

        self._show_category("Identity")

    def _show_category(self, cat_name):
        if self._current_cat == cat_name:
            return
        self._current_cat = cat_name

        for cn, btn in self._cat_btns.items():
            for c, clr, _ in CATEGORIES:
                if c == cn:
                    if cn == cat_name:
                        btn.configure(bg=clr, fg="#fff")
                    else:
                        btn.configure(bg=BG2, fg=DIM)
                    break

        for cn, nb in self._cat_frames.items():
            if cn == cat_name:
                nb.pack(fill="both", expand=True)
            else:
                nb.pack_forget()

    def _build_tool(self, name, f):
        f.columnconfigure(0, weight=1)
        if name == "MAC Address":
            self._build_mac(f)
        elif name == "IP Address":
            self._build_ip(f)
        elif name == "DNS":
            self._build_dns(f)
        elif name == "Hostname":
            self._build_host(f)
        elif name == "Hardware ID":
            self._build_hwid(f)
        elif name == "Browser Clean":
            self._build_browser(f)
        elif name == "Proxy":
            self._build_proxy(f)
        elif name == "Hosts File":
            self._build_hosts(f)
        elif name == "Public IP":
            self._build_pubip(f)
        elif name == "WiFi Pass":
            self._build_wifi(f)
        elif name == "Net Info":
            self._build_netinfo(f)
        elif name == "NetScan":
            self._build_netscan(f)
        elif name == "Speed Test":
            self._build_speed(f)
        elif name == "Connections":
            self._build_conns(f)
        elif name == "Ping/Trace":
            self._build_ping(f)
        elif name == "DNS Lookup":
            self._build_lookup(f)
        elif name == "ARP/Routes":
            self._build_arp(f)
        elif name == "Firewall":
            self._build_fw(f)
        elif name == "Port Scanner":
            self._build_ports(f)
        elif name == "Processes":
            self._build_procs(f)
        elif name == "Adapter Ctl":
            self._build_adpctl(f)
        elif name == "System Info":
            self._build_sysinfo(f)
        elif name == "Startup":
            self._build_startup(f)
        elif name == "Temp Cleaner":
            self._build_temp(f)
        elif name == "Hash Gen":
            self._build_hash(f)
        elif name == "PassGen":
            self._build_passgen(f)
        elif name == "Wake on LAN":
            self._build_wol(f)
        elif name == "IP Geolocate":
            self._build_geolocate(f)
        elif name == "Task Kill":
            self._build_taskkill(f)
        elif name == "Clipboard":
            self._build_clipboard(f)
        elif name == "MAC Vendor":
            self._build_mac_vendor(f)
        elif name == "Subnet Calc":
            self._build_subnet(f)
        elif name == "DNS Benchmark":
            self._build_dns_bench(f)
        elif name == "Network Usage":
            self._build_net_usage(f)
        elif name == "Bluetooth":
            self._build_bluetooth(f)
        elif name == "About":
            self._build_about(f)
        elif name == "MAC Converter":
            self._build_mac_converter(f)
        elif name == "Uptime":
            self._build_uptime(f)
        elif name == "Installed Apps":
            self._build_installed(f)
        elif name == "Services":
            self._build_services(f)
        elif name == "Environment":
            self._build_env(f)
        elif name == "Network Time":
            self._build_ntp(f)
        elif name == "Scheduled Tasks":
            self._build_sched_tasks(f)
        elif name == "Disk Info":
            self._build_disk_info(f)

    def _entry(self, parent, **kw):
        return tk.Entry(parent, bg=BG3, fg=FG, insertbackground=FG, font=("Consolas", 11),
                        bd=1, relief="solid", **kw)

    def _text(self, parent, h=12):
        return tk.Text(parent, bg="#0d1117", fg=FG, font=("Consolas", 10), bd=0,
                       wrap="word", insertbackground=FG, height=h)

    def _btn(self, parent, text, color, fg="#fff", cmd=None):
        return tk.Button(parent, text=text, bg=color, fg=fg, font=("Segoe UI", 10, "bold"),
                         bd=0, cursor="hand2", command=cmd)

    # ---- LOG ----
    def log(self, msg, level="info"):
        tags = {"info": "[*]", "success": "[+]", "error": "[-]", "warning": "[!]"}
        self.log_box.insert("end", tags.get(level, "[*]") + " " + msg + "\n")
        self.log_box.see("end")

    def _update_status_time(self):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        cnt = str(len(self.adapters)) + " adapters"
        sel = self.sel["name"] if self.sel else "none"
        self.lbl_status_right.config(text=now + "  |  " + cnt + "  |  Selected: " + sel)
        self.after(1000, self._update_status_time)

    def _set_status(self, msg):
        try:
            self.lbl_status_left.config(text=msg)
        except:
            pass

    def _export_log(self):
        content = self.log_box.get("1.0", "end").strip()
        if not content:
            messagebox.showinfo("Export", "Log is empty")
            return
        path = export_to_file(content, "MACalypse_Log.txt")
        if path:
            self.log("Log exported to: " + path, "success")
            messagebox.showinfo("Export", "Log saved to:\n" + path)
        else:
            self.log("Export failed", "error")

    def _update_sel_panel(self):
        if self.sel:
            self.lbl_sel_name.config(text=self.sel["name"])
            self.lbl_sel_mac.config(text="MAC: " + self.sel["mac"])
            self.lbl_sel_ip.config(text="IP: " + str(self.sel.get("ip", "N/A")))
        else:
            self.lbl_sel_name.config(text="(none)")
            self.lbl_sel_mac.config(text="MAC: ---")
            self.lbl_sel_ip.config(text="IP: ---")

    # ---- ADAPTERS ----
    def _load_adapters(self):
        for w in self.adapter_frame.winfo_children():
            w.destroy()
        self.log("Loading adapters...", "info")
        self.update()
        self.adapters = get_network_adapters()
        if not self.adapters:
            tk.Label(self.adapter_frame, text="No adapters", bg=BG2, fg=DIM).pack(pady=10)
            return
        for a in self.adapters:
            col = PURPLE if a["type"] == "Wi-Fi" else CYAN
            card = tk.Frame(self.adapter_frame, bg=BG3, cursor="hand2")
            card.pack(fill="x", pady=2, padx=2)
            tk.Frame(card, bg=col, width=4).pack(side="left", fill="y")
            inf = tk.Frame(card, bg=BG3)
            inf.pack(side="left", fill="both", expand=True, padx=5, pady=3)
            nm = a["name"][:20] + "..." if len(a["name"]) > 23 else a["name"]
            l1 = tk.Label(inf, text=nm, bg=BG3, fg=FG, font=("Segoe UI", 8, "bold"), anchor="w")
            l1.pack(anchor="w")
            l2 = tk.Label(inf, text=a["type"] + " | " + a["mac"], bg=BG3, fg=DIM,
                          font=("Consolas", 7), anchor="w")
            l2.pack(anchor="w")
            for w in [card, inf, l1, l2]:
                w.bind("<Button-1>", lambda e, x=a: self._select(x))
        self.log("Found " + str(len(self.adapters)) + " adapter(s)", "info")
        if self.adapters and not self.sel:
            self._select(self.adapters[0])
            self.log("Auto-selected: " + self.adapters[0]["name"], "info")

    def _select(self, a):
        self.sel = a
        for w in self.adapter_frame.winfo_children():
            try:
                w.configure(bg=BG3)
            except:
                pass
        try:
            self.lbl_mac.config(text=a["mac"])
        except:
            pass
        try:
            self.lbl_ip.config(text=a["ip"] or "N/A")
        except:
            pass
        try:
            self.lbl_mac_old.config(text=a["mac"])
            self.lbl_mac_new.config(text="---")
            self.lbl_mac_status.config(text="Ready - click Change or Check", fg=DIM)
            self.lbl_mac_reg.config(text=str(a.get("regkey", "N/A"))[:60])
        except:
            pass
        self._update_sel_panel()
        self._set_status("Selected: " + a["name"])
        self.log(">> " + a["name"] + " | MAC: " + a["mac"] + " | IP: " + str(a["ip"]), "success")

    # ============================================================
    #  TOOL BUILDERS (each builds UI inside a frame)
    # ============================================================

    # ---- MAC ADDRESS ----
    def _build_mac(self, f):
        f.columnconfigure(1, weight=1)
        tk.Label(f, text="Current MAC:", bg=BG2, fg=DIM).grid(row=0, column=0, sticky="w", pady=4)
        self.lbl_mac = tk.Label(f, text="--:--:--:--:--:--", bg=BG2, fg=BLUE, font=("Consolas", 14, "bold"))
        self.lbl_mac.grid(row=0, column=1, sticky="w", padx=10, pady=4)

        tk.Label(f, text="New MAC:", bg=BG2, fg=DIM).grid(row=1, column=0, sticky="w", pady=4)
        self.ent_mac = self._entry(f, width=22)
        self.ent_mac.grid(row=1, column=1, sticky="ew", padx=10, pady=4)

        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=2, column=0, columnspan=2, sticky="w", pady=6)
        self._btn(bf, "Random MAC", PURPLE, cmd=self._gen_mac).pack(side="left", padx=(0, 6))
        self._btn(bf, "CHANGE MAC", BLUE, cmd=self._change_mac).pack(side="left", padx=(0, 6))
        self._btn(bf, "Reset Original", RED, cmd=self._reset_mac).pack(side="left")

        tk.Frame(f, bg=DIM, height=1).grid(row=3, column=0, columnspan=2, sticky="ew", pady=8)

        tk.Label(f, text="MAC CHECKER", bg=BG2, fg=ORANGE, font=("Segoe UI", 11, "bold")).grid(
            row=4, column=0, columnspan=2, sticky="w", pady=(0, 4))
        ck = tk.Frame(f, bg=BG3, padx=10, pady=6)
        ck.grid(row=5, column=0, columnspan=2, sticky="ew")
        ck.columnconfigure(1, weight=1)
        tk.Label(ck, text="OLD:", bg=BG3, fg=DIM).grid(row=0, column=0, sticky="w", pady=2)
        self.lbl_mac_old = tk.Label(ck, text="---", bg=BG3, fg=RED, font=("Consolas", 12, "bold"))
        self.lbl_mac_old.grid(row=0, column=1, sticky="w", padx=8)
        tk.Label(ck, text="NEW:", bg=BG3, fg=DIM).grid(row=1, column=0, sticky="w", pady=2)
        self.lbl_mac_new = tk.Label(ck, text="---", bg=BG3, fg=GREEN, font=("Consolas", 12, "bold"))
        self.lbl_mac_new.grid(row=1, column=1, sticky="w", padx=8)
        tk.Label(ck, text="STATUS:", bg=BG3, fg=DIM).grid(row=2, column=0, sticky="w", pady=2)
        self.lbl_mac_status = tk.Label(ck, text="---", bg=BG3, fg=DIM, font=("Segoe UI", 12, "bold"))
        self.lbl_mac_status.grid(row=2, column=1, sticky="w", padx=8)
        tk.Label(ck, text="REG:", bg=BG3, fg=DIM, font=("Segoe UI", 8)).grid(row=3, column=0, sticky="w")
        self.lbl_mac_reg = tk.Label(ck, text="---", bg=BG3, fg=DIM, font=("Consolas", 7))
        self.lbl_mac_reg.grid(row=3, column=1, sticky="w", padx=8)

        bf2 = tk.Frame(f, bg=BG2)
        bf2.grid(row=6, column=0, columnspan=2, sticky="w", pady=6)
        self._btn(bf2, "CHECK NOW", ORANGE, fg="#000", cmd=self._check_mac).pack(side="left", padx=(0, 6))
        self._btn(bf2, "Copy Report", BLUE, cmd=self._copy_mac_report).pack(side="left")

        tk.Frame(f, bg=DIM, height=1).grid(row=7, column=0, columnspan=2, sticky="ew", pady=8)
        tk.Label(f, text="CHANGE ALL ADAPTERS (PC + WiFi)", bg=BG2, fg=RED,
                 font=("Segoe UI", 11, "bold")).grid(row=8, column=0, columnspan=2, sticky="w", pady=(0, 4))

        allf = tk.Frame(f, bg=BG3, padx=10, pady=8)
        allf.grid(row=9, column=0, columnspan=2, sticky="ew")
        self.all_mac_text = tk.Text(allf, bg="#0d1117", fg=FG, font=("Consolas", 10), height=5,
                                     bd=0, wrap="word", insertbackground=FG)
        self.all_mac_text.pack(fill="x")

        bf3 = tk.Frame(f, bg=BG2)
        bf3.grid(row=10, column=0, columnspan=2, sticky="w", pady=6)
        self._btn(bf3, "CHANGE ALL MACs", RED, cmd=self._change_all_macs).pack(side="left", padx=(0, 6))
        self._btn(bf3, "CHECK ALL", ORANGE, fg="#000", cmd=self._check_all_macs).pack(side="left")

    def _gen_mac(self):
        m = generate_random_mac()
        self.ent_mac.delete(0, "end")
        self.ent_mac.insert(0, m)
        self.log("Random MAC: " + m, "info")

    def _change_mac(self):
        if not self.sel:
            self.log("Select adapter first!", "error"); return
        m = self.ent_mac.get().strip()
        if not re.match(r'^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$', m):
            self.log("Invalid MAC! Use XX:XX:XX:XX:XX:XX", "error"); return
        old = self.sel["mac"]
        n = self.sel["name"]
        desc = self.sel.get("desc", "")
        rk = self.sel["regkey"]
        self.lbl_mac_old.config(text=old)
        self.lbl_mac_status.config(text="CHANGING... (wait ~20s)", fg=ORANGE)
        self.lbl_mac_reg.config(text=str(rk or "searching...")[:60])
        self.log("========================================", "warning")
        self.log("  MAC CHANGE START", "warning")
        self.log("========================================", "warning")
        self.log("Connection: " + n, "info")
        self.log("Adapter:    " + desc, "info")
        self.log("Old MAC:    " + old, "info")
        self.log("Target MAC: " + m, "info")
        self.log("Admin:      " + ("YES" if is_admin() else "NO!!!"), "success" if is_admin() else "error")
        if not is_admin():
            self.log("*** RUN AS ADMIN! Right-click run.bat -> Run as Admin ***", "error")
        self.update()
        target = m
        def step_log(msg):
            self.after(0, lambda: self.log("  " + msg, "info"))
        def worker():
            ok, used_rk, steps = set_mac_address(n, target, rk, desc, step_log)
            for s in steps:
                self.after(0, lambda ss=s: self.log("  >> " + ss, "success" if "OK" in ss else ("error" if "FAIL" in ss else "info")))
            if used_rk:
                self.after(0, lambda: self.lbl_mac_reg.config(text=str(used_rk)[-30:]))
            time.sleep(4)
            live = get_current_mac_live(n)
            self.after(0, lambda: self.log("  Live MAC: " + str(live), "info"))
            self.after(0, lambda: self._mac_done(ok, old, target, live))
        threading.Thread(target=worker, daemon=True).start()

    def _mac_done(self, ok, old, target, live):
        self.lbl_mac_new.config(text=live or "(unreadable)")
        oc = old.replace(":", "").replace("-", "").upper()
        nc = (live or "").replace(":", "").replace("-", "").upper()
        tc = target.replace(":", "").replace("-", "").upper()
        if nc == tc:
            self.lbl_mac_status.config(text="CHANGED!", fg=GREEN)
            self.log("MAC verified: " + str(live), "success")
        elif nc != oc and nc:
            self.lbl_mac_status.config(text="CHANGED (diff from target)", fg=ORANGE)
            self.log("MAC changed: " + str(live), "warning")
        elif ok:
            self.lbl_mac_status.config(text="Registry set - restart adapter", fg=ORANGE)
            self.log("Registry updated, restart adapter manually", "warning")
        else:
            self.lbl_mac_status.config(text="FAILED - Run as Admin!", fg=RED)
            self.log("MAC change failed", "error")
        self.lbl_mac.config(text=live or old)
        self.after(2000, self._load_adapters)

    def _reset_mac(self):
        if not self.sel:
            self.log("Select adapter first!", "error"); return
        old = self.sel["mac"]
        desc = self.sel.get("desc", "")
        self.lbl_mac_old.config(text=old)
        self.lbl_mac_status.config(text="RESETTING...", fg=ORANGE)
        self.update()
        n, rk = self.sel["name"], self.sel["regkey"]
        def worker():
            ok = reset_mac(n, rk, desc)
            time.sleep(6)
            live = get_current_mac_live(n)
            self.after(0, lambda: self._mac_reset_done(ok, live))
        threading.Thread(target=worker, daemon=True).start()

    def _mac_reset_done(self, ok, live):
        self.lbl_mac_new.config(text=live or "---")
        if ok:
            self.lbl_mac_status.config(text="RESET OK", fg=GREEN)
            self.log("MAC reset: " + str(live), "success")
        else:
            self.lbl_mac_status.config(text="RESET FAILED", fg=RED)
        self.after(2000, self._load_adapters)

    def _check_mac(self):
        if not self.sel:
            self.log("Select adapter first!", "error"); return
        self.lbl_mac_status.config(text="CHECKING...", fg=ORANGE)
        self.log("=== MAC CHECK ===", "info")
        n = self.sel["name"]
        desc = self.sel.get("desc", "")
        rk = self.sel["regkey"]
        self.log("  Connection: " + n, "info")
        self.log("  Adapter:    " + desc, "info")
        self.log("  Admin:      " + ("YES" if is_admin() else "NO"), "info")
        self.update()
        def step_log(msg):
            self.after(0, lambda: self.log("  " + msg, "info"))
        def worker():
            live = get_current_mac_live(n)
            self.after(0, lambda: self.log("  Live MAC from system: " + str(live), "info"))
            reg_mac = None
            r = rk
            if not r and desc:
                r = find_registry_key_for_adapter(desc, "", step_log)
            if not r:
                r = find_registry_key_for_adapter(n, "", step_log)
            if r:
                try:
                    k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r)
                    reg_mac, _ = winreg.QueryValueEx(k, "NetworkAddress")
                    winreg.CloseKey(k)
                except:
                    pass
            self.after(0, lambda: self.log("  Registry key:  " + str(r), "info"))
            self.after(0, lambda: self.log("  Registry MAC:  " + str(reg_mac), "info"))
            original = self.sel.get("mac", "")
            self.after(0, lambda: self.log("  Original MAC:  " + original, "info"))
            self.after(0, lambda: self._check_done(live, reg_mac, r))
        threading.Thread(target=worker, daemon=True).start()

    def _check_done(self, live, reg_mac, rk):
        self.lbl_mac_new.config(text=live or "N/A")
        self.lbl_mac_reg.config(text=str(rk or "not found")[:60])
        if reg_mac:
            fmt = ":".join(reg_mac[i:i+2] for i in range(0, len(reg_mac), 2))
            self.lbl_mac_old.config(text="Reg: " + fmt)
            lc = (live or "").replace(":", "").replace("-", "").upper()
            if lc == reg_mac.upper():
                self.lbl_mac_status.config(text="SPOOFED (match)", fg=GREEN)
            else:
                self.lbl_mac_status.config(text="MISMATCH reg vs live", fg=ORANGE)
        else:
            self.lbl_mac_old.config(text="(no spoof)")
            self.lbl_mac_status.config(text="ORIGINAL (not spoofed)", fg=CYAN)

    def _copy_mac_report(self):
        lines = ["OLD: " + self.lbl_mac_old.cget("text"), "NEW: " + self.lbl_mac_new.cget("text"),
                 "STATUS: " + self.lbl_mac_status.cget("text")]
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        self.log("Report copied!", "success")

    def _change_all_macs(self):
        if not self.adapters:
            self.log("No adapters found! Click Refresh.", "error"); return
        self.all_mac_text.delete("1.0", "end")
        self.all_mac_text.insert("end", "Changing ALL adapters...\n\n")
        self.log("=== CHANGE ALL MACs ===", "warning")
        if not is_admin():
            self.log("*** NOT ADMIN! MAC change will FAIL! ***", "error")
        self.update()
        adapters = list(self.adapters)
        def worker():
            for a in adapters:
                new_mac = generate_random_mac()
                n = a["name"]
                desc = a.get("desc", "")
                rk = a["regkey"]
                old = a["mac"]
                self.after(0, lambda nn=n, o=old, nm=new_mac: self.all_mac_text.insert("end",
                    "  " + nn + ":\n    OLD: " + o + "\n    NEW: " + nm + "\n"))
                self.after(0, lambda nn=n: self.log("Changing " + nn + "...", "warning"))
                ok, used_rk, steps = set_mac_address(n, new_mac, rk, desc)
                if ok:
                    self.after(0, lambda nn=n, nm=new_mac: self.log(nn + " -> " + nm + " (registry OK)", "success"))
                    self.after(0, lambda: self.all_mac_text.insert("end", "    STATUS: Registry OK\n\n"))
                else:
                    self.after(0, lambda nn=n: self.log(nn + " FAILED!", "error"))
                    for s in steps:
                        self.after(0, lambda ss=s: self.log("  " + ss, "info"))
                    self.after(0, lambda: self.all_mac_text.insert("end", "    STATUS: FAILED\n\n"))
                time.sleep(2)
            self.after(0, lambda: self.log("=== ALL DONE - Verifying... ===", "warning"))
            time.sleep(4)
            for a in adapters:
                live = get_current_mac_live(a["name"])
                self.after(0, lambda nn=a["name"], lv=live: self.log(nn + " live MAC: " + str(lv), "info"))
                self.after(0, lambda nn=a["name"], lv=live: self.all_mac_text.insert("end",
                    "  " + nn + " LIVE: " + str(lv) + "\n"))
            self.after(0, lambda: self.log("=== CHANGE ALL COMPLETE ===", "success"))
            self.after(2000, self._load_adapters)
        threading.Thread(target=worker, daemon=True).start()

    def _check_all_macs(self):
        if not self.adapters:
            self.log("No adapters!", "error"); return
        self.all_mac_text.delete("1.0", "end")
        self.all_mac_text.insert("end", "Checking all adapters...\n\n")
        self.log("=== CHECK ALL MACs ===", "info")
        self.update()
        adapters = list(self.adapters)
        def worker():
            for a in adapters:
                n = a["name"]
                desc = a.get("desc", "")
                rk = a["regkey"]
                live = get_current_mac_live(n)
                reg_mac = None
                r = rk
                if not r and desc:
                    r = find_registry_key_for_adapter(desc)
                if r:
                    try:
                        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r)
                        reg_mac, _ = winreg.QueryValueEx(k, "NetworkAddress")
                        winreg.CloseKey(k)
                    except:
                        pass
                spoofed = "SPOOFED" if reg_mac else "ORIGINAL"
                self.after(0, lambda nn=n, lv=live, rm=reg_mac, sp=spoofed: self.all_mac_text.insert("end",
                    "  " + nn + ":\n    Live MAC: " + str(lv) + "\n    Registry: " + str(rm) + "\n    Status: " + sp + "\n\n"))
                self.after(0, lambda nn=n, sp=spoofed: self.log(nn + ": " + sp, "success" if sp == "SPOOFED" else "info"))
            self.after(0, lambda: self.log("Check complete", "success"))
        threading.Thread(target=worker, daemon=True).start()

    # ---- IP ADDRESS ----
    def _build_ip(self, f):
        f.columnconfigure(1, weight=1)
        tk.Label(f, text="Current IP:", bg=BG2, fg=DIM).grid(row=0, column=0, sticky="w", pady=4)
        self.lbl_ip = tk.Label(f, text="---", bg=BG2, fg=GREEN, font=("Consolas", 13, "bold"))
        self.lbl_ip.grid(row=0, column=1, sticky="w", padx=10)
        for i, lbl in enumerate(["New IP:", "Subnet:", "Gateway:"]):
            tk.Label(f, text=lbl, bg=BG2, fg=DIM).grid(row=i+1, column=0, sticky="w", pady=4)
        self.ent_ip = self._entry(f, width=22)
        self.ent_ip.grid(row=1, column=1, sticky="ew", padx=10, pady=4)
        self.ent_sub = self._entry(f, width=22)
        self.ent_sub.grid(row=2, column=1, sticky="ew", padx=10, pady=4)
        self.ent_sub.insert(0, "255.255.255.0")
        self.ent_gw = self._entry(f, width=22)
        self.ent_gw.grid(row=3, column=1, sticky="ew", padx=10, pady=4)
        self.ent_gw.insert(0, "192.168.1.1")
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=4, column=0, columnspan=2, sticky="w", pady=8)
        self._btn(bf, "Change IP", BLUE, cmd=self._change_ip).pack(side="left", padx=(0, 6))
        self._btn(bf, "DHCP (Auto)", GREEN, fg="#000", cmd=self._set_dhcp).pack(side="left", padx=(0, 6))
        self._btn(bf, "Random IP", PURPLE, cmd=self._gen_ip).pack(side="left")

    def _gen_ip(self):
        ip = "192.168." + str(random.randint(0, 254)) + "." + str(random.randint(2, 254))
        self.ent_ip.delete(0, "end"); self.ent_ip.insert(0, ip)

    def _change_ip(self):
        if not self.sel:
            self.log("Select adapter!", "error"); return
        ip = self.ent_ip.get().strip()
        if set_ip_address(self.sel["name"], ip, self.ent_sub.get().strip(), self.ent_gw.get().strip()):
            self.log("IP -> " + ip, "success")
        else:
            self.log("Failed (Admin?)", "error")

    def _set_dhcp(self):
        if not self.sel:
            self.log("Select adapter!", "error"); return
        if set_dhcp(self.sel["name"]):
            self.log("DHCP enabled", "success")
        else:
            self.log("Failed", "error")

    # ---- DNS ----
    def _build_dns(self, f):
        f.columnconfigure(1, weight=1)
        tk.Label(f, text="Primary:", bg=BG2, fg=DIM).grid(row=0, column=0, sticky="w", pady=4)
        self.ent_d1 = self._entry(f, width=22)
        self.ent_d1.grid(row=0, column=1, sticky="ew", padx=10, pady=4)
        tk.Label(f, text="Secondary:", bg=BG2, fg=DIM).grid(row=1, column=0, sticky="w", pady=4)
        self.ent_d2 = self._entry(f, width=22)
        self.ent_d2.grid(row=1, column=1, sticky="ew", padx=10, pady=4)
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=2, column=0, columnspan=2, sticky="w", pady=8)
        self._btn(bf, "Set DNS", BLUE, cmd=self._set_dns).pack(side="left", padx=(0, 6))
        self._btn(bf, "Auto DNS", GREEN, fg="#000", cmd=self._dns_auto).pack(side="left", padx=(0, 6))
        self._btn(bf, "Flush DNS", ORANGE, fg="#000", cmd=self._flush).pack(side="left")
        pf = tk.LabelFrame(f, text="Quick Presets", bg=BG2, fg=DIM, font=("Segoe UI", 9), bd=1)
        pf.grid(row=3, column=0, columnspan=2, sticky="ew", pady=8)
        for nm, p, s in [("Google", "8.8.8.8", "8.8.4.4"), ("Cloudflare", "1.1.1.1", "1.0.0.1"),
                         ("OpenDNS", "208.67.222.222", "208.67.220.220"), ("Quad9", "9.9.9.9", "149.112.112.112")]:
            tk.Button(pf, text=nm, bg=BG3, fg=FG, font=("Segoe UI", 9), bd=0, cursor="hand2",
                      command=lambda a=p, b=s: self._dns_pre(a, b)).pack(side="left", padx=5, pady=4)

    def _dns_pre(self, p, s):
        self.ent_d1.delete(0, "end"); self.ent_d1.insert(0, p)
        self.ent_d2.delete(0, "end"); self.ent_d2.insert(0, s)

    def _set_dns(self):
        if not self.sel:
            self.log("Select adapter!", "error"); return
        d1 = self.ent_d1.get().strip()
        if set_dns(self.sel["name"], d1, self.ent_d2.get().strip()):
            self.log("DNS set", "success")
        else:
            self.log("Failed", "error")

    def _dns_auto(self):
        if not self.sel:
            self.log("Select adapter!", "error"); return
        if set_dns_auto(self.sel["name"]):
            self.log("DNS auto", "success")
        else:
            self.log("Failed", "error")

    def _flush(self):
        if flush_dns():
            self.log("DNS flushed", "success")
        else:
            self.log("Failed", "error")

    # ---- HOSTNAME ----
    def _build_host(self, f):
        f.columnconfigure(1, weight=1)
        tk.Label(f, text="Current:", bg=BG2, fg=DIM).grid(row=0, column=0, sticky="w", pady=4)
        self.lbl_host = tk.Label(f, text=get_computer_name(), bg=BG2, fg=CYAN, font=("Consolas", 13, "bold"))
        self.lbl_host.grid(row=0, column=1, sticky="w", padx=10)
        tk.Label(f, text="New:", bg=BG2, fg=DIM).grid(row=1, column=0, sticky="w", pady=4)
        self.ent_host = self._entry(f, width=22)
        self.ent_host.grid(row=1, column=1, sticky="ew", padx=10, pady=4)
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=2, column=0, columnspan=2, sticky="w", pady=8)
        self._btn(bf, "Random", PURPLE, cmd=self._gen_host).pack(side="left", padx=(0, 6))
        self._btn(bf, "Change", BLUE, cmd=self._change_host).pack(side="left")
        tk.Label(f, text="* Restart required", bg=BG2, fg=ORANGE, font=("Segoe UI", 9)).grid(
            row=3, column=0, columnspan=2, sticky="w")

    def _gen_host(self):
        n = random_hostname()
        self.ent_host.delete(0, "end"); self.ent_host.insert(0, n)

    def _change_host(self):
        n = self.ent_host.get().strip()
        if not n or len(n) > 15:
            self.log("1-15 chars!", "error"); return
        if set_computer_name(n):
            self.lbl_host.config(text=n)
            self.log("Hostname -> " + n, "success")
        else:
            self.log("Failed", "error")

    # ---- HARDWARE ID ----
    def _build_hwid(self, f):
        f.rowconfigure(1, weight=1)
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=0, column=0, sticky="w", pady=(0, 8))
        self._btn(bf, "Scan HWID", BLUE, cmd=self._scan_hw).pack(side="left", padx=(0, 6))
        self._btn(bf, "Spoof GUID", RED, cmd=self._spoof_guid).pack(side="left")
        self.hw_text = self._text(f)
        self.hw_text.grid(row=1, column=0, sticky="nsew")
        self.hw_text.insert("end", "Click 'Scan HWID'\n")

    def _scan_hw(self):
        self.hw_text.delete("1.0", "end"); self.hw_text.insert("end", "Scanning...\n"); self.update()
        def w():
            info = get_hwid()
            self.after(0, lambda: self._show_hw(info))
        threading.Thread(target=w, daemon=True).start()

    def _show_hw(self, info):
        self.hw_text.delete("1.0", "end")
        for k, v in info.items():
            self.hw_text.insert("end", "  " + k + ":\n    " + str(v) + "\n\n")
        self.log("HWID scan done", "success")

    def _spoof_guid(self):
        r = spoof_guid()
        if r:
            self.log("GUID -> " + r, "success"); self._scan_hw()
        else:
            self.log("Failed (Admin?)", "error")

    # ---- BROWSER CLEAN ----
    def _build_browser(self, f):
        tk.Label(f, text="Close browsers before cleaning!", bg=BG2, fg=ORANGE,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.bvars = {}
        for b in ["Chrome", "Edge", "Firefox", "Brave", "Opera"]:
            v = tk.BooleanVar(value=True)
            tk.Checkbutton(f, text=b, variable=v, bg=BG2, fg=FG, selectcolor=BG3,
                           activebackground=BG2, activeforeground=FG, font=("Segoe UI", 11)).pack(
                anchor="w", padx=8, pady=2)
            self.bvars[b] = v
        self._btn(f, "CLEAN SELECTED", RED, cmd=self._clean_br).pack(fill="x", pady=(12, 0))

    def _clean_br(self):
        for b, v in self.bvars.items():
            if v.get():
                c = clean_browser(b)
                self.log(b + ": " + str(c) + " cleaned", "success")

    # ---- PROXY ----
    def _build_proxy(self, f):
        f.columnconfigure(1, weight=1)
        tk.Label(f, text="Status:", bg=BG2, fg=DIM).grid(row=0, column=0, sticky="w", pady=4)
        self.lbl_proxy_st = tk.Label(f, text="---", bg=BG2, fg=DIM, font=("Consolas", 12, "bold"))
        self.lbl_proxy_st.grid(row=0, column=1, sticky="w", padx=10)
        tk.Label(f, text="Proxy:", bg=BG2, fg=DIM).grid(row=1, column=0, sticky="w", pady=4)
        self.ent_proxy = self._entry(f, width=25)
        self.ent_proxy.grid(row=1, column=1, sticky="ew", padx=10, pady=4)
        self.ent_proxy.insert(0, "127.0.0.1:8080")
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=2, column=0, columnspan=2, sticky="w", pady=8)
        self._btn(bf, "Enable", GREEN, fg="#000", cmd=self._en_proxy).pack(side="left", padx=(0, 6))
        self._btn(bf, "Disable", RED, cmd=self._dis_proxy).pack(side="left", padx=(0, 6))
        self._btn(bf, "Refresh", BLUE, cmd=self._ref_proxy).pack(side="left")
        pf = tk.LabelFrame(f, text="Presets", bg=BG2, fg=DIM, bd=1)
        pf.grid(row=3, column=0, columnspan=2, sticky="ew", pady=4)
        for nm, v in [("Tor", "127.0.0.1:9050"), ("Burp", "127.0.0.1:8080"), ("Fiddler", "127.0.0.1:8888")]:
            tk.Button(pf, text=nm, bg=BG3, fg=FG, font=("Segoe UI", 9), bd=0,
                      command=lambda x=v: [self.ent_proxy.delete(0, "end"), self.ent_proxy.insert(0, x)]).pack(
                side="left", padx=4, pady=3)
        self._ref_proxy()

    def _ref_proxy(self):
        p = get_proxy_settings()
        if p["enabled"]:
            self.lbl_proxy_st.config(text="ON: " + p["server"], fg=GREEN)
        else:
            self.lbl_proxy_st.config(text="OFF", fg=RED)

    def _en_proxy(self):
        srv = self.ent_proxy.get().strip()
        if set_proxy(srv):
            self.log("Proxy ON: " + srv, "success"); self._ref_proxy()
        else:
            self.log("Failed", "error")

    def _dis_proxy(self):
        if disable_proxy():
            self.log("Proxy OFF", "success"); self._ref_proxy()
        else:
            self.log("Failed", "error")

    # ---- HOSTS FILE ----
    def _build_hosts(self, f):
        f.rowconfigure(2, weight=1)
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=0, column=0, sticky="w", pady=(0, 4))
        self._btn(bf, "Load", BLUE, cmd=self._load_hosts).pack(side="left", padx=(0, 6))
        self._btn(bf, "Save", GREEN, fg="#000", cmd=self._save_hosts).pack(side="left", padx=(0, 6))
        self._btn(bf, "Block Site", RED, cmd=self._block_site).pack(side="left")
        af = tk.Frame(f, bg=BG2)
        af.grid(row=1, column=0, sticky="ew", pady=4)
        tk.Label(af, text="Block:", bg=BG2, fg=DIM).pack(side="left")
        self.ent_block = self._entry(af, width=25)
        self.ent_block.pack(side="left", padx=6)
        self.hosts_text = self._text(f)
        self.hosts_text.grid(row=2, column=0, sticky="nsew")

    def _load_hosts(self):
        self.hosts_text.delete("1.0", "end")
        self.hosts_text.insert("end", read_hosts_file())
        self.log("Hosts loaded", "info")

    def _save_hosts(self):
        if write_hosts_file(self.hosts_text.get("1.0", "end").strip()):
            self.log("Hosts saved!", "success")
        else:
            self.log("Failed (Admin?)", "error")

    def _block_site(self):
        s = self.ent_block.get().strip()
        if s:
            self.hosts_text.insert("end", "\n127.0.0.1    " + s)
            self.log("Added " + s + " (Save to apply)", "info")

    # ---- PUBLIC IP ----
    def _build_pubip(self, f):
        f.rowconfigure(1, weight=1)
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=0, column=0, sticky="w", pady=(0, 8))
        self._btn(bf, "Check Public IP", GREEN, fg="#000", cmd=self._chk_pubip).pack(side="left")
        self.pub_text = self._text(f)
        self.pub_text.grid(row=1, column=0, sticky="nsew")

    def _chk_pubip(self):
        self.pub_text.delete("1.0", "end"); self.pub_text.insert("end", "Checking...\n"); self.update()
        def w():
            data = get_public_ip()
            self.after(0, lambda: self._show_pubip(data))
        threading.Thread(target=w, daemon=True).start()

    def _show_pubip(self, d):
        self.pub_text.delete("1.0", "end")
        for k in ["ip", "city", "region", "country", "org", "timezone", "loc"]:
            self.pub_text.insert("end", "  " + k.upper() + ":  " + str(d.get(k, "N/A")) + "\n\n")
        self.log("Public IP: " + d.get("ip", "?"), "success")

    # ---- WIFI PASS ----
    def _build_wifi(self, f):
        f.rowconfigure(1, weight=1)
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=0, column=0, sticky="w", pady=(0, 8))
        self._btn(bf, "Show WiFi Passwords", PURPLE, cmd=self._show_wifi).pack(side="left", padx=(0, 6))
        self._btn(bf, "Copy All", BLUE, cmd=self._copy_wifi).pack(side="left")
        self.wifi_text = self._text(f)
        self.wifi_text.grid(row=1, column=0, sticky="nsew")

    def _show_wifi(self):
        self.wifi_text.delete("1.0", "end"); self.wifi_text.insert("end", "Scanning...\n"); self.update()
        def w():
            p = get_wifi_passwords()
            self.after(0, lambda: self._fill_wifi(p))
        threading.Thread(target=w, daemon=True).start()

    def _fill_wifi(self, passwords):
        self.wifi_text.delete("1.0", "end")
        self._wifi_data = passwords
        for i, p in enumerate(passwords):
            self.wifi_text.insert("end", "  [" + str(i+1) + "] " + p["name"] + "\n      -> " + p["password"] + "\n\n")
        self.log(str(len(passwords)) + " WiFi networks", "success")

    def _copy_wifi(self):
        d = getattr(self, "_wifi_data", [])
        if d:
            self.clipboard_clear()
            self.clipboard_append("\n".join(p["name"] + " -> " + p["password"] for p in d))
            self.log("Copied!", "success")

    # ---- NET INFO ----
    def _build_netinfo(self, f):
        f.rowconfigure(1, weight=1)
        self._btn(f, "Scan Network Info", CYAN, fg="#000", cmd=self._net_info).grid(row=0, column=0, sticky="w", pady=(0, 8))
        self.info_text = self._text(f)
        self.info_text.grid(row=1, column=0, sticky="nsew")

    def _net_info(self):
        self.info_text.delete("1.0", "end"); self.info_text.insert("end", "Scanning...\n"); self.update()
        def w():
            info = get_network_info()
            self.after(0, lambda: self._fill_info(info))
        threading.Thread(target=w, daemon=True).start()

    def _fill_info(self, info):
        self.info_text.delete("1.0", "end")
        for k, v in info.items():
            self.info_text.insert("end", "  " + k + ":  " + str(v) + "\n\n")
        self.log("Net info loaded", "success")

    # ---- NETSCAN ----
    def _build_netscan(self, f):
        f.columnconfigure(1, weight=1)
        f.rowconfigure(2, weight=1)
        tk.Label(f, text="Subnet:", bg=BG2, fg=DIM).grid(row=0, column=0, sticky="w")
        self.ent_subnet = self._entry(f, width=15)
        self.ent_subnet.grid(row=0, column=1, sticky="w", padx=10, pady=4)
        self.ent_subnet.insert(0, "192.168.1")
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=1, column=0, columnspan=2, sticky="w", pady=4)
        self._btn(bf, "Scan Network", RED, cmd=self._do_netscan).pack(side="left")
        self.scan_text = self._text(f)
        self.scan_text.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(6, 0))

    def _do_netscan(self):
        prefix = self.ent_subnet.get().strip()
        self.scan_text.delete("1.0", "end"); self.scan_text.insert("end", "Scanning " + prefix + ".1-254 (~30s)...\n"); self.update()
        def w():
            devs = network_scan(prefix)
            self.after(0, lambda: self._fill_scan(devs))
        threading.Thread(target=w, daemon=True).start()

    def _fill_scan(self, devs):
        self.scan_text.delete("1.0", "end")
        for ip, hn in devs:
            self.scan_text.insert("end", "  " + ip.ljust(18) + (hn or "(unknown)") + "\n")
        self.scan_text.insert("end", "\n  Total: " + str(len(devs)) + " devices\n")
        self.log(str(len(devs)) + " devices found", "success")

    # ---- SPEED TEST ----
    def _build_speed(self, f):
        f.rowconfigure(1, weight=1)
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=0, column=0, sticky="w", pady=(0, 8))
        self._btn(bf, "START SPEED TEST", GREEN, fg="#000", cmd=self._do_speed).pack(side="left")
        self.lbl_speed = tk.Label(bf, text="", bg=BG2, fg=ORANGE, font=("Segoe UI", 10))
        self.lbl_speed.pack(side="left", padx=12)
        self.speed_text = self._text(f)
        self.speed_text.grid(row=1, column=0, sticky="nsew")

    def _do_speed(self):
        self.speed_text.delete("1.0", "end"); self.speed_text.insert("end", "Testing (~15s)...\n")
        self.lbl_speed.config(text="TESTING...", fg=ORANGE); self.update()
        def w():
            r = speed_test_download()
            self.after(0, lambda: self._fill_speed(r))
        threading.Thread(target=w, daemon=True).start()

    def _fill_speed(self, results):
        self.speed_text.delete("1.0", "end")
        for sz, sp, t in results:
            self.speed_text.insert("end", "  " + sz + ": " + str(sp) + " Mbps (" + str(t) + "s)\n\n")
        best = max((r[1] for r in results), default=0)
        self.lbl_speed.config(text=str(best) + " Mbps", fg=GREEN if best else RED)
        self.log("Speed: " + str(best) + " Mbps", "success")

    # ---- CONNECTIONS ----
    def _build_conns(self, f):
        f.rowconfigure(1, weight=1)
        self._btn(f, "Show Connections", ORANGE, fg="#000", cmd=self._show_conns).grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.conn_text = self._text(f)
        self.conn_text.grid(row=1, column=0, sticky="nsew")

    def _show_conns(self):
        self.conn_text.delete("1.0", "end"); self.conn_text.insert("end", "Loading...\n"); self.update()
        def w():
            r = get_active_connections()
            self.after(0, lambda: [self.conn_text.delete("1.0", "end"), self.conn_text.insert("end", r)])
        threading.Thread(target=w, daemon=True).start()

    # ---- PING/TRACE ----
    def _build_ping(self, f):
        f.columnconfigure(1, weight=1); f.rowconfigure(2, weight=1)
        tk.Label(f, text="Host:", bg=BG2, fg=DIM).grid(row=0, column=0, sticky="w")
        self.ent_ping = self._entry(f, width=25)
        self.ent_ping.grid(row=0, column=1, sticky="ew", padx=10, pady=4)
        self.ent_ping.insert(0, "google.com")
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=1, column=0, columnspan=2, sticky="w", pady=4)
        self._btn(bf, "Ping", GREEN, fg="#000", cmd=self._do_ping).pack(side="left", padx=(0, 6))
        self._btn(bf, "Traceroute", ORANGE, fg="#000", cmd=self._do_trace).pack(side="left")
        self.ping_text = self._text(f)
        self.ping_text.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(6, 0))

    def _do_ping(self):
        h = self.ent_ping.get().strip()
        self.ping_text.delete("1.0", "end"); self.ping_text.insert("end", "Pinging " + h + "...\n"); self.update()
        def w():
            r = ping_host(h)
            self.after(0, lambda: [self.ping_text.delete("1.0", "end"), self.ping_text.insert("end", r)])
        threading.Thread(target=w, daemon=True).start()

    def _do_trace(self):
        h = self.ent_ping.get().strip()
        self.ping_text.delete("1.0", "end"); self.ping_text.insert("end", "Traceroute " + h + " (~30s)...\n"); self.update()
        def w():
            r = traceroute(h)
            self.after(0, lambda: [self.ping_text.delete("1.0", "end"), self.ping_text.insert("end", r)])
        threading.Thread(target=w, daemon=True).start()

    # ---- DNS LOOKUP ----
    def _build_lookup(self, f):
        f.columnconfigure(1, weight=1); f.rowconfigure(2, weight=1)
        tk.Label(f, text="Domain:", bg=BG2, fg=DIM).grid(row=0, column=0, sticky="w")
        self.ent_lk = self._entry(f, width=25)
        self.ent_lk.grid(row=0, column=1, sticky="ew", padx=10, pady=4)
        self.ent_lk.insert(0, "google.com")
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=1, column=0, columnspan=2, sticky="w", pady=4)
        self._btn(bf, "Lookup", BLUE, cmd=self._do_lk).pack(side="left", padx=(0, 6))
        self._btn(bf, "Resolve IP", GREEN, fg="#000", cmd=self._resolve).pack(side="left")
        self.lk_text = self._text(f)
        self.lk_text.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(6, 0))

    def _do_lk(self):
        d = self.ent_lk.get().strip()
        self.lk_text.delete("1.0", "end"); self.lk_text.insert("end", "Looking up...\n"); self.update()
        def w():
            r = whois_lookup(d)
            self.after(0, lambda: [self.lk_text.delete("1.0", "end"), self.lk_text.insert("end", r)])
        threading.Thread(target=w, daemon=True).start()

    def _resolve(self):
        d = self.ent_lk.get().strip()
        try:
            ip = socket.gethostbyname(d)
            self.lk_text.delete("1.0", "end")
            self.lk_text.insert("end", d + " -> " + ip + "\n")
            self.log(d + " -> " + ip, "success")
        except:
            self.log("Failed to resolve", "error")

    # ---- ARP/ROUTES ----
    def _build_arp(self, f):
        f.rowconfigure(1, weight=1)
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=0, column=0, sticky="w", pady=(0, 6))
        self._btn(bf, "ARP Table", CYAN, fg="#000", cmd=self._show_arp).pack(side="left", padx=(0, 6))
        self._btn(bf, "Routing Table", ORANGE, fg="#000", cmd=self._show_rt).pack(side="left")
        self.arp_text = self._text(f)
        self.arp_text.grid(row=1, column=0, sticky="nsew")

    def _show_arp(self):
        self.arp_text.delete("1.0", "end"); self.update()
        def w():
            r = get_arp_table()
            self.after(0, lambda: [self.arp_text.delete("1.0", "end"), self.arp_text.insert("end", r)])
        threading.Thread(target=w, daemon=True).start()

    def _show_rt(self):
        self.arp_text.delete("1.0", "end"); self.update()
        def w():
            r = get_routing_table()
            self.after(0, lambda: [self.arp_text.delete("1.0", "end"), self.arp_text.insert("end", r)])
        threading.Thread(target=w, daemon=True).start()

    # ---- FIREWALL ----
    def _build_fw(self, f):
        f.rowconfigure(2, weight=1)
        tk.Label(f, text="Windows Firewall", bg=BG2, fg=FG, font=("Segoe UI", 13, "bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 8))
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=1, column=0, sticky="w", pady=4)
        self._btn(bf, "ENABLE", GREEN, fg="#000", cmd=lambda: self._fw_act(True)).pack(side="left", padx=(0, 8))
        self._btn(bf, "DISABLE", RED, cmd=lambda: self._fw_act(False)).pack(side="left", padx=(0, 8))
        self._btn(bf, "Status", BLUE, cmd=self._fw_st).pack(side="left")
        self.fw_text = self._text(f)
        self.fw_text.grid(row=2, column=0, sticky="nsew", pady=(6, 0))

    def _fw_act(self, en):
        if toggle_firewall(en):
            self.log("Firewall " + ("ON" if en else "OFF"), "success"); self._fw_st()
        else:
            self.log("Failed (Admin?)", "error")

    def _fw_st(self):
        self.fw_text.delete("1.0", "end")
        try:
            r = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"],
                                capture_output=True, text=True, creationflags=HIDE, timeout=10)
            self.fw_text.insert("end", r.stdout)
        except:
            self.fw_text.insert("end", "Failed\n")

    # ---- PORT SCANNER ----
    def _build_ports(self, f):
        f.columnconfigure(1, weight=1); f.rowconfigure(3, weight=1)
        tk.Label(f, text="Target:", bg=BG2, fg=DIM).grid(row=0, column=0, sticky="w")
        self.ent_tgt = self._entry(f, width=20)
        self.ent_tgt.grid(row=0, column=1, sticky="ew", padx=10, pady=4)
        self.ent_tgt.insert(0, "127.0.0.1")
        tk.Label(f, text="Ports:", bg=BG2, fg=DIM).grid(row=1, column=0, sticky="w")
        self.ent_pts = self._entry(f, width=20)
        self.ent_pts.grid(row=1, column=1, sticky="ew", padx=10, pady=4)
        self.ent_pts.insert(0, "21,22,80,443,3306,3389,8080")
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=2, column=0, columnspan=2, sticky="w", pady=4)
        self._btn(bf, "Scan", RED, cmd=self._do_portscan).pack(side="left", padx=(0, 6))
        self._btn(bf, "Quick Top 40", ORANGE, fg="#000", cmd=self._quick_ports).pack(side="left")
        self.port_text = self._text(f)
        self.port_text.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=(6, 0))

    def _do_portscan(self):
        host = self.ent_tgt.get().strip()
        try:
            ports = [int(p.strip()) for p in self.ent_pts.get().split(",") if p.strip().isdigit()]
        except:
            return
        self.port_text.delete("1.0", "end"); self.port_text.insert("end", "Scanning " + str(len(ports)) + " ports...\n"); self.update()
        def w():
            r = scan_ports(host, ports)
            self.after(0, lambda: self._fill_ports(r, len(ports)))
        threading.Thread(target=w, daemon=True).start()

    def _fill_ports(self, results, total):
        self.port_text.delete("1.0", "end")
        for p, st, svc in results:
            self.port_text.insert("end", "  " + str(p).ljust(8) + st.ljust(8) + svc + "\n")
        self.port_text.insert("end", "\n  " + str(len(results)) + " open / " + str(total) + " scanned\n")
        self.log(str(len(results)) + " open ports", "success")

    def _quick_ports(self):
        top = [20,21,22,23,25,53,80,110,135,139,143,443,445,993,1433,3306,3389,5432,5900,8000,8080,8443,
               9090,27017,6379,5060,1521,2049,5432,8888,9200,9300,11211,6380,50000,50070,61616,7001,4848,8181]
        self.ent_pts.delete(0, "end")
        self.ent_pts.insert(0, ",".join(str(p) for p in top))
        self._do_portscan()

    # ---- PROCESSES ----
    def _build_procs(self, f):
        f.rowconfigure(1, weight=1)
        self._btn(f, "Show Network Processes (Admin)", ORANGE, fg="#000", cmd=self._show_procs).grid(
            row=0, column=0, sticky="w", pady=(0, 6))
        self.proc_text = self._text(f)
        self.proc_text.grid(row=1, column=0, sticky="nsew")

    def _show_procs(self):
        self.proc_text.delete("1.0", "end"); self.proc_text.insert("end", "Loading...\n"); self.update()
        def w():
            r = get_network_processes()
            self.after(0, lambda: [self.proc_text.delete("1.0", "end"), self.proc_text.insert("end", r)])
        threading.Thread(target=w, daemon=True).start()

    # ---- ADAPTER CONTROL ----
    def _build_adpctl(self, f):
        tk.Label(f, text="Enable / Disable Adapters", bg=BG2, fg=FG, font=("Segoe UI", 13, "bold")).pack(pady=(0, 4))
        tk.Label(f, text="Select adapter in sidebar first. Admin required.", bg=BG2, fg=ORANGE).pack(pady=(0, 12))
        bf = tk.Frame(f, bg=BG2)
        bf.pack(pady=8)
        self._btn(bf, "  DISABLE  ", RED, cmd=lambda: self._togadp(False)).pack(side="left", padx=8)
        self._btn(bf, "  ENABLE  ", GREEN, fg="#000", cmd=lambda: self._togadp(True)).pack(side="left", padx=8)
        self._btn(f, "Cycle (Disable+Enable = new DHCP IP)", PURPLE, cmd=self._cycle_adp).pack(pady=12)

    def _togadp(self, en):
        if not self.sel:
            self.log("Select adapter!", "error"); return
        if toggle_adapter(self.sel["name"], en):
            self.log(self.sel["name"] + " " + ("enabled" if en else "disabled"), "success")
        else:
            self.log("Failed (Admin?)", "error")

    def _cycle_adp(self):
        if not self.sel:
            self.log("Select adapter!", "error"); return
        n = self.sel["name"]
        self.log("Cycling " + n + "...", "warning")
        def w():
            toggle_adapter(n, False); time.sleep(3); toggle_adapter(n, True)
            self.after(0, lambda: self.log(n + " cycled", "success"))
            self.after(5000, self._load_adapters)
        threading.Thread(target=w, daemon=True).start()

    # ---- SYSTEM INFO ----
    def _build_sysinfo(self, f):
        f.rowconfigure(1, weight=1)
        self._btn(f, "Full System Scan (~15s)", PURPLE, cmd=self._do_sys).grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.sys_text = self._text(f)
        self.sys_text.grid(row=1, column=0, sticky="nsew")

    def _do_sys(self):
        self.sys_text.delete("1.0", "end"); self.sys_text.insert("end", "Scanning (~15s)...\n"); self.update()
        def w():
            info = get_system_info()
            self.after(0, lambda: self._fill_sys(info))
        threading.Thread(target=w, daemon=True).start()

    def _fill_sys(self, info):
        self.sys_text.delete("1.0", "end")
        for k, v in info.items():
            self.sys_text.insert("end", "  " + k + ":\n    " + str(v) + "\n\n")
        self.log("System scan done", "success")

    # ---- STARTUP ----
    def _build_startup(self, f):
        f.rowconfigure(1, weight=1)
        self._btn(f, "Show Startup Items", PURPLE, cmd=self._do_startup).grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.startup_text = self._text(f)
        self.startup_text.grid(row=1, column=0, sticky="nsew")

    def _do_startup(self):
        self.startup_text.delete("1.0", "end"); self.update()
        def w():
            items = get_startup_items()
            self.after(0, lambda: self._fill_startup(items))
        threading.Thread(target=w, daemon=True).start()

    def _fill_startup(self, items):
        self.startup_text.delete("1.0", "end")
        for i, it in enumerate(items):
            self.startup_text.insert("end", "  [" + str(i+1) + "] " + it["name"] + "\n      " + it["location"] + "\n      " + it["path"] + "\n\n")
        self.log(str(len(items)) + " startup items", "success")

    # ---- TEMP CLEANER ----
    def _build_temp(self, f):
        tk.Label(f, text="Temp / Junk Cleaner", bg=BG2, fg=FG, font=("Segoe UI", 13, "bold")).pack(pady=(0, 4))
        tk.Label(f, text="%TEMP% + Windows\\Temp + Prefetch", bg=BG2, fg=DIM).pack(pady=(0, 10))
        self._btn(f, "  CLEAN TEMP FILES  ", RED, cmd=self._do_temp).pack(pady=8)
        self.temp_lbl = tk.Label(f, text="", bg=BG2, fg=GREEN, font=("Segoe UI", 14, "bold"))
        self.temp_lbl.pack(pady=8)
        self.temp_text = self._text(f, h=6)
        self.temp_text.pack(fill="both", expand=True)

    def _do_temp(self):
        self.temp_lbl.config(text="CLEANING...", fg=ORANGE); self.update()
        def w():
            c, s = clean_temp_files()
            self.after(0, lambda: self._fill_temp(c, s))
        threading.Thread(target=w, daemon=True).start()

    def _fill_temp(self, count, size):
        mb = round(size / (1024*1024), 2)
        self.temp_lbl.config(text=str(count) + " files (" + str(mb) + " MB)", fg=GREEN)
        self.temp_text.delete("1.0", "end")
        self.temp_text.insert("end", "  Files:  " + str(count) + "\n  Freed:  " + str(mb) + " MB\n")
        self.log("Cleaned " + str(count) + " files", "success")

    # ---- HASH GEN ----
    def _build_hash(self, f):
        f.rowconfigure(2, weight=1)
        tk.Label(f, text="Input:", bg=BG2, fg=DIM).grid(row=0, column=0, sticky="nw", pady=4)
        self.hash_inp = tk.Text(f, bg=BG3, fg=FG, font=("Consolas", 11), height=3, bd=1, relief="solid", insertbackground=FG)
        self.hash_inp.grid(row=0, column=1, sticky="ew", padx=10, pady=4)
        f.columnconfigure(1, weight=1)
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=1, column=0, columnspan=2, sticky="w", pady=4)
        self._btn(bf, "Hash", BLUE, cmd=self._gen_hashes).pack(side="left", padx=(0, 6))
        self._btn(bf, "Copy", GREEN, fg="#000", cmd=self._copy_hash).pack(side="left")
        self.hash_text = self._text(f)
        self.hash_text.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(4, 0))

    def _gen_hashes(self):
        txt = self.hash_inp.get("1.0", "end").strip()
        if not txt:
            return
        self.hash_text.delete("1.0", "end")
        for a in ["MD5", "SHA1", "SHA256", "SHA512"]:
            self.hash_text.insert("end", "  " + a + ":\n  " + generate_hash(txt, a) + "\n\n")

    def _copy_hash(self):
        c = self.hash_text.get("1.0", "end").strip()
        if c:
            self.clipboard_clear(); self.clipboard_append(c); self.log("Copied!", "success")

    # ---- PASSWORD GEN ----
    def _build_passgen(self, f):
        f.columnconfigure(1, weight=1); f.rowconfigure(3, weight=1)
        tk.Label(f, text="Length:", bg=BG2, fg=DIM).grid(row=0, column=0, sticky="w", pady=4)
        self.ent_plen = self._entry(f, width=8)
        self.ent_plen.grid(row=0, column=1, sticky="w", padx=10, pady=4)
        self.ent_plen.insert(0, "20")
        self.pass_special = tk.BooleanVar(value=True)
        tk.Checkbutton(f, text="Special chars (!@#$%...)", variable=self.pass_special, bg=BG2, fg=FG,
                       selectcolor=BG3, activebackground=BG2, activeforeground=FG).grid(
            row=1, column=0, columnspan=2, sticky="w", pady=4)
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=2, column=0, columnspan=2, sticky="w", pady=4)
        self._btn(bf, "Generate", PURPLE, cmd=self._gen1pass).pack(side="left", padx=(0, 6))
        self._btn(bf, "Generate 10", BLUE, cmd=self._gen10pass).pack(side="left", padx=(0, 6))
        self._btn(bf, "Copy", GREEN, fg="#000", cmd=self._copy_pass).pack(side="left")
        self.pass_text = tk.Text(f, bg="#0d1117", fg=GREEN, font=("Consolas", 12), bd=0, insertbackground=FG)
        self.pass_text.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=(6, 0))

    def _gen1pass(self):
        try:
            ln = int(self.ent_plen.get())
        except:
            ln = 20
        self.pass_text.delete("1.0", "end")
        self.pass_text.insert("end", generate_password(ln, self.pass_special.get()) + "\n")

    def _gen10pass(self):
        try:
            ln = int(self.ent_plen.get())
        except:
            ln = 20
        self.pass_text.delete("1.0", "end")
        for i in range(10):
            self.pass_text.insert("end", str(i+1).rjust(2) + ". " + generate_password(ln, self.pass_special.get()) + "\n")

    def _copy_pass(self):
        c = self.pass_text.get("1.0", "end").strip()
        if c:
            first = c.split("\n")[0].strip()
            if ". " in first:
                first = first.split(". ", 1)[1]
            self.clipboard_clear(); self.clipboard_append(first); self.log("Copied!", "success")

    # ---- WAKE ON LAN ----
    def _build_wol(self, f):
        f.columnconfigure(1, weight=1)
        tk.Label(f, text="Wake on LAN", bg=BG2, fg=FG, font=("Segoe UI", 13, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        tk.Label(f, text="MAC:", bg=BG2, fg=DIM).grid(row=1, column=0, sticky="w", pady=4)
        self.ent_wol = self._entry(f, width=22)
        self.ent_wol.grid(row=1, column=1, sticky="ew", padx=10, pady=4)
        self.ent_wol.insert(0, "AA:BB:CC:DD:EE:FF")
        self._btn(f, "SEND WAKE PACKET", GREEN, fg="#000", cmd=self._send_wol).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=12)
        tk.Label(f, text="Target must have WoL enabled in BIOS.", bg=BG2, fg=ORANGE,
                 font=("Segoe UI", 9)).grid(row=3, column=0, columnspan=2, sticky="w")

    def _send_wol(self):
        mac = self.ent_wol.get().strip()
        if send_wol(mac):
            self.log("WoL sent to " + mac, "success")
        else:
            self.log("Failed (invalid MAC?)", "error")

    # ---- IP GEOLOCATE ----
    def _build_geolocate(self, f):
        f.columnconfigure(1, weight=1)
        f.rowconfigure(3, weight=1)
        tk.Label(f, text="IP Geolocation", bg=BG2, fg=FG, font=("Segoe UI", 13, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 6))
        tk.Label(f, text="IP Address:", bg=BG2, fg=DIM).grid(row=1, column=0, sticky="w", pady=4)
        self.ent_geo = self._entry(f, width=22)
        self.ent_geo.grid(row=1, column=1, sticky="ew", padx=10, pady=4)
        self.ent_geo.insert(0, "8.8.8.8")
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=2, column=0, columnspan=2, sticky="w", pady=6)
        self._btn(bf, "Lookup", BLUE, cmd=self._do_geolocate).pack(side="left", padx=(0, 6))
        self._btn(bf, "My IP", GREEN, fg="#000", cmd=self._geo_myip).pack(side="left", padx=(0, 6))
        self._btn(bf, "Copy", PURPLE, cmd=self._copy_geo).pack(side="left")
        self.geo_text = self._text(f)
        self.geo_text.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=(4, 0))

    def _do_geolocate(self):
        ip = self.ent_geo.get().strip()
        if not ip:
            return
        self.geo_text.delete("1.0", "end")
        self.geo_text.insert("end", "  Looking up " + ip + "...\n")
        self._set_status("Looking up " + ip)
        self.update()
        def w():
            data = geolocate_ip(ip)
            self.after(0, lambda: self._fill_geo(data))
        threading.Thread(target=w, daemon=True).start()

    def _geo_myip(self):
        self.ent_geo.delete(0, "end")
        def w():
            try:
                r = urllib.request.urlopen("https://api.ipify.org?format=json", timeout=6)
                ip = json.loads(r.read().decode()).get("ip", "?")
                self.after(0, lambda: self.ent_geo.insert(0, ip))
                self.after(0, self._do_geolocate)
            except:
                self.after(0, lambda: self.log("Failed to get public IP", "error"))
        threading.Thread(target=w, daemon=True).start()

    def _fill_geo(self, data):
        self.geo_text.delete("1.0", "end")
        if "error" in data:
            self.geo_text.insert("end", "  Error: " + data["error"] + "\n")
            self.log("Geo lookup failed", "error")
            return
        fields = [("IP", "ip"), ("Hostname", "hostname"), ("City", "city"), ("Region", "region"),
                  ("Country", "country"), ("Location", "loc"), ("ISP/Org", "org"),
                  ("Postal", "postal"), ("Timezone", "timezone")]
        for label, key in fields:
            val = data.get(key, "N/A")
            self.geo_text.insert("end", "  " + label.ljust(12) + ": " + str(val) + "\n")
        self.log("Geo: " + data.get("city", "?") + ", " + data.get("country", "?"), "success")
        self._set_status("Geolocated: " + data.get("ip", ""))

    def _copy_geo(self):
        c = self.geo_text.get("1.0", "end").strip()
        if c:
            self.clipboard_clear(); self.clipboard_append(c); self.log("Copied!", "success")

    # ---- TASK KILL ----
    def _build_taskkill(self, f):
        f.columnconfigure(0, weight=1)
        f.rowconfigure(3, weight=1)
        tk.Label(f, text="Task Kill / Process Manager", bg=BG2, fg=FG,
                 font=("Segoe UI", 13, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 6))
        row1 = tk.Frame(f, bg=BG2)
        row1.grid(row=1, column=0, sticky="ew", pady=4)
        tk.Label(row1, text="Process:", bg=BG2, fg=DIM).pack(side="left")
        self.ent_kill = self._entry(row1, width=25)
        self.ent_kill.pack(side="left", padx=6)
        self._btn(row1, "KILL", RED, cmd=self._do_kill_proc).pack(side="left", padx=4)
        self._btn(row1, "Refresh List", BLUE, cmd=self._do_list_procs).pack(side="left", padx=4)
        self._btn(row1, "Export", ORANGE, cmd=self._export_procs).pack(side="left", padx=4)
        tk.Label(f, text="Enter process name (e.g. chrome.exe) or PID", bg=BG2, fg=DIM,
                 font=("Segoe UI", 8)).grid(row=2, column=0, sticky="w", pady=(0, 4))
        self.kill_text = self._text(f)
        self.kill_text.grid(row=3, column=0, sticky="nsew", pady=(4, 0))

    def _do_kill_proc(self):
        name = self.ent_kill.get().strip()
        if not name:
            return
        self._set_status("Killing " + name)
        ok, out = kill_process(name)
        if ok:
            self.log("Killed: " + name, "success")
            self.kill_text.insert("end", "  [KILLED] " + name + "\n  " + out.strip() + "\n\n")
        else:
            self.log("Kill failed: " + name, "error")
            self.kill_text.insert("end", "  [FAIL] " + name + "\n  " + out.strip() + "\n\n")
        self.kill_text.see("end")

    def _do_list_procs(self):
        self.kill_text.delete("1.0", "end")
        self._set_status("Loading processes...")
        self.update()
        def w():
            procs = get_running_processes()
            self.after(0, lambda: self._fill_procs(procs))
        threading.Thread(target=w, daemon=True).start()

    def _fill_procs(self, procs):
        self.kill_text.delete("1.0", "end")
        self.kill_text.insert("end", "  " + "NAME".ljust(35) + "PID".ljust(10) + "MEMORY\n")
        self.kill_text.insert("end", "  " + "-" * 55 + "\n")
        for p in procs:
            self.kill_text.insert("end", "  " + p["name"].ljust(35) + p["pid"].ljust(10) + p["mem"] + "\n")
        self.log(str(len(procs)) + " processes running", "success")
        self._set_status(str(len(procs)) + " processes")

    def _export_procs(self):
        content = self.kill_text.get("1.0", "end").strip()
        if content:
            path = export_to_file(content, "MACalypse_Processes.txt")
            if path:
                self.log("Exported to " + path, "success")

    # ---- CLIPBOARD ----
    def _build_clipboard(self, f):
        tk.Label(f, text="Clipboard Manager", bg=BG2, fg=FG, font=("Segoe UI", 13, "bold")).pack(pady=(0, 8))
        tk.Label(f, text="Clear clipboard data to remove traces", bg=BG2, fg=DIM).pack(pady=(0, 16))
        self._btn(f, "  CLEAR CLIPBOARD  ", RED, cmd=self._do_clear_clip).pack(pady=8)
        self.clip_lbl = tk.Label(f, text="", bg=BG2, fg=GREEN, font=("Segoe UI", 12, "bold"))
        self.clip_lbl.pack(pady=8)
        tk.Label(f, text="Useful after copying sensitive data (passwords, keys, etc.)",
                 bg=BG2, fg=DIM, font=("Segoe UI", 9)).pack(pady=(20, 0))

    def _do_clear_clip(self):
        if clear_clipboard():
            self.clip_lbl.config(text="Clipboard CLEARED", fg=GREEN)
            self.log("Clipboard cleared", "success")
        else:
            self.clip_lbl.config(text="Failed to clear", fg=RED)
            self.log("Clipboard clear failed", "error")

    # ---- MAC VENDOR LOOKUP ----
    def _build_mac_vendor(self, f):
        f.columnconfigure(1, weight=1); f.rowconfigure(3, weight=1)
        tk.Label(f, text="MAC Vendor Lookup", bg=BG2, fg=FG, font=("Segoe UI", 13, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        tk.Label(f, text="MAC Address:", bg=BG2, fg=DIM).grid(row=1, column=0, sticky="w", pady=4)
        self.ent_mac_vendor = self._entry(f, width=22)
        self.ent_mac_vendor.grid(row=1, column=1, sticky="ew", padx=10, pady=4)
        self.ent_mac_vendor.insert(0, "00:11:22:00:00:00")
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=2, column=0, columnspan=2, sticky="w", pady=6)
        self._btn(bf, "Lookup Vendor", PURPLE, cmd=self._do_mac_vendor).pack(side="left", padx=(0, 6))
        self.mac_vendor_text = self._text(f)
        self.mac_vendor_text.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=(4, 0))

    def _do_mac_vendor(self):
        mac = self.ent_mac_vendor.get().strip()
        if not mac:
            return
        self.mac_vendor_text.delete("1.0", "end")
        self.mac_vendor_text.insert("end", f"  Looking up {mac}...\n")
        self.update()
        def w():
            vendor = mac_vendor_lookup(mac)
            self.after(0, lambda: self._fill_mac_vendor(mac, vendor))
        threading.Thread(target=w, daemon=True).start()

    def _fill_mac_vendor(self, mac, vendor):
        self.mac_vendor_text.delete("1.0", "end")
        self.mac_vendor_text.insert("end", f"  MAC:       {mac}\n")
        self.mac_vendor_text.insert("end", f"  Vendor:    {vendor}\n")
        prefix = mac.replace(":", "").replace("-", "").strip().upper()[:6]
        self.mac_vendor_text.insert("end", f"  OUI:       {prefix}\n")
        self.log(f"MAC Vendor: {mac} -> {vendor}", "success")

    # ---- SUBNET CALCULATOR ----
    def _build_subnet(self, f):
        f.columnconfigure(1, weight=1); f.rowconfigure(3, weight=1)
        tk.Label(f, text="Subnet Calculator", bg=BG2, fg=FG, font=("Segoe UI", 13, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        tk.Label(f, text="IP/CIDR:", bg=BG2, fg=DIM).grid(row=1, column=0, sticky="w", pady=4)
        self.ent_subnet_calc = self._entry(f, width=22)
        self.ent_subnet_calc.grid(row=1, column=1, sticky="ew", padx=10, pady=4)
        self.ent_subnet_calc.insert(0, "192.168.1.0/24")
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=2, column=0, columnspan=2, sticky="w", pady=6)
        self._btn(bf, "Calculate", CYAN, fg="#000", cmd=self._do_subnet).pack(side="left", padx=(0, 6))
        self._btn(bf, "Quick /24", ORANGE, fg="#000",
                  cmd=lambda: self._subnet_q("192.168.1.0/24")).pack(side="left", padx=(0, 6))
        self._btn(bf, "Quick /16", ORANGE, fg="#000",
                  cmd=lambda: self._subnet_q("10.0.0.0/16")).pack(side="left")
        self.subnet_text = self._text(f)
        self.subnet_text.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=(4, 0))

    def _subnet_q(self, val):
        self.ent_subnet_calc.delete(0, "end")
        self.ent_subnet_calc.insert(0, val)

    def _do_subnet(self):
        cidr = self.ent_subnet_calc.get().strip()
        if not cidr:
            return
        self.subnet_text.delete("1.0", "end")
        self.subnet_text.insert("end", f"  Calculating {cidr}...\n")
        self.update()
        def w():
            result = subnet_calculator(cidr)
            self.after(0, lambda: self._fill_subnet(result))
        threading.Thread(target=w, daemon=True).start()

    def _fill_subnet(self, result):
        self.subnet_text.delete("1.0", "end")
        if "error" in result:
            self.subnet_text.insert("end", f"  Error: {result['error']}\n")
            self.log(f"Subnet calc failed: {result['error']}", "error")
            return
        for k in ["Network", "Broadcast", "Netmask", "CIDR", "Wildcard",
                   "Hosts Min", "Hosts Max", "Total Hosts", "Is Private"]:
            v = result.get(k, "N/A")
            self.subnet_text.insert("end", f"  {k.ljust(14)}: {v}\n")
        self.log(f"Subnet: {result.get('Network', '?')}/{result.get('CIDR', '?')}", "success")

    # ---- DNS BENCHMARK ----
    def _build_dns_bench(self, f):
        f.rowconfigure(2, weight=1)
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=0, column=0, sticky="w", pady=(0, 8))
        self._btn(bf, "Benchmark DNS (5 servers)", GREEN, fg="#000", cmd=self._do_dns_bench).pack(side="left")
        self.dns_bench_lbl = tk.Label(bf, text="", bg=BG2, fg=ORANGE, font=("Segoe UI", 10))
        self.dns_bench_lbl.pack(side="left", padx=12)
        self.dns_bench_text = self._text(f)
        self.dns_bench_text.grid(row=1, column=0, sticky="nsew")

    def _do_dns_bench(self):
        self.dns_bench_text.delete("1.0", "end")
        self.dns_bench_text.insert("end", "  Benchmarking DNS servers (~15s)...\n")
        self.dns_bench_lbl.config(text="TESTING...")
        self.update()
        def w():
            results = dns_benchmark()
            self.after(0, lambda: self._fill_dns_bench(results))
        threading.Thread(target=w, daemon=True).start()

    def _fill_dns_bench(self, results):
        self.dns_bench_text.delete("1.0", "end")
        self.dns_bench_text.insert("end", f"  {'SERVER'.ljust(18)} {'AVG(ms)'.ljust(10)} {'T1'.ljust(8)} {'T2'.ljust(8)} {'T3'.ljust(8)}\n")
        self.dns_bench_text.insert("end", f"  {'-'*52}\n")
        best = None
        for r in sorted(results, key=lambda x: x["average"] if x["average"] else 9999):
            avg = f"{r['average']:.1f}" if r["average"] else "FAIL"
            tms = [f"{t:.1f}" if t else "TIMEOUT" for t in r["times"]]
            if best is None and r["average"]:
                best = r["server"]
            self.dns_bench_text.insert("end", f"  {r['server'].ljust(18)} {str(avg).ljust(10)} {tms[0].ljust(8)} {tms[1].ljust(8)} {tms[2].ljust(8)}\n")
        if best:
            self.dns_bench_lbl.config(text=f"Fastest: {best}", fg=GREEN)
            self.log(f"DNS Benchmark: fastest {best}", "success")
        else:
            self.dns_bench_lbl.config(text="All failed", fg=RED)
            self.log("DNS Benchmark: all servers failed", "error")

    # ---- NETWORK USAGE ----
    def _build_net_usage(self, f):
        f.rowconfigure(1, weight=1)
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=0, column=0, sticky="w", pady=(0, 8))
        self._btn(bf, "Show Network Usage", BLUE, cmd=self._do_net_usage).pack(side="left", padx=(0, 6))
        self._btn(bf, "Refresh", GREEN, fg="#000", cmd=self._do_net_usage).pack(side="left")
        self.usage_text = self._text(f)
        self.usage_text.grid(row=1, column=0, sticky="nsew")

    def _do_net_usage(self):
        self.usage_text.delete("1.0", "end")
        self.usage_text.insert("end", "  Collecting interface statistics...\n")
        self.update()
        def w():
            stats = get_network_usage()
            self.after(0, lambda: self._fill_net_usage(stats))
        threading.Thread(target=w, daemon=True).start()

    def _fill_net_usage(self, stats):
        self.usage_text.delete("1.0", "end")
        if not stats:
            self.usage_text.insert("end", "  No data available\n")
            return
        header = f"  {'INTERFACE'.ljust(30)} {'SENT'.ljust(12)} {'RECEIVED'.ljust(12)} {'PACKETS OUT'.ljust(14)} {'PACKETS IN'.ljust(14)}\n"
        self.usage_text.insert("end", header)
        self.usage_text.insert("end", f"  {'-'*82}\n")
        for s in stats:
            if "Error" in s.get("interface", ""):
                self.usage_text.insert("end", f"  {s['interface']}\n")
                return
            self.usage_text.insert("end",
                f"  {s['interface'][:28].ljust(30)} "
                f"{format_bytes(s['bytes_sent']).ljust(12)} "
                f"{format_bytes(s['bytes_recv']).ljust(12)} "
                f"{str(s['packets_sent']).ljust(14)} "
                f"{str(s['packets_recv']).ljust(14)}\n")
        self.log(f"Network usage: {len(stats)} interfaces", "success")

    # ---- BLUETOOTH ----
    def _build_bluetooth(self, f):
        f.rowconfigure(1, weight=1)
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=0, column=0, sticky="w", pady=(0, 8))
        self._btn(bf, "Scan Bluetooth Devices", BLUE, cmd=self._do_bluetooth).pack(side="left")
        self.bt_text = self._text(f)
        self.bt_text.grid(row=1, column=0, sticky="nsew")

    def _do_bluetooth(self):
        self.bt_text.delete("1.0", "end")
        self.bt_text.insert("end", "  Scanning Bluetooth devices...\n")
        self.update()
        def w():
            devices = get_bluetooth_devices()
            self.after(0, lambda: self._fill_bluetooth(devices))
        threading.Thread(target=w, daemon=True).start()

    def _fill_bluetooth(self, devices):
        self.bt_text.delete("1.0", "end")
        if not devices:
            self.bt_text.insert("end", "  No Bluetooth adapters found.\n")
            self.log("Bluetooth: none found", "info")
            return
        for d in devices:
            self.bt_text.insert("end", f"  Name:   {d['name']}\n")
            if d.get("status"):
                self.bt_text.insert("end", f"  Status: {d['status']}\n")
            if d.get("id"):
                self.bt_text.insert("end", f"  ID:     {d['id']}\n")
            self.bt_text.insert("end", "\n")
        self.log(f"Bluetooth: {len(devices)} device(s)", "success")

    # ---- SCHEDULED TASKS ----
    def _build_sched_tasks(self, f):
        f.rowconfigure(1, weight=1)
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=0, column=0, sticky="w", pady=(0, 8))
        self._btn(bf, "List Scheduled Tasks (Top 50)", ORANGE, fg="#000", cmd=self._do_sched).pack(side="left")
        self.sched_text = self._text(f)
        self.sched_text.grid(row=1, column=0, sticky="nsew")

    def _do_sched(self):
        self.sched_text.delete("1.0", "end")
        self.sched_text.insert("end", "  Loading scheduled tasks...\n")
        self.update()
        def w():
            tasks = get_scheduled_tasks()
            self.after(0, lambda: self._fill_sched(tasks))
        threading.Thread(target=w, daemon=True).start()

    def _fill_sched(self, tasks):
        self.sched_text.delete("1.0", "end")
        if not tasks:
            self.sched_text.insert("end", "  No tasks found (try Admin)\n")
            self.log("Scheduled tasks: none", "info")
            return
        header = f"  {'STATE'.ljust(10)} {'NAME'.ljust(40)} PATH\n"
        self.sched_text.insert("end", header)
        self.sched_text.insert("end", f"  {'-'*90}\n")
        for t in tasks[:50]:
            st = t.get("state", "?")[:8]
            nm = t.get("name", "?")[:38]
            p = t.get("path", "?")
            self.sched_text.insert("end", f"  {st.ljust(10)} {nm.ljust(40)} {p}\n")
        self.log(f"Scheduled tasks: {len(tasks)}", "success")

    # ---- DISK INFO ----
    def _build_disk_info(self, f):
        f.rowconfigure(1, weight=1)
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=0, column=0, sticky="w", pady=(0, 8))
        self._btn(bf, "Scan Disk Info", BLUE, cmd=self._do_disk).pack(side="left")
        self.disk_text = self._text(f)
        self.disk_text.grid(row=1, column=0, sticky="nsew")

    def _do_disk(self):
        self.disk_text.delete("1.0", "end")
        self.disk_text.insert("end", "  Scanning disks...\n")
        self.update()
        def w():
            disks = get_disk_info()
            self.after(0, lambda: self._fill_disk(disks))
        threading.Thread(target=w, daemon=True).start()

    def _fill_disk(self, disks):
        self.disk_text.delete("1.0", "end")
        if not disks:
            self.disk_text.insert("end", "  No disk info available\n")
            return
        header = f"  {'DEVICE'.ljust(12)} {'TYPE'.ljust(8)} {'TOTAL'.ljust(10)} {'USED'.ljust(10)} {'FREE'.ljust(10)} {'USE%'.ljust(6)} MOUNT\n"
        self.disk_text.insert("end", header)
        self.disk_text.insert("end", f"  {'-'*75}\n")
        for d in disks:
            if "Error" in d.get("device", ""):
                self.disk_text.insert("end", f"  {d['device']}\n")
                return
            total = format_bytes(d["total"])
            used = format_bytes(d["used"])
            free = format_bytes(d["free"])
            pct = f"{d['percent']:.0f}%"
            self.disk_text.insert("end",
                f"  {d['device'][:10].ljust(12)} {d['fstype'][:6].ljust(8)} "
                f"{total.ljust(10)} {used.ljust(10)} {free.ljust(10)} {pct.ljust(6)} {d['mount']}\n")
        self.log(f"Disk info: {len(disks)} drives", "success")

    # ---- ABOUT ----
    def _build_about(self, f):
        f.configure(bg=BG2)
        f.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)

        card = tk.Frame(f, bg=BG3, padx=40, pady=30, relief="flat")
        card.place(relx=0.5, rely=0.5, anchor="center")

        # Logo
        logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.png")
        if os.path.exists(logo_path):
            try:
                from PIL import Image, ImageTk
                pil_img = Image.open(logo_path).resize((96, 96), Image.LANCZOS)
                self.about_logo = ImageTk.PhotoImage(pil_img)
                tk.Label(card, image=self.about_logo, bg=BG3).pack(pady=(0, 10))
            except:
                pass

        tk.Label(card, text="MACalypse", bg=BG3, fg=RED,
                 font=("Segoe UI", 28, "bold")).pack()
        tk.Label(card, text="Network Identity Toolkit", bg=BG3, fg=PURPLE,
                 font=("Segoe UI", 11)).pack(pady=(0, 12))

        sep = tk.Frame(card, bg=DIM, height=1)
        sep.pack(fill="x", pady=8)

        info_items = [
            ("Version", "2.1"),
            ("Tools", "42"),
            ("Categories", "7"),
            ("Python", sys.version.split()[0]),
        ]
        for lbl, val in info_items:
            row = tk.Frame(card, bg=BG3)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=lbl + ":", bg=BG3, fg=DIM, font=("Segoe UI", 10),
                     width=12, anchor="w").pack(side="left")
            tk.Label(row, text=val, bg=BG3, fg=FG, font=("Segoe UI", 10, "bold"),
                     anchor="w").pack(side="left", padx=6)

        sep2 = tk.Frame(card, bg=DIM, height=1)
        sep2.pack(fill="x", pady=8)

        tk.Label(card, text="Contact / Support", bg=BG3, fg=ORANGE,
                 font=("Segoe UI", 11, "bold")).pack(pady=(4, 2))

        tg_btn = tk.Button(card, text="\u2709  Telegram", bg=BLUE, fg="#fff",
                           font=("Segoe UI", 11, "bold"), bd=0, cursor="hand2",
                           padx=20, pady=6,
                           command=lambda: webbrowser.open("https://t.me/werlist99"))
        tg_btn.pack(pady=6)

        tk.Label(card, text="@werlist99", bg=BG3, fg=BLUE,
                 font=("Segoe UI", 9)).pack()

        tk.Label(card, text="\nRun as Administrator for full features.\n"
                            "Windows only - Python + psutil required.",
                 bg=BG3, fg=DIM, font=("Segoe UI", 8), justify="center").pack(pady=(12, 0))

    # ---- MAC CONVERTER ----
    def _build_mac_converter(self, f):
        f.columnconfigure(1, weight=1); f.rowconfigure(2, weight=1)
        tk.Label(f, text="MAC Converter", bg=BG2, fg=FG, font=("Segoe UI", 13, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        tk.Label(f, text="MAC Address:", bg=BG2, fg=DIM).grid(row=1, column=0, sticky="w", pady=4)
        self.ent_mac_conv = self._entry(f, width=25)
        self.ent_mac_conv.grid(row=1, column=1, sticky="ew", padx=10, pady=4)
        self.ent_mac_conv.insert(0, "aa:bb:cc:dd:ee:ff")
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=2, column=0, columnspan=2, sticky="w", pady=6)
        self._btn(bf, "Convert", BLUE, cmd=self._do_mac_conv).pack(side="left", padx=(0, 6))
        self._btn(bf, "Copy All", PURPLE, cmd=self._copy_mac_conv).pack(side="left")
        self.mac_conv_text = self._text(f, h=6)
        self.mac_conv_text.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=(4, 0))
        self._mac_conv_data = ""

    def _do_mac_conv(self):
        mac = self.ent_mac_conv.get().strip()
        if not mac:
            return
        result = mac_convert(mac)
        self.mac_conv_text.delete("1.0", "end")
        if "error" in result:
            self.mac_conv_text.insert("end", f"  Error: {result['error']}\n")
            return
        self._mac_conv_data = result
        for k in ["IEEE", "Cisco", "Plain", "Dash", "Reverse"]:
            self.mac_conv_text.insert("end", f"  {k.ljust(10)}: {result[k]}\n")
        self.log("MAC converted", "success")

    def _copy_mac_conv(self):
        if self._mac_conv_data:
            txt = "\n".join(f"{k}: {v}" for k, v in self._mac_conv_data.items())
            self.clipboard_clear(); self.clipboard_append(txt)
            self.log("MAC formats copied!", "success")

    # ---- UPTIME ----
    def _build_uptime(self, f):
        f.columnconfigure(0, weight=1)
        tk.Label(f, text="System Uptime", bg=BG2, fg=FG, font=("Segoe UI", 13, "bold")).pack(anchor="w", pady=(0, 12))
        bf = tk.Frame(f, bg=BG2)
        bf.pack(anchor="w", pady=(0, 12))
        self._btn(bf, "Get Uptime", GREEN, fg="#000", cmd=self._do_uptime).pack(side="left")
        self.uptime_lbl = tk.Label(bf, text="", bg=BG2, fg=CYAN, font=("Consolas", 14, "bold"))
        self.uptime_lbl.pack(side="left", padx=16)
        self.uptime_text = self._text(f, h=3)
        self.uptime_text.pack(fill="x")
        self._do_uptime()

    def _do_uptime(self):
        self.uptime_text.delete("1.0", "end")
        self.uptime_text.insert("end", "  Querying system uptime...\n")
        self.update()
        def w():
            uptime = get_uptime()
            boot = uptime
            since = ""
            try:
                from datetime import datetime
                if "20" in uptime:
                    since = uptime
                else:
                    since = uptime
            except:
                pass
            self.after(0, lambda: self._fill_uptime(uptime))
        threading.Thread(target=w, daemon=True).start()

    def _fill_uptime(self, uptime):
        self.uptime_text.delete("1.0", "end")
        self.uptime_lbl.config(text=uptime[:40] if uptime != "N/A" else "N/A")
        self.uptime_text.insert("end", f"  Last boot: {uptime}\n")
        try:
            r = subprocess.run(["wmic", "os", "get", "LocalDateTime"],
                               capture_output=True, text=True, creationflags=HIDE, timeout=5)
            lines = [l.strip() for l in r.stdout.split("\n") if l.strip() and "Local" not in l]
            if lines:
                self.uptime_text.insert("end", f"  System time: {lines[0][:19]}\n")
        except:
            pass
        self.log(f"Uptime: {uptime[:40]}", "success")

    # ---- INSTALLED APPS ----
    def _build_installed(self, f):
        f.rowconfigure(1, weight=1)
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=0, column=0, sticky="w", pady=(0, 8))
        self._btn(bf, "List Installed Apps", PURPLE, cmd=self._do_installed).pack(side="left", padx=(0, 6))
        self._btn(bf, "Export", ORANGE, fg="#000", cmd=self._export_installed).pack(side="left")
        self.installed_text = self._text(f)
        self.installed_text.grid(row=1, column=0, sticky="nsew")

    def _do_installed(self):
        self.installed_text.delete("1.0", "end")
        self.installed_text.insert("end", "  Scanning registry for installed apps...\n")
        self._set_status("Scanning installed apps...")
        self.update()
        def w():
            apps = get_installed_apps()
            self.after(0, lambda: self._fill_installed(apps))
        threading.Thread(target=w, daemon=True).start()

    def _fill_installed(self, apps):
        self.installed_text.delete("1.0", "end")
        self._installed_data = apps
        count = str(len(apps))
        self.installed_text.insert("end", f"  Total: {count} apps\n\n")
        header = f"  {'NAME'.ljust(50)} {'VERSION'.ljust(16)} PUBLISHER\n"
        self.installed_text.insert("end", header)
        self.installed_text.insert("end", f"  {'-'*90}\n")
        for a in apps:
            nm = a["name"][:48]
            ver = a.get("version", "")[:14]
            pub = a.get("publisher", "")[:30]
            self.installed_text.insert("end", f"  {nm.ljust(50)} {ver.ljust(16)} {pub}\n")
        self.log(f"Installed apps: {count}", "success")
        self._set_status(f"{count} installed apps")

    def _export_installed(self):
        data = getattr(self, "_installed_data", [])
        if data:
            txt = "\n".join(f"{a['name']} | {a.get('version','')} | {a.get('publisher','')}" for a in data)
            path = export_to_file(txt, "MACalypse_Apps.txt")
            if path:
                self.log(f"Exported to {path}", "success")

    # ---- SERVICES ----
    def _build_services(self, f):
        f.rowconfigure(2, weight=1)
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=0, column=0, sticky="w", pady=(0, 8))
        self._btn(bf, "All Services", BLUE, cmd=lambda: self._do_services("all")).pack(side="left", padx=(0, 6))
        self._btn(bf, "Running Only", GREEN, fg="#000", cmd=lambda: self._do_services("running")).pack(side="left", padx=(0, 6))
        self._btn(bf, "Stopped Only", RED, cmd=lambda: self._do_services("stopped")).pack(side="left")
        self.services_text = self._text(f)
        self.services_text.grid(row=1, column=0, sticky="nsew")

    def _do_services(self, flt):
        self.services_text.delete("1.0", "end")
        self.services_text.insert("end", f"  Loading {flt} services...\n")
        self.update()
        def w():
            svcs = get_services(flt)
            self.after(0, lambda: self._fill_services(svcs, flt))
        threading.Thread(target=w, daemon=True).start()

    def _fill_services(self, svcs, flt):
        self.services_text.delete("1.0", "end")
        self.services_text.insert("end", f"  Total {flt}: {len(svcs)}\n\n")
        header = f"  {'STATUS'.ljust(10)} {'NAME'.ljust(30)} DISPLAY\n"
        self.services_text.insert("end", header)
        self.services_text.insert("end", f"  {'-'*80}\n")
        for s in svcs[:100]:
            st = s["status"][:8]
            nm = s["name"][:28]
            disp = s["display"][:40]
            self.services_text.insert("end", f"  {st.ljust(10)} {nm.ljust(30)} {disp}\n")
        self.log(f"Services ({flt}): {len(svcs)}", "success")

    # ---- ENVIRONMENT ----
    def _build_env(self, f):
        f.rowconfigure(1, weight=1)
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=0, column=0, sticky="w", pady=(0, 8))
        self._btn(bf, "Show Environment Vars", CYAN, fg="#000", cmd=self._do_env).pack(side="left", padx=(0, 6))
        self._btn(bf, "Search", BLUE, cmd=self._search_env).pack(side="left")
        self.ent_env_search = self._entry(f, width=20)
        self.ent_env_search.grid(row=0, column=1, sticky="w", padx=6, pady=4)
        self.ent_env_search.insert(0, "PATH")
        self.env_text = self._text(f)
        self.env_text.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(4, 0))

    def _do_env(self):
        self.env_text.delete("1.0", "end")
        self.env_text.insert("end", "  Loading environment variables...\n")
        self.update()
        def w():
            vars_ = get_env_vars()
            self.after(0, lambda: self._fill_env(vars_))
        threading.Thread(target=w, daemon=True).start()

    def _fill_env(self, vars_):
        self._env_data = vars_
        self.env_text.delete("1.0", "end")
        self.env_text.insert("end", f"  Total: {len(vars_)} variables\n\n")
        for v in vars_:
            self.env_text.insert("end", f"  {v['name']}={v['value']}\n")
        self.log(f"Environment: {len(vars_)} vars", "success")

    def _search_env(self):
        term = self.ent_env_search.get().strip().upper()
        data = getattr(self, "_env_data", [])
        if not data:
            self._do_env()
            return
        self.env_text.delete("1.0", "end")
        found = [v for v in data if term in v["name"].upper()]
        if found:
            self.env_text.insert("end", f"  Found {len(found)} matches for '{term}':\n\n")
            for v in found:
                self.env_text.insert("end", f"  {v['name']}={v['value']}\n")
        else:
            self.env_text.insert("end", f"  No matches for '{term}'\n")

    # ---- NETWORK TIME ----
    def _build_ntp(self, f):
        f.columnconfigure(1, weight=1); f.rowconfigure(3, weight=1)
        tk.Label(f, text="Network Time (NTP)", bg=BG2, fg=FG, font=("Segoe UI", 13, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        tk.Label(f, text="NTP Server:", bg=BG2, fg=DIM).grid(row=1, column=0, sticky="w", pady=4)
        self.ent_ntp = self._entry(f, width=25)
        self.ent_ntp.grid(row=1, column=1, sticky="ew", padx=10, pady=4)
        self.ent_ntp.insert(0, "pool.ntp.org")
        bf = tk.Frame(f, bg=BG2)
        bf.grid(row=2, column=0, columnspan=2, sticky="w", pady=6)
        self._btn(bf, "Sync Time", GREEN, fg="#000", cmd=self._do_ntp).pack(side="left", padx=(0, 6))
        for nm, srv in [("Cloudflare", "time.cloudflare.com"), ("Google", "time.google.com"),
                        ("Windows", "time.windows.com"), ("Pool", "pool.ntp.org")]:
            tk.Button(bf, text=nm, bg=BG3, fg=FG, font=("Segoe UI", 8), bd=0, cursor="hand2",
                      command=lambda x=srv: self._ntp_preset(x)).pack(side="left", padx=2)
        self.ntp_text = self._text(f)
        self.ntp_text.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=(4, 0))

    def _ntp_preset(self, srv):
        self.ent_ntp.delete(0, "end"); self.ent_ntp.insert(0, srv)

    def _do_ntp(self):
        srv = self.ent_ntp.get().strip()
        if not srv:
            return
        self.ntp_text.delete("1.0", "end")
        self.ntp_text.insert("end", f"  Querying {srv}...\n")
        self.update()
        def w():
            result = get_ntp_time(srv)
            self.after(0, lambda: self._fill_ntp(result))
        threading.Thread(target=w, daemon=True).start()

    def _fill_ntp(self, result):
        self.ntp_text.delete("1.0", "end")
        if "error" in result:
            self.ntp_text.insert("end", f"  Error: {result['error']}\n")
            self.log(f"NTP failed: {result['error']}", "error")
            return
        for k in ["server", "time", "rtt_ms", "local"]:
            self.ntp_text.insert("end", f"  {k.ljust(10)}: {result[k]}\n")
        diff = ""
        try:
            from datetime import datetime
            ntp = datetime.strptime(result['time'], "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=None)
            loc = datetime.strptime(result['local'], "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=None)
            diff = f"{abs((ntp- loc).total_seconds()):.1f}s"
            self.ntp_text.insert("end", f"  {'Offset'.ljust(10)}: {diff}\n")
        except:
            pass
        self.log(f"NTP {result['server']}: {result['time']} (rtt: {result['rtt_ms']}ms)", "success")

    # ---- FULL RESET ----
    def _full_reset(self):
        self.log("=== FULL IDENTITY RESET ===", "warning"); self.update()
        if self.sel:
            m = generate_random_mac()
            ok, _, _ = set_mac_address(self.sel["name"], m, self.sel["regkey"], self.sel.get("desc", ""))
            if ok:
                self.log("MAC -> " + m, "success")
            else:
                self.log("MAC change failed", "error")
        if flush_dns():
            self.log("DNS flushed", "success")
        n = random_hostname()
        if set_computer_name(n):
            self.log("Hostname -> " + n, "success")
        g = spoof_guid()
        if g:
            self.log("GUID -> " + g, "success")
        for b in ["Chrome", "Edge", "Firefox", "Brave", "Opera"]:
            c = clean_browser(b)
            if c > 0:
                self.log("Cleaned " + b + ": " + str(c), "success")
        self.log("=== DONE - Restart PC ===", "warning")
        self.after(4000, self._load_adapters)


def run_as_admin():
    if not is_admin():
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, '"' + os.path.abspath(__file__) + '"', None, 1
            )
            sys.exit(0)
        except:
            pass

if __name__ == "__main__":
    try:
        if not is_admin():
            print("Requesting administrator privileges...")
            run_as_admin()
        print("Starting MACalypse...")
        app = App()
        print("Window is open!")
        if not is_admin():
            app.log("WARNING: Not Admin! MAC change, firewall etc will FAIL.", "error")
            app.log("Right-click run.bat -> Run as administrator", "error")
        else:
            app.log("Running as Administrator - all features available", "success")
        app.mainloop()
    except Exception as e:
        print("ERROR: " + str(e))
        import traceback
        traceback.print_exc()
        input("Press Enter...")
