#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 INSTALLED SOFTWARE AUDITOR (SWAUDIT)
 Complete software inventory and hygiene audit for one host - CLI + Web App
--------------------------------------------------------------------------------
 Author  : Karanam Shrivasta
 GitHub  : https://github.com/mrshrivasta
 LinkedIn: https://www.linkedin.com/in/karanam-shrivasta/
 Version : 1.0.0
--------------------------------------------------------------------------------
 WHAT THIS DOES
   Builds one inventory of everything installed on this machine, across every
   package manager it can find - dpkg, rpm, apk, pacman, snap, flatpak, pip, npm,
   gem, cargo, Homebrew, macOS application bundles and the Windows uninstall
   registry - and then audits it:

     - runtimes past their end-of-life date
     - the same software installed twice through different managers
     - remote-access and dual-use tooling, judged against the role you declare
     - software installed outside any package manager
     - third-party repositories
     - pending updates sitting in the local package cache
     - what changed since the last scan: installed, removed, upgraded, downgraded

 WHAT THIS IS NOT
   *** This is NOT a vulnerability scanner. It does not check CVEs. ***
   It never contacts a vulnerability database, because that needs network access
   and usually an API key, and this tool has neither by design. A package listed
   here as current may still be vulnerable. For CVE matching use Trivy, Grype or
   osv-scanner against the JSON export this tool produces.

   It is also not a licence compliance tool, and it does not remove anything. It
   only reads.

 DATA INTEGRITY PROMISE
   Every package listed came from a package manager on this machine. A manager
   that is not installed is reported as absent; one that fails is reported as
   unavailable with the reason, and any check depending on it is reported as not
   performed - never as a pass. Where a value is a proxy rather than an
   authoritative fact (dpkg has no install-date field, so file mtime is used),
   the report says so at the point of use.

   The end-of-life table is embedded data with a stated "as of" date, not a live
   feed. The tool warns when that table is older than six months relative to the
   day you run it, and you can supply your own with --eol-file.

 PRIVACY NOTICE
   A software inventory describes what a machine is for and who uses it, and it
   is exactly the reconnaissance an attacker wants. It stays in your local
   database, nothing is uploaded, and 'purge' removes it. Treat exported reports
   as sensitive.

 LEGAL DISCLAIMER
   Audit only machines you own or are explicitly authorised to audit. Findings
   are heuristics: "dual-use tooling" means a program has legitimate and
   illegitimate uses, not that anything is wrong. Verify before acting, and never
   uninstall anything based on this report alone. Provided "as is" with no
   warranty; the author accepts no liability for any loss or damage.
================================================================================
"""

from __future__ import annotations

import argparse
import csv
import glob
import io
import json
import math
import os
import platform
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import textwrap
import time
from datetime import datetime, timedelta, timezone

APP_NAME = "Installed Software Auditor"
APP_SHORT = "SWAUDIT"
VERSION = "1.0.0"
AUTHOR = "Karanam Shrivasta"
GITHUB = "https://github.com/mrshrivasta"
LINKEDIN = "https://www.linkedin.com/in/karanam-shrivasta/"
DEFAULT_DB = os.environ.get("SWAUDIT_DB", "swaudit.db")

DISCLAIMER_SHORT = (
    "Reads installed-software metadata only, never file contents. NOT a vulnerability "
    "scanner - no CVE data is consulted. Audit machines you own or are authorised to audit, "
    "and never uninstall anything based on this report alone."
)
DISCLAIMER_LONG = textwrap.dedent(
    """\
    AUTHORISED USE ONLY. Audit only machines you own or have permission to audit. This tool
    reads what each package manager reports about installed software; it changes nothing and
    removes nothing. It is NOT a vulnerability scanner: no CVE database is consulted, no
    network request is made, and a package shown as current here may still be vulnerable -
    use Trivy, Grype or osv-scanner against the JSON export for that. Findings are
    heuristics. "Dual-use tooling" means a program has both legitimate and illegitimate
    uses, judged against the machine role you declare; it is not an accusation. The
    end-of-life table is embedded data with a stated date, not a live feed - verify anything
    you act on. Provided "as is" with no warranty; the author accepts no liability for any
    loss or damage."""
)

PRIVACY_NOTICE = (
    "A software inventory describes what a machine is for, who uses it, and where its weak "
    "points are - it is precisely the reconnaissance an attacker wants. It stays in your "
    "local database, nothing is uploaded, and 'purge' removes it. Treat exported reports as "
    "sensitive."
)

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_WEIGHT = {"critical": 18.0, "high": 10.0, "medium": 4.5, "low": 1.5, "info": 0.0}
SEV_COLOR = {"critical": "#e5484d", "high": "#f76808", "medium": "#ffb224",
             "low": "#3e9dd8", "info": "#8b8f9b"}

MANAGER_COLOR = {
    "dpkg": "#e5484d", "rpm": "#f76808", "apk": "#0d597f", "pacman": "#1793d1",
    "snap": "#e95420", "flatpak": "#4a90d9", "pip": "#3776ab", "npm": "#cb3837",
    "gem": "#701516", "cargo": "#dea584", "brew": "#fbb040", "macos-app": "#8b8f9b",
    "windows": "#00a4ef", "appx": "#0078d7", "other": "#6f7685",
}

# ---------------------------------------------------------------------------
# End-of-life data. Embedded, not fetched: this tool makes no network requests.
# Verify anything you act on - support windows move, and vendors extend them.
# ---------------------------------------------------------------------------
EOL_AS_OF = "2026-05-01"
EOL_TABLE = {
    # runtime: [(version_prefix, eol_date, note), ...] - most specific first
    "python": [
        ("2.", "2020-01-01", "Python 2 has been unsupported since January 2020"),
        ("3.6", "2021-12-23", ""), ("3.7", "2023-06-27", ""), ("3.8", "2024-10-07", ""),
        ("3.9", "2025-10-31", ""), ("3.10", "2026-10-31", "scheduled"),
        ("3.11", "2027-10-31", "scheduled"), ("3.12", "2028-10-31", "scheduled"),
    ],
    "node": [
        ("10.", "2021-04-30", ""), ("12.", "2022-04-30", ""), ("14.", "2023-04-30", ""),
        ("16.", "2023-09-11", ""), ("18.", "2025-04-30", ""),
        ("20.", "2026-04-30", "scheduled"), ("22.", "2027-04-30", "scheduled"),
    ],
    "nodejs": [],   # alias, filled in below
    "php": [
        ("7.4", "2022-11-28", ""), ("8.0", "2023-11-26", ""), ("8.1", "2025-12-31", ""),
        ("8.2", "2026-12-31", "scheduled"), ("8.3", "2027-12-31", "scheduled"),
    ],
    "ruby": [
        ("2.6", "2022-03-31", ""), ("2.7", "2023-03-31", ""), ("3.0", "2024-04-23", ""),
        ("3.1", "2025-03-31", ""),
    ],
    "openssl": [
        ("1.0.2", "2019-12-31", ""), ("1.1.0", "2019-09-11", ""),
        ("1.1.1", "2023-09-11", "still shipped by some distributions under paid support"),
        ("3.0", "2026-09-07", "3.0 is the LTS branch; 3.1 and 3.2 have shorter windows"),
    ],
    "dotnet": [
        ("3.1", "2022-12-13", ""), ("5.", "2022-05-10", ""), ("6.", "2024-11-12", ""),
        ("7.", "2024-05-14", ""),
    ],
    "postgresql": [
        ("10", "2022-11-10", ""), ("11", "2023-11-09", ""), ("12", "2024-11-14", ""),
        ("13", "2025-11-13", ""),
    ],
    "mysql-server": [("5.7", "2023-10-31", "")],
    "mariadb-server": [("10.3", "2023-05-25", ""), ("10.4", "2024-06-18", "")],
    "nginx": [], "apache2": [],
    "openjdk": [
        ("7", "2022-07-19", "vendor support windows vary considerably"),
        ("8", "2026-11-01", "vendor support windows vary considerably"),
    ],
}
EOL_TABLE["nodejs"] = EOL_TABLE["node"]

# Dual-use tooling. Judged against a declared machine role, because the same
# program is normal on a laptop and a liability on a production web server.
DUAL_USE = {
    "network-recon": {
        "packages": {"nmap", "masscan", "zmap", "hping3", "fping", "arp-scan", "netdiscover",
                     "nbtscan", "dnsrecon", "dnsenum", "fierce", "sslscan", "testssl.sh"},
        "why": "Network reconnaissance tooling. Normal on an admin workstation; on a "
               "production server it is a ready-made scanner for anyone who lands a shell.",
    },
    "traffic-capture": {
        "packages": {"tcpdump", "wireshark", "tshark", "termshark", "ngrep", "dsniff",
                     "ettercap-text-only", "ettercap-graphical", "bettercap"},
        "why": "Packet capture can read credentials off the wire and is a common "
               "post-compromise step.",
    },
    "credential-attack": {
        "packages": {"john", "hashcat", "hydra", "medusa", "ncrack", "patator", "sqlmap",
                     "aircrack-ng", "reaver", "responder", "crackmapexec", "metasploit-framework",
                     "cewl", "crunch"},
        "why": "Offensive security tooling. Legitimate for a penetration tester; on any "
               "other machine its presence should be explained.",
    },
    "remote-access": {
        "packages": {"teamviewer", "anydesk", "rustdesk", "nomachine", "x11vnc", "tigervnc-viewer",
                     "tigervnc-standalone-server", "realvnc-vnc-server", "xrdp", "rdesktop",
                     "remmina", "chrome-remote-desktop", "splashtop-streamer", "logmein-hamachi",
                     "supremo", "screenconnect"},
        "why": "Remote access software is an inbound path onto the machine and a frequent "
               "route for both support staff and intruders.",
    },
    "tunneling": {
        "packages": {"ngrok", "cloudflared", "localtunnel", "chisel", "frp", "proxychains",
                     "proxychains4", "tor", "torsocks", "stunnel4", "socat"},
        "why": "Tunnelling tools can expose an internal service to the internet or move data "
               "out past a firewall.",
    },
    "build-toolchain": {
        "packages": {"gcc", "g++", "clang", "make", "cmake", "golang-go", "rustc", "cargo",
                     "nasm", "gdb", "strace", "ltrace", "binutils"},
        "why": "Compilers and debuggers let an intruder build tooling in place instead of "
               "downloading it. Essential on a build host, unnecessary on most production "
               "servers.",
    },
    "download": {
        "packages": {"curl", "wget", "aria2", "netcat-openbsd", "netcat-traditional", "ncat",
                     "socat", "rsync", "lftp"},
        "why": "Transfer utilities are the standard way payloads arrive and data leaves. "
               "Near-universal, so this is context only.",
    },
}

# Roles decide which of the above categories actually matter.
ROLES = {
    "workstation": {
        "label": "developer or admin workstation",
        "expected": {"network-recon", "traffic-capture", "build-toolchain", "download",
                     "remote-access"},
        "note": "Development and admin tooling is expected here, so only credential-attack "
                "and tunnelling tools are flagged.",
    },
    "server": {
        "label": "production server",
        "expected": {"download"},
        "note": "A production server should carry as little tooling as possible; anything "
                "beyond basic transfer utilities is flagged for justification.",
    },
    "pentest": {
        "label": "security testing machine",
        "expected": set(DUAL_USE),
        "note": "All security tooling is expected; nothing in this category is flagged.",
    },
    "unknown": {
        "label": "role not declared",
        "expected": {"download", "build-toolchain"},
        "note": "Declare the role with --role for findings tuned to how this machine is "
                "actually used.",
    },
}

MANAGER_LABEL = {
    "dpkg": "Debian/Ubuntu system packages", "rpm": "RPM system packages",
    "apk": "Alpine packages", "pacman": "Arch packages", "snap": "Snap packages",
    "flatpak": "Flatpak applications", "pip": "Python packages", "npm": "Node.js globals",
    "gem": "Ruby gems", "cargo": "Rust binaries", "brew": "Homebrew",
    "macos-app": "macOS applications", "windows": "Windows uninstall registry",
    "appx": "Windows Store apps",
}

IS_WINDOWS = os.name == "nt"
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")


# =============================================================================
# SECTION 1 - Utilities
# =============================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ts_pretty(iso: str | None) -> str:
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def html_escape(s) -> str:
    s = "" if s is None else str(s)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


def fmt_bytes(n, precision: int = 1) -> str:
    if n is None:
        return "-"
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.{0 if unit == 'B' else precision}f} {unit}"
        n /= 1024.0
    return f"{n:.{precision}f} TiB"


def days_between(a: str, b: str | None = None) -> int | None:
    try:
        d1 = datetime.fromisoformat(a).date()
        d2 = datetime.fromisoformat(b).date() if b else datetime.now(timezone.utc).date()
        return (d2 - d1).days
    except Exception:
        return None


def run(cmd: list[str], timeout: int = 60) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           errors="replace")
        return {"ok": p.returncode == 0, "rc": p.returncode, "out": p.stdout or "",
                "err": (p.stderr or "").strip()}
    except FileNotFoundError:
        return {"ok": False, "rc": -1, "out": "", "err": "not installed"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": -2, "out": "", "err": f"timed out after {timeout}s"}
    except Exception as e:
        return {"ok": False, "rc": -3, "out": "", "err": str(e)}


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def read_text(path: str, limit: int = 5_000_000) -> tuple[str | None, str | None]:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(limit), None
    except FileNotFoundError:
        return None, "not present"
    except PermissionError:
        return None, "permission denied"
    except Exception as e:
        return None, str(e)


def version_tuple(v: str) -> tuple:
    """Loose version comparison that copes with distro epochs and suffixes."""
    v = (v or "").split(":")[-1]
    parts = re.split(r"[^0-9]+", v)
    return tuple(int(p) for p in parts if p.isdigit()) or (0,)


class Source:
    """One package manager's result, with an honest status."""

    def __init__(self, name: str):
        self.name = name
        self.packages: list[dict] = []
        self.status = "absent"      # absent | ok | partial | unavailable
        self.detail = ""
        self.command = ""

    def ok(self, command: str = ""):
        self.status = "ok"
        self.command = command or self.command
        return self

    def absent(self, detail: str = "not installed on this machine"):
        self.status, self.detail = "absent", detail
        return self

    def unavailable(self, detail: str):
        self.status, self.detail = "unavailable", detail
        return self

    def partial(self, detail: str):
        self.status = "partial"
        self.detail = " ".join((self.detail + "; " + detail).strip("; ").split())[:400]
        return self


def pkg(manager, name, version, **kw) -> dict:
    d = {"manager": manager, "name": name, "version": version or "", "arch": None,
         "size": None, "section": None, "origin": None, "installed_at": None,
         "install_date_is_proxy": 0, "manual": None, "summary": None, "path": None}
    d.update(kw)
    return d


# =============================================================================
# SECTION 2 - Collectors, one per package manager
#   Each reports absent / ok / partial / unavailable. "Absent" means the manager
#   is not installed, which is not a failure; "unavailable" means it is there but
#   would not answer, which is.
# =============================================================================

def collect_dpkg() -> Source:
    s = Source("dpkg")
    if not have("dpkg-query"):
        return s.absent()
    fmt = ("${Package}\\t${Version}\\t${Architecture}\\t${Installed-Size}\\t${Section}\\t"
           "${db:Status-Status}\\t${binary:Summary}\\n")
    res = run(["dpkg-query", "-W", "-f=" + fmt], timeout=90)
    if not res["ok"] and not res["out"]:
        return s.unavailable(res["err"] or "dpkg-query failed")
    manual = set()
    mres = run(["apt-mark", "showmanual"], timeout=60)
    if mres["ok"]:
        manual = {l.strip() for l in mres["out"].splitlines() if l.strip()}
    else:
        s.partial("apt-mark unavailable, so manual/automatic status is unknown")
    info_dir = "/var/lib/dpkg/info"
    for line in res["out"].splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        name, ver, arch, size, section, status = parts[:6]
        summary = parts[6] if len(parts) > 6 else ""
        if status.strip() != "installed":
            continue
        installed_at = None
        for candidate in (f"{info_dir}/{name}.list", f"{info_dir}/{name}:{arch}.list"):
            try:
                installed_at = datetime.fromtimestamp(
                    os.path.getmtime(candidate), tz=timezone.utc
                ).replace(microsecond=0).isoformat()
                break
            except OSError:
                continue
        s.packages.append(pkg(
            "dpkg", name, ver, arch=arch or None,
            size=int(size) * 1024 if size.isdigit() else None,
            section=section or None, summary=summary or None,
            installed_at=installed_at, install_date_is_proxy=1,
            manual=(1 if name in manual else 0) if manual else None))
    return s.ok("dpkg-query -W")


def collect_rpm() -> Source:
    s = Source("rpm")
    if not have("rpm"):
        return s.absent()
    fmt = "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{SIZE}\\t%{GROUP}\\t%{INSTALLTIME}\\t%{SUMMARY}\\n"
    res = run(["rpm", "-qa", "--qf", fmt], timeout=120)
    if not res["ok"] and not res["out"]:
        return s.unavailable(res["err"] or "rpm query failed")
    for line in res["out"].splitlines():
        p = line.split("\t")
        if len(p) < 6:
            continue
        installed_at = None
        if p[5].isdigit():
            installed_at = datetime.fromtimestamp(int(p[5]), tz=timezone.utc).replace(
                microsecond=0).isoformat()
        s.packages.append(pkg("rpm", p[0], p[1], arch=p[2] or None,
                              size=int(p[3]) if p[3].isdigit() else None,
                              section=p[4] or None, installed_at=installed_at,
                              summary=p[6] if len(p) > 6 else None))
    return s.ok("rpm -qa")


def collect_apk() -> Source:
    s = Source("apk")
    if not have("apk"):
        return s.absent()
    res = run(["apk", "info", "-v"], timeout=60)
    if not res["ok"]:
        return s.unavailable(res["err"] or "apk info failed")
    for line in res["out"].splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^(.+)-(\d[^-]*(?:-r\d+)?)$", line)
        if m:
            s.packages.append(pkg("apk", m.group(1), m.group(2)))
        else:
            s.packages.append(pkg("apk", line, ""))
    return s.ok("apk info -v")


def collect_pacman() -> Source:
    s = Source("pacman")
    if not have("pacman"):
        return s.absent()
    res = run(["pacman", "-Q"], timeout=60)
    if not res["ok"]:
        return s.unavailable(res["err"] or "pacman -Q failed")
    for line in res["out"].splitlines():
        p = line.split()
        if len(p) >= 2:
            s.packages.append(pkg("pacman", p[0], p[1]))
    return s.ok("pacman -Q")


def collect_snap() -> Source:
    s = Source("snap")
    if not have("snap"):
        return s.absent()
    res = run(["snap", "list"], timeout=60)
    if not res["ok"]:
        return s.unavailable(res["err"] or "snap list failed")
    for line in res["out"].splitlines()[1:]:
        p = line.split()
        if len(p) >= 5:
            s.packages.append(pkg("snap", p[0], p[1], origin=p[4],
                                  section="snap:" + (p[5] if len(p) > 5 else "")))
    return s.ok("snap list")


def collect_flatpak() -> Source:
    s = Source("flatpak")
    if not have("flatpak"):
        return s.absent()
    res = run(["flatpak", "list", "--app", "--columns=application,version,origin,size"],
              timeout=60)
    if not res["ok"]:
        return s.unavailable(res["err"] or "flatpak list failed")
    for line in res["out"].splitlines():
        p = line.split("\t")
        if p and p[0].strip():
            s.packages.append(pkg("flatpak", p[0].strip(),
                                  p[1].strip() if len(p) > 1 else "",
                                  origin=p[2].strip() if len(p) > 2 else None))
    return s.ok("flatpak list")


def collect_pip() -> Source:
    s = Source("pip")
    exe = None
    for candidate in ("pip3", "pip"):
        if have(candidate):
            exe = candidate
            break
    if not exe:
        res = run([sys.executable, "-m", "pip", "--version"], timeout=30)
        if not res["ok"]:
            return s.absent()
        exe = None
    cmd = [exe, "list", "--format=json"] if exe else [sys.executable, "-m", "pip", "list",
                                                      "--format=json"]
    res = run(cmd, timeout=120)
    if not res["ok"] and not res["out"].strip().startswith("["):
        return s.unavailable(res["err"] or "pip list failed")
    try:
        for d in json.loads(res["out"]):
            s.packages.append(pkg("pip", d.get("name", ""), d.get("version", ""),
                                  path=d.get("location")))
    except json.JSONDecodeError as e:
        return s.unavailable(f"pip list output was not valid JSON: {e}")
    if "--user" not in " ".join(cmd):
        s.partial("only the environment this tool runs in was queried; other virtualenvs "
                  "and Python installations are not visible")
    return s.ok(" ".join(cmd))


def collect_npm() -> Source:
    s = Source("npm")
    if not have("npm"):
        return s.absent()
    res = run(["npm", "ls", "-g", "--depth=0", "--json"], timeout=120)
    if not res["out"].strip():
        return s.unavailable(res["err"] or "npm produced no output")
    try:
        doc = json.loads(res["out"])
    except json.JSONDecodeError as e:
        return s.unavailable(f"npm output was not valid JSON: {e}")
    for name, meta in (doc.get("dependencies") or {}).items():
        s.packages.append(pkg("npm", name, (meta or {}).get("version", "")))
    if doc.get("problems"):
        s.partial(f"npm reported {len(doc['problems'])} dependency problem(s)")
    return s.ok("npm ls -g --depth=0")


def collect_gem() -> Source:
    s = Source("gem")
    if not have("gem"):
        return s.absent()
    res = run(["gem", "list", "--local"], timeout=90)
    if not res["ok"]:
        return s.unavailable(res["err"] or "gem list failed")
    for line in res["out"].splitlines():
        m = re.match(r"^(\S+)\s+\(([^)]+)\)", line.strip())
        if m:
            s.packages.append(pkg("gem", m.group(1), m.group(2).split(",")[0].strip()))
    return s.ok("gem list --local")


def collect_cargo() -> Source:
    s = Source("cargo")
    if not have("cargo"):
        return s.absent()
    res = run(["cargo", "install", "--list"], timeout=60)
    if not res["ok"]:
        return s.unavailable(res["err"] or "cargo install --list failed")
    for line in res["out"].splitlines():
        m = re.match(r"^(\S+)\s+v([^\s:]+)", line)
        if m:
            s.packages.append(pkg("cargo", m.group(1), m.group(2)))
    return s.ok("cargo install --list")


def collect_brew() -> Source:
    s = Source("brew")
    if not have("brew"):
        return s.absent()
    res = run(["brew", "list", "--versions"], timeout=120)
    if not res["ok"]:
        return s.unavailable(res["err"] or "brew list failed")
    for line in res["out"].splitlines():
        p = line.split()
        if p:
            s.packages.append(pkg("brew", p[0], " ".join(p[1:])))
    cask = run(["brew", "list", "--cask", "--versions"], timeout=120)
    if cask["ok"]:
        for line in cask["out"].splitlines():
            p = line.split()
            if p:
                s.packages.append(pkg("brew", p[0], " ".join(p[1:]), section="cask"))
    return s.ok("brew list --versions")


def collect_macos_apps() -> Source:
    s = Source("macos-app")
    if not IS_MAC:
        return s.absent("not a macOS host")
    res = run(["system_profiler", "SPApplicationsDataType", "-json"], timeout=180)
    if not res["ok"] or not res["out"].strip():
        return s.unavailable(res["err"] or "system_profiler returned nothing")
    try:
        doc = json.loads(res["out"])
    except json.JSONDecodeError as e:
        return s.unavailable(f"system_profiler output was not valid JSON: {e}")
    for a in doc.get("SPApplicationsDataType", []):
        s.packages.append(pkg("macos-app", a.get("_name", ""), a.get("version", ""),
                              path=a.get("path"), origin=a.get("obtained_from"),
                              installed_at=(a.get("lastModified") or "").replace(" ", "T")
                              or None, install_date_is_proxy=1,
                              summary=a.get("info")))
    return s.ok("system_profiler SPApplicationsDataType")


def collect_windows_registry() -> Source:
    """The uninstall registry keys.

    Deliberately NOT Win32_Product: enumerating that WMI class triggers an MSI
    self-repair for every product it touches, which can reconfigure or even
    reinstall software on the machine being audited. An auditor must not change
    what it measures.
    """
    s = Source("windows")
    if not IS_WINDOWS:
        return s.absent("not a Windows host")
    try:
        import winreg
    except ImportError:
        return s.unavailable("winreg unavailable")
    roots = [
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM32"),
        (winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU"),
    ]
    seen, denied = set(), 0
    for hive, path, tag in roots:
        try:
            base = winreg.OpenKey(hive, path)
        except FileNotFoundError:
            continue
        except PermissionError:
            denied += 1
            continue
        except OSError:
            continue
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(base, i)
            except OSError:
                break
            i += 1
            try:
                k = winreg.OpenKey(base, sub)
            except OSError:
                continue

            def val(name):
                try:
                    return winreg.QueryValueEx(k, name)[0]
                except OSError:
                    return None

            name = val("DisplayName")
            if not name or val("SystemComponent") == 1:
                continue
            key = (str(name), str(val("DisplayVersion") or ""))
            if key in seen:
                continue
            seen.add(key)
            raw_date = str(val("InstallDate") or "")
            installed_at = None
            if re.fullmatch(r"\d{8}", raw_date):
                try:
                    installed_at = datetime.strptime(raw_date, "%Y%m%d").replace(
                        tzinfo=timezone.utc).isoformat()
                except ValueError:
                    pass
            size = val("EstimatedSize")
            s.packages.append(pkg("windows", str(name), str(val("DisplayVersion") or ""),
                                  origin=str(val("Publisher") or "") or None,
                                  size=int(size) * 1024 if isinstance(size, int) else None,
                                  installed_at=installed_at, section=tag,
                                  path=str(val("InstallLocation") or "") or None))
    if denied:
        s.partial(f"{denied} registry hive(s) unreadable - run as Administrator for the "
                  f"complete list")
    if not s.packages:
        return s.unavailable("no uninstall entries readable")
    return s.ok(r"HKLM/HKCU ...\Uninstall (not Win32_Product, which would trigger MSI repair)")


def collect_appx() -> Source:
    s = Source("appx")
    if not IS_WINDOWS:
        return s.absent("not a Windows host")
    res = run(["powershell", "-NoProfile", "-Command",
               "Get-AppxPackage | Select-Object Name,Version,Publisher | "
               "ConvertTo-Json -Compress"], timeout=120)
    if not res["ok"] or not res["out"].strip():
        return s.unavailable(res["err"] or "Get-AppxPackage returned nothing")
    try:
        raw = json.loads(res["out"])
    except json.JSONDecodeError as e:
        return s.unavailable(f"Get-AppxPackage output was not valid JSON: {e}")
    if isinstance(raw, dict):
        raw = [raw]
    for a in raw:
        s.packages.append(pkg("appx", a.get("Name", ""), a.get("Version", ""),
                              origin=a.get("Publisher")))
    return s.ok("Get-AppxPackage")


ALL_COLLECTORS = [collect_dpkg, collect_rpm, collect_apk, collect_pacman, collect_snap,
                  collect_flatpak, collect_pip, collect_npm, collect_gem, collect_cargo,
                  collect_brew, collect_macos_apps, collect_windows_registry, collect_appx]


# =============================================================================
# SECTION 3 - Context collectors (repositories, updates, unmanaged binaries)
# =============================================================================

def collect_repositories() -> dict:
    """Third-party package sources. Each one is a party you trust with root."""
    out = {"status": "absent", "detail": "", "repos": []}
    if IS_LINUX and os.path.isdir("/etc/apt"):
        files = ["/etc/apt/sources.list"] + sorted(
            glob.glob("/etc/apt/sources.list.d/*.list")
            + glob.glob("/etc/apt/sources.list.d/*.sources"))
        official = ("ubuntu.com", "debian.org", "canonical.com", "launchpad.net/ubuntu",
                    "raspbian.org", "raspberrypi.org")
        unreadable = 0
        for f in files:
            txt, err = read_text(f, 200_000)
            if txt is None:
                unreadable += 1
                continue
            for line in txt.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                url = None
                if line.startswith("deb"):
                    parts = line.split()
                    url = next((p for p in parts if p.startswith(("http", "https", "ftp"))),
                               None)
                elif line.lower().startswith("uris:"):
                    url = line.split(":", 1)[1].strip().split()[0]
                if not url:
                    continue
                host = re.sub(r"^\w+://", "", url).split("/")[0]
                out["repos"].append({
                    "file": os.path.basename(f), "url": url, "host": host,
                    "third_party": int(not any(o in host for o in official))})
        if unreadable:
            out["detail"] = f"{unreadable} source file(s) unreadable"
        out["status"] = "ok" if out["repos"] else "unavailable"
        if not out["repos"] and not out["detail"]:
            out["detail"] = "no apt sources found"
    elif IS_LINUX and os.path.isdir("/etc/yum.repos.d"):
        for f in sorted(glob.glob("/etc/yum.repos.d/*.repo")):
            txt, _ = read_text(f, 200_000)
            if not txt:
                continue
            for line in txt.splitlines():
                if line.strip().startswith(("baseurl=", "metalink=")):
                    url = line.split("=", 1)[1].strip()
                    host = re.sub(r"^\w+://", "", url).split("/")[0]
                    out["repos"].append({
                        "file": os.path.basename(f), "url": url, "host": host,
                        "third_party": int(not any(
                            o in host for o in ("redhat.com", "fedoraproject.org",
                                                "centos.org", "rockylinux.org")))})
        out["status"] = "ok" if out["repos"] else "unavailable"
    else:
        out["detail"] = "no supported repository configuration on this platform"
    return out


def collect_pending_updates() -> dict:
    """Pending updates from the LOCAL cache only - no network refresh is triggered."""
    out = {"status": "absent", "detail": "", "packages": [], "security": 0}
    if have("apt"):
        res = run(["apt", "list", "--upgradable"], timeout=90)
        if res["ok"]:
            for line in res["out"].splitlines():
                if "/" in line and "upgradable from" in line:
                    name = line.split("/")[0]
                    is_sec = "-security" in line
                    out["packages"].append({"name": name, "detail": line.strip()[:200],
                                            "security": int(is_sec)})
                    out["security"] += int(is_sec)
            out["status"] = "ok"
            out["detail"] = ("counted from the local apt cache; run 'apt update' first for "
                             "an accurate figure")
        else:
            out["status"] = "unavailable"
            out["detail"] = res["err"] or "apt list failed"
    elif have("dnf"):
        res = run(["dnf", "--cacheonly", "check-update"], timeout=90)
        for line in res["out"].splitlines():
            p = line.split()
            if len(p) >= 3 and not line.startswith(("Last metadata", "Obsoleting")):
                out["packages"].append({"name": p[0], "detail": line.strip()[:200],
                                        "security": 0})
        out["status"] = "ok" if out["packages"] or res["rc"] in (0, 100) else "unavailable"
        out["detail"] = "counted from the local dnf cache"
    else:
        out["detail"] = "no supported package manager for update checking"
    return out


def collect_unmanaged_binaries(limit: int = 400) -> dict:
    """Executables in system paths that no package manager claims.

    These are the installs nobody will patch, because no updater knows they are
    there. Language-manager shims are excluded - they are managed, just not by
    the system package manager.
    """
    out = {"status": "absent", "detail": "", "files": []}
    if not IS_LINUX or not have("dpkg-query"):
        out["detail"] = "implemented for dpkg-based systems only"
        return out
    dirs = [d for d in ("/usr/local/bin", "/usr/local/sbin", "/opt") if os.path.isdir(d)]
    if not dirs:
        out["status"] = "ok"
        out["detail"] = "no /usr/local/bin, /usr/local/sbin or /opt on this host"
        return out
    candidates = []
    for d in dirs:
        try:
            for entry in sorted(os.listdir(d))[:limit]:
                p = os.path.join(d, entry)
                if os.path.isfile(p) and os.access(p, os.X_OK):
                    candidates.append(p)
        except PermissionError:
            out["detail"] = f"{d}: permission denied"
    if not candidates:
        out["status"] = "ok"
        return out
    res = run(["dpkg-query", "-S"] + candidates[:limit], timeout=90)
    owned = set()
    for line in res["out"].splitlines():
        if ": " in line:
            owned.add(line.split(": ", 1)[1].strip())
    for p in candidates[:limit]:
        if p in owned:
            continue
        try:
            st = os.stat(p)
        except OSError:
            continue
        # a console script with a language shebang is managed - by pip, npm or gem
        # rather than by dpkg. Calling those "unmanaged" would be wrong and would
        # bury the handful of executables that genuinely have no updater.
        hint = None
        try:
            with open(p, "rb") as fh:
                head = fh.read(128)
            if head.startswith(b"#!"):
                shebang = head.split(b"\n", 1)[0].decode("utf-8", "replace").lower()
                for token, mgr in (("python", "pip"), ("node", "npm"), ("ruby", "gem"),
                                   ("perl", "perl")):
                    if token in shebang:
                        hint = mgr
                        break
        except OSError:
            pass
        out["files"].append({
            "path": p, "size": st.st_size, "managed_by": hint,
            "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
            .replace(microsecond=0).isoformat()})
    out["status"] = "ok"
    return out


# =============================================================================
# SECTION 4 - End-of-life matching
# =============================================================================

# Package names carry their own version far more often than the version field is
# useful: python3.8, openjdk-11-jre, php8.1-cli, postgresql-14.
NAME_VERSION = re.compile(r"^(?P<base>[a-z][a-z+._-]*?)-?(?P<ver>\d+(?:\.\d+)*)"
                          r"(?P<suffix>[-a-z0-9+._]*)$")
RUNTIME_ALIASES = {
    "python3": "python", "python2": "python", "nodejs": "node", "node": "node",
    "openjdk": "openjdk", "default-jdk": "openjdk", "default-jre": "openjdk",
    "libssl": "openssl", "openssl": "openssl", "php": "php", "ruby": "ruby",
    "postgresql": "postgresql", "postgresql-client": "postgresql",
    "mysql-server": "mysql-server", "mariadb-server": "mariadb-server",
    "dotnet-runtime": "dotnet", "dotnet-sdk": "dotnet", "aspnetcore-runtime": "dotnet",
}


def load_eol_table(path: str | None = None) -> tuple[dict, str, str]:
    """Returns (table, as_of, source). Falls back to the embedded table."""
    if path:
        txt, err = read_text(path, 2_000_000)
        if txt is None:
            return EOL_TABLE, EOL_AS_OF, f"built-in (could not read {path}: {err})"
        try:
            doc = json.loads(txt)
        except json.JSONDecodeError as e:
            return EOL_TABLE, EOL_AS_OF, f"built-in ({path} is not valid JSON: {e})"
        table = {k: [tuple(x) for x in v] for k, v in (doc.get("runtimes") or {}).items()}
        if table:
            return table, doc.get("as_of", "unknown"), os.path.abspath(path)
    return EOL_TABLE, EOL_AS_OF, "built-in table"


def runtime_of(name: str, version: str) -> tuple[str | None, str | None]:
    """Map a package to (runtime_key, version_to_test), or (None, None)."""
    n = (name or "").lower()
    for strip in ("-dev", "-doc", "-common", "-data", "-bin", "-cli", "-fpm", "-jre",
                  "-jdk", "-headless", "-minimal", "-client", "-contrib", "-server"):
        if n.endswith(strip):
            n = n[: -len(strip)]
    n = n.strip("-")
    m = NAME_VERSION.match(n)
    if m:
        # Anything left after the version means this is a library BINDING, not the
        # runtime: python3-apt is a Debian package for the apt bindings whose own
        # version is 2.7.7, and matching that against the Python interpreter table
        # would report it as Python 2. Under-reporting beats a false accusation.
        if m.group("suffix"):
            return None, None
        base = RUNTIME_ALIASES.get(m.group("base"), m.group("base"))
        if base in EOL_TABLE or base in RUNTIME_ALIASES.values():
            return base, m.group("ver")
    base = RUNTIME_ALIASES.get(n, n)
    if base in EOL_TABLE:
        return base, (version or "").split(":")[-1]
    return None, None


def check_eol(name: str, version: str, table: dict,
              today: str | None = None) -> dict | None:
    """Return EOL detail when a package matches a known runtime, else None.

    A name like 'libssl1.1' is ambiguous - 1.1.0 and 1.1.1 had different end
    dates - so when the version embedded in the name does not resolve, the
    package's actual version field is tried before giving up. Guessing between
    two support windows would be worse than reporting nothing.
    """
    key, ver = runtime_of(name, version)
    if not key or key not in table:
        return None
    today = today or datetime.now(timezone.utc).date().isoformat()
    entries = sorted(table[key], key=lambda e: -len(str(e[0])))
    # strip a distro epoch, revision and any trailing letter: '1:1.1.1f-1ubuntu2' -> '1.1.1'
    clean_version = (version or "").split(":")[-1].split("-")[0].split("+")[0].strip()
    m_ver = re.match(r"^(\d+(?:\.\d+)*)", clean_version)
    clean_version = m_ver.group(1) if m_ver else clean_version
    for candidate, precision in ((ver, "package name"), (clean_version, "version field")):
        if not candidate:
            continue
        for prefix, eol_date, note in entries:
            p = str(prefix)
            if (candidate == p or candidate == p.rstrip(".")
                    or candidate.startswith(p if p.endswith(".") else p + ".")):
                shown = re.match(r"^\d+(?:\.\d+)*", candidate)
                return {"runtime": key, "version": shown.group(0) if shown else candidate,
                        "eol": eol_date,
                        "note": note, "past": eol_date < today,
                        "days": days_between(eol_date, today), "matched_on": precision}
    return None


# =============================================================================
# SECTION 5 - Findings
# =============================================================================

def F(category, title, severity, description, evidence="", recommendation="",
      reference="", subject=None):
    return {"category": category, "title": title, "severity": severity,
            "description": description, "evidence": str(evidence)[:3000],
            "recommendation": recommendation, "reference": reference, "subject": subject}


def not_performed(category, title, reason):
    return F(category, f"Check not performed: {title}", "info",
             "This check could not be evaluated, so its result is unknown. It is NOT "
             "counted as a pass.", reason,
             "Install or repair the relevant package manager, or re-run with the "
             "privileges it needs.")


def analyse(packages: list[dict], sources: list[Source], context: dict, baseline: dict,
            role: str = "unknown", eol_table=None, eol_as_of: str = EOL_AS_OF,
            eol_source: str = "built-in table") -> list[dict]:
    out: list[dict] = []
    eol_table = eol_table or EOL_TABLE
    role_cfg = ROLES.get(role, ROLES["unknown"])
    today = datetime.now(timezone.utc).date().isoformat()

    # ---- collector honesty ----
    for s in sources:
        if s.status == "unavailable":
            out.append(not_performed("Inventory", f"{s.name} inventory", s.detail))
    ok_sources = [s for s in sources if s.status in ("ok", "partial")]
    if not ok_sources:
        out.append(F("Inventory", "No package manager could be queried", "high",
                     "Nothing could be inventoried, so this report describes nothing.",
                     "; ".join(f"{s.name}: {s.status} {s.detail}" for s in sources),
                     "Check that a package manager is installed and answers on this host."))
        return out

    # ---- the EOL table's own freshness ----
    stale_days = days_between(eol_as_of, today) or 0
    if stale_days > 180:
        out.append(F("Lifecycle", "The end-of-life table is getting old", "low",
                     "This tool ships end-of-life dates as embedded data because it makes no "
                     "network requests. Support windows change, so an old table both misses "
                     "newly expired versions and may misstate scheduled dates.",
                     f"table dated {eol_as_of} ({stale_days} days ago), source: {eol_source}",
                     "Supply a current table with --eol-file, or verify anything you act on "
                     "against the vendor's own lifecycle page."))

    # ---- end of life ----
    eol_hits, upcoming = [], []
    for p in packages:
        hit = check_eol(p["name"], p["version"], eol_table, today)
        if not hit:
            continue
        if hit["past"]:
            eol_hits.append((p, hit))
        elif hit["days"] is not None and -180 <= hit["days"] <= 0:
            upcoming.append((p, hit))
    if eol_hits:
        by_age = sorted(eol_hits, key=lambda x: x[1]["eol"])
        very_old = [x for x in by_age if (days_between(x[1]["eol"], today) or 0) > 730]
        sev = "critical" if very_old else "high"
        out.append(F("Lifecycle", f"{len(eol_hits)} package(s) are past end of life", sev,
                     "Unsupported software stops receiving security fixes. Anything found "
                     "in it after the end date stays unfixed, and this is one of the most "
                     "reliable ways machines get compromised.",
                     "; ".join(f"{p['name']} {p['version'] or hit['version']} "
                               f"({hit['runtime']} {hit['version']}, EOL {hit['eol']}"
                               f"{', ' + hit['note'] if hit['note'] else ''})"
                               for p, hit in by_age[:20]),
                     "Upgrade to a supported release, or document why this one is retained "
                     "and how it is isolated.",
                     "verify against the vendor's lifecycle page before acting"))
    if upcoming:
        out.append(F("Lifecycle", f"{len(upcoming)} package(s) reach end of life soon", "low",
                     "These are still supported but the window is closing. Planning an "
                     "upgrade now is much cheaper than doing it under pressure later.",
                     "; ".join(f"{p['name']} ({hit['runtime']} {hit['version']}, "
                               f"EOL {hit['eol']})" for p, hit in upcoming[:20]),
                     "Schedule the upgrade before the date."))

    # ---- the same software from two managers ----
    by_name: dict[str, list[dict]] = {}
    for p in packages:
        key = re.sub(r"^(python3?-|node-|ruby-|lib)", "", p["name"].lower())
        key = re.sub(r"[-_.]", "", key)
        by_name.setdefault(key, []).append(p)
    overlaps = []
    for key, group in by_name.items():
        managers = {g["manager"] for g in group}
        system = {"dpkg", "rpm", "apk", "pacman"} & managers
        language = {"pip", "npm", "gem", "cargo"} & managers
        other = {"snap", "flatpak", "brew"} & managers
        if len(managers) > 1 and (system and (language or other) or len(other) > 1):
            versions = {f"{g['manager']}:{g['version'] or '?'}" for g in group}
            if len({v.split(":", 1)[1] for v in versions}) > 1:
                overlaps.append((group[0]["name"], sorted(versions)))
    if overlaps:
        out.append(F("Duplication",
                     f"{len(overlaps)} package(s) installed through more than one manager",
                     "medium",
                     "When two managers own the same software, which copy runs depends on "
                     "PATH, and only one of them gets updated. This is a common source of "
                     "'we patched that' being wrong.",
                     "; ".join(f"{name}: {', '.join(vers)}" for name, vers in overlaps[:15]),
                     "Pick one manager per piece of software and remove the other copy."))

    # ---- dual-use tooling, judged against the declared role ----
    installed_names = {p["name"].lower() for p in packages}
    flagged_categories = []
    for cat, meta in DUAL_USE.items():
        present = sorted(installed_names & meta["packages"])
        if not present:
            continue
        if cat in role_cfg["expected"]:
            out.append(F("Tooling", f"{cat.replace('-', ' ').title()} present "
                         f"({len(present)})", "info",
                         f"Expected for a {role_cfg['label']}, so this is context rather "
                         f"than a finding. {meta['why']}",
                         ", ".join(present[:25]),
                         "No action needed unless the role declaration is wrong."))
            continue
        sev = "medium" if cat in ("credential-attack", "remote-access") else "low"
        flagged_categories.append(cat)
        out.append(F("Tooling", f"{cat.replace('-', ' ').title()} on a "
                     f"{role_cfg['label']}", sev,
                     meta["why"] + " This is judged against the role you declared; it is a "
                     "prompt to justify the software, not an accusation that anything is "
                     "wrong.",
                     ", ".join(present[:25]),
                     f"If these belong here, record why - or re-run with a role that "
                     f"matches how the machine is used (--role workstation|server|pentest).",
                     "MITRE ATT&CK T1588.002 / living-off-the-land tooling", cat))
    if role == "unknown":
        out.append(F("Tooling", "Machine role not declared", "info",
                     ROLES["unknown"]["note"],
                     f"flagged categories with the default role: "
                     f"{', '.join(flagged_categories) or 'none'}",
                     "Re-run with --role workstation, --role server or --role pentest."))

    # ---- repositories ----
    repos = context.get("repos") or {}
    if repos.get("status") == "ok":
        third = [r for r in repos["repos"] if r["third_party"]]
        if third:
            hosts = sorted({r["host"] for r in third})
            out.append(F("Supply chain", f"{len(hosts)} third-party package repository "
                         f"(repositories)", "low",
                         "Every configured repository is a party that can install software "
                         "on this machine as root. That is often a deliberate and reasonable "
                         "choice; it should still be a known one.",
                         "; ".join(f"{r['host']} (from {r['file']})" for r in third[:12]),
                         "Confirm each source is intended, and that its signing key is still "
                         "one you trust."))
    elif repos.get("status") == "unavailable":
        out.append(not_performed("Supply chain", "repository review",
                                 repos.get("detail") or "no repository data"))

    # ---- pending updates ----
    upd = context.get("updates") or {}
    if upd.get("status") == "ok":
        n = len(upd["packages"])
        sec = upd.get("security", 0)
        if sec:
            out.append(F("Patching", f"{sec} security update(s) pending", "high",
                         "Updates from a security pocket are the ones that matter most, and "
                         "they are waiting.",
                         "; ".join(p["name"] for p in upd["packages"]
                                   if p["security"])[:800],
                         "Apply them at the next opportunity."))
        remaining = n - sec
        if remaining >= 50:
            sev = "medium"
        elif remaining >= 10:
            sev = "low"
        else:
            sev = None
        if sev:
            out.append(F("Patching", f"{remaining} non-security update(s) pending", sev,
                         "Routine updates accumulating. " + upd.get("detail", ""),
                         "; ".join(p["name"] for p in upd["packages"]
                                   if not p["security"])[:800],
                         "Apply during your next maintenance window."))
        elif n == 0:
            out.append(F("Patching", "No pending updates in the local cache", "info",
                         upd.get("detail", ""), "",
                         "Refresh the package cache regularly so this stays meaningful."))
    elif upd.get("status") == "unavailable":
        out.append(not_performed("Patching", "pending update check",
                                 upd.get("detail") or "no update data"))

    # ---- software nothing will ever patch ----
    unm = context.get("unmanaged") or {}
    if unm.get("status") == "ok":
        truly = [f for f in unm["files"] if not f.get("managed_by")]
        managed = len(unm["files"]) - len(truly)
        if truly:
            out.append(F("Supply chain", f"{len(truly)} executable(s) not owned by any "
                         f"package manager", "medium",
                         "Nothing will ever update these. They were installed by hand, by a "
                         "vendor script, or by an installer that bypassed the package "
                         "system, so no updater knows they exist."
                         + (f" A further {managed} executable(s) in the same directories are "
                            f"language-manager console scripts and ARE managed, just not by "
                            f"the system package manager." if managed else ""),
                         "; ".join(f"{f['path']} ({fmt_bytes(f['size'])}, modified "
                                   f"{f['mtime'][:10]})" for f in truly[:20]),
                         "Record where each came from and how it gets updated, or replace it "
                         "with a packaged version."))
        else:
            out.append(F("Supply chain", "No unmanaged executables in system paths", "info",
                         f"Everything in the directories checked is owned by a package "
                         f"manager ({managed} of them language-manager console scripts).",
                         "", "Re-check after any manual install."))

    # ---- baseline ----
    if baseline:
        unapproved = [p for p in packages
                      if f"{p['manager']}:{p['name']}" not in baseline]
        out.append(F("Baseline", f"{len(packages) - len(unapproved)} of {len(packages)} "
                     f"package(s) are approved", "info",
                     "Approved software is excluded from baseline drift reporting.",
                     f"the baseline holds {len(baseline)} entries",
                     "Keep it current as the machine's purpose changes."))
    else:
        out.append(F("Baseline", "No approved-software baseline has been set", "low",
                     "Without a baseline, every scan reports the whole inventory and nothing "
                     "stands out. With one, later scans show only what changed.",
                     "the baseline is empty",
                     "Approve the current inventory once you have reviewed it: "
                     "swaudit approve --all"))

    # ---- summary ----
    per_manager = {}
    for p in packages:
        per_manager[p["manager"]] = per_manager.get(p["manager"], 0) + 1
    sized = [p["size"] for p in packages if p["size"]]
    out.append(F("Summary", f"{len(packages)} package(s) across "
                 f"{len(per_manager)} manager(s)", "info",
                 ", ".join(f"{k}: {v}" for k, v in sorted(per_manager.items(),
                                                          key=lambda x: -x[1])),
                 f"total reported size {fmt_bytes(sum(sized))} across {len(sized)} package(s) "
                 f"that report one",
                 "This inventory is what an attacker would enumerate first - treat the "
                 "export as sensitive."))
    out.append(F("Summary", "This audit did not check for known vulnerabilities", "info",
                 "No CVE database was consulted, because that requires network access and "
                 "usually an API key. A package shown here as current and supported may "
                 "still have known vulnerabilities.",
                 "no network request was made at any point",
                 "Run Trivy, Grype or osv-scanner against the JSON export from this tool for "
                 "CVE matching."))
    return out


def compute_score(counts: dict) -> float:
    return round(clamp(100.0 - sum(SEV_WEIGHT[s] * counts.get(s, 0) for s in SEVERITIES),
                       0.0, 100.0), 1)


def risk_label(score: float) -> tuple[str, str]:
    if score >= 90:
        return "healthy", "#30a46c"
    if score >= 75:
        return "minor issues", "#5bb98b"
    if score >= 55:
        return "needs attention", "#ffb224"
    if score >= 30:
        return "significant issues", "#f76808"
    return "urgent attention", "#e5484d"


def diff_packages(previous: list[dict], current: list[dict]) -> dict:
    """What changed between two inventories."""
    def index(rows):
        return {(r["manager"], r["name"]): (r.get("version") or "") for r in rows}
    a, b = index(previous), index(current)
    added = [{"manager": m, "name": n, "version": b[(m, n)]}
             for (m, n) in sorted(b.keys() - a.keys())]
    removed = [{"manager": m, "name": n, "version": a[(m, n)]}
               for (m, n) in sorted(a.keys() - b.keys())]
    changed = []
    for key in sorted(a.keys() & b.keys()):
        if a[key] != b[key]:
            direction = "upgraded"
            try:
                if version_tuple(b[key]) < version_tuple(a[key]):
                    direction = "downgraded"
            except Exception:
                direction = "changed"
            changed.append({"manager": key[0], "name": key[1], "from": a[key],
                            "to": b[key], "direction": direction})
    return {"added": added, "removed": removed, "changed": changed}


# =============================================================================
# SECTION 6 - Database
# =============================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, hostname TEXT, os_name TEXT, os_version TEXT, role TEXT,
    sources_json TEXT, context_json TEXT, eol_as_of TEXT, eol_source TEXT,
    packages INTEGER DEFAULT 0, managers INTEGER DEFAULT 0, total_size INTEGER DEFAULT 0,
    score REAL, risk TEXT, total_findings INTEGER DEFAULT 0,
    critical INTEGER DEFAULT 0, high INTEGER DEFAULT 0, medium INTEGER DEFAULT 0,
    low INTEGER DEFAULT 0, info INTEGER DEFAULT 0,
    added INTEGER DEFAULT 0, removed INTEGER DEFAULT 0, changed INTEGER DEFAULT 0,
    prev_scan_id INTEGER, note TEXT
);
CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
    manager TEXT, name TEXT, version TEXT, arch TEXT, size INTEGER, section TEXT,
    origin TEXT, summary TEXT, path TEXT, installed_at TEXT,
    install_date_is_proxy INTEGER DEFAULT 0, manual INTEGER,
    eol_runtime TEXT, eol_date TEXT, eol_past INTEGER DEFAULT 0, approved INTEGER DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
    category TEXT, title TEXT, severity TEXT, description TEXT, evidence TEXT,
    recommendation TEXT, reference TEXT, subject TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL, prev_scan_id INTEGER,
    kind TEXT, manager TEXT, name TEXT, version_from TEXT, version_to TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS baseline (
    key TEXT PRIMARY KEY, manager TEXT, name TEXT, version TEXT, approved_at TEXT,
    approved_by TEXT, note TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, level TEXT NOT NULL, source TEXT, message TEXT, scan_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_pkg_scan ON packages(scan_id);
CREATE INDEX IF NOT EXISTS idx_pkg_mgr ON packages(manager);
CREATE INDEX IF NOT EXISTS idx_pkg_name ON packages(name);
CREATE INDEX IF NOT EXISTS idx_find_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_chg_scan ON changes(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""

_DB_PATH = DEFAULT_DB


def set_db_path(p: str) -> None:
    global _DB_PATH
    _DB_PATH = p


def db_path() -> str:
    return _DB_PATH


def connect(path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or _DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        if own:
            conn.close()


def q(sql: str, args: tuple = (), conn=None) -> list[sqlite3.Row]:
    own = conn is None
    conn = conn or connect()
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        if own:
            conn.close()


def q1(sql: str, args: tuple = (), conn=None):
    rows = q(sql, args, conn)
    return rows[0] if rows else None


def log_event(level: str, source: str, message: str, scan_id=None, conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.execute("INSERT INTO audit_log (ts, level, source, message, scan_id) "
                     "VALUES (?,?,?,?,?)",
                     (now_iso(), level.upper(), source,
                      " ".join(str(message).split())[:1000], scan_id))
        conn.commit()
    except Exception:
        pass
    finally:
        if own:
            conn.close()


def load_baseline(conn=None) -> dict:
    return {r["key"]: dict(r) for r in q("SELECT * FROM baseline", (), conn)}


def approve_packages(entries: list[dict], by: str = "", note: str = "") -> int:
    conn = connect()
    try:
        init_db(conn)
        n = 0
        for e in entries:
            key = f"{e['manager']}:{e['name']}"
            conn.execute("INSERT INTO baseline (key, manager, name, version, approved_at,"
                         " approved_by, note) VALUES (?,?,?,?,?,?,?) "
                         "ON CONFLICT(key) DO UPDATE SET version=excluded.version,"
                         " approved_at=excluded.approved_at",
                         (key, e["manager"], e["name"], e.get("version", ""), now_iso(),
                          by or os.environ.get("USER") or "unknown", note))
            n += 1
        conn.commit()
        log_event("INFO", "baseline", f"Approved {n} package(s)", None, conn)
        return n
    finally:
        conn.close()


def revoke_package(key: str) -> int:
    conn = connect()
    try:
        n = conn.execute("DELETE FROM baseline WHERE key=?", (key,)).rowcount
        conn.commit()
        return n
    finally:
        conn.close()


def latest_scan_id(conn=None):
    row = q1("SELECT id FROM scans ORDER BY id DESC LIMIT 1", (), conn)
    return row["id"] if row else None


def scan_summary(scan_id: int, conn=None):
    row = q1("SELECT * FROM scans WHERE id=?", (scan_id,), conn)
    if not row:
        return None
    d = dict(row)
    d["risk_label"], d["risk_colour"] = risk_label(d["score"] or 0)
    return d


def save_scan(packages, sources, context, findings, role, eol_as_of, eol_source,
              note="") -> int:
    conn = connect()
    try:
        init_db(conn)
        counts = {s: 0 for s in SEVERITIES}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        score = compute_score(counts)
        risk, _ = risk_label(score)
        prev_id = latest_scan_id(conn)
        prev_pkgs = [dict(r) for r in q("SELECT manager,name,version FROM packages "
                                        "WHERE scan_id=?", (prev_id,), conn)] if prev_id else []
        delta = diff_packages(prev_pkgs, packages) if prev_pkgs else {
            "added": [], "removed": [], "changed": []}
        managers = {p["manager"] for p in packages}
        cur = conn.execute(
            "INSERT INTO scans (ts, hostname, os_name, os_version, role, sources_json,"
            " context_json, eol_as_of, eol_source, packages, managers, total_size, score,"
            " risk, total_findings, critical, high, medium, low, info, added, removed,"
            " changed, prev_scan_id, note)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (now_iso(), socket.gethostname(), platform.system(), platform.platform(), role,
             json.dumps([{"name": s.name, "status": s.status, "detail": s.detail,
                          "command": s.command, "count": len(s.packages)} for s in sources]),
             json.dumps({k: {kk: vv for kk, vv in v.items() if kk != "files"}
                         if isinstance(v, dict) else v for k, v in context.items()}),
             eol_as_of, eol_source, len(packages), len(managers),
             sum(p["size"] or 0 for p in packages), score, risk, len(findings),
             counts["critical"], counts["high"], counts["medium"], counts["low"],
             counts["info"], len(delta["added"]), len(delta["removed"]),
             len(delta["changed"]), prev_id, note))
        sid = cur.lastrowid
        baseline = load_baseline(conn)
        table, _, _ = load_eol_table(None)
        for p in packages:
            hit = check_eol(p["name"], p["version"], table)
            conn.execute(
                "INSERT INTO packages (scan_id, manager, name, version, arch, size, section,"
                " origin, summary, path, installed_at, install_date_is_proxy, manual,"
                " eol_runtime, eol_date, eol_past, approved)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid, p["manager"], p["name"], p["version"], p.get("arch"), p.get("size"),
                 p.get("section"), p.get("origin"), p.get("summary"), p.get("path"),
                 p.get("installed_at"), p.get("install_date_is_proxy", 0), p.get("manual"),
                 hit["runtime"] if hit else None, hit["eol"] if hit else None,
                 int(hit["past"]) if hit else 0,
                 int(f"{p['manager']}:{p['name']}" in baseline)))
        for f in findings:
            conn.execute("INSERT INTO findings (scan_id, category, title, severity,"
                         " description, evidence, recommendation, reference, subject)"
                         " VALUES (?,?,?,?,?,?,?,?,?)",
                         (sid, f["category"], f["title"], f["severity"], f["description"],
                          f["evidence"], f["recommendation"], f["reference"], f["subject"]))
        for kind in ("added", "removed", "changed"):
            for c in delta[kind]:
                conn.execute("INSERT INTO changes (scan_id, prev_scan_id, kind, manager,"
                             " name, version_from, version_to) VALUES (?,?,?,?,?,?,?)",
                             (sid, prev_id, c.get("direction", kind), c["manager"], c["name"],
                              c.get("from", c.get("version") if kind == "removed" else None),
                              c.get("to", c.get("version") if kind == "added" else None)))
        conn.commit()
        log_event("INFO", "scan", f"Scan #{sid}: {len(packages)} package(s) across "
                  f"{len(managers)} manager(s), {len(findings)} finding(s), score {score}"
                  + (f"; changes vs #{prev_id}: +{len(delta['added'])} "
                     f"-{len(delta['removed'])} ~{len(delta['changed'])}" if prev_id else ""),
                  sid, conn)
        for s in sources:
            if s.status == "unavailable":
                log_event("WARN", f"collector.{s.name}", s.detail, sid, conn)
        return sid
    finally:
        conn.close()


def run_scan(role: str = "unknown", eol_file: str | None = None, note: str = "",
             progress=None) -> int:
    sources = []
    for fn in ALL_COLLECTORS:
        if progress:
            progress(fn.__name__.replace("collect_", ""))
        sources.append(fn())
    packages = [p for s in sources for p in s.packages]
    if progress:
        progress("context (repositories, updates, unmanaged binaries)")
    context = {"repos": collect_repositories(), "updates": collect_pending_updates(),
               "unmanaged": collect_unmanaged_binaries()}
    table, as_of, src = load_eol_table(eol_file)
    findings = analyse(packages, sources, context, load_baseline(), role, table, as_of, src)
    return save_scan(packages, sources, context, findings, role, as_of, src, note)


# =============================================================================
# SECTION 7 - Charts (hand-drawn SVG: no CDN, no JS charting library, offline)
# =============================================================================

def svg_pie(items, size=200, title="Findings by severity", fmt=lambda v: f"{v:g}"):
    items = [(l, float(v), c) for (l, v, c) in items if v and v > 0]
    total = sum(v for _, v, _ in items)
    if total <= 0:
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    cx = cy = size / 2
    r_out, r_in = size / 2 - 10, size / 2 - 46
    parts, legend, angle = [], [], -90.0
    for label, value, color in items:
        sweep = 360.0 * value / total
        if abs(sweep - 360.0) < 1e-9:
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2:.2f}" fill="none" '
                         f'stroke="{color}" stroke-width="{r_out - r_in:.2f}"/>')
        else:
            a0, a1 = math.radians(angle), math.radians(angle + sweep)
            x0, y0 = cx + r_out * math.cos(a0), cy + r_out * math.sin(a0)
            x1, y1 = cx + r_out * math.cos(a1), cy + r_out * math.sin(a1)
            x2, y2 = cx + r_in * math.cos(a1), cy + r_in * math.sin(a1)
            x3, y3 = cx + r_in * math.cos(a0), cy + r_in * math.sin(a0)
            lg = 1 if sweep > 180 else 0
            parts.append(f'<path d="M {x0:.2f} {y0:.2f} A {r_out:.2f} {r_out:.2f} 0 {lg} 1 '
                         f'{x1:.2f} {y1:.2f} L {x2:.2f} {y2:.2f} A {r_in:.2f} {r_in:.2f} 0 '
                         f'{lg} 0 {x3:.2f} {y3:.2f} Z" fill="{color}">'
                         f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title></path>')
        angle += sweep
        legend.append(f'<div class="lg"><i style="background:{color}"></i>'
                      f'<span>{html_escape(label)}</span><b>{html_escape(fmt(value))}</b>'
                      f'<em>{100.0 * value / total:.0f}%</em></div>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<div class="chart-row"><svg viewBox="0 0 {size} {size}" width="{size}" '
            f'height="{size}" role="img" aria-label="{html_escape(title)}">{"".join(parts)}'
            f'<text x="{cx}" y="{cy + 5}" text-anchor="middle" class="pie-n">'
            f'{html_escape(fmt(total))}</text></svg>'
            f'<div class="legend">{"".join(legend)}</div></div></figure>')


def svg_bar(items, width=430, title="By manager", color="#5b8def",
            fmt=lambda v: f"{v:g}", colors=None):
    items = [(str(l), float(v or 0)) for l, v in items]
    if not items or all(v <= 0 for _, v in items):
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    row_h, gap, pad_l, pad_t = 23, 8, 150, 8
    height = pad_t * 2 + len(items) * (row_h + gap)
    mx = max(v for _, v in items) or 1
    bw = width - pad_l - 80
    rows = []
    for i, (label, value) in enumerate(items):
        y = pad_t + i * (row_h + gap)
        w = max(2.0, bw * value / mx)
        c = (colors or {}).get(label, color)
        lbl = label if len(label) <= 20 else label[:19] + "\u2026"
        rows.append(
            f'<text x="{pad_l - 10}" y="{y + row_h * 0.7:.1f}" text-anchor="end" class="bl">'
            f'{html_escape(lbl)}</text>'
            f'<rect x="{pad_l}" y="{y}" width="{bw}" height="{row_h}" rx="4" class="btrack"/>'
            f'<rect x="{pad_l}" y="{y}" width="{w:.1f}" height="{row_h}" rx="4" fill="{c}">'
            f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title></rect>'
            f'<text x="{pad_l + bw + 8:.1f}" y="{y + row_h * 0.7:.1f}" class="bv">'
            f'{html_escape(fmt(value))}</text>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" role="img" '
            f'aria-label="{html_escape(title)}">{"".join(rows)}</svg></figure>')


def svg_columns(items, width=470, height=210, title="History", ymax=None, color="#5b8def"):
    items = [(str(l), float(v or 0), c) if len(x) == 3 else (str(x[0]), float(x[1] or 0), color)
             for x in items for l, v, *c in [x]]
    if not items:
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    pad_l, pad_b, pad_t, pad_r = 40, 26, 16, 8
    pw, ph = width - pad_l - pad_r, height - pad_t - pad_b
    slot = pw / len(items)
    bw = min(34.0, slot * 0.62)
    top = ymax or max(v for _, v, _ in items) or 1
    bars, grid = [], []
    for f in (0, 0.5, 1.0):
        y = pad_t + ph - ph * f
        grid.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width - pad_r}" y2="{y:.1f}" '
                    f'class="gl"/><text x="{pad_l - 7}" y="{y + 4:.1f}" text-anchor="end" '
                    f'class="bl">{top * f:g}</text>')
    for i, (label, value, c) in enumerate(items):
        h = ph * clamp(value, 0, top) / top
        x = pad_l + slot * i + (slot - bw) / 2
        y = pad_t + ph - h
        bars.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw:.1f}" height="{max(h, 1):.1f}" rx="3" '
            f'fill="{c}"><title>{html_escape(label)}: {value:g}</title></rect>'
            f'<text x="{x + bw / 2:.1f}" y="{y - 4:.1f}" text-anchor="middle" class="bv">'
            f'{value:g}</text>'
            f'<text x="{x + bw / 2:.1f}" y="{height - 8}" text-anchor="middle" class="bl">'
            f'{html_escape(label)}</text>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" role="img" '
            f'aria-label="{html_escape(title)}">{"".join(grid)}{"".join(bars)}</svg></figure>')


def svg_gauge(score, label, size=150):
    colour = risk_label(score)[1]
    r = size / 2 - 13
    cx = cy = size / 2
    circ = 2 * math.pi * r
    return (f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img" '
            f'aria-label="Score {score} of 100, {label}">'
            f'<circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" stroke="#262a33" '
            f'stroke-width="12"/>'
            f'<circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" stroke="{colour}" '
            f'stroke-width="12" stroke-linecap="round" '
            f'stroke-dasharray="{circ * clamp(score, 0, 100) / 100:.2f} {circ:.2f}" '
            f'transform="rotate(-90 {cx} {cy})"/>'
            f'<text x="{cx}" y="{cy + 4}" text-anchor="middle" class="g-n" fill="{colour}">'
            f'{score:g}</text>'
            f'<text x="{cx}" y="{cy + 22}" text-anchor="middle" class="g-l">/100</text></svg>')


def svg_treemap(items, width=980, height=190, title="Disk footprint by package"):
    """A simple squarified-ish treemap: the biggest packages, by reported size."""
    items = [(str(n), float(v)) for n, v in items if v and v > 0][:40]
    if not items:
        return (f'<div class="chart-empty">{html_escape(title)}: no package reported a '
                f'size on this system</div>')
    total = sum(v for _, v in items)
    cells, x, y, row, row_sum = [], 0.0, 0.0, [], 0.0
    target_rows = max(1, int(math.sqrt(len(items) / 2)))
    row_h = height / target_rows
    per_row = math.ceil(len(items) / target_rows)
    for i, (name, value) in enumerate(items):
        if len(row) >= per_row:
            rx = 0.0
            for n2, v2 in row:
                w = width * (v2 / row_sum) if row_sum else 0
                cells.append((rx, y, w, row_h, n2, v2))
                rx += w
            y += row_h
            row, row_sum = [], 0.0
        row.append((name, value))
        row_sum += value
    if row:
        rx = 0.0
        for n2, v2 in row:
            w = width * (v2 / row_sum) if row_sum else 0
            cells.append((rx, y, w, row_h, n2, v2))
            rx += w
    out = []
    for i, (cx, cy, cw, ch, name, value) in enumerate(cells):
        shade = 0.30 + 0.55 * (value / max(v for _, v in items))
        out.append(
            f'<rect x="{cx:.1f}" y="{cy:.1f}" width="{max(cw - 2, 1):.1f}" '
            f'height="{max(ch - 2, 1):.1f}" rx="3" fill="#5b8def" fill-opacity="{shade:.2f}">'
            f'<title>{html_escape(name)}: {html_escape(fmt_bytes(value))}</title></rect>')
        if cw > 62 and ch > 22:
            out.append(f'<text x="{cx + 6:.1f}" y="{cy + 15:.1f}" class="tm">'
                       f'{html_escape(name[:int(cw / 7)])}</text>')
    return (f'<figure class="chart wide"><figcaption>{html_escape(title)} &middot; '
            f'{html_escape(fmt_bytes(total))} across the {len(items)} largest</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" '
            f'aria-label="{html_escape(title)}">{"".join(out)}</svg></figure>')


# =============================================================================
# SECTION 8 - Exports
# =============================================================================

def report_payload(scan_id=None, conn=None) -> dict:
    own = conn is None
    conn = conn or connect()
    try:
        sid = scan_id or latest_scan_id(conn)
        scan = scan_summary(sid, conn) if sid else None
        return {
            "tool": APP_NAME, "version": VERSION, "author": AUTHOR,
            "generated_at": now_iso(), "disclaimer": DISCLAIMER_LONG,
            "privacy_notice": PRIVACY_NOTICE,
            "not_a_vulnerability_scan": (
                "No CVE database was consulted and no network request was made. Packages "
                "listed here as current may still have known vulnerabilities. Feed this "
                "JSON to Trivy, Grype or osv-scanner for vulnerability matching."),
            "scan": scan,
            "sources": json.loads(scan["sources_json"]) if scan and scan["sources_json"]
                       else [],
            "context": json.loads(scan["context_json"]) if scan and scan["context_json"]
                       else {},
            "packages": [dict(r) for r in q("SELECT manager,name,version,arch,size,section,"
                                            "origin,installed_at,install_date_is_proxy,manual,"
                                            "eol_runtime,eol_date,eol_past,approved "
                                            "FROM packages WHERE scan_id=? ORDER BY manager,"
                                            "name", (sid,), conn)] if sid else [],
            "findings": [dict(r) for r in q(
                "SELECT category,title,severity,description,evidence,recommendation,reference "
                "FROM findings WHERE scan_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 "
                "WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id",
                (sid,), conn)] if sid else [],
            "changes": [dict(r) for r in q("SELECT kind,manager,name,version_from,version_to "
                                           "FROM changes WHERE scan_id=? ORDER BY kind,name",
                                           (sid,), conn)] if sid else [],
            "scans": [dict(r) for r in q("SELECT id,ts,role,packages,score,risk,"
                                         "total_findings,added,removed,changed FROM scans "
                                         "ORDER BY id DESC LIMIT 50", (), conn)],
        }
    finally:
        if own:
            conn.close()


def export_json(scan_id=None) -> str:
    return json.dumps(report_payload(scan_id), indent=2, default=str)


def export_csv(scan_id=None) -> str:
    conn = connect()
    try:
        sid = scan_id or latest_scan_id(conn)
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow([f"# {APP_NAME} v{VERSION} by {AUTHOR}"])
        w.writerow([f"# scan_id={sid} generated={now_iso()}"])
        w.writerow([f"# {DISCLAIMER_SHORT}"])
        w.writerow(["# NOT a vulnerability scan - no CVE data was consulted."])
        w.writerow(["manager", "name", "version", "arch", "size_bytes", "section", "origin",
                    "installed_at", "install_date_is_proxy", "manual", "eol_runtime",
                    "eol_date", "eol_past", "approved"])
        for r in q("SELECT * FROM packages WHERE scan_id=? ORDER BY manager, name",
                   (sid,), conn):
            w.writerow([r[k] for k in ("manager", "name", "version", "arch", "size",
                                       "section", "origin", "installed_at",
                                       "install_date_is_proxy", "manual", "eol_runtime",
                                       "eol_date", "eol_past", "approved")])
        return buf.getvalue()
    finally:
        conn.close()


def export_html(scan_id=None) -> str:
    conn = connect()
    try:
        p = report_payload(scan_id, conn)
        scan, esc = p["scan"], html_escape
        if not scan:
            return "<!doctype html><html><body><h1>No scans recorded</h1></body></html>"
        counts = {s: scan[s] or 0 for s in SEVERITIES}
        by_mgr = {}
        by_size = []
        for pk in p["packages"]:
            by_mgr[pk["manager"]] = by_mgr.get(pk["manager"], 0) + 1
            if pk["size"]:
                by_size.append((pk["name"], pk["size"]))
        pie = svg_pie([(s, counts[s], SEV_COLOR[s]) for s in SEVERITIES])
        bar = svg_bar(sorted(by_mgr.items(), key=lambda x: -x[1]), title="Packages by manager",
                      colors=MANAGER_COLOR)
        tree = svg_treemap(sorted(by_size, key=lambda x: -x[1])[:40])
        eol_rows = [pk for pk in p["packages"] if pk["eol_past"]]
        frows = "".join(
            f'<tr><td><span class="pill" style="background:{SEV_COLOR[f["severity"]]}">'
            f'{esc(f["severity"].upper())}</span></td><td class="mono">{esc(f["category"])}</td>'
            f'<td><b>{esc(f["title"])}</b><div class="desc">{esc(f["description"])}</div>'
            + (f'<pre>{esc(f["evidence"])}</pre>' if f["evidence"] else "")
            + f'<div class="rec"><b>Next:</b> {esc(f["recommendation"])}</div>'
            + (f'<div class="ref">{esc(f["reference"])}</div>' if f["reference"] else "")
            + "</td></tr>" for f in p["findings"])
        erows = "".join(
            f'<tr><td class="mono">{esc(pk["manager"])}</td><td>{esc(pk["name"])}</td>'
            f'<td class="mono">{esc(pk["version"])}</td>'
            f'<td class="mono">{esc(pk["eol_runtime"])}</td>'
            f'<td class="mono">{esc(pk["eol_date"])}</td></tr>' for pk in eol_rows[:60])
        crows = "".join(
            f'<tr><td class="mono">{esc(c["kind"])}</td><td class="mono">{esc(c["manager"])}</td>'
            f'<td>{esc(c["name"])}</td><td class="mono">{esc(c["version_from"] or "-")}</td>'
            f'<td class="mono">{esc(c["version_to"] or "-")}</td></tr>'
            for c in p["changes"][:200])
        srows = "".join(
            f'<tr><td class="mono">{esc(s["name"])}</td><td>{esc(s["status"])}</td>'
            f'<td class="mono">{s["count"]}</td><td class="mono">{esc(s["command"] or "-")}</td>'
            f'<td>{esc(s["detail"] or "")}</td></tr>' for s in p["sources"])
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{APP_SHORT} report - {esc(scan['hostname'] or '')}</title><style>
 body{{font:14px/1.55 ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif;margin:0;
      background:#0f1115;color:#e6e8ee}}
 .wrap{{max-width:1120px;margin:0 auto;padding:28px 20px 60px}}
 h1{{font-size:22px;margin:0 0 4px}} .meta{{color:#8b8f9b;font-size:12.5px}}
 h2{{font-size:12px;text-transform:uppercase;letter-spacing:.15em;color:#8b8f9b;
     margin:32px 0 12px;border-bottom:1px solid #262a33;padding-bottom:8px}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:18px 0}}
 .card{{background:#171a21;border:1px solid #262a33;border-radius:10px;padding:12px 14px}}
 .card .n{{font-size:23px;font-weight:700;font-family:ui-monospace,monospace}}
 .card .l{{font-size:10.5px;text-transform:uppercase;letter-spacing:.11em;color:#8b8f9b}}
 table{{width:100%;border-collapse:collapse;background:#171a21;border:1px solid #262a33;
        border-radius:10px;overflow:hidden;font-size:13px}}
 th{{text-align:left;font-size:10.5px;letter-spacing:.11em;text-transform:uppercase;
     color:#8b8f9b;padding:10px 12px;border-bottom:1px solid #262a33;background:#1c2029}}
 td{{padding:9px 12px;border-bottom:1px solid #1e222a;vertical-align:top}}
 .mono{{font-family:ui-monospace,Menlo,monospace;font-size:12px}}
 .pill{{color:#0f1115;font-weight:700;font-size:10px;padding:2px 8px;border-radius:20px}}
 .desc{{color:#b6bac4;margin-top:4px;max-width:76ch}}
 .rec{{margin-top:6px;color:#8fd3b0;max-width:76ch}}
 .ref{{margin-top:4px;color:#6f7685;font-size:11.5px;font-family:ui-monospace,monospace}}
 pre{{background:#0f1115;border:1px solid #262a33;border-radius:6px;padding:8px;
      font-family:ui-monospace,monospace;font-size:11.5px;margin:7px 0 0;overflow:auto;
      white-space:pre-wrap;word-break:break-all;color:#b6bac4;max-height:170px}}
 .warn{{background:#231a12;border:1px solid #5a3b1c;color:#ffcf9e;padding:12px 14px;
        border-radius:10px;font-size:12.5px;margin:16px 0;white-space:pre-wrap}}
 .privacy{{background:#1a1226;border:1px solid #4a2f6b;color:#d9c2f0;padding:11px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0}}
 .note{{background:#12202a;border:1px solid #1c4a5e;color:#a8d8e8;padding:11px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0}}
 .charts{{display:flex;gap:20px;flex-wrap:wrap;align-items:flex-start}}
 .chart{{margin:0;background:#171a21;border:1px solid #262a33;border-radius:10px;padding:14px 16px}}
 .chart.wide{{width:100%}}
 .chart figcaption{{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;
   color:#8b8f9b;margin-bottom:10px;font-family:ui-monospace,monospace}}
 .chart-row{{display:flex;gap:16px;align-items:center;flex-wrap:wrap}}
 .chart-empty{{background:#171a21;border:1px dashed #31363f;border-radius:10px;padding:18px;
   color:#8b8f9b;font-size:12.5px}}
 .legend{{display:flex;flex-direction:column;gap:6px;min-width:150px}}
 .lg{{display:flex;align-items:center;gap:7px;font-size:12.5px}}
 .lg i{{width:11px;height:11px;border-radius:3px}} .lg span{{flex:1}}
 .lg em{{font-style:normal;color:#8b8f9b;font-size:11px}}
 text.bl{{fill:#8b8f9b;font:11px ui-monospace,monospace}}
 text.bv{{fill:#e6e8ee;font:11px ui-monospace,monospace}}
 text.tm{{fill:#e6e8ee;font:10px ui-monospace,monospace}}
 rect.btrack{{fill:#1e222a}} line.gl{{stroke:#262a33;stroke-width:1}}
 text.pie-n{{fill:#e6e8ee;font:700 17px ui-monospace,monospace}}
 text.g-n{{font:700 26px ui-monospace,monospace}}
 text.g-l{{fill:#8b8f9b;font:10px ui-monospace,monospace}}
 footer{{margin-top:36px;color:#6f7685;font-size:12px;border-top:1px solid #262a33;padding-top:14px}}
</style></head><body><div class="wrap">
<h1>{APP_NAME} - report</h1>
<div class="meta">{esc(scan['hostname'])} &middot; {esc(scan['os_version'] or '')} &middot;
 role <b>{esc(scan['role'])}</b> &middot; {ts_pretty(scan['ts'])}</div>
<div class="warn">{esc(DISCLAIMER_LONG)}</div>
<div class="note"><b>This is not a vulnerability scan.</b>
 {esc(p['not_a_vulnerability_scan'])} End-of-life data: {esc(scan['eol_source'])}, dated
 {esc(scan['eol_as_of'])}.</div>
<div class="privacy"><b>Privacy.</b> {esc(PRIVACY_NOTICE)}</div>
<div class="charts">{svg_gauge(scan['score'] or 0, scan['risk'] or '')}
 <div><div style="font-size:24px;font-weight:700">{esc(scan['risk'] or '')}</div>
 <div class="meta">{scan['packages']} packages across {scan['managers']} manager(s) &middot;
 {scan['total_findings']} findings</div></div></div>
<div class="grid">
{"".join(f'<div class="card"><div class="l">{s}</div><div class="n" '
         f'style="color:{SEV_COLOR[s]}">{counts[s]}</div></div>' for s in SEVERITIES)}
 <div class="card"><div class="l">Past EOL</div>
  <div class="n" style="color:{SEV_COLOR['high']}">{len(eol_rows)}</div></div>
</div>
<h2>Disk footprint</h2><div class="charts">{tree}</div>
<h2>Analytics</h2><div class="charts">{pie}{bar}</div>
<h2>Inventory sources</h2>
<table><tr><th>Manager</th><th>Status</th><th>Packages</th><th>Command</th><th>Detail</th></tr>
{srows}</table>
<h2>Findings ({len(p['findings'])})</h2>
<table><tr><th>Severity</th><th>Area</th><th>Detail</th></tr>{frows}</table>
{'<h2>Past end of life (' + str(len(eol_rows)) + ')</h2><table><tr><th>Manager</th>'
 '<th>Package</th><th>Version</th><th>Runtime</th><th>EOL date</th></tr>' + erows + '</table>'
 if erows else ''}
{'<h2>Changes since the previous scan (' + str(len(p['changes'])) + ')</h2><table><tr>'
 '<th>Kind</th><th>Manager</th><th>Package</th><th>From</th><th>To</th></tr>' + crows
 + '</table>' if crows else ''}
<footer>Generated by {APP_NAME} v{VERSION} &middot; {AUTHOR} &middot; {GITHUB}<br>
 A full software inventory is reconnaissance material. Share it only with authorised parties
 and delete it securely when it is no longer needed.</footer>
</div></body></html>"""
    finally:
        conn.close()


# =============================================================================
# SECTION 9 - Web application (5 pages, no CDN, no JavaScript libraries)
# =============================================================================

CSS = """
:root{--bg:#0f1115;--panel:#171a21;--panel-2:#1c2029;--line:#262a33;--line-2:#31363f;
 --tx:#e6e8ee;--tx-dim:#8b8f9b;--tx-mid:#b6bac4;--accent:#5b8def;--ok:#30a46c;
 --warn:#ffb224;--crit:#e5484d;
 --mono:ui-monospace,SFMono-Regular,'JetBrains Mono',Menlo,Consolas,'Courier New',monospace;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
 font:14px/1.55 ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
header.top{border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:9}
.hd{max-width:1220px;margin:0 auto;padding:12px 20px;display:flex;align-items:center;gap:16px;
 flex-wrap:wrap}
.brand{font-family:var(--mono);font-weight:700;letter-spacing:-.4px;font-size:15px}
.brand b{color:var(--accent)}
.brand small{display:block;font-weight:400;font-size:10.5px;letter-spacing:.14em;
 text-transform:uppercase;color:var(--tx-dim)}
nav{display:flex;gap:2px;margin-left:auto;flex-wrap:wrap}
nav a{font-family:var(--mono);font-size:12px;letter-spacing:.06em;text-transform:uppercase;
 padding:7px 11px;border-radius:6px;color:var(--tx-dim)}
nav a:hover{background:var(--panel-2);color:var(--tx);text-decoration:none}
nav a.on{background:var(--accent);color:#0b0d10;font-weight:600}
.wrap{max-width:1220px;margin:0 auto;padding:20px 20px 70px}
.banner{background:#231a12;border:1px solid #5a3b1c;color:#ffcf9e;padding:10px 14px;
 border-radius:9px;font-size:12.3px;margin-bottom:12px;line-height:1.5}
.banner.privacy{background:#1a1226;border-color:#4a2f6b;color:#d9c2f0}
.banner.info{background:#12202a;border-color:#1c4a5e;color:#a8d8e8}
.banner b{color:#fff}
h1{font-size:19px;margin:0 0 3px;letter-spacing:-.3px}
h2{font-family:var(--mono);font-size:11.5px;letter-spacing:.16em;text-transform:uppercase;
 color:var(--tx-dim);margin:26px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
.sub{color:var(--tx-dim);font-size:12.5px;margin-bottom:14px}
.bar{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin:0 0 16px}
.btn{font-family:var(--mono);font-size:12px;padding:8px 13px;border-radius:7px;cursor:pointer;
 border:1px solid var(--line-2);background:var(--panel-2);color:var(--tx);display:inline-block}
.btn:hover{border-color:var(--accent);text-decoration:none}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#0b0d10;font-weight:700}
select,input[type=text],input[type=number]{font-family:var(--mono);font-size:12px;padding:7px 9px;
 background:var(--panel-2);color:var(--tx);border:1px solid var(--line-2);border-radius:7px}
input[type=text]{min-width:200px}
label.chk{font-family:var(--mono);font-size:12px;color:var(--tx-dim);display:flex;gap:5px;
 align-items:center}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(136px,1fr));margin:14px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:14px 16px}
.card .l{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;text-transform:uppercase;
 color:var(--tx-dim)}
.card .n{font-size:24px;font-weight:700;line-height:1.3;font-family:var(--mono)}
.card .s{font-size:11.5px;color:var(--tx-dim)}
.hero{display:flex;gap:22px;align-items:center;flex-wrap:wrap;background:var(--panel);
 border:1px solid var(--line);border-radius:12px;padding:16px 20px}
.hero .meta{flex:1;min-width:250px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:3px 14px;font-size:12.5px}
.kv dt{color:var(--tx-dim);font-family:var(--mono);font-size:11px;letter-spacing:.07em;
 text-transform:uppercase}
.kv dd{margin:0;word-break:break-word}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
 border-radius:11px;overflow:hidden;font-size:13px}
th{text-align:left;font-family:var(--mono);font-size:10.5px;letter-spacing:.12em;
 text-transform:uppercase;color:var(--tx-dim);padding:10px 12px;border-bottom:1px solid var(--line);
 background:var(--panel-2);white-space:nowrap}
td{padding:8px 12px;border-bottom:1px solid #1e222a;vertical-align:top}
tr:last-child td{border-bottom:none} tr:hover td{background:#1b1f27}
.mono{font-family:var(--mono);font-size:12px}
.num{font-family:var(--mono);font-size:12px;text-align:right}
.pill{display:inline-block;color:#0b0d10;font-weight:700;font-size:10px;padding:2px 8px;
 border-radius:20px;letter-spacing:.06em;font-family:var(--mono);white-space:nowrap}
.tag{display:inline-block;font-family:var(--mono);font-size:10.5px;padding:1px 6px;border-radius:5px;
 border:1px solid var(--line-2);color:var(--tx-dim);white-space:nowrap}
.tag.good{border-color:#1e5138;color:#7fd9ab} .tag.bad{border-color:#5a2326;color:#ff9b9e}
.strip{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}
.strip div{font-family:var(--mono);font-size:11px;padding:6px 10px;border-radius:7px;
 border:1px solid var(--line);background:var(--panel)}
.strip .ok{border-color:#1e5138} .strip .partial{border-color:#5a3b1c}
.strip .unavailable{border-color:#5a2326} .strip .absent{opacity:.5}
.strip b{text-transform:uppercase;letter-spacing:.08em}
.desc{color:var(--tx-mid);margin-top:4px;max-width:78ch}
.rec{margin-top:6px;color:#8fd3b0;font-size:12.5px;max-width:78ch}
.ref{margin-top:4px;color:#6f7685;font-size:11.5px;font-family:var(--mono)}
pre{background:var(--bg);border:1px solid var(--line);border-radius:7px;padding:8px 10px;
 font-family:var(--mono);font-size:11.5px;margin:7px 0 0;max-height:170px;overflow:auto;
 white-space:pre-wrap;word-break:break-all;color:var(--tx-mid)}
details summary{cursor:pointer;color:var(--tx-dim);font-size:12px;font-family:var(--mono)}
.charts{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start}
.chart{margin:0;background:var(--panel);border:1px solid var(--line);border-radius:11px;
 padding:14px 16px}
.chart.wide{width:100%}
.chart figcaption{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;
 text-transform:uppercase;color:var(--tx-dim);margin-bottom:10px}
.chart-row{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
.chart-empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;
 padding:20px;color:var(--tx-dim);font-size:12.5px;flex:1;min-width:250px}
.legend{display:flex;flex-direction:column;gap:6px;min-width:150px}
.lg{display:flex;align-items:center;gap:7px;font-size:12.5px}
.lg i{width:11px;height:11px;border-radius:3px;flex:none}
.lg span{flex:1} .lg b{font-family:var(--mono)}
.lg em{font-style:normal;color:var(--tx-dim);font-family:var(--mono);font-size:11px}
text.bl{fill:#8b8f9b;font:11px var(--mono)} text.bv{fill:#e6e8ee;font:11px var(--mono)}
text.tm{fill:#e6e8ee;font:10px var(--mono)}
rect.btrack{fill:#1e222a} line.gl{stroke:#262a33;stroke-width:1}
text.pie-n{fill:#e6e8ee;font:700 17px var(--mono)}
text.g-n{font:700 26px var(--mono)} text.g-l{fill:#8b8f9b;font:10px var(--mono)}
.empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;padding:28px;
 text-align:center;color:var(--tx-dim)}
.empty b{display:block;color:var(--tx);margin-bottom:6px;font-size:15px}
footer{max-width:1220px;margin:0 auto;padding:16px 20px 40px;color:#6f7685;font-size:11.5px;
 border-top:1px solid var(--line);line-height:1.7}
.lvl-ERROR{color:var(--crit)} .lvl-WARN{color:var(--warn)} .lvl-INFO{color:var(--tx-dim)}
@media (max-width:640px){.hd{padding:10px 14px} .wrap{padding:14px 14px 50px}
 nav{margin-left:0;width:100%} .card .n{font-size:20px} table{font-size:12.2px}
 th,td{padding:8px 9px} input[type=text]{min-width:140px}}
"""

BASE_TPL = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ page }} - """ + APP_SHORT + """</title><style>""" + CSS + """</style></head><body>
<header class="top"><div class="hd">
 <div class="brand"><b>SWAUDIT</b> Installed Software Auditor
  <small>inventory and hygiene &middot; not a vulnerability scan</small></div>
 <nav>
  <a href="{{ url_for('page_overview') }}" class="{{ 'on' if nav=='overview' }}">Overview</a>
  <a href="{{ url_for('page_packages') }}" class="{{ 'on' if nav=='packages' }}">Packages</a>
  <a href="{{ url_for('page_changes') }}" class="{{ 'on' if nav=='changes' }}">Changes</a>
  <a href="{{ url_for('page_analytics') }}" class="{{ 'on' if nav=='analytics' }}">Analytics</a>
  <a href="{{ url_for('page_logs') }}" class="{{ 'on' if nav=='logs' }}">Logs</a>
 </nav></div></header>
<div class="wrap">
 <div class="banner"><b>Authorised use only.</b> """ + DISCLAIMER_SHORT + """</div>
 {% if error %}<div class="banner" style="background:#2a1216;border-color:#6b2229;
  color:#ffc9cd"><b>That failed:</b> {{ error }}</div>{% endif %}
 {% if flash %}<div class="banner info">{{ flash }}</div>{% endif %}
 {% block body %}{% endblock %}
</div>
<footer>""" + APP_NAME + """ v""" + VERSION + """ &middot; built by """ + AUTHOR + """ &middot;
 <a href=\"""" + GITHUB + """\" rel="noopener">GitHub</a> &middot;
 <a href=\"""" + LINKEDIN + """\" rel="noopener">LinkedIn</a><br>
 <b>Not a vulnerability scanner</b> - no CVE database is consulted and no network request is
 made. Feed the JSON export to Trivy, Grype or osv-scanner for that.<br>
 """ + PRIVACY_NOTICE + """</footer>
</body></html>"""

CONTROLS_TPL = """
<div class="bar">
 <form method="post" action="{{ url_for('do_scan') }}" style="display:flex;gap:8px;
  align-items:center">
  <label class="mono" style="color:var(--tx-dim)">ROLE</label>
  <select name="role">
   {% for r, cfg in roles.items() %}<option value="{{ r }}"
    {{ 'selected' if r==(scan.role if scan else 'unknown') }}>{{ r }} - {{ cfg.label }}
   </option>{% endfor %}</select>
  <button class="btn primary" type="submit">Scan this machine</button></form>
 {% if scan %}
 <form method="get" style="display:flex;gap:8px;align-items:center">
  <label class="mono" style="color:var(--tx-dim)">SCAN</label>
  <select name="scan" onchange="this.form.submit()">
   {% for s in all_scans %}<option value="{{ s.id }}" {{ 'selected' if s.id==scan.id }}>
    #{{ s.id }} &middot; {{ s.ts[:16].replace('T',' ') }} &middot; {{ s.packages }} pkgs
   </option>{% endfor %}</select></form>
 <a class="btn" href="{{ url_for('export', fmt='html') }}?scan={{ scan.id }}">Export HTML</a>
 <a class="btn" href="{{ url_for('export', fmt='json') }}?scan={{ scan.id }}">JSON</a>
 <a class="btn" href="{{ url_for('export', fmt='csv') }}?scan={{ scan.id }}">CSV</a>
 {% endif %}
</div>"""

EMPTY_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Overview</h1>
""" + CONTROLS_TPL + """
<div class="empty"><b>No scans yet</b>
 Scan this machine to inventory every package manager it has and audit the result. A manager
 that is not installed is reported as absent; one that fails is reported as unavailable with
 the reason - nothing is quietly treated as empty.
 <div class="mono" style="margin-top:12px;color:var(--tx-dim)">
  from the terminal: python3 software_auditor.py scan --role server</div>
</div>{% endblock %}"""

OVERVIEW_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Overview</h1>
<div class="sub">Scan #{{ scan.id }} of {{ scan.hostname }} &middot; {{ ts_pretty(scan.ts) }}
 &middot; role <b>{{ scan.role }}</b></div>
""" + CONTROLS_TPL + """
<div class="banner info"><b>This is not a vulnerability scan.</b> No CVE database was
 consulted and no network request was made, so a package shown here as current may still be
 vulnerable. End-of-life data: {{ scan.eol_source }}, dated {{ scan.eol_as_of }}.
 Feed the JSON export to Trivy, Grype or osv-scanner for CVE matching.</div>
<div class="hero">
 {{ gauge|safe }}
 <div class="meta"><dl class="kv">
  <dt>Verdict</dt><dd><b>{{ scan.risk }}</b> - {{ scan.total_findings }} finding(s)</dd>
  <dt>Inventory</dt><dd>{{ scan.packages }} packages across {{ scan.managers }} manager(s),
   {{ fmt_bytes(scan.total_size) }} reported</dd>
  <dt>Past EOL</dt><dd>{{ n_eol }} package(s)</dd>
  <dt>Changes</dt><dd>{% if scan.prev_scan_id %}since scan #{{ scan.prev_scan_id }}:
   +{{ scan.added }} installed, -{{ scan.removed }} removed, {{ scan.changed }} version
   change(s){% else %}first scan - nothing to compare against yet{% endif %}</dd>
  <dt>Host</dt><dd>{{ scan.os_version }}</dd>
 </dl></div>
</div>
<h2>Inventory sources</h2>
<div class="sub">"Absent" means the manager is not installed here, which is normal.
 "Unavailable" means it is installed but would not answer - those checks are reported as not
 performed rather than passed.</div>
<div class="strip">
{% for s in sources %}
 <div class="{{ s.status }}"><b>{{ s.name }}</b> &middot; {{ s.status }}
  {% if s.status in ('ok','partial') %}&middot; {{ s.count }} pkgs{% endif %}
  {% if s.detail %}&middot; {{ s.detail[:90] }}{% endif %}</div>
{% endfor %}
</div>
<div class="grid">
{% for s in severities %}
 <div class="card"><div class="l">{{ s }}</div>
  <div class="n" style="color:{{ sev[s] }}">{{ scan[s] }}</div></div>
{% endfor %}
</div>
<h2>Findings</h2>
{% if findings %}
<table><tr><th>Severity</th><th>Area</th><th>Detail</th></tr>
{% for f in findings %}
<tr><td><span class="pill" style="background:{{ sev[f.severity] }}">
 {{ f.severity|upper }}</span></td>
 <td class="mono">{{ f.category }}</td>
 <td><b>{{ f.title }}</b><div class="desc">{{ f.description }}</div>
  {% if f.evidence %}<details><summary>Evidence</summary><pre>{{ f.evidence }}</pre></details>
  {% endif %}
  <div class="rec">Next: {{ f.recommendation }}</div>
  {% if f.reference %}<div class="ref">{{ f.reference }}</div>{% endif %}</td></tr>
{% endfor %}</table>
{% else %}<div class="empty">No findings were raised.</div>{% endif %}
{% endblock %}"""

PACKAGES_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Packages</h1>
<div class="sub">{{ rows|length }} of {{ scan.packages }} package(s) from scan #{{ scan.id }}.
 {% if truncated %}Showing the first {{ limit }} - narrow the filter or use the CSV export
 for everything.{% endif %}</div>
<div class="banner privacy"><b>Privacy.</b> """ + PRIVACY_NOTICE + """</div>
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <input type="hidden" name="scan" value="{{ scan.id }}">
 <select name="manager"><option value="">All managers</option>
  {% for m in managers %}<option value="{{ m }}" {{ 'selected' if m==f_manager }}>{{ m }}
  </option>{% endfor %}</select>
 <input type="text" name="qq" value="{{ f_q }}" placeholder="name, version or summary">
 <label class="chk"><input type="checkbox" name="eol" value="1" {{ 'checked' if f_eol }}>
  past EOL only</label>
 <label class="chk"><input type="checkbox" name="unapproved" value="1"
  {{ 'checked' if f_unapproved }}> unapproved only</label>
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_packages') }}?scan={{ scan.id }}">Reset</a>
</form>
<form method="post" action="{{ url_for('do_approve') }}">
 <input type="hidden" name="scan" value="{{ scan.id }}">
 <button class="btn" type="submit">Approve this whole inventory as the baseline</button></form>
</div>
{% if rows %}
<table><tr><th>Manager</th><th>Package</th><th>Version</th><th>Size</th><th>Installed</th>
 <th>Lifecycle</th><th>Baseline</th></tr>
{% for p in rows %}
<tr><td><span class="tag" style="border-color:{{ mgr_colour.get(p.manager,'#31363f') }}">
 {{ p.manager }}</span></td>
 <td>{{ p.name }}{% if p.summary %}<div class="sub" style="margin:0">{{ p.summary[:90] }}
  </div>{% endif %}</td>
 <td class="mono">{{ p.version or '-' }}</td>
 <td class="num">{{ fmt_bytes(p.size) if p.size else '-' }}</td>
 <td class="mono">{{ (p.installed_at or '-')[:10] }}
  {% if p.install_date_is_proxy and p.installed_at %}<span class="tag">proxy</span>{% endif %}</td>
 <td>{% if p.eol_past %}<span class="tag bad">EOL {{ p.eol_date }}</span>
  {% elif p.eol_date %}<span class="tag good">supported to {{ p.eol_date }}</span>
  {% else %}-{% endif %}</td>
 <td>{% if p.approved %}<span class="tag good">approved</span>{% else %}
  <span class="tag">new</span>{% endif %}</td></tr>
{% endfor %}</table>
<div class="sub" style="margin-top:10px">"Proxy" on an install date means the package manager
 does not record one and the file mtime was used instead - close, but not authoritative.</div>
{% else %}<div class="empty"><b>Nothing matches this filter</b></div>{% endif %}
{% endblock %}"""

CHANGES_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Changes</h1>
<div class="sub">{% if scan.prev_scan_id %}Scan #{{ scan.prev_scan_id }} &rarr;
 #{{ scan.id }}{% else %}This is the first scan, so there is nothing to compare against
 yet.{% endif %}</div>
<div class="grid">
 <div class="card"><div class="l">Installed</div>
  <div class="n" style="color:var(--ok)">{{ scan.added }}</div></div>
 <div class="card"><div class="l">Removed</div>
  <div class="n" style="color:var(--crit)">{{ scan.removed }}</div></div>
 <div class="card"><div class="l">Version changes</div>
  <div class="n" style="color:var(--accent)">{{ scan.changed }}</div></div>
 <div class="card"><div class="l">Total now</div><div class="n">{{ scan.packages }}</div></div>
</div>
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <input type="hidden" name="scan" value="{{ scan.id }}">
 <select name="kind"><option value="">All changes</option>
  {% for k in kinds %}<option value="{{ k }}" {{ 'selected' if k==f_kind }}>{{ k }}</option>
  {% endfor %}</select>
 <input type="text" name="qq" value="{{ f_q }}" placeholder="package name">
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_changes') }}?scan={{ scan.id }}">Reset</a>
</form></div>
{% if rows %}
<table><tr><th>Change</th><th>Manager</th><th>Package</th><th>From</th><th>To</th></tr>
{% for c in rows %}
<tr><td>{% if c.kind=='added' %}<span class="tag good">installed</span>
 {% elif c.kind=='removed' %}<span class="tag bad">removed</span>
 {% elif c.kind=='downgraded' %}<span class="tag bad">downgraded</span>
 {% else %}<span class="tag">{{ c.kind }}</span>{% endif %}</td>
 <td class="mono">{{ c.manager }}</td><td>{{ c.name }}</td>
 <td class="mono">{{ c.version_from or '-' }}</td>
 <td class="mono">{{ c.version_to or '-' }}</td></tr>
{% endfor %}</table>
{% else %}
<div class="empty"><b>No changes recorded</b>
 {% if scan.prev_scan_id %}Nothing was installed, removed or changed version between the two
 scans.{% else %}Run a second scan later to see what changed.{% endif %}</div>
{% endif %}
{% endblock %}"""

ANALYTICS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Analytics</h1>
<div class="sub">Charts are plain SVG rendered from the SQLite database - no external chart
 library, no network calls.</div>
""" + CONTROLS_TPL + """
{% if scan %}
<h2>Disk footprint</h2><div class="charts">{{ tree|safe }}</div>
<div class="charts" style="margin-top:16px">{{ pie_sev|safe }}{{ bar_mgr|safe }}</div>
<div class="charts" style="margin-top:16px">{{ bar_size|safe }}{{ bar_section|safe }}</div>
<div class="charts" style="margin-top:16px">{{ col_hist|safe }}{{ col_pkgs|safe }}</div>
{% endif %}
<h2>Scan history</h2>
{% if scans %}
<table><tr><th>#</th><th>When</th><th>Role</th><th>Packages</th><th>Score</th><th>Verdict</th>
 <th>+</th><th>-</th><th>~</th><th>C</th><th>H</th><th>M</th></tr>
{% for s in scans %}<tr>
 <td class="mono"><a href="{{ url_for('page_overview') }}?scan={{ s.id }}">#{{ s.id }}</a></td>
 <td class="mono">{{ s.ts[:19].replace('T',' ') }}</td><td class="mono">{{ s.role }}</td>
 <td class="num">{{ s.packages }}</td>
 <td class="num" style="color:{{ s.colour }}"><b>{{ s.score }}</b></td><td>{{ s.risk }}</td>
 <td class="num" style="color:var(--ok)">{{ s.added }}</td>
 <td class="num" style="color:var(--crit)">{{ s.removed }}</td>
 <td class="num">{{ s.changed }}</td>
 <td class="num" style="color:{{ sev.critical }}">{{ s.critical }}</td>
 <td class="num" style="color:{{ sev.high }}">{{ s.high }}</td>
 <td class="num" style="color:{{ sev.medium }}">{{ s.medium }}</td></tr>{% endfor %}</table>
{% else %}<div class="empty">No scans yet.</div>{% endif %}
{% endblock %}"""

LOGS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Logs</h1><div class="sub">Every scan, approval and export, stored locally in
 {{ dbfile }}.</div>
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <select name="level"><option value="">All levels</option>
  {% for l in ['INFO','WARN','ERROR'] %}<option value="{{ l }}" {{ 'selected' if l==f_level }}>
   {{ l }}</option>{% endfor %}</select>
 <select name="limit">{% for n in [50,100,250,500,1000] %}
  <option value="{{ n }}" {{ 'selected' if n==limit }}>last {{ n }}</option>{% endfor %}</select>
 <input type="text" name="qq" value="{{ f_q }}" placeholder="search message">
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_logs') }}">Reset</a>
</form></div>
<div class="grid">
 <div class="card"><div class="l">Events</div><div class="n">{{ counts.total }}</div></div>
 <div class="card"><div class="l">Errors</div>
  <div class="n" style="color:var(--crit)">{{ counts.ERROR }}</div></div>
 <div class="card"><div class="l">Warnings</div>
  <div class="n" style="color:var(--warn)">{{ counts.WARN }}</div></div>
 <div class="card"><div class="l">Info</div><div class="n">{{ counts.INFO }}</div></div>
</div>
{% if rows %}
<table><tr><th>Time (UTC)</th><th>Level</th><th>Source</th><th>Message</th><th>Scan</th></tr>
{% for e in rows %}<tr><td class="mono">{{ e.ts[:19].replace('T',' ') }}</td>
 <td class="mono lvl-{{ e.level }}"><b>{{ e.level }}</b></td>
 <td class="mono">{{ e.source }}</td><td>{{ e.message }}</td>
 <td class="mono">{{ ('#' ~ e.scan_id) if e.scan_id else '-' }}</td></tr>{% endfor %}</table>
{% else %}<div class="empty"><b>No log entries match</b></div>{% endif %}
{% endblock %}"""

TEMPLATES = {"base.html": BASE_TPL, "empty.html": EMPTY_TPL, "overview.html": OVERVIEW_TPL,
             "packages.html": PACKAGES_TPL, "changes.html": CHANGES_TPL,
             "analytics.html": ANALYTICS_TPL, "logs.html": LOGS_TPL}

try:
    from flask import (Flask, Response, jsonify, redirect, render_template, request, url_for)
    from jinja2 import ChoiceLoader, DictLoader
    HAVE_FLASK = True
except Exception:  # pragma: no cover
    HAVE_FLASK = False


def build_app():
    if not HAVE_FLASK:
        raise SystemExit("Flask is not installed. Install it with:  pip install flask\n"
                         "(The CLI works without Flask; only the web app needs it.)")
    app = Flask(__name__)
    app.jinja_loader = ChoiceLoader([DictLoader(TEMPLATES), app.jinja_loader])

    def ctx(nav, conn, **kw):
        base = {"nav": nav, "page": nav.capitalize(), "sev": SEV_COLOR,
                "severities": SEVERITIES, "ts_pretty": ts_pretty, "fmt_bytes": fmt_bytes,
                "roles": ROLES, "mgr_colour": MANAGER_COLOR, "scan": None,
                "error": request.args.get("error"), "flash": request.args.get("flash"),
                "all_scans": q("SELECT id, ts, packages FROM scans ORDER BY id DESC LIMIT 100",
                               (), conn)}
        base.update(kw)
        return base

    def pick_scan(conn):
        try:
            sid = int(request.args.get("scan", "") or 0)
        except ValueError:
            sid = 0
        if sid and scan_summary(sid, conn):
            return scan_summary(sid, conn)
        sid = latest_scan_id(conn)
        return scan_summary(sid, conn) if sid else None

    @app.route("/")
    def page_overview():
        conn = connect()
        try:
            scan = pick_scan(conn)
            if not scan:
                return render_template("empty.html", **ctx("overview", conn))
            return render_template("overview.html", **ctx(
                "overview", conn, scan=scan,
                gauge=svg_gauge(scan["score"] or 0, scan["risk"] or ""),
                sources=json.loads(scan["sources_json"] or "[]"),
                n_eol=q1("SELECT COUNT(*) c FROM packages WHERE scan_id=? AND eol_past=1",
                         (scan["id"],), conn)["c"],
                findings=q("SELECT * FROM findings WHERE scan_id=? ORDER BY CASE severity "
                           "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                           "WHEN 'low' THEN 3 ELSE 4 END, id", (scan["id"],), conn)))
        finally:
            conn.close()

    @app.route("/packages")
    def page_packages():
        conn = connect()
        try:
            scan = pick_scan(conn)
            if not scan:
                return render_template("empty.html", **ctx("packages", conn))
            mgr = request.args.get("manager", "").strip()
            term = request.args.get("qq", "").strip()
            eol = request.args.get("eol") == "1"
            unapproved = request.args.get("unapproved") == "1"
            limit = 800
            sql, args = "SELECT * FROM packages WHERE scan_id=?", [scan["id"]]
            if mgr:
                sql += " AND manager=?"
                args.append(mgr)
            if eol:
                sql += " AND eol_past=1"
            if unapproved:
                sql += " AND approved=0"
            if term:
                sql += (" AND (name LIKE ? OR IFNULL(version,'') LIKE ? "
                        "OR IFNULL(summary,'') LIKE ?)")
                args += [f"%{term}%"] * 3
            total = q1(sql.replace("SELECT *", "SELECT COUNT(*) c"), tuple(args), conn)["c"]
            sql += " ORDER BY eol_past DESC, manager, name LIMIT ?"
            args.append(limit)
            managers = [r["manager"] for r in q("SELECT DISTINCT manager FROM packages "
                                                "WHERE scan_id=? ORDER BY manager",
                                                (scan["id"],), conn)]
            return render_template("packages.html", **ctx(
                "packages", conn, scan=scan, rows=q(sql, tuple(args), conn),
                managers=managers, f_manager=mgr, f_q=term, f_eol=eol,
                f_unapproved=unapproved, limit=limit, truncated=total > limit))
        finally:
            conn.close()

    @app.route("/changes")
    def page_changes():
        conn = connect()
        try:
            scan = pick_scan(conn)
            if not scan:
                return render_template("empty.html", **ctx("changes", conn))
            kind = request.args.get("kind", "").strip()
            term = request.args.get("qq", "").strip()
            sql, args = "SELECT * FROM changes WHERE scan_id=?", [scan["id"]]
            if kind:
                sql += " AND kind=?"
                args.append(kind)
            if term:
                sql += " AND name LIKE ?"
                args.append(f"%{term}%")
            sql += " ORDER BY kind, manager, name LIMIT 2000"
            kinds = [r["kind"] for r in q("SELECT DISTINCT kind FROM changes WHERE scan_id=?",
                                          (scan["id"],), conn)]
            return render_template("changes.html", **ctx(
                "changes", conn, scan=scan, rows=q(sql, tuple(args), conn),
                kinds=sorted(kinds), f_kind=kind, f_q=term))
        finally:
            conn.close()

    @app.route("/analytics")
    def page_analytics():
        conn = connect()
        try:
            scan = pick_scan(conn)
            kw = {"scan": scan}
            if scan:
                sid = scan["id"]
                mgr = q("SELECT manager, COUNT(*) c FROM packages WHERE scan_id=? "
                        "GROUP BY manager ORDER BY c DESC", (sid,), conn)
                size = q("SELECT name, size FROM packages WHERE scan_id=? AND size IS NOT NULL "
                         "ORDER BY size DESC LIMIT 40", (sid,), conn)
                sect = q("SELECT IFNULL(section,'(none)') s, COUNT(*) c FROM packages "
                         "WHERE scan_id=? GROUP BY s ORDER BY c DESC LIMIT 12", (sid,), conn)
                hist = list(reversed([dict(r) for r in q(
                    "SELECT id, score, packages FROM scans ORDER BY id DESC LIMIT 12",
                    (), conn)]))
                kw.update(
                    tree=svg_treemap([(r["name"], r["size"]) for r in size]),
                    pie_sev=svg_pie([(s, scan[s] or 0, SEV_COLOR[s]) for s in SEVERITIES]),
                    bar_mgr=svg_bar([(r["manager"], r["c"]) for r in mgr],
                                    title="Packages by manager", colors=MANAGER_COLOR),
                    bar_size=svg_bar([(r["name"], r["size"]) for r in size[:10]],
                                     title="Largest packages", color="#9775fa", fmt=fmt_bytes),
                    bar_section=svg_bar([(r["s"], r["c"]) for r in sect],
                                        title="Packages by section", color="#30a46c"),
                    col_hist=svg_columns([(f"#{h['id']}", h["score"] or 0,
                                           risk_label(h["score"] or 0)[1]) for h in hist],
                                         title="Score by scan", ymax=100),
                    col_pkgs=svg_columns([(f"#{h['id']}", h["packages"] or 0, "#5b8def")
                                          for h in hist], title="Package count by scan"))
            scans = []
            for s in q("SELECT * FROM scans ORDER BY id DESC LIMIT 25", (), conn):
                d = dict(s)
                d["colour"] = risk_label(d["score"] or 0)[1]
                scans.append(d)
            kw["scans"] = scans
            return render_template("analytics.html", **ctx("analytics", conn, **kw))
        finally:
            conn.close()

    @app.route("/logs")
    def page_logs():
        conn = connect()
        try:
            level = request.args.get("level", "").strip().upper()
            term = request.args.get("qq", "").strip()
            try:
                limit = clamp(int(request.args.get("limit", 100)), 10, 1000)
            except ValueError:
                limit = 100
            sql, args = "SELECT * FROM audit_log WHERE 1=1", []
            if level in ("INFO", "WARN", "ERROR"):
                sql += " AND level=?"
                args.append(level)
            if term:
                sql += " AND (message LIKE ? OR source LIKE ?)"
                args += [f"%{term}%"] * 2
            sql += " ORDER BY id DESC LIMIT ?"
            args.append(limit)
            counts = {"total": q1("SELECT COUNT(*) c FROM audit_log", (), conn)["c"]}
            for lv in ("INFO", "WARN", "ERROR"):
                counts[lv] = q1("SELECT COUNT(*) c FROM audit_log WHERE level=?",
                                (lv,), conn)["c"]
            return render_template("logs.html", **ctx(
                "logs", conn, rows=q(sql, tuple(args), conn), counts=counts, limit=limit,
                f_level=level, f_q=term, dbfile=os.path.abspath(db_path())))
        finally:
            conn.close()

    @app.post("/scan")
    def do_scan():
        role = (request.form.get("role") or "unknown").strip()
        if role not in ROLES:
            role = "unknown"
        try:
            sid = run_scan(role=role, note="from the web UI")
            return redirect(url_for("page_overview") + f"?scan={sid}")
        except Exception as e:
            log_event("ERROR", "scan", str(e))
            import urllib.parse
            return redirect(url_for("page_overview") + "?error="
                            + urllib.parse.quote(str(e)))

    @app.post("/approve")
    def do_approve():
        import urllib.parse
        try:
            sid = int(request.form.get("scan") or 0)
        except ValueError:
            sid = 0
        sid = sid or latest_scan_id()
        rows = q("SELECT manager, name, version FROM packages WHERE scan_id=?", (sid,))
        n = approve_packages([dict(r) for r in rows], note="approved from the web UI")
        return redirect(url_for("page_packages") + f"?scan={sid}&flash="
                        + urllib.parse.quote(f"Approved {n} package(s) as the baseline. "
                                             f"Later scans will show what changed against it."))

    @app.route("/export/<fmt>")
    def export(fmt):
        try:
            sid = int(request.args.get("scan", "") or 0) or None
        except ValueError:
            sid = None
        fmt = fmt.lower()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if fmt == "json":
            body, mime = export_json(sid), "application/json"
        elif fmt == "csv":
            body, mime = export_csv(sid), "text/csv"
        elif fmt == "html":
            body, mime = export_html(sid), "text/html"
        else:
            return Response("Unsupported format. Use json, csv or html.", 400,
                            mimetype="text/plain")
        log_event("INFO", "export", f"Exported the report as {fmt.upper()}", sid)
        return Response(body, mimetype=mime, headers={
            "Content-Disposition": f'attachment; filename="swaudit-{stamp}.{fmt}"'})

    @app.route("/api/summary")
    def api_summary():
        sid = latest_scan_id()
        if not sid:
            return jsonify({"error": "no scans yet"}), 404
        return jsonify({"tool": APP_NAME, "version": VERSION,
                        "disclaimer": DISCLAIMER_SHORT,
                        "not_a_vulnerability_scan": True, "scan": scan_summary(sid)})

    @app.errorhandler(404)
    def nf(_e):
        return Response("404 - page not found. Valid pages: / /packages /changes "
                        "/analytics /logs", 404, mimetype="text/plain")

    return app


def serve(host: str, port: int, debug: bool = False):
    app = build_app()
    init_db()
    log_event("INFO", "web", f"Web app started on http://{host}:{port} (db={db_path()})")
    print(f"\n  {APP_NAME} v{VERSION} - by {AUTHOR}")
    print(f"  {'-' * 66}")
    print(f"  Web app : http://{'127.0.0.1' if host == '0.0.0.0' else host}:{port}")
    print(f"  Database: {os.path.abspath(db_path())}")
    print(f"  Pages   : /  /packages  /changes  /analytics  /logs")
    if host == "0.0.0.0":
        print("  WARNING : bound to 0.0.0.0 - this UI has no authentication and publishes a\n"
              "            complete software inventory, which is reconnaissance material.\n"
              "            Use 127.0.0.1 unless you have a specific reason.")
    print(f"  {textwrap.fill(DISCLAIMER_SHORT, 66, subsequent_indent='  ')}")
    print(f"  {'-' * 66}\n  Press Ctrl+C to stop.\n")
    app.run(host=host, port=port, debug=debug, use_reloader=False)


# =============================================================================
# SECTION 10 - Command line interface
# =============================================================================

def line(char="-", n=78):
    print(char * n)


def banner():
    print(f"\n{APP_NAME} v{VERSION}  |  {AUTHOR}")
    line()
    print(textwrap.fill(DISCLAIMER_SHORT, 78))
    line()


def _print_findings(rows, limit=None):
    shown = rows[:limit] if limit else rows
    for f in shown:
        print(f"\n  [{f['severity'].upper():^8}] {f['title']}   ({f['category']})")
        for l in textwrap.wrap(f["description"], 70):
            print(f"      {l}")
        if f["evidence"]:
            ev = " ".join(str(f["evidence"]).split())
            print(f"      evidence: {ev[:220]}{'...' if len(ev) > 220 else ''}")
        if f["recommendation"]:
            for l in textwrap.wrap("next: " + f["recommendation"], 70):
                print(f"      {l}")
    if limit and len(rows) > limit:
        print(f"\n  ... {len(rows) - limit} more (use 'findings')")


def cmd_scan(a):
    banner()
    print(f"Inventorying {socket.gethostname()} as role '{a.role}' "
          f"({ROLES.get(a.role, ROLES['unknown'])['label']})\n")
    sid = run_scan(role=a.role, eol_file=a.eol_file, note=a.note or "",
                   progress=None if a.quiet else (lambda n: print(f"  [*] {n}", flush=True)))
    print()
    cmd_show(argparse.Namespace(scan=sid, limit=a.show))
    return 0


def cmd_show(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No scans yet. Run:  scan --role server")
        return
    s = scan_summary(sid)
    if not s:
        print(f"Scan #{sid} not found.")
        return
    conn = connect()
    try:
        line("=")
        print(f"  SCAN #{s['id']}  {s['hostname']}  ({s['os_version']})")
        print(f"  {ts_pretty(s['ts'])}  |  role {s['role']}")
        line("=")
        bars = int(round((s["score"] or 0) / 5))
        print(f"  [{'#' * bars}{'.' * (20 - bars)}]  {s['score']}/100   {s['risk']}")
        print(f"  {s['packages']} package(s) across {s['managers']} manager(s), "
              f"{fmt_bytes(s['total_size'])} reported")
        print(f"  critical {s['critical']}   high {s['high']}   medium {s['medium']}   "
              f"low {s['low']}   info {s['info']}")
        if s["prev_scan_id"]:
            print(f"  since scan #{s['prev_scan_id']}: +{s['added']} installed, "
                  f"-{s['removed']} removed, {s['changed']} version change(s)")
        line()
        print("  INVENTORY SOURCES")
        for src in json.loads(s["sources_json"] or "[]"):
            mark = {"ok": "[ok]", "partial": "[!!]", "unavailable": "[XX]",
                    "absent": "[--]"}.get(src["status"], "[??]")
            detail = f"  {src['detail']}" if src["detail"] else ""
            print(f"   {mark} {src['name']:<12} {src['count']:>5} pkgs{detail[:56]}")
        print(f"\n  EOL data: {s['eol_source']} (dated {s['eol_as_of']})")
        line()
        eol = q("SELECT * FROM packages WHERE scan_id=? AND eol_past=1 ORDER BY eol_date",
                (sid,), conn)
        if eol:
            print(f"  PAST END OF LIFE ({len(eol)})")
            for p in eol[:15]:
                print(f"   {p['manager']:<8} {p['name']:<28} {(p['version'] or '')[:16]:<18} "
                      f"{p['eol_runtime']} EOL {p['eol_date']}")
            line()
        rows = [dict(r) for r in q(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY CASE severity "
            "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 3 ELSE 4 END, id LIMIT ?", (sid, a.limit), conn)]
        print(f"  FINDINGS (showing {len(rows)} of {s['total_findings']})")
        _print_findings(rows)
        line()
        print("  This is NOT a vulnerability scan: no CVE data was consulted. Feed the JSON")
        print("  export to Trivy, Grype or osv-scanner for that.")
        line()
        print(f"  Packages: python3 {os.path.basename(__file__)} packages --scan {sid}")
        print(f"  Changes : python3 {os.path.basename(__file__)} changes --scan {sid}")
        print(f"  Web app : python3 {os.path.basename(__file__)} serve")
        line()
    finally:
        conn.close()


def cmd_packages(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No scans yet.")
        return
    sql, args = "SELECT * FROM packages WHERE scan_id=?", [sid]
    if a.manager:
        sql += " AND manager=?"
        args.append(a.manager)
    if a.eol:
        sql += " AND eol_past=1"
    if a.unapproved:
        sql += " AND approved=0"
    if a.search:
        sql += " AND (name LIKE ? OR IFNULL(summary,'') LIKE ?)"
        args += [f"%{a.search}%"] * 2
    sql += " ORDER BY eol_past DESC, manager, name LIMIT ?"
    args.append(a.limit)
    rows = q(sql, tuple(args))
    if not rows:
        print("No packages match that filter.")
        return
    print(f"{'MANAGER':<10} {'PACKAGE':<34} {'VERSION':<22} {'SIZE':>10}  LIFECYCLE")
    line()
    for p in rows:
        life = ""
        if p["eol_past"]:
            life = f"PAST EOL {p['eol_date']}"
        elif p["eol_date"]:
            life = f"supported to {p['eol_date']}"
        print(f"{p['manager']:<10} {p['name'][:33]:<34} {(p['version'] or '')[:21]:<22} "
              f"{fmt_bytes(p['size']) if p['size'] else '-':>10}  {life}")
    print(f"\n{len(rows)} package(s) from scan #{sid}")


def cmd_changes(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No scans yet.")
        return
    s = scan_summary(sid)
    if not s["prev_scan_id"]:
        print(f"Scan #{sid} is the first one, so there is nothing to compare against yet.")
        print("Run another scan later to see what changed.")
        return
    sql, args = "SELECT * FROM changes WHERE scan_id=?", [sid]
    if a.kind:
        sql += " AND kind=?"
        args.append(a.kind)
    sql += " ORDER BY kind, manager, name LIMIT ?"
    args.append(a.limit)
    rows = q(sql, tuple(args))
    print(f"Scan #{s['prev_scan_id']} -> #{sid}:  +{s['added']} installed, "
          f"-{s['removed']} removed, {s['changed']} version change(s)")
    if not rows:
        print("\nNothing changed between the two scans.")
        return
    line()
    print(f"{'CHANGE':<12} {'MANAGER':<10} {'PACKAGE':<30} FROM -> TO")
    line()
    for c in rows:
        print(f"{c['kind']:<12} {c['manager']:<10} {c['name'][:29]:<30} "
              f"{(c['version_from'] or '-')[:18]} -> {(c['version_to'] or '-')[:18]}")
    print(f"\n{len(rows)} change(s)")


def cmd_findings(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No scans yet.")
        return
    sql, args = "SELECT * FROM findings WHERE scan_id=?", [sid]
    if a.severity:
        sql += " AND severity=?"
        args.append(a.severity)
    if a.category:
        sql += " AND category=?"
        args.append(a.category)
    sql += (" ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id")
    rows = [dict(r) for r in q(sql, tuple(args))]
    if not rows:
        print("No findings match that filter.")
        return
    print(f"Scan #{sid} - {len(rows)} finding(s)")
    _print_findings(rows)


def cmd_approve(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No scans yet.")
        return 1
    if a.all:
        rows = q("SELECT manager, name, version FROM packages WHERE scan_id=?", (sid,))
        n = approve_packages([dict(r) for r in rows], note=a.note or "")
        print(f"Approved {n} package(s) from scan #{sid} as the baseline.")
        print("Later scans will report what changed against it.")
    elif a.key:
        m, _, name = a.key.partition(":")
        if not name:
            print("Use --key manager:name, for example dpkg:openssh-server")
            return 1
        approve_packages([{"manager": m, "name": name, "version": ""}], note=a.note or "")
        print(f"Approved {a.key}")
    else:
        print("Specify --all or --key manager:name")
        return 1
    return 0


def cmd_revoke(a):
    n = revoke_package(a.key)
    print(f"Removed {n} entry(ies) from the baseline." if n
          else f"{a.key} was not in the baseline.")


def cmd_baseline(a):
    rows = q("SELECT * FROM baseline ORDER BY manager, name LIMIT ?", (a.limit,))
    if not rows:
        print("The baseline is empty. Approve the current inventory with:  approve --all")
        return
    total = q1("SELECT COUNT(*) c FROM baseline", ())["c"]
    print(f"{'KEY':<44} {'VERSION':<22} APPROVED")
    line()
    for r in rows:
        print(f"{r['key'][:43]:<44} {(r['version'] or '-')[:21]:<22} "
              f"{(r['approved_at'] or '')[:19]}")
    print(f"\n{len(rows)} shown of {total} approved package(s)")


def cmd_eol(a):
    table, as_of, src = load_eol_table(a.eol_file)
    banner()
    print(f"End-of-life data: {src} (dated {as_of})\n")
    stale = days_between(as_of) or 0
    if stale > 180:
        print(textwrap.fill(
            f"WARNING: this table is {stale} days old. Support windows move, so verify "
            f"anything you act on, or supply a current table with --eol-file.", 78))
        print()
    today = datetime.now(timezone.utc).date().isoformat()
    print(f"{'RUNTIME':<16} {'VERSION':<12} {'EOL DATE':<14} STATUS")
    line()
    for runtime in sorted(table):
        for prefix, eol_date, note in table[runtime]:
            status = "PAST" if eol_date < today else "supported"
            print(f"{runtime:<16} {str(prefix):<12} {eol_date:<14} {status}"
                  f"{'  - ' + note if note else ''}")
    line()
    print("No network request is made to obtain this data, by design. Supply your own with")
    print("--eol-file FILE, where FILE is JSON: "
          '{"as_of": "YYYY-MM-DD", "runtimes": {"python": [["3.9","2025-10-31",""]]}}')
    line()


def cmd_sources(a):
    banner()
    print("Probing every package manager this tool knows about.\n")
    print(f"{'MANAGER':<14} {'STATUS':<13} {'PKGS':>6}  COMMAND / DETAIL")
    line()
    for fn in ALL_COLLECTORS:
        s = fn()
        detail = s.command if s.status in ("ok", "partial") else s.detail
        print(f"{s.name:<14} {s.status:<13} {len(s.packages):>6}  {detail[:44]}")
        if s.status == "partial" and s.detail:
            for l in textwrap.wrap(s.detail, 60):
                print(f"{'':<36}{l}")
    line()
    print("'absent' means the manager is not installed here, which is normal.")
    print("'unavailable' means it is installed but would not answer - that is a gap.")


def cmd_explain(_a):
    banner()
    print(textwrap.dedent("""\
        WHAT AN INVENTORY IS FOR
          You cannot patch, licence or defend software you do not know you have. Most
          machines carry software from three or four different managers, and each one
          only updates its own. That gap is where old, unpatched code survives.

        WHY THIS TOOL DOES NOT CHECK CVEs
          Matching packages to vulnerabilities needs a database that changes daily,
          which means network access and usually an API key. This tool has neither by
          design, so it will never tell you a package is "safe". What it gives you is a
          complete, accurate inventory - export it as JSON and feed it to Trivy, Grype
          or osv-scanner, which do that job properly.

        THE FOUR THINGS WORTH FIXING FIRST
          1. Anything past end of life. No fixes are coming for it, ever.
          2. The same software installed by two managers. Only one gets updated, and
             which one runs depends on PATH. This is why "we patched that" is sometimes
             wrong.
          3. Executables nothing owns. Installed by hand or by a vendor script, so no
             updater knows they exist and nobody will ever patch them.
          4. Third-party repositories. Each one can install software as root. Usually a
             deliberate choice - it should still be a known one.

        ON DUAL-USE TOOLING
          nmap, tcpdump, gcc and netcat are ordinary tools. On an admin workstation they
          are expected; on a production web server they are a ready-made toolkit for
          whoever lands a shell. That is why this tool asks for a role and judges
          against it, and why the finding says "justify this" rather than "remove this".

        A NOTE ON WINDOWS
          This tool reads the uninstall registry keys, not Win32_Product. Enumerating
          that WMI class triggers an MSI self-repair for every product it touches, which
          can reconfigure software on the machine you are auditing. An auditor must not
          change what it measures.
        """))
    line()
    print(PRIVACY_NOTICE)
    line()


def cmd_scans(a):
    rows = q("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (a.limit,))
    if not rows:
        print("No scans yet.")
        return
    print(f"{'ID':>4}  {'WHEN (UTC)':<20} {'ROLE':<12} {'PKGS':>6} {'SCORE':>6}  "
          f"{'+/-/~':<12} VERDICT")
    line()
    for s in rows:
        delta = f"+{s['added']}/-{s['removed']}/~{s['changed']}"
        when = s["ts"][:19].replace("T", " ")
        print(f"{s['id']:>4}  {when:<20} {s['role']:<12} {s['packages']:>6} "
              f"{s['score']:>6}  {delta:<12} {s['risk']}")


def cmd_export(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No scans to export yet.")
        return 1
    fmt = a.format.lower()
    body = {"json": export_json, "csv": export_csv, "html": export_html}[fmt](sid)
    out = a.out or f"swaudit-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.{fmt}"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(body)
    log_event("INFO", "export", f"Exported scan #{sid} as {fmt.upper()} to {out}", sid)
    print(f"Wrote {out} ({len(body):,} bytes)")
    if fmt == "json":
        print("For vulnerability matching:  trivy sbom " + out + "   (or grype / osv-scanner)")
    print("A full inventory is reconnaissance material - treat this file as sensitive.")
    return 0


def cmd_logs(a):
    sql, args = "SELECT * FROM audit_log WHERE 1=1", []
    if a.level:
        sql += " AND level=?"
        args.append(a.level.upper())
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(a.limit)
    rows = q(sql, tuple(args))
    if not rows:
        print("No log entries.")
        return
    for e in reversed(rows):
        print(f"{e['ts'][:19].replace('T', ' ')}  {e['level']:<5} {e['source']:<14} "
              f"{e['message']}")


def cmd_purge(a):
    conn = connect()
    try:
        if a.all:
            for t in ("findings", "changes", "packages", "scans", "audit_log"):
                conn.execute(f"DELETE FROM {t}")
            if a.baseline:
                conn.execute("DELETE FROM baseline")
            conn.commit()
            print("All scans, packages, findings and logs deleted."
                  + (" The baseline was cleared too." if a.baseline
                     else " The approved-software baseline was kept."))
            return
        rows = q("SELECT id FROM scans ORDER BY id DESC", (), conn)
        drop = [r["id"] for r in rows[a.keep:]]
        for sid in drop:
            for t in ("findings", "changes", "packages"):
                conn.execute(f"DELETE FROM {t} WHERE scan_id=?", (sid,))
            conn.execute("DELETE FROM scans WHERE id=?", (sid,))
        conn.commit()
        log_event("INFO", "purge", f"Purged {len(drop)} scan(s), kept the newest {a.keep}",
                  None, conn)
        print(f"Purged {len(drop)} scan(s); kept the newest {a.keep}.")
    finally:
        conn.close()


def cmd_serve(a):
    serve(a.host, a.port, a.debug)


def cmd_version(_a):
    table, as_of, src = load_eol_table(None)
    banner()
    print(f"  Python     : {platform.python_version()} ({sys.platform})")
    print(f"  Flask      : {'yes' if HAVE_FLASK else 'NOT INSTALLED - web app unavailable'}")
    print(f"  Collectors : {len(ALL_COLLECTORS)} package managers supported")
    print(f"  EOL data   : {src}, dated {as_of} ({len(table)} runtimes)")
    print(f"  Database   : {os.path.abspath(db_path())}")
    print(f"  GitHub     : {GITHUB}")
    print(f"  LinkedIn   : {LINKEDIN}")
    line()
    print(DISCLAIMER_LONG)
    line()
    print(PRIVACY_NOTICE)
    line()


# =============================================================================
# SECTION 11 - Self test
#   Logic is checked against fixtures; collectors are run against this machine
#   and reported honestly. Runs in a throwaway database.
# =============================================================================

def cmd_selftest(_a=None) -> int:
    import tempfile
    passed, failed = [], []

    def check(name, cond, detail=""):
        (passed if cond else failed).append(name)
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              f"{'  <- ' + str(detail) if detail and not cond else ''}")

    banner()
    print("SELF TEST - logic against fixtures, collectors against this machine.\n")
    original = db_path()
    tmp = tempfile.mkdtemp(prefix="swaudit-selftest-")
    set_db_path(os.path.join(tmp, "selftest.db"))
    try:
        print(" Unit checks")
        check("byte formatting", fmt_bytes(1024) == "1.0 KiB" and fmt_bytes(None) == "-")
        check("html escaping blocks tag injection",
              "<script>" not in html_escape("<script>alert(1)</script>"))
        check("version comparison handles distro epochs",
              version_tuple("2:9.1.0") > version_tuple("1:8.2.0"))
        check("scoring: clean is 100, one critical costs 18",
              compute_score({}) == 100.0 and compute_score({"critical": 1}) == 82.0)
        check("scoring floors at 0 and ignores info",
              compute_score({"critical": 99}) == 0.0 and compute_score({"info": 50}) == 100.0)
        check("day arithmetic", days_between("2026-01-01", "2026-01-31") == 30)

        print("\n End-of-life matching (fixtures)")
        T, today = EOL_TABLE, "2026-07-31"
        cases = [
            ("python3.8", "", True, "3.8"), ("python2.7", "", True, "2."),
            ("python3.12", "", False, "3.12"), ("php7.4-cli", "", True, "7.4"),
            ("ruby2.7", "", True, "2.7"), ("postgresql-12", "", True, "12"),
            ("dotnet-runtime-6.0", "6.0.36", True, "6."),
        ]
        for name, ver, want_past, _ in cases:
            hit = check_eol(name, ver, T, today)
            check(f"{name} resolves and is {'past EOL' if want_past else 'supported'}",
                  hit is not None and hit["past"] == want_past, hit)
        check("an ambiguous name falls back to the version field",
              (check_eol("libssl1.1", "1.1.1f-1ubuntu2.19", T, today) or {}).get("eol")
              == "2023-09-11")
        check("that fallback distinguishes 1.1.0 from 1.1.1",
              (check_eol("libssl1.1", "1.1.0g-2", T, today) or {}).get("eol") == "2019-09-11")
        check("a trailing letter in a version does not break matching",
              check_eol("openssl", "3.0.13", T, today) is not None)
        check("unrelated packages do not match anything",
              check_eol("vim", "2:9.1", T, today) is None
              and check_eol("coreutils", "9.4", T, today) is None)
        check("a language BINDING is not mistaken for the runtime itself",
              check_eol("python3-apt", "2.7.7ubuntu5.2", T, today) is None
              and check_eol("python3-jwt", "2.7.0-1ubuntu0.1", T, today) is None,
              check_eol("python3-apt", "2.7.7ubuntu5.2", T, today))
        check("the interpreter package itself still resolves",
              (check_eol("python3", "3.12.3-0ubuntu2", T, today) or {}).get("runtime")
              == "python")
        check("other library bindings are ignored too",
              check_eol("php-mbstring", "2:8.3+93", T, today) is None
              and check_eol("ruby-rack", "2.2.7-1", T, today) is None)
        check("the matched-on field records which value was used",
              (check_eol("python3.8", "", T, today) or {})["matched_on"] == "package name")
        custom = os.path.join(tmp, "eol.json")
        with open(custom, "w") as fh:
            json.dump({"as_of": "2030-01-01",
                       "runtimes": {"python": [["3.99", "2029-01-01", "fixture"]]}}, fh)
        tbl, as_of, src = load_eol_table(custom)
        check("a user-supplied EOL table is loaded", as_of == "2030-01-01"
              and src.endswith("eol.json"))
        tbl2, _, src2 = load_eol_table(os.path.join(tmp, "missing.json"))
        check("a missing EOL file falls back to the built-in table and says so",
              tbl2 is EOL_TABLE and "built-in" in src2)

        print("\n Findings (fixtures)")
        src_dpkg = Source("dpkg")
        src_dpkg.packages = [
            pkg("dpkg", "python3.8", "3.8.10-1", size=4096),
            pkg("dpkg", "nmap", "7.94", size=8192),
            pkg("dpkg", "hydra", "9.5", size=2048),
            pkg("dpkg", "anydesk", "6.3.0", size=1024),
            pkg("dpkg", "requests", "2.31.0", size=512),
            pkg("dpkg", "coreutils", "9.4", size=1024),
        ]
        src_dpkg.ok("fixture")
        src_pip = Source("pip")
        src_pip.packages = [pkg("pip", "requests", "2.28.0")]
        src_pip.ok("fixture")
        src_broken = Source("rpm").unavailable("rpm database is corrupt")
        fixtures = src_dpkg.packages + src_pip.packages
        ctx = {"repos": {"status": "ok", "repos": [
                   {"file": "third.list", "url": "https://x.test/deb", "host": "x.test",
                    "third_party": 1}]},
               "updates": {"status": "ok", "packages": [
                   {"name": "libc6", "detail": "libc6 security", "security": 1}],
                   "security": 1, "detail": ""},
               "unmanaged": {"status": "ok", "files": [
                   {"path": "/usr/local/bin/thing", "size": 100, "mtime": "2026-01-01T00:00:00",
                    "managed_by": None},
                   {"path": "/usr/local/bin/script", "size": 50, "mtime": "2026-01-01T00:00:00",
                    "managed_by": "pip"}]}}
        f = analyse(fixtures, [src_dpkg, src_pip, src_broken], ctx, {}, "server")

        def has(sub):
            return any(sub.lower() in x["title"].lower() for x in f)
        check("an unavailable manager is reported as not performed, never as a pass",
              has("Check not performed"))
        check("a package past EOL is reported", has("past end of life"))
        check("the same package from two managers is reported",
              has("more than one manager"))
        check("credential-attack tooling is flagged on a server", has("Credential Attack"))
        check("remote access tooling is flagged on a server", has("Remote Access"))
        check("a third-party repository is reported", has("third-party package repository"))
        check("pending security updates are reported as high",
              any(x["severity"] == "high" and "security update" in x["title"] for x in f))
        check("a genuinely unmanaged executable is reported",
              has("not owned by any package manager"))
        check("language console scripts are not counted as unmanaged",
              any("1 executable(s) not owned" in x["title"] for x in f))
        check("an empty baseline is called out", has("No approved-software baseline"))
        check("the report states it is not a vulnerability scan",
              has("did not check for known vulnerabilities"))
        check("every finding carries a recommendation",
              all(x["recommendation"] for x in f if x["severity"] != "info"))
        f_ws = analyse(fixtures, [src_dpkg, src_pip], ctx, {}, "workstation")
        check("the same tooling is context, not a finding, on a workstation",
              not any(x["severity"] in ("medium", "high") and "Network Recon" in x["title"]
                      for x in f_ws))
        check("credential-attack tooling is still flagged on a workstation",
              any("Credential Attack" in x["title"] and x["severity"] == "medium"
                  for x in f_ws))
        f_pt = analyse(fixtures, [src_dpkg, src_pip], ctx, {}, "pentest")
        check("nothing in the tooling category is flagged on a pentest machine",
              not any(x["category"] == "Tooling" and x["severity"] != "info" for x in f_pt))
        check("a server scores worse than a pentest box on the same inventory",
              compute_score({s: sum(1 for x in f if x["severity"] == s) for s in SEVERITIES})
              < compute_score({s: sum(1 for x in f_pt if x["severity"] == s)
                               for s in SEVERITIES}))
        old_table = {"python": [("3.8", "2024-10-07", "")]}
        f_stale = analyse(fixtures, [src_dpkg], ctx, {}, "server", old_table, "2020-01-01",
                          "fixture")
        check("a stale EOL table warns about itself",
              any("end-of-life table is getting old" in x["title"].lower() for x in f_stale))
        f_none = analyse([], [Source("dpkg").unavailable("x")], {}, {}, "server")
        check("a host where nothing could be inventoried says so plainly",
              any(x["severity"] == "high" and "No package manager" in x["title"]
                  for x in f_none))

        print("\n Change detection")
        before = [{"manager": "dpkg", "name": "a", "version": "1.0"},
                  {"manager": "dpkg", "name": "b", "version": "2.0"},
                  {"manager": "dpkg", "name": "gone", "version": "1.0"}]
        after = [{"manager": "dpkg", "name": "a", "version": "1.1"},
                 {"manager": "dpkg", "name": "b", "version": "1.9"},
                 {"manager": "dpkg", "name": "new", "version": "1.0"}]
        d = diff_packages(before, after)
        check("newly installed packages are detected",
              [x["name"] for x in d["added"]] == ["new"])
        check("removed packages are detected",
              [x["name"] for x in d["removed"]] == ["gone"])
        check("an upgrade is labelled as an upgrade",
              any(c["name"] == "a" and c["direction"] == "upgraded" for c in d["changed"]))
        check("a downgrade is labelled as a downgrade",
              any(c["name"] == "b" and c["direction"] == "downgraded" for c in d["changed"]))
        check("an unchanged inventory produces no changes",
              diff_packages(after, after) == {"added": [], "removed": [], "changed": []})

        print("\n Collectors (this machine, read-only)")
        init_db()
        live_sources = [fn() for fn in ALL_COLLECTORS]
        present = [s for s in live_sources if s.status in ("ok", "partial")]
        check(f"at least one package manager answered ({len(present)})", len(present) >= 1,
              [f"{s.name}:{s.status}" for s in live_sources])
        check("every collector reports one of the four known states",
              all(s.status in ("ok", "partial", "unavailable", "absent")
                  for s in live_sources))
        check("an absent manager is distinguished from a broken one",
              all(s.detail for s in live_sources if s.status in ("absent", "unavailable")))
        check("every collected package has a manager and a name",
              all(p["manager"] and p["name"] for s in present for p in s.packages))
        check("collectors that answered recorded the command they ran",
              all(s.command for s in present))
        check("repository collector returns a known status",
              collect_repositories()["status"] in ("ok", "absent", "unavailable"))
        unm = collect_unmanaged_binaries()
        check("unmanaged-binary scan classifies language console scripts",
              unm["status"] in ("ok", "absent")
              and all("managed_by" in x for x in unm["files"]))

        print("\n Full scan and persistence")
        sid = run_scan(role="server", note="selftest")
        s = scan_summary(sid)
        check("scan stored with a score and a verdict",
              s and s["score"] is not None and s["risk"])
        n_pkgs = q1("SELECT COUNT(*) c FROM packages WHERE scan_id=?", (sid,))["c"]
        check("packages persisted", n_pkgs == s["packages"] and n_pkgs > 0)
        check("severity counters match the stored rows",
              all(s[sv] == q1("SELECT COUNT(*) c FROM findings WHERE scan_id=? AND severity=?",
                              (sid, sv))["c"] for sv in SEVERITIES))
        check("the first scan records no changes and no previous scan",
              s["prev_scan_id"] is None and s["added"] == 0)
        sid2 = run_scan(role="server", note="selftest second")
        s2 = scan_summary(sid2)
        check("a second scan links to the first",
              s2["prev_scan_id"] == sid)
        check("two identical scans of an unchanged machine report no drift",
              s2["added"] == 0 and s2["removed"] == 0 and s2["changed"] == 0,
              f"+{s2['added']} -{s2['removed']} ~{s2['changed']}")

        print("\n Baseline")
        rows = q("SELECT manager, name, version FROM packages WHERE scan_id=? LIMIT 5",
                 (sid2,))
        n = approve_packages([dict(r) for r in rows])
        check("packages can be approved", n == len(rows) and len(load_baseline()) == n)
        sid3 = run_scan(role="server", note="after approval")
        check("approved packages are marked in a later scan",
              q1("SELECT COUNT(*) c FROM packages WHERE scan_id=? AND approved=1",
                 (sid3,))["c"] == n)
        key = f"{rows[0]['manager']}:{rows[0]['name']}"
        check("a baseline entry can be revoked",
              revoke_package(key) == 1 and key not in load_baseline())

        print("\n Charts")
        check("pie renders slices", svg_pie([("a", 2, "#fff"), ("b", 1, "#000")]
                                            ).count("<path") == 2)
        check("pie with no data says so", "nothing to show" in svg_pie([]))
        check("bar renders rows", svg_bar([("x", 2), ("y", 1)]).count("<rect") == 4)
        check("columns render", svg_columns([("#1", 80), ("#2", 40)]).count("<rect") == 2)
        check("gauge renders", "<circle" in svg_gauge(72, "needs attention"))
        tm = svg_treemap([("a", 500), ("b", 300), ("c", 100)])
        check("treemap renders one cell per package", tm.count("<rect") == 3)
        check("treemap with no sizes explains why",
              "no package reported a size" in svg_treemap([]))

        print("\n Exports")
        j = json.loads(export_json(sid3))
        check("JSON export is valid and carries the disclaimer",
              "AUTHORISED" in j["disclaimer"].upper() and j["scan"]["id"] == sid3)
        check("JSON export states plainly that it is not a vulnerability scan",
              "CVE" in j["not_a_vulnerability_scan"])
        check("JSON export carries the privacy notice",
              "reconnaissance" in j["privacy_notice"])
        check("JSON export lists packages, sources and findings",
              len(j["packages"]) == s2["packages"] and j["sources"] and j["findings"])
        c = export_csv(sid3)
        rows_csv = [r for r in csv.reader(io.StringIO(c)) if r and not r[0].startswith("#")]
        check("CSV export has a header plus one row per package",
              rows_csv[0][0] == "manager" and len(rows_csv) == s2["packages"] + 1)
        h = export_html(sid3)
        check("HTML export is a complete document",
              h.startswith("<!doctype html") and h.rstrip().endswith("</html>"))
        check("HTML export contains charts, disclaimer, privacy notice and author",
              "<svg" in h and "AUTHORISED USE ONLY" in h and "Privacy" in h and AUTHOR in h)
        check("HTML export repeats the not-a-vulnerability-scan warning",
              "not a vulnerability scan" in h.lower())

        print("\n Web application")
        if not HAVE_FLASK:
            check("Flask installed", False, "pip install flask")
        else:
            app = build_app()
            app.config["TESTING"] = True
            cl = app.test_client()
            for path, must in (("/", "Overview"), ("/packages", "Packages"),
                               ("/changes", "Changes"), ("/analytics", "Analytics"),
                               ("/logs", "Logs")):
                r = cl.get(path)
                body = r.get_data(as_text=True)
                check(f"page {path} returns 200 and renders",
                      r.status_code == 200 and must in body, f"status={r.status_code}")
                check(f"page {path} shows the disclaimer", "Authorised use only" in body)
            check("the overview warns it is not a vulnerability scan",
                  "not a vulnerability scan" in cl.get("/").get_data(as_text=True).lower())
            check("the packages page carries the privacy notice",
                  "Privacy" in cl.get("/packages").get_data(as_text=True))
            check("package filters apply",
                  cl.get("/packages?manager=dpkg").status_code == 200
                  and cl.get("/packages?eol=1&unapproved=1&qq=lib").status_code == 200)
            check("changes filters apply",
                  cl.get("/changes?kind=added&qq=lib").status_code == 200)
            check("analytics renders SVG charts",
                  cl.get("/analytics").get_data(as_text=True).count("<svg") >= 5)
            check("logs filters apply",
                  cl.get("/logs?level=INFO&limit=50&qq=scan").status_code == 200)
            n_before = len(load_baseline())
            r = cl.post("/approve", data={"scan": str(sid3)})
            check("approving the inventory from the web works",
                  r.status_code == 302 and len(load_baseline()) > n_before)
            n_scans = q1("SELECT COUNT(*) c FROM scans", ())["c"]
            r = cl.post("/scan", data={"role": "workstation"})
            check("scanning from the web works and honours the role",
                  r.status_code == 302
                  and q1("SELECT role FROM scans ORDER BY id DESC LIMIT 1",
                         ())["role"] == "workstation"
                  and q1("SELECT COUNT(*) c FROM scans", ())["c"] == n_scans + 1)
            for fmt, ctype in (("json", "application/json"), ("csv", "text/csv"),
                               ("html", "text/html")):
                r = cl.get(f"/export/{fmt}?scan={sid3}")
                check(f"export /{fmt} downloads",
                      r.status_code == 200 and ctype in r.headers["Content-Type"]
                      and "attachment" in r.headers.get("Content-Disposition", ""))
            check("bad export format is rejected", cl.get("/export/exe").status_code == 400)
            check("unknown route returns a helpful 404", cl.get("/nope").status_code == 404)
            check("api summary returns JSON and flags the CVE limitation",
                  cl.get("/api/summary").get_json()["not_a_vulnerability_scan"] is True)
            check("empty-state page renders with no scans",
                  "No scans yet" in _empty_state_probe())

        print("\n Retention")
        cmd_purge(argparse.Namespace(all=False, keep=1, baseline=False))
        check("purge keeps exactly the newest scan",
              q1("SELECT COUNT(*) c FROM scans", ())["c"] == 1)
        check("purge removes orphaned packages, findings and changes",
              all(q1(f"SELECT COUNT(*) c FROM {t} WHERE scan_id NOT IN "
                     f"(SELECT id FROM scans)", ())["c"] == 0
                  for t in ("packages", "findings", "changes")))
        cmd_purge(argparse.Namespace(all=True, keep=1, baseline=False))
        check("purge --all clears the scans", q1("SELECT COUNT(*) c FROM scans", ())["c"] == 0)
        check("the baseline survives unless explicitly cleared", bool(load_baseline()))
        cmd_purge(argparse.Namespace(all=True, keep=1, baseline=True))
        check("purge --all --baseline clears the baseline too", not load_baseline())
    finally:
        set_db_path(original)
        shutil.rmtree(tmp, ignore_errors=True)

    line("=")
    print(f"  {len(passed)} passed, {len(failed)} failed")
    if failed:
        print("  Failed: " + ", ".join(failed))
    else:
        print("  All checks passed. The temporary database has been removed; your own\n"
              "  data was never touched and nothing on this machine was modified.")
    line("=")
    return 0 if not failed else 1


def _empty_state_probe() -> str:
    import tempfile
    original = db_path()
    d = tempfile.mkdtemp(prefix="swaudit-empty-")
    try:
        set_db_path(os.path.join(d, "empty.db"))
        init_db()
        app = build_app()
        app.config["TESTING"] = True
        return app.test_client().get("/").get_data(as_text=True)
    finally:
        set_db_path(original)
        shutil.rmtree(d, ignore_errors=True)


# =============================================================================
# SECTION 12 - Entry point
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{APP_NAME} v{VERSION} - inventory and audit every package manager on "
                    f"one host, by {AUTHOR}",
        epilog=textwrap.dedent(f"""\
            examples
              %(prog)s explain                  what an inventory is for, and its limits
              %(prog)s sources                  which package managers this host has
              %(prog)s scan --role server       inventory and audit
              %(prog)s packages --eol           only packages past end of life
              %(prog)s changes                  what changed since the last scan
              %(prog)s approve --all            record the current inventory as the baseline
              %(prog)s export --format json     feed this to trivy / grype / osv-scanner
              %(prog)s serve                    web app on http://127.0.0.1:5000
              %(prog)s selftest                 verify every component end to end

            THIS IS NOT A VULNERABILITY SCANNER. No CVE database is consulted.

            {PRIVACY_NOTICE}

            {DISCLAIMER_LONG}
            """))
    p.add_argument("--db", default=DEFAULT_DB,
                   help=f"SQLite database file (default: {DEFAULT_DB}, env SWAUDIT_DB)")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION} by {AUTHOR}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="inventory every package manager and audit the result")
    s.add_argument("--role", choices=sorted(ROLES), default="unknown",
                   help="how this machine is used; tunes the dual-use tooling findings")
    s.add_argument("--eol-file", help="JSON file of end-of-life dates to use instead of the "
                                      "built-in table")
    s.add_argument("--show", type=int, default=10, help="findings to print")
    s.add_argument("--quiet", action="store_true", help="no progress output")
    s.add_argument("--note")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("show", help="summary of one scan")
    s.add_argument("scan", nargs="?", type=int)
    s.add_argument("--limit", type=int, default=10)
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("packages", help="the inventory from a scan")
    s.add_argument("--scan", type=int)
    s.add_argument("--manager")
    s.add_argument("--search")
    s.add_argument("--eol", action="store_true", help="only packages past end of life")
    s.add_argument("--unapproved", action="store_true")
    s.add_argument("--limit", type=int, default=200)
    s.set_defaults(func=cmd_packages)

    s = sub.add_parser("changes", help="what changed since the previous scan")
    s.add_argument("--scan", type=int)
    s.add_argument("--kind", choices=["added", "removed", "upgraded", "downgraded", "changed"])
    s.add_argument("--limit", type=int, default=200)
    s.set_defaults(func=cmd_changes)

    s = sub.add_parser("findings", help="findings from a scan")
    s.add_argument("--scan", type=int)
    s.add_argument("--severity", choices=SEVERITIES)
    s.add_argument("--category")
    s.set_defaults(func=cmd_findings)

    s = sub.add_parser("sources", help="which package managers this host has")
    s.set_defaults(func=cmd_sources)

    s = sub.add_parser("eol", help="show the end-of-life table in use")
    s.add_argument("--eol-file")
    s.set_defaults(func=cmd_eol)

    s = sub.add_parser("approve", help="record software as approved")
    s.add_argument("--all", action="store_true", help="approve the whole current inventory")
    s.add_argument("--key", help="approve one package, as manager:name")
    s.add_argument("--scan", type=int)
    s.add_argument("--note")
    s.set_defaults(func=cmd_approve)

    s = sub.add_parser("revoke", help="remove software from the baseline")
    s.add_argument("--key", required=True, help="manager:name")
    s.set_defaults(func=cmd_revoke)

    s = sub.add_parser("baseline", help="list approved software")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_baseline)

    s = sub.add_parser("scans", help="list previous scans")
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(func=cmd_scans)

    s = sub.add_parser("explain", help="what an inventory is for, and what it cannot tell you")
    s.set_defaults(func=cmd_explain)

    s = sub.add_parser("serve", help="start the web app (5 pages)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5000)
    s.add_argument("--debug", action="store_true")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("export", help="write a report to a file")
    s.add_argument("--scan", type=int)
    s.add_argument("--format", choices=["json", "csv", "html"], default="html")
    s.add_argument("--out")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("logs", help="local event log")
    s.add_argument("--level", choices=["INFO", "WARN", "ERROR", "info", "warn", "error"])
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("purge", help="delete stored scans")
    s.add_argument("--keep", type=int, default=10)
    s.add_argument("--all", action="store_true")
    s.add_argument("--baseline", action="store_true",
                   help="with --all, also clear the approved-software baseline")
    s.set_defaults(func=cmd_purge)

    s = sub.add_parser("selftest", help="verify every component (temporary database)")
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("version", help="versions, dependencies and the disclaimer")
    s.set_defaults(func=cmd_version)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_db_path(args.db)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    if args.cmd != "selftest":
        init_db()
    try:
        rc = args.func(args)
        return rc if isinstance(rc, int) else 0
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except PermissionError as e:
        print(f"Permission denied: {e}")
        return 1
    except sqlite3.OperationalError as e:
        print(f"Database error: {e}\nIs another copy running against {db_path()}?")
        return 1


if __name__ == "__main__":
    sys.exit(main())
